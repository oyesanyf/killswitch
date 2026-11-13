//! # Axum Middleware Layers & Port 3030 Multi-Tier Token-Bucket Rate Limiter
//!
//! Adapted from the EDR `Port3030RateLimiter`:
//! - Provides CORS headers, body limits, request tracing, and multi-tier Token-Bucket
//!   rate limiting (`heavy_policy`, `control_policy`, `general_policy`).
//! - Strictly exempts `/health-probe` and `/status` liveness probes from rate limiting
//!   to prevent anti-lockout stalls.

use axum::{
    body::Body,
    extract::DefaultBodyLimit,
    http::{Request, Response, StatusCode},
    middleware::Next,
    Json,
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;
use std::time::Instant;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BucketPolicy {
    pub capacity: f64,
    pub refill_rate_per_sec: f64,
}

impl BucketPolicy {
    pub const fn new(capacity: f64, refill_rate_per_sec: f64) -> Self {
        Self {
            capacity,
            refill_rate_per_sec,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientBucket {
    pub tokens: f64,
    pub last_update: Instant,
}

impl ClientBucket {
    pub fn new(capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_update: Instant::now(),
        }
    }

    pub fn try_consume(
        &mut self,
        policy: &BucketPolicy,
        tokens_to_consume: f64,
    ) -> Result<(), f64> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;

        self.tokens = (self.tokens + elapsed * policy.refill_rate_per_sec).min(policy.capacity);

        if self.tokens >= tokens_to_consume {
            self.tokens -= tokens_to_consume;
            Ok(())
        } else {
            let deficit = tokens_to_consume - self.tokens;
            let wait_secs = (deficit / policy.refill_rate_per_sec).ceil().max(1.0);
            Err(wait_secs)
        }
    }
}

pub struct Port3030RateLimiter {
    control_buckets: DashMap<String, ClientBucket>,
    heavy_buckets: DashMap<String, ClientBucket>,
    general_buckets: DashMap<String, ClientBucket>,
    pub control_policy: BucketPolicy,
    pub heavy_policy: BucketPolicy,
    pub general_policy: BucketPolicy,
    total_throttled_requests: AtomicU64,
}

impl Default for Port3030RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl Port3030RateLimiter {
    pub fn new() -> Self {
        Self {
            control_buckets: DashMap::new(),
            heavy_buckets: DashMap::new(),
            general_buckets: DashMap::new(),
            // Control plane mutations: burst 30, refill 5.0/sec
            control_policy: BucketPolicy::new(30.0, 5.0),
            // Heavy analytical / benchmark endpoints: burst 25, refill 2.0/sec
            heavy_policy: BucketPolicy::new(25.0, 2.0),
            // General telemetry & status endpoints: burst 150, refill 30.0/sec
            general_policy: BucketPolicy::new(150.0, 30.0),
            total_throttled_requests: AtomicU64::new(0),
        }
    }

    pub fn check_rate_limit(&self, client_key: &str, path: &str) -> Result<(), u64> {
        let (map, policy) = if path.contains("/edr-bench/evaluate")
            || path.contains("/rl/benchmark")
            || path.contains("/tpm/seal")
        {
            (&self.heavy_buckets, &self.heavy_policy)
        } else if path.contains("/engage")
            || path.contains("/service/control")
            || path.contains("/peers/control")
        {
            (&self.control_buckets, &self.control_policy)
        } else {
            (&self.general_buckets, &self.general_policy)
        };

        if map.len() > 10_000 {
            let cutoff = Instant::now() - std::time::Duration::from_secs(3600);
            map.retain(|_, v| v.last_update > cutoff);
        }

        let mut entry = map
            .entry(client_key.to_string())
            .or_insert_with(|| ClientBucket::new(policy.capacity));
        let res = entry.try_consume(policy, 1.0);
        drop(entry);

        match res {
            Ok(()) => Ok(()),
            Err(wait_secs) => {
                self.total_throttled_requests
                    .fetch_add(1, Ordering::Relaxed);
                Err(wait_secs as u64)
            }
        }
    }

    pub fn total_throttled(&self) -> u64 {
        self.total_throttled_requests.load(Ordering::Relaxed)
    }

    pub fn active_bucket_counts(&self) -> (usize, usize, usize) {
        (
            self.control_buckets.len(),
            self.heavy_buckets.len(),
            self.general_buckets.len(),
        )
    }
}

pub static GLOBAL_HTTP_RATE_LIMITER: LazyLock<Port3030RateLimiter> =
    LazyLock::new(Port3030RateLimiter::new);

pub fn extract_client_key(req: &Request<Body>) -> String {
    #[cfg(test)]
    if let Some(test_ip) = req
        .headers()
        .get("x-test-client-ip")
        .and_then(|v| v.to_str().ok())
    {
        let trimmed = test_ip.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    if let Some(connect_info) = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        return connect_info.0.ip().to_string();
    }

    "127.0.0.1".to_string()
}

/// Axum middleware enforcing multi-tier token-bucket rate limiting while preserving
/// rate-limit exemptions ONLY for read-only liveness/UI endpoints (`/status`, `/`, `/ui`, `/.well-known/jwks.json`).
pub async fn rate_limit_middleware(
    req: Request<Body>,
    next: Next,
) -> Result<Response<Body>, (StatusCode, Json<serde_json::Value>)> {
    let path = req.uri().path().to_string();

    if path == "/status" || path == "/" || path == "/ui" || path == "/.well-known/jwks.json" {
        return Ok(next.run(req).await);
    }

    let client_key = extract_client_key(&req);
    match GLOBAL_HTTP_RATE_LIMITER.check_rate_limit(&client_key, &path) {
        Ok(()) => Ok(next.run(req).await),
        Err(wait_secs) => {
            let error_json = json!({
                "ok": false,
                "error": "TOO_MANY_REQUESTS",
                "message": format!(
                    "EDR Port 3030 token-bucket rate limit exceeded for '{}'. Retry after {}s.",
                    path, wait_secs
                ),
                "retry_after_seconds": wait_secs,
            });
            Err((StatusCode::TOO_MANY_REQUESTS, Json(error_json)))
        }
    }
}

/// Strict authentication gate applied across ALL mutating control/telemetry endpoints.
/// Exempts only read-only GET/HEAD/OPTIONS routes and Ed25519-signed CAGE substrate routes
/// (`/v1/cage/quarantine`, `/v1/cage/release`, `/v1/cage/conformal/validate` and `/api/v1/cage/*` aliases).
pub async fn control_plane_post_auth_middleware(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<crate::server::ServerState>>,
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    use axum::extract::ConnectInfo;
    use axum::http::Method;
    use axum::response::IntoResponse;

    let method = req.method().clone();
    if method == Method::GET || method == Method::HEAD || method == Method::OPTIONS {
        return next.run(req).await;
    }

    let path = req.uri().path().to_string();
    if matches!(
        path.as_str(),
        "/v1/cage/quarantine"
            | "/api/v1/cage/quarantine"
            | "/v1/cage/release"
            | "/api/v1/cage/release"
            | "/v1/cage/conformal/validate"
            | "/api/v1/cage/conformal/validate"
    ) {
        return next.run(req).await;
    }

    let connect_info = req
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .cloned();
    let max_bytes = state.config.max_body_bytes.max(64 * 1024);
    let (parts, body) = req.into_parts();

    let body_bytes = match axum::body::to_bytes(body, max_bytes).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return crate::error::ServerError::Validation(format!(
                "Request body exceeded limit or failed read: {}",
                e
            ))
            .into_response();
        }
    };

    let (body_token, body_caller_pid) = if body_bytes.is_empty() {
        (None, None)
    } else if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
        let tok = val
            .get("token")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let pid = val
            .get("caller_pid")
            .and_then(|v| v.as_u64())
            .and_then(|n| u32::try_from(n).ok());
        (tok, pid)
    } else {
        (None, None)
    };

    let header_pid = parts
        .headers
        .get("x-killswitch-caller-pid")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u32>().ok());
    let claimed_pid = body_caller_pid.or(header_pid);

    if let Err(err) = crate::auth::verify_control_plane_auth(
        &state,
        &parts.headers,
        body_token.as_deref(),
        claimed_pid,
        connect_info.as_ref(),
        &path,
    ) {
        return err.into_response();
    }

    let rebuilt = Request::from_parts(parts, Body::from(body_bytes));
    next.run(rebuilt).await
}

pub fn cors_layer_for_port(bound_port: u16) -> CorsLayer {
    use axum::http::{header, HeaderName, HeaderValue, Method};
    use tower_http::cors::AllowOrigin;

    let effective_port = if bound_port == 0 { 3030 } else { bound_port };
    let mut origins = Vec::new();
    for host in &["127.0.0.1", "[::1]"] {
        if let Ok(val) = format!("http://{}:{}", host, effective_port).parse::<HeaderValue>() {
            origins.push(val);
        }
    }

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::OPTIONS,
            Method::PUT,
            Method::DELETE,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::ACCEPT,
            HeaderName::from_static("x-killswitch-token"),
            HeaderName::from_static("x-killswitch-caller-pid"),
            HeaderName::from_static("x-killswitch-csrf"),
            HeaderName::from_static("x-killswitch-auth"),
            HeaderName::from_static("x-cage-quarantine-assertion"),
            HeaderName::from_static("x-cage-quarantine-release"),
            HeaderName::from_static("x-cage-signer-kid"),
        ])
}

pub fn cors_layer() -> CorsLayer {
    cors_layer_for_port(3030)
}

pub fn body_limit_layer(max_body_bytes: usize) -> DefaultBodyLimit {
    DefaultBodyLimit::max(max_body_bytes)
}

pub fn trace_layer(
) -> TraceLayer<tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>>
{
    TraceLayer::new_for_http()
}
