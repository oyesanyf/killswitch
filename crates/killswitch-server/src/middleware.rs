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
use tower_http::cors::{Any, CorsLayer};
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
    if let Some(forwarded) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(first_ip) = forwarded.split(',').next() {
            let trimmed = first_ip.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}

/// Axum middleware enforcing multi-tier token-bucket rate limiting while preserving
/// anti-lockout exemptions for `/disarm`, `/health-probe`, and `/status`.
pub async fn rate_limit_middleware(
    req: Request<Body>,
    next: Next,
) -> Result<Response<Body>, (StatusCode, Json<serde_json::Value>)> {
    let path = req.uri().path().to_string();

    // Anti-lockout invariant: /disarm, /health-probe, and /status are never blocked by rate limiting
    if path == "/disarm"
        || path == "/health-probe"
        || path == "/status"
        || path == "/"
        || path == "/ui"
    {
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

pub fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
}

pub fn body_limit_layer(max_body_bytes: usize) -> DefaultBodyLimit {
    DefaultBodyLimit::max(max_body_bytes)
}

pub fn trace_layer(
) -> TraceLayer<tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>>
{
    TraceLayer::new_for_http()
}
