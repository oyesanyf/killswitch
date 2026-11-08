//! # Control Plane Mutual Authentication & Loopback Hardening (R4)
//!
//! Provides cryptographic token verification, caller PID anti-spoofing,
//! and quarantined caller isolation checks for control plane modification endpoints.

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::HeaderMap;
use std::net::SocketAddr;
use subtle::ConstantTimeEq;
use tracing::warn;

use killswitch_core::peer_pid::resolve_loopback_peer_pid;
use killswitch_types::status::{
    KILLCHAIN_ISOLATE_CONFIRMATION_PHRASE, KILLCHAIN_RESTORE_CONFIRMATION_PHRASE,
};
use killswitch_types::validate_caller_pid;

use crate::error::ServerError;
use crate::server::ServerState;

pub const DEFAULT_CONTROL_PLANE_HEADER: &str = "X-KillSwitch-Token";
pub const TEST_MASTER_TOKEN: &str = "KS-TOKEN-SEC-REM-9999-VERIFIED-AUTH";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthVerdict {
    Authorized,
    Unauthorized401,
    Forbidden403CallerQuarantined,
    Forbidden403PidSpoofing,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedControlCaller {
    pub operator: String,
    pub caller_pid: Option<u32>,
    pub actual_peer_pid: Option<u32>,
    pub token: String,
}

/// Constant-time token comparison resistant to timing side-channels.
pub fn constant_time_token_match(candidate: &str, expected: &str) -> bool {
    let c = candidate.trim().as_bytes();
    let e = expected.trim().as_bytes();
    if c.len() != e.len() {
        return false;
    }
    c.ct_eq(e).into()
}

/// Extracts control plane token from headers:
/// 1. `Authorization: Bearer <token>`
/// 2. `X-KillSwitch-Token: <token>`
/// 3. `x-killswitch-token: <token>`
pub fn extract_token_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(auth) = headers.get("authorization").and_then(|h| h.to_str().ok()) {
        let trimmed = auth.trim();
        if let Some(bearer) = trimmed.strip_prefix("Bearer ") {
            let t = bearer.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        } else if let Some(bearer) = trimmed.strip_prefix("bearer ") {
            let t = bearer.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }

    if let Some(token) = headers
        .get(DEFAULT_CONTROL_PLANE_HEADER)
        .and_then(|h| h.to_str().ok())
    {
        let t = token.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }

    if let Some(token) = headers
        .get("x-killswitch-token")
        .and_then(|h| h.to_str().ok())
    {
        let t = token.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }

    None
}

/// Standalone verification function matching Module 6 test contract in `tests/e2e_peer_review_remediation.rs`.
pub fn verify_control_plane_request_with_token(
    token_header: Option<&str>,
    body_token: Option<&str>,
    claimed_pid: Option<u32>,
    actual_peer_pid: u32,
    frozen_pids: &[u32],
    expected_token: &str,
) -> AuthVerdict {
    let presented_token = token_header.or(body_token);
    let token = match presented_token {
        Some(t) if !t.trim().is_empty() => t.trim(),
        _ => return AuthVerdict::Unauthorized401,
    };

    if !constant_time_token_match(token, expected_token) {
        return AuthVerdict::Unauthorized401;
    }

    if let Some(claimed) = claimed_pid {
        if claimed != actual_peer_pid {
            return AuthVerdict::Forbidden403PidSpoofing;
        }
    }

    if frozen_pids.contains(&actual_peer_pid) {
        return AuthVerdict::Forbidden403CallerQuarantined;
    }

    AuthVerdict::Authorized
}

/// Standalone verification helper defaulting to `TEST_MASTER_TOKEN`.
pub fn verify_control_plane_request(
    token_header: Option<&str>,
    body_token: Option<&str>,
    claimed_pid: Option<u32>,
    actual_peer_pid: u32,
    frozen_pids: &[u32],
) -> AuthVerdict {
    verify_control_plane_request_with_token(
        token_header,
        body_token,
        claimed_pid,
        actual_peer_pid,
        frozen_pids,
        TEST_MASTER_TOKEN,
    )
}

/// End-to-end verification helper used inside Axum request handlers.
pub fn verify_control_plane_auth(
    state: &ServerState,
    headers: &HeaderMap,
    body_token: Option<&str>,
    claimed_pid: Option<u32>,
    connect_info: Option<&ConnectInfo<SocketAddr>>,
    endpoint_name: &str,
) -> Result<AuthenticatedControlCaller, ServerError> {
    // 1. Extract token from header or body
    let header_token = extract_token_from_headers(headers);
    let presented_token = match header_token.as_deref().or(body_token) {
        Some(t) if !t.trim().is_empty() => Some(t.trim()),
        _ => None,
    };

    let token_to_verify = match presented_token {
        Some(t) => t,
        None => {
            return Err(ServerError::AuthenticationFailed(format!(
                "Missing required authentication token for control plane endpoint '{}'",
                endpoint_name
            )));
        }
    };

    // 2. Validate token against state control token or confirmation phrase (for /engage and /disarm)
    let token_valid = if (endpoint_name == "/engage"
        && constant_time_token_match(token_to_verify, KILLCHAIN_ISOLATE_CONFIRMATION_PHRASE))
        || (endpoint_name == "/disarm"
            && constant_time_token_match(token_to_verify, KILLCHAIN_RESTORE_CONFIRMATION_PHRASE))
    {
        true
    } else {
        state.is_valid_control_token(token_to_verify)
    };

    if !token_valid {
        return Err(ServerError::AuthenticationFailed(format!(
            "Invalid authentication token presented for endpoint '{}'",
            endpoint_name
        )));
    }

    // 3. Resolve peer socket PID and detect spoofing
    let bound_port = state
        .active_bound_port
        .load(std::sync::atomic::Ordering::SeqCst);
    let actual_peer_pid = if let Some(ConnectInfo(addr)) = connect_info {
        match resolve_loopback_peer_pid(*addr, bound_port) {
            Ok(pid) => Some(pid),
            Err(e) => {
                if claimed_pid.is_some() {
                    return Err(ServerError::AuthenticationFailed(format!(
                        "Loopback peer PID verification failed on connected socket: {}",
                        e
                    )));
                }
                None
            }
        }
    } else {
        None
    };

    if let (Some(claimed), Some(actual)) = (claimed_pid, actual_peer_pid) {
        if claimed != actual {
            warn!(
                "🚨 [SERVER-AUTH] Caller PID mismatch on '{}': claimed={}, actual_peer_pid={}",
                endpoint_name, claimed, actual
            );
            if endpoint_name == "/disarm" {
                return Err(ServerError::AuthenticationFailed(format!(
                    "Caller PID spoofing detected: claimed PID {} does not match authenticated peer PID {}",
                    claimed, actual
                )));
            }
            return Err(ServerError::CallerPidSpoofing { claimed, actual });
        }
    }

    // 4. Verify against quarantined callers
    let effective_pid = actual_peer_pid.or(claimed_pid);
    if let Some(pid) = effective_pid {
        let current_status = state.containment_manager.get_status();
        if current_status.frozen_pids.contains(&pid) {
            warn!(
                "🚨 [SERVER-AUTH] Calling process PID {} is quarantined/frozen; rejected on '{}'",
                pid, endpoint_name
            );
            return Err(ServerError::CallerQuarantined(pid));
        }
        if let Err(e) = validate_caller_pid(Some(pid), &current_status.frozen_pids) {
            return Err(ServerError::Core(e));
        }
    }

    Ok(AuthenticatedControlCaller {
        operator: "control_plane_operator".to_string(),
        caller_pid: claimed_pid,
        actual_peer_pid,
        token: token_to_verify.to_string(),
    })
}

/// Axum Extractor for Header-Only Control Plane Authentication
#[derive(Debug, Clone)]
pub struct ControlPlaneHeaderAuth {
    pub token: String,
    pub peer_addr: Option<SocketAddr>,
}

#[async_trait::async_trait]
impl<S> FromRequestParts<S> for ControlPlaneHeaderAuth
where
    S: Send + Sync,
{
    type Rejection = ServerError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let token = extract_token_from_headers(&parts.headers).ok_or_else(|| {
            ServerError::AuthenticationFailed("Missing control plane token in headers".to_string())
        })?;

        let peer_addr = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0);

        Ok(Self { token, peer_addr })
    }
}
