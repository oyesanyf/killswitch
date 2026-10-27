//! # Server Error Taxonomy & Axum HTTP Response Envelope
//!
//! Provides structured JSON error responses with canonical error codes.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Anti-lockout defense active: {0}s remaining")]
    LockoutActive(u64),

    #[error("Caller PID {0} is quarantined/frozen and forbidden from invoking containment controls")]
    CallerQuarantined(u32),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Payload too large: {0}")]
    PayloadTooLarge(String),

    #[error("Octopus boundary violation: {0}")]
    OctopusViolation(String),

    #[error("Native OS service error: {0}")]
    ServiceError(String),

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Port {0} already in use")]
    PortInUse(u16),

    #[error("KillSwitch core error: {0}")]
    Core(#[from] killswitch_types::errors::KillSwitchError),
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::AuthenticationFailed(_) => (StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED"),
            Self::LockoutActive(_) => (StatusCode::TOO_MANY_REQUESTS, "LOCKOUT_ACTIVE"),
            Self::CallerQuarantined(_) => (StatusCode::FORBIDDEN, "CALLER_QUARANTINED"),
            Self::Validation(_) => (StatusCode::BAD_REQUEST, "VALIDATION_ERROR"),
            Self::NotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            Self::PayloadTooLarge(_) => (StatusCode::PAYLOAD_TOO_LARGE, "PAYLOAD_TOO_LARGE"),
            Self::OctopusViolation(_) => (StatusCode::BAD_REQUEST, "OCTOPUS_VIOLATION"),
            Self::ServiceError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "SERVICE_ERROR"),
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
            Self::PortInUse(_) => (StatusCode::SERVICE_UNAVAILABLE, "PORT_IN_USE"),
            Self::Core(err) => match err {
                killswitch_types::errors::KillSwitchError::AuthenticationFailed(_) => {
                    (StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED")
                }
                killswitch_types::errors::KillSwitchError::LockoutActive(_) => {
                    (StatusCode::TOO_MANY_REQUESTS, "LOCKOUT_ACTIVE")
                }
                killswitch_types::errors::KillSwitchError::CallerQuarantined { .. }
                | killswitch_types::errors::KillSwitchError::QuarantinedCaller(_) => {
                    (StatusCode::FORBIDDEN, "CALLER_QUARANTINED")
                }
                _ => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
            },
        };

        let body = Json(serde_json::json!({
            "error": {
                "code": code,
                "message": self.to_string(),
                "timestamp": chrono::Utc::now().to_rfc3339()
            }
        }));

        (status, body).into_response()
    }
}
