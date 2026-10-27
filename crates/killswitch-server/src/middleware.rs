//! # Axum Middleware Layers
//!
//! Provides CORS headers, body limits, and request tracing.

use axum::extract::DefaultBodyLimit;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

pub fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
}

pub fn body_limit_layer(max_body_bytes: usize) -> DefaultBodyLimit {
    DefaultBodyLimit::max(max_body_bytes)
}

pub fn trace_layer() -> TraceLayer<tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>> {
    TraceLayer::new_for_http()
}
