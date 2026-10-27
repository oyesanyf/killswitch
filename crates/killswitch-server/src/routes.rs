//! # Axum Router Assembly & Middleware Stacking
//!
//! Exposes all 15 dedicated endpoints with layered security middleware.

use std::sync::Arc;
use axum::routing::{get, post};
use axum::Router;

use crate::handlers;
use crate::middleware;
use crate::server::ServerState;

pub fn build_router(state: Arc<ServerState>) -> Router {
    Router::new()
        // 0. Interactive WebUI Dashboard
        .route("/", get(crate::webui::get_webui_dashboard))
        .route("/ui", get(crate::webui::get_webui_dashboard))
        // 1. Containment & Status
        .route("/status", get(handlers::get_status))
        .route("/history", get(handlers::get_history))
        .route("/engage", post(handlers::post_engage))
        .route("/disarm", post(handlers::post_disarm))
        .route("/health-probe", post(handlers::post_health_probe))
        // 2. Orchestrator & Mode
        .route("/graph/step", post(handlers::post_graph_step))
        .route("/graph/state", get(handlers::get_graph_state))
        .route("/mode", post(handlers::post_mode))
        // 3. Telemetry & Octopus
        .route("/octopus/arms", get(handlers::get_octopus_arms))
        .route("/edr/ingest", post(handlers::post_edr_ingest))
        // 4. Native OS Service Lifecycle
        .route("/service/status", get(handlers::get_service_status))
        .route("/service/control", post(handlers::post_service_control))
        // 5. DLP Data Lineage Engine
        .route("/lineage/status", get(handlers::get_lineage_status))
        .route("/lineage/seed", post(handlers::post_lineage_seed))
        .route("/lineage/evaluate", post(handlers::post_lineage_evaluate))
        // 6. SWE-Bench Two-Gate (`FAIL_TO_PASS` + `PASS_TO_PASS`) Anti-Blind-KillSwitch Harness
        .route("/api/edr-bench/tasks", get(handlers::get_edr_bench_tasks))
        .route("/edr-bench/tasks", get(handlers::get_edr_bench_tasks))
        .route("/api/killswitch-bench/tasks", get(handlers::get_edr_bench_tasks))
        .route("/api/edr-bench/evaluate", post(handlers::post_edr_bench_evaluate))
        .route("/edr-bench/evaluate", post(handlers::post_edr_bench_evaluate))
        .route("/api/killswitch-bench/evaluate", post(handlers::post_edr_bench_evaluate))
        // 7. Connected Peers Inspection & 1-Click Disable/Enable Control
        .route("/peers/status", get(handlers::get_peers_status))
        .route("/api/peers/status", get(handlers::get_peers_status))
        .route("/peers/control", post(handlers::post_peers_control))
        .route("/api/peers/control", post(handlers::post_peers_control))
        // 8. Native TPM 2.0 Hardware Security & PCR Attestation
        .route("/tpm/status", get(handlers::get_tpm_status))
        .route("/api/tpm/status", get(handlers::get_tpm_status))
        .route("/tpm/seal", post(handlers::post_tpm_seal))
        .route("/api/tpm/seal", post(handlers::post_tpm_seal))
        // 9. NASA JPL F' (F Prime) Flight-Software Component & Rate-Group Supervision
        .route("/fprime/status", get(handlers::get_fprime_status))
        .route("/api/fprime/status", get(handlers::get_fprime_status))
        .route("/fprime/dispatch", post(handlers::post_fprime_dispatch))
        .route("/api/fprime/dispatch", post(handlers::post_fprime_dispatch))
        // Middleware Layers (applied bottom-up)
        .layer(middleware::cors_layer())
        .layer(middleware::body_limit_layer(state.config.max_body_bytes))
        .layer(middleware::trace_layer())
        .with_state(state)
}
