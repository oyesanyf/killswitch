//! # `killswitch-server`
//!
//! Local Axum HTTP Control & Telemetry API Server (Port 3030).
//!
//! Features:
//! - 15 dedicated endpoints covering containment, history, health probes, orchestrator, EDR, Octopus, services, and DLP lineage
//! - Loopback and port 3030 preservation during full network containment
//! - Anti-lockout rate-limiting and caller PID validation
//! - Zero external OS command subprocess spawning

pub mod error;
pub mod handlers;
pub mod middleware;
pub mod orchestrator_bridge;
pub mod routes;
pub mod server;
pub mod types;
pub mod webui;

// Re-exports
pub use error::ServerError;
pub use orchestrator_bridge::{InMemoryOrchestratorBridge, OrchestratorBridge};
pub use routes::build_router;
pub use server::{run_server, AppState, KillSwitchServer, ServerConfig, ServerState};
pub use types::*;
