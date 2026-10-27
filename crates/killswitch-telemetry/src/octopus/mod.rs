//! # Octopus Multi-Ring Agent Containment & Breakout Defense
//!
//! Submodules:
//! - `arm_ring`: Level 1 Arm Containment Ring, Surgical Autotomy & Registry
//! - `mesh_guard`: Neural MeshGuard, Homological Boundary Audit ($\partial^2 = 0$) & Sticky Taint
//! - `breakout`: 4-Category Breakout Defense Coordinator, Mathematical SSRF & Safe Path Sandboxing

pub mod arm_ring;
pub mod breakout;
pub mod mesh_guard;

pub use arm_ring::{
    ArmContainmentRing, ArmRingConfig, ArmRingRegistry, ArmState, CapabilityToken,
    MeshWatchOutSignal,
};
pub use breakout::{
    validate_egress_url, validate_sandbox_path, BehavioralBreakoutVerdict,
    BreakoutDefenseCoordinator, DataBreakoutVerdict, OperationalContainmentVerdict,
    TechnicalBreakoutVerdict, UnifiedBreakoutEvaluation,
};
pub use mesh_guard::{
    HomologicalAuditReport, HomologicalBoundaryAuditor, MeshGuard, VerifiedMeshMessage,
};
