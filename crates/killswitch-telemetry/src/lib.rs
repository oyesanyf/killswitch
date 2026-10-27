//! # `killswitch-telemetry`
//!
//! Enterprise EDR Telemetry, Nonlinear Phase-Lock Lyapunov Divergence Monitor,
//! Causal and Attack Graphs, Canaries/Watchdog/Honeytokens, Octopus Multi-Ring
//! Agent Containment, and 100% OpenTelemetry & OpenLineage DLP Data Lineage Engine.

pub mod attack;
pub mod canary;
pub mod causal;
pub mod correlator;
pub mod honeytokens;
pub mod octopus;
pub mod otel_lineage;
pub mod phaselock;
pub mod watchdog;

// Re-exports for clean ergonomics
pub use attack::{
    AttackGraphMatcher, AttackPattern, AttackSequenceEvaluation, AttackStage, ProcessTimelineEvent,
};
pub use canary::{CanaryAuditReport, CanaryDecoyFile, CanaryManager};
pub use causal::{CausalEdge, CausalEdgeKind, CausalNodeType, CausalSecurityGraph};
pub use correlator::{EventCorrelator, ProcessCorrelationContext};
pub use honeytokens::{HoneytokenManager, HoneytokenRecord, HoneytokenType, NativeEphemeralTrap};
pub use octopus::{
    validate_egress_url, validate_sandbox_path, ArmContainmentRing, ArmRingConfig,
    ArmRingRegistry, ArmState, BehavioralBreakoutVerdict, BreakoutDefenseCoordinator,
    CapabilityToken, DataBreakoutVerdict, HomologicalAuditReport, HomologicalBoundaryAuditor,
    MeshGuard, MeshWatchOutSignal, OperationalContainmentVerdict, TechnicalBreakoutVerdict,
    UnifiedBreakoutEvaluation, VerifiedMeshMessage,
};
pub use otel_lineage::{
    DatasetRole, DlpClassification, DlpPolicy, EgressVerdict, EndpointLineageEngine, FileKey,
    FileTaintState, LineageEngineConfig, OpenLineageDataset, OpenLineageDatasetFacets, ProcessKey,
    ProcessTaintState, TaintBaggage, W3cTraceContext,
};
pub use phaselock::{
    compute_shannon_entropy, compute_syscall_phase_metric, PerPidPhaseLockMonitor,
    PhaseLockManager, PhaseSpaceConfig, PhaseSpaceVerdict,
};
pub use watchdog::{HardwareWatchdog, MemoryPressureLevel, WatchdogConfig};
