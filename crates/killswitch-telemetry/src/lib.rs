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
pub mod rate_limit_backoff;
pub mod rl_traffic;
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
pub use rl_traffic::{
    query_live_os_process_sockets, run_empirical_rl_benchmark, ConfidenceInterval95,
    LearnedDestinationProfile, OsQueryProcessSocketRow, PolicyEvaluationMetrics,
    RlEmpiricalBenchmarkReport, RlPolicyPersistenceSnapshot, RlTrafficAction, RlTrafficDecision,
    RlTrafficLearner, TrafficFeatureVector, RL_ENVIRONMENT_BACKEND_LABEL,
};
pub use rate_limit_backoff::{
    calculate_exponential_backoff_ms, global_agent_velocity_limiter, global_rate_limit_ensemble,
    global_rete_engine, rfc6298_next_rto_ms, rfc6298_rto_after_attempts_ms, rfc9002_next_pto_ms,
    AgentCallRecord, AgentSessionWindow, AgentVelocityRateLimiter, AgentVelocityVerdict,
    BackoffEvaluationReport, CorrelatedEvidenceBundle, CurveFitResult, DeterministicPhysicsVoter,
    EdrAction, GenerativeLlmVoter, GoogleApiBackoffAnalyzer, HarEntrySample, HarFlowFact,
    NetworkProtocol, OpenJevDecisionVoter, OsqueryProcessFact, RateLimitAllowlist,
    RateLimitReleaseEntry, RateLimitVoterEnsemble, ReaBinaryFact, ReteEngine, VoterConsensus,
    VoterVerdict,
};
pub use watchdog::{HardwareWatchdog, MemoryPressureLevel, WatchdogConfig};
