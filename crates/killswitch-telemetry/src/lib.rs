//! # `killswitch-telemetry`
//!
//! Enterprise EDR Telemetry, Nonlinear Phase-Lock Lyapunov Divergence Monitor,
//! Causal and Attack Graphs, Canaries/Watchdog/Honeytokens, Octopus Multi-Ring
//! Agent Containment, Oso 3-Way Intersection + AWS R1-R5 Containment KillSwitch,
//! Bounded Agents APC (`arXiv:2608.15888`), Tamper Guard, Cognitive Red-Team HITL,
//! Signed Ring-0 Kernel Driver Loader (`ELAM / Minifilter / eBPF`), Distributed
//! Multi-Node Raft/Valkey Consensus Storage, and 100% OpenTelemetry & OpenLineage
//! DLP Data Lineage Engine.

pub mod attack;
pub mod bounded_agents_apc;
pub mod cage_governance;
pub mod canary;
pub mod causal;
pub mod continuous_defense;
pub mod correlator;
pub mod distributed_consensus;
pub mod edr_behavioral;
pub mod honeytokens;
pub mod jcs;
pub mod octopus;
pub mod oso_aws_containment;
pub mod otel_lineage;
pub mod phaselock;
pub mod rate_limit_backoff;
pub mod ring0_driver_loader;
pub mod rl_traffic;
pub mod tamper_and_process_killswitch;
pub mod watchdog;

// Re-exports for clean ergonomics
pub use attack::{
    AttackGraphMatcher, AttackPattern, AttackSequenceEvaluation, AttackStage, ProcessTimelineEvent,
};
pub use bounded_agents_apc::{
    bounded_agents_apc_cedar_policies, classify_action_class, compute_action_hash,
    compute_hmac_sha256_hex, default_enterprise_apc_scope, global_apc_pdp,
    resource_pattern_matches, ApcActionRequest, ApcDecision, ApcPolicyDecisionPoint, ApcScope,
    ApcStatusSummary, ApprovalToken, AuthorizationEnvelope, BudgetState, CompositionChecker,
    DelegationBudgetSpec, EnvelopeSealedError, EvidenceRecord, EvidenceSink, ExecutedActionEvent,
    IntentEnforcementMode, IntentSpec, KTupleRestriction, KTupleStep, PairwiseRestriction,
};
pub use cage_governance::{
    export_cage_governance_trace_v1, global_cage_kernel, AtomicFiscalBarrier, CageDecisionReceipt,
    CageEvidenceEntry, CageEvidenceWriter, CageEvaluationRequest, CageEvaluationResponse,
    CageGovernanceKernel, CageKernelStatusReport, CageTier, CageTraceVerifier, CageVerdict,
    CageWarrantToken, CompiledSubstrateArtifact, Cumulative24hTracker, FinanceBoundingBarrier,
    GovernanceTraceEvent, GovernanceTraceEventType, HealthcareDoseBarrier, HitlConsensusApproval,
    KeyedCumulative24hTracker, SubstrateCompiler, SubstrateFormat, SubstrateNorm,
    TraceConformanceReport, CTRL_CBF_DOSE_001, CTRL_CBF_FINANCE_001, CTRL_CONF_001,
    CTRL_CONSENSUS_REQUIRED, CTRL_FTRA_001, CTRL_OPA_005, CTRL_STPA_UCA1, CTRL_STPA_UCA2,
    CTRL_STPA_UCA3, CTRL_STPA_UCA4, CTRL_WARRANT_INVALID, CTRL_WARRANT_REQUIRED,
    FISCAL_CAP_EXCEEDED,
};
pub use jcs::{canonicalize_jcs, canonicalize_jcs_string, JcsError};
pub use canary::{CanaryAuditReport, CanaryDecoyFile, CanaryManager};
pub use causal::{CausalEdge, CausalEdgeKind, CausalNodeType, CausalSecurityGraph};
pub use continuous_defense::{
    canonical_research_rule_id, clear_all_ingested_research_rules,
    detect_verified_code_repo_from_texts, global_continuous_defense, is_current_research_arxiv_id,
    list_ingested_research_rules, normalize_base_arxiv_id, register_ingested_research_rule,
    remove_ingested_research_rule, restore_default_research_rules, run_paper2agent_accuracy_suite,
    safe_arxiv_abs_url, synthesize_rust_guard_snippet, validate_research_rule_acceptance,
    BoundaryDirection, BoundaryInspectionVerdict, BoundaryViolationIncident,
    BreakoutTaxonomyCategory, ContinuousDefenseEngine, IngestedResearchDefenseRule,
    LlmFusionArmReport, OperationalResilienceReport, OperationalResilienceTracker,
    Paper2AgentAccuracySuiteResult, ResearchAcceptanceVerdict, RuleAccuracyReport,
    CODE_REPO_PRIORITY_BOOST,
};
pub use correlator::{EventCorrelator, ProcessCorrelationContext};
pub use distributed_consensus::{
    command_to_resp_tokens, encode_resp_command, global_consensus_cluster,
    ClusterLineageTaintRecord, ConsensusCommand, ConsensusProposalOutcome,
    DistributedConsensusStatus, QuorumNodeVote, RaftClusterCoordinator, RaftLogEntry, RaftPeerNode,
    RaftRole, RequestVoteRequest, RequestVoteResponse, CLUSTER_FISCAL_CAP_EXCEEDED,
};
pub use edr_behavioral::{
    evaluate_deterministic_mitre_ioas, global_edr_behavioral_engine, AccountRole,
    BaselineAnomalyDeviation, EdrBehavioralEngine, EdrBehavioralStatusReport, EdrContainmentAction,
    EdrSensorTelemetryEvent, EdrThreatNarrative, LineageChainViolation, MitreIoaFinding,
    OsSensorMechanism, ProcessLineageNode, StatefulProcessLineageTree, WelfordBaselineMetric,
};
pub use honeytokens::{HoneytokenManager, HoneytokenRecord, HoneytokenType, NativeEphemeralTrap};
pub use octopus::{
    validate_egress_url, validate_sandbox_path, ArmContainmentRing, ArmRingConfig,
    ArmRingRegistry, ArmState, BehavioralBreakoutVerdict, BreakoutDefenseCoordinator,
    CapabilityToken, DataBreakoutVerdict, HomologicalAuditReport, HomologicalBoundaryAuditor,
    MeshGuard, MeshWatchOutSignal, OperationalContainmentVerdict, TechnicalBreakoutVerdict,
    UnifiedBreakoutEvaluation, VerifiedMeshMessage,
};
pub use oso_aws_containment::{
    action_requires_hitl_step_up, default_compliant_containment_snapshot,
    global_oso_aws_containment, issue_hitl_step_up_ticket, role_static_capabilities,
    verify_hitl_step_up_ticket, AgentClusterServiceState, ContainmentEnvironmentSnapshot,
    DelegatingUserContext, HitlStepUpTicket, KillSwitchTerminationReport, OsoAuthzDecision,
    OsoAwsContainmentEngine, OsoAwsContainmentStatusReport, RagDocumentChunk, RagFilterResult,
    RouteTableEntry, SecurityGroupEgressRule, TaskScopeEnvelope, WatchdogAssessmentReport,
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
pub use ring0_driver_loader::{
    build_canonical_ebpf_elf_object, build_canonical_signed_pe_sys_image, global_ring0_manager,
    query_live_host_ring0_inventory, verify_linux_ebpf_elf_binary, verify_windows_pe_sys_binary,
    EbpfElfVerificationReport, EdrArchitectureClassification, HostKernelDriverInventory,
    PeSysVerificationReport, Ring0DeploymentManager, Ring0DriverStatusReport,
    Ring0KernelEventFrame, Ring0Posture, KILLSWITCH_BPFFS_PIN_ROOT, KILLSWITCH_MINIFILTER_ALTITUDE,
    KILLSWITCH_MINIFILTER_PORT,
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
pub use tamper_and_process_killswitch::{
    begin_database_maintenance_lease, compute_hardened_console_mode,
    compute_maintenance_auth_token, evaluate_hitl_card, expected_blast_radius_token,
    flush_console_input, get_tamper_guard_status, global_agent_process_table,
    global_cognitive_redteam, harden_windows_console, is_console_mode_hardened,
    is_maintenance_window_active, scan_for_visual_deception, AgentProcess, AgentStatus,
    BlastRadiusDiff, CognitiveRedTeamAssessment, CognitiveRedTeamInterceptor,
    CognitiveRedTeamStatus, EdrExecutableTamperGuard, HitlApprovalReceipt, HitlApprovalState,
    HitlCardEvaluation, HitlDeceptionIndicator, IrreversibleMutationType, IrreversibleStateChange,
    LocalMySqlTamperGuard, MaintenanceLeaseGuard, MeshTaintLevel, PendingExecutionGraphNode,
    PolymorphicChallenge, PolymorphicChallengePublic, ProcessTable, StoredPendingHitlAction,
    TamperCheckOutcome, TamperGuardStatusReport, KILLSWITCH_ACTIVE,
};
pub use watchdog::{HardwareWatchdog, MemoryPressureLevel, WatchdogConfig};
