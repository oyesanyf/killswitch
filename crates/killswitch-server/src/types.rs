//! # Request and Response Data Transfer Objects
//!
//! Serialization and deserialization models for all 15 Axum HTTP API endpoints.

use killswitch_types::status::{KillChainHealthProbeReport, KillChainStatus};
use serde::{Deserialize, Serialize};

// =============================================================================
// Containment & Status DTOs
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub isolated: bool,
    pub containment_level: String,
    pub isolated_at: Option<String>,
    pub isolated_by: Option<String>,
    pub reason: Option<String>,
    pub network_isolated: bool,
    pub processes_frozen_count: usize,
    pub processes_tarpitted_count: usize,
    pub kernel_lockdown_active: bool,
    pub allowlisted_ports: Vec<u16>,
    pub frozen_pids: Vec<u32>,
    pub state_hash_blake3: String,
    pub active_mode: String,
    pub uptime_secs: u64,
    pub version: String,
    #[serde(default)]
    pub trigger_cause: String,
    #[serde(default)]
    pub trigger_source: String,
    #[serde(default)]
    pub trigger_details: String,
    #[serde(default)]
    pub platform_os: String,
    #[serde(default)]
    pub isolation_engine: String,
    #[serde(default = "default_peers_enabled")]
    pub peers_enabled: bool,
    #[serde(default)]
    pub connected_peers_count: usize,
    #[serde(default)]
    pub connected_peer_endpoints: Vec<String>,
    #[serde(default)]
    pub tpm_present: bool,
    #[serde(default)]
    pub tpm_version: String,
    #[serde(default)]
    pub tpm_provider: String,
    #[serde(default)]
    pub tpm_interface_type: String,
    #[serde(default)]
    pub tpm_sealed: bool,
    #[serde(default)]
    pub tpm_integrity_verified: bool,
    #[serde(default)]
    pub tpm_pcr_0_7_sha256: String,
    #[serde(default)]
    pub tpm_anchored_ledger_hash: String,
    #[serde(default)]
    pub tpm_status_detail: String,
}

fn default_peers_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntryDto {
    pub index: usize,
    pub timestamp: String,
    pub action: String,
    pub operator: String,
    pub reason: String,
    pub prev_hash: String,
    pub entry_hash: String,
    pub containment_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryResponse {
    pub total_entries: usize,
    pub genesis_hash: String,
    pub latest_hash: String,
    pub chain_valid: bool,
    pub entries: Vec<HistoryEntryDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngageRequest {
    pub operator: String,
    pub reason: String,
    pub token: Option<String>,
    pub level: Option<String>,
    pub caller_pid: Option<u32>,
    /// Optional candidate YARA / detection rule that MUST pass SWE-bench `FAIL_TO_PASS` and
    /// `PASS_TO_PASS` (0 false positives on benign baseline) before engaging the KillSwitch.
    #[serde(default)]
    pub candidate_rule: Option<String>,
    #[serde(default)]
    pub task_instance_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngageResponse {
    pub success: bool,
    pub message: String,
    pub status: KillChainStatus,
    #[serde(default)]
    pub blind_killswitch_prevented: bool,
    #[serde(default)]
    pub swe_bench_report: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisarmRequest {
    pub operator: Option<String>,
    pub reason: Option<String>,
    pub token: Option<String>,
    pub caller_pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisarmResponse {
    pub success: bool,
    pub message: String,
    pub status: KillChainStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthProbeRequest {
    pub operator: Option<String>,
    pub force_rollback: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthProbeResponse {
    pub probe_report: KillChainHealthProbeReport,
    pub early_rollback_executed: bool,
    pub containment_status: KillChainStatus,
}

// =============================================================================
// Orchestrator & Mode DTOs
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GraphStepRequest {
    pub step_input: Option<serde_json::Value>,
    pub force_node: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStepResponse {
    pub executed_node: String,
    pub next_node: String,
    pub threat_score: f32,
    pub is_isolated: bool,
    pub is_paused: bool,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStateResponse {
    pub incident_id: String,
    pub current_node: String,
    pub mode: String,
    pub created_at: String,
    pub updated_at: String,
    pub aggregate_threat_score: f32,
    pub active_threats_count: usize,
    pub execution_trace_len: usize,
    pub trace_chain_valid: bool,
    pub vetoed_fraud_proofs_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeRequest {
    pub mode: String,
    pub operator: Option<String>,
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeResponse {
    pub success: bool,
    pub previous_mode: String,
    pub current_mode: String,
    pub updated_at: String,
}

// =============================================================================
// Telemetry & Octopus DTOs
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OctopusArmsResponse {
    pub total_arms: usize,
    pub master_seed_fingerprint: String,
    pub arms: Vec<serde_json::Value>,
    pub quarantined_arms: serde_json::Value,
}

fn default_event_id() -> String {
    format!("evt-{}", uuid::Uuid::new_v4())
}

fn default_event_kind() -> String {
    "ProcessCreate".to_string()
}

fn default_edr_pid() -> u32 {
    std::process::id()
}

fn default_process_name() -> String {
    "standalone_host_sensor".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrIngestRequest {
    #[serde(default = "default_event_id")]
    pub event_id: String,
    pub timestamp: Option<String>,
    #[serde(default = "default_event_kind")]
    pub event_kind: String,
    #[serde(default = "default_edr_pid")]
    pub pid: u32,
    #[serde(default = "default_process_name")]
    pub process_name: String,
    #[serde(default)]
    pub image_path: String,
    #[serde(default)]
    pub command_line: String,
    pub parent_pid: Option<u32>,
    #[serde(default)]
    pub scan_live_host: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrIngestResponse {
    pub ingested: bool,
    pub event_id: String,
    pub correlator_score: f32,
    pub threat_signal_emitted: bool,
    #[serde(default)]
    pub live_processes_scanned: usize,
    #[serde(default)]
    pub critical_anchors_verified: usize,
    #[serde(default)]
    pub standalone_mode: bool,
    #[serde(default)]
    pub summary: String,
}

// =============================================================================
// Native OS Service Lifecycle DTOs
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatusResponse {
    pub name: String,
    pub display_name: String,
    pub state: String,
    pub pid: Option<u32>,
    pub binary_path: String,
    pub is_installed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceControlRequest {
    pub action: String,
    pub service_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceControlResponse {
    pub success: bool,
    pub action: String,
    pub service_name: String,
    pub resulting_status: ServiceStatusResponse,
}

// =============================================================================
// DLP Data Lineage DTOs
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageStatusResponse {
    pub total_processes_tracked: usize,
    pub tainted_processes_count: usize,
    pub total_files_tracked: usize,
    pub tainted_files_count: usize,
    pub tainted_processes: Vec<serde_json::Value>,
    pub tainted_files: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageSeedRequest {
    pub path: String,
    pub sha256: String,
    pub classification: String,
    pub policy: String,
    pub inode_or_id: Option<u64>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub process_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageSeedResponse {
    pub success: bool,
    pub path: String,
    pub sha256: String,
    pub classification: String,
    pub policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageEvaluateRequest {
    pub pid: u32,
    pub destination_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageEvaluateResponse {
    pub verdict: String,
    pub is_block: bool,
    pub reason: Option<String>,
    pub trace_id: Option<String>,
    pub classification: Option<String>,
    pub policy: Option<String>,
    pub source_hashes: Vec<String>,
    #[serde(default)]
    pub autonomous_killswitch_triggered: bool,
    #[serde(default)]
    pub trigger_cause: Option<String>,
}

// =============================================================================
// SWE-Bench Two-Gate (`FAIL_TO_PASS` + `PASS_TO_PASS`) EDR-Bench DTOs
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrBenchEvaluateRequest {
    #[serde(default)]
    pub instance_id: Option<String>,
    /// Candidate YARA / containment rule or preset (`"overbroad_blind"`, `"surgical_verified"`).
    #[serde(default)]
    pub candidate_yara_rule: Option<String>,
    #[serde(default)]
    pub preset: Option<String>,
    /// Whether to run the compiler-in-the-loop feedback loop to refine false-positive rules.
    #[serde(default)]
    pub auto_refine: Option<bool>,
    #[serde(default)]
    pub max_iterations: Option<usize>,
    /// If true and the rule passes BOTH `FAIL_TO_PASS` and `PASS_TO_PASS` (0 FPs), engage KillSwitch.
    #[serde(default)]
    pub engage_if_promoted: Option<bool>,
}

// =============================================================================
// Connected Peers Control DTOs
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeersControlRequest {
    /// Explicit boolean (`true` = enable peers, `false` = disable & disconnect peers)
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Optional action string (`"disable"`, `"enable"`, `"toggle"`, `"disconnect"`)
    #[serde(default)]
    pub action: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeersStatusResponse {
    pub success: bool,
    pub peers_enabled: bool,
    pub connected_peers_count: usize,
    pub connected_peer_endpoints: Vec<String>,
    pub terminated_connections: usize,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmStatusResponse {
    pub success: bool,
    pub tpm_present: bool,
    pub tpm_version: String,
    pub tpm_provider: String,
    pub tpm_interface_type: String,
    pub tpm_sealed: bool,
    pub tpm_integrity_verified: bool,
    pub pcr_0_7_sha256: String,
    pub pcr_update_counter: u32,
    pub anchored_ledger_hash: String,
    pub anchored_sequence_number: u64,
    pub last_sealed_at: Option<String>,
    pub status_detail: String,
}



// =============================================================================
// NASA JPL F' (F Prime) Flight-Software Command & Telemetry DTOs
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FPrimeCommandRequest {
    /// Optional numeric opcode (`0x0100`..`0x0105`).
    #[serde(default)]
    pub opcode: Option<u32>,
    /// Optional mnemonic (`"CMD_NO_OP"`, `"CMD_PING_ALL_COMPONENTS"`, `"CMD_VERIFY_SWEBENCH_GATES"`, `"CMD_ENGAGE_SAFE_MODE"`, `"CMD_EXIT_SAFE_MODE"`).
    #[serde(default)]
    pub mnemonic: Option<String>,
}

// =============================================================================
// Conformal Sequential Detection DTOs
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConformalEvaluateRequest {
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub feature_vector: Option<Vec<f64>>,
    #[serde(default)]
    pub is_base_injection: Option<bool>,
    #[serde(default)]
    pub reset_stream: Option<bool>,
}

// =============================================================================
// Research Breakout Ingest & Google LangExtract DTOs
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResearchBreakoutExtraction {
    pub arxiv_id: String,
    pub title: String,
    pub attack_vector: String,
    pub target_boundary: String,
    #[serde(default)]
    pub evasion_technique: Option<String>,
    #[serde(default)]
    pub mitigation: Option<String>,
    #[serde(default)]
    pub source_char_start: Option<usize>,
    #[serde(default)]
    pub source_char_end: Option<usize>,
    #[serde(default)]
    pub source_quote: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResearchIngestRequest {
    #[serde(default)]
    pub extractions: Vec<ResearchBreakoutExtraction>,
    #[serde(default)]
    pub auto_synthesize_rules: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResearchCoverageReport {
    pub attack_vector: String,
    pub target_boundary: String,
    pub covered_by_killswitch: bool,
    pub active_gate: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResearchIngestResponse {
    pub success: bool,
    pub ingested_count: usize,
    pub evaluated_against_containment: bool,
    pub coverage_percentage: f64,
    pub containment_coverage: Vec<ResearchCoverageReport>,
    pub timestamp: String,
}

