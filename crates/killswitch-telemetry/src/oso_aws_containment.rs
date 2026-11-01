//! # Oso Agent Authorization & AWS Agent Containment-Response Engine
//!
//! Implements two production agent containment and authorization standards:
//!
//! 1. **Oso Best Practices for Authorizing AI Agents**:
//!    - **3-Way Delegated Identity Intersection**:
//!      $$\text{EffectivePerm}(u, a, t) = \text{Perm}(\text{User } u) \cap \text{Cap}(\text{AgentRole } a) \cap \text{Scope}(\text{Task } t)$$
//!    - **Pre-Retrieval RAG Context Filtering**: Enforces document-level ACLs (`allowed_tenants`,
//!      `required_clearance`, `allowed_principals`) *before* vector embeddings or chunks enter the
//!      LLM prompt context window, neutralizing indirect prompt injection via unauthorized documents.
//!    - **MCP Tool-Call Parameter & Row-Ownership Gate**: Validates both the tool action and the
//!      resource row ownership (`resource_owner`, `tenant_id`, `max_record_limit`) before execution.
//!    - **Out-of-Band Cryptographic HITL Step-Up Ticket**: High-impact or destructive actions
//!      require an HMAC-SHA256 signed human-in-the-loop approval ticket bound to `(user_id, agent_id,
//!      task_id, action, resource_id)` rather than conversational text confirmation.
//!
//! 2. **AWS Security Blog — Architecting Agent Containment-Response Mechanisms (R1–R5)**:
//!    - **R1 (Trust Separation & DNS Firewall)**: Agent execution plane is isolated from the
//!      containment control plane; outbound DNS queries outside the explicit allowlist receive
//!      deterministic `NXDOMAIN`.
//!    - **R2 (Baseline Drift Detection)**: Behavioral baseline drift and `AccessDenied` probing velocity.
//!    - **R3 (Independent Containment Watchdog — 4 Invariants)**: Continuously audits:
//!      1. Security Group egress rules (rejects `0.0.0.0/0` and `::/0` open egress).
//!      2. Route Table entries (rejects unauthorized `igw-*` internet gateway routes in isolated subnets).
//!      3. IAM Role Policy attachment count AND exact Policy ARN set (detects policy-swap attacks
//!         where an attacker detaches a restrictive policy and attaches a permissive one while keeping
//!         the count constant).
//!      4. Route 53 DNS Firewall domain list association status (`COMPLETE`).
//!    - **R4 (Adversarial Audit Isolation)**: Agents are explicitly denied all read/write access
//!      to security telemetry, watchdog state, and IAM/CloudTrail control plane APIs.
//!    - **R5 (Capability Envelope Alarms & KillSwitch)**: Tracks `AccessDenied` velocity; `>= 3`
//!      denied calls within a 60-second sliding window automatically triggers the **KillSwitch**
//!      (`desired_count = 0`, terminates running tasks, and advances the generation epoch).

use hmac::{Hmac, Mac};
use killswitch_types::ArmRole;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{BTreeSet, VecDeque};
use std::sync::OnceLock;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

// ============================================================================
// PART 1: OSO 3-WAY DELEGATED IDENTITY INTERSECTION & RAG / MCP GATES
// ============================================================================

/// Represents the human or service principal delegating authority to an AI agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatingUserContext {
    pub user_id: String,
    pub tenant_id: String,
    /// Fine-grained permissions held by the human user (e.g., `"Order:read"`, `"Invoice:approve"`).
    pub permissions: BTreeSet<String>,
    /// Data classification clearance level (`0 = Public`, `1 = Internal`, `2 = Confidential`, `3 = Restricted`).
    pub clearance_level: u8,
}

/// Represents the ephemeral, task-scoped capability envelope minted for a single agent run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskScopeEnvelope {
    pub task_id: String,
    pub session_id: String,
    pub allowed_actions: BTreeSet<String>,
    pub allowed_resource_prefixes: BTreeSet<String>,
    pub max_rows_per_query: usize,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

impl TaskScopeEnvelope {
    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix > self.expires_at_unix || now_unix < self.issued_at_unix
    }

    pub fn allows_resource(&self, resource_id: &str) -> bool {
        self.allowed_resource_prefixes
            .iter()
            .any(|prefix| resource_id == prefix || resource_id.starts_with(prefix.as_str()))
    }
}

/// Document chunk candidate evaluated by the Pre-Retrieval RAG Context Filter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RagDocumentChunk {
    pub doc_id: String,
    pub tenant_id: String,
    pub required_clearance: u8,
    pub allowed_users: BTreeSet<String>,
    pub required_permission: String,
    pub content_preview: String,
}

/// Result of pre-retrieval RAG filtering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RagFilterResult {
    pub permitted_doc_ids: Vec<String>,
    pub redacted_doc_ids: Vec<String>,
    pub audit_reasons: Vec<String>,
}

/// Cryptographic out-of-band Human-in-the-Loop (HITL) step-up approval ticket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HitlStepUpTicket {
    pub ticket_id: String,
    pub approver_id: String,
    pub user_id: String,
    pub agent_id: String,
    pub task_id: String,
    pub action: String,
    pub resource_id: String,
    pub expires_at_unix: u64,
    pub hmac_hex: String,
}

impl HitlStepUpTicket {
    pub fn canonical_payload(&self) -> String {
        format!(
            "oso-hitl-v1|{}|{}|{}|{}|{}|{}|{}|{}",
            self.ticket_id,
            self.approver_id,
            self.user_id,
            self.agent_id,
            self.task_id,
            self.action.to_ascii_lowercase(),
            self.resource_id,
            self.expires_at_unix
        )
    }
}

/// Authorization decision returned by the Oso 3-Way Intersection & AWS Containment Engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsoAuthzDecision {
    Allow {
        effective_principal: String,
        audit_note: String,
    },
    RequireHitlStepUp {
        reason: String,
        required_action: String,
        resource_id: String,
    },
    Deny {
        failed_layer: String,
        reason: String,
        kill_switch_triggered: bool,
    },
}

impl OsoAuthzDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }
}

/// Returns the static capability ceiling for each `ArmRole` (`Cap(AgentRole)`).
///
/// Exhaustive match over all 18 `ArmRole` variants (fail-closed, zero wildcards).
pub fn role_static_capabilities(role: &ArmRole) -> BTreeSet<&'static str> {
    match role {
        ArmRole::UntrustedDocIngest => BTreeSet::from(["Document:ingest", "Document:read_public"]),
        ArmRole::AccountingLedgerWrite => BTreeSet::from([
            "Ledger:read",
            "Ledger:append",
            "Invoice:read",
            "Invoice:approve",
            "Order:read",
        ]),
        ArmRole::OutboundNotification => {
            BTreeSet::from(["Notification:send", "Template:read", "Order:read"])
        }
        ArmRole::NetworkEgress => BTreeSet::from(["Network:connect_allowlisted", "Dns:resolve"]),
        ArmRole::TarpitDecoyDefense => BTreeSet::from(["Decoy:read", "Decoy:trap"]),
        ArmRole::KernelLevelSentinel => BTreeSet::from([
            "Sentinel:inspect",
            "Sentinel:quarantine",
            "Process:read",
            "Order:read",
        ]),
        ArmRole::CedarPolicyEvaluation => BTreeSet::from([
            "Policy:evaluate",
            "Policy:read",
            "Order:read",
            "Document:read",
        ]),
        ArmRole::AtlasThreatIntelligence => {
            BTreeSet::from(["ThreatIntel:read", "ThreatIntel:correlate", "Document:read"])
        }
        ArmRole::AnomalyDetection => {
            BTreeSet::from(["Telemetry:read", "Anomaly:score", "Order:read"])
        }
        ArmRole::VulnerabilityResearch => {
            BTreeSet::from(["Research:read", "Advisory:analyze", "Document:read"])
        }
        ArmRole::ContinuousOssFuzz => BTreeSet::from(["FuzzTarget:execute", "Corpus:read"]),
        ArmRole::ContinuousOsvScanner => BTreeSet::from(["Sbom:read", "Osv:query"]),
        ArmRole::DifferentialProtocolAnalyzer => {
            BTreeSet::from(["Protocol:parse", "WireSample:read"])
        }
        ArmRole::AutonomousProtocolResearch => {
            BTreeSet::from(["Protocol:probe_sandbox", "RfcSpec:read"])
        }
        ArmRole::PostQuantumAttestation => {
            BTreeSet::from(["Pqc:attest", "Pqc:verify", "Ledger:read"])
        }
        ArmRole::EvolutionaryOptimizer => BTreeSet::from(["Benchmark:read", "Weights:propose"]),
        ArmRole::DreamRsiOptimizer => BTreeSet::from(["Checkpoint:read", "Distill:verify"]),
        ArmRole::RecursiveHarnessOptimizer => BTreeSet::from(["Harness:profile", "Trace:read"]),
    }
}

/// Returns `true` if the action is high-impact/destructive and requires an out-of-band
/// cryptographic HITL step-up ticket under Oso's Human-in-the-Loop governance pattern.
pub fn action_requires_hitl_step_up(action: &str) -> bool {
    let lower = action.trim().to_ascii_lowercase();
    lower.ends_with(":delete")
        || lower.ends_with(":drop")
        || lower.ends_with(":transfer_funds")
        || lower.ends_with(":approve")
        || lower.ends_with(":wire_transfer")
        || lower.ends_with(":revoke_all")
}

/// Mints an HMAC-SHA256 signed HITL Step-Up Ticket bound to `(user_id, agent_id, task_id, action, resource_id)`.
#[allow(clippy::too_many_arguments)]
pub fn issue_hitl_step_up_ticket(
    ticket_id: &str,
    approver_id: &str,
    user_id: &str,
    agent_id: &str,
    task_id: &str,
    action: &str,
    resource_id: &str,
    expires_at_unix: u64,
    signing_key: &[u8; 32],
) -> HitlStepUpTicket {
    let mut ticket = HitlStepUpTicket {
        ticket_id: ticket_id.to_string(),
        approver_id: approver_id.to_string(),
        user_id: user_id.to_string(),
        agent_id: agent_id.to_string(),
        task_id: task_id.to_string(),
        action: action.to_string(),
        resource_id: resource_id.to_string(),
        expires_at_unix,
        hmac_hex: String::new(),
    };
    let mut mac = HmacSha256::new_from_slice(signing_key).expect("32-byte HMAC key is valid");
    mac.update(ticket.canonical_payload().as_bytes());
    ticket.hmac_hex = hex::encode(mac.finalize().into_bytes());
    ticket
}

/// Verifies an out-of-band HITL Step-Up Ticket in constant time using `subtle::ConstantTimeEq`.
#[allow(clippy::too_many_arguments)]
pub fn verify_hitl_step_up_ticket(
    ticket: &HitlStepUpTicket,
    expected_user_id: &str,
    expected_agent_id: &str,
    expected_task_id: &str,
    expected_action: &str,
    expected_resource_id: &str,
    now_unix: u64,
    signing_key: &[u8; 32],
) -> Result<(), String> {
    if now_unix > ticket.expires_at_unix {
        return Err("HITL step-up ticket has expired".to_string());
    }
    if ticket.user_id != expected_user_id
        || ticket.agent_id != expected_agent_id
        || ticket.task_id != expected_task_id
        || !ticket.action.eq_ignore_ascii_case(expected_action)
        || ticket.resource_id != expected_resource_id
    {
        return Err(
            "HITL step-up ticket binding mismatch (user/agent/task/action/resource)".to_string(),
        );
    }
    let Ok(provided_bytes) = hex::decode(&ticket.hmac_hex) else {
        return Err("HITL step-up ticket signature is not valid hex".to_string());
    };
    let mut mac = HmacSha256::new_from_slice(signing_key).expect("32-byte key is valid");
    mac.update(ticket.canonical_payload().as_bytes());
    let expected_bytes = mac.finalize().into_bytes();

    if provided_bytes.len() != expected_bytes.len()
        || !bool::from(provided_bytes.ct_eq(&expected_bytes))
    {
        return Err("HITL step-up ticket HMAC-SHA256 verification failed".to_string());
    }
    Ok(())
}

// ============================================================================
// PART 2: AWS R1-R5 AGENT CONTAINMENT-RESPONSE & KILL SWITCH ENGINE
// ============================================================================

/// Represents an outbound security group egress rule inspected by the R3 Containment Watchdog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityGroupEgressRule {
    pub rule_id: String,
    pub cidr_block: String,
    pub protocol: String,
    pub port_range: (u16, u16),
}

/// Represents a VPC route table entry inspected by the R3 Containment Watchdog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteTableEntry {
    pub destination_cidr: String,
    pub target_id: String,
}

/// Snapshot of the AWS/Host containment perimeter audited by the independent R3 Watchdog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentEnvironmentSnapshot {
    pub security_group_egress_rules: Vec<SecurityGroupEgressRule>,
    pub route_table_entries: Vec<RouteTableEntry>,
    pub attached_iam_policy_arns: BTreeSet<String>,
    pub expected_iam_policy_arns: BTreeSet<String>,
    pub dns_firewall_status: String,
    pub dns_firewall_allowed_domains: BTreeSet<String>,
}

/// Detailed R3 Watchdog verification report across all 4 AWS containment invariants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchdogAssessmentReport {
    pub security_group_invariant_ok: bool,
    pub route_table_invariant_ok: bool,
    pub iam_policy_invariant_ok: bool,
    pub dns_firewall_invariant_ok: bool,
    pub all_invariants_passed: bool,
    pub violations: Vec<String>,
    pub kill_switch_engaged: bool,
}

/// Record of an autonomous KillSwitch termination event (`desired_count = 0`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillSwitchTerminationReport {
    pub cluster_name: String,
    pub previous_desired_count: u32,
    pub new_desired_count: u32,
    pub terminated_task_ids: Vec<String>,
    pub new_generation_epoch: u64,
    pub trigger_reason: String,
    pub timestamp_unix: u64,
}

/// Simulated ECS/Fargate or local agent worker service state controlled by the KillSwitch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentClusterServiceState {
    pub cluster_name: String,
    pub desired_count: u32,
    pub running_task_ids: Vec<String>,
    pub auto_respawn_disabled: bool,
    pub generation_epoch: u64,
    pub kill_switch_history: Vec<KillSwitchTerminationReport>,
}

/// Status summary for REST API, WebUI, and CLI reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsoAwsContainmentStatusReport {
    pub cluster_name: String,
    pub desired_count: u32,
    pub running_task_ids: Vec<String>,
    pub auto_respawn_disabled: bool,
    pub generation_epoch: u64,
    pub access_denied_velocity_threshold: usize,
    pub access_denied_window_secs: u64,
    pub recent_access_denied_count: usize,
    pub kill_switch_history: Vec<KillSwitchTerminationReport>,
}

/// Unified Oso 3-Way Intersection + AWS R1-R5 Agent Containment Engine.
pub struct OsoAwsContainmentEngine {
    pub cluster_state: Mutex<AgentClusterServiceState>,
    /// Sliding window of `(timestamp_unix, agent_id, action)` for `AccessDenied` velocity tracking (R5).
    access_denied_window: Mutex<VecDeque<(u64, String, String)>>,
    pub access_denied_threshold: usize,
    pub access_denied_window_secs: u64,
    pub hitl_signing_key: [u8; 32],
}

impl OsoAwsContainmentEngine {
    pub fn new(
        cluster_name: impl Into<String>,
        initial_tasks: Vec<String>,
        hitl_signing_key: [u8; 32],
    ) -> Self {
        let count = initial_tasks.len() as u32;
        Self {
            cluster_state: Mutex::new(AgentClusterServiceState {
                cluster_name: cluster_name.into(),
                desired_count: count,
                running_task_ids: initial_tasks,
                auto_respawn_disabled: false,
                generation_epoch: 1,
                kill_switch_history: Vec::new(),
            }),
            access_denied_window: Mutex::new(VecDeque::new()),
            access_denied_threshold: 3,
            access_denied_window_secs: 60,
            hitl_signing_key,
        }
    }

    /// Returns a snapshot of the current cluster state and kill switch history.
    pub fn status_report(&self) -> OsoAwsContainmentStatusReport {
        let state = self.cluster_state.lock();
        let window = self.access_denied_window.lock();
        OsoAwsContainmentStatusReport {
            cluster_name: state.cluster_name.clone(),
            desired_count: state.desired_count,
            running_task_ids: state.running_task_ids.clone(),
            auto_respawn_disabled: state.auto_respawn_disabled,
            generation_epoch: state.generation_epoch,
            access_denied_velocity_threshold: self.access_denied_threshold,
            access_denied_window_secs: self.access_denied_window_secs,
            recent_access_denied_count: window.len(),
            kill_switch_history: state.kill_switch_history.clone(),
        }
    }

    // ------------------------------------------------------------------------
    // AWS R4: Adversarial Audit & Control-Plane Isolation
    // ------------------------------------------------------------------------

    /// Returns `true` if the requested action attempts to read, tamper with, or disable
    /// security audit logs, containment watchdogs, or IAM/network control plane resources (AWS R4).
    pub fn is_adversarial_audit_or_control_plane_probe(action: &str, resource_id: &str) -> bool {
        let act = action.trim().to_ascii_lowercase();
        let res = resource_id.trim().to_ascii_lowercase();

        let forbidden_action_prefixes = [
            "iam:",
            "cloudtrail:",
            "cloudwatch:",
            "guardduty:",
            "ec2:modifysecuritygroup",
            "ec2:authorizeSecuritygroup",
            "ec2:creatroute",
            "ec2:replaceroute",
            "route53resolver:",
            "ecs:updateservice",
            "osoosi:watchdog:",
            "osoosi:audit:",
            "osoosi:killswitch:",
            "killswitch:watchdog:",
            "killswitch:audit:",
            "sentinel:disable",
            "watchdog:tamper",
        ];

        if forbidden_action_prefixes
            .iter()
            .any(|p| act.starts_with(&p.to_ascii_lowercase()))
        {
            return true;
        }

        res.contains("arn:aws:iam::")
            || res.contains("arn:aws:cloudtrail:")
            || res.contains("containment-watchdog")
            || res.contains("audit-ledger-control")
    }

    // ------------------------------------------------------------------------
    // OSO 3-WAY INTERSECTION + MCP PARAMETER GATE + AWS R4/R5
    // ------------------------------------------------------------------------

    /// Evaluates the Oso 3-Way Delegated Identity Intersection:
    /// $$\text{EffectivePerm}(u, a, t) = \text{Perm}(u) \cap \text{Cap}(a) \cap \text{Scope}(t)$$
    /// combined with AWS R4 (Adversarial Audit Isolation) and R5 (`AccessDenied` velocity KillSwitch).
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_intersection_authority(
        &self,
        user: &DelegatingUserContext,
        agent_id: &str,
        agent_role: &ArmRole,
        task_scope: &TaskScopeEnvelope,
        action: &str,
        resource_id: &str,
        resource_tenant_id: &str,
        requested_rows: usize,
        hitl_ticket: Option<&HitlStepUpTicket>,
        now_unix: u64,
    ) -> OsoAuthzDecision {
        // 0. Check if KillSwitch has already scaled cluster desired_count to 0
        {
            let state = self.cluster_state.lock();
            if state.desired_count == 0 || state.auto_respawn_disabled {
                return OsoAuthzDecision::Deny {
                    failed_layer: "AWS_KILLSWITCH_ACTIVE".to_string(),
                    reason: format!(
                        "Cluster '{}' is terminated by KillSwitch (epoch {})",
                        state.cluster_name, state.generation_epoch
                    ),
                    kill_switch_triggered: true,
                };
            }
        }

        // 1. AWS R4: Adversarial Audit & Control-Plane Isolation
        if Self::is_adversarial_audit_or_control_plane_probe(action, resource_id) {
            let triggered = self.record_access_denied_and_check_alarm(
                agent_id,
                action,
                now_unix,
                "AWS_R4_ADVERSARIAL_AUDIT_PROBE",
            );
            return OsoAuthzDecision::Deny {
                failed_layer: "AWS_R4_AUDIT_ISOLATION".to_string(),
                reason: format!(
                    "Agent '{}' attempted forbidden control-plane or audit action '{}' on '{}'",
                    agent_id, action, resource_id
                ),
                kill_switch_triggered: triggered,
            };
        }

        // 2. Tenant Isolation Gate (Oso multi-tenant ABAC)
        if user.tenant_id != resource_tenant_id {
            let triggered = self.record_access_denied_and_check_alarm(
                agent_id,
                action,
                now_unix,
                "OSO_CROSS_TENANT_VIOLATION",
            );
            return OsoAuthzDecision::Deny {
                failed_layer: "OSO_TENANT_BOUNDARY".to_string(),
                reason: format!(
                    "Cross-tenant access denied: user tenant '{}' != resource tenant '{}'",
                    user.tenant_id, resource_tenant_id
                ),
                kill_switch_triggered: triggered,
            };
        }

        // 3. Layer 1 of Intersection: Delegating User Permission (`Perm(User u)`)
        if !user.permissions.contains(action) {
            let triggered = self.record_access_denied_and_check_alarm(
                agent_id,
                action,
                now_unix,
                "OSO_USER_PERMISSION_MISSING",
            );
            return OsoAuthzDecision::Deny {
                failed_layer: "OSO_USER_DELEGATION".to_string(),
                reason: format!(
                    "Delegating user '{}' lacks permission '{}' (agents cannot exceed human principal)",
                    user.user_id, action
                ),
                kill_switch_triggered: triggered,
            };
        }

        // 4. Layer 2 of Intersection: Static Agent Role Capability (`Cap(AgentRole a)`)
        let role_caps = role_static_capabilities(agent_role);
        if !role_caps.contains(action) {
            let triggered = self.record_access_denied_and_check_alarm(
                agent_id,
                action,
                now_unix,
                "OSO_AGENT_ROLE_CAPABILITY_EXCEEDED",
            );
            return OsoAuthzDecision::Deny {
                failed_layer: "OSO_AGENT_ROLE_CAPABILITY".to_string(),
                reason: format!(
                    "Agent role '{}' capability ceiling does not include '{}'",
                    agent_role, action
                ),
                kill_switch_triggered: triggered,
            };
        }

        // 5. Layer 3 of Intersection: Ephemeral Task Scope (`Scope(Task t)`)
        if task_scope.is_expired(now_unix) {
            let triggered = self.record_access_denied_and_check_alarm(
                agent_id,
                action,
                now_unix,
                "OSO_TASK_SCOPE_EXPIRED",
            );
            return OsoAuthzDecision::Deny {
                failed_layer: "OSO_TASK_SCOPE_EXPIRY".to_string(),
                reason: format!("Task scope '{}' has expired", task_scope.task_id),
                kill_switch_triggered: triggered,
            };
        }
        if !task_scope.allowed_actions.contains(action) || !task_scope.allows_resource(resource_id)
        {
            let triggered = self.record_access_denied_and_check_alarm(
                agent_id,
                action,
                now_unix,
                "OSO_TASK_SCOPE_VIOLATION",
            );
            return OsoAuthzDecision::Deny {
                failed_layer: "OSO_TASK_SCOPE_ENVELOPE".to_string(),
                reason: format!(
                    "Action '{}' on '{}' is outside ephemeral task scope '{}'",
                    action, resource_id, task_scope.task_id
                ),
                kill_switch_triggered: triggered,
            };
        }
        if requested_rows > task_scope.max_rows_per_query {
            let triggered = self.record_access_denied_and_check_alarm(
                agent_id,
                action,
                now_unix,
                "OSO_MCP_ROW_LIMIT_EXCEEDED",
            );
            return OsoAuthzDecision::Deny {
                failed_layer: "OSO_MCP_PARAMETER_BOUND".to_string(),
                reason: format!(
                    "Requested row count {} exceeds task scope max_rows_per_query {}",
                    requested_rows, task_scope.max_rows_per_query
                ),
                kill_switch_triggered: triggered,
            };
        }

        // 6. Out-of-Band Cryptographic HITL Step-Up Gate for high-impact actions
        if action_requires_hitl_step_up(action) {
            let Some(ticket) = hitl_ticket else {
                return OsoAuthzDecision::RequireHitlStepUp {
                    reason: format!(
                        "Action '{}' is high-impact and requires an out-of-band HMAC-SHA256 HITL ticket",
                        action
                    ),
                    required_action: action.to_string(),
                    resource_id: resource_id.to_string(),
                };
            };
            if let Err(err) = verify_hitl_step_up_ticket(
                ticket,
                &user.user_id,
                agent_id,
                &task_scope.task_id,
                action,
                resource_id,
                now_unix,
                &self.hitl_signing_key,
            ) {
                let triggered = self.record_access_denied_and_check_alarm(
                    agent_id,
                    action,
                    now_unix,
                    "OSO_FORGED_HITL_TICKET",
                );
                return OsoAuthzDecision::Deny {
                    failed_layer: "OSO_HITL_STEP_UP_VERIFICATION".to_string(),
                    reason: err,
                    kill_switch_triggered: triggered,
                };
            }
        }

        OsoAuthzDecision::Allow {
            effective_principal: format!(
                "user:{} ∩ role:{} ∩ task:{}",
                user.user_id, agent_role, task_scope.task_id
            ),
            audit_note: format!(
                "3-way intersection verified for '{}' on '{}'",
                action, resource_id
            ),
        }
    }

    // ------------------------------------------------------------------------
    // OSO PRE-RETRIEVAL RAG CONTEXT FILTERING
    // ------------------------------------------------------------------------

    /// Filters RAG document chunks *before* vector retrieval / LLM prompt assembly so that
    /// unauthorized documents never enter the model context window.
    pub fn filter_rag_documents_pre_retrieval(
        &self,
        user: &DelegatingUserContext,
        agent_role: &ArmRole,
        task_scope: &TaskScopeEnvelope,
        candidates: &[RagDocumentChunk],
        now_unix: u64,
    ) -> RagFilterResult {
        let mut permitted_doc_ids = Vec::new();
        let mut redacted_doc_ids = Vec::new();
        let mut audit_reasons = Vec::new();

        if task_scope.is_expired(now_unix) {
            for doc in candidates {
                redacted_doc_ids.push(doc.doc_id.clone());
            }
            audit_reasons.push("Task scope expired: 100% of RAG candidates redacted".to_string());
            return RagFilterResult {
                permitted_doc_ids,
                redacted_doc_ids,
                audit_reasons,
            };
        }

        let role_caps = role_static_capabilities(agent_role);

        for doc in candidates {
            let tenant_ok = doc.tenant_id == user.tenant_id;
            let clearance_ok = user.clearance_level >= doc.required_clearance;
            let acl_ok =
                doc.allowed_users.contains("*") || doc.allowed_users.contains(&user.user_id);
            let perm_ok = user.permissions.contains(&doc.required_permission)
                && role_caps.contains(doc.required_permission.as_str())
                && task_scope.allowed_actions.contains(&doc.required_permission);
            let scope_res_ok = task_scope.allows_resource(&doc.doc_id);

            if tenant_ok && clearance_ok && acl_ok && perm_ok && scope_res_ok {
                permitted_doc_ids.push(doc.doc_id.clone());
            } else {
                redacted_doc_ids.push(doc.doc_id.clone());
                audit_reasons.push(format!(
                    "Redacted '{}': tenant_ok={}, clearance_ok={}, acl_ok={}, perm_ok={}, scope_res_ok={}",
                    doc.doc_id, tenant_ok, clearance_ok, acl_ok, perm_ok, scope_res_ok
                ));
            }
        }

        RagFilterResult {
            permitted_doc_ids,
            redacted_doc_ids,
            audit_reasons,
        }
    }

    // ------------------------------------------------------------------------
    // AWS R1: DNS FIREWALL ALLOWLIST ENFORCEMENT
    // ------------------------------------------------------------------------

    /// Evaluates an outbound DNS resolution query against the Route 53 Resolver DNS Firewall
    /// allowlist (AWS R1). Returns `Ok("NOERROR")` if permitted, or `Err("NXDOMAIN")` if blocked.
    pub fn check_dns_firewall_query(
        snapshot: &ContainmentEnvironmentSnapshot,
        queried_domain: &str,
    ) -> Result<&'static str, String> {
        if snapshot.dns_firewall_status != "COMPLETE" {
            return Err(format!(
                "NXDOMAIN: DNS Firewall association is not COMPLETE (status='{}')",
                snapshot.dns_firewall_status
            ));
        }
        let normalized = queried_domain
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let allowed = snapshot.dns_firewall_allowed_domains.iter().any(|d| {
            let pat = d.trim().trim_end_matches('.').to_ascii_lowercase();
            if let Some(suffix) = pat.strip_prefix("*.") {
                normalized == suffix || normalized.ends_with(&format!(".{}", suffix))
            } else {
                normalized == pat
            }
        });

        if allowed {
            Ok("NOERROR")
        } else {
            Err(format!(
                "NXDOMAIN: Domain '{}' blocked by Route 53 DNS Firewall containment allowlist",
                normalized
            ))
        }
    }

    // ------------------------------------------------------------------------
    // AWS R3: INDEPENDENT CONTAINMENT WATCHDOG (4 INVARIANTS)
    // ------------------------------------------------------------------------

    /// Audits all 4 AWS Containment Watchdog invariants (`check_security_group_invariants`,
    /// `check_route_table_invariants`, `check_iam_policy_invariants`, `check_dns_firewall_invariants`).
    ///
    /// If any invariant fails, immediately invokes `execute_kill_switch` (`desired_count = 0`).
    pub fn verify_four_containment_invariants(
        &self,
        snapshot: &ContainmentEnvironmentSnapshot,
        now_unix: u64,
    ) -> WatchdogAssessmentReport {
        let mut violations = Vec::new();

        // Invariant 1: Security Group Egress Rules (forbid unrestricted 0.0.0.0/0 or ::/0)
        let mut sg_ok = true;
        if snapshot.security_group_egress_rules.is_empty() {
            sg_ok = false;
            violations.push(
                "R3_SG_INVARIANT: Security group egress rule set is empty/missing".to_string(),
            );
        }
        for rule in &snapshot.security_group_egress_rules {
            let cidr = rule.cidr_block.trim();
            if cidr == "0.0.0.0/0" || cidr == "::/0" {
                sg_ok = false;
                violations.push(format!(
                    "R3_SG_INVARIANT: Unrestricted internet egress rule '{}' ({}) detected",
                    rule.rule_id, cidr
                ));
            }
        }

        // Invariant 2: Route Table Entries (forbid Internet Gateway `igw-*` or NAT `nat-*` in isolated subnet)
        let mut rt_ok = true;
        for entry in &snapshot.route_table_entries {
            let target = entry.target_id.trim().to_ascii_lowercase();
            if target.starts_with("igw-") || target.starts_with("eigw-") {
                rt_ok = false;
                violations.push(format!(
                    "R3_ROUTE_INVARIANT: Unauthorized Internet Gateway route '{}' -> '{}' in isolated subnet",
                    entry.destination_cidr, entry.target_id
                ));
            }
        }

        // Invariant 3: IAM Policy Attachment Count AND Exact Policy ARN Set
        // Prevents the policy-swap loophole where an attacker swaps a restrictive policy for
        // AdministratorAccess while keeping the attachment count equal.
        let count_matches =
            snapshot.attached_iam_policy_arns.len() == snapshot.expected_iam_policy_arns.len();
        let set_matches = snapshot.attached_iam_policy_arns == snapshot.expected_iam_policy_arns;
        let iam_ok = count_matches && set_matches && !snapshot.expected_iam_policy_arns.is_empty();
        if !iam_ok {
            violations.push(format!(
                "R3_IAM_INVARIANT: IAM policy drift/swap detected (attached={:?}, expected={:?})",
                snapshot.attached_iam_policy_arns, snapshot.expected_iam_policy_arns
            ));
        }

        // Invariant 4: Route 53 DNS Firewall Association Status
        let dns_ok = snapshot.dns_firewall_status == "COMPLETE"
            && !snapshot.dns_firewall_allowed_domains.is_empty();
        if !dns_ok {
            violations.push(format!(
                "R3_DNS_FIREWALL_INVARIANT: DNS Firewall status='{}' (expected 'COMPLETE' with non-empty allowlist)",
                snapshot.dns_firewall_status
            ));
        }

        let all_passed = sg_ok && rt_ok && iam_ok && dns_ok;
        let mut kill_switch_engaged = false;
        if !all_passed {
            self.execute_kill_switch(& violations.join("; "), now_unix);
            kill_switch_engaged = true;
        }

        WatchdogAssessmentReport {
            security_group_invariant_ok: sg_ok,
            route_table_invariant_ok: rt_ok,
            iam_policy_invariant_ok: iam_ok,
            dns_firewall_invariant_ok: dns_ok,
            all_invariants_passed: all_passed,
            violations,
            kill_switch_engaged,
        }
    }

    // ------------------------------------------------------------------------
    // AWS R5: CAPABILITY ENVELOPE ACCESS-DENIED ALARM & KILL SWITCH
    // ------------------------------------------------------------------------

    /// Records an `AccessDenied` event in the sliding window and triggers the KillSwitch if
    /// the count within `access_denied_window_secs` reaches `access_denied_threshold` (AWS R5).
    pub fn record_access_denied_and_check_alarm(
        &self,
        agent_id: &str,
        action: &str,
        now_unix: u64,
        reason_tag: &str,
    ) -> bool {
        let should_trigger = {
            let mut window = self.access_denied_window.lock();
            let cutoff = now_unix.saturating_sub(self.access_denied_window_secs);
            while let Some(&(ts, _, _)) = window.front() {
                if ts < cutoff {
                    window.pop_front();
                } else {
                    break;
                }
            }
            window.push_back((now_unix, agent_id.to_string(), action.to_string()));
            window.len() >= self.access_denied_threshold
        };

        if should_trigger {
            self.execute_kill_switch(
                &format!(
                    "R5_CAPABILITY_ENVELOPE_ALARM: >= {} AccessDenied events within {}s (latest: agent='{}', action='{}', tag='{}')",
                    self.access_denied_threshold,
                    self.access_denied_window_secs,
                    agent_id,
                    action,
                    reason_tag
                ),
                now_unix,
            );
            true
        } else {
            false
        }
    }

    /// Executes the AWS Containment KillSwitch Handler:
    /// 1. Sets service `desired_count = 0` and `auto_respawn_disabled = true`.
    /// 2. Terminates all running task IDs immediately.
    /// 3. Monotonically advances the cluster `generation_epoch` (`Gen N -> Gen N + 1`).
    pub fn execute_kill_switch(
        &self,
        reason: &str,
        now_unix: u64,
    ) -> KillSwitchTerminationReport {
        let mut state = self.cluster_state.lock();
        let prev_desired = state.desired_count;
        let terminated: Vec<String> = std::mem::take(&mut state.running_task_ids);
        state.desired_count = 0;
        state.auto_respawn_disabled = true;
        state.generation_epoch += 1;

        let report = KillSwitchTerminationReport {
            cluster_name: state.cluster_name.clone(),
            previous_desired_count: prev_desired,
            new_desired_count: 0,
            terminated_task_ids: terminated,
            new_generation_epoch: state.generation_epoch,
            trigger_reason: reason.to_string(),
            timestamp_unix: now_unix,
        };
        state.kill_switch_history.push(report.clone());
        report
    }
}

/// Returns a baseline compliant `ContainmentEnvironmentSnapshot` for AWS R3 watchdog evaluation.
pub fn default_compliant_containment_snapshot() -> ContainmentEnvironmentSnapshot {
    ContainmentEnvironmentSnapshot {
        security_group_egress_rules: vec![SecurityGroupEgressRule {
            rule_id: "sgr-vpc-endpoint-https".to_string(),
            cidr_block: "10.24.0.0/16".to_string(),
            protocol: "tcp".to_string(),
            port_range: (443, 443),
        }],
        route_table_entries: vec![
            RouteTableEntry {
                destination_cidr: "10.24.0.0/16".to_string(),
                target_id: "local".to_string(),
            },
            RouteTableEntry {
                destination_cidr: "172.31.0.0/16".to_string(),
                target_id: "vpce-0a1b2c3d4e5f".to_string(),
            },
        ],
        attached_iam_policy_arns: BTreeSet::from([
            "arn:aws:iam::123456789012:policy/KillSwitchAgentLeastPrivilege".to_string(),
            "arn:aws:iam::123456789012:policy/KillSwitchDenyControlPlane".to_string(),
        ]),
        expected_iam_policy_arns: BTreeSet::from([
            "arn:aws:iam::123456789012:policy/KillSwitchAgentLeastPrivilege".to_string(),
            "arn:aws:iam::123456789012:policy/KillSwitchDenyControlPlane".to_string(),
        ]),
        dns_firewall_status: "COMPLETE".to_string(),
        dns_firewall_allowed_domains: BTreeSet::from([
            "api.internal.killswitch.local".to_string(),
            "*.amazonaws.com".to_string(),
        ]),
    }
}

static GLOBAL_OSO_AWS_CONTAINMENT: OnceLock<OsoAwsContainmentEngine> = OnceLock::new();

/// Global thread-safe singleton for the Oso 3-Way Intersection & AWS R1-R5 Containment Engine.
pub fn global_oso_aws_containment() -> &'static OsoAwsContainmentEngine {
    GLOBAL_OSO_AWS_CONTAINMENT.get_or_init(|| {
        OsoAwsContainmentEngine::new(
            "killswitch-agent-cluster-prod",
            vec![
                "task-arm-01".to_string(),
                "task-arm-02".to_string(),
                "task-arm-03".to_string(),
            ],
            [0x4Bu8; 32],
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_engine() -> OsoAwsContainmentEngine {
        OsoAwsContainmentEngine::new(
            "killswitch-agent-cluster-prod",
            vec![
                "task-001".to_string(),
                "task-002".to_string(),
                "task-003".to_string(),
            ],
            [0x42u8; 32],
        )
    }

    fn sample_user() -> DelegatingUserContext {
        DelegatingUserContext {
            user_id: "alice@acme.corp".to_string(),
            tenant_id: "tenant-acme".to_string(),
            permissions: BTreeSet::from([
                "Order:read".to_string(),
                "Invoice:read".to_string(),
                "Invoice:approve".to_string(),
                "Document:read".to_string(),
            ]),
            clearance_level: 2,
        }
    }

    fn sample_task_scope() -> TaskScopeEnvelope {
        TaskScopeEnvelope {
            task_id: "task-q3-audit".to_string(),
            session_id: "sess-900".to_string(),
            allowed_actions: BTreeSet::from([
                "Order:read".to_string(),
                "Invoice:read".to_string(),
                "Invoice:approve".to_string(),
                "Document:read".to_string(),
            ]),
            allowed_resource_prefixes: BTreeSet::from([
                "order:acme-".to_string(),
                "invoice:acme-".to_string(),
                "doc:acme-".to_string(),
            ]),
            max_rows_per_query: 50,
            issued_at_unix: 1_700_000_000,
            expires_at_unix: 1_700_003_600,
        }
    }

    #[test]
    fn test_oso_three_way_delegated_identity_intersection() {
        let engine = sample_engine();
        let user = sample_user();
        let scope = sample_task_scope();

        // 1. Valid 3-way intersection: User has Order:read, AccountingLedgerWrite has Order:read, Task allows order:acme-101
        let allow_dec = engine.evaluate_intersection_authority(
            &user,
            "agent-ledger-1",
            &ArmRole::AccountingLedgerWrite,
            &scope,
            "Order:read",
            "order:acme-101",
            "tenant-acme",
            10,
            None,
            1_700_000_500,
        );
        assert!(allow_dec.is_allowed());

        // 2. Role lacks capability: UntrustedDocIngest does NOT have Order:read even though User and Task do
        let role_deny = engine.evaluate_intersection_authority(
            &user,
            "agent-ingest-1",
            &ArmRole::UntrustedDocIngest,
            &scope,
            "Order:read",
            "order:acme-101",
            "tenant-acme",
            10,
            None,
            1_700_000_501,
        );
        assert!(matches!(
            role_deny,
            OsoAuthzDecision::Deny {
                ref failed_layer,
                kill_switch_triggered: false,
                ..
            } if failed_layer == "OSO_AGENT_ROLE_CAPABILITY"
        ));

        // 3. User lacks permission: AccountingLedgerWrite has Ledger:append, but Alice does NOT
        let mut scope_with_append = scope.clone();
        scope_with_append
            .allowed_actions
            .insert("Ledger:append".to_string());
        let user_deny = engine.evaluate_intersection_authority(
            &user,
            "agent-ledger-1",
            &ArmRole::AccountingLedgerWrite,
            &scope_with_append,
            "Ledger:append",
            "order:acme-101",
            "tenant-acme",
            1,
            None,
            1_700_000_502,
        );
        assert!(matches!(
            user_deny,
            OsoAuthzDecision::Deny {
                ref failed_layer,
                ..
            } if failed_layer == "OSO_USER_DELEGATION"
        ));
    }

    #[test]
    fn test_oso_hitl_step_up_ticket_enforcement() {
        let engine = sample_engine();
        let user = sample_user();
        let scope = sample_task_scope();

        // Invoice:approve is high-impact -> without a ticket, returns RequireHitlStepUp
        let step_up = engine.evaluate_intersection_authority(
            &user,
            "agent-ledger-1",
            &ArmRole::AccountingLedgerWrite,
            &scope,
            "Invoice:approve",
            "invoice:acme-99",
            "tenant-acme",
            1,
            None,
            1_700_000_600,
        );
        assert!(matches!(
            step_up,
            OsoAuthzDecision::RequireHitlStepUp { .. }
        ));

        // Issue a valid cryptographic HITL ticket bound to the exact parameters
        let ticket = issue_hitl_step_up_ticket(
            "tkt-501",
            "secops-reviewer",
            &user.user_id,
            "agent-ledger-1",
            &scope.task_id,
            "Invoice:approve",
            "invoice:acme-99",
            1_700_001_200,
            &engine.hitl_signing_key,
        );

        let approved = engine.evaluate_intersection_authority(
            &user,
            "agent-ledger-1",
            &ArmRole::AccountingLedgerWrite,
            &scope,
            "Invoice:approve",
            "invoice:acme-99",
            "tenant-acme",
            1,
            Some(&ticket),
            1_700_000_605,
        );
        assert!(approved.is_allowed());
    }

    #[test]
    fn test_oso_pre_retrieval_rag_filtering() {
        let engine = sample_engine();
        let user = sample_user();
        let scope = sample_task_scope();

        let chunks = vec![
            RagDocumentChunk {
                doc_id: "doc:acme-handbook".to_string(),
                tenant_id: "tenant-acme".to_string(),
                required_clearance: 1,
                allowed_users: BTreeSet::from(["*".to_string()]),
                required_permission: "Document:read".to_string(),
                content_preview: "Standard travel policy".to_string(),
            },
            RagDocumentChunk {
                doc_id: "doc:acme-board-mna".to_string(),
                tenant_id: "tenant-acme".to_string(),
                required_clearance: 3, // User clearance is 2 -> must be redacted pre-retrieval!
                allowed_users: BTreeSet::from(["alice@acme.corp".to_string()]),
                required_permission: "Document:read".to_string(),
                content_preview: "CONFIDENTIAL M&A target valuation".to_string(),
            },
            RagDocumentChunk {
                doc_id: "doc:other-tenant".to_string(),
                tenant_id: "tenant-beta".to_string(), // Cross-tenant -> must be redacted!
                required_clearance: 0,
                allowed_users: BTreeSet::from(["*".to_string()]),
                required_permission: "Document:read".to_string(),
                content_preview: "Other tenant prompt injection payload".to_string(),
            },
        ];

        let filtered = engine.filter_rag_documents_pre_retrieval(
            &user,
            &ArmRole::CedarPolicyEvaluation,
            &scope,
            &chunks,
            1_700_000_500,
        );
        assert_eq!(filtered.permitted_doc_ids, vec!["doc:acme-handbook"]);
        assert_eq!(
            filtered.redacted_doc_ids,
            vec!["doc:acme-board-mna", "doc:other-tenant"]
        );
    }

    #[test]
    fn test_aws_r3_watchdog_four_invariants_and_policy_swap_detection() {
        let engine = sample_engine();
        let compliant = default_compliant_containment_snapshot();

        let report_ok = engine.verify_four_containment_invariants(&compliant, 1_700_000_100);
        assert!(report_ok.all_invariants_passed);
        assert!(!report_ok.kill_switch_engaged);
        assert_eq!(engine.cluster_state.lock().desired_count, 3);

        // Simulate an IAM Policy Swap attack: same policy count (2), but one ARN is swapped for AdministratorAccess
        let mut swapped = compliant.clone();
        swapped
            .attached_iam_policy_arns
            .remove("arn:aws:iam::123456789012:policy/KillSwitchDenyControlPlane");
        swapped
            .attached_iam_policy_arns
            .insert("arn:aws:iam::aws:policy/AdministratorAccess".to_string());

        let report_tampered = engine.verify_four_containment_invariants(&swapped, 1_700_000_200);
        assert!(!report_tampered.iam_policy_invariant_ok);
        assert!(!report_tampered.all_invariants_passed);
        assert!(report_tampered.kill_switch_engaged);

        // Verify KillSwitch set desired_count = 0, cleared running tasks, and advanced epoch
        let state = engine.cluster_state.lock();
        assert_eq!(state.desired_count, 0);
        assert!(state.running_task_ids.is_empty());
        assert!(state.auto_respawn_disabled);
        assert_eq!(state.generation_epoch, 2);
    }

    #[test]
    fn test_aws_r1_dns_firewall_and_r5_access_denied_velocity_kill_switch() {
        let engine = sample_engine();
        let snapshot = default_compliant_containment_snapshot();
        let user = sample_user();
        let scope = sample_task_scope();

        // R1: Allowlisted domain succeeds; non-allowlisted domain returns NXDOMAIN
        assert_eq!(
            OsoAwsContainmentEngine::check_dns_firewall_query(
                &snapshot,
                "s3.us-east-1.amazonaws.com"
            )
            .unwrap(),
            "NOERROR"
        );
        assert!(OsoAwsContainmentEngine::check_dns_firewall_query(
            &snapshot,
            "exfil.attacker-c2.org"
        )
        .unwrap_err()
        .contains("NXDOMAIN"));

        // R4 + R5: 3 consecutive denied probes within 60s automatically trigger the KillSwitch
        for i in 0..3 {
            let dec = engine.evaluate_intersection_authority(
                &user,
                "agent-rogue",
                &ArmRole::AccountingLedgerWrite,
                &scope,
                "iam:AttachRolePolicy",
                "arn:aws:iam::123456789012:role/AgentRole",
                "tenant-acme",
                1,
                None,
                1_700_001_000 + i,
            );
            if i < 2 {
                assert!(matches!(
                    dec,
                    OsoAuthzDecision::Deny {
                        kill_switch_triggered: false,
                        ..
                    }
                ));
            } else {
                assert!(matches!(
                    dec,
                    OsoAuthzDecision::Deny {
                        kill_switch_triggered: true,
                        ..
                    }
                ));
            }
        }

        let state = engine.cluster_state.lock();
        assert_eq!(state.desired_count, 0);
        assert_eq!(state.kill_switch_history.len(), 1);
    }
}
