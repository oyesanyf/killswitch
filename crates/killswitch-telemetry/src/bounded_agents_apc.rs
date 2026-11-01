//! # Bounded Agents: Agentic Principal Chain (APC) Engine (`arXiv:2608.15888`)
//!
//! Full Rust implementation of the formal delegation and capability-enforcement framework
//! from **Bounded Agents: Formal Delegation & Capability Enforcement via the Agentic
//! Principal Chain (APC)** (`arXiv:2608.15888`, reference implementation `xmuruaga/bounded-agents`).
//!
//! ## Core Mathematical & Security Invariants Implemented
//! 1. **Asymmetric Meet-Semilattice Scope Narrowing ($\mathcal{S}_1 \sqcap \mathcal{S}_2$, Def. 4.3 / Thm. 4.6)**:
//!    $$\mathcal{S}_1 \sqcap \mathcal{S}_2 = (R_1 \cap R_2,\ A_1 \cap A_2,\ D_1 \cap D_2,\ X_1 \cup X_2)$$
//!    Positive grants (resources $R$, actions $A$, data classifications $D$) narrow via set
//!    intersection ($\cap$), whereas composition restrictions $X$ accumulate via set union ($\cup$).
//!    Guarantees monotonic non-increasing blast radius:
//!    $$\text{BlastRadius}(\mathcal{S}_k) \le \text{BlastRadius}(\mathcal{S}_{k-1}) \le \dots \le \text{BlastRadius}(\mathcal{S}_0)$$
//!
//! 2. **Sealed Authorization Envelopes (`AuthorizationEnvelope`, Paper §4.2 / `apc/envelopes.py`)**:
//!    - Immutable once sealed with HMAC-SHA256 (`EnvelopeSealedError` on any mutation attempt).
//!    - Multi-hop narrowing (`delegate_narrowed`) verifies the parent seal before computing
//!      $\mathcal{S}_{\text{child}} = \mathcal{S}_{\text{parent}} \sqcap \mathcal{S}_{\text{req}}$.
//!
//! 3. **Stateful Composition Restriction Checker (`CompositionChecker`, Paper §4.4 / `apc/composition.py`)**:
//!    - Pairwise forbidden transitions ($k=2$, e.g. `READ_CONFIDENTIAL` $\to$ `EXTERNAL_TRANSMIT`).
//!    - Ordered resource-qualified $k$-tuple subsequence matching ($k \ge 2$).
//!    - **Cross-Session Principal Lineage Anti-Splitting Guard** (Adaptive Attack Mitigation, Paper §6.3):
//!      Tracks action history both per `session_id` AND per `root_principal_id` across concurrent or
//!      sequential sessions so an attacker cannot bypass composition rules by splitting step 1 and
//!      step 2 across two separate sessions.
//!
//! 4. **6-Dimensional Monotonic Delegation Budget (`DelegationBudgetSpec` & `BudgetState`, `apc/budget.py`)**:
//!    Enforces `(max_actions, max_irreversible_actions, max_delegation_depth, max_sensitivity_tier,
//!    allow_cross_domain, max_cost)`.
//!
//! 5. **6 Conjunctive Admissibility Conditions (`ApcPolicyDecisionPoint`, Paper §5 / `apc/pdp.py`)**:
//!    $$\text{Admissible}(a) \iff C_1 \wedge C_2 \wedge C_3 \wedge C_4 \wedge C_5 \wedge C_6$$
//!    - $C_1$: Cryptographic Identity & Envelope Seal Binding (`constant_time_eq`).
//!    - $C_2$: Narrowed Scope + Stateful Composition + 6D Budget Check.
//!    - $C_3$: Context Binding (timestamp window, `task_session_id`, `policy_version`).
//!    - $C_4$: Single-Use Action-Hash Bound Approval Token (`ApprovalToken`) for irreversible/high-consequence actions.
//!    - $C_5$: Fail-Closed Hash-Chained Evidence Sink (`EvidenceSink`) — if the evidence sink is unavailable, execution is denied.
//!    - $C_6$: Pre-Declared Intent Alignment (`IntentSpec`) with `action_resource_map` precedence and `Strict` / `Warn` / `Audit` modes.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Mutex, OnceLock};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Constant-time byte comparison wrapper using `subtle::ConstantTimeEq`.
fn constant_time_eq_str(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// Computes an HMAC-SHA256 hex digest over canonical payload bytes.
pub fn compute_hmac_sha256_hex(secret: &[u8], payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts keys of any byte length");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

/// Glob/wildcard pattern matcher supporting exact match, `*` wildcard, and prefix `foo/*` or `foo*`.
pub fn resource_pattern_matches(pattern: &str, candidate: &str) -> bool {
    if pattern == "*" || pattern == candidate {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return candidate.starts_with(prefix);
    }
    false
}

/// Intersects two sets of glob/resource patterns according to the APC meet-semilattice:
/// keeps the more specific pattern when one subsumes the other.
fn intersect_pattern_sets(a: &BTreeSet<String>, b: &BTreeSet<String>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for pa in a {
        for pb in b {
            if pa == pb {
                out.insert(pa.clone());
            } else if resource_pattern_matches(pa, pb) {
                out.insert(pb.clone());
            } else if resource_pattern_matches(pb, pa) {
                out.insert(pa.clone());
            }
        }
    }
    out
}

/// Maps a concrete tool/action name to its canonical APC action class for composition checking.
pub fn classify_action_class(action: &str) -> &'static str {
    let lower = action.to_ascii_lowercase();
    if lower.contains("read_confidential")
        || lower.contains("secret")
        || lower.contains("credential")
        || lower.contains("financial")
        || lower.contains("pii")
    {
        "READ_CONFIDENTIAL"
    } else if lower.contains("send")
        || lower.contains("email")
        || lower.contains("webhook")
        || lower.contains("post")
        || lower.contains("upload")
        || lower.contains("egress")
        || lower.contains("transmit")
    {
        "EXTERNAL_TRANSMIT"
    } else if lower.contains("exec")
        || lower.contains("shell")
        || lower.contains("spawn")
        || lower.contains("eval")
    {
        "EXECUTE_CODE"
    } else if lower.contains("delete")
        || lower.contains("drop")
        || lower.contains("write")
        || lower.contains("modify")
        || lower.contains("update")
    {
        "MUTATE_STATE"
    } else {
        "READ_PUBLIC"
    }
}

/// Pairwise ($k=2$) forbidden action-class composition rule:
/// forbids executing `second_class` if `first_class` has already occurred in the session/lineage.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PairwiseRestriction {
    pub rule_id: String,
    pub first_class: String,
    pub second_class: String,
}

impl PairwiseRestriction {
    pub fn new(
        rule_id: impl Into<String>,
        first_class: impl Into<String>,
        second_class: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            first_class: first_class.into(),
            second_class: second_class.into(),
        }
    }
}

/// Single step in an ordered $k$-tuple ($k \ge 2$) resource-qualified composition restriction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KTupleStep {
    pub action_class: String,
    pub resource_pattern: String,
}

/// Ordered $k$-tuple ($k \ge 2$) composition restriction (`KTupleRestriction`, `apc/scopes.py`).
/// Blocks the final step when the preceding $k-1$ steps appear as an ordered subsequence in the
/// session or principal lineage history.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KTupleRestriction {
    pub rule_id: String,
    pub ordered_steps: Vec<KTupleStep>,
}

impl KTupleRestriction {
    pub fn new(rule_id: impl Into<String>, ordered_steps: Vec<KTupleStep>) -> Self {
        Self {
            rule_id: rule_id.into(),
            ordered_steps,
        }
    }
}

/// Formal APC Scope $\mathcal{S} = (R, A, D, X)$ forming a bounded meet-semilattice (Def. 4.3, Thm. 4.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApcScope {
    /// Permitted resource patterns ($R$).
    pub resources: BTreeSet<String>,
    /// Permitted tool/action identifiers ($A$).
    pub actions: BTreeSet<String>,
    /// Permitted data classifications ($D$, e.g. `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`).
    pub data_classifications: BTreeSet<String>,
    /// Pairwise composition restrictions ($X_{\text{pairwise}}$) — combined via set UNION on meet.
    pub pairwise_restrictions: BTreeSet<PairwiseRestriction>,
    /// Ordered $k$-tuple composition restrictions ($X_{k\text{-tuple}}$) — combined via set UNION on meet.
    pub ktuple_restrictions: BTreeSet<KTupleRestriction>,
}

impl ApcScope {
    pub fn new(
        resources: impl IntoIterator<Item = impl Into<String>>,
        actions: impl IntoIterator<Item = impl Into<String>>,
        data_classifications: impl IntoIterator<Item = impl Into<String>>,
        pairwise_restrictions: impl IntoIterator<Item = PairwiseRestriction>,
        ktuple_restrictions: impl IntoIterator<Item = KTupleRestriction>,
    ) -> Self {
        Self {
            resources: resources.into_iter().map(Into::into).collect(),
            actions: actions.into_iter().map(Into::into).collect(),
            data_classifications: data_classifications.into_iter().map(Into::into).collect(),
            pairwise_restrictions: pairwise_restrictions.into_iter().collect(),
            ktuple_restrictions: ktuple_restrictions.into_iter().collect(),
        }
    }

    /// Asymmetric meet operation ($\mathcal{S}_1 \sqcap \mathcal{S}_2$, Def. 4.3):
    /// - Positive grants $(R, A, D)$ intersect ($\cap$).
    /// - Negative composition restrictions $X$ union ($\cup$).
    pub fn meet(&self, other: &Self) -> Self {
        let resources = intersect_pattern_sets(&self.resources, &other.resources);
        let actions = intersect_pattern_sets(&self.actions, &other.actions);
        let data_classifications = self
            .data_classifications
            .intersection(&other.data_classifications)
            .cloned()
            .collect();
        let pairwise_restrictions = self
            .pairwise_restrictions
            .union(&other.pairwise_restrictions)
            .cloned()
            .collect();
        let ktuple_restrictions = self
            .ktuple_restrictions
            .union(&other.ktuple_restrictions)
            .cloned()
            .collect();

        Self {
            resources,
            actions,
            data_classifications,
            pairwise_restrictions,
            ktuple_restrictions,
        }
    }

    /// Returns `true` iff `self` is a valid narrowing of (or equal to) `parent` ($\mathcal{S}_{\text{self}} \sqsubseteq \mathcal{S}_{\text{parent}}$).
    pub fn is_subscope_of(&self, parent: &Self) -> bool {
        let merged = parent.meet(self);
        merged == *self
    }

    /// Checks whether a concrete resource is permitted by $R$.
    pub fn allows_resource(&self, resource: &str) -> bool {
        self.resources
            .iter()
            .any(|pat| resource_pattern_matches(pat, resource))
    }

    /// Checks whether a concrete action is permitted by $A$.
    pub fn allows_action(&self, action: &str) -> bool {
        self.actions
            .iter()
            .any(|pat| resource_pattern_matches(pat, action))
    }

    /// Checks whether a data classification is permitted by $D$.
    pub fn allows_classification(&self, classification: &str) -> bool {
        self.data_classifications.contains("*") || self.data_classifications.contains(classification)
    }

    /// Computes the discrete blast-radius cardinality $|\text{Reach}(\mathcal{S})| = |R| \times |A| \times |D|$ (Thm. 4.6).
    pub fn blast_radius(&self) -> usize {
        self.resources.len() * self.actions.len() * self.data_classifications.len()
    }
}

/// 6-Dimensional Monotonic Delegation Budget Specification (`DelegationBudgetSpec`, `apc/budget.py`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DelegationBudgetSpec {
    pub max_actions: u32,
    pub max_irreversible_actions: u32,
    pub max_delegation_depth: u32,
    pub max_sensitivity_tier: u8,
    pub allow_cross_domain: bool,
    pub max_cost: f64,
}

impl Default for DelegationBudgetSpec {
    fn default() -> Self {
        Self {
            max_actions: 64,
            max_irreversible_actions: 4,
            max_delegation_depth: 5,
            max_sensitivity_tier: 3,
            allow_cross_domain: false,
            max_cost: 10.0,
        }
    }
}

impl DelegationBudgetSpec {
    /// Componentwise minimum narrowing across a delegation hop ($\text{Budget}_{\text{child}} \le \text{Budget}_{\text{parent}}$).
    pub fn narrow(&self, requested: &Self) -> Self {
        Self {
            max_actions: self.max_actions.min(requested.max_actions),
            max_irreversible_actions: self
                .max_irreversible_actions
                .min(requested.max_irreversible_actions),
            max_delegation_depth: self
                .max_delegation_depth
                .min(requested.max_delegation_depth),
            max_sensitivity_tier: self
                .max_sensitivity_tier
                .min(requested.max_sensitivity_tier),
            allow_cross_domain: self.allow_cross_domain && requested.allow_cross_domain,
            max_cost: self.max_cost.min(requested.max_cost),
        }
    }
}

/// Runtime accumulator tracking consumed budget along a delegation chain (`BudgetState`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BudgetState {
    pub actions_executed: u32,
    pub irreversible_executed: u32,
    pub accumulated_cost: f64,
}

impl BudgetState {
    #[allow(clippy::too_many_arguments)]
    pub fn check_and_record(
        &mut self,
        spec: &DelegationBudgetSpec,
        action_increment: u32,
        is_irreversible: bool,
        current_depth: u32,
        sensitivity_tier: u8,
        is_cross_domain: bool,
        cost_delta: f64,
    ) -> Result<(), String> {
        if current_depth > spec.max_delegation_depth {
            return Err(format!(
                "BUDGET_DEPTH_EXCEEDED: depth {} > max {}",
                current_depth, spec.max_delegation_depth
            ));
        }
        if sensitivity_tier > spec.max_sensitivity_tier {
            return Err(format!(
                "BUDGET_SENSITIVITY_EXCEEDED: tier {} > max {}",
                sensitivity_tier, spec.max_sensitivity_tier
            ));
        }
        if is_cross_domain && !spec.allow_cross_domain {
            return Err(
                "BUDGET_CROSS_DOMAIN_DENIED: cross-domain execution disabled in budget".to_string(),
            );
        }
        if self.actions_executed.saturating_add(action_increment) > spec.max_actions {
            return Err(format!(
                "BUDGET_MAX_ACTIONS_EXCEEDED: {} + {} > {}",
                self.actions_executed, action_increment, spec.max_actions
            ));
        }
        let next_irrev = self.irreversible_executed + u32::from(is_irreversible);
        if next_irrev > spec.max_irreversible_actions {
            return Err(format!(
                "BUDGET_IRREVERSIBLE_EXCEEDED: {} > {}",
                next_irrev, spec.max_irreversible_actions
            ));
        }
        let next_cost = self.accumulated_cost + cost_delta;
        if next_cost > spec.max_cost + 1e-9 {
            return Err(format!(
                "BUDGET_COST_EXCEEDED: {:.4} > {:.4}",
                next_cost, spec.max_cost
            ));
        }

        self.actions_executed += action_increment;
        self.irreversible_executed = next_irrev;
        self.accumulated_cost = next_cost;
        Ok(())
    }
}

/// Error raised when attempting to mutate an already-sealed `AuthorizationEnvelope`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeSealedError(pub String);

impl std::fmt::Display for EnvelopeSealedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EnvelopeSealedError: {}", self.0)
    }
}

impl std::error::Error for EnvelopeSealedError {}

/// Cryptographically sealed APC Authorization Envelope (`AuthorizationEnvelope`, Paper §4.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationEnvelope {
    pub envelope_id: String,
    pub parent_envelope_id: Option<String>,
    pub root_principal_id: String,
    pub delegator_id: String,
    pub delegatee_id: String,
    pub hop_index: u32,
    pub task_session_id: String,
    pub policy_version: String,
    pub effective_scope: ApcScope,
    pub budget_spec: DelegationBudgetSpec,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub parent_seal_hex: Option<String>,
    pub seal_hmac_hex: String,
    sealed: bool,
}

impl AuthorizationEnvelope {
    /// Creates and seals a root (hop 1) authorization envelope from a human/root principal to an orchestrator agent.
    #[allow(clippy::too_many_arguments)]
    pub fn new_root(
        envelope_id: impl Into<String>,
        root_principal_id: impl Into<String>,
        delegatee_id: impl Into<String>,
        task_session_id: impl Into<String>,
        policy_version: impl Into<String>,
        scope: ApcScope,
        budget_spec: DelegationBudgetSpec,
        issued_at_unix: i64,
        expires_at_unix: i64,
        signing_key: &[u8],
    ) -> Self {
        let root_id = root_principal_id.into();
        let mut env = Self {
            envelope_id: envelope_id.into(),
            parent_envelope_id: None,
            root_principal_id: root_id.clone(),
            delegator_id: root_id,
            delegatee_id: delegatee_id.into(),
            hop_index: 1,
            task_session_id: task_session_id.into(),
            policy_version: policy_version.into(),
            effective_scope: scope,
            budget_spec,
            issued_at_unix,
            expires_at_unix,
            parent_seal_hex: None,
            seal_hmac_hex: String::new(),
            sealed: false,
        };
        env.seal_in_place(signing_key);
        env
    }

    fn canonical_payload(&self) -> String {
        let res_vec: Vec<&String> = self.effective_scope.resources.iter().collect();
        let act_vec: Vec<&String> = self.effective_scope.actions.iter().collect();
        let cls_vec: Vec<&String> = self.effective_scope.data_classifications.iter().collect();
        let pw_vec: Vec<String> = self
            .effective_scope
            .pairwise_restrictions
            .iter()
            .map(|r| format!("{}:{}>{}", r.rule_id, r.first_class, r.second_class))
            .collect();
        let kt_vec: Vec<String> = self
            .effective_scope
            .ktuple_restrictions
            .iter()
            .map(|k| {
                let steps: Vec<String> = k
                    .ordered_steps
                    .iter()
                    .map(|s| format!("{}@{}", s.action_class, s.resource_pattern))
                    .collect();
                format!("{}:[{}]", k.rule_id, steps.join(","))
            })
            .collect();

        format!(
            "v1|id={}|parent={:?}|root={}|delegator={}|delegatee={}|hop={}|sess={}|pol={}|R={:?}|A={:?}|D={:?}|PW={:?}|KT={:?}|B=({},{},{},{},{},{:.4})|iat={}|exp={}|pseal={:?}",
            self.envelope_id,
            self.parent_envelope_id,
            self.root_principal_id,
            self.delegator_id,
            self.delegatee_id,
            self.hop_index,
            self.task_session_id,
            self.policy_version,
            res_vec,
            act_vec,
            cls_vec,
            pw_vec,
            kt_vec,
            self.budget_spec.max_actions,
            self.budget_spec.max_irreversible_actions,
            self.budget_spec.max_delegation_depth,
            self.budget_spec.max_sensitivity_tier,
            self.budget_spec.allow_cross_domain,
            self.budget_spec.max_cost,
            self.issued_at_unix,
            self.expires_at_unix,
            self.parent_seal_hex
        )
    }

    fn seal_in_place(&mut self, signing_key: &[u8]) {
        let payload = self.canonical_payload();
        self.seal_hmac_hex = compute_hmac_sha256_hex(signing_key, payload.as_bytes());
        self.sealed = true;
    }

    /// Verifies the HMAC-SHA256 seal in constant time.
    pub fn verify_seal(&self, signing_key: &[u8]) -> bool {
        if !self.sealed || self.seal_hmac_hex.is_empty() {
            return false;
        }
        let expected = compute_hmac_sha256_hex(signing_key, self.canonical_payload().as_bytes());
        constant_time_eq_str(&self.seal_hmac_hex, &expected)
    }

    /// Rejects any post-seal in-place scope modification (`EnvelopeSealedError`).
    pub fn attempt_in_place_scope_mutation(
        &mut self,
        new_scope: ApcScope,
    ) -> Result<(), EnvelopeSealedError> {
        if self.sealed {
            return Err(EnvelopeSealedError(format!(
                "Envelope '{}' is cryptographically sealed; create a narrowed child envelope via delegate_narrowed()",
                self.envelope_id
            )));
        }
        self.effective_scope = new_scope;
        Ok(())
    }

    /// Creates a child envelope for hop $k+1$ via asymmetric meet narrowing:
    /// $\mathcal{S}_{\text{child}} = \mathcal{S}_{\text{parent}} \sqcap \mathcal{S}_{\text{requested}}$.
    pub fn delegate_narrowed(
        &self,
        child_envelope_id: impl Into<String>,
        next_delegatee_id: impl Into<String>,
        requested_scope: &ApcScope,
        signing_key: &[u8],
    ) -> Result<Self, String> {
        if !self.verify_seal(signing_key) {
            return Err("PARENT_SEAL_INVALID: Cannot delegate from an unverified parent envelope".to_string());
        }
        let next_hop = self.hop_index + 1;
        if next_hop > self.budget_spec.max_delegation_depth {
            return Err(format!(
                "DELEGATION_DEPTH_EXCEEDED: hop {} exceeds max_delegation_depth {}",
                next_hop, self.budget_spec.max_delegation_depth
            ));
        }

        let narrowed_scope = self.effective_scope.meet(requested_scope);
        let mut child = Self {
            envelope_id: child_envelope_id.into(),
            parent_envelope_id: Some(self.envelope_id.clone()),
            root_principal_id: self.root_principal_id.clone(),
            delegator_id: self.delegatee_id.clone(),
            delegatee_id: next_delegatee_id.into(),
            hop_index: next_hop,
            task_session_id: self.task_session_id.clone(),
            policy_version: self.policy_version.clone(),
            effective_scope: narrowed_scope,
            budget_spec: self.budget_spec.clone(),
            issued_at_unix: self.issued_at_unix,
            expires_at_unix: self.expires_at_unix,
            parent_seal_hex: Some(self.seal_hmac_hex.clone()),
            seal_hmac_hex: String::new(),
            sealed: false,
        };
        child.seal_in_place(signing_key);
        Ok(child)
    }
}

/// Recorded action entry in the stateful composition history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutedActionEvent {
    pub session_id: String,
    pub root_principal_id: String,
    pub actor_id: String,
    pub action: String,
    pub action_class: String,
    pub resource: String,
}

/// Stateful Composition Checker (`CompositionChecker`, Paper §4.4 & §6.3).
///
/// Tracks executed actions per `session_id` AND per `root_principal_id` (lineage) so that
/// cross-session splitting attacks are deterministically caught.
#[derive(Debug, Default)]
pub struct CompositionChecker {
    session_history: Mutex<HashMap<String, Vec<ExecutedActionEvent>>>,
    principal_lineage_history: Mutex<HashMap<String, Vec<ExecutedActionEvent>>>,
    pub enforce_cross_session_lineage: bool,
}

impl CompositionChecker {
    pub fn new(enforce_cross_session_lineage: bool) -> Self {
        Self {
            session_history: Mutex::new(HashMap::new()),
            principal_lineage_history: Mutex::new(HashMap::new()),
            enforce_cross_session_lineage,
        }
    }

    /// Evaluates whether executing `(action, resource)` would violate any pairwise or $k$-tuple
    /// composition restriction in `scope`.
    pub fn check_candidate(
        &self,
        scope: &ApcScope,
        session_id: &str,
        root_principal_id: &str,
        actor_id: &str,
        action: &str,
        resource: &str,
    ) -> Result<ExecutedActionEvent, String> {
        let candidate_class = classify_action_class(action).to_string();
        let candidate = ExecutedActionEvent {
            session_id: session_id.to_string(),
            root_principal_id: root_principal_id.to_string(),
            actor_id: actor_id.to_string(),
            action: action.to_string(),
            action_class: candidate_class,
            resource: resource.to_string(),
        };

        // 1. Check within-session history
        {
            let sess_map = self.session_history.lock().unwrap();
            if let Some(history) = sess_map.get(session_id) {
                Self::verify_against_history(scope, history, &candidate, "SESSION")?;
            }
        }

        // 2. Check cross-session root principal lineage history (Adaptive Attack Defense, Paper §6.3)
        if self.enforce_cross_session_lineage {
            let lin_map = self.principal_lineage_history.lock().unwrap();
            if let Some(history) = lin_map.get(root_principal_id) {
                Self::verify_against_history(
                    scope,
                    history,
                    &candidate,
                    "CROSS_SESSION_LINEAGE",
                )?;
            }
        }

        Ok(candidate)
    }

    /// Commits an approved action event into both session and principal-lineage histories.
    pub fn commit_event(&self, event: ExecutedActionEvent) {
        self.session_history
            .lock()
            .unwrap()
            .entry(event.session_id.clone())
            .or_default()
            .push(event.clone());
        self.principal_lineage_history
            .lock()
            .unwrap()
            .entry(event.root_principal_id.clone())
            .or_default()
            .push(event);
    }

    pub fn total_tracked_sessions(&self) -> usize {
        self.session_history.lock().unwrap().len()
    }

    pub fn total_tracked_lineages(&self) -> usize {
        self.principal_lineage_history.lock().unwrap().len()
    }

    fn verify_against_history(
        scope: &ApcScope,
        history: &[ExecutedActionEvent],
        candidate: &ExecutedActionEvent,
        window_label: &str,
    ) -> Result<(), String> {
        // Pairwise check (k = 2)
        for rule in &scope.pairwise_restrictions {
            if candidate.action_class == rule.second_class
                && history.iter().any(|h| h.action_class == rule.first_class)
            {
                return Err(format!(
                    "COMPOSITION_PAIRWISE_VIOLATION ({}) [{}]: forbidden transition {} -> {} on resource '{}'",
                    window_label, rule.rule_id, rule.first_class, rule.second_class, candidate.resource
                ));
            }
        }

        // Ordered k-tuple subsequence check (k >= 2)
        for krule in &scope.ktuple_restrictions {
            let k = krule.ordered_steps.len();
            if k < 2 {
                continue;
            }
            let last_step = &krule.ordered_steps[k - 1];
            if candidate.action_class != last_step.action_class
                || !resource_pattern_matches(&last_step.resource_pattern, &candidate.resource)
            {
                continue;
            }

            // Greedy ordered subsequence scan for steps 0 .. k-1 across prior history
            let prefix_steps = &krule.ordered_steps[..k - 1];
            let mut matched_idx = 0;
            for ev in history {
                let target_step = &prefix_steps[matched_idx];
                if ev.action_class == target_step.action_class
                    && resource_pattern_matches(&target_step.resource_pattern, &ev.resource)
                {
                    matched_idx += 1;
                    if matched_idx == prefix_steps.len() {
                        return Err(format!(
                            "COMPOSITION_KTUPLE_VIOLATION ({}) [{}]: ordered {}-step exfiltration chain completed at '{}'",
                            window_label, krule.rule_id, k, candidate.resource
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

/// Computes the deterministic SHA-256 action hash for Condition 4 (`ApprovalToken` binding):
/// `SHA256(actor_id | action | resource | session_id | canonical_params)`.
pub fn compute_action_hash(
    actor_id: &str,
    action: &str,
    resource: &str,
    session_id: &str,
    canonical_params: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(
        format!(
            "{}|{}|{}|{}|{}",
            actor_id, action, resource, session_id, canonical_params
        )
        .as_bytes(),
    );
    hex::encode(hasher.finalize())
}

/// Condition 4 (`C4`): Single-Use Action-Hash Bound Approval Token (`ApprovalToken`, Paper §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalToken {
    pub token_id: String,
    pub approver_id: String,
    pub expected_action_hash: String,
    pub expires_at_unix: i64,
    pub hmac_signature: String,
}

impl ApprovalToken {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        token_id: impl Into<String>,
        approver_id: impl Into<String>,
        actor_id: &str,
        action: &str,
        resource: &str,
        session_id: &str,
        canonical_params: &str,
        expires_at_unix: i64,
        signing_key: &[u8],
    ) -> Self {
        let token_id = token_id.into();
        let approver_id = approver_id.into();
        let expected_action_hash =
            compute_action_hash(actor_id, action, resource, session_id, canonical_params);
        let payload = format!(
            "{}|{}|{}|{}",
            token_id, approver_id, expected_action_hash, expires_at_unix
        );
        let hmac_signature = compute_hmac_sha256_hex(signing_key, payload.as_bytes());
        Self {
            token_id,
            approver_id,
            expected_action_hash,
            expires_at_unix,
            hmac_signature,
        }
    }
}

/// Condition 5 (`C5`): Tamper-Evident SHA-256 Hash-Chained Evidence Sink (`EvidenceSink`, Paper §5.2).
///
/// Enforces fail-closed semantics: if `available == false`, `append_evidence` fails and the PDP
/// denies execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub sequence_no: usize,
    pub envelope_id: String,
    pub actor_id: String,
    pub action: String,
    pub resource: String,
    pub decision: String,
    pub prev_hash: String,
    pub record_hash: String,
}

#[derive(Debug)]
pub struct EvidenceSink {
    records: Mutex<Vec<EvidenceRecord>>,
    pub available: bool,
}

impl Default for EvidenceSink {
    fn default() -> Self {
        Self::new(true)
    }
}

impl EvidenceSink {
    pub fn new(available: bool) -> Self {
        Self {
            records: Mutex::new(Vec::new()),
            available,
        }
    }

    pub fn append_evidence(
        &self,
        envelope_id: &str,
        actor_id: &str,
        action: &str,
        resource: &str,
        decision: &str,
    ) -> Result<EvidenceRecord, String> {
        if !self.available {
            return Err(
                "C5_EVIDENCE_SINK_UNAVAILABLE: Fail-closed evidence requirement violated"
                    .to_string(),
            );
        }
        let mut guard = self.records.lock().unwrap();
        let seq = guard.len();
        let prev_hash = guard
            .last()
            .map(|r| r.record_hash.clone())
            .unwrap_or_else(|| "genesis".to_string());

        let mut hasher = Sha256::new();
        hasher.update(
            format!(
                "{}|{}|{}|{}|{}|{}|{}",
                seq, envelope_id, actor_id, action, resource, decision, prev_hash
            )
            .as_bytes(),
        );
        let record_hash = hex::encode(hasher.finalize());
        let record = EvidenceRecord {
            sequence_no: seq,
            envelope_id: envelope_id.to_string(),
            actor_id: actor_id.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            decision: decision.to_string(),
            prev_hash,
            record_hash,
        };
        guard.push(record.clone());
        Ok(record)
    }

    pub fn verify_integrity(&self) -> bool {
        let guard = self.records.lock().unwrap();
        let mut expected_prev = "genesis".to_string();
        for (idx, rec) in guard.iter().enumerate() {
            if rec.sequence_no != idx || rec.prev_hash != expected_prev {
                return false;
            }
            let mut hasher = Sha256::new();
            hasher.update(
                format!(
                    "{}|{}|{}|{}|{}|{}|{}",
                    rec.sequence_no,
                    rec.envelope_id,
                    rec.actor_id,
                    rec.action,
                    rec.resource,
                    rec.decision,
                    rec.prev_hash
                )
                .as_bytes(),
            );
            let computed = hex::encode(hasher.finalize());
            if !constant_time_eq_str(&computed, &rec.record_hash) {
                return false;
            }
            expected_prev = rec.record_hash.clone();
        }
        true
    }

    pub fn len(&self) -> usize {
        self.records.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Condition 6 (`C6`): Pre-Declared Intent Enforcement Mode (`apc/intent.py`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentEnforcementMode {
    Strict,
    Warn,
    Audit,
}

/// Pre-Declared Intent Specification (`IntentSpec`, Paper §5.3).
/// Enforces `action_resource_map` precedence over flat `intended_actions`/`intended_resources`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentSpec {
    pub intent_id: String,
    pub intended_actions: BTreeSet<String>,
    pub intended_resources: BTreeSet<String>,
    pub action_resource_map: BTreeMap<String, BTreeSet<String>>,
    pub mode: IntentEnforcementMode,
}

impl IntentSpec {
    pub fn check_intent(&self, action: &str, resource: &str) -> Result<Option<String>, String> {
        let matched = if !self.action_resource_map.is_empty() {
            if let Some(allowed_res) = self.action_resource_map.get(action) {
                allowed_res
                    .iter()
                    .any(|pattern| resource_pattern_matches(pattern, resource))
            } else {
                false
            }
        } else {
            let act_ok =
                self.intended_actions.contains("*") || self.intended_actions.contains(action);
            let res_ok = self
                .intended_resources
                .iter()
                .any(|pattern| resource_pattern_matches(pattern, resource));
            act_ok && res_ok
        };

        if matched {
            return Ok(None);
        }

        let violation = format!(
            "C6_INTENT_MISMATCH: action '{}' on resource '{}' outside pre-declared intent '{}'",
            action, resource, self.intent_id
        );
        match self.mode {
            IntentEnforcementMode::Strict => Err(violation),
            IntentEnforcementMode::Warn | IntentEnforcementMode::Audit => Ok(Some(violation)),
        }
    }
}

/// Proposed agent tool call submitted to the APC Policy Decision Point (`ApcActionRequest`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApcActionRequest {
    pub actor_id: String,
    pub action: String,
    pub resource: String,
    pub data_classification: String,
    pub parameters_canonical: String,
    pub task_session_id: String,
    pub policy_version: String,
    pub now_unix: i64,
    pub requires_approval: bool,
    pub approval_token: Option<ApprovalToken>,
    pub is_irreversible: bool,
    pub sensitivity_tier: u8,
    pub is_cross_domain: bool,
    pub cost_delta: f64,
}

/// Decision returned by `ApcPolicyDecisionPoint::evaluate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApcDecision {
    pub allowed: bool,
    pub satisfied_conditions: Vec<String>,
    pub failed_condition: Option<String>,
    pub reason: String,
    pub evidence_hash: Option<String>,
    pub intent_warning: Option<String>,
}

/// Status summary of the APC Policy Decision Point for REST API, WebUI, and CLI reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApcStatusSummary {
    pub active_policy_version: String,
    pub enforce_cross_session_lineage: bool,
    pub evidence_sink_available: bool,
    pub evidence_chain_length: usize,
    pub evidence_chain_integrity_ok: bool,
    pub tracked_sessions_count: usize,
    pub tracked_principal_lineages_count: usize,
    pub consumed_approval_tokens_count: usize,
}

/// Agentic Principal Chain Policy Decision Point (`ApcPolicyDecisionPoint`, Paper §5).
///
/// Evaluates the six conjunctive admissibility conditions:
/// $\text{Admissible}(a) \iff C_1 \wedge C_2 \wedge C_3 \wedge C_4 \wedge C_5 \wedge C_6$
pub struct ApcPolicyDecisionPoint {
    signing_key: Vec<u8>,
    pub active_policy_version: String,
    pub composition_checker: CompositionChecker,
    pub evidence_sink: EvidenceSink,
    consumed_approval_tokens: Mutex<BTreeSet<String>>,
    budget_states: Mutex<HashMap<String, BudgetState>>,
}

impl ApcPolicyDecisionPoint {
    pub fn new(
        signing_key: impl Into<Vec<u8>>,
        active_policy_version: impl Into<String>,
        enforce_cross_session_lineage: bool,
    ) -> Self {
        Self {
            signing_key: signing_key.into(),
            active_policy_version: active_policy_version.into(),
            composition_checker: CompositionChecker::new(enforce_cross_session_lineage),
            evidence_sink: EvidenceSink::new(true),
            consumed_approval_tokens: Mutex::new(BTreeSet::new()),
            budget_states: Mutex::new(HashMap::new()),
        }
    }

    pub fn signing_key(&self) -> &[u8] {
        &self.signing_key
    }

    pub fn status_summary(&self) -> ApcStatusSummary {
        ApcStatusSummary {
            active_policy_version: self.active_policy_version.clone(),
            enforce_cross_session_lineage: self.composition_checker.enforce_cross_session_lineage,
            evidence_sink_available: self.evidence_sink.available,
            evidence_chain_length: self.evidence_sink.len(),
            evidence_chain_integrity_ok: self.evidence_sink.verify_integrity(),
            tracked_sessions_count: self.composition_checker.total_tracked_sessions(),
            tracked_principal_lineages_count: self.composition_checker.total_tracked_lineages(),
            consumed_approval_tokens_count: self.consumed_approval_tokens.lock().unwrap().len(),
        }
    }

    pub fn evaluate(
        &self,
        envelope: &AuthorizationEnvelope,
        intent: &IntentSpec,
        req: &ApcActionRequest,
    ) -> ApcDecision {
        let mut satisfied = Vec::with_capacity(6);

        // C1: Identity & Cryptographic Envelope Seal Binding
        if !envelope.verify_seal(&self.signing_key) {
            return self.deny(
                envelope,
                req,
                satisfied,
                "C1_IDENTITY",
                "Envelope HMAC seal verification failed",
            );
        }
        if envelope.delegatee_id != req.actor_id {
            return self.deny(
                envelope,
                req,
                satisfied,
                "C1_IDENTITY",
                &format!(
                    "Actor '{}' does not match envelope delegatee '{}'",
                    req.actor_id, envelope.delegatee_id
                ),
            );
        }
        satisfied.push("C1_IDENTITY".to_string());

        // C2: Scope + Stateful Composition + 6D Monotonic Budget
        if !envelope.effective_scope.allows_action(&req.action) {
            return self.deny(
                envelope,
                req,
                satisfied,
                "C2_SCOPE_ACTION",
                &format!("Action '{}' not in narrowed scope", req.action),
            );
        }
        if !envelope.effective_scope.allows_resource(&req.resource) {
            return self.deny(
                envelope,
                req,
                satisfied,
                "C2_SCOPE_RESOURCE",
                &format!("Resource '{}' not in narrowed scope", req.resource),
            );
        }
        if !envelope
            .effective_scope
            .allows_classification(&req.data_classification)
        {
            return self.deny(
                envelope,
                req,
                satisfied,
                "C2_SCOPE_CLASSIFICATION",
                &format!(
                    "Classification '{}' not in narrowed scope",
                    req.data_classification
                ),
            );
        }

        let candidate_event = match self.composition_checker.check_candidate(
            &envelope.effective_scope,
            &req.task_session_id,
            &envelope.root_principal_id,
            &req.actor_id,
            &req.action,
            &req.resource,
        ) {
            Ok(ev) => ev,
            Err(err) => return self.deny(envelope, req, satisfied, "C2_COMPOSITION", &err),
        };

        {
            let mut budgets = self.budget_states.lock().unwrap();
            let bstate = budgets
                .entry(envelope.root_principal_id.clone())
                .or_default();
            if let Err(budget_err) = bstate.check_and_record(
                &envelope.budget_spec,
                1,
                req.is_irreversible,
                envelope.hop_index,
                req.sensitivity_tier,
                req.is_cross_domain,
                req.cost_delta,
            ) {
                return self.deny(envelope, req, satisfied, "C2_BUDGET", &budget_err);
            }
        }
        satisfied.push("C2_SCOPE_COMPOSITION_BUDGET".to_string());

        // C3: Context Binding (Freshness, Session ID, Policy Version)
        if req.now_unix < envelope.issued_at_unix || req.now_unix > envelope.expires_at_unix {
            return self.deny(
                envelope,
                req,
                satisfied,
                "C3_CONTEXT_EXPIRY",
                "Action timestamp outside envelope validity window",
            );
        }
        if req.task_session_id != envelope.task_session_id {
            return self.deny(
                envelope,
                req,
                satisfied,
                "C3_CONTEXT_SESSION",
                "Cross-session envelope replay rejected",
            );
        }
        if req.policy_version != self.active_policy_version
            || envelope.policy_version != self.active_policy_version
        {
            return self.deny(
                envelope,
                req,
                satisfied,
                "C3_CONTEXT_POLICY_VERSION",
                "Stale policy version rejected",
            );
        }
        satisfied.push("C3_CONTEXT".to_string());

        // C4: Single-Use Action-Hash Bound Approval Token
        if req.requires_approval || req.is_irreversible {
            let Some(token) = &req.approval_token else {
                return self.deny(
                    envelope,
                    req,
                    satisfied,
                    "C4_APPROVAL_MISSING",
                    "High-consequence or irreversible action requires ApprovalToken",
                );
            };
            if req.now_unix > token.expires_at_unix {
                return self.deny(
                    envelope,
                    req,
                    satisfied,
                    "C4_APPROVAL_EXPIRED",
                    "ApprovalToken has expired",
                );
            }
            let expected_hash = compute_action_hash(
                &req.actor_id,
                &req.action,
                &req.resource,
                &req.task_session_id,
                &req.parameters_canonical,
            );
            if !constant_time_eq_str(&token.expected_action_hash, &expected_hash) {
                return self.deny(
                    envelope,
                    req,
                    satisfied,
                    "C4_APPROVAL_HASH_MISMATCH",
                    "ApprovalToken action hash does not match request parameters",
                );
            }
            let payload = format!(
                "{}|{}|{}|{}",
                token.token_id,
                token.approver_id,
                token.expected_action_hash,
                token.expires_at_unix
            );
            let expected_sig = compute_hmac_sha256_hex(&self.signing_key, payload.as_bytes());
            if !constant_time_eq_str(&token.hmac_signature, &expected_sig) {
                return self.deny(
                    envelope,
                    req,
                    satisfied,
                    "C4_APPROVAL_SIGNATURE_INVALID",
                    "ApprovalToken HMAC signature invalid",
                );
            }
            let mut used = self.consumed_approval_tokens.lock().unwrap();
            if !used.insert(token.token_id.clone()) {
                return self.deny(
                    envelope,
                    req,
                    satisfied,
                    "C4_APPROVAL_REPLAY",
                    "Single-use ApprovalToken already consumed",
                );
            }
        }
        satisfied.push("C4_APPROVAL".to_string());

        // C6: Pre-Declared Intent Alignment (evaluated before committing C5 evidence)
        let intent_warning = match intent.check_intent(&req.action, &req.resource) {
            Ok(warn_opt) => warn_opt,
            Err(intent_err) => {
                return self.deny(envelope, req, satisfied, "C6_INTENT", &intent_err);
            }
        };
        satisfied.push("C6_INTENT".to_string());

        // C5: Fail-Closed SHA-256 Hash-Chained Evidence Sink
        let evidence_rec = match self.evidence_sink.append_evidence(
            &envelope.envelope_id,
            &req.actor_id,
            &req.action,
            &req.resource,
            "ALLOW",
        ) {
            Ok(rec) => rec,
            Err(ev_err) => return self.deny(envelope, req, satisfied, "C5_EVIDENCE", &ev_err),
        };
        satisfied.push("C5_EVIDENCE".to_string());

        // Commit event to stateful session & lineage history only after all 6 conditions succeed
        self.composition_checker.commit_event(candidate_event);

        ApcDecision {
            allowed: true,
            satisfied_conditions: satisfied,
            failed_condition: None,
            reason: "ALLOW: All 6 conjunctive APC conditions satisfied (C1..C6)".to_string(),
            evidence_hash: Some(evidence_rec.record_hash),
            intent_warning,
        }
    }

    fn deny(
        &self,
        envelope: &AuthorizationEnvelope,
        req: &ApcActionRequest,
        satisfied: Vec<String>,
        failed_cond: &str,
        reason: &str,
    ) -> ApcDecision {
        let ev_hash = self
            .evidence_sink
            .append_evidence(
                &envelope.envelope_id,
                &req.actor_id,
                &req.action,
                &req.resource,
                &format!("DENY:{}", failed_cond),
            )
            .ok()
            .map(|r| r.record_hash);

        ApcDecision {
            allowed: false,
            satisfied_conditions: satisfied,
            failed_condition: Some(failed_cond.to_string()),
            reason: reason.to_string(),
            evidence_hash: ev_hash,
            intent_warning: None,
        }
    }
}

/// Cedar Policy Templates grounded from `arXiv:2608.15888` (`xmuruaga/bounded-agents`).
pub fn bounded_agents_apc_cedar_policies() -> &'static str {
    r#"// Bounded Agents: Agentic Principal Chain (APC) Cedar Policies (arXiv:2608.15888)
// Enforces C1..C6 conjunctive delegation security and cross-session composition invariants.

@id("arxiv-2608-15888-apc-c1-c3-envelope-seal-and-context")
forbid (
    principal,
    action,
    resource
)
when {
    !context.envelope_seal_verified ||
    context.actor_id != context.envelope_delegatee_id ||
    context.task_session_id != context.envelope_session_id ||
    context.policy_version != context.active_policy_version
};

@id("arxiv-2608-15888-apc-c2-pairwise-and-ktuple-exfiltration-guard")
forbid (
    principal,
    action,
    resource
)
when {
    context.composition_pairwise_violated ||
    context.composition_ktuple_violated ||
    context.cross_session_lineage_split_detected ||
    context.delegation_budget_exceeded
};

@id("arxiv-2608-15888-apc-c4-c5-c6-approval-evidence-intent")
forbid (
    principal,
    action,
    resource
)
when {
    (context.requires_approval && !context.approval_token_valid) ||
    !context.evidence_sink_healthy ||
    context.intent_strict_mismatch
};
"#
}

/// Default enterprise APC scope for evaluating actions via REST API / CLI.
pub fn default_enterprise_apc_scope() -> ApcScope {
    ApcScope::new(
        ["docs/*", "external/email", "internal/*"],
        ["read_confidential", "send_email", "read_public"],
        ["CONFIDENTIAL", "PUBLIC", "INTERNAL"],
        [PairwiseRestriction::new(
            "no_confidential_exfil",
            "READ_CONFIDENTIAL",
            "EXTERNAL_TRANSMIT",
        )],
        [KTupleRestriction::new(
            "ordered_q3_exfil",
            vec![
                KTupleStep {
                    action_class: "READ_CONFIDENTIAL".to_string(),
                    resource_pattern: "docs/q3-*".to_string(),
                },
                KTupleStep {
                    action_class: "EXTERNAL_TRANSMIT".to_string(),
                    resource_pattern: "external/*".to_string(),
                },
            ],
        )],
    )
}

static GLOBAL_APC_PDP: OnceLock<ApcPolicyDecisionPoint> = OnceLock::new();

/// Global thread-safe singleton for the Bounded Agents APC Policy Decision Point (`arXiv:2608.15888`).
pub fn global_apc_pdp() -> &'static ApcPolicyDecisionPoint {
    GLOBAL_APC_PDP.get_or_init(|| {
        ApcPolicyDecisionPoint::new(b"killswitch-apc-root-key-32bytes!".to_vec(), "v1.0", true)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_scope() -> ApcScope {
        default_enterprise_apc_scope()
    }

    #[test]
    fn test_thm_4_6_asymmetric_meet_semilattice_and_monotonic_blast_radius() {
        let parent = sample_scope();
        let child_req = ApcScope::new(
            ["docs/q3-financials", "external/email", "ungranted/secret"],
            ["read_confidential", "send_email", "exec_shell"],
            ["CONFIDENTIAL"],
            [PairwiseRestriction::new(
                "no_code_exec_after_read",
                "READ_CONFIDENTIAL",
                "EXECUTE_CODE",
            )],
            [],
        );

        let narrowed = parent.meet(&child_req);
        assert!(narrowed.allows_resource("docs/q3-financials"));
        assert!(!narrowed.allows_resource("docs/q4-financials"));
        assert!(!narrowed.allows_resource("ungranted/secret"));
        assert!(narrowed.allows_action("read_confidential"));
        assert!(!narrowed.allows_action("exec_shell"));
        assert_eq!(narrowed.pairwise_restrictions.len(), 2);
        assert_eq!(narrowed.ktuple_restrictions.len(), 1);
        assert!(narrowed.blast_radius() <= parent.blast_radius());
    }

    #[test]
    fn test_sealed_envelope_and_multi_hop_attenuation() {
        let key = b"killswitch-apc-test-key-32-bytes";
        let mut root_env = AuthorizationEnvelope::new_root(
            "env-hop-1",
            "user-alice",
            "orchestrator-agent",
            "sess-100",
            "v1.0",
            sample_scope(),
            DelegationBudgetSpec::default(),
            1_700_000_000,
            1_700_003_600,
            key,
        );

        assert!(root_env
            .attempt_in_place_scope_mutation(sample_scope())
            .is_err());

        let sub_scope = ApcScope::new(
            ["docs/q3-financials", "external/email"],
            ["read_confidential", "send_email"],
            ["CONFIDENTIAL", "PUBLIC"],
            [],
            [],
        );
        let hop2 = root_env
            .delegate_narrowed("env-hop-2", "worker-subagent", &sub_scope, key)
            .expect("hop 2 delegation must succeed");
        assert_eq!(hop2.hop_index, 2);
        assert_eq!(hop2.root_principal_id, "user-alice");
        assert!(hop2.verify_seal(key));
        assert!(hop2.effective_scope.blast_radius() <= root_env.effective_scope.blast_radius());
    }

    #[test]
    fn test_six_conjunctive_conditions_and_exfiltration_prevention() {
        let key = b"killswitch-apc-test-key-32-bytes";
        let pdp = ApcPolicyDecisionPoint::new(key.to_vec(), "v1.0", true);
        let env = AuthorizationEnvelope::new_root(
            "env-root",
            "principal-alice",
            "agent-worker-1",
            "sess-alpha",
            "v1.0",
            sample_scope(),
            DelegationBudgetSpec::default(),
            1_700_000_000,
            1_700_003_600,
            key,
        );
        let mut action_map = BTreeMap::new();
        action_map.insert(
            "read_confidential".to_string(),
            BTreeSet::from(["docs/*".to_string()]),
        );
        action_map.insert(
            "send_email".to_string(),
            BTreeSet::from(["external/email".to_string()]),
        );
        let intent = IntentSpec {
            intent_id: "intent-q3-summary".to_string(),
            intended_actions: BTreeSet::new(),
            intended_resources: BTreeSet::new(),
            action_resource_map: action_map,
            mode: IntentEnforcementMode::Strict,
        };

        // Step 1: Read confidential Q3 financials -> ALLOWED
        let req1 = ApcActionRequest {
            actor_id: "agent-worker-1".to_string(),
            action: "read_confidential".to_string(),
            resource: "docs/q3-financials".to_string(),
            data_classification: "CONFIDENTIAL".to_string(),
            parameters_canonical: "{}".to_string(),
            task_session_id: "sess-alpha".to_string(),
            policy_version: "v1.0".to_string(),
            now_unix: 1_700_000_100,
            requires_approval: false,
            approval_token: None,
            is_irreversible: false,
            sensitivity_tier: 2,
            is_cross_domain: false,
            cost_delta: 0.5,
        };
        let dec1 = pdp.evaluate(&env, &intent, &req1);
        assert!(dec1.allowed, "Step 1 read must be allowed: {:?}", dec1);

        // Step 2: Send external email in same session -> BLOCKED by C2 Composition
        let req2 = ApcActionRequest {
            action: "send_email".to_string(),
            resource: "external/email".to_string(),
            data_classification: "PUBLIC".to_string(),
            ..req1.clone()
        };
        let dec2 = pdp.evaluate(&env, &intent, &req2);
        assert!(!dec2.allowed);
        assert_eq!(dec2.failed_condition.as_deref(), Some("C2_COMPOSITION"));

        // Step 3: Adaptive attack — Cross-session splitting under same root principal ("principal-alice")
        let env_session_beta = AuthorizationEnvelope::new_root(
            "env-root-beta",
            "principal-alice",
            "agent-worker-2",
            "sess-beta",
            "v1.0",
            sample_scope(),
            DelegationBudgetSpec::default(),
            1_700_000_000,
            1_700_003_600,
            key,
        );
        let req_split = ApcActionRequest {
            actor_id: "agent-worker-2".to_string(),
            action: "send_email".to_string(),
            resource: "external/email".to_string(),
            data_classification: "PUBLIC".to_string(),
            task_session_id: "sess-beta".to_string(),
            ..req1
        };
        let dec_split = pdp.evaluate(&env_session_beta, &intent, &req_split);
        assert!(
            !dec_split.allowed,
            "Cross-session principal lineage guard must block adaptive session-splitting attack"
        );
        assert!(dec_split.reason.contains("CROSS_SESSION_LINEAGE"));
        assert!(pdp.evidence_sink.verify_integrity());
    }

    #[test]
    fn test_c4_single_use_approval_and_c5_fail_closed_evidence() {
        let key = b"killswitch-apc-test-key-32-bytes";
        let mut pdp = ApcPolicyDecisionPoint::new(key.to_vec(), "v1.0", true);
        let env = AuthorizationEnvelope::new_root(
            "env-c4",
            "principal-bob",
            "agent-ops",
            "sess-c4",
            "v1.0",
            sample_scope(),
            DelegationBudgetSpec::default(),
            1_700_000_000,
            1_700_003_600,
            key,
        );
        let intent = IntentSpec {
            intent_id: "intent-ops".to_string(),
            intended_actions: BTreeSet::from(["read_public".to_string()]),
            intended_resources: BTreeSet::from(["docs/*".to_string()]),
            action_resource_map: BTreeMap::new(),
            mode: IntentEnforcementMode::Strict,
        };
        let token = ApprovalToken::issue(
            "tok-001",
            "human-secops",
            "agent-ops",
            "read_public",
            "docs/readme",
            "sess-c4",
            "{\"fmt\":\"txt\"}",
            1_700_001_000,
            key,
        );
        let req = ApcActionRequest {
            actor_id: "agent-ops".to_string(),
            action: "read_public".to_string(),
            resource: "docs/readme".to_string(),
            data_classification: "PUBLIC".to_string(),
            parameters_canonical: "{\"fmt\":\"txt\"}".to_string(),
            task_session_id: "sess-c4".to_string(),
            policy_version: "v1.0".to_string(),
            now_unix: 1_700_000_200,
            requires_approval: true,
            approval_token: Some(token),
            is_irreversible: true,
            sensitivity_tier: 1,
            is_cross_domain: false,
            cost_delta: 0.1,
        };
        let first = pdp.evaluate(&env, &intent, &req);
        assert!(first.allowed);

        // Replay of the same ApprovalToken must be denied (C4_APPROVAL_REPLAY)
        let replay = pdp.evaluate(&env, &intent, &req);
        assert!(!replay.allowed);
        assert_eq!(
            replay.failed_condition.as_deref(),
            Some("C4_APPROVAL_REPLAY")
        );

        // Disable evidence sink -> must fail closed on C5_EVIDENCE
        pdp.evidence_sink.available = false;
        let mut req_no_approval = req.clone();
        req_no_approval.requires_approval = false;
        req_no_approval.is_irreversible = false;
        let c5_fail = pdp.evaluate(&env, &intent, &req_no_approval);
        assert!(!c5_fail.allowed);
        assert_eq!(c5_fail.failed_condition.as_deref(), Some("C5_EVIDENCE"));
    }
}
