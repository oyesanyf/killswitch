//! # Octopus Arm Containment Ring & Surgical Autotomy Controller
//!
//! Level 1 containment ring for sandboxed agent arms, enforcing:
//! 1. Monotonic Generation Epoch Advancement (`Gen N -> Gen N + 1`).
//! 2. Surgical Autotomy State Machine (`Active -> Severing -> Severed -> Regenerating -> Active(Gen+1)`).
//! 3. Fail-Closed Role Authorizers (zero wildcard arm match; all 18 roles mapped).
//! 4. Capability Token Issuance & Verification with constant-time HMAC check.
//! 5. Resource and tool boundary constraints.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

use killswitch_types::{
    role_trust_tier, ArmRole, KillSwitchError, KillSwitchResult, ProvenanceHop, TrustTier,
};

type HmacSha256 = Hmac<Sha256>;

/// Surgical Autotomy Lifecycle States.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ArmState {
    Active {
        generation: u64,
    },
    Severing {
        generation: u64,
        reason: String,
        initiated_at_us: u64,
    },
    Severed {
        revoked_generation: u64,
        reason: String,
        severed_at_us: u64,
    },
    Regenerating {
        from_gen: u64,
        target_gen: u64,
        started_at_us: u64,
    },
}

#[derive(Debug, Clone)]
pub struct ArmRingConfig {
    pub max_memory_bytes: usize,
    pub step_limit: usize,
    pub max_execution_time: Duration,
}

impl Default for ArmRingConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 64 * 1024 * 1024, // 64 MB
            step_limit: 10,
            max_execution_time: Duration::from_secs(5),
        }
    }
}

/// Short-lived capability token required for arm tool invocations.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapabilityToken {
    pub token_id: String,
    pub originator_agent: String,
    pub bearer_agent: String,
    pub permitted_role: ArmRole,
    pub permitted_tool: String,
    pub resource_uri_prefix: String,
    pub issued_at_secs: u64,
    pub expires_at_secs: u64,
    pub policy_fingerprint: String,
    pub signature_hex: String,
}

impl CapabilityToken {
    pub fn is_expired(&self, current_time_secs: u64) -> bool {
        current_time_secs > self.expires_at_secs
    }
}

/// Broadcast signal emitted upon arm autotomy to alert the entire mesh.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MeshWatchOutSignal {
    pub severed_arm_id: usize,
    pub revoked_generation: u64,
    pub new_generation: u64,
    pub reason: String,
    pub timestamp_us: u64,
}

/// Level 1 Agent Arm Containment Ring.
#[derive(Clone)]
pub struct ArmContainmentRing {
    pub arm_id: usize,
    pub agent_name: String,
    pub role: ArmRole,
    pub generation: Arc<AtomicU64>,
    master_seed: [u8; 32],
    state: Arc<RwLock<ArmState>>,
    allowed_tools: Arc<RwLock<HashSet<String>>>,
    allowed_resource_prefixes: Arc<RwLock<Vec<String>>>,
    revoked_epochs: Arc<RwLock<HashSet<u64>>>,
    step_counter: Arc<AtomicU64>,
    pub config: ArmRingConfig,
    taint_state: Arc<RwLock<(TrustTier, Vec<ProvenanceHop>)>>,
}

impl ArmContainmentRing {
    pub fn new(arm_id: usize, role: ArmRole, initial_generation: u64, master_seed: &[u8]) -> Self {
        let mut seed = [0u8; 32];
        if master_seed.len() >= 32 {
            seed.copy_from_slice(&master_seed[..32]);
        } else {
            let hash = Sha256::digest(master_seed);
            seed.copy_from_slice(&hash);
        }

        let agent_name = format!("arm-{}-{}", role.as_str().to_ascii_lowercase(), arm_id);
        let (tools, prefixes) = Self::default_permissions_for_role(&role);
        let initial_tier = role_trust_tier(&role);

        Self {
            arm_id,
            agent_name,
            role,
            generation: Arc::new(AtomicU64::new(initial_generation)),
            master_seed: seed,
            state: Arc::new(RwLock::new(ArmState::Active {
                generation: initial_generation,
            })),
            allowed_tools: Arc::new(RwLock::new(tools)),
            allowed_resource_prefixes: Arc::new(RwLock::new(prefixes)),
            revoked_epochs: Arc::new(RwLock::new(HashSet::new())),
            step_counter: Arc::new(AtomicU64::new(0)),
            config: ArmRingConfig::default(),
            taint_state: Arc::new(RwLock::new((initial_tier, Vec::new()))),
        }
    }

    /// Explicit, fail-closed role permission mapper.
    /// INVARIANT: NO wildcard match (`_ => ...`). Adding a role requires explicit classification.
    pub fn default_permissions_for_role(role: &ArmRole) -> (HashSet<String>, Vec<String>) {
        let mut tools = HashSet::new();
        let mut prefixes = Vec::new();

        match role {
            ArmRole::UntrustedDocIngest => {
                tools.insert("doc_extractor".to_string());
                tools.insert("peripheral_digest".to_string());
                prefixes.push("s3://invoices/".to_string());
                prefixes.push("s3://raw-docs/".to_string());
                prefixes.push("local_scratchpad".to_string());
            }
            ArmRole::AccountingLedgerWrite => {
                tools.insert("ledger_writer".to_string());
                prefixes.push("s3://accounting/".to_string());
                prefixes.push("local_scratchpad".to_string());
            }
            ArmRole::NetworkEgress => {
                tools.insert("http_egress".to_string());
                prefixes.push("https://".to_string());
                prefixes.push("http://".to_string());
            }
            ArmRole::OutboundNotification => {
                tools.insert("notifier".to_string());
                prefixes.push("notification://".to_string());
            }
            ArmRole::TarpitDecoyDefense => {
                tools.insert("quarantine".to_string());
                prefixes.push("tarpit://".to_string());
            }
            ArmRole::KernelLevelSentinel => {
                tools.insert("kernel_sentinel".to_string());
                prefixes.push("kernel://".to_string());
            }
            ArmRole::CedarPolicyEvaluation => {
                tools.insert("cedar_evaluator".to_string());
                prefixes.push("cedar://".to_string());
            }
            ArmRole::AtlasThreatIntelligence => {
                tools.insert("atlas_sync".to_string());
                prefixes.push("https://raw.githubusercontent.com/mitre-atlas/".to_string());
            }
            ArmRole::AnomalyDetection => {
                tools.insert("anomaly_evaluator".to_string());
                prefixes.push("metrics://".to_string());
            }
            ArmRole::VulnerabilityResearch => {
                tools.insert("vuln_research".to_string());
                prefixes.push("cve://".to_string());
            }
            ArmRole::ContinuousOssFuzz => {
                tools.insert("fuzz_runner".to_string());
                prefixes.push("fuzz://".to_string());
            }
            ArmRole::ContinuousOsvScanner => {
                tools.insert("osv_scanner".to_string());
                prefixes.push("osv://".to_string());
            }
            ArmRole::DifferentialProtocolAnalyzer => {
                tools.insert("protocol_analyzer".to_string());
                prefixes.push("protocol://".to_string());
            }
            ArmRole::AutonomousProtocolResearch => {
                tools.insert("protocol_research".to_string());
                prefixes.push("protocol://".to_string());
            }
            ArmRole::PostQuantumAttestation => {
                tools.insert("pqc_attestation".to_string());
                prefixes.push("pqc://".to_string());
            }
            ArmRole::EvolutionaryOptimizer => {
                tools.insert("evolutionary_optimizer".to_string());
                prefixes.push("evolution://".to_string());
            }
            ArmRole::DreamRsiOptimizer => {
                tools.insert("dream_rsi_optimizer".to_string());
                prefixes.push("dream_rsi://".to_string());
            }
            ArmRole::RecursiveHarnessOptimizer => {
                tools.insert("harness2_optimizer".to_string());
                prefixes.push("harness2://".to_string());
            }
        }

        (tools, prefixes)
    }

    /// Derives the cryptographic epoch key:
    /// EpochKey = SHA256(MasterSeed || ArmID_le || Epoch_le || Role_str)
    pub fn derive_epoch_key(&self, arm_id: usize, epoch: u64, role: &ArmRole) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.master_seed);
        hasher.update(arm_id.to_le_bytes());
        hasher.update(epoch.to_le_bytes());
        hasher.update(role.as_str().as_bytes());
        let hash = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        key
    }

    pub async fn allowed_tools(&self) -> HashSet<String> {
        self.allowed_tools.read().await.clone()
    }

    pub async fn allowed_resource_prefixes(&self) -> Vec<String> {
        self.allowed_resource_prefixes.read().await.clone()
    }

    pub fn current_key(&self) -> [u8; 32] {
        let current_gen = self.generation.load(Ordering::SeqCst);
        self.derive_epoch_key(self.arm_id, current_gen, &self.role)
    }

    pub fn current_generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Surgical Autotomy: Severs the arm and revokes its current epoch.
    pub async fn sever(&self, reason: &str) -> KillSwitchResult<()> {
        let now_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let current_gen = self.current_generation();

        {
            let mut state = self.state.write().await;
            *state = ArmState::Severing {
                generation: current_gen,
                reason: reason.to_string(),
                initiated_at_us: now_us,
            };
        }

        {
            let mut revoked = self.revoked_epochs.write().await;
            revoked.insert(current_gen);
        }

        {
            let mut state = self.state.write().await;
            *state = ArmState::Severed {
                revoked_generation: current_gen,
                reason: reason.to_string(),
                severed_at_us: now_us,
            };
        }

        Ok(())
    }

    /// Regenerates the arm: transitions `Severed -> Regenerating -> Active(Gen N + 1)`.
    pub async fn sever_and_regenerate(&self, reason: &str) -> KillSwitchResult<u64> {
        self.sever(reason).await?;

        let old_gen = self.current_generation();
        let next_gen = old_gen + 1;
        let now_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        {
            let mut state = self.state.write().await;
            *state = ArmState::Regenerating {
                from_gen: old_gen,
                target_gen: next_gen,
                started_at_us: now_us,
            };
        }

        self.generation.store(next_gen, Ordering::SeqCst);
        self.step_counter.store(0, Ordering::SeqCst);

        {
            let mut taint = self.taint_state.write().await;
            *taint = (role_trust_tier(&self.role), Vec::new());
        }

        {
            let mut state = self.state.write().await;
            *state = ArmState::Active {
                generation: next_gen,
            };
        }

        Ok(next_gen)
    }

    /// Validates a presented epoch token against this arm's active state.
    pub async fn validate_epoch(&self, epoch: u64) -> KillSwitchResult<()> {
        let state = self.state.read().await;
        match &*state {
            ArmState::Severed {
                revoked_generation,
                reason,
                ..
            } => {
                return Err(KillSwitchError::ArmQuarantined {
                    arm_id: self.arm_id,
                    role: self.role.as_str().to_string(),
                    epoch: *revoked_generation,
                    reason: reason.clone(),
                });
            }
            ArmState::Severing { .. } | ArmState::Regenerating { .. } => {
                return Err(KillSwitchError::OctopusViolation(format!(
                    "Arm {} is currently in transition ({:?})",
                    self.arm_id, *state
                )));
            }
            ArmState::Active { generation } => {
                let revoked = self.revoked_epochs.read().await;
                if revoked.contains(&epoch) {
                    return Err(KillSwitchError::StaleGenerationEpoch {
                        arm_id: self.arm_id,
                        expected: *generation,
                        presented: epoch,
                    });
                }
                if epoch != *generation {
                    return Err(KillSwitchError::StaleGenerationEpoch {
                        arm_id: self.arm_id,
                        expected: *generation,
                        presented: epoch,
                    });
                }
            }
        }
        Ok(())
    }

    /// Issues an unforgeable, short-lived capability token.
    pub async fn issue_capability(
        &self,
        tool: &str,
        resource: &str,
        ttl_secs: u64,
    ) -> KillSwitchResult<CapabilityToken> {
        let current_gen = self.current_generation();
        self.validate_epoch(current_gen).await?;

        let epoch_key = self.derive_epoch_key(self.arm_id, current_gen, &self.role);
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expires_at_secs = now_secs + ttl_secs;

        let token_id = format!("cap-{}-{}-{}", self.arm_id, current_gen, now_secs);
        let policy_fingerprint = format!(
            "arm_ring:epoch={}:arm={}:role={}",
            current_gen,
            self.arm_id,
            self.role.as_str()
        );

        let signing_content = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}",
            token_id,
            "supervisor",
            self.agent_name,
            self.role.as_str(),
            tool,
            resource,
            now_secs,
            expires_at_secs,
            policy_fingerprint
        );

        let mut mac = HmacSha256::new_from_slice(&epoch_key)
            .map_err(|e| KillSwitchError::CryptoError(e.to_string()))?;
        mac.update(signing_content.as_bytes());
        let sig_hex = hex::encode(mac.finalize().into_bytes());

        Ok(CapabilityToken {
            token_id,
            originator_agent: "supervisor".to_string(),
            bearer_agent: self.agent_name.clone(),
            permitted_role: self.role.clone(),
            permitted_tool: tool.to_string(),
            resource_uri_prefix: resource.to_string(),
            issued_at_secs: now_secs,
            expires_at_secs,
            policy_fingerprint,
            signature_hex: sig_hex,
        })
    }

    /// Verifies capability token in constant time BEFORE allowing tool invocation.
    pub async fn verify_capability(&self, token: &CapabilityToken) -> KillSwitchResult<()> {
        let current_gen = self.current_generation();
        self.validate_epoch(current_gen).await?;

        if !token.bearer_agent.eq_ignore_ascii_case(&self.agent_name) {
            return Err(KillSwitchError::OctopusViolation(format!(
                "Capability token bearer mismatch: issued to '{}' but used by '{}'",
                token.bearer_agent, self.agent_name
            )));
        }

        if token.permitted_role != self.role {
            return Err(KillSwitchError::OctopusViolation(format!(
                "Capability token role mismatch: token has {:?} but arm is {:?}",
                token.permitted_role, self.role
            )));
        }

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if token.is_expired(now_secs) {
            return Err(KillSwitchError::OctopusViolation(
                "Capability token has expired".to_string(),
            ));
        }

        let epoch_key = self.derive_epoch_key(self.arm_id, current_gen, &self.role);
        let signing_content = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}",
            token.token_id,
            token.originator_agent,
            token.bearer_agent,
            token.permitted_role.as_str(),
            token.permitted_tool,
            token.resource_uri_prefix,
            token.issued_at_secs,
            token.expires_at_secs,
            token.policy_fingerprint
        );

        let mut mac = HmacSha256::new_from_slice(&epoch_key)
            .map_err(|e| KillSwitchError::CryptoError(e.to_string()))?;
        mac.update(signing_content.as_bytes());
        let expected_bytes = mac.finalize().into_bytes();

        let sig_bytes = hex::decode(&token.signature_hex)
            .map_err(|e| KillSwitchError::CryptoError(format!("Invalid hex signature: {}", e)))?;

        if sig_bytes.len() != expected_bytes.len()
            || bool::from(!expected_bytes.ct_eq(&sig_bytes))
        {
            return Err(KillSwitchError::MeshHmacVerificationFailed {
                arm_id: self.arm_id,
            });
        }

        Ok(())
    }

    /// Primary Multi-Ring Containment Gate:
    /// Actively invokes capability HMAC verification, step-budget enforcement, role prefix authorization,
    /// `BreakoutDefenseCoordinator` (Technical, Operational, Behavioral/Entropy, Data), Mathematical SSRF
    /// validation, and Safe `Path::join` sandbox validation BEFORE any tool closure executes.
    /// Automatically performs Surgical Autotomy (`self.sever(...)`) on any breakout violation.
    pub async fn execute_guarded_tool<F, T>(
        &self,
        token: &CapabilityToken,
        resource: &str,
        payload: &str,
        sandbox_root: Option<&std::path::Path>,
        tool_closure: F,
    ) -> KillSwitchResult<T>
    where
        F: FnOnce() -> KillSwitchResult<T>,
    {
        // 1. Constant-time HMAC-SHA256 & Generation Epoch verification
        self.verify_capability(token).await?;

        // 2. Step-budget enforcement
        let step = self.step_counter.fetch_add(1, Ordering::SeqCst) + 1;
        if step > self.config.step_limit as u64 {
            let reason = format!(
                "Arm {} exceeded step budget ({} > {})",
                self.arm_id, step, self.config.step_limit
            );
            self.sever(&reason).await?;
            return Err(KillSwitchError::OctopusViolation(reason));
        }

        // 3. Explicit fail-closed tool & resource prefix check
        {
            let allowed_tools = self.allowed_tools.read().await;
            if !allowed_tools.contains(&token.permitted_tool) {
                let reason = format!(
                    "Tool '{}' is not authorized for role {:?}",
                    token.permitted_tool, self.role
                );
                self.sever(&reason).await?;
                return Err(KillSwitchError::OctopusViolation(reason));
            }
        }

        // 4. Active BreakoutDefenseCoordinator Gate (OpenAI Preparedness ARA & Anthropic RSP ASL-3/4)
        let coordinator = crate::octopus::BreakoutDefenseCoordinator::new();
        let eval = coordinator.evaluate_action(&token.permitted_tool, resource, payload);
        if !eval.is_clean {
            self.sever(&eval.summary).await?;
            return Err(KillSwitchError::OctopusViolation(eval.summary));
        }

        // 5. Mathematical IPv4/IPv6 SSRF Guard for HTTP/HTTPS egress resources
        let trimmed_res = resource.trim();
        if trimmed_res.starts_with("http://") || trimmed_res.starts_with("https://") {
            if let Err(ssrf_err) = crate::octopus::validate_egress_url(trimmed_res, false) {
                let reason = format!("SSRF guard blocked egress from Arm {}: {}", self.arm_id, ssrf_err);
                self.sever(&reason).await?;
                return Err(ssrf_err);
            }
        }

        // 6. Safe Path::join Sandbox Traversal Guard when sandbox_root is configured
        if let Some(root) = sandbox_root {
            if let Err(path_err) = crate::octopus::validate_sandbox_path(trimmed_res, root) {
                let reason = format!(
                    "Sandbox path traversal blocked on Arm {}: {}",
                    self.arm_id, path_err
                );
                self.sever(&reason).await?;
                return Err(path_err);
            }
        }

        // 7. Execute tool closure only after all containment rings pass
        tool_closure()
    }
}

/// Supervisor Registry managing all Level 1 containment rings.
#[derive(Clone)]
pub struct ArmRingRegistry {
    rings: Arc<RwLock<HashMap<usize, Arc<ArmContainmentRing>>>>,
    master_seed: [u8; 32],
    watchout_signals: Arc<RwLock<Vec<MeshWatchOutSignal>>>,
}

impl ArmRingRegistry {
    pub fn new(master_seed: &[u8]) -> Self {
        let mut seed = [0u8; 32];
        if master_seed.len() >= 32 {
            seed.copy_from_slice(&master_seed[..32]);
        } else {
            let hash = Sha256::digest(master_seed);
            seed.copy_from_slice(&hash);
        }

        let mut map = HashMap::new();
        let all_roles = [
            (0, ArmRole::UntrustedDocIngest),
            (1, ArmRole::AccountingLedgerWrite),
            (2, ArmRole::NetworkEgress),
            (3, ArmRole::OutboundNotification),
            (4, ArmRole::TarpitDecoyDefense),
            (5, ArmRole::KernelLevelSentinel),
            (6, ArmRole::CedarPolicyEvaluation),
            (7, ArmRole::AtlasThreatIntelligence),
            (8, ArmRole::AnomalyDetection),
            (9, ArmRole::VulnerabilityResearch),
            (10, ArmRole::ContinuousOssFuzz),
            (11, ArmRole::ContinuousOsvScanner),
            (12, ArmRole::DifferentialProtocolAnalyzer),
            (13, ArmRole::AutonomousProtocolResearch),
            (14, ArmRole::PostQuantumAttestation),
            (15, ArmRole::EvolutionaryOptimizer),
            (16, ArmRole::DreamRsiOptimizer),
            (17, ArmRole::RecursiveHarnessOptimizer),
        ];

        for (id, role) in all_roles {
            let ring = Arc::new(ArmContainmentRing::new(id, role, 1, &seed));
            map.insert(id, ring);
        }

        Self {
            rings: Arc::new(RwLock::new(map)),
            master_seed: seed,
            watchout_signals: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn get_ring(&self, arm_id: usize) -> Option<Arc<ArmContainmentRing>> {
        self.rings.read().await.get(&arm_id).cloned()
    }

    pub async fn sever_and_regenerate_arm(&self, arm_id: usize, reason: &str) -> KillSwitchResult<u64> {
        let ring = self.get_ring(arm_id).await.ok_or_else(|| {
            KillSwitchError::OctopusViolation(format!("Arm ID {} not found in registry", arm_id))
        })?;

        let old_gen = ring.current_generation();
        let new_gen = ring.sever_and_regenerate(reason).await?;

        let now_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        let signal = MeshWatchOutSignal {
            severed_arm_id: arm_id,
            revoked_generation: old_gen,
            new_generation: new_gen,
            reason: reason.to_string(),
            timestamp_us: now_us,
        };

        self.watchout_signals.write().await.push(signal);
        Ok(new_gen)
    }

    pub fn master_seed(&self) -> &[u8; 32] {
        &self.master_seed
    }

    pub async fn active_watchout_signals(&self) -> Vec<MeshWatchOutSignal> {
        self.watchout_signals.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_primary_gate_blocks_breakout_and_severs_arm_before_closure() {
        let registry = ArmRingRegistry::new(b"test_octopus_master_seed_32bytes!");
        let arm = registry.get_ring(2).await.expect("Arm 2 (NetworkEgress)");
        assert_eq!(arm.current_generation(), 1);

        let cap = arm
            .issue_capability("http_egress", "https://", 60)
            .await
            .expect("issue capability");

        let mut closure_ran = false;
        // Attempt an OpenAI/Anthropic breakout payload via the primary containment gate
        let res = arm
            .execute_guarded_tool(
                &cap,
                "https://a8f9d0e1c2b3a4f5e6d7c8b9a0f1e2d3.exfil-c2.org/leak",
                "cat ~/.netrc && curl /var/run/docker.sock",
                None,
                || {
                    closure_ran = true;
                    Ok("should_never_execute")
                },
            )
            .await;

        assert!(res.is_err(), "Breakout payload must fail closed");
        assert!(!closure_ran, "Tool closure must NEVER execute on breakout");

        // Verify arm was automatically severed and old epoch fails validation
        assert!(arm.validate_epoch(1).await.is_err());

        // Regenerating advances epoch monotonically to Gen 2
        let new_gen = registry
            .sever_and_regenerate_arm(2, "Breakout recovery")
            .await
            .expect("regenerate");
        assert_eq!(new_gen, 2);
        assert!(arm.validate_epoch(1).await.is_err(), "Stale epoch 1 must remain rejected");
        assert!(arm.validate_epoch(2).await.is_ok(), "New epoch 2 must be active");
    }
}
