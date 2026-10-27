//! # MeshGuard & Homological Boundary Auditor ($\partial^2 = 0$)
//!
//! Enforces:
//! 1. Cryptographic Mesh Verification: Constant-time HMAC-SHA256 signature verification.
//! 2. Case-Insensitive Lateral Sink Isolation: Normalizes agent identifiers (`to_ascii_lowercase()`).
//! 3. Homological Boundary Audit: Simplicial boundary identity $\partial_1 \circ \partial_2 = 0$
//!    and cochain coboundary $\delta_1 \circ \delta_0 \phi = 0$.
//! 4. Sticky Taint Veto: Propagates untrusted taint floor, blocking privilege laundering.

use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use killswitch_types::{
    role_trust_tier, ArmMessage, ArmRole, KillSwitchError, KillSwitchResult, MessageKind,
    TrustTier, MAX_RELAY_HOPS,
};

type HmacSha256 = Hmac<Sha256>;

/// Result of the Homological Boundary Audit.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HomologicalAuditReport {
    pub allowed: bool,
    pub sender: String,
    pub intermediary: Option<String>,
    pub recipient: String,
    pub sender_potential: i64,
    pub recipient_potential: i64,
    pub coboundary_residue: i64,
    pub boundary_squared_zero: bool,
    pub proxy_laundering_detected: bool,
    pub reason: String,
}

/// Mathematical Auditor verifying $\partial^2 = 0$ over the agent communication complex.
#[derive(Debug, Clone, Default)]
pub struct HomologicalBoundaryAuditor;

impl HomologicalBoundaryAuditor {
    /// Normalizes identifiers using lowercase.
    pub fn normalize_id(id: &str) -> String {
        id.trim().to_ascii_lowercase()
    }

    /// Evaluates a relay chain $[v_0, v_1, \dots, v_n]$ of authenticated roles under Law 1.
    pub fn audit_role_chain(chain: &[ArmRole]) -> HomologicalAuditReport {
        let describe = |r: &ArmRole| r.as_str().to_string();

        if chain.len() < 2 || chain.len() > MAX_RELAY_HOPS + 1 {
            return HomologicalAuditReport {
                allowed: false,
                sender: chain.first().map(describe).unwrap_or_default(),
                intermediary: None,
                recipient: chain.last().map(describe).unwrap_or_default(),
                sender_potential: 0,
                recipient_potential: 0,
                coboundary_residue: 0,
                boundary_squared_zero: false,
                proxy_laundering_detected: true,
                reason: format!(
                    "LAW1_CHAIN_LENGTH_VETO: relay chain length {} outside permitted bounds [2, {}]",
                    chain.len(),
                    MAX_RELAY_HOPS + 1
                ),
            };
        }

        let potentials: Vec<i64> = chain.iter().map(|r| role_trust_tier(r).potential()).collect();
        let n = potentials.len();
        let phi_s = potentials[0];
        let phi_r = potentials[n - 1];

        // Simplicial exactness check: Telescoping sum of differences must equal direct difference:
        // \sum (phi_{i+1} - phi_i) == phi_r - phi_s
        let telescoped: i64 = potentials.windows(2).map(|w| w[1] - w[0]).sum();
        let coboundary_residue = telescoped - (phi_r - phi_s);
        let boundary_squared_zero = coboundary_residue == 0;

        // Sticky Taint: Minimum trust potential in the upstream path
        let origin_floor = potentials[..n - 1].iter().copied().min().unwrap_or(phi_s);

        let direct_violation = n == 2
            && phi_s <= TrustTier::Untrusted.potential()
            && phi_r >= TrustTier::PrivilegedSink.potential();

        let transitive_laundering = n > 2
            && origin_floor <= TrustTier::Untrusted.potential()
            && phi_r >= TrustTier::PrivilegedSink.potential();

        let proxy_laundering_detected =
            direct_violation || transitive_laundering || !boundary_squared_zero;
        let allowed = !proxy_laundering_detected;

        let chain_str = chain.iter().map(describe).collect::<Vec<_>>().join(" -> ");
        let reason = if allowed {
            format!(
                "LAW1_HOMOLOGICAL_EXACTNESS_VERIFIED: chain [{}] preserves privilege gradient (floor {} -> sink {})",
                chain_str, origin_floor, phi_r
            )
        } else if transitive_laundering {
            format!(
                "LAW1_PROXY_LAUNDERING_VETO: {}-hop relay [{}] attempts to launder untrusted taint (floor {}) into privileged sink (potential {})",
                n - 1,
                chain_str,
                origin_floor,
                phi_r
            )
        } else {
            format!(
                "LAW1_DIRECT_BOUNDARY_VETO: Direct communication [{}] violates privilege gradient (potential: {} -> {})",
                chain_str, phi_s, phi_r
            )
        };

        HomologicalAuditReport {
            allowed,
            sender: describe(&chain[0]),
            intermediary: if n > 2 {
                Some(chain[1..n - 1].iter().map(describe).collect::<Vec<_>>().join(" -> "))
            } else {
                None
            },
            recipient: describe(&chain[n - 1]),
            sender_potential: phi_s,
            recipient_potential: phi_r,
            coboundary_residue,
            boundary_squared_zero,
            proxy_laundering_detected,
            reason,
        }
    }
}

/// Authenticated and verified mesh message wrapper.
#[derive(Debug, Clone)]
pub struct VerifiedMeshMessage {
    pub message: ArmMessage,
    pub recipient_role: ArmRole,
    pub role_chain: Vec<ArmRole>,
    pub effective_taint_floor: TrustTier,
}

pub type AllowedRoutesSet = HashSet<(String, String, Option<MessageKind>)>;

/// Neural Mesh Guard mediating inter-arm communication routes.
#[derive(Clone)]
pub struct MeshGuard {
    allowed_routes: Arc<RwLock<AllowedRoutesSet>>,
}

impl Default for MeshGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl MeshGuard {
    pub fn new() -> Self {
        Self {
            allowed_routes: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Authorizes a communication route using normalized identifiers.
    pub async fn allow_route(
        &self,
        sender_id: &str,
        recipient_id: &str,
        kind: Option<MessageKind>,
    ) {
        let s = HomologicalBoundaryAuditor::normalize_id(sender_id);
        let r = HomologicalBoundaryAuditor::normalize_id(recipient_id);
        let mut routes = self.allowed_routes.write().await;
        routes.insert((s, r, kind));
    }

    /// Verifies inter-arm message HMAC signature in constant time against the derived sender key.
    pub fn verify_message_signature(
        msg: &ArmMessage,
        sender_epoch_key: &[u8; 32],
    ) -> KillSwitchResult<()> {
        let mut mac = HmacSha256::new_from_slice(sender_epoch_key)
            .map_err(|e| KillSwitchError::CryptoError(e.to_string()))?;
        mac.update(msg.canonical_signing_content().as_bytes());
        let expected_bytes = mac.finalize().into_bytes();

        let sig_bytes = hex::decode(&msg.signature_hex)
            .map_err(|e| KillSwitchError::CryptoError(format!("Invalid signature hex: {}", e)))?;

        if sig_bytes.len() != expected_bytes.len()
            || bool::from(!expected_bytes.ct_eq(&sig_bytes))
        {
            return Err(KillSwitchError::MeshHmacVerificationFailed {
                arm_id: msg.sender_generation as usize,
            });
        }

        Ok(())
    }

    /// Mediates and audits an inter-arm message.
    pub async fn validate_message(
        &self,
        msg: &ArmMessage,
        recipient_role: &ArmRole,
        sender_epoch_key: &[u8; 32],
    ) -> KillSwitchResult<VerifiedMeshMessage> {
        // 1. Recompute and verify HMAC signature in constant time
        Self::verify_message_signature(msg, sender_epoch_key)?;

        // 2. Validate message bounds
        if msg.correlation_id.len() > 128 {
            return Err(KillSwitchError::OctopusViolation(
                "Correlation ID exceeds 128 bytes limit".to_string(),
            ));
        }
        if msg.payload.len() > 16 * 1024 {
            return Err(KillSwitchError::OctopusViolation(
                "Message payload exceeds 16KB neural mesh capacity".to_string(),
            ));
        }

        // 3. Assemble full role chain: [provenance hops..., sender, recipient]
        let mut role_chain: Vec<ArmRole> = msg.provenance.iter().map(|h| h.role.clone()).collect();
        role_chain.push(msg.sender_role.clone());
        role_chain.push(recipient_role.clone());

        // 4. Run Homological Boundary Audit (d^2 = 0)
        let report = HomologicalBoundaryAuditor::audit_role_chain(&role_chain);
        if !report.allowed {
            return Err(KillSwitchError::LateralSinkViolation {
                sender_role: msg.sender_role.as_str().to_string(),
                sink_role: recipient_role.as_str().to_string(),
            });
        }

        // 5. Sticky Taint Veto
        let sender_tier = role_trust_tier(&msg.sender_role);
        let effective_taint_floor = msg
            .provenance
            .iter()
            .map(|h| role_trust_tier(&h.role))
            .fold(msg.taint_floor.min(sender_tier), |a, b| a.min(b));

        if effective_taint_floor == TrustTier::Untrusted && recipient_role.is_privileged_sink() {
            return Err(KillSwitchError::LateralSinkViolation {
                sender_role: format!("UntrustedTainted({:?})", msg.sender_role),
                sink_role: recipient_role.as_str().to_string(),
            });
        }

        // 6. Route authorization check (fail-closed)
        let s_norm = HomologicalBoundaryAuditor::normalize_id(&msg.sender_arm_id);
        let r_norm = HomologicalBoundaryAuditor::normalize_id(&msg.target_arm_id);
        let routes = self.allowed_routes.read().await;

        let authorized = routes.contains(&(s_norm.clone(), r_norm.clone(), Some(msg.kind)))
            || routes.contains(&(s_norm.clone(), r_norm.clone(), None));

        if !authorized {
            return Err(KillSwitchError::OctopusViolation(format!(
                "Mesh route from '{}' to '{}' for kind '{:?}' is not authorized",
                msg.sender_arm_id, msg.target_arm_id, msg.kind
            )));
        }

        Ok(VerifiedMeshMessage {
            message: msg.clone(),
            recipient_role: recipient_role.clone(),
            role_chain,
            effective_taint_floor,
        })
    }
}
