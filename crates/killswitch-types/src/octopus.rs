use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub const MAX_RELAY_HOPS: usize = 16;

/// Mathematical Trust Tier defining discrete privilege potentials ($\phi \in \mathbb{Z}$).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TrustTier {
    /// Arms that ingest attacker-controlled input (documents, fuzz corpora, raw wire traffic, decoys).
    Untrusted = 10,
    /// Standard worker / analysis arms.
    Worker = 50,
    /// High-privilege sinks (ledger writes, kernel sentinel, policy authority, signing keys).
    PrivilegedSink = 100,
}

impl TrustTier {
    pub fn potential(self) -> i64 {
        self as i64
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Untrusted => "Untrusted",
            Self::Worker => "Worker",
            Self::PrivilegedSink => "PrivilegedSink",
        }
    }
}

impl fmt::Display for TrustTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Exhaustive catalog of all 18 agent arm roles in the hybrid containment architecture.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArmRole {
    UntrustedDocIngest,
    AccountingLedgerWrite,
    OutboundNotification,
    NetworkEgress,
    TarpitDecoyDefense,
    KernelLevelSentinel,
    CedarPolicyEvaluation,
    AtlasThreatIntelligence,
    AnomalyDetection,
    VulnerabilityResearch,
    ContinuousOssFuzz,
    ContinuousOsvScanner,
    DifferentialProtocolAnalyzer,
    AutonomousProtocolResearch,
    PostQuantumAttestation,
    EvolutionaryOptimizer,
    DreamRsiOptimizer,
    RecursiveHarnessOptimizer,
}

impl ArmRole {
    /// Maps this role to its compile-time immutable trust tier.
    pub fn trust_tier(&self) -> TrustTier {
        role_trust_tier(self)
    }

    pub fn is_privileged_sink(&self) -> bool {
        self.trust_tier() == TrustTier::PrivilegedSink
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UntrustedDocIngest => "UntrustedDocIngest",
            Self::AccountingLedgerWrite => "AccountingLedgerWrite",
            Self::OutboundNotification => "OutboundNotification",
            Self::NetworkEgress => "NetworkEgress",
            Self::TarpitDecoyDefense => "TarpitDecoyDefense",
            Self::KernelLevelSentinel => "KernelLevelSentinel",
            Self::CedarPolicyEvaluation => "CedarPolicyEvaluation",
            Self::AtlasThreatIntelligence => "AtlasThreatIntelligence",
            Self::AnomalyDetection => "AnomalyDetection",
            Self::VulnerabilityResearch => "VulnerabilityResearch",
            Self::ContinuousOssFuzz => "ContinuousOssFuzz",
            Self::ContinuousOsvScanner => "ContinuousOsvScanner",
            Self::DifferentialProtocolAnalyzer => "DifferentialProtocolAnalyzer",
            Self::AutonomousProtocolResearch => "AutonomousProtocolResearch",
            Self::PostQuantumAttestation => "PostQuantumAttestation",
            Self::EvolutionaryOptimizer => "EvolutionaryOptimizer",
            Self::DreamRsiOptimizer => "DreamRsiOptimizer",
            Self::RecursiveHarnessOptimizer => "RecursiveHarnessOptimizer",
        }
    }
}

impl fmt::Display for ArmRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for ArmRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "UntrustedDocIngest" => Ok(Self::UntrustedDocIngest),
            "AccountingLedgerWrite" => Ok(Self::AccountingLedgerWrite),
            "OutboundNotification" => Ok(Self::OutboundNotification),
            "NetworkEgress" => Ok(Self::NetworkEgress),
            "TarpitDecoyDefense" => Ok(Self::TarpitDecoyDefense),
            "KernelLevelSentinel" => Ok(Self::KernelLevelSentinel),
            "CedarPolicyEvaluation" => Ok(Self::CedarPolicyEvaluation),
            "AtlasThreatIntelligence" => Ok(Self::AtlasThreatIntelligence),
            "AnomalyDetection" => Ok(Self::AnomalyDetection),
            "VulnerabilityResearch" => Ok(Self::VulnerabilityResearch),
            "ContinuousOssFuzz" => Ok(Self::ContinuousOssFuzz),
            "ContinuousOsvScanner" => Ok(Self::ContinuousOsvScanner),
            "DifferentialProtocolAnalyzer" => Ok(Self::DifferentialProtocolAnalyzer),
            "AutonomousProtocolResearch" => Ok(Self::AutonomousProtocolResearch),
            "PostQuantumAttestation" => Ok(Self::PostQuantumAttestation),
            "EvolutionaryOptimizer" => Ok(Self::EvolutionaryOptimizer),
            "DreamRsiOptimizer" => Ok(Self::DreamRsiOptimizer),
            "RecursiveHarnessOptimizer" => Ok(Self::RecursiveHarnessOptimizer),
            other => Err(format!("Unknown ArmRole: '{}'", other)),
        }
    }
}

/// Exhaustive role -> trust tier mapping.
///
/// INVARIANT: There is deliberately NO wildcard arm match (`_ => ...`).
/// Adding a new variant is an intentional compile error until it is explicitly classified (fail-closed).
pub fn role_trust_tier(role: &ArmRole) -> TrustTier {
    match role {
        ArmRole::UntrustedDocIngest
        | ArmRole::DifferentialProtocolAnalyzer
        | ArmRole::AutonomousProtocolResearch
        | ArmRole::ContinuousOssFuzz
        | ArmRole::TarpitDecoyDefense => TrustTier::Untrusted,

        ArmRole::AccountingLedgerWrite
        | ArmRole::KernelLevelSentinel
        | ArmRole::CedarPolicyEvaluation
        | ArmRole::PostQuantumAttestation => TrustTier::PrivilegedSink,

        ArmRole::OutboundNotification
        | ArmRole::NetworkEgress
        | ArmRole::AtlasThreatIntelligence
        | ArmRole::AnomalyDetection
        | ArmRole::VulnerabilityResearch
        | ArmRole::ContinuousOsvScanner
        | ArmRole::EvolutionaryOptimizer
        | ArmRole::DreamRsiOptimizer
        | ArmRole::RecursiveHarnessOptimizer => TrustTier::Worker,
    }
}

/// State controller for an arm's monotonic generation epoch and cryptographic keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmEpoch {
    pub arm_id: String,
    pub role: ArmRole,
    pub generation: u64,
    pub master_seed: [u8; 32],
    pub revoked_epochs: HashSet<u64>,
    pub is_severed: bool,
}

impl ArmEpoch {
    pub fn new(arm_id: impl Into<String>, role: ArmRole, master_seed: [u8; 32]) -> Self {
        Self {
            arm_id: arm_id.into(),
            role,
            generation: 1, // Generations begin at 1
            master_seed,
            revoked_epochs: HashSet::new(),
            is_severed: false,
        }
    }

    /// Derives the cryptographic HMAC key for a specific generation epoch:
    /// EpochKey = SHA256(MasterSeed || ArmID.to_ascii_lowercase() || Epoch || Role)
    pub fn derive_epoch_key(&self, epoch: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.master_seed);
        hasher.update(self.arm_id.to_ascii_lowercase().as_bytes());
        hasher.update(epoch.to_le_bytes());
        hasher.update(self.role.as_str().as_bytes());
        let output = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&output);
        key
    }

    /// Current epoch signing key.
    pub fn current_key(&self) -> [u8; 32] {
        self.derive_epoch_key(self.generation)
    }

    /// Surgically severs the arm: marks severed, revokes current epoch.
    pub fn sever(&mut self) {
        self.is_severed = true;
        self.revoked_epochs.insert(self.generation);
    }

    /// Regenerates a severed arm by monotonically advancing epoch (Gen N -> Gen N+1).
    pub fn sever_and_regenerate(&mut self) -> u64 {
        self.sever();
        self.generation += 1;
        self.is_severed = false;
        self.generation
    }

    /// Checks if a message bearing generation `msg_epoch` is currently valid.
    pub fn is_epoch_valid(&self, msg_epoch: u64) -> bool {
        !self.is_severed && msg_epoch == self.generation && !self.revoked_epochs.contains(&msg_epoch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageKind {
    Finding,
    ThreatMapping,
    ChainCandidate,
    Alert,
    Command,
    Heartbeat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceHop {
    pub arm_id: String,
    pub role: ArmRole,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArmMessage {
    pub sender_arm_id: String,
    pub sender_role: ArmRole,
    pub sender_generation: u64,
    pub target_arm_id: String,
    pub target_generation: u64,
    pub kind: MessageKind,
    pub correlation_id: String,
    pub payload: String,
    pub provenance: Vec<ProvenanceHop>,
    pub taint_floor: TrustTier,
    pub signature_hex: String,
}

impl ArmMessage {
    /// Canonicalizes the payload string for HMAC-SHA256 signing and verification.
    pub fn canonical_signing_content(&self) -> String {
        let prov = self
            .provenance
            .iter()
            .map(|h| format!("{}/{:?}/{}", h.arm_id.to_ascii_lowercase(), h.role, h.generation))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{}:{}:{}:{}:{}:{:?}:{}:{}|prov=[{}]|floor={:?}",
            self.sender_arm_id.to_ascii_lowercase(),
            self.sender_role,
            self.sender_generation,
            self.target_arm_id.to_ascii_lowercase(),
            self.target_generation,
            self.kind,
            self.correlation_id,
            self.payload,
            prov,
            self.taint_floor
        )
    }

    /// Computes and applies the HMAC-SHA256 signature using the sender's epoch key.
    pub fn sign(&mut self, epoch_key: &[u8; 32]) -> Result<(), String> {
        let mut mac = HmacSha256::new_from_slice(epoch_key)
            .map_err(|e| format!("HMAC key initialization failed: {}", e))?;
        mac.update(self.canonical_signing_content().as_bytes());
        self.signature_hex = hex::encode(mac.finalize().into_bytes());
        Ok(())
    }

    /// Verifies the HMAC-SHA256 signature in constant time using `subtle::ConstantTimeEq`.
    ///
    /// INVARIANT: Never check `!signature.is_empty()`. Always recompute and compare constant-time.
    pub fn verify_signature(&self, epoch_key: &[u8; 32]) -> bool {
        let expected_bytes = match HmacSha256::new_from_slice(epoch_key) {
            Ok(mut mac) => {
                mac.update(self.canonical_signing_content().as_bytes());
                mac.finalize().into_bytes()
            }
            Err(_) => return false,
        };

        let signature_bytes = match hex::decode(&self.signature_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        if expected_bytes.len() != signature_bytes.len() {
            return false;
        }

        expected_bytes.ct_eq(&signature_bytes).into()
    }

    /// Validates lateral movement isolation (LAW1_STICKY_TAINT_VETO).
    /// Prevents Untrusted tainted messages from reaching PrivilegedSink roles.
    pub fn validate_lateral_movement(&self, recipient_role: &ArmRole) -> Result<(), String> {
        if self.taint_floor <= TrustTier::Untrusted && recipient_role.is_privileged_sink() {
            return Err(format!(
                "LAW1_STICKY_TAINT_VETO: Tainted message (tier {:?}) blocked from high-privilege sink '{}'",
                self.taint_floor, recipient_role
            ));
        }
        if self.provenance.len() >= MAX_RELAY_HOPS {
            return Err(format!(
                "Relay hop ceiling exceeded: {} >= {}",
                self.provenance.len(),
                MAX_RELAY_HOPS
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arm_message_hmac_sign_and_verify() {
        let master_seed = [42u8; 32];
        let epoch_mgr = ArmEpoch::new("arm-worker-1", ArmRole::AnomalyDetection, master_seed);
        let key = epoch_mgr.current_key();

        let mut msg = ArmMessage {
            sender_arm_id: "arm-worker-1".to_string(),
            sender_role: ArmRole::AnomalyDetection,
            sender_generation: 1,
            target_arm_id: "arm-egress-1".to_string(),
            target_generation: 1,
            kind: MessageKind::Finding,
            correlation_id: "corr-101".to_string(),
            payload: "High entropy process discovered".to_string(),
            provenance: Vec::new(),
            taint_floor: TrustTier::Worker,
            signature_hex: String::new(),
        };

        // Sign message
        assert!(msg.sign(&key).is_ok());
        assert!(!msg.signature_hex.is_empty());

        // Verify valid signature
        assert!(msg.verify_signature(&key));

        // Tamper with payload -> verification must fail
        msg.payload = "Modified payload".to_string();
        assert!(!msg.verify_signature(&key));
    }

    #[test]
    fn test_arm_epoch_monotonic_advancement() {
        let master_seed = [99u8; 32];
        let mut epoch_mgr = ArmEpoch::new("fuzz-arm", ArmRole::ContinuousOssFuzz, master_seed);
        assert_eq!(epoch_mgr.generation, 1);
        assert!(epoch_mgr.is_epoch_valid(1));

        // Advance epoch (Gen 1 -> Gen 2)
        let new_gen = epoch_mgr.sever_and_regenerate();
        assert_eq!(new_gen, 2);
        assert_eq!(epoch_mgr.generation, 2);

        // Gen 1 must now be invalid
        assert!(!epoch_mgr.is_epoch_valid(1));
        assert!(epoch_mgr.is_epoch_valid(2));
    }

    #[test]
    fn test_sticky_taint_veto() {
        let msg = ArmMessage {
            sender_arm_id: "untrusted-ingest".to_string(),
            sender_role: ArmRole::UntrustedDocIngest,
            sender_generation: 1,
            target_arm_id: "ledger-sink".to_string(),
            target_generation: 1,
            kind: MessageKind::Finding,
            correlation_id: "corr-500".to_string(),
            payload: "parsed PDF content".to_string(),
            provenance: Vec::new(),
            taint_floor: TrustTier::Untrusted,
            signature_hex: String::new(),
        };

        // Untrusted message cannot reach PrivilegedSink (AccountingLedgerWrite)
        let res = msg.validate_lateral_movement(&ArmRole::AccountingLedgerWrite);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("LAW1_STICKY_TAINT_VETO"));

        // Untrusted message can reach Worker (AnomalyDetection)
        assert!(msg.validate_lateral_movement(&ArmRole::AnomalyDetection).is_ok());
    }

    #[test]
    fn test_all_18_arm_roles_classified() {
        let roles = vec![
            ArmRole::UntrustedDocIngest,
            ArmRole::AccountingLedgerWrite,
            ArmRole::OutboundNotification,
            ArmRole::NetworkEgress,
            ArmRole::TarpitDecoyDefense,
            ArmRole::KernelLevelSentinel,
            ArmRole::CedarPolicyEvaluation,
            ArmRole::AtlasThreatIntelligence,
            ArmRole::AnomalyDetection,
            ArmRole::VulnerabilityResearch,
            ArmRole::ContinuousOssFuzz,
            ArmRole::ContinuousOsvScanner,
            ArmRole::DifferentialProtocolAnalyzer,
            ArmRole::AutonomousProtocolResearch,
            ArmRole::PostQuantumAttestation,
            ArmRole::EvolutionaryOptimizer,
            ArmRole::DreamRsiOptimizer,
            ArmRole::RecursiveHarnessOptimizer,
        ];

        assert_eq!(roles.len(), 18);
        for role in roles {
            let tier = role.trust_tier();
            assert!(tier.potential() > 0);
        }
    }

    #[test]
    fn test_arm_message_sender_role_tamper_fails() {
        let master_seed = [77u8; 32];
        let epoch_mgr = ArmEpoch::new("arm-worker-1", ArmRole::AnomalyDetection, master_seed);
        let key = epoch_mgr.current_key();

        let mut msg = ArmMessage {
            sender_arm_id: "arm-worker-1".to_string(),
            sender_role: ArmRole::AnomalyDetection,
            sender_generation: 1,
            target_arm_id: "arm-egress-1".to_string(),
            target_generation: 1,
            kind: MessageKind::Finding,
            correlation_id: "corr-102".to_string(),
            payload: "Entropy report".to_string(),
            provenance: Vec::new(),
            taint_floor: TrustTier::Worker,
            signature_hex: String::new(),
        };

        assert!(msg.sign(&key).is_ok());
        assert!(msg.verify_signature(&key));

        // Tamper with sender_role -> verification MUST fail under original key
        msg.sender_role = ArmRole::KernelLevelSentinel;
        assert!(
            !msg.verify_signature(&key),
            "Tampered sender_role MUST fail HMAC verification because it is bound into canonical_signing_content"
        );
    }
}
