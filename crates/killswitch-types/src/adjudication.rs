use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// Domain separation context for fraud proof BLAKE3 seals.
pub const FRAUD_PROOF_SEAL_CONTEXT: &[u8] = b"KILL_SWITCH_FRAUD_PROOF_V2|";

/// Domain separation context for REA seals.
pub const REA_SEAL_CONTEXT: &[u8] = b"REA_ADJUDICATION_SEAL_V2|";

/// Non-repudiable Cryptographic Fraud Proof holding a Byzantine peer accountable
/// for attempting to weaponize the kill-switch against protected OS/developer binaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByzantineKillSwitchFraudProof {
    /// Unique identifier or reporting peer ID for this fraud proof.
    pub peer_id: String,
    /// Peer ID of the rogue/accused node that broadcast the malicious candidate.
    pub accused_peer_id: String,
    /// BLAKE3 hex hash of the protected local binary that was illicitly targeted.
    pub target_binary_hash: String,
    /// Process name that was targeted (e.g. "svchost.exe", "cargo.exe", "explorer.exe").
    pub proc_name: String,
    /// Formal reason why containment was vetoed and classified as fraudulent.
    pub fraud_reason: String,
    /// Cryptographic BLAKE3 seal proving integrity and non-repudiation of the proof.
    pub proof_seal: String,
    /// UTC timestamp formatted as RFC 3339 when the fraud proof was synthesized.
    pub timestamp: String,
}

impl ByzantineKillSwitchFraudProof {
    /// Computes the canonical BLAKE3 cryptographic seal over proof fields.
    pub fn compute_seal(
        peer_id: &str,
        accused_peer_id: &str,
        target_binary_hash: &str,
        proc_name: &str,
        fraud_reason: &str,
        timestamp: &str,
    ) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(FRAUD_PROOF_SEAL_CONTEXT);
        hasher.update(peer_id.as_bytes());
        hasher.update(b"|");
        hasher.update(accused_peer_id.as_bytes());
        hasher.update(b"|");
        hasher.update(target_binary_hash.as_bytes());
        hasher.update(b"|");
        hasher.update(proc_name.as_bytes());
        hasher.update(b"|");
        hasher.update(fraud_reason.as_bytes());
        hasher.update(b"|");
        hasher.update(timestamp.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Computes a keyed HMAC-BLAKE3 seal using a node's local secret key.
    pub fn compute_keyed_seal(
        key: &[u8; 32],
        peer_id: &str,
        accused_peer_id: &str,
        target_binary_hash: &str,
        proc_name: &str,
        fraud_reason: &str,
        timestamp: &str,
    ) -> String {
        let mut hasher = blake3::Hasher::new_keyed(key);
        hasher.update(FRAUD_PROOF_SEAL_CONTEXT);
        hasher.update(peer_id.as_bytes());
        hasher.update(b"|");
        hasher.update(accused_peer_id.as_bytes());
        hasher.update(b"|");
        hasher.update(target_binary_hash.as_bytes());
        hasher.update(b"|");
        hasher.update(proc_name.as_bytes());
        hasher.update(b"|");
        hasher.update(fraud_reason.as_bytes());
        hasher.update(b"|");
        hasher.update(timestamp.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Constructs a new `ByzantineKillSwitchFraudProof`, immediately computing its seal.
    pub fn new(
        peer_id: impl Into<String>,
        accused_peer_id: impl Into<String>,
        target_binary_hash: impl Into<String>,
        proc_name: impl Into<String>,
        fraud_reason: impl Into<String>,
    ) -> Self {
        let peer_id = peer_id.into();
        let accused_peer_id = accused_peer_id.into();
        let target_binary_hash = target_binary_hash.into();
        let proc_name = proc_name.into();
        let fraud_reason = fraud_reason.into();
        let timestamp = chrono::Utc::now().to_rfc3339();

        let proof_seal = Self::compute_seal(
            &peer_id,
            &accused_peer_id,
            &target_binary_hash,
            &proc_name,
            &fraud_reason,
            &timestamp,
        );

        Self {
            peer_id,
            accused_peer_id,
            target_binary_hash,
            proc_name,
            fraud_reason,
            proof_seal,
            timestamp,
        }
    }

    /// Verifies the cryptographic BLAKE3 seal using constant-time comparison.
    /// Returns `true` only if the seal matches the canonical fields.
    pub fn verify_seal(&self) -> bool {
        if self.proof_seal.is_empty() {
            return false;
        }

        let expected_seal = Self::compute_seal(
            &self.peer_id,
            &self.accused_peer_id,
            &self.target_binary_hash,
            &self.proc_name,
            &self.fraud_reason,
            &self.timestamp,
        );

        let actual_bytes = self.proof_seal.as_bytes();
        let expected_bytes = expected_seal.as_bytes();

        if actual_bytes.len() != expected_bytes.len() {
            return false;
        }

        actual_bytes.ct_eq(expected_bytes).into()
    }

    /// Verifies a keyed HMAC-BLAKE3 seal using constant-time comparison.
    pub fn verify_keyed_seal(&self, key: &[u8; 32]) -> bool {
        if self.proof_seal.is_empty() {
            return false;
        }

        let expected_seal = Self::compute_keyed_seal(
            key,
            &self.peer_id,
            &self.accused_peer_id,
            &self.target_binary_hash,
            &self.proc_name,
            &self.fraud_reason,
            &self.timestamp,
        );

        let actual_bytes = self.proof_seal.as_bytes();
        let expected_bytes = expected_seal.as_bytes();

        if actual_bytes.len() != expected_bytes.len() {
            return false;
        }

        actual_bytes.ct_eq(expected_bytes).into()
    }
}

/// Detailed status of an Authenticode certificate chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthenticodeChainStatus {
    /// 0 / ERROR_SUCCESS: Cryptographically valid and trusted by OS root store.
    ValidTrusted,
    /// 0x800B0109 / CERT_E_UNTRUSTEDROOT: Valid signature, untrusted root CA.
    UntrustedRoot,
    /// 0x80096010 / TRUST_E_BAD_DIGEST: Hash mismatch, file has been tampered with.
    TamperedBadDigest,
    /// 0x800B0100 / TRUST_E_NOSIGNATURE: No signature present.
    NotSigned,
    /// 0x800B0111 / TRUST_E_EXPLICIT_DISTRUST: Explicitly disallowed by administrative policy.
    ExplicitDistrust,
    /// 0x800B010C / CERT_E_REVOKED or 0x80092013 / CRYPT_E_REVOKED: Certificate revoked.
    Revoked,
    /// Other WinVerifyTrust error code.
    OtherError(i32),
}

impl AuthenticodeChainStatus {
    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::ValidTrusted)
    }

    pub fn code(&self) -> i32 {
        match self {
            Self::ValidTrusted => 0,
            Self::UntrustedRoot => -2146762487, // 0x800B0109
            Self::TamperedBadDigest => -2146869232, // 0x80096010
            Self::NotSigned => -2146762496, // 0x800B0100
            Self::ExplicitDistrust => -2146762479, // 0x800B0111
            Self::Revoked => -2146762484, // 0x800B010C
            Self::OtherError(code) => *code,
        }
    }
}

/// Detailed digital signature inspection metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticodeStatus {
    /// Subject CN (e.g. "Microsoft Corporation", "Rust Project").
    pub subject: Option<String>,
    /// Issuing Certificate Authority (e.g. "Microsoft Root Certificate Authority 2010").
    pub issuer: Option<String>,
    /// Certificate serial number hex string.
    pub serial: Option<String>,
    /// SHA-256 certificate thumbprint (lowercase hex).
    pub thumbprint: Option<String>,
    /// Cryptographic chain status.
    pub chain_status: AuthenticodeChainStatus,
}

impl AuthenticodeStatus {
    pub fn new_valid(
        subject: impl Into<String>,
        issuer: impl Into<String>,
        serial: impl Into<String>,
        thumbprint: impl Into<String>,
    ) -> Self {
        Self {
            subject: Some(subject.into()),
            issuer: Some(issuer.into()),
            serial: Some(serial.into()),
            thumbprint: Some(thumbprint.into()),
            chain_status: AuthenticodeChainStatus::ValidTrusted,
        }
    }

    pub fn not_signed() -> Self {
        Self {
            subject: None,
            issuer: None,
            serial: None,
            thumbprint: None,
            chain_status: AuthenticodeChainStatus::NotSigned,
        }
    }

    pub fn is_trusted(&self) -> bool {
        self.chain_status.is_trusted()
    }
}

/// Cryptographic trust verdict for an executable binary or shared library.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryTrustVerdict {
    /// Cryptographically verified via embedded Authenticode signature (trusted root).
    TrustedAuthenticode {
        signer_subject: Option<String>,
        thumbprint: Option<String>,
    },
    /// Cryptographically verified via Windows Security Catalog (CatRoot hash lookup).
    TrustedCatalog {
        catalog_name: Option<String>,
    },
    /// Cryptographically verified via matching a known BLAKE3 digest in the protected local inventory.
    TrustedProtectedHash {
        blake3_hash: String,
    },
    /// Cryptographically verified via Linux/Unix package manager or system integrity manifest.
    TrustedSystemPackage {
        package_name: Option<String>,
        digest: Option<String>,
    },
    /// Untrusted: signature or catalog check explicitly failed, was revoked, untrusted root, or tampered.
    UntrustedSignature {
        status: AuthenticodeStatus,
        reason: String,
    },
    /// Untrusted: binary in user-writable/temp directory without valid signature or inventory match.
    UntrustedWritableLocation {
        path: String,
        reason: String,
    },
    /// Untrusted: binary has no digital signature, catalog registration, or inventory digest.
    UntrustedUnsigned {
        blake3_hash: String,
    },
    /// Untrusted: binary path does not exist, cannot be read, or is not a regular file.
    UntrustedIoError {
        error: String,
    },
}

impl BinaryTrustVerdict {
    /// Returns `true` if the verdict represents cryptographic trust.
    pub fn is_trusted(&self) -> bool {
        matches!(
            self,
            Self::TrustedAuthenticode { .. }
                | Self::TrustedCatalog { .. }
                | Self::TrustedProtectedHash { .. }
                | Self::TrustedSystemPackage { .. }
        )
    }

    /// Returns `true` if the verdict represents an untrusted or suspicious binary.
    pub fn is_untrusted(&self) -> bool {
        !self.is_trusted()
    }

    /// Short human-readable category string for logging, telemetry, and audit records.
    pub fn category(&self) -> &'static str {
        match self {
            Self::TrustedAuthenticode { .. } => "trusted_authenticode",
            Self::TrustedCatalog { .. } => "trusted_catalog",
            Self::TrustedProtectedHash { .. } => "trusted_protected_hash",
            Self::TrustedSystemPackage { .. } => "trusted_system_package",
            Self::UntrustedSignature { .. } => "untrusted_signature",
            Self::UntrustedWritableLocation { .. } => "untrusted_writable_location",
            Self::UntrustedUnsigned { .. } => "untrusted_unsigned",
            Self::UntrustedIoError { .. } => "untrusted_io_error",
        }
    }
}

/// Orthogonal categories of security telemetry evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceClass {
    /// Active network socket connection, packet trace, or DNS lookup.
    LiveNetwork,
    /// Process execution sequence, command-line arguments, parentage, or file modification.
    Behavior,
    /// Code injection, memory scanning, heap/stack inspection, or thread hijacking.
    Memory,
    /// Static PE/ELF properties, entropy, imports, sections, or compiled YARA rules.
    StaticArtifact,
    /// External Threat Intelligence, IoC feed match, or CVE/KEV correlation.
    ThreatIntel,
    /// Historical host reputation, binary popularity, or developer identity.
    Reputation,
}

impl EvidenceClass {
    /// Returns a string identifier for this evidence class.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LiveNetwork => "LiveNetwork",
            Self::Behavior => "Behavior",
            Self::Memory => "Memory",
            Self::StaticArtifact => "StaticArtifact",
            Self::ThreatIntel => "ThreatIntel",
            Self::Reputation => "Reputation",
        }
    }

    /// Base reliability weight (0.0 .. 1.0) assigned during multi-voter corroboration.
    pub fn default_reliability(&self) -> f32 {
        match self {
            Self::LiveNetwork => 0.95,
            Self::Behavior => 0.90,
            Self::Memory => 0.92,
            Self::StaticArtifact => 0.85,
            Self::ThreatIntel => 0.70,
            Self::Reputation => 0.65,
        }
    }

    /// Returns `true` if this class represents active runtime execution telemetry.
    pub fn is_runtime(&self) -> bool {
        matches!(self, Self::LiveNetwork | Self::Behavior | Self::Memory)
    }

    /// List of all evidence classes.
    pub fn all() -> &'static [EvidenceClass] {
        &[
            Self::LiveNetwork,
            Self::Behavior,
            Self::Memory,
            Self::StaticArtifact,
            Self::ThreatIntel,
            Self::Reputation,
        ]
    }
}

/// Action proposed by an individual security voter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum VoteAction {
    /// Recommend host isolation or hard process containment.
    Isolate,
    /// Recommend raising an alert or operator notification without containment.
    #[default]
    Alert,
    /// Recommend continuing to passively monitor and track telemetry.
    Monitor,
}

impl VoteAction {
    pub fn is_isolate(&self) -> bool {
        matches!(self, Self::Isolate)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Isolate => "Isolate",
            Self::Alert => "Alert",
            Self::Monitor => "Monitor",
        }
    }
}

/// Structured vote emitted by a detector or heuristic voter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoteResult {
    /// PID of candidate process under inspection, if applicable.
    pub candidate_pid: Option<u32>,
    /// Proposed response action (`Isolate`, `Alert`, `Monitor`).
    pub action: VoteAction,
    /// Confidence score strictly clamped to `[0.0, 1.0]`.
    pub confidence: f32,
    /// Evidence class classifying this voter's telemetry domain.
    pub evidence_class: EvidenceClass,
    /// Human-readable explanation and forensic context.
    pub explanation: String,
    /// Name of the voter casting this result (e.g. "ReaVoter", "YaraXVoter").
    pub voter_name: String,
    /// Voting weight in consensus calculation (negative value signifies veto).
    pub weight: f32,
    /// UTC timestamp of vote generation.
    pub timestamp: String,
}

impl VoteResult {
    /// Constructs a validated `VoteResult`, clamping confidence to `0.0..=1.0`.
    pub fn new(
        candidate_pid: Option<u32>,
        action: VoteAction,
        confidence: f32,
        evidence_class: EvidenceClass,
        explanation: impl Into<String>,
        voter_name: impl Into<String>,
    ) -> Self {
        Self {
            candidate_pid,
            action,
            confidence: confidence.clamp(0.0, 1.0),
            evidence_class,
            explanation: explanation.into(),
            voter_name: voter_name.into(),
            weight: 1.0,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Constructs a veto vote with negative weight.
    pub fn new_veto(
        candidate_pid: Option<u32>,
        explanation: impl Into<String>,
        voter_name: impl Into<String>,
        evidence_class: EvidenceClass,
    ) -> Self {
        Self {
            candidate_pid,
            action: VoteAction::Monitor,
            confidence: 0.98,
            evidence_class,
            explanation: explanation.into(),
            voter_name: voter_name.into(),
            weight: -1.50,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn is_veto(&self) -> bool {
        self.weight < 0.0
    }
}

/// Input threat candidate presented to the zero-false-positive adjudication gate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatCandidate {
    /// Target PID if currently running on the host.
    pub pid: Option<u32>,
    /// Executable name (e.g. "svchost.exe", "unknown_dropper.exe").
    pub proc_name: String,
    /// Absolute or relative path on disk, if known.
    pub binary_path: Option<String>,
    /// BLAKE3 digest of the binary image on disk.
    pub blake3_hash: Option<String>,
    /// SHA-256 digest of the binary image on disk.
    pub sha256_hash: Option<String>,
    /// Command line string executed by the process.
    pub command_line: Option<String>,
    /// Parent process PID.
    pub parent_pid: Option<u32>,
    /// Source detector that surfaced the initial signal (e.g. "PhaseLock", "MeshGuard").
    pub source_detector: String,
    /// Initial detector reason or alert message.
    pub detection_reason: String,
    /// Initial raw detector confidence score (0.0 .. 1.0).
    pub initial_confidence: f32,
    /// Telemetry evidence classification.
    pub evidence_class: EvidenceClass,
    /// Peer ID if this threat was broadcast or gossiped from an external limb/peer.
    pub peer_id: Option<String>,
    /// Optional YARA rule syntax if generated or matched.
    pub yara_rule: Option<String>,
    /// Arbitrary detector metadata payload.
    pub raw_telemetry: Option<serde_json::Value>,
    /// RFC 3339 timestamp of detection.
    pub timestamp: String,
}

impl ThreatCandidate {
    pub fn new(
        pid: Option<u32>,
        proc_name: impl Into<String>,
        source_detector: impl Into<String>,
        detection_reason: impl Into<String>,
        initial_confidence: f32,
        evidence_class: EvidenceClass,
    ) -> Self {
        Self {
            pid,
            proc_name: proc_name.into(),
            binary_path: None,
            blake3_hash: None,
            sha256_hash: None,
            command_line: None,
            parent_pid: None,
            source_detector: source_detector.into(),
            detection_reason: detection_reason.into(),
            initial_confidence: initial_confidence.clamp(0.0, 1.0),
            evidence_class,
            peer_id: None,
            yara_rule: None,
            raw_telemetry: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// Evaluation verdict from `AutonomousReaEngine::evaluate_detector_candidate`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReaDetectorEvaluation {
    pub detector_name: String,
    pub target: String,
    pub benign_veto: bool,
    pub masquerade_escalated: bool,
    pub prompt_injection_escalated: bool,
    pub adjusted_score: f64,
    pub rea_threat_score: f32,
    pub verdict: String,
    pub explanation: String,
    pub rea_seal_blake3: String,
    pub auto_yara_synthesized: bool,
}

/// Structured consensus vote cast by `AutonomousReaEngine::cast_consensus_vote`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReaConsensusVote {
    pub voter_name: String,
    pub target: String,
    pub detector_source: String,
    pub decision: String,
    pub weight: f64,
    pub confidence: f64,
    pub benign_veto: bool,
    pub masquerade_escalated: bool,
    pub prompt_injection_detected: bool,
    pub reason: String,
    pub rea_seal_blake3: String,
    pub timestamp: String,
}

impl ReaConsensusVote {
    pub fn compute_seal(
        target: &str,
        decision: &str,
        weight: f64,
        confidence: f64,
        reason: &str,
        timestamp: &str,
    ) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(REA_SEAL_CONTEXT);
        hasher.update(target.as_bytes());
        hasher.update(b"|");
        hasher.update(decision.as_bytes());
        hasher.update(b"|");
        hasher.update(&weight.to_le_bytes());
        hasher.update(b"|");
        hasher.update(&confidence.to_le_bytes());
        hasher.update(b"|");
        hasher.update(reason.as_bytes());
        hasher.update(b"|");
        hasher.update(timestamp.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    pub fn verify_seal(&self) -> bool {
        let expected = Self::compute_seal(
            &self.target,
            &self.decision,
            self.weight,
            self.confidence,
            &self.reason,
            &self.timestamp,
        );
        let actual = self.rea_seal_blake3.as_bytes();
        let exp = expected.as_bytes();
        if actual.len() != exp.len() || actual.is_empty() {
            return false;
        }
        actual.ct_eq(exp).into()
    }
}

/// Enumeration of reasons why a candidate threat was vetoed by adjudication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VetoReason {
    /// Binary BLAKE3 hash matches local protected inventory (`PROTECTED_LOCAL_BINARY_HASHES`).
    ProtectedBinaryHash,
    /// PID matches critical system or developer whitelist (`is_critical_system_pid`).
    CriticalSystemPid,
    /// Process is an ancestor (depth <= 5) of the security agent or critical system daemon.
    ProtectedParentLineage,
    /// Binary has valid Authenticode signature from a trusted vendor.
    AuthenticodeTrustedVendor,
    /// Binary is verified in the Windows Security Catalog (`CatRoot`).
    WindowsCatalogSigned,
    /// Candidate is a benign Rust build artifact in `target/` or cargo test runner.
    BenignDevToolchain,
    /// Corroboration penalty reduced confidence below isolation threshold (`independent < 3`).
    SingleVoterCorroborationPenalty,
    /// YARA rule illicitly matches protected system binary filenames.
    PoisonedYaraRuleTarget,
    /// Counter-AI prompt injection detected in alert reasoning string.
    PromptInjectionDetected,
}

impl VetoReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProtectedBinaryHash => "PROTECTED_LOCAL_BINARY_HASH_VETO",
            Self::CriticalSystemPid => "CRITICAL_SYSTEM_PID_VETO",
            Self::ProtectedParentLineage => "PROTECTED_PARENT_LINEAGE_VETO",
            Self::AuthenticodeTrustedVendor => "AUTHENTICODE_TRUSTED_VENDOR_VETO",
            Self::WindowsCatalogSigned => "WINDOWS_CATALOG_SIGNED_VETO",
            Self::BenignDevToolchain => "BENIGN_DEV_TOOLCHAIN_VETO",
            Self::SingleVoterCorroborationPenalty => "SINGLE_VOTER_PENALTY_VETO",
            Self::PoisonedYaraRuleTarget => "POISONED_YARA_TARGET_VETO",
            Self::PromptInjectionDetected => "PROMPT_INJECTION_VETO",
        }
    }
}

/// Comprehensive outcome of Zero-False-Positive multi-layer adjudication.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AdjudicationResult {
    /// Threat candidate was deterministically vetoed. The KillSwitch will NEVER isolate.
    Vetoed {
        reason: VetoReason,
        explanation: String,
        fraud_proof: Option<Box<ByzantineKillSwitchFraudProof>>,
        trust_verdict: Option<BinaryTrustVerdict>,
        adjudication_seal: String,
        timestamp: String,
    },
    /// Threat candidate passed all 4 layers with high confidence (>= 0.94) and multi-class corroboration.
    ConfirmedThreat {
        recommended_action: VoteAction,
        confidence: f32,
        independent_classes: usize,
        votes: Vec<VoteResult>,
        explanation: String,
        adjudication_seal: String,
        timestamp: String,
    },
    /// Candidate confidence is high (>= 0.82) but requires manual operator confirmation before isolation.
    AwaitingManualConfirmation {
        confidence: f32,
        votes: Vec<VoteResult>,
        explanation: String,
        adjudication_seal: String,
        timestamp: String,
    },
    /// Low or uncorroborated confidence; candidate should be tracked passively without isolation.
    MonitorOnly {
        confidence: f32,
        explanation: String,
        timestamp: String,
    },
}

impl AdjudicationResult {
    /// Returns `true` if this candidate was vetoed.
    pub fn is_vetoed(&self) -> bool {
        matches!(self, Self::Vetoed { .. })
    }

    /// Returns `true` if this candidate was confirmed as an actionable threat.
    pub fn is_confirmed(&self) -> bool {
        matches!(self, Self::ConfirmedThreat { .. })
    }

    /// Returns `true` if this candidate requires human-in-the-loop manual confirmation.
    pub fn is_awaiting_confirmation(&self) -> bool {
        matches!(self, Self::AwaitingManualConfirmation { .. })
    }

    /// Returns the fraud proof if this veto generated one.
    pub fn fraud_proof(&self) -> Option<&ByzantineKillSwitchFraudProof> {
        match self {
            Self::Vetoed { fraud_proof, .. } => fraud_proof.as_deref(),
            _ => None,
        }
    }

    /// Returns the composite confidence score of the adjudication.
    pub fn confidence(&self) -> f32 {
        match self {
            Self::Vetoed { .. } => 0.0,
            Self::ConfirmedThreat { confidence, .. } => *confidence,
            Self::AwaitingManualConfirmation { confidence, .. } => *confidence,
            Self::MonitorOnly { confidence, .. } => *confidence,
        }
    }

    /// Computes a canonical BLAKE3 adjudication seal over the result.
    pub fn compute_seal(verdict_name: &str, confidence: f32, explanation: &str, timestamp: &str) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(REA_SEAL_CONTEXT);
        hasher.update(verdict_name.as_bytes());
        hasher.update(b"|");
        hasher.update(&confidence.to_le_bytes());
        hasher.update(b"|");
        hasher.update(explanation.as_bytes());
        hasher.update(b"|");
        hasher.update(timestamp.as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}

/// Computes the mathematical corroboration multiplier based on count of independent evidence classes:
/// - 0 classes -> 0.0
/// - 1 class   -> 0.52 (Strict Single-Voter Penalty)
/// - 2 classes -> 0.82
/// - >=3 classes -> 1.00
pub fn corroboration_multiplier(distinct_classes_count: usize) -> f32 {
    match distinct_classes_count {
        0 => 0.0,
        1 => 0.52,
        2 => 0.82,
        _ => 1.00,
    }
}

/// Calculates composite consensus confidence over a set of votes.
/// Returns (composite_confidence, independent_classes_count).
pub fn calculate_consensus(votes: &[VoteResult]) -> (f32, usize) {
    if votes.is_empty() {
        return (0.0, 0);
    }

    // Check for veto votes (weight < 0.0)
    if votes.iter().any(|v| v.is_veto()) {
        return (0.0, 0);
    }

    use std::collections::HashSet;
    let mut classes = HashSet::new();
    let mut total_support = 0.0f32;
    let mut total_mass = 0.0f32;

    for v in votes {
        classes.insert(v.evidence_class);
        let reliability = v.evidence_class.default_reliability();
        let mass = v.weight * reliability;
        total_support += v.confidence * mass;
        total_mass += mass;
    }

    if total_mass <= 0.0 {
        return (0.0, classes.len());
    }

    let base_score = total_support / total_mass;
    let multiplier = corroboration_multiplier(classes.len());
    let final_confidence = (base_score * multiplier).clamp(0.0, 1.0);

    (final_confidence, classes.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fraud_proof_seal_generation_and_verification() {
        let proof = ByzantineKillSwitchFraudProof::new(
            "node-alpha",
            "peer-rogue-01",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "svchost.exe",
            "Critical system process targeted",
        );

        assert!(proof.verify_seal());
    }

    #[test]
    fn test_fraud_proof_tamper_detection() {
        let mut proof = ByzantineKillSwitchFraudProof::new(
            "node-alpha",
            "peer-rogue-01",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "svchost.exe",
            "Critical system process targeted",
        );

        assert!(proof.verify_seal());

        // Tamper with target_binary_hash
        proof.target_binary_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
        assert!(!proof.verify_seal());

        // Restore hash and tamper with proc_name
        proof.target_binary_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string();
        assert!(proof.verify_seal());
        proof.proc_name = "explorer.exe".to_string();
        assert!(!proof.verify_seal());
    }

    #[test]
    fn test_binary_trust_verdict_classification() {
        let auth = BinaryTrustVerdict::TrustedAuthenticode {
            signer_subject: Some("Microsoft Windows".to_string()),
            thumbprint: Some("abc123".to_string()),
        };
        assert!(auth.is_trusted());
        assert!(!auth.is_untrusted());
        assert_eq!(auth.category(), "trusted_authenticode");

        let bad_loc = BinaryTrustVerdict::UntrustedWritableLocation {
            path: "C:\\Users\\user\\AppData\\Local\\Temp\\mal.exe".to_string(),
            reason: "Temp execution".to_string(),
        };
        assert!(!bad_loc.is_trusted());
        assert!(bad_loc.is_untrusted());
        assert_eq!(bad_loc.category(), "untrusted_writable_location");
    }

    #[test]
    fn test_vote_result_clamping_and_veto() {
        let vote = VoteResult::new(
            Some(4412),
            VoteAction::Isolate,
            1.85, // Out of bounds -> should clamp to 1.0
            EvidenceClass::Behavior,
            "Ransomware encryption detected",
            "BehaviorVoter",
        );
        assert_eq!(vote.confidence, 1.0);
        assert!(!vote.is_veto());

        let veto = VoteResult::new_veto(
            Some(4),
            "System kernel PID is immune",
            "SystemWhitelistVoter",
            EvidenceClass::StaticArtifact,
        );
        assert!(veto.is_veto());
        assert!(veto.weight < 0.0);
    }

    #[test]
    fn test_single_voter_penalty_invariant() {
        // Even with 0.99 confidence on 1 voter, score must be penalized by 0.52 -> ~0.5148
        let vote = VoteResult::new(
            Some(8888),
            VoteAction::Isolate,
            0.99,
            EvidenceClass::LiveNetwork,
            "C2 Beaconing",
            "NetworkVoter",
        );

        let (score, count) = calculate_consensus(&[vote]);
        assert_eq!(count, 1);
        assert!(score < 0.55);
        assert!(score < 0.94); // Will NEVER isolate on single voter
    }

    #[test]
    fn test_rea_consensus_vote_seal_verification() {
        let target = "powershell.exe";
        let decision = "VETO";
        let weight = -1.0;
        let confidence = 0.99;
        let reason = "Dev process white-listed";
        let timestamp = "2026-10-26T12:00:00Z";

        let seal = ReaConsensusVote::compute_seal(target, decision, weight, confidence, reason, timestamp);

        let vote = ReaConsensusVote {
            voter_name: "AutonomousReaEngine".to_string(),
            target: target.to_string(),
            detector_source: "MasqueradeDetector".to_string(),
            decision: decision.to_string(),
            weight,
            confidence,
            benign_veto: true,
            masquerade_escalated: false,
            prompt_injection_detected: false,
            reason: reason.to_string(),
            rea_seal_blake3: seal,
            timestamp: timestamp.to_string(),
        };

        assert!(vote.verify_seal());
    }
}
