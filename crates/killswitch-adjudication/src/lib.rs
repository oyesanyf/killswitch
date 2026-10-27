//! # `killswitch-adjudication`
//!
//! Production-grade Zero-False-Positive Adjudication Gate & Multi-Voter Consensus Engine ("Never Wrong" Invariant).
//!
//! Exposes:
//! - 5-Layer Zero-False-Positive Defense Gate (`ZeroFalsePositiveAdjudicator`)
//! - Multi-Voter Consensus Engine with Corroboration Multiplier & Strict Veto Propagation (`MultiVoterConsensusEngine`)
//! - Mandatory First-Class DLP Data Lineage Threat Voter (`DataLineageVoter`)
//! - Autonomous REA 4-Layer Defense Engine (`AutonomousReaEngine`)
//! - WinTrust Authenticode, CatRoot Catalog, and Cross-Platform Trust Verification (`win_trust`)
//! - Process Ancestry Traversal (Depth <= 5) & Critical System PID Whitelist (`immunity`)
//! - Protected Local Binary BLAKE3 Hash Inventory (`inventory`)
//! - Cryptographically Sealed Byzantine Kill-Switch Fraud Proofs (`byzantine`)

pub mod adjudicator;
pub mod byzantine;
pub mod consensus;
pub mod edr_bench;
pub mod immunity;
pub mod inventory;
pub mod rea;
pub mod voters;
pub mod win_trust;

// Public re-exports
pub use adjudicator::ZeroFalsePositiveAdjudicator;
pub use edr_bench::{
    load_all_bench_tasks, resolve_fixture_path, BenignBaselineAssertion, BenchmarkReport,
    EdrBenchHarness, EdrBenchTask, ExpectedVerdict, GateIterationTrace, HarnessBounds, TargetArch,
    TelemetryContext, ThreatAssertion, MAX_RULE_SOURCE_BYTES,
};
pub use byzantine::{
    build_kill_switch_fraud_proof, veto_peer_kill_switch_candidate, PEER_SLASHED_STAKE,
};
pub use consensus::MultiVoterConsensusEngine;
pub use immunity::{
    get_process_ancestry_chain, inspect_process_lineage, LineageImmunityVerdict,
    MAX_ANCESTRY_DEPTH,
};
pub use inventory::{
    get_protected_local_binary_hashes, is_protected_local_binary_hash,
    register_protected_binary_hash,
};
pub use rea::{
    detect_binary_masquerade_spoof, extract_printable_strings,
    get_canonical_protected_binary_names, has_active_lotl_or_exploit_indicators,
    inspect_binary_format_safe, is_canonical_protected_binary_name,
    is_rea_benign_system_or_dev_process, is_untrusted_writable_or_temp_path,
    scan_and_sanitize_counter_ai_strings, validate_rea_target_path, AutonomousReaEngine,
    BinaryFormatInfo, BinaryFormatKind, SectionInfo, MAX_EXTRACTED_STRINGS, MAX_PE_SECTIONS,
    MAX_REA_FILE_BYTES, MAX_SINGLE_STRING_BYTES,
};
pub use voters::{
    AdjudicationContext, BehaviorVoter, DataLineageVoter, DlpClassification, DlpPolicy,
    EgressVerdict, LineageAdjudicationEvidence, LineageCausalLink, LiveNetworkVoter, MemoryVoter,
    OpenLineageDataset, OpenLineageDatasetFacets, ReaVoter, StaticArtifactVoter, TaintBaggage,
    ThreatIntelVoter, ThreatVoter, VoterRegistry,
};
pub use win_trust::{
    clear_authenticode_cache, get_cached_authenticode_status, invalidate_cache_entry,
    is_trusted_vendor, is_untrusted_writable_location, verify_binary_cryptographic_trust,
    AuthenticodeChainStatus, AuthenticodeStatus, BinaryTrustVerdict, AUTHENTICODE_CACHE,
    AUTHENTICODE_CACHE_TTL, BINARY_TRUST_CACHE,
};
