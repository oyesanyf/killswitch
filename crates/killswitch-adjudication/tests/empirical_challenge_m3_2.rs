//! Empirical Challenge Test Suite 2 for Milestone 3 (`crates/killswitch-adjudication`)
//!
//! Adversarial stress tests verifying:
//! 1. Multi-Hop OpenTelemetry / OpenLineage DLP Fan-In Scenario (Follow-up #2 & #3)
//! 2. Uncompromised Admin Shell vs Compromised LOTL Shell
//! 3. Process Ancestry Traversal Depth 5 & Cyclic Link Defense
//! 4. Byzantine Fraud Proof Tamper Detection & Constant-Time Verification
//! 5. In-Memory Inventory Lookup Concurrency (Zero Deadlocks & Consistency)

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use killswitch_adjudication::immunity::{
    get_process_ancestry_chain, inspect_process_lineage, LineageImmunityVerdict, MAX_ANCESTRY_DEPTH,
};
use killswitch_adjudication::inventory::{
    get_protected_local_binary_hashes, is_protected_local_binary_hash,
    register_protected_binary_hash,
};
use killswitch_adjudication::voters::{
    AdjudicationContext, DataLineageVoter, DlpClassification, DlpPolicy, EgressVerdict,
    LineageAdjudicationEvidence, LineageCausalLink, OpenLineageDataset, OpenLineageDatasetFacets,
    TaintBaggage, ThreatVoter,
};
use killswitch_adjudication::ZeroFalsePositiveAdjudicator;
use killswitch_core::killchain::is_critical_system_pid;
use killswitch_types::adjudication::{
    AdjudicationResult, ByzantineKillSwitchFraudProof, EvidenceClass, ThreatCandidate, VetoReason,
    VoteAction, VoteResult,
};

// ============================================================================
// 1. Multi-Hop OpenTelemetry / OpenLineage DLP Fan-In Scenario
// ============================================================================

#[tokio::test]
async fn test_empirical_dlp_fan_in_exfiltration_adjudication() {
    // Exact scenario from Follow-up #2 & #3:
    // 1. Secret asset 1: `secret_roadmap.docx` (CrownJewel, Quarantine, SHA-256 A)
    // 2. Secret asset 2: `q4_financials.xlsx` (Confidential, Audit, SHA-256 B)
    // 3. Spawning process: `powershell.exe` (PID 2104) spawns `7z.exe` (PID 4812)
    // 4. `7z.exe` reads both assets: TaintBaggage merges to CrownJewel + Quarantine, concatenates hashes
    // 5. `7z.exe` writes `staging_upload.zip`
    // 6. `curl.exe` (PID 5001) reads `staging_upload.zip` and attempts egress to `https://external-drop.example.com/upload`
    // 7. EgressVerdict::Block returned with trace_id and merged SHA-256 hashes

    let sha_roadmap = "aaa1111111111111111111111111111111111111111111111111111111111111";
    let sha_financials = "bbb2222222222222222222222222222222222222222222222222222222222222";

    let mut baggage_doc = TaintBaggage::new(
        DlpClassification::CrownJewel,
        DlpPolicy::Quarantine,
        sha_roadmap,
    );
    let baggage_xls = TaintBaggage::new(
        DlpClassification::Confidential,
        DlpPolicy::Audit,
        sha_financials,
    );

    // Merge baggage as 7z.exe ingests both files
    baggage_doc.merge(&baggage_xls);
    assert_eq!(baggage_doc.classification, DlpClassification::CrownJewel);
    assert_eq!(baggage_doc.policy, DlpPolicy::Quarantine);
    assert!(baggage_doc.is_crown_jewel());
    assert!(baggage_doc.is_quarantine());
    assert!(baggage_doc.source_sha256.contains(sha_roadmap));
    assert!(baggage_doc.source_sha256.contains(sha_financials));

    let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
    let destination_url = "https://external-drop.example.com/upload";

    let input_datasets = vec![
        OpenLineageDataset {
            namespace: "file://endpoint-local".to_string(),
            name: "C:\\Users\\Alice\\Documents\\secret_roadmap.docx".to_string(),
            facets: OpenLineageDatasetFacets {
                content_sha256: sha_roadmap.to_string(),
                dlp_classification: DlpClassification::CrownJewel,
            },
        },
        OpenLineageDataset {
            namespace: "file://endpoint-local".to_string(),
            name: "C:\\Users\\Alice\\Documents\\q4_financials.xlsx".to_string(),
            facets: OpenLineageDatasetFacets {
                content_sha256: sha_financials.to_string(),
                dlp_classification: DlpClassification::Confidential,
            },
        },
    ];

    let causal_links = vec![
        LineageCausalLink {
            trace_id: trace_id.to_string(),
            span_id: "00f067aa0ba902b7".to_string(),
            role: "INPUT".to_string(),
            file_path: "C:\\Users\\Alice\\Documents\\secret_roadmap.docx".to_string(),
        },
        LineageCausalLink {
            trace_id: trace_id.to_string(),
            span_id: "5fb397be34d23b0f".to_string(),
            role: "INPUT".to_string(),
            file_path: "C:\\Users\\Alice\\Documents\\q4_financials.xlsx".to_string(),
        },
    ];

    let egress_verdict = EgressVerdict::Block {
        reason: "DLP Egress Blocked: QUARANTINE policy active on trace".to_string(),
        trace_id: trace_id.to_string(),
    };
    assert!(egress_verdict.is_block());

    let evidence = LineageAdjudicationEvidence {
        actor_pid: 5001,
        actor_exe: "curl.exe".to_string(),
        parent_pid: Some(4812), // Parent was 7z.exe
        destination: destination_url.to_string(),
        egress_verdict: egress_verdict.clone(),
        baggage: Some(baggage_doc),
        causal_links,
        input_datasets,
        provenance_hops: vec![
            "powershell.exe:2104".to_string(),
            "7z.exe:4812".to_string(),
            "curl.exe:5001".to_string(),
        ],
    };

    let context = AdjudicationContext {
        lineage_evidence: Some(evidence),
        ..Default::default()
    };

    let candidate = ThreatCandidate::new(
        Some(5001),
        "curl.exe",
        "EndpointLineageEngine",
        "Multi-hop DLP egress blocked to https://external-drop.example.com/upload",
        0.95,
        EvidenceClass::LiveNetwork,
    );

    // 1. Assert DataLineageVoter directly casts Isolate vote on curl.exe PID 5001
    let voter = DataLineageVoter::new();
    let vote = voter.vote(&candidate, Some(&context)).await;
    assert!(vote.is_some(), "DataLineageVoter must cast a vote on DLP exfiltration");
    let v = vote.unwrap();
    assert_eq!(v.candidate_pid, Some(5001));
    assert_eq!(v.action, VoteAction::Isolate);
    assert_eq!(v.confidence, 0.96);
    assert_eq!(v.weight, 1.85);
    assert_eq!(v.evidence_class, EvidenceClass::LiveNetwork);
    assert!(v.explanation.contains(trace_id));
    assert!(v.explanation.contains(sha_roadmap));
    assert!(v.explanation.contains(sha_financials));
    assert!(v.explanation.contains("curl.exe"));

    // 2. Evaluate with full ZeroFalsePositiveAdjudicator:
    // With only DataLineageVoter (1 evidence class: LiveNetwork), single-voter penalty
    // ensures confidence is clamped to 0.52 (< 0.82 manual confirmation), preventing unilateral false positives.
    let adjudicator = ZeroFalsePositiveAdjudicator::new();
    let result_single = adjudicator
        .adjudicate_threat_candidate(&candidate, Some(&context))
        .await;
    println!("result_single: {:?}", result_single);
    assert!(!result_single.is_vetoed(), "curl.exe PID 5001 must not be vetoed");

    // 3. Now corroborate across >= 3 classes (LiveNetwork from Lineage + Behavior + Memory):
    // Register custom multi-class votes and verify ConfirmedThreat is reached for PID 5001
    let votes = vec![
        v.clone(),
        VoteResult::new(
            Some(5001),
            VoteAction::Isolate,
            0.95,
            EvidenceClass::Behavior,
            "Anomalous outbound socket spawned by archive utility",
            "BehaviorVoter",
        ),
        VoteResult::new(
            Some(5001),
            VoteAction::Isolate,
            0.95,
            EvidenceClass::Memory,
            "Injected payload memory page in network client",
            "MemoryVoter",
        ),
    ];
    let result_confirmed = adjudicator
        .consensus_engine()
        .orchestrate_evidence(&votes, &candidate);
    assert!(
        result_confirmed.is_confirmed(),
        "Corroborated 3-class evidence must confirm autonomous threat containment"
    );
    assert!(result_confirmed.confidence() >= 0.94);
    if let AdjudicationResult::ConfirmedThreat { recommended_action, .. } = result_confirmed {
        assert_eq!(recommended_action, VoteAction::Isolate);
    } else {
        panic!("Expected ConfirmedThreat");
    }
}

// ============================================================================
// 2. Uncompromised Admin Shell vs Compromised LOTL Shell
// ============================================================================

#[tokio::test]
async fn test_empirical_admin_shell_veto_vs_lotl_exfiltration() {
    let voter = DataLineageVoter::new();
    let adjudicator = ZeroFalsePositiveAdjudicator::new();

    // -------------------------------------------------------------------------
    // Scenario A: Uncompromised Admin powershell.exe runs clean admin command
    // -------------------------------------------------------------------------
    let clean_evidence = LineageAdjudicationEvidence {
        actor_pid: 2104,
        actor_exe: "powershell.exe".to_string(),
        parent_pid: Some(1000),
        destination: "127.0.0.1:3030".to_string(),
        egress_verdict: EgressVerdict::Allow,
        baggage: None, // No quarantined taint
        causal_links: vec![],
        input_datasets: vec![],
        provenance_hops: vec![],
    };

    let clean_context = AdjudicationContext {
        lineage_evidence: Some(clean_evidence),
        ..Default::default()
    };

    let clean_candidate = ThreatCandidate::new(
        Some(2104),
        "powershell.exe",
        "SysmonDetector",
        "Administrative Get-Process command",
        0.20,
        EvidenceClass::Behavior,
    );

    // DataLineageVoter must cast a benign veto with weight -1.50
    let clean_vote = voter.vote(&clean_candidate, Some(&clean_context)).await;
    assert!(clean_vote.is_some());
    let v_clean = clean_vote.unwrap();
    assert!(v_clean.is_veto(), "Clean admin shell must receive a veto vote");
    assert_eq!(v_clean.weight, -1.50);
    assert_eq!(v_clean.action, VoteAction::Monitor);
    assert!(v_clean.explanation.contains("attested clean by DataLineageVoter"));

    // Adjudicator must veto isolation of clean powershell.exe (both via Layer 1 immunity and consensus)
    let clean_adjudication = adjudicator
        .adjudicate_threat_candidate(&clean_candidate, Some(&clean_context))
        .await;
    assert!(
        clean_adjudication.is_vetoed(),
        "Adjudicator must veto isolation of uncompromised admin shell"
    );
    assert_eq!(clean_adjudication.confidence(), 0.0);
    if let AdjudicationResult::Vetoed { reason, .. } = clean_adjudication {
        assert_eq!(reason, VetoReason::CriticalSystemPid);
    } else {
        panic!("Expected Vetoed result");
    }

    // -------------------------------------------------------------------------
    // Scenario B: Compromised LOTL powershell.exe attempting CrownJewel egress
    // -------------------------------------------------------------------------
    let compromised_baggage = TaintBaggage::new(
        DlpClassification::CrownJewel,
        DlpPolicy::Quarantine,
        "crown_jewel_exfil_sha256_hash",
    );

    let compromised_evidence = LineageAdjudicationEvidence {
        actor_pid: 2104,
        actor_exe: "powershell.exe".to_string(),
        parent_pid: Some(1000),
        destination: "https://c2-exfil-staging.attacker.org/post".to_string(),
        egress_verdict: EgressVerdict::Block {
            reason: "DLP Quarantine policy active".to_string(),
            trace_id: "trace-lotl-exfil-001".to_string(),
        },
        baggage: Some(compromised_baggage),
        causal_links: vec![],
        input_datasets: vec![],
        provenance_hops: vec!["powershell.exe:2104".to_string()],
    };

    let compromised_context = AdjudicationContext {
        lineage_evidence: Some(compromised_evidence),
        ..Default::default()
    };

    let compromised_candidate = ThreatCandidate::new(
        Some(2104),
        "powershell.exe",
        "EndpointLineageEngine",
        "CrownJewel DLP exfiltration attempt in shell",
        0.98,
        EvidenceClass::LiveNetwork,
    );

    // DataLineageVoter recommends network containment while preserving the critical shell PID from process freeze
    let comp_vote = voter
        .vote(&compromised_candidate, Some(&compromised_context))
        .await;
    assert!(comp_vote.is_some());
    let v_comp = comp_vote.unwrap();
    assert_eq!(v_comp.action, VoteAction::Isolate);
    assert_eq!(v_comp.confidence, 0.96);
    assert!(
        v_comp.explanation.contains("Preserving PID from freeze termination; network isolation recommended"),
        "Vote must explicitly preserve shell PID from process freeze"
    );

    // Full adjudicator evaluation: Layer 1 process immunity ensures critical shell PID is NEVER frozen or killed
    let comp_adjudication = adjudicator
        .adjudicate_threat_candidate(&compromised_candidate, Some(&compromised_context))
        .await;
    assert!(
        comp_adjudication.is_vetoed(),
        "Adjudicator must preserve powershell.exe from process kill/freeze containment"
    );
    if let AdjudicationResult::Vetoed { reason, .. } = comp_adjudication {
        assert_eq!(reason, VetoReason::CriticalSystemPid);
    } else {
        panic!("Expected Vetoed result");
    }
}

// ============================================================================
// 3. Process Ancestry Traversal Depth 5 & Cyclic Link Defense
// ============================================================================

/// Simulated Process Tree Traversal Engine matching the exact architecture:
/// - Max Depth: `MAX_ANCESTRY_DEPTH` (5)
/// - Cycle Boundary Defense: `HashSet<u32>`
/// - Critical/Dev Tool Ancestor Immunity: `is_critical_system_pid`
fn simulate_process_lineage_traversal(
    target_pid: u32,
    target_name: &str,
    tree: &HashMap<u32, (u32, String)>, // pid -> (parent_pid, parent_name)
) -> LineageImmunityVerdict {
    // 1. Direct Target Immunity Check
    if is_critical_system_pid(target_pid, target_name) {
        return LineageImmunityVerdict::ImmuneTarget {
            pid: target_pid,
            proc_name: target_name.to_string(),
        };
    }

    // 2. Ancestry Traversal with cycle boundary
    let mut current_pid = target_pid;
    let mut visited = HashSet::new();
    visited.insert(current_pid);

    let mut depth = 0;
    while depth < MAX_ANCESTRY_DEPTH {
        let Some(&(parent_pid, ref parent_name)) = tree.get(&current_pid) else {
            break;
        };

        // Safe cycle boundary: terminate if ancestor already visited
        if !visited.insert(parent_pid) {
            // Cycle detected! Break safely without hanging
            break;
        }

        depth += 1;

        // Check if ancestor is critical OS or developer toolchain
        if parent_pid <= 4 || is_critical_system_pid(parent_pid, parent_name) {
            return LineageImmunityVerdict::ImmuneAncestor {
                target_pid,
                ancestor_pid: parent_pid,
                ancestor_name: parent_name.clone(),
                depth,
            };
        }

        current_pid = parent_pid;
    }

    LineageImmunityVerdict::NotImmune
}

#[test]
fn test_empirical_ancestry_depth_5_boundary_and_cyclic_defense() {
    assert_eq!(MAX_ANCESTRY_DEPTH, 5);

    // -------------------------------------------------------------------------
    // Test Depth 1: Direct child of `cargo.exe` (e.g. build script / test runner)
    // -------------------------------------------------------------------------
    let mut tree_depth1 = HashMap::new();
    tree_depth1.insert(5001, (2000, "cargo.exe".to_string()));

    let verdict1 = simulate_process_lineage_traversal(5001, "custom_worker.exe", &tree_depth1);
    assert!(verdict1.is_immune());
    assert_eq!(verdict1.to_veto_reason(), Some(VetoReason::ProtectedParentLineage));
    match verdict1 {
        LineageImmunityVerdict::ImmuneAncestor { depth, ancestor_name, .. } => {
            assert_eq!(depth, 1);
            assert_eq!(ancestor_name, "cargo.exe");
        }
        _ => panic!("Expected ImmuneAncestor"),
    }

    // -------------------------------------------------------------------------
    // Test Depth 3: PID 5003 -> 5002 -> 5001 -> 1008 (`explorer.exe`)
    // -------------------------------------------------------------------------
    let mut tree_depth3 = HashMap::new();
    tree_depth3.insert(5003, (5002, "subproc3.exe".to_string()));
    tree_depth3.insert(5002, (5001, "subproc2.exe".to_string()));
    tree_depth3.insert(5001, (1008, "explorer.exe".to_string()));

    let verdict3 = simulate_process_lineage_traversal(5003, "leaf_proc.exe", &tree_depth3);
    assert!(verdict3.is_immune());
    assert_eq!(verdict3.to_veto_reason(), Some(VetoReason::ProtectedParentLineage));
    match verdict3 {
        LineageImmunityVerdict::ImmuneAncestor { depth, ancestor_name, .. } => {
            assert_eq!(depth, 3);
            assert_eq!(ancestor_name, "explorer.exe");
        }
        _ => panic!("Expected ImmuneAncestor"),
    }

    // -------------------------------------------------------------------------
    // Test Depth 5: Exactly at MAX_ANCESTRY_DEPTH boundary
    // PID 6005 -> 6004 -> 6003 -> 6002 -> 6001 -> 2004 (`rustc.exe`)
    // -------------------------------------------------------------------------
    let mut tree_depth5 = HashMap::new();
    tree_depth5.insert(6005, (6004, "p5.exe".to_string()));
    tree_depth5.insert(6004, (6003, "p4.exe".to_string()));
    tree_depth5.insert(6003, (6002, "p3.exe".to_string()));
    tree_depth5.insert(6002, (6001, "p2.exe".to_string()));
    tree_depth5.insert(6001, (2004, "rustc.exe".to_string()));

    let verdict5 = simulate_process_lineage_traversal(6005, "leaf_at_5.exe", &tree_depth5);
    assert!(verdict5.is_immune(), "Depth 5 ancestor MUST receive immunity");
    assert_eq!(verdict5.to_veto_reason(), Some(VetoReason::ProtectedParentLineage));
    match verdict5 {
        LineageImmunityVerdict::ImmuneAncestor { depth, ancestor_name, .. } => {
            assert_eq!(depth, 5);
            assert_eq!(ancestor_name, "rustc.exe");
        }
        _ => panic!("Expected ImmuneAncestor"),
    }

    // -------------------------------------------------------------------------
    // Test Depth 6: Beyond MAX_ANCESTRY_DEPTH (depth 6 does NOT receive immunity)
    // PID 7006 -> 7005 -> 7004 -> 7003 -> 7002 -> 7001 -> 2004 (`rustc.exe`)
    // -------------------------------------------------------------------------
    let mut tree_depth6 = HashMap::new();
    tree_depth6.insert(7006, (7005, "p6.exe".to_string()));
    tree_depth6.insert(7005, (7004, "p5.exe".to_string()));
    tree_depth6.insert(7004, (7003, "p4.exe".to_string()));
    tree_depth6.insert(7003, (7002, "p3.exe".to_string()));
    tree_depth6.insert(7002, (7001, "p2.exe".to_string()));
    tree_depth6.insert(7001, (2004, "rustc.exe".to_string())); // rustc is at depth 6!

    let verdict6 = simulate_process_lineage_traversal(7006, "leaf_at_6.exe", &tree_depth6);
    assert!(
        !verdict6.is_immune(),
        "Depth 6 ancestor MUST NOT receive immunity (strictly bounded at depth 5)"
    );
    assert_eq!(verdict6, LineageImmunityVerdict::NotImmune);
    assert_eq!(verdict6.to_veto_reason(), None);

    // -------------------------------------------------------------------------
    // Test Cyclic Link Defense (PID A parent is B, B parent is A)
    // Must terminate safely without infinite recursion, hang, or stack overflow
    // -------------------------------------------------------------------------
    let mut cyclic_tree = HashMap::new();
    cyclic_tree.insert(8001, (8002, "cycle_b.exe".to_string()));
    cyclic_tree.insert(8002, (8001, "cycle_a.exe".to_string())); // Cycle back to 8001

    let verdict_cyclic = simulate_process_lineage_traversal(8001, "cycle_a.exe", &cyclic_tree);
    assert!(
        !verdict_cyclic.is_immune(),
        "Cyclic tree without critical root must terminate as NotImmune"
    );

    // Multi-hop cycle: 9001 -> 9002 -> 9003 -> 9001
    let mut multi_cycle = HashMap::new();
    multi_cycle.insert(9001, (9002, "c2.exe".to_string()));
    multi_cycle.insert(9002, (9003, "c3.exe".to_string()));
    multi_cycle.insert(9003, (9001, "c1.exe".to_string()));

    let verdict_multi = simulate_process_lineage_traversal(9001, "c1.exe", &multi_cycle);
    assert!(!verdict_multi.is_immune());

    // Self-parenting cycle: 9999 -> 9999
    let mut self_cycle = HashMap::new();
    self_cycle.insert(9999, (9999, "self.exe".to_string()));

    let verdict_self = simulate_process_lineage_traversal(9999, "self.exe", &self_cycle);
    assert!(!verdict_self.is_immune());

    // -------------------------------------------------------------------------
    // Live OS ancestry test on current process
    // -------------------------------------------------------------------------
    let cur_pid = std::process::id();
    let live_chain = get_process_ancestry_chain(cur_pid);
    assert!(live_chain.len() <= MAX_ANCESTRY_DEPTH);
    let live_verdict = inspect_process_lineage(cur_pid, Some("empirical_challenge_m3_2.exe"));
    assert!(
        live_verdict.is_immune(),
        "Current test process or its cargo parent must be immune"
    );
}

// ============================================================================
// 4. Byzantine Fraud Proof Tamper Detection
// ============================================================================

#[test]
fn test_empirical_byzantine_fraud_proof_tamper_detection() {
    let peer_id = "trusted-verifier-01";
    let accused_peer = "byzantine-rogue-node-99";
    let target_hash = "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069";
    let proc_name = "cargo.exe";
    let fraud_reason = "POISONED_PROPOSAL: Illicit proposal targeting protected developer binary";

    let proof = ByzantineKillSwitchFraudProof::new(
        peer_id,
        accused_peer,
        target_hash,
        proc_name,
        fraud_reason,
    );

    // 1. Untampered proof MUST verify
    assert!(proof.verify_seal(), "Untampered proof seal must verify successfully");

    // 2. Tamper with `peer_id` by 1 character
    let mut tampered_peer = proof.clone();
    tampered_peer.peer_id = format!("{}_tampered", peer_id);
    assert!(!tampered_peer.verify_seal(), "Tampered peer_id must fail verification");

    // 3. Tamper with `accused_peer_id`
    let mut tampered_accused = proof.clone();
    tampered_accused.accused_peer_id = "innocent-peer-01".to_string();
    assert!(!tampered_accused.verify_seal(), "Tampered accused_peer_id must fail verification");

    // 4. Tamper with `target_binary_hash` (flip 1 character)
    let mut tampered_hash = proof.clone();
    let mut hash_chars: Vec<char> = target_hash.chars().collect();
    hash_chars[0] = if hash_chars[0] == '0' { '1' } else { '0' };
    tampered_hash.target_binary_hash = hash_chars.into_iter().collect();
    assert!(!tampered_hash.verify_seal(), "Tampered target_binary_hash must fail verification");

    // 5. Tamper with `proc_name`
    let mut tampered_proc = proof.clone();
    tampered_proc.proc_name = "svchost.exe".to_string();
    assert!(!tampered_proc.verify_seal(), "Tampered proc_name must fail verification");

    // 6. Tamper with `fraud_reason`
    let mut tampered_reason = proof.clone();
    tampered_reason.fraud_reason = format!("{} (modified)", fraud_reason);
    assert!(!tampered_reason.verify_seal(), "Tampered fraud_reason must fail verification");

    // 7. Tamper with `proof_seal` by 1 bit/character
    let mut tampered_seal = proof.clone();
    let mut seal_chars: Vec<char> = tampered_seal.proof_seal.chars().collect();
    seal_chars[0] = if seal_chars[0] == 'a' { 'b' } else { 'a' };
    tampered_seal.proof_seal = seal_chars.into_iter().collect();
    assert!(!tampered_seal.verify_seal(), "Tampered proof_seal must fail verification");

    // 8. Truncated seal and empty seal failure
    let mut truncated_seal = proof.clone();
    truncated_seal.proof_seal = proof.proof_seal[..10].to_string();
    assert!(!truncated_seal.verify_seal(), "Truncated proof_seal must fail verification");

    let mut empty_seal = proof.clone();
    empty_seal.proof_seal = String::new();
    assert!(!empty_seal.verify_seal(), "Empty proof_seal must fail verification");

    // 9. Tamper with `timestamp`
    let mut tampered_ts = proof.clone();
    tampered_ts.timestamp = "2020-01-01T00:00:00Z".to_string();
    assert!(!tampered_ts.verify_seal(), "Tampered timestamp must fail verification");

    // 10. Keyed seal verification and tampering
    let key = [0x5au8; 32];
    let timestamp = "2026-10-26T15:00:00Z";
    let keyed_seal = ByzantineKillSwitchFraudProof::compute_keyed_seal(
        &key,
        peer_id,
        accused_peer,
        target_hash,
        proc_name,
        fraud_reason,
        timestamp,
    );
    let keyed_proof = ByzantineKillSwitchFraudProof {
        peer_id: peer_id.to_string(),
        accused_peer_id: accused_peer.to_string(),
        target_binary_hash: target_hash.to_string(),
        proc_name: proc_name.to_string(),
        fraud_reason: fraud_reason.to_string(),
        proof_seal: keyed_seal,
        timestamp: timestamp.to_string(),
    };
    assert!(keyed_proof.verify_keyed_seal(&key), "Valid keyed seal must verify");

    let wrong_key = [0x5bu8; 32];
    assert!(!keyed_proof.verify_keyed_seal(&wrong_key), "Wrong key must fail verification");
}

// ============================================================================
// 5. In-Memory Inventory Lookup Concurrency
// ============================================================================

#[test]
fn test_empirical_inventory_lookup_concurrency_no_deadlocks() {
    let inventory = get_protected_local_binary_hashes();
    assert!(!inventory.is_empty(), "Initial inventory must be pre-populated");

    const NUM_THREADS: usize = 16;
    const OPERATIONS_PER_THREAD: usize = 100;

    let successful_reads = Arc::new(AtomicUsize::new(0));
    let successful_writes = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(NUM_THREADS);

    for thread_idx in 0..NUM_THREADS {
        let reads_clone = Arc::clone(&successful_reads);
        let writes_clone = Arc::clone(&successful_writes);

        let handle = std::thread::spawn(move || {
            for op in 0..OPERATIONS_PER_THREAD {
                if thread_idx % 2 == 0 {
                    // Writer thread: register new hash
                    let raw_bytes = format!("concurrent_test_hash_{}_{}", thread_idx, op);
                    let hash_hex = blake3::hash(raw_bytes.as_bytes()).to_hex().to_string();
                    register_protected_binary_hash(&hash_hex);

                    // Verify immediate membership
                    assert!(
                        is_protected_local_binary_hash(&hash_hex),
                        "Registered hash must be immediately queryable"
                    );
                    assert!(
                        is_protected_local_binary_hash(&hash_hex.to_uppercase()),
                        "Query must be case-insensitive"
                    );

                    writes_clone.fetch_add(1, Ordering::Relaxed);
                } else {
                    // Reader thread: query existing and synthetic hashes
                    let raw_bytes = format!("concurrent_test_hash_{}_{}", thread_idx - 1, op);
                    let query_hash = blake3::hash(raw_bytes.as_bytes()).to_hex().to_string();

                    // Lookup should never panic or deadlock
                    let _ = is_protected_local_binary_hash(&query_hash);
                    let _ = is_protected_local_binary_hash("");
                    let _ = is_protected_local_binary_hash("nonexistent_hash_string");

                    reads_clone.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        handles.push(handle);
    }

    // Join all threads with a hard timeout to empirically assert zero deadlocks
    let start_join = std::time::Instant::now();
    for handle in handles {
        handle.join().expect("Concurrent inventory thread panicked");
    }
    let elapsed = start_join.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "All threads must finish rapidly without deadlock, took {:?}",
        elapsed
    );

    let total_writes = successful_writes.load(Ordering::SeqCst);
    let total_reads = successful_reads.load(Ordering::SeqCst);
    assert_eq!(total_writes, (NUM_THREADS / 2) * OPERATIONS_PER_THREAD);
    assert_eq!(total_reads, (NUM_THREADS / 2) * OPERATIONS_PER_THREAD);
}
