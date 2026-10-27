use std::sync::Arc;
use killswitch_adjudication::consensus::MultiVoterConsensusEngine;
use killswitch_adjudication::voters::{
    BehaviorVoter, LiveNetworkVoter, MemoryVoter, StaticArtifactVoter, ThreatIntelVoter,
};
use killswitch_types::adjudication::{
    calculate_consensus, corroboration_multiplier, EvidenceClass, ThreatCandidate, VoteAction,
    VoteResult,
};

#[test]
fn test_single_voter_penalty_invariant() {
    // Mathematical invariant: Multiplier for 1 class is strictly 0.52.
    // Even if confidence is 1.0, 1.0 * 0.52 = 0.52 < 0.94.
    // Autonomous isolation must NEVER fire on an uncorroborated single voter.
    assert_eq!(corroboration_multiplier(0), 0.0);
    assert_eq!(corroboration_multiplier(1), 0.52);

    let vote = VoteResult::new(
        Some(1234),
        VoteAction::Isolate,
        1.0,
        EvidenceClass::LiveNetwork,
        "Single network beacon",
        "NetworkDetector",
    );

    let (score, count) = calculate_consensus(&[vote]);
    assert_eq!(count, 1);
    assert!((score - 0.52).abs() < 1e-4);
    assert!(score < 0.94);

    let engine = MultiVoterConsensusEngine::new();
    let candidate = ThreatCandidate::new(
        Some(1234),
        "dropper.exe",
        "NetworkDetector",
        "Single network beacon",
        1.0,
        EvidenceClass::LiveNetwork,
    );

    let votes = vec![VoteResult::new(
        Some(1234),
        VoteAction::Isolate,
        1.0,
        EvidenceClass::LiveNetwork,
        "Single network beacon",
        "NetworkDetector",
    )];

    let result = engine.orchestrate_evidence(&votes, &candidate);
    assert!(!result.is_confirmed());
    assert!(!result.is_awaiting_confirmation());
    assert!(result.confidence() < 0.55);
}

#[test]
fn test_two_class_corroboration_ceiling() {
    // Invariant: Two independent evidence classes receive multiplier 0.82.
    // Score ~0.82 reaches AwaitingManualConfirmation (>= 0.82) but CANNOT autonomously isolate (< 0.94).
    assert_eq!(corroboration_multiplier(2), 0.82);

    let votes = vec![
        VoteResult::new(
            Some(2233),
            VoteAction::Isolate,
            1.0,
            EvidenceClass::LiveNetwork,
            "C2 beacon",
            "NetworkVoter",
        ),
        VoteResult::new(
            Some(2233),
            VoteAction::Isolate,
            1.0,
            EvidenceClass::Behavior,
            "Process spawn anomaly",
            "BehaviorVoter",
        ),
    ];

    let (score, count) = calculate_consensus(&votes);
    assert_eq!(count, 2);
    assert!((score - 0.82).abs() < 1e-4);
    assert!(score < 0.94);

    let engine = MultiVoterConsensusEngine::new();
    let candidate = ThreatCandidate::new(
        Some(2233),
        "suspicious.exe",
        "Correlator",
        "Network + Behavior",
        1.0,
        EvidenceClass::Behavior,
    );

    let result = engine.orchestrate_evidence(&votes, &candidate);
    assert!(result.is_awaiting_confirmation());
    assert!(!result.is_confirmed());
    assert_eq!(result.confidence(), 0.82);
}

#[test]
fn test_three_classes_confirmed_autonomous_isolation() {
    // Invariant: >= 3 independent evidence classes receive multiplier 1.00.
    // If consensus score >= 0.94, ConfirmedThreat with Isolate is emitted.
    assert_eq!(corroboration_multiplier(3), 1.00);
    assert_eq!(corroboration_multiplier(4), 1.00);

    let votes = vec![
        VoteResult::new(
            Some(3344),
            VoteAction::Isolate,
            0.98,
            EvidenceClass::LiveNetwork,
            "C2 traffic",
            "NetworkVoter",
        ),
        VoteResult::new(
            Some(3344),
            VoteAction::Isolate,
            0.96,
            EvidenceClass::Behavior,
            "Ransomware encryption burst",
            "BehaviorVoter",
        ),
        VoteResult::new(
            Some(3344),
            VoteAction::Isolate,
            0.95,
            EvidenceClass::Memory,
            "Reflective DLL injection",
            "MemoryVoter",
        ),
    ];

    let (score, count) = calculate_consensus(&votes);
    assert_eq!(count, 3);
    assert!(score >= 0.94);

    let engine = MultiVoterConsensusEngine::new();
    let candidate = ThreatCandidate::new(
        Some(3344),
        "lockbit.exe",
        "Correlator",
        "Multi-stage ransomware",
        0.98,
        EvidenceClass::Behavior,
    );

    let result = engine.orchestrate_evidence(&votes, &candidate);
    assert!(result.is_confirmed());
    assert!(result.confidence() >= 0.94);
    match result {
        killswitch_types::adjudication::AdjudicationResult::ConfirmedThreat {
            recommended_action,
            independent_classes,
            ..
        } => {
            assert_eq!(recommended_action, VoteAction::Isolate);
            assert_eq!(independent_classes, 3);
        }
        _ => panic!("Expected ConfirmedThreat result"),
    }
}

#[test]
fn test_strict_veto_propagation_overrides_consensus() {
    // Invariant: A single voter casting a veto (weight < 0.0) MUST immediately
    // zero out consensus and emit AdjudicationResult::Vetoed, even if all other voters voted Isolate 1.0.
    let votes = vec![
        VoteResult::new(
            Some(4455),
            VoteAction::Isolate,
            1.0,
            EvidenceClass::LiveNetwork,
            "High network traffic",
            "LiveNetworkVoter",
        ),
        VoteResult::new(
            Some(4455),
            VoteAction::Isolate,
            1.0,
            EvidenceClass::Behavior,
            "High file I/O",
            "BehaviorVoter",
        ),
        VoteResult::new(
            Some(4455),
            VoteAction::Isolate,
            1.0,
            EvidenceClass::Memory,
            "Memory consumption",
            "MemoryVoter",
        ),
        VoteResult::new_veto(
            Some(4455),
            "Critical system binary or dev toolchain verified",
            "WhiteListVoter",
            EvidenceClass::StaticArtifact,
        ),
    ];

    let (score, count) = calculate_consensus(&votes);
    assert_eq!(score, 0.0);
    assert_eq!(count, 0);

    let engine = MultiVoterConsensusEngine::new();
    let candidate = ThreatCandidate::new(
        Some(4455),
        "cargo.exe",
        "AnomalousHeuristic",
        "Build compilation activity",
        0.99,
        EvidenceClass::Behavior,
    );

    let result = engine.orchestrate_evidence(&votes, &candidate);
    assert!(result.is_vetoed());
    assert_eq!(result.confidence(), 0.0);
}

#[test]
fn test_threat_intel_only_score_suppression() {
    // Invariant: ThreatIntel-only evidence cannot exceed 0.49.
    let engine = MultiVoterConsensusEngine::new();
    let candidate = ThreatCandidate::new(
        Some(5566),
        "sample.exe",
        "ThreatIntelFeed",
        "IoC hash match",
        0.95,
        EvidenceClass::ThreatIntel,
    );

    let votes = vec![
        VoteResult::new(
            Some(5566),
            VoteAction::Alert,
            0.95,
            EvidenceClass::ThreatIntel,
            "IoC feed match 1",
            "ThreatIntelVoter1",
        ),
        VoteResult::new(
            Some(5566),
            VoteAction::Alert,
            0.99,
            EvidenceClass::ThreatIntel,
            "IoC feed match 2",
            "ThreatIntelVoter2",
        ),
    ];

    let result = engine.orchestrate_evidence(&votes, &candidate);
    assert!(!result.is_confirmed());
    assert!(!result.is_awaiting_confirmation());
    assert!(result.confidence() <= 0.49);
}

#[test]
fn test_static_artifact_uncorroborated_capping() {
    // Invariant: Pure StaticArtifact evidence uncorroborated by runtime signals capped at <= 0.68.
    let engine = MultiVoterConsensusEngine::new();
    let candidate = ThreatCandidate::new(
        Some(6677),
        "packer.exe",
        "StaticScanner",
        "YARA rule match",
        0.95,
        EvidenceClass::StaticArtifact,
    );

    let votes = vec![VoteResult::new(
        Some(6677),
        VoteAction::Alert,
        0.95,
        EvidenceClass::StaticArtifact,
        "YARA rule match",
        "StaticArtifactVoter",
    )];

    let result = engine.orchestrate_evidence(&votes, &candidate);
    assert!(!result.is_confirmed());
    assert!(result.confidence() <= 0.68);
}

#[tokio::test]
async fn test_concurrent_multi_voter_collection_resilience() {
    let engine = MultiVoterConsensusEngine::new();
    engine.register_voter(Arc::new(LiveNetworkVoter::new()));
    engine.register_voter(Arc::new(BehaviorVoter::new()));
    engine.register_voter(Arc::new(MemoryVoter::new()));
    engine.register_voter(Arc::new(StaticArtifactVoter::new()));
    engine.register_voter(Arc::new(ThreatIntelVoter::new()));

    let candidate = ThreatCandidate::new(
        Some(7788),
        "malicious_tool.exe",
        "EDRCorrelator",
        "Beaconing network activity with comsvcs minidump",
        0.90,
        EvidenceClass::Behavior,
    );

    let votes = engine.collect_votes(&candidate, None).await;
    assert!(!votes.is_empty());

    let result = engine.orchestrate_evidence(&votes, &candidate);
    assert!(result.confidence() > 0.0);
}

#[tokio::test]
async fn test_empty_votes_returns_monitor_only() {
    let engine = MultiVoterConsensusEngine::new();
    let candidate = ThreatCandidate::new(
        Some(8899),
        "clean.exe",
        "EmptySource",
        "Nothing suspicious",
        0.1,
        EvidenceClass::Behavior,
    );

    let result = engine.orchestrate_evidence(&[], &candidate);
    assert_eq!(result.confidence(), 0.0);
    match result {
        killswitch_types::adjudication::AdjudicationResult::MonitorOnly { explanation, .. } => {
            assert!(explanation.contains("No security voter returned an actionable verdict"));
        }
        _ => panic!("Expected MonitorOnly"),
    }
}
