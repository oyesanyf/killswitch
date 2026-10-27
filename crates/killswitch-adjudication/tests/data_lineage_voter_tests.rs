use killswitch_adjudication::voters::{
    AdjudicationContext, DataLineageVoter, DlpClassification, DlpPolicy, EgressVerdict,
    LineageAdjudicationEvidence, LineageCausalLink, OpenLineageDataset, OpenLineageDatasetFacets,
    TaintBaggage, ThreatVoter,
};
use killswitch_types::adjudication::{EvidenceClass, ThreatCandidate, VoteAction};

#[tokio::test]
async fn test_multi_hop_dlp_exfiltration_fan_in_scenario() {
    // -------------------------------------------------------------------------
    // Exact scenario from ORIGINAL_REQUEST.md Follow-up #2 and #3:
    // 1. Seed `secret_roadmap.docx` (CrownJewel, Quarantine, SHA-256 "aaa111...")
    //    and `q4_financials.xlsx` (Confidential, Audit, SHA-256 "bbb222...")
    // 2. `powershell.exe` (PID 2104) spawns `7z.exe` (PID 4812)
    // 3. `7z.exe` reads both files: TaintBaggage::merge escalates to CrownJewel + Quarantine
    //    and concatenates distinct hashes: "aaa111...,bbb222...". Writes `staging_upload.zip`.
    // 4. `curl.exe` (PID 5001) reads `staging_upload.zip` and attempts egress to
    //    `https://external-drop.example.com/upload`.
    // 5. evaluate_egress returns EgressVerdict::Block { reason, trace_id: "w3c-trace-999" }.
    // 6. Verify DataLineageVoter casts an Isolate vote with confidence 0.96 and weight 1.85!
    // -------------------------------------------------------------------------

    let voter = DataLineageVoter::new();

    let mut baggage_doc = TaintBaggage::new(
        DlpClassification::CrownJewel,
        DlpPolicy::Quarantine,
        "aaa1111111111111111111111111111111111111111111111111111111111111",
    );
    let baggage_xls = TaintBaggage::new(
        DlpClassification::Confidential,
        DlpPolicy::Audit,
        "bbb2222222222222222222222222222222222222222222222222222222222222",
    );

    // Merge taints as 7z.exe reads both
    baggage_doc.merge(&baggage_xls);
    assert_eq!(baggage_doc.classification, DlpClassification::CrownJewel);
    assert_eq!(baggage_doc.policy, DlpPolicy::Quarantine);
    assert!(baggage_doc.source_sha256.contains("aaa111"));
    assert!(baggage_doc.source_sha256.contains("bbb222"));

    let input_datasets = vec![
        OpenLineageDataset {
            namespace: "file://endpoint-local".to_string(),
            name: "C:\\Users\\Alice\\Documents\\secret_roadmap.docx".to_string(),
            facets: OpenLineageDatasetFacets {
                content_sha256: "aaa1111111111111111111111111111111111111111111111111111111111111".to_string(),
                dlp_classification: DlpClassification::CrownJewel,
            },
        },
        OpenLineageDataset {
            namespace: "file://endpoint-local".to_string(),
            name: "C:\\Users\\Alice\\Documents\\q4_financials.xlsx".to_string(),
            facets: OpenLineageDatasetFacets {
                content_sha256: "bbb2222222222222222222222222222222222222222222222222222222222222".to_string(),
                dlp_classification: DlpClassification::Confidential,
            },
        },
    ];

    let causal_links = vec![
        LineageCausalLink {
            trace_id: "w3c-trace-999".to_string(),
            span_id: "span-101".to_string(),
            role: "INPUT".to_string(),
            file_path: "C:\\Users\\Alice\\Documents\\secret_roadmap.docx".to_string(),
        },
        LineageCausalLink {
            trace_id: "w3c-trace-999".to_string(),
            span_id: "span-102".to_string(),
            role: "INPUT".to_string(),
            file_path: "C:\\Users\\Alice\\Documents\\q4_financials.xlsx".to_string(),
        },
    ];

    let evidence = LineageAdjudicationEvidence {
        actor_pid: 5001,
        actor_exe: "curl.exe".to_string(),
        parent_pid: Some(4812), // Parent 7z.exe
        destination: "https://external-drop.example.com/upload".to_string(),
        egress_verdict: EgressVerdict::Block {
            reason: "DLP Egress Blocked: QUARANTINE policy active on trace".to_string(),
            trace_id: "w3c-trace-999".to_string(),
        },
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
        "Egress blocked to https://external-drop.example.com/upload",
        0.95,
        EvidenceClass::LiveNetwork,
    );

    let vote = voter.vote(&candidate, Some(&context)).await;
    assert!(vote.is_some());
    let v = vote.unwrap();
    assert_eq!(v.action, VoteAction::Isolate);
    assert_eq!(v.confidence, 0.96);
    assert_eq!(v.weight, 1.85);
    assert_eq!(v.evidence_class, EvidenceClass::LiveNetwork);
    assert!(v.explanation.contains("w3c-trace-999"));
    assert!(v.explanation.contains("aaa111"));
    assert!(v.explanation.contains("bbb222"));
    assert!(v.explanation.contains("curl.exe"));
}

#[tokio::test]
async fn test_uncompromised_admin_powershell_veto() {
    // Legitimate admin powershell.exe without quarantined taint baggage receives benign veto
    let voter = DataLineageVoter::new();

    let evidence = LineageAdjudicationEvidence {
        actor_pid: 2104,
        actor_exe: "powershell.exe".to_string(),
        parent_pid: Some(1000),
        destination: "127.0.0.1:3030".to_string(),
        egress_verdict: EgressVerdict::Allow,
        baggage: None,
        causal_links: vec![],
        input_datasets: vec![],
        provenance_hops: vec![],
    };

    let context = AdjudicationContext {
        lineage_evidence: Some(evidence),
        ..Default::default()
    };

    let candidate = ThreatCandidate::new(
        Some(2104),
        "powershell.exe",
        "CLIWatcher",
        "Get-Service admin command",
        0.15,
        EvidenceClass::Behavior,
    );

    let vote = voter.vote(&candidate, Some(&context)).await;
    assert!(vote.is_some());
    let v = vote.unwrap();
    assert!(v.is_veto());
    assert_eq!(v.action, VoteAction::Monitor);
    assert!(v.weight < 0.0);
    assert!(v.explanation.contains("attested clean by DataLineageVoter"));
}

#[tokio::test]
async fn test_compromised_admin_powershell_exfiltration_preserves_shell() {
    // When powershell.exe itself attempts egress of CrownJewel data,
    // DataLineageVoter emits an Isolate vote but explicitly notes
    // that the shell PID must not be frozen/bricked, recommending network isolation.
    let voter = DataLineageVoter::new();

    let baggage = TaintBaggage::new(
        DlpClassification::CrownJewel,
        DlpPolicy::Quarantine,
        "crown_jewel_hash_123",
    );

    let evidence = LineageAdjudicationEvidence {
        actor_pid: 2104,
        actor_exe: "powershell.exe".to_string(),
        parent_pid: Some(1000),
        destination: "https://evil-exfil.org/leak".to_string(),
        egress_verdict: EgressVerdict::Block {
            reason: "Quarantine active".to_string(),
            trace_id: "trace-shell-leak".to_string(),
        },
        baggage: Some(baggage),
        causal_links: vec![],
        input_datasets: vec![],
        provenance_hops: vec!["powershell.exe:2104".to_string()],
    };

    let context = AdjudicationContext {
        lineage_evidence: Some(evidence),
        ..Default::default()
    };

    let candidate = ThreatCandidate::new(
        Some(2104),
        "powershell.exe",
        "EndpointLineageEngine",
        "CrownJewel egress attempt",
        0.95,
        EvidenceClass::LiveNetwork,
    );

    let vote = voter.vote(&candidate, Some(&context)).await;
    assert!(vote.is_some());
    let v = vote.unwrap();
    assert_eq!(v.action, VoteAction::Isolate);
    assert_eq!(v.confidence, 0.96);
    assert!(v.explanation.contains("Preserving PID from freeze termination; network isolation recommended"));
}

#[tokio::test]
async fn test_multihop_staging_alert_without_egress() {
    // 7z.exe aggregating multiple secret files into a zip file without network egress
    let voter = DataLineageVoter::new();

    let baggage = TaintBaggage::new(
        DlpClassification::CrownJewel,
        DlpPolicy::Quarantine,
        "hash_a,hash_b",
    );

    let datasets = vec![
        OpenLineageDataset {
            namespace: "file://local".to_string(),
            name: "file1.docx".to_string(),
            facets: OpenLineageDatasetFacets {
                content_sha256: "hash_a".to_string(),
                dlp_classification: DlpClassification::CrownJewel,
            },
        },
        OpenLineageDataset {
            namespace: "file://local".to_string(),
            name: "file2.xlsx".to_string(),
            facets: OpenLineageDatasetFacets {
                content_sha256: "hash_b".to_string(),
                dlp_classification: DlpClassification::Confidential,
            },
        },
    ];

    let evidence = LineageAdjudicationEvidence {
        actor_pid: 4812,
        actor_exe: "7z.exe".to_string(),
        parent_pid: Some(2104),
        destination: "local".to_string(),
        egress_verdict: EgressVerdict::Allow,
        baggage: Some(baggage),
        causal_links: vec![],
        input_datasets: datasets,
        provenance_hops: vec![],
    };

    let context = AdjudicationContext {
        lineage_evidence: Some(evidence),
        ..Default::default()
    };

    let candidate = ThreatCandidate::new(
        Some(4812),
        "7z.exe",
        "FileWatcher",
        "Packing multiple sensitive files",
        0.80,
        EvidenceClass::Behavior,
    );

    let vote = voter.vote(&candidate, Some(&context)).await;
    assert!(vote.is_some());
    let v = vote.unwrap();
    assert_eq!(v.action, VoteAction::Alert);
    assert_eq!(v.confidence, 0.92);
    assert_eq!(v.evidence_class, EvidenceClass::Behavior);
    assert!(v.explanation.contains("DLP Multi-Source Staging"));
}
