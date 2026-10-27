//! Integration tests for Causal DAG and MITRE ATT&CK Correlator (Feature 17)

use killswitch_telemetry::attack::{AttackGraphMatcher, AttackStage, ProcessTimelineEvent};
use killswitch_telemetry::causal::CausalSecurityGraph;
use killswitch_telemetry::correlator::EventCorrelator;
use killswitch_types::identity::ProcessInstanceIdentity;
use killswitch_types::telemetry::{SecurityEvent, TelemetryEventKind, ThreatSeverity};

#[test]
fn test_t1_f17_01_causal_node_and_edge_provenance() {
    let graph = CausalSecurityGraph::new();

    let parent = ProcessInstanceIdentity::new(1000, 500000, "parent_image_hash", None, None, "Session-1");
    let child = ProcessInstanceIdentity::new(
        2000,
        600000,
        "child_image_hash",
        Some(parent.instance_id.clone()),
        None,
        "Session-1",
    );

    graph.record_process_spawn(None, &parent, "explorer.exe");
    graph.record_process_spawn(Some(&parent.instance_id), &child, "cmd.exe");

    let ancestry = graph.get_lineage_ancestry(&child.instance_id, 3);
    assert_eq!(ancestry.len(), 1);
    assert_eq!(ancestry[0].instance_id, parent.instance_id);

    // Record file write and network connect
    graph.record_file_interaction(&child.instance_id, "C:\\Temp\\script.bat", "hash_script", true);
    graph.record_network_connect(&child.instance_id, "203.0.113.5", 443);

    let taint = graph.get_transitive_taint_forward(&child.instance_id);
    assert!(taint.contains(&child.instance_id));
    assert!(taint.iter().any(|t| t.contains("script.bat")));
    assert!(taint.iter().any(|t| t.contains("203.0.113.5")));
}

#[test]
fn test_t1_f17_02_mitre_killchain_sequence_evaluation() {
    let matcher = AttackGraphMatcher::new();

    let timeline = vec![
        ProcessTimelineEvent {
            timestamp: chrono::Utc::now(),
            stage: AttackStage::DefenseEvasion,
            event_kind: TelemetryEventKind::ProcessAccess,
            details: "Tampered process access".to_string(),
            raw_score: 0.5,
        },
        ProcessTimelineEvent {
            timestamp: chrono::Utc::now(),
            stage: AttackStage::Discovery,
            event_kind: TelemetryEventKind::ProcessCreate,
            details: "Volume discovery".to_string(),
            raw_score: 0.4,
        },
        ProcessTimelineEvent {
            timestamp: chrono::Utc::now(),
            stage: AttackStage::Impact,
            event_kind: TelemetryEventKind::FileCreate,
            details: "Mass file overwrite".to_string(),
            raw_score: 0.8,
        },
    ];

    let eval = matcher.evaluate_sequence(&timeline);
    assert_eq!(eval.stages_count, 3);
    assert!(eval.has_killchain_progression);
    assert!(eval.multi_stage_multiplier >= 1.7);
    assert!(eval.matched_patterns.contains(&"Ransomware Destruction Sequence".to_string()));
}

#[test]
fn test_t1_f17_03_time_decay_event_correlator() {
    let correlator = EventCorrelator::new(300.0, 0.70);

    let ev1 = SecurityEvent::new(
        TelemetryEventKind::ProcessAccess,
        8080,
        "mimikatz.exe",
        "C:\\Temp\\mimikatz.exe",
        "sekurlsa::logonpasswords",
    );
    let ev2 = SecurityEvent::new(
        TelemetryEventKind::CreateRemoteThread,
        8080,
        "mimikatz.exe",
        "C:\\Temp\\mimikatz.exe",
        "CreateRemoteThread -> LSASS",
    );

    // First event (CredentialAccess)
    let sig1 = correlator.ingest_event(&ev1, AttackStage::CredentialAccess, 0.40);
    assert!(sig1.is_none());

    // Second event (LateralMovement)
    let sig2 = correlator.ingest_event(&ev2, AttackStage::LateralMovement, 0.45);
    assert!(sig2.is_some());
    let sig = sig2.unwrap();
    assert_eq!(sig.target_pid, 8080);
    assert_eq!(sig.severity, ThreatSeverity::Critical);
}
