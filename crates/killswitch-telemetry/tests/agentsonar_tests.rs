//! Comprehensive integration tests for Dynamic AgentSonar (`agentsonar.rs`),
//! SQLite WAL persistence, hot-reloading JSON config, pure-Rust RFC 8446 TLS SNI /
//! RFC 1035 DNS QNAME parsing, AST-guarded external classifiers, RL/Correlator
//! enrichment, and native `SiqueryEngine` relational SQL joins.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use killswitch_telemetry::agentsonar::{
    domain_matches_pattern, extract_dns_qname, extract_tls_sni, generate_osquery_atc_schema,
    glob_match_case_insensitive, global_agentsonar_engine, parse_tcp_packet, resolve_safe_db_path,
    run_external_classifier, AgentSonarEngine, DynamicRuleSet, HeuristicWeightsPatch,
    ProcSocketResolver, TriageDecision,
};
use killswitch_telemetry::attack::AttackStage;
use killswitch_telemetry::correlator::EventCorrelator;
use killswitch_telemetry::rl_traffic::RlTrafficLearner;
use killswitch_telemetry::siquery::SiqueryEngine;
use killswitch_types::telemetry::{SecurityEvent, TelemetryEventKind};

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), nanos));
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Builds a genuine RFC 8446 / RFC 5246 TLS 1.2/1.3 `ClientHello` record containing
/// a Server Name Indication (`0x0000`) extension for `hostname`.
fn build_real_tls_client_hello(hostname: &str) -> Vec<u8> {
    let host_bytes = hostname.as_bytes();
    // ServerName: NameType=0x00 (host_name), HostName length (u16), HostName bytes
    let mut server_name_entry = vec![0x00];
    server_name_entry.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    server_name_entry.extend_from_slice(host_bytes);

    // ServerNameList: list length (u16) + entries
    let mut sni_ext_data = Vec::new();
    sni_ext_data.extend_from_slice(&(server_name_entry.len() as u16).to_be_bytes());
    sni_ext_data.extend_from_slice(&server_name_entry);

    // Extension: type 0x0000 (server_name) + length (u16) + data
    let mut extensions = Vec::new();
    // Prepend a non-SNI dummy extension (0x000a supported_groups) to exercise extension walking
    extensions.extend_from_slice(&0x000au16.to_be_bytes());
    extensions.extend_from_slice(&4u16.to_be_bytes());
    extensions.extend_from_slice(&[0x00, 0x02, 0x00, 0x1d]);
    // SNI extension (0x0000)
    extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_ext_data.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext_data);

    // ClientHello body:
    // Version (0x0303) + Random (32B) + SessionID (1B len=0) + CipherSuites (2B len=2, 0x1301)
    // + CompressionMethods (1B len=1, 0x00) + ExtensionsLen (2B) + Extensions
    let mut ch_body = Vec::new();
    ch_body.extend_from_slice(&[0x03, 0x03]);
    ch_body.extend_from_slice(&[0xAB; 32]);
    ch_body.push(0x00); // session_id_len = 0
    ch_body.extend_from_slice(&2u16.to_be_bytes());
    ch_body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    ch_body.push(0x01); // comp_methods_len = 1
    ch_body.push(0x00); // null compression
    ch_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    ch_body.extend_from_slice(&extensions);

    // Handshake message: HandshakeType=0x01 (ClientHello) + u24 length + body
    let ch_len = ch_body.len();
    let mut handshake = vec![
        0x01,
        ((ch_len >> 16) & 0xFF) as u8,
        ((ch_len >> 8) & 0xFF) as u8,
        (ch_len & 0xFF) as u8,
    ];
    handshake.extend_from_slice(&ch_body);

    // TLS Plaintext Record: ContentType=0x16 (Handshake) + LegacyVersion=0x0301 + u16 length + handshake
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Wraps a TCP payload in a raw IPv4 + TCP header.
fn wrap_ipv4_tcp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = (20 + 20 + payload.len()) as u16;
    let mut pkt = Vec::with_capacity(total_len as usize);
    // IPv4 header (20 bytes, IHL=5, proto=6 TCP)
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 64, 6, 0x00, 0x00]);
    pkt.extend_from_slice(&src_ip);
    pkt.extend_from_slice(&dst_ip);
    // TCP header (20 bytes, data offset = 5 words -> 0x50)
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&1u32.to_be_bytes());
    pkt.extend_from_slice(&1u32.to_be_bytes());
    pkt.push(0x50);
    pkt.push(0x18); // PSH+ACK
    pkt.extend_from_slice(&65535u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(payload);
    pkt
}

#[test]
fn test_tls_client_hello_sni_and_dns_qname_extraction() {
    let ch_anthropic = build_real_tls_client_hello("api.anthropic.com");
    assert_eq!(
        extract_tls_sni(&ch_anthropic).as_deref(),
        Some("api.anthropic.com")
    );

    let ch_openai = build_real_tls_client_hello("api.openai.com");
    assert_eq!(
        extract_tls_sni(&ch_openai).as_deref(),
        Some("api.openai.com")
    );

    // Truncated / malformed TLS payloads must safely return None without panicking
    assert_eq!(extract_tls_sni(&[]), None);
    assert_eq!(extract_tls_sni(&ch_anthropic[..12]), None);
    assert_eq!(
        extract_tls_sni(&[0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5]),
        None
    );

    // IPv4 + TCP framing + TLS SNI end-to-end parse
    let raw_pkt = wrap_ipv4_tcp_packet(
        [127, 0, 0, 1],
        [198, 51, 100, 42],
        54321,
        443,
        &ch_anthropic,
    );
    let seg = parse_tcp_packet(&raw_pkt, false).expect("valid IPv4/TCP packet");
    assert_eq!(seg.src_port, 54321);
    assert_eq!(seg.dst_port, 443);
    assert_eq!(
        extract_tls_sni(seg.payload).as_deref(),
        Some("api.anthropic.com")
    );

    // RFC 1035 DNS QNAME query for api.cursor.sh
    let mut dns_query = vec![
        0x12, 0x34, // ID
        0x01, 0x00, // Standard query, RD=1
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    dns_query.extend_from_slice(&[
        3, b'a', b'p', b'i', 6, b'c', b'u', b'r', b's', b'o', b'r', 2, b's', b'h', 0,
    ]);
    dns_query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE A, QCLASS IN
    assert_eq!(
        extract_dns_qname(&dns_query).as_deref(),
        Some("api.cursor.sh")
    );
}

#[test]
fn test_glob_and_domain_matching_prevent_false_positives() {
    assert!(glob_match_case_insensitive("claude*", "claude-code.exe"));
    assert!(!glob_match_case_insensitive(
        "claude*",
        "my_claude_notes.txt"
    ));
    assert!(domain_matches_pattern(
        "api.anthropic.com",
        "*.anthropic.com"
    ));
    assert!(domain_matches_pattern("anthropic.com", "*.anthropic.com"));
    assert!(!domain_matches_pattern(
        "evil-anthropic.com",
        "*.anthropic.com"
    ));
}

#[test]
fn test_sqlite_wal_crud_triage_and_hot_reload() {
    let dir = unique_temp_dir("agentsonar_wal");
    let db_path = dir.join("agentsonar.db");
    let cfg_path = dir.join("agentsonar.json");

    // Reject path traversal
    assert!(resolve_safe_db_path("../escape/agentsonar.db").is_err());

    let engine = AgentSonarEngine::new(db_path.clone(), Some(cfg_path.clone())).unwrap();
    let initial_rules = engine.load_rules().unwrap();
    assert!(initial_rules.agents.len() >= 6);

    // 1. Dynamic rule CRUD
    engine
        .add_agent_rule("shadow-wrapper", "stealth_runner*", "*.groq.com")
        .unwrap();
    engine.add_noise_domain("telemetry.internal.corp").unwrap();
    engine.add_browser_proc("arc_browser").unwrap();

    // Known agent rule yields ai_score = 1.0
    let known_ev = engine
        .record_flow(
            4242,
            "stealth_runner.exe",
            "stealth_runner.exe --daemon",
            "api.groq.com",
            "198.51.100.10",
            443,
            "tls",
            48_000,
            2_000,
            120,
            20,
            8_000,
            false,
        )
        .unwrap();
    assert_eq!(known_ev.agent, "shadow-wrapper");
    assert!((known_ev.ai_score - 1.0).abs() < 1e-6);

    // Unclassified Shadow-AI SSE streaming flow yields high score (1.0 across all 4 factors)
    let shadow_ev = engine
        .record_flow(
            7777,
            "renamed_tool.exe",
            "renamed_tool.exe --run",
            "llm-gateway.example.org",
            "198.51.100.77",
            443,
            "tls",
            64_000, // byte ratio = 32.0 in [4.0, 200.0] -> +0.30
            2_000,
            160, // pkt ratio = 8.0 >= 2.5, avg_pkt_in = 400 in [50, 850] -> +0.30
            20,
            12_000, // duration in [1500, 180000] -> +0.20; programmatic -> +0.20
            false,
        )
        .unwrap();
    assert!(shadow_ev.agent.is_empty());
    assert!(!shadow_ev.is_noise);
    assert!(shadow_ev.ai_score >= 0.95);

    // Interactive browser gets non-programmatic deduction, whereas --headless browser is programmatic
    let rules = engine.load_rules().unwrap();
    assert!(!rules.is_programmatic("chrome.exe", "chrome.exe https://chat.openai.com"));
    assert!(rules.is_programmatic(
        "chrome.exe",
        "chrome.exe --headless --remote-debugging-port=9222"
    ));

    // 2. Triage workflow promotes candidate and updates historical event in SQLite
    let candidates = engine.triage_candidates(0.70).unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].proc_name, "renamed_tool.exe");

    engine
        .apply_triage_decision(&TriageDecision::KnownAgent {
            agent: "approved-internal-llm".to_string(),
            proc_pattern: "renamed_tool.exe".to_string(),
            domain_pattern: "llm-gateway.example.org".to_string(),
        })
        .unwrap();
    assert!(engine.triage_candidates(0.70).unwrap().is_empty());

    // 3. Hot-reload from config/agentsonar.json when mtime advances
    let mut custom_cfg = DynamicRuleSet::default();
    custom_cfg.heuristics.min_byte_ratio = 9.5;
    custom_cfg.agents.push(killswitch_telemetry::AgentRule {
        agent: "hot-reloaded-agent".to_string(),
        proc_pattern: "hot_agent*".to_string(),
        domain_pattern: "*.mistral.ai".to_string(),
    });
    fs::write(
        &cfg_path,
        serde_json::to_string_pretty(&custom_cfg).unwrap(),
    )
    .unwrap();
    assert!(engine.sync_config_file_if_modified().unwrap());

    std::thread::sleep(Duration::from_millis(25));
    custom_cfg.heuristics.min_byte_ratio = 11.25;
    fs::write(
        &cfg_path,
        serde_json::to_string_pretty(&custom_cfg).unwrap(),
    )
    .unwrap();
    let reloaded = engine.load_rules().unwrap();
    assert!(reloaded
        .agents
        .iter()
        .any(|a| a.agent == "hot-reloaded-agent"));
    assert!((reloaded.heuristics.min_byte_ratio - 11.25).abs() < 1e-6);

    // 4. Heuristic patch & ATC schema generation
    let patched = engine
        .update_heuristics(&HeuristicWeightsPatch {
            min_pkt_ratio: Some(3.25),
            ..Default::default()
        })
        .unwrap();
    assert!((patched.min_pkt_ratio - 3.25).abs() < 1e-6);

    let atc = generate_osquery_atc_schema(&db_path.to_string_lossy());
    assert!(atc["options"]["table_construction"]["agentsonar_events"].is_object());
    assert!(atc["options"]["table_construction"]["agentsonar_heuristics"].is_object());

    // 5. Raw packet ingest into flow tracker
    let mut resolver = ProcSocketResolver::new();
    let ch = build_real_tls_client_hello("api.mistral.ai");
    let pkt = wrap_ipv4_tcp_packet([127, 0, 0, 1], [198, 51, 100, 88], 55111, 443, &ch);
    let seg = parse_tcp_packet(&pkt, false).unwrap();
    engine.ingest_parsed_segment(&seg, &mut resolver, true);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_external_classifier_ast_guard_and_execution() {
    // 1. Reject shell chaining and privilege escalation commands via semantic AST guard
    assert!(run_external_classifier("python classifier.py; whoami", "{}").is_err());
    assert!(run_external_classifier("python classifier.py | cat", "{}").is_err());
    assert!(run_external_classifier("sudo -n classifier", "{}").is_err());
    assert!(run_external_classifier("wsl -u root classifier", "{}").is_err());

    // 2. Execute a real safe OS command returning valid JSON score

    let ext_dir = unique_temp_dir("agentsonar_ext_cls");
    let out_file = ext_dir.join("classifier_score.json");
    fs::write(&out_file, "{\"score\":0.91}\n").unwrap();
    let safe_cmd = if cfg!(target_os = "windows") {
        format!("cmd /c type \"{}\"", out_file.display())
    } else {
        format!("cat \"{}\"", out_file.display())
    };

    let score =
        run_external_classifier(&safe_cmd, "{\"proc\":\"test\",\"domain\":\"example.com\"}")
            .expect("safe external classifier should execute");
    assert_eq!(score, Some(0.91));
    let _ = fs::remove_dir_all(&ext_dir);
}

#[test]
fn test_siquery_46_table_join_sweep_1d_and_rl_correlator_enrichment() {
    let global = global_agentsonar_engine();
    let shadow = global
        .record_flow(
            991122,
            "mystery_llm_cli",
            "mystery_llm_cli --prompt secret",
            "inference.shadow-ai.io",
            "198.51.100.200",
            443,
            "tls",
            90_000,
            3_000,
            210,
            25,
            15_000,
            false,
        )
        .unwrap();
    assert!(shadow.ai_score >= 0.90);

    // 1. Siquery exposes all 5 agentsonar_* tables natively
    let tables = SiqueryEngine::list_tables();
    assert!(tables.len() >= 46);
    for expected in &[
        "agentsonar_browser_procs",
        "agentsonar_events",
        "agentsonar_heuristics",
        "agentsonar_known_agents",
        "agentsonar_noise_domains",
    ] {
        assert!(tables.contains(expected), "missing table {}", expected);
    }

    let siquery = SiqueryEngine::new();
    let joined = siquery
        .execute_query(
            "SELECT e.pid, e.proc, e.domain, e.ai_score, h.id AS heur_id \
             FROM agentsonar_events e CROSS JOIN agentsonar_heuristics h \
             WHERE e.proc = 'mystery_llm_cli';",
        )
        .unwrap();
    assert!(!joined.is_empty());
    assert_eq!(joined[0]["domain"], "inference.shadow-ai.io");

    // 2. Sweep 1D surfaces Shadow AI flow while preserving sweeps_executed == 12
    let sweep = siquery.run_siquery_edr_audit_sweep();
    assert_eq!(sweep["sweeps_executed"], 12);
    let anomalies = sweep["anomalies"].as_array().unwrap();
    assert!(anomalies
        .iter()
        .any(|a| a["sweep"] == "agentsonar_shadow_ai" && a["domain"] == "inference.shadow-ai.io"));

    // 3. RL Traffic Learner boosts breakout signal on tainted Shadow AI flow
    let rl = RlTrafficLearner::new_in_memory();
    let decision = rl.evaluate_traffic_with_agentsonar(
        "https://inference.shadow-ai.io/v1/chat/completions",
        Some("mystery_llm_cli"),
        0.90,
        0.10,
        &global,
    );
    assert!(decision.features.ai_breakout_signal >= 0.80);

    // 4. EventCorrelator ingests Shadow AI flow into multi-stage sequence
    let correlator = EventCorrelator::new(300.0, 0.75);
    let stage1 = SecurityEvent::new(
        TelemetryEventKind::FileCreate,
        991122,
        "mystery_llm_cli",
        "mystery_llm_cli",
        "read .env",
    );
    let _ = correlator.ingest_event(&stage1, AttackStage::Collection, 0.35);
    let sig = correlator.ingest_agentsonar_flow(&shadow);
    assert!(sig.is_some());

    // Clean up test shadow flow by marking domain as known agent then removing rule
    let _ = global.apply_triage_decision(&TriageDecision::KnownAgent {
        agent: "temp-cleanup-agent".to_string(),
        proc_pattern: "mystery_llm_cli".to_string(),
        domain_pattern: "inference.shadow-ai.io".to_string(),
    });
    let _ = global.remove_agent_rule("temp-cleanup-agent");
}
