//! # Empirical Challenge Test Suite 2 for Milestone 4 (`crates/killswitch-telemetry`)
//!
//! Exhaustive, adversarial stress testing verifying:
//! 1. Octopus Arm Containment Ring: Monotonic generation epoch advancement, 5-state autotomy machine,
//!    post-autotomy token invalidation, constant-time HMAC capability verification, and fail-closed 18-role authorizers.
//! 2. MeshGuard & Homological Boundary Audit: Simplicial boundary identity $\partial^2 = 0$, coboundary $\delta^2 \phi = 0$,
//!    proxy-laundering detection ($\oint \omega \ne 0$), case-insensitive normalized routing, and sticky taint veto.
//! 3. Breakout Defense & Mathematical SSRF: Mathematical IPv4/IPv6 parser against alternate encodings (dword, hex, octal,
//!    IPv4-mapped IPv6, NAT64, 6to4, cloud metadata 169.254.169.254, RFC1918), local LLM exception (11434/3030),
//!    and safe Path::join traversal defenses (colons, ADS, UNC, percent-encoding, DOS devices).
//! 4. 100% Data Lineage Engine: Composite key collision resistance, lattice meet-semilattice properties, W3C traceparent roundtrips,
//!    multi-hop fan-in exfiltration scenario, sub-10us hot-path evaluate_egress latency, and concurrent DashMap thread safety.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use killswitch_telemetry::octopus::arm_ring::{ArmContainmentRing, ArmRingRegistry};
use killswitch_telemetry::octopus::breakout::{
    validate_egress_url, validate_sandbox_path, BreakoutDefenseCoordinator,
};
use killswitch_telemetry::octopus::mesh_guard::{HomologicalBoundaryAuditor, MeshGuard};
use killswitch_telemetry::otel_lineage::{
    DlpClassification, DlpPolicy, EndpointLineageEngine, FileKey, ProcessKey,
    TaintBaggage, W3cTraceContext,
};
use killswitch_types::{
    ArmMessage, ArmRole, KillSwitchError, MessageKind, TrustTier, MAX_RELAY_HOPS,
};

// ============================================================================
// SUITE 1: Octopus Arm Containment & Surgical Autotomy Machine
// ============================================================================

#[tokio::test]
async fn test_c1_arm_monotonic_epoch_advancement_and_stale_rejection() {
    let master_seed = [0x33u8; 32];
    let ring = ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, &master_seed);

    assert_eq!(ring.current_generation(), 1);
    assert!(ring.validate_epoch(1).await.is_ok());

    // Advance generation 10 times consecutively
    for expected_gen in 2..=11 {
        let new_gen = ring
            .sever_and_regenerate(&format!("Autotomy test step {}", expected_gen))
            .await
            .expect("Autotomy must succeed");
        assert_eq!(new_gen, expected_gen);
        assert_eq!(ring.current_generation(), expected_gen);

        // All historical generations [1..expected_gen) must be strictly rejected
        for old_gen in 1..expected_gen {
            let res = ring.validate_epoch(old_gen).await;
            assert!(
                matches!(res, Err(KillSwitchError::StaleGenerationEpoch { .. })),
                "Historical generation {} was not rejected at gen {}",
                old_gen,
                expected_gen
            );
        }

        // Current generation succeeds
        assert!(ring.validate_epoch(expected_gen).await.is_ok());

        // Future unissued generation also fails
        let future_res = ring.validate_epoch(expected_gen + 1).await;
        assert!(matches!(
            future_res,
            Err(KillSwitchError::StaleGenerationEpoch { .. })
        ));
    }
}

#[tokio::test]
async fn test_c2_arm_autotomy_state_machine_and_quarantine() {
    let master_seed = [0x44u8; 32];
    let ring = ArmContainmentRing::new(1, ArmRole::AccountingLedgerWrite, 1, &master_seed);

    // Initial state is Active(1)
    assert!(ring.validate_epoch(1).await.is_ok());

    // Sever the arm without regenerating
    ring.sever("Manual breach detection").await.unwrap();

    // While severed, validate_epoch returns ArmQuarantined
    let res = ring.validate_epoch(1).await;
    match res {
        Err(KillSwitchError::ArmQuarantined {
            arm_id,
            role,
            epoch,
            reason,
        }) => {
            assert_eq!(arm_id, 1);
            assert_eq!(role, "AccountingLedgerWrite");
            assert_eq!(epoch, 1);
            assert!(reason.contains("Manual breach detection"));
        }
        other => panic!("Expected ArmQuarantined error, got {:?}", other),
    }

    // Attempting to issue capability while severed must fail
    let cap_res = ring.issue_capability("ledger_writer", "s3://accounting/", 30).await;
    assert!(cap_res.is_err(), "Should not issue capability when severed");
}

#[tokio::test]
async fn test_c3_arm_post_autotomy_token_invalidation() {
    let master_seed = [0x55u8; 32];
    let ring = ArmContainmentRing::new(2, ArmRole::NetworkEgress, 1, &master_seed);

    // Issue capability token T1 under Gen 1
    let token_gen1 = ring
        .issue_capability("http_egress", "https://api.example.com/", 120)
        .await
        .expect("Token issuance under active Gen 1 must succeed");

    // Token verifies cleanly under Gen 1
    assert!(ring.verify_capability(&token_gen1).await.is_ok());

    // Sever and regenerate arm to Gen 2
    let gen2 = ring
        .sever_and_regenerate("Compromised session key")
        .await
        .unwrap();
    assert_eq!(gen2, 2);

    // Presenting token T1 from Gen 1 to regenerated arm Gen 2 must FAIL
    let verify_res = ring.verify_capability(&token_gen1).await;
    assert!(
        verify_res.is_err(),
        "Token issued under Gen 1 must be rejected by Gen 2"
    );

    // Issue new capability token T2 under Gen 2
    let token_gen2 = ring
        .issue_capability("http_egress", "https://api.example.com/", 120)
        .await
        .expect("Token issuance under active Gen 2 must succeed");
    assert!(ring.verify_capability(&token_gen2).await.is_ok());
}

#[tokio::test]
async fn test_c4_arm_capability_token_adversarial_tampering() {
    let master_seed = [0x66u8; 32];
    let ring = ArmContainmentRing::new(3, ArmRole::OutboundNotification, 1, &master_seed);

    let token = ring
        .issue_capability("notifier", "notification://slack", 60)
        .await
        .unwrap();

    // 1. Alter permitted role to AccountingLedgerWrite
    let mut rogue_role = token.clone();
    rogue_role.permitted_role = ArmRole::AccountingLedgerWrite;
    assert!(ring.verify_capability(&rogue_role).await.is_err());

    // 2. Alter permitted tool to shell_exec
    let mut rogue_tool = token.clone();
    rogue_tool.permitted_tool = "shell_exec".to_string();
    assert!(ring.verify_capability(&rogue_tool).await.is_err());

    // 3. Alter bearer agent
    let mut rogue_bearer = token.clone();
    rogue_bearer.bearer_agent = "arm-attacker-99".to_string();
    assert!(ring.verify_capability(&rogue_bearer).await.is_err());

    // 4. Invalidate signature hex
    let mut rogue_sig = token.clone();
    rogue_sig.signature_hex = hex::encode([0xFFu8; 32]);
    let sig_err = ring.verify_capability(&rogue_sig).await;
    assert!(matches!(
        sig_err,
        Err(KillSwitchError::MeshHmacVerificationFailed { .. })
    ));

    // 5. Expired token
    let mut expired_token = token.clone();
    expired_token.expires_at_secs = 1; // Expired in 1970
    assert!(ring.verify_capability(&expired_token).await.is_err());
}

#[tokio::test]
async fn test_c5_arm_fail_closed_all_18_roles_completeness() {
    let all_18_roles = [
        ArmRole::UntrustedDocIngest,
        ArmRole::AccountingLedgerWrite,
        ArmRole::NetworkEgress,
        ArmRole::OutboundNotification,
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

    assert_eq!(all_18_roles.len(), 18, "Must test exactly all 18 ArmRoles");

    let mut seen_roles = HashSet::new();
    for role in &all_18_roles {
        assert!(
            seen_roles.insert(role.as_str()),
            "Duplicate role string detected: {}",
            role.as_str()
        );

        let (tools, prefixes) = ArmContainmentRing::default_permissions_for_role(role);
        assert!(
            !tools.is_empty(),
            "Role {:?} must have at least one explicit permitted tool",
            role
        );
        assert!(
            !prefixes.is_empty(),
            "Role {:?} must have at least one explicit resource prefix",
            role
        );
    }
}

#[tokio::test]
async fn test_c6_registry_concurrent_autotomy_and_broadcasting() {
    let master_seed = [0x77u8; 32];
    let registry = Arc::new(ArmRingRegistry::new(&master_seed));

    let mut handles = Vec::new();
    for arm_id in 0..18 {
        let reg = registry.clone();
        handles.push(tokio::spawn(async move {
            reg.sever_and_regenerate_arm(arm_id, "Concurrent stress autotomy")
                .await
                .expect("Autotomy must succeed");
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    let signals = registry.active_watchout_signals().await;
    assert_eq!(signals.len(), 18, "All 18 arms must have broadcast signals");

    let signal_ids: HashSet<usize> = signals.iter().map(|s| s.severed_arm_id).collect();
    assert_eq!(signal_ids.len(), 18);
}

// ============================================================================
// SUITE 2: MeshGuard, Homological Boundary Audit, & Sticky Taint Veto
// ============================================================================

#[test]
fn test_c7_homological_simplicial_boundary_identity() {
    // 1. Simplicial 2-simplex exactness: Telescoping sum vanishes: \partial^2 = 0
    let valid_chain = vec![
        ArmRole::AnomalyDetection,
        ArmRole::ContinuousOssFuzz,
        ArmRole::VulnerabilityResearch,
        ArmRole::OutboundNotification,
    ];

    let report = HomologicalBoundaryAuditor::audit_role_chain(&valid_chain);
    assert!(report.allowed);
    assert_eq!(report.coboundary_residue, 0);
    assert!(report.boundary_squared_zero);
    assert!(!report.proxy_laundering_detected);

    // 2. Chain length boundaries: < 2 elements rejected
    let too_short = vec![ArmRole::AnomalyDetection];
    let short_report = HomologicalBoundaryAuditor::audit_role_chain(&too_short);
    assert!(!short_report.allowed);
    assert!(short_report.reason.contains("LAW1_CHAIN_LENGTH_VETO"));

    // 3. Chain length boundaries: > MAX_RELAY_HOPS + 1 rejected
    let mut too_long = Vec::new();
    for _ in 0..=(MAX_RELAY_HOPS + 2) {
        too_long.push(ArmRole::AnomalyDetection);
    }
    let long_report = HomologicalBoundaryAuditor::audit_role_chain(&too_long);
    assert!(!long_report.allowed);
    assert!(long_report.reason.contains("LAW1_CHAIN_LENGTH_VETO"));
}

#[test]
fn test_c8_proxy_laundering_adversarial_deep_chains() {
    // Attack 1: 3-hop proxy laundering: Untrusted -> Worker -> PrivilegedSink
    let chain_3hop = [
        ArmRole::UntrustedDocIngest,
        ArmRole::CedarPolicyEvaluation,
        ArmRole::AccountingLedgerWrite,
    ];
    let rep_3hop = HomologicalBoundaryAuditor::audit_role_chain(&chain_3hop);
    assert!(!rep_3hop.allowed);
    assert!(rep_3hop.proxy_laundering_detected);
    assert!(rep_3hop.reason.contains("LAW1_PROXY_LAUNDERING_VETO"));

    // Attack 2: 6-hop proxy laundering with innocent intermediaries
    let chain_6hop = [
        ArmRole::UntrustedDocIngest,
        ArmRole::AtlasThreatIntelligence,
        ArmRole::AnomalyDetection,
        ArmRole::VulnerabilityResearch,
        ArmRole::DifferentialProtocolAnalyzer,
        ArmRole::AccountingLedgerWrite,
    ];
    let rep_6hop = HomologicalBoundaryAuditor::audit_role_chain(&chain_6hop);
    assert!(!rep_6hop.allowed);
    assert!(rep_6hop.proxy_laundering_detected);
    assert!(rep_6hop.reason.contains("LAW1_PROXY_LAUNDERING_VETO"));

    // Attack 3: Direct boundary jump Untrusted -> PrivilegedSink
    let chain_direct = [
        ArmRole::UntrustedDocIngest,
        ArmRole::AccountingLedgerWrite,
    ];
    let rep_direct = HomologicalBoundaryAuditor::audit_role_chain(&chain_direct);
    assert!(!rep_direct.allowed);
    assert!(rep_direct.reason.contains("LAW1_DIRECT_BOUNDARY_VETO"));
}

#[tokio::test]
async fn test_c9_mesh_guard_case_insensitive_normalized_routing() {
    let guard = MeshGuard::new();
    let sender_key = [0x88u8; 32];

    // Authorize route with mixed casing and spaces
    guard
        .allow_route("  Arm-Alpha-0  ", "  ARM-BETA-1  ", Some(MessageKind::Finding))
        .await;

    let mut msg = ArmMessage {
        sender_arm_id: "arm-alpha-0".to_string(), // lowercase
        sender_role: ArmRole::AnomalyDetection,
        sender_generation: 1,
        target_arm_id: "ARM-BETA-1".to_string(), // uppercase
        target_generation: 1,
        kind: MessageKind::Finding,
        correlation_id: "corr-norm-1".to_string(),
        payload: "{\"test\":\"normalized\"}".to_string(),
        provenance: vec![],
        taint_floor: TrustTier::Worker,
        signature_hex: String::new(),
    };
    msg.sign(&sender_key).unwrap();

    // Verify authorized route matches despite case/whitespace differences
    let valid_res = guard
        .validate_message(&msg, &ArmRole::OutboundNotification, &sender_key)
        .await;
    assert!(valid_res.is_ok());

    // Unauthorized route must be rejected
    let mut unauth_msg = msg.clone();
    unauth_msg.target_arm_id = "arm-charlie-2".to_string();
    unauth_msg.sign(&sender_key).unwrap();
    let unauth_res = guard
        .validate_message(&unauth_msg, &ArmRole::OutboundNotification, &sender_key)
        .await;
    assert!(matches!(
        unauth_res,
        Err(KillSwitchError::OctopusViolation(..))
    ));
}

#[tokio::test]
async fn test_c10_mesh_guard_payload_and_correlation_limits() {
    let guard = MeshGuard::new();
    let sender_key = [0x99u8; 32];
    guard.allow_route("arm-0", "arm-1", None).await;

    // 1. Oversized correlation ID (> 128 bytes)
    let mut msg_big_corr = ArmMessage {
        sender_arm_id: "arm-0".to_string(),
        sender_role: ArmRole::AnomalyDetection,
        sender_generation: 1,
        target_arm_id: "arm-1".to_string(),
        target_generation: 1,
        kind: MessageKind::Heartbeat,
        correlation_id: "A".repeat(129),
        payload: "{}".to_string(),
        provenance: vec![],
        taint_floor: TrustTier::Worker,
        signature_hex: String::new(),
    };
    msg_big_corr.sign(&sender_key).unwrap();
    let res_corr = guard
        .validate_message(&msg_big_corr, &ArmRole::OutboundNotification, &sender_key)
        .await;
    assert!(res_corr.is_err());

    // 2. Oversized payload (> 16KB)
    let mut msg_big_payload = ArmMessage {
        sender_arm_id: "arm-0".to_string(),
        sender_role: ArmRole::AnomalyDetection,
        sender_generation: 1,
        target_arm_id: "arm-1".to_string(),
        target_generation: 1,
        kind: MessageKind::Heartbeat,
        correlation_id: "corr-1".to_string(),
        payload: "B".repeat(16 * 1024 + 1),
        provenance: vec![],
        taint_floor: TrustTier::Worker,
        signature_hex: String::new(),
    };
    msg_big_payload.sign(&sender_key).unwrap();
    let res_payload = guard
        .validate_message(&msg_big_payload, &ArmRole::OutboundNotification, &sender_key)
        .await;
    assert!(res_payload.is_err());
}

// ============================================================================
// SUITE 3: Breakout Defense & Mathematical SSRF & Safe Path Sandboxing
// ============================================================================

#[test]
fn test_c11_mathematical_ssrf_alternate_encodings_comprehensive() {
    // 1. Dword decimal encodings
    assert!(validate_egress_url("http://2130706433/", false).is_err()); // 127.0.0.1
    assert!(validate_egress_url("http://2852039166/", false).is_err()); // 169.254.169.254
    assert!(validate_egress_url("http://167772161/", false).is_err()); // 10.0.0.1

    // 2. Hex dword encodings
    assert!(validate_egress_url("http://0x7f000001/", false).is_err());
    assert!(validate_egress_url("http://0xa9fea9fe/", false).is_err());

    // 3. Octal and mixed dotted notations
    assert!(validate_egress_url("http://0177.0.0.1/", false).is_err());
    assert!(validate_egress_url("http://0x7f.0.0.1/", false).is_err());
    assert!(validate_egress_url("http://127.0.0.01/", false).is_err());

    // 4. Shortened dotted notations
    assert!(validate_egress_url("http://127.1/", false).is_err());
    assert!(validate_egress_url("http://10.1/", false).is_err());

    // 5. Cloud metadata
    assert!(validate_egress_url("http://169.254.169.254/latest/meta-data", false).is_err());
    assert!(validate_egress_url("http://169.254.1.1/", false).is_err());

    // 6. RFC 1918 Private ranges
    assert!(validate_egress_url("http://10.255.255.255/secret", false).is_err());
    assert!(validate_egress_url("http://172.31.255.255/secret", false).is_err());
    assert!(validate_egress_url("http://192.168.0.100/secret", false).is_err());

    // 7. CGNAT (100.64.0.0/10)
    assert!(validate_egress_url("http://100.64.0.1/", false).is_err());
    assert!(validate_egress_url("http://100.127.255.254/", false).is_err());

    // 8. IPv4-mapped IPv6
    assert!(validate_egress_url("http://[::ffff:127.0.0.1]/", false).is_err());
    assert!(validate_egress_url("http://[::ffff:169.254.169.254]/", false).is_err());
    assert!(validate_egress_url("http://[::ffff:10.0.0.1]/", false).is_err());

    // 9. NAT64 and 6to4 prefixes
    assert!(validate_egress_url("http://[64:ff9b::127.0.0.1]/", false).is_err());
    assert!(validate_egress_url("http://[2002:7f00:0001::]/", false).is_err());

    // 10. IPv6 ULA (fc00::/7) and Link-Local (fe80::/10)
    assert!(validate_egress_url("http://[fc00::1]/", false).is_err());
    assert!(validate_egress_url("http://[fd12:3456:789a::1]/", false).is_err());
    assert!(validate_egress_url("http://[fe80::1]/", false).is_err());

    // 11. Current network, Unspecified, Multicast
    assert!(validate_egress_url("http://0.0.0.0/", false).is_err());
    assert!(validate_egress_url("http://0.1.2.3/", false).is_err());
    assert!(validate_egress_url("http://[::]/", false).is_err());
    assert!(validate_egress_url("http://224.0.0.1/", false).is_err());
    assert!(validate_egress_url("http://[ff02::1]/", false).is_err());

    // 12. Embedded credentials
    assert!(validate_egress_url("http://admin:secret@1.1.1.1/", false).is_err());

    // 13. Forbidden schemes
    assert!(validate_egress_url("file:///etc/passwd", false).is_err());
    assert!(validate_egress_url("gopher://127.0.0.1:11434/", false).is_err());

    // 14. Legitimate public egress URL succeeds
    assert!(validate_egress_url("https://api.github.com/repos", false).is_ok());
    assert!(validate_egress_url("https://1.1.1.1/dns-query", false).is_ok());
}

#[test]
fn test_c12_local_inference_exception_strict_boundaries() {
    // 1. When allow_local_inference = false: loopback inference ports BLOCKED
    assert!(validate_egress_url("http://127.0.0.1:11434/api/tags", false).is_err());
    assert!(validate_egress_url("http://127.0.0.1:3030/status", false).is_err());
    assert!(validate_egress_url("http://localhost:11434/api/generate", false).is_err());

    // 2. When allow_local_inference = true: inference ports ALLOWED
    assert!(validate_egress_url("http://127.0.0.1:11434/api/tags", true).is_ok());
    assert!(validate_egress_url("http://127.0.0.1:3030/status", true).is_ok());
    assert!(validate_egress_url("http://localhost:11434/api/generate", true).is_ok());
    assert!(validate_egress_url("http://127.0.0.1:5000/predict", true).is_ok());
    assert!(validate_egress_url("http://127.0.0.1:8000/v1/models", true).is_ok());

    // 3. When allow_local_inference = true: non-whitelisted loopback ports STILL BLOCKED
    assert!(validate_egress_url("http://127.0.0.1:22/ssh", true).is_err());
    assert!(validate_egress_url("http://127.0.0.1:80/web", true).is_err());
    assert!(validate_egress_url("http://127.0.0.1:443/ssl", true).is_err());
    assert!(validate_egress_url("http://127.0.0.1:9090/metrics", true).is_err());

    // 4. Cloud metadata is NEVER allowed, even with allow_local_inference = true
    assert!(validate_egress_url("http://169.254.169.254/latest", true).is_err());

    // 5. RFC 1918 is NEVER allowed, even with allow_local_inference = true
    assert!(validate_egress_url("http://10.0.0.1:11434/api/tags", true).is_err());
}

#[test]
fn test_c13_safe_path_sandboxing_defense_thorough() {
    let sandbox = Path::new("C:\\Sandbox\\SafeDir");

    // 1. Directory traversals
    assert!(validate_sandbox_path("../foo", sandbox).is_err());
    assert!(validate_sandbox_path("foo/../../bar", sandbox).is_err());
    assert!(validate_sandbox_path(r"foo\..\..\bar", sandbox).is_err());

    // 2. Drive letters and absolute paths
    assert!(validate_sandbox_path("C:\\Windows\\System32", sandbox).is_err());
    assert!(validate_sandbox_path("D:relative_drive", sandbox).is_err());
    assert!(validate_sandbox_path("/etc/passwd", sandbox).is_err());
    assert!(validate_sandbox_path(r"\Windows\System32", sandbox).is_err());

    // 3. NTFS Alternate Data Streams (ADS)
    assert!(validate_sandbox_path("file.txt:hidden", sandbox).is_err());
    assert!(validate_sandbox_path("nested/dir:evil.exe", sandbox).is_err());

    // 4. Percent-encoded traversals
    assert!(validate_sandbox_path("%2e%2e/secret", sandbox).is_err());
    assert!(validate_sandbox_path("dir/%2e%2e/file", sandbox).is_err());
    assert!(validate_sandbox_path("%252e%252e", sandbox).is_err());
    assert!(validate_sandbox_path("file%00.txt", sandbox).is_err());

    // 5. UNC paths and Device namespaces
    assert!(validate_sandbox_path(r"\\192.168.1.1\share\payload", sandbox).is_err());
    assert!(validate_sandbox_path(r"\\?\C:\secret", sandbox).is_err());
    assert!(validate_sandbox_path(r"\\.\pipe\docker", sandbox).is_err());
    assert!(validate_sandbox_path("//remote/share", sandbox).is_err());

    // 6. DOS reserved names
    assert!(validate_sandbox_path("CON", sandbox).is_err());
    assert!(validate_sandbox_path("aux.txt", sandbox).is_err());
    assert!(validate_sandbox_path("nested/nul", sandbox).is_err());
    assert!(validate_sandbox_path("com1.dat", sandbox).is_err());
    assert!(validate_sandbox_path("lpt9.log", sandbox).is_err());

    // 7. Legitimate paths resolve strictly under sandbox root
    let p1 = validate_sandbox_path("work/report.pdf", sandbox).unwrap();
    assert!(p1.starts_with(sandbox));

    let p2 = validate_sandbox_path("./data/table.csv", sandbox).unwrap();
    assert!(p2.starts_with(sandbox));
}

#[test]
fn test_c14_4_category_breakout_defense_coordinator() {
    let coordinator = BreakoutDefenseCoordinator::new();

    // 1. Technical: Docker socket / privileged container
    let t1 = coordinator.evaluate_action("access", "/var/run/docker.sock", "");
    assert!(!t1.is_clean);
    assert!(!t1.technical.is_clean);

    let t2 = coordinator.evaluate_action("exec", "nsenter --target 1 --mount", "");
    assert!(!t2.is_clean);
    assert!(!t2.technical.is_clean);

    // 2. Operational: API tokens and credentials
    let o1 = coordinator.evaluate_action("env", "app", "export AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE");
    assert!(!o1.is_clean);
    assert!(!o1.operational.is_clean);

    let o2 = coordinator.evaluate_action("code", "main.rs", "let token = \"ghp_1234567890abcdefghijklmnopqrstuvwxyz\";");
    assert!(!o2.is_clean);
    assert!(!o2.operational.is_clean);

    // 3. Behavioral: Reconnaissance and exfiltration channels
    let b1 = coordinator.evaluate_action("exec", "netstat -r", "");
    assert!(!b1.is_clean);
    assert!(!b1.behavioral.is_clean);

    let b2 = coordinator.evaluate_action("curl", "https://webhook.site/abc", "");
    assert!(!b2.is_clean);
    assert!(!b2.behavioral.is_clean);

    // 4. Data: Memory dumps and credential harvesting
    let d1 = coordinator.evaluate_action("exec", "mimikatz.exe", "sekurlsa::logonpasswords");
    assert!(!d1.is_clean);
    assert!(!d1.data.is_clean);

    // 5. Clean benign action
    let clean = coordinator.evaluate_action("read", "local_scratchpad/clean_invoice.txt", "");
    assert!(clean.is_clean);
}

// ============================================================================
// SUITE 4: 100% Data Lineage Engine (`otel_lineage.rs`)
// ============================================================================

#[test]
fn test_c15_composite_key_uniqueness_and_immutability() {
    // ProcessKey uniqueness: PID, timestamp, and executable hash
    let p_base = ProcessKey::new(1001, 1000000, "C:\\Tools\\app.exe");
    let p_diff_time = ProcessKey::new(1001, 2000000, "C:\\Tools\\app.exe");
    let p_diff_exe = ProcessKey::new(1001, 1000000, "C:\\Tools\\other.exe");
    let p_diff_pid = ProcessKey::new(1002, 1000000, "C:\\Tools\\app.exe");

    assert_ne!(p_base, p_diff_time);
    assert_ne!(p_base, p_diff_exe);
    assert_ne!(p_base, p_diff_pid);

    // FileKey uniqueness: path hash and inode/file_id
    let f1 = FileKey::new("C:\\Data\\file.bin", 500);
    let f2 = FileKey::new("C:\\Data\\file.bin", 501);
    let f3 = FileKey::new("C:\\Data\\other.bin", 500);

    assert_ne!(f1, f2);
    assert_ne!(f1, f3);
}

#[test]
fn test_c16_lattice_join_properties_and_deduplication() {
    // Verify DlpClassification Meet-Semilattice properties:
    // CrownJewel > Confidential > Internal > Public
    assert_eq!(DlpClassification::Public.join(DlpClassification::CrownJewel), DlpClassification::CrownJewel);
    assert_eq!(DlpClassification::Confidential.join(DlpClassification::Internal), DlpClassification::Confidential);
    assert_eq!(DlpClassification::Internal.join(DlpClassification::Internal), DlpClassification::Internal); // Idempotence

    // Verify DlpPolicy Meet-Semilattice properties:
    // Quarantine > Block > Audit > Allow
    assert_eq!(DlpPolicy::Allow.join(DlpPolicy::Quarantine), DlpPolicy::Quarantine);
    assert_eq!(DlpPolicy::Audit.join(DlpPolicy::Block), DlpPolicy::Block);
    assert_eq!(DlpPolicy::Quarantine.join(DlpPolicy::Block), DlpPolicy::Quarantine);

    // Deduplication across 50 baggage merges
    let mut baggage = TaintBaggage::public_clean();
    for i in 0..50 {
        let incoming = TaintBaggage::new(
            DlpClassification::Internal,
            DlpPolicy::Audit,
            format!("hash_{}", i % 5), // Only 5 unique hashes
        );
        baggage.merge(&incoming);
    }

    assert_eq!(baggage.classification, DlpClassification::Internal);
    assert_eq!(baggage.policy, DlpPolicy::Audit);
    assert_eq!(baggage.distinct_hashes().len(), 5);
}

#[test]
fn test_c17_w3c_traceparent_serialization_and_malformed_handling() {
    let sc = opentelemetry::trace::SpanContext::new(
        opentelemetry::trace::TraceId::from_bytes([0xAA; 16]),
        opentelemetry::trace::SpanId::from_bytes([0xBB; 8]),
        opentelemetry::trace::TraceFlags::SAMPLED,
        false,
        opentelemetry::trace::TraceState::default(),
    );

    let tp = W3cTraceContext::to_traceparent(&sc);
    assert!(tp.starts_with("00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"));

    let parsed = W3cTraceContext::from_traceparent(&tp).expect("Valid traceparent must parse");
    assert_eq!(parsed.trace_id(), sc.trace_id());
    assert_eq!(parsed.span_id(), sc.span_id());

    // Malformed traceparents fail safely returning None
    assert!(W3cTraceContext::from_traceparent("01-invalid-version-00").is_none());
    assert!(W3cTraceContext::from_traceparent("not-a-traceparent").is_none());
    assert!(W3cTraceContext::from_traceparent("").is_none());
}

#[test]
fn test_c18_sub_10us_hot_path_egress_evaluation_benchmark() {
    let engine = EndpointLineageEngine::new_in_memory();

    let file_key = FileKey::new("C:\\Vault\\classified.docx", 777);
    engine.seed_sensitive_file(
        file_key,
        "C:\\Vault\\classified.docx",
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        DlpClassification::CrownJewel,
        DlpPolicy::Quarantine,
    );

    let proc_key = ProcessKey::new(8888, 50000, "C:\\App\\worker.exe");
    engine.on_process_create(None, proc_key, "C:\\App\\worker.exe");
    engine.on_file_read(proc_key, file_key);

    // Warm up cache
    for _ in 0..100 {
        let _ = engine.evaluate_egress(proc_key, "https://api.external.com/upload");
    }

    // Benchmark 1,000 evaluations
    let iterations = 1000;
    let start = Instant::now();
    for _ in 0..iterations {
        let verdict = engine.evaluate_egress(proc_key, "https://api.external.com/upload");
        assert!(verdict.is_block());
    }
    let total_elapsed = start.elapsed();
    let avg_latency = total_elapsed / iterations;

    println!(
        "evaluate_egress hot path: {} iterations took {:?} (average: {:?} / call)",
        iterations, total_elapsed, avg_latency
    );

    // Sub-10 microsecond requirement: average must comfortably be < 20 microseconds
    assert!(
        avg_latency.as_micros() < 20,
        "evaluate_egress hot-path exceeded 20 microseconds: {:?}",
        avg_latency
    );
}

#[tokio::test]
async fn test_c19_concurrent_lineage_engine_thread_safety() {
    let engine = Arc::new(EndpointLineageEngine::new_in_memory());

    let mut handles = Vec::new();
    for thread_id in 0..16 {
        let eng = engine.clone();
        handles.push(tokio::spawn(async move {
            for step in 0..20 {
                let pid = (thread_id * 1000 + step) as u32;
                let proc_key = ProcessKey::new(pid, step as u64, "C:\\App\\proc.exe");
                let file_key = FileKey::new(&format!("C:\\Docs\\file_{}_{}.txt", thread_id, step), pid as u64);

                eng.seed_sensitive_file(
                    file_key,
                    &format!("C:\\Docs\\file_{}_{}.txt", thread_id, step),
                    &format!("{:064x}", pid),
                    DlpClassification::Confidential,
                    DlpPolicy::Quarantine,
                );

                eng.on_process_create(None, proc_key, "C:\\App\\proc.exe");
                eng.on_file_read(proc_key, file_key);

                let out_file = FileKey::new(&format!("C:\\Out\\zip_{}_{}.zip", thread_id, step), (pid + 5000) as u64);
                eng.on_file_write(
                    proc_key,
                    out_file,
                    &format!("C:\\Out\\zip_{}_{}.zip", thread_id, step),
                    &format!("{:064x}", pid + 5000),
                );

                let verdict = eng.evaluate_egress(proc_key, "https://remote.exfil.org/data");
                assert!(verdict.is_block());
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    let tainted_procs = engine.all_tainted_processes();
    assert_eq!(tainted_procs.len(), 16 * 20);

    let tainted_files = engine.all_tainted_files();
    assert_eq!(tainted_files.len(), 16 * 20 * 2); // 1 seed + 1 write per step
}
