//! # Adversarial Empirical Challenge Suite: Milestone SEC-2
//!
//! Empirical challenge tests for Milestone SEC-2: Semantic Command Analysis,
//! Privilege Equivalence Classes, Dynamic Binary Probing, and Bounded Agents APC.
//!
//! Specifically tests:
//! 1. Privilege Equivalence Class Taxonomy & Action Classification Stress
//! 2. APC Condition C4 Single-Use Approval Token Exhaustion & Concurrent Replay
//! 3. APC Expired & Boundary Timestamp Approval Token Rejections
//! 4. APC Action Hash & HMAC Signature Tampering Defenses
//! 5. APC Invalid Capability, Scope Narrowing, and Composition Defenses
//! 6. Dynamic Binary Probing: Renamed Binaries with POSIX SUID & Linux Capabilities
//! 7. Dynamic Binary Probing: Renamed Windows PE `requireAdministrator` Manifest (UTF-8 & UTF-16 LE)
//! 8. End-to-End APC + Dynamic Binary Probing Gating and Composition Integration
//! 9. Empirical Defect Verification:
//!    - Bug A: `tokenize_command` strips Windows backslashes inside double quotes.
//!    - Bug B: `DynamicBinaryMetadataProbe::is_privileged_target` returns false for non-root SUID,
//!      rendering `TargetUserDelegation` unreachable in `parse_semantic_command_with_probe`.

use killswitch_telemetry::{
    classify_action_class, default_enterprise_apc_scope, parse_semantic_command,
    parse_semantic_command_with_probe, tokenize_command, ApcActionRequest, ApcPolicyDecisionPoint,
    ApcScope, ApprovalToken, AuthorizationEnvelope, DelegationBudgetSpec,
    DynamicBinaryMetadataProbe, ElevationRequirement, IntentEnforcementMode, IntentSpec,
    PrivilegeEquivalenceClass,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::sync::Arc;
use std::thread;
use tempfile::NamedTempFile;

fn permissive_intent() -> IntentSpec {
    IntentSpec {
        intent_id: "intent-challenge".to_string(),
        intended_actions: BTreeSet::from(["*".to_string()]),
        intended_resources: BTreeSet::from(["*".to_string()]),
        action_resource_map: BTreeMap::new(),
        mode: IntentEnforcementMode::Strict,
    }
}

fn create_test_pdp_and_envelope_with_grants(
    signing_key: &[u8],
    root_principal: &str,
    session_id: &str,
    now: i64,
    extra_actions: &[&str],
    extra_resources: &[&str],
) -> (ApcPolicyDecisionPoint, AuthorizationEnvelope) {
    let pdp = ApcPolicyDecisionPoint::new(signing_key.to_vec(), "v1.0", true);

    let mut scope = default_enterprise_apc_scope();
    for a in extra_actions {
        scope.actions.insert(a.to_string());
    }
    for r in extra_resources {
        scope.resources.insert(r.to_string());
    }
    let budget = DelegationBudgetSpec::default();

    let env = AuthorizationEnvelope::new_root(
        "env-root-01",
        root_principal,
        root_principal,
        session_id,
        "v1.0",
        scope,
        budget,
        now,
        now + 3600,
        signing_key,
    );

    (pdp, env)
}

// ============================================================================
// SUITE 1: Privilege Equivalence Class Taxonomy & Action Classification Stress
// ============================================================================

#[test]
fn test_challenge_root_or_admin_elevation_equivalence_family() {
    let test_cases = [
        ("sudo id", true, false),
        ("sudo -n id", true, true),
        ("sudo -u root whoami", true, false),
        ("sudo -u 0 whoami", true, false),
        ("sudo --user=root cat /etc/shadow", true, false),
        ("su", true, false),
        ("su -", true, false),
        ("su root", true, false),
        ("su 0", true, false),
        ("doas id", true, false),
        ("doas -n id", true, true),
        ("pkexec id", true, false),
        ("pkexec --user root id", true, false),
        ("runas /user:Administrator cmd.exe", true, false),
        ("runas /user:SYSTEM powershell.exe", true, false),
        ("wsl id", true, false),
        ("wsl -u root id", true, false),
        ("wsl -u 0 id", true, false),
        ("wsl --user=root id", true, false),
    ];

    for (cmd_str, should_be_root, should_be_non_interactive) in test_cases {
        let sem = parse_semantic_command(cmd_str);
        assert_eq!(
            sem.privilege_class,
            PrivilegeEquivalenceClass::RootOrAdminElevation,
            "Command '{}' must classify as RootOrAdminElevation",
            cmd_str
        );
        assert!(
            sem.privilege_class.is_privileged_execution(),
            "Command '{}' must be privileged execution",
            cmd_str
        );
        assert_eq!(
            sem.privilege_class.is_root_or_admin(),
            should_be_root,
            "Command '{}' is_root_or_admin check failed",
            cmd_str
        );
        assert_eq!(
            sem.is_non_interactive, should_be_non_interactive,
            "Command '{}' non-interactive check failed",
            cmd_str
        );

        // APC Action Class mapping verification
        let action_class = classify_action_class(cmd_str);
        assert_eq!(
            action_class, "PRIVILEGED_EXECUTION",
            "Command '{}' must map to action class PRIVILEGED_EXECUTION, not READ_PUBLIC",
            cmd_str
        );
    }
}

#[test]
fn test_challenge_target_user_delegation_equivalence_family() {
    let test_cases = [
        ("sudo -u www-data cat /var/log/nginx/access.log", "www-data"),
        ("sudo --user=appuser /opt/app/run.sh", "appuser"),
        ("su guest", "guest"),
        ("doas -u backup /bin/tar -czf /backup/db.tar.gz", "backup"),
        ("pkexec --user deploy /usr/local/bin/deploy.sh", "deploy"),
        ("runas /user:service_account notepad.exe", "service_account"),
        ("wsl -u ubuntu whoami", "ubuntu"),
    ];

    for (cmd_str, expected_user) in test_cases {
        let sem = parse_semantic_command(cmd_str);
        assert_eq!(
            sem.privilege_class,
            PrivilegeEquivalenceClass::TargetUserDelegation,
            "Command '{}' must classify as TargetUserDelegation",
            cmd_str
        );
        assert!(
            sem.privilege_class.is_privileged_execution(),
            "Command '{}' must be recognized as privileged execution",
            cmd_str
        );
        assert!(
            !sem.privilege_class.is_root_or_admin(),
            "Command '{}' must NOT be classified as direct root",
            cmd_str
        );
        assert_eq!(
            sem.target_user.as_deref(),
            Some(expected_user),
            "Target user mismatch for '{}'",
            cmd_str
        );

        // Delegation is still high privilege, requiring PRIVILEGED_EXECUTION gating
        let action_class = classify_action_class(cmd_str);
        assert_eq!(
            action_class, "PRIVILEGED_EXECUTION",
            "Delegated command '{}' must map to PRIVILEGED_EXECUTION",
            cmd_str
        );
    }
}

#[test]
fn test_challenge_benign_query_informational_commands() {
    let test_cases = [
        "sudo -l",
        "sudo -V",
        "sudo -v",
        "sudo -h",
        "sudo --help",
        "sudo --version",
        "su -h",
        "su --help",
        "su -V",
        "su --version",
        "doas -h",
        "doas --help",
        "pkexec --version",
        "pkexec --help",
        "wsl -l",
        "wsl -l -v",
        "wsl --list --verbose",
        "wsl --status",
        "wsl --help",
        "wsl -h",
    ];

    for cmd_str in test_cases {
        let sem = parse_semantic_command(cmd_str);
        assert_eq!(
            sem.privilege_class,
            PrivilegeEquivalenceClass::PrivilegeQueryOrBenign,
            "Benign query '{}' must classify as PrivilegeQueryOrBenign",
            cmd_str
        );
        assert!(
            sem.privilege_class.is_benign_query(),
            "Command '{}' is_benign_query() must be true",
            cmd_str
        );
        assert!(
            !sem.privilege_class.is_privileged_execution(),
            "Benign query '{}' must NOT be classified as privileged execution",
            cmd_str
        );

        // Benign queries must map to READ_PUBLIC, never triggering elevation approval tokens
        let action_class = classify_action_class(cmd_str);
        assert_eq!(
            action_class, "READ_PUBLIC",
            "Benign query '{}' must map to READ_PUBLIC",
            cmd_str
        );
    }
}

#[test]
fn test_challenge_shell_unwrapping_and_env_prefix_stripping() {
    // 1. Environment variable prefix stripping
    let cmd1 = "SUDO_ASKPASS=/bin/false ENV_VAR=123 sudo -n id";
    let sem1 = parse_semantic_command(cmd1);
    assert_eq!(
        sem1.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert!(sem1.is_non_interactive);
    assert_eq!(sem1.env_vars.len(), 2);
    assert_eq!(classify_action_class(cmd1), "PRIVILEGED_EXECUTION");

    // 2. Recursive shell unwrapping
    let cmd2 = r#"bash -c "sudo id""#;
    let sem2 = parse_semantic_command(cmd2);
    assert_eq!(
        sem2.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert_eq!(classify_action_class(cmd2), "PRIVILEGED_EXECUTION");

    let cmd3 = r#"powershell.exe -Command "wsl -u root id""#;
    let sem3 = parse_semantic_command(cmd3);
    assert_eq!(
        sem3.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert!(sem3.is_cross_boundary);
    assert_eq!(classify_action_class(cmd3), "PRIVILEGED_EXECUTION");

    let cmd4 = r#"cmd.exe /c "runas /user:Administrator regedit.exe""#;
    let sem4 = parse_semantic_command(cmd4);
    assert_eq!(
        sem4.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert_eq!(classify_action_class(cmd4), "PRIVILEGED_EXECUTION");
}

// ============================================================================
// SUITE 2: APC Single-Use Approval Token Exhaustion & Concurrent Replay Stress
// ============================================================================

#[test]
fn test_challenge_apc_single_use_token_exhaustion_sequential() {
    let signing_key = b"secret-test-key-32-bytes-apc-challenge!";
    let now = 1700000000;
    let action = "sudo -n id";
    let resource = "system:root";
    let params = "{}";

    let (pdp, env) = create_test_pdp_and_envelope_with_grants(
        signing_key,
        "principal-01",
        "session-01",
        now,
        &[action],
        &[resource],
    );

    let token = ApprovalToken::issue(
        "tok-single-use-001",
        "human-admin-01",
        "principal-01",
        action,
        resource,
        "session-01",
        params,
        now + 300,
        signing_key,
    );

    let req1 = ApcActionRequest {
        actor_id: "principal-01".to_string(),
        action: action.to_string(),
        resource: resource.to_string(),
        data_classification: "INTERNAL".to_string(),
        task_session_id: "session-01".to_string(),
        policy_version: "v1.0".to_string(),
        now_unix: now + 10,
        parameters_canonical: params.to_string(),
        requires_approval: false,
        is_irreversible: false,
        sensitivity_tier: 1,
        is_cross_domain: false,
        cost_delta: 0.0,
        approval_token: Some(token.clone()),
    };

    let intent = permissive_intent();

    // First attempt: MUST SUCCEED
    let dec1 = pdp.evaluate(&env, &intent, &req1);
    assert!(
        dec1.allowed,
        "First evaluation of valid elevation approval token must succeed: {:?}",
        dec1.reason
    );
    assert_eq!(dec1.failed_condition, None);

    // Second attempt with exact same token: MUST BE DENIED AS REPLAY
    let mut req2 = req1.clone();
    req2.now_unix = now + 15;
    let dec2 = pdp.evaluate(&env, &intent, &req2);
    assert!(
        !dec2.allowed,
        "Replay of consumed ApprovalToken must be denied!"
    );
    assert_eq!(
        dec2.failed_condition.as_deref(),
        Some("C4_APPROVAL_REPLAY"),
        "Failed condition must be C4_APPROVAL_REPLAY"
    );
    assert!(
        dec2.reason.contains("Single-use ApprovalToken already consumed"),
        "Reason must state token was consumed: {}",
        dec2.reason
    );
}

#[test]
fn test_challenge_apc_concurrent_token_replay_race_condition() {
    let signing_key = b"secret-test-key-32-bytes-apc-challenge!";
    let now = 1700000000;
    let action = "wsl -u root id";
    let resource = "vm:wsl2";
    let params = "{}";

    let (pdp, env) = create_test_pdp_and_envelope_with_grants(
        signing_key,
        "principal-01",
        "session-01",
        now,
        &[action],
        &[resource],
    );

    let pdp = Arc::new(pdp);
    let env = Arc::new(env);

    let token = ApprovalToken::issue(
        "tok-race-condition-999",
        "human-admin-01",
        "principal-01",
        action,
        resource,
        "session-01",
        params,
        now + 300,
        signing_key,
    );
    let token = Arc::new(token);

    let num_threads = 16;
    let mut handles = Vec::new();

    for i in 0..num_threads {
        let pdp_c = Arc::clone(&pdp);
        let env_c = Arc::clone(&env);
        let tok_c = Arc::clone(&token);

        handles.push(thread::spawn(move || {
            let req = ApcActionRequest {
                actor_id: "principal-01".to_string(),
                action: action.to_string(),
                resource: resource.to_string(),
                data_classification: "INTERNAL".to_string(),
                task_session_id: "session-01".to_string(),
                policy_version: "v1.0".to_string(),
                now_unix: now + 5 + (i as i64),
                parameters_canonical: params.to_string(),
                requires_approval: false,
                is_irreversible: false,
                sensitivity_tier: 1,
                is_cross_domain: false,
                cost_delta: 0.0,
                approval_token: Some((*tok_c).clone()),
            };
            let intent = permissive_intent();
            pdp_c.evaluate(&env_c, &intent, &req)
        }));
    }

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    let allowed_count = results.iter().filter(|r| r.allowed).count();
    let denied_count = results
        .iter()
        .filter(|r| !r.allowed && r.failed_condition.as_deref() == Some("C4_APPROVAL_REPLAY"))
        .count();

    assert_eq!(
        allowed_count, 1,
        "CRITICAL: Exactly ONE thread must successfully consume the single-use token"
    );
    assert_eq!(
        denied_count,
        num_threads - 1,
        "CRITICAL: Exactly {} threads must be rejected with C4_APPROVAL_REPLAY",
        num_threads - 1
    );
}

// ============================================================================
// SUITE 3: APC Expired & Boundary Timestamp Stress Tests
// ============================================================================

#[test]
fn test_challenge_apc_expired_approval_token() {
    let signing_key = b"secret-test-key-32-bytes-apc-challenge!";
    let now = 1700000000;
    let action = "runas /user:Administrator cmd.exe";
    let resource = "host:windows";
    let params = "{}";

    let (pdp, env) = create_test_pdp_and_envelope_with_grants(
        signing_key,
        "principal-01",
        "session-01",
        now,
        &[action],
        &[resource],
    );

    // Expired 1 second ago
    let token = ApprovalToken::issue(
        "tok-expired-001",
        "human-admin-01",
        "principal-01",
        action,
        resource,
        "session-01",
        params,
        now - 1,
        signing_key,
    );

    let req = ApcActionRequest {
        actor_id: "principal-01".to_string(),
        action: action.to_string(),
        resource: resource.to_string(),
        data_classification: "INTERNAL".to_string(),
        task_session_id: "session-01".to_string(),
        policy_version: "v1.0".to_string(),
        now_unix: now,
        parameters_canonical: params.to_string(),
        requires_approval: false,
        is_irreversible: false,
        sensitivity_tier: 1,
        is_cross_domain: false,
        cost_delta: 0.0,
        approval_token: Some(token),
    };

    let intent = permissive_intent();
    let dec = pdp.evaluate(&env, &intent, &req);

    assert!(!dec.allowed, "Expired ApprovalToken must be denied");
    assert_eq!(dec.failed_condition.as_deref(), Some("C4_APPROVAL_EXPIRED"));
    assert!(dec.reason.contains("ApprovalToken has expired"));
}

#[test]
fn test_challenge_apc_envelope_expiry_boundaries() {
    let signing_key = b"secret-test-key-32-bytes-apc-challenge!";
    let now = 1700000000;
    let action = "sudo -n id";
    let resource = "system:root";
    let params = "{}";

    let (pdp, env) = create_test_pdp_and_envelope_with_grants(
        signing_key,
        "principal-01",
        "session-01",
        now,
        &[action],
        &[resource],
    );

    let token = ApprovalToken::issue(
        "tok-bound-001",
        "human-admin-01",
        "principal-01",
        action,
        resource,
        "session-01",
        params,
        now + 7200,
        signing_key,
    );

    // Case A: Request timestamp AFTER envelope expiry (env.expires_at_unix is now + 3600)
    let req_stale = ApcActionRequest {
        actor_id: "principal-01".to_string(),
        action: action.to_string(),
        resource: resource.to_string(),
        data_classification: "INTERNAL".to_string(),
        task_session_id: "session-01".to_string(),
        policy_version: "v1.0".to_string(),
        now_unix: now + 3601, // 1 second past envelope validity
        parameters_canonical: params.to_string(),
        requires_approval: false,
        is_irreversible: false,
        sensitivity_tier: 1,
        is_cross_domain: false,
        cost_delta: 0.0,
        approval_token: Some(token.clone()),
    };

    let intent = permissive_intent();
    let dec_stale = pdp.evaluate(&env, &intent, &req_stale);
    assert!(!dec_stale.allowed);
    assert_eq!(dec_stale.failed_condition.as_deref(), Some("C3_CONTEXT_EXPIRY"));

    // Case B: Request timestamp BEFORE envelope issue time
    let req_future = ApcActionRequest {
        actor_id: "principal-01".to_string(),
        action: action.to_string(),
        resource: resource.to_string(),
        data_classification: "INTERNAL".to_string(),
        task_session_id: "session-01".to_string(),
        policy_version: "v1.0".to_string(),
        now_unix: now - 1, // before issue
        parameters_canonical: params.to_string(),
        requires_approval: false,
        is_irreversible: false,
        sensitivity_tier: 1,
        is_cross_domain: false,
        cost_delta: 0.0,
        approval_token: Some(token),
    };
    let dec_future = pdp.evaluate(&env, &intent, &req_future);
    assert!(!dec_future.allowed);
    assert_eq!(dec_future.failed_condition.as_deref(), Some("C3_CONTEXT_EXPIRY"));
}

// ============================================================================
// SUITE 4: APC Action Hash & HMAC Signature Tampering Defenses
// ============================================================================

#[test]
fn test_challenge_apc_action_hash_mismatch_detection() {
    let signing_key = b"secret-test-key-32-bytes-apc-challenge!";
    let now = 1700000000;

    let (pdp, env) = create_test_pdp_and_envelope_with_grants(
        signing_key,
        "principal-01",
        "session-01",
        now,
        &["sudo cat /tmp/safe_log.txt", "sudo rm -rf /var/log"],
        &["file:/tmp/safe_log.txt"],
    );

    // Issue token for specific command
    let approved_action = "sudo cat /tmp/safe_log.txt";
    let token = ApprovalToken::issue(
        "tok-mismatch-001",
        "human-admin-01",
        "principal-01",
        approved_action,
        "file:/tmp/safe_log.txt",
        "session-01",
        "{}",
        now + 300,
        signing_key,
    );

    // Attacker attempts to use this token for an unauthorized privileged action
    let attacker_action = "sudo rm -rf /var/log";
    let req = ApcActionRequest {
        actor_id: "principal-01".to_string(),
        action: attacker_action.to_string(),
        resource: "file:/tmp/safe_log.txt".to_string(),
        data_classification: "INTERNAL".to_string(),
        task_session_id: "session-01".to_string(),
        policy_version: "v1.0".to_string(),
        now_unix: now + 10,
        parameters_canonical: "{}".to_string(),
        requires_approval: false,
        is_irreversible: false,
        sensitivity_tier: 1,
        is_cross_domain: false,
        cost_delta: 0.0,
        approval_token: Some(token),
    };

    let intent = permissive_intent();
    let dec = pdp.evaluate(&env, &intent, &req);

    assert!(!dec.allowed, "Hash mismatch must be denied");
    assert_eq!(dec.failed_condition.as_deref(), Some("C4_APPROVAL_HASH_MISMATCH"));
    assert!(dec.reason.contains("ApprovalToken action hash does not match"));
}

#[test]
fn test_challenge_apc_signature_tampering_and_forgery() {
    let signing_key = b"secret-test-key-32-bytes-apc-challenge!";
    let now = 1700000000;
    let action = "sudo -n id";
    let resource = "system:root";
    let params = "{}";

    let (pdp, env) = create_test_pdp_and_envelope_with_grants(
        signing_key,
        "principal-01",
        "session-01",
        now,
        &[action],
        &[resource],
    );

    let mut token = ApprovalToken::issue(
        "tok-tamper-001",
        "human-admin-01",
        "principal-01",
        action,
        resource,
        "session-01",
        params,
        now + 300,
        signing_key,
    );

    // Tamper with HMAC signature: flip last byte
    let mut sig_chars: Vec<char> = token.hmac_signature.chars().collect();
    let last_idx = sig_chars.len() - 1;
    sig_chars[last_idx] = if sig_chars[last_idx] == '0' { '1' } else { '0' };
    token.hmac_signature = sig_chars.into_iter().collect();

    let req = ApcActionRequest {
        actor_id: "principal-01".to_string(),
        action: action.to_string(),
        resource: resource.to_string(),
        data_classification: "INTERNAL".to_string(),
        task_session_id: "session-01".to_string(),
        policy_version: "v1.0".to_string(),
        now_unix: now + 10,
        parameters_canonical: params.to_string(),
        requires_approval: false,
        is_irreversible: false,
        sensitivity_tier: 1,
        is_cross_domain: false,
        cost_delta: 0.0,
        approval_token: Some(token),
    };

    let intent = permissive_intent();
    let dec = pdp.evaluate(&env, &intent, &req);

    assert!(!dec.allowed, "Forged HMAC signature must be denied");
    assert_eq!(dec.failed_condition.as_deref(), Some("C4_APPROVAL_SIGNATURE_INVALID"));
    assert!(dec.reason.contains("ApprovalToken HMAC signature invalid"));
}

// ============================================================================
// SUITE 5: APC Capability, Scope Narrowing & Pairwise Composition Defenses
// ============================================================================

#[test]
fn test_challenge_apc_unauthorized_action_outside_scope() {
    let signing_key = b"secret-test-key-32-bytes-apc-challenge!";
    let now = 1700000000;

    let pdp = ApcPolicyDecisionPoint::new(signing_key.to_vec(), "v1.0", true);

    // Narrowed scope ONLY granting search/read tools
    let narrow_scope = ApcScope::new(
        vec!["docs:*", "repo:*"],
        vec!["tool:search", "tool:read"],
        vec!["PUBLIC"],
        vec![],
        vec![],
    );

    let env = AuthorizationEnvelope::new_root(
        "env-narrow-01",
        "principal-01",
        "principal-01",
        "session-01",
        "v1.0",
        narrow_scope,
        DelegationBudgetSpec::default(),
        now,
        now + 3600,
        signing_key,
    );

    let action = "sudo -n id";
    let token = ApprovalToken::issue(
        "tok-scope-fail-001",
        "human-admin-01",
        "principal-01",
        action,
        "repo:main",
        "session-01",
        "{}",
        now + 300,
        signing_key,
    );

    let req = ApcActionRequest {
        actor_id: "principal-01".to_string(),
        action: action.to_string(),
        resource: "repo:main".to_string(),
        data_classification: "PUBLIC".to_string(),
        task_session_id: "session-01".to_string(),
        policy_version: "v1.0".to_string(),
        now_unix: now + 10,
        parameters_canonical: "{}".to_string(),
        requires_approval: false,
        is_irreversible: false,
        sensitivity_tier: 1,
        is_cross_domain: false,
        cost_delta: 0.0,
        approval_token: Some(token),
    };

    let intent = permissive_intent();
    let dec = pdp.evaluate(&env, &intent, &req);

    assert!(
        !dec.allowed,
        "Action outside narrowed capability scope must be denied"
    );
    assert_eq!(dec.failed_condition.as_deref(), Some("C2_SCOPE_ACTION"));
    assert!(dec.reason.contains("not in narrowed scope"));
}

#[test]
fn test_challenge_apc_pairwise_composition_privileged_execution_restrictions() {
    let signing_key = b"secret-test-key-32-bytes-apc-challenge!";
    let now = 1700000000;
    let action_priv = "sudo -n id";
    let res_priv = "system:root";

    let (pdp, env) = create_test_pdp_and_envelope_with_grants(
        signing_key,
        "principal-01",
        "session-01",
        now,
        &[action_priv, "tool:read_confidential_database"],
        &[res_priv, "db:production"],
    );
    let intent = permissive_intent();

    // Step 1: Perform READ_CONFIDENTIAL
    let req_read = ApcActionRequest {
        actor_id: "principal-01".to_string(),
        action: "tool:read_confidential_database".to_string(),
        resource: "db:production".to_string(),
        data_classification: "CONFIDENTIAL".to_string(),
        task_session_id: "session-01".to_string(),
        policy_version: "v1.0".to_string(),
        now_unix: now + 5,
        parameters_canonical: "{}".to_string(),
        requires_approval: false,
        is_irreversible: false,
        sensitivity_tier: 2,
        is_cross_domain: false,
        cost_delta: 0.0,
        approval_token: None,
    };
    let dec_read = pdp.evaluate(&env, &intent, &req_read);
    assert!(dec_read.allowed, "READ_CONFIDENTIAL step 1 must succeed: {:?}", dec_read.reason);

    // Step 2: Attempt PRIVILEGED_EXECUTION (e.g. sudo -n id)
    // Even with a valid ApprovalToken, composition rule MUST DENY!
    let token = ApprovalToken::issue(
        "tok-comp-001",
        "human-admin-01",
        "principal-01",
        action_priv,
        res_priv,
        "session-01",
        "{}",
        now + 300,
        signing_key,
    );

    let req_priv = ApcActionRequest {
        actor_id: "principal-01".to_string(),
        action: action_priv.to_string(),
        resource: res_priv.to_string(),
        data_classification: "INTERNAL".to_string(),
        task_session_id: "session-01".to_string(),
        policy_version: "v1.0".to_string(),
        now_unix: now + 10,
        parameters_canonical: "{}".to_string(),
        requires_approval: false,
        is_irreversible: false,
        sensitivity_tier: 1,
        is_cross_domain: false,
        cost_delta: 0.0,
        approval_token: Some(token),
    };

    let dec_priv = pdp.evaluate(&env, &intent, &req_priv);
    assert!(
        !dec_priv.allowed,
        "PRIVILEGED_EXECUTION after READ_CONFIDENTIAL must be DENIED by composition rule!"
    );
    assert_eq!(dec_priv.failed_condition.as_deref(), Some("C2_COMPOSITION"));
    assert!(
        dec_priv.reason.contains("no_privileged_execution_after_confidential_read"),
        "Reason must name the violated pairwise restriction: {}",
        dec_priv.reason
    );
}

// ============================================================================
// SUITE 6: Dynamic Binary Probing: Renamed Binaries with POSIX SUID & Linux Caps
// ============================================================================

#[test]
fn test_challenge_dynamic_binary_probe_posix_suid_renamed_executable() {
    // Renamed binary "harmless_calculator" carrying SUID (0o4000) and root UID (0)
    let mode_suid_root = 0o4755;
    let file_uid_root = 0;
    let probe_root = DynamicBinaryMetadataProbe::from_posix(mode_suid_root, file_uid_root, 0);

    assert!(probe_root.is_privileged_target());
    assert!(probe_root.is_suid);
    assert_eq!(probe_root.file_uid, 0);

    // Parse command using probe
    let cmd = parse_semantic_command_with_probe(
        "/usr/local/bin/harmless_calculator --calculate",
        Some(&probe_root),
    );

    assert_eq!(
        cmd.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        "Renamed SUID root executable must resolve to RootOrAdminElevation"
    );
    assert!(cmd.privilege_class.is_privileged_execution());
    assert!(cmd.privilege_class.is_root_or_admin());

    // SGID only (0o2000) without SUID -> UnprivilegedStandard
    let mode_sgid_only = 0o2755;
    let probe_sgid = DynamicBinaryMetadataProbe::from_posix(mode_sgid_only, 0, 0);
    let cmd_sgid = parse_semantic_command_with_probe(
        "/usr/local/bin/mail_spooler --check",
        Some(&probe_sgid),
    );

    assert_eq!(
        cmd_sgid.privilege_class,
        PrivilegeEquivalenceClass::UnprivilegedStandard,
        "SGID only must NOT escalate to RootOrAdminElevation"
    );
}

#[test]
fn test_challenge_dynamic_binary_probe_linux_capabilities_mask() {
    // Binary with Linux CAP_SETUID (0x80)
    let cap_mask = 0x80u64;
    let probe_cap = DynamicBinaryMetadataProbe::from_posix(0o0755, 1000, cap_mask);

    assert!(probe_cap.has_linux_capabilities);
    assert!(probe_cap.is_privileged_target());

    let cmd = parse_semantic_command_with_probe(
        "/tmp/custom_container_helper --fork",
        Some(&probe_cap),
    );

    assert_eq!(
        cmd.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        "Linux capability mask must dynamically classify binary as RootOrAdminElevation"
    );
    assert!(cmd.privilege_class.is_privileged_execution());
}

// ============================================================================
// SUITE 7: Dynamic Binary Probing: Renamed Windows PE `requireAdministrator`
// ============================================================================

#[test]
fn test_challenge_dynamic_binary_probe_windows_pe_manifest_utf8_on_disk() {
    let mut temp = NamedTempFile::new().unwrap();

    let manifest = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>"#;

    // Write PE stub header followed by manifest XML
    temp.write_all(b"MZ\x90\x00PE\x00\x00").unwrap();
    temp.write_all(manifest.as_bytes()).unwrap();
    temp.flush().unwrap();

    let path = temp.path();

    // 1. Probe path directly
    let probe = DynamicBinaryMetadataProbe::probe_path(path).unwrap();
    assert_eq!(
        probe.elevation_requirement,
        ElevationRequirement::RequireAdministrator
    );
    assert!(probe.is_privileged_target());

    // 2. Call parse_semantic_command using forward-slashed path (POSIX/normalized)
    let fwd_path = path.to_str().unwrap().replace('\\', "/");
    let cmd_str = format!("\"{}\" --install-service", fwd_path);
    let sem = parse_semantic_command(&cmd_str);

    assert_eq!(
        sem.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        "Renamed executable with requireAdministrator manifest must resolve to RootOrAdminElevation"
    );
    assert!(sem.privilege_class.is_privileged_execution());

    // 3. Verify classify_action_class identifies this as PRIVILEGED_EXECUTION
    let action_class = classify_action_class(&cmd_str);
    assert_eq!(
        action_class, "PRIVILEGED_EXECUTION",
        "Action class for renamed requireAdministrator binary must be PRIVILEGED_EXECUTION"
    );

    // 4. Immunity check: verify it cannot receive blanket target immunity
    assert!(
        killswitch_adjudication::immunity::inspect_process_lineage(
            9999,
            Some(path.to_str().unwrap())
        ) != killswitch_adjudication::LineageImmunityVerdict::ImmuneTarget {
            pid: 9999,
            proc_name: path.to_str().unwrap().to_string()
        },
        "Renamed PE with requireAdministrator must NEVER receive blanket target immunity!"
    );
}

#[test]
fn test_challenge_dynamic_binary_probe_windows_pe_manifest_utf16le() {
    let mut temp = NamedTempFile::new().unwrap();

    let manifest_utf8 = r#"<requestedPrivileges><requestedExecutionLevel level="highestAvailable" uiAccess="false"/></requestedPrivileges>"#;
    let mut utf16_bytes = Vec::new();
    for ch in manifest_utf8.encode_utf16() {
        utf16_bytes.extend_from_slice(&ch.to_le_bytes());
    }

    temp.write_all(b"MZ\x00\x00").unwrap();
    temp.write_all(&utf16_bytes).unwrap();
    temp.flush().unwrap();

    let path = temp.path();
    let probe = DynamicBinaryMetadataProbe::probe_path(path).unwrap();

    assert_eq!(
        probe.elevation_requirement,
        ElevationRequirement::HighestAvailable
    );
    assert!(probe.is_privileged_target());

    let fwd_path = path.to_str().unwrap().replace('\\', "/");
    let cmd_str = format!("\"{}\" --update", fwd_path);
    let sem = parse_semantic_command(&cmd_str);
    assert_eq!(
        sem.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
}

#[test]
fn test_challenge_dynamic_binary_probe_as_invoker_not_privileged() {
    let mut temp = NamedTempFile::new().unwrap();

    let manifest = r#"<requestedExecutionLevel level="asInvoker" uiAccess="false"/>"#;
    temp.write_all(b"MZ\x00\x00").unwrap();
    temp.write_all(manifest.as_bytes()).unwrap();
    temp.flush().unwrap();

    let path = temp.path();
    let probe = DynamicBinaryMetadataProbe::probe_path(path).unwrap();

    assert_eq!(
        probe.elevation_requirement,
        ElevationRequirement::AsInvoker
    );
    assert!(!probe.is_privileged_target());

    let fwd_path = path.to_str().unwrap().replace('\\', "/");
    let cmd_str = format!("\"{}\" --check", fwd_path);
    let sem = parse_semantic_command(&cmd_str);
    assert_eq!(
        sem.privilege_class,
        PrivilegeEquivalenceClass::UnprivilegedStandard
    );
    assert!(!sem.privilege_class.is_privileged_execution());
}

#[test]
fn test_challenge_dynamic_binary_probe_wsl_and_hyperv_imports() {
    let mut temp = NamedTempFile::new().unwrap();

    let mock_pe = b"MZ\x90\x00PE\x00\x00Importing WSLAPI.DLL and VMCOMPUTE.DLL for container boundary crossing";
    temp.write_all(mock_pe).unwrap();
    temp.flush().unwrap();

    let path = temp.path();
    let probe = DynamicBinaryMetadataProbe::probe_path(path).unwrap();

    assert!(probe.invokes_wsl_subsystem);
    assert!(probe.invokes_hyperv_compute);
    assert!(probe.is_privileged_target());

    let fwd_path = path.to_str().unwrap().replace('\\', "/");
    let cmd_str = format!("\"{}\" --start-session", fwd_path);
    let sem = parse_semantic_command(&cmd_str);

    assert_eq!(
        sem.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert!(sem.is_cross_boundary);
}

// ============================================================================
// SUITE 8: End-to-End APC + Dynamic Probing Integration Stress
// ============================================================================

#[test]
fn test_challenge_apc_e2e_renamed_executable_requires_token_and_enforces_lifecycle() {
    let signing_key = b"secret-test-key-32-bytes-apc-challenge!";
    let now = 1700000000;
    let intent = permissive_intent();

    // Create a renamed executable on disk with requireAdministrator manifest
    let mut temp = NamedTempFile::new().unwrap();
    let manifest = r#"<requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>"#;
    temp.write_all(b"MZ\x90\x00PE\x00\x00").unwrap();
    temp.write_all(manifest.as_bytes()).unwrap();
    temp.flush().unwrap();

    let binary_path = temp.path().to_str().unwrap().replace('\\', "/");
    let cmd_str = format!("\"{}\" --escalate", binary_path);
    let resource = "service:host";

    let (pdp, env) = create_test_pdp_and_envelope_with_grants(
        signing_key,
        "principal-01",
        "session-01",
        now,
        &[&cmd_str, "tool:send_webhook_exfiltration"],
        &[resource, "endpoint:attacker.com"],
    );

    // Case 1: Agent calls this innocent-looking renamed binary WITHOUT an ApprovalToken
    let req_no_token = ApcActionRequest {
        actor_id: "principal-01".to_string(),
        action: cmd_str.clone(),
        resource: resource.to_string(),
        data_classification: "INTERNAL".to_string(),
        task_session_id: "session-01".to_string(),
        policy_version: "v1.0".to_string(),
        now_unix: now + 10,
        parameters_canonical: "{}".to_string(),
        requires_approval: false, // Agent claims false, but dynamic probe overrides!
        is_irreversible: false,
        sensitivity_tier: 1,
        is_cross_domain: false,
        cost_delta: 0.0,
        approval_token: None,
    };

    let dec_no_token = pdp.evaluate(&env, &intent, &req_no_token);
    assert!(
        !dec_no_token.allowed,
        "Renamed binary requiring administrator MUST BE DENIED when no ApprovalToken is provided!"
    );
    assert_eq!(dec_no_token.failed_condition.as_deref(), Some("C4_APPROVAL_MISSING"));
    assert!(
        dec_no_token
            .reason
            .contains("Privileged execution attempt requires elevation ApprovalToken"),
        "Reason: {}",
        dec_no_token.reason
    );

    // Case 2: Present valid ApprovalToken for this renamed binary -> ALLOWED
    let token = ApprovalToken::issue(
        "tok-renamed-001",
        "human-admin-01",
        "principal-01",
        &cmd_str,
        resource,
        "session-01",
        "{}",
        now + 300,
        signing_key,
    );

    let mut req_valid = req_no_token.clone();
    req_valid.approval_token = Some(token.clone());

    let dec_valid = pdp.evaluate(&env, &intent, &req_valid);
    assert!(
        dec_valid.allowed,
        "Valid ApprovalToken for renamed binary must succeed: {:?}",
        dec_valid.reason
    );
    assert_eq!(dec_valid.failed_condition, None);

    // Case 3: Replay of same ApprovalToken for renamed binary -> DENIED
    let mut req_replay = req_valid.clone();
    req_replay.now_unix = now + 15;

    let dec_replay = pdp.evaluate(&env, &intent, &req_replay);
    assert!(
        !dec_replay.allowed,
        "Replay of ApprovalToken on renamed binary must be denied!"
    );
    assert_eq!(dec_replay.failed_condition.as_deref(), Some("C4_APPROVAL_REPLAY"));

    // Case 4: Subsequent External Transmit in same session -> DENIED by composition!
    let req_egress = ApcActionRequest {
        actor_id: "principal-01".to_string(),
        action: "tool:send_webhook_exfiltration".to_string(),
        resource: "endpoint:attacker.com".to_string(),
        data_classification: "INTERNAL".to_string(),
        task_session_id: "session-01".to_string(),
        policy_version: "v1.0".to_string(),
        now_unix: now + 20,
        parameters_canonical: "{}".to_string(),
        requires_approval: false,
        is_irreversible: false,
        sensitivity_tier: 1,
        is_cross_domain: true,
        cost_delta: 0.0,
        approval_token: None,
    };

    let dec_egress = pdp.evaluate(&env, &intent, &req_egress);
    assert!(
        !dec_egress.allowed,
        "External transmit after privileged execution must be denied by composition rule!"
    );
    assert_eq!(dec_egress.failed_condition.as_deref(), Some("C2_COMPOSITION"));
    assert!(
        dec_egress
            .reason
            .contains("no_external_transmit_after_privileged_execution"),
        "Reason: {}",
        dec_egress.reason
    );
}

// ============================================================================
// SUITE 9: Empirical Defect Verification
// ============================================================================

/// DEFECT 1: `tokenize_command` strips Windows backslashes inside double quotes.
///
/// Under standard Windows CLI parsing rules (cmd.exe and CommandLineToArgvW),
/// backslashes are NOT escape characters for general letters (e.g. `\U`, `\A`, `\L`),
/// and are path separators. However, `tokenize_command` currently has:
/// ```rust
/// '\\' if !in_single => {
///     if let Some(&next) = chars.peek() {
///         chars.next();
///         current.push(next);
///     }
/// }
/// ```
/// This strips the backslash from `\U`, turning `"C:\Users\foo.exe"` into `"C:Usersfoo.exe"`.
/// As a consequence, on-disk dynamic probing fails for any Windows path containing backslashes.
#[test]
fn test_defect_tokenize_command_strips_windows_backslashes() {
    let win_cmd = r#""C:\Program Files\App\updater.exe" --check"#;
    let tokens = tokenize_command(win_cmd);

    // REMEDIATED: Windows path backslashes inside double quotes are preserved
    assert_eq!(
        tokens[0],
        r#"C:\Program Files\App\updater.exe"#,
        "Remediated: Backslashes in quoted path are preserved"
    );
    assert_eq!(tokens[1], "--check");
}

/// DEFECT 2 REMEDIATED: `is_privileged_target` gate allows `TargetUserDelegation` for non-root SUID in dynamic probe.
#[test]
fn test_defect_non_root_suid_target_user_delegation_unreachable() {
    let mode_suid_user = 0o4755;
    let file_uid_user = 1001; // Non-root user (e.g. www-data or service account)
    let probe_user = DynamicBinaryMetadataProbe::from_posix(mode_suid_user, file_uid_user, 0);

    // Confirm that is_privileged_target() returns true for non-root SUID:
    assert!(
        probe_user.is_privileged_target(),
        "Remediated: is_privileged_target() returns true for non-root SUID"
    );

    // Confirm that parse_semantic_command_with_probe classifies as TargetUserDelegation:
    let cmd = parse_semantic_command_with_probe(
        "/usr/local/bin/service_worker --run",
        Some(&probe_user),
    );

    assert_eq!(
        cmd.privilege_class,
        PrivilegeEquivalenceClass::TargetUserDelegation,
        "Remediated: Non-root SUID is classified as TargetUserDelegation"
    );
}
