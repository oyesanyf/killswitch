//! Empirical Challenge Test Suite for Milestone SEC-2
//!
//! Scope:
//! 1. Challenge `SemanticCommand` parser against heavily obfuscated command lines:
//!    - Mixed quotes, multiple spaces, env prefixes (`FOO=1 BAR=2 sudo id`),
//!    - Chained commands (`sh -c "sudo id"`), non-standard flags, symlinks, renamed binaries.
//! 2. Challenge Bounded Agents APC:
//!    - Attempt to slip privileged commands through to `READ_PUBLIC` using obscure variants or casing (`SUDO`, `DoAs`, `PkExec`, `wsl.exe -u root`).
//! 3. Verify pairwise rules:
//!    - Privileged execution blocked after confidential read within-session and cross-session lineage.
//!    - Test evasion resistance against flagged combinations.
//! 4. Dynamic binary metadata probing and immunity decoupling.

use killswitch_telemetry::bounded_agents_apc::{
    classify_action_class, default_enterprise_apc_scope, ApcActionRequest, ApcPolicyDecisionPoint,
    ApprovalToken, AuthorizationEnvelope, DelegationBudgetSpec, IntentEnforcementMode, IntentSpec,
};
use killswitch_telemetry::semantic_command::{
    parse_semantic_command, parse_semantic_command_with_probe, tokenize_command,
    DynamicBinaryMetadataProbe, ElevationRequirement, PrivilegeEquivalenceClass,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

fn permissive_intent() -> IntentSpec {
    IntentSpec {
        intent_id: "intent-permissive".to_string(),
        intended_actions: BTreeSet::from(["*".to_string()]),
        intended_resources: BTreeSet::from(["*".to_string()]),
        action_resource_map: BTreeMap::new(),
        mode: IntentEnforcementMode::Strict,
    }
}

// ============================================================================
// SUITE 1: Heavily Obfuscated Command Lines & Parsing Edge Cases
// ============================================================================

#[test]
fn test_challenge_tokenize_mixed_quotes_and_spaces() {
    // Mixed quotes inside command tokens: 's'"u"'d'o
    let tokens = tokenize_command("'s'\"u\"'d'o   -n    id");
    assert_eq!(tokens, vec!["sudo", "-n", "id"]);

    let cmd = parse_semantic_command("'s'\"u\"'d'o   -n    id");
    assert_eq!(
        cmd.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert!(cmd.is_non_interactive);
    assert_eq!(cmd.executable, "sudo");

    // Multiple spaces and tabs
    let tokens2 = tokenize_command("  \t  sudo   \t  -n   \t  id  \t ");
    assert_eq!(tokens2, vec!["sudo", "-n", "id"]);

    let cmd2 = parse_semantic_command("  \t  sudo   \t  -n   \t  id  \t ");
    assert_eq!(
        cmd2.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
}

#[test]
fn test_challenge_env_variable_prefixes_adversarial() {
    // Multiple env variables with quotes and special characters
    let raw = r#"FOO=1 BAR="baz qux" SUDO_ASKPASS='/bin/false' KEY_123=val456 sudo -n id"#;
    let cmd = parse_semantic_command(raw);
    assert_eq!(
        cmd.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert_eq!(cmd.executable, "sudo");
    assert_eq!(cmd.env_vars.len(), 4);
    assert_eq!(cmd.env_vars[0], ("FOO".to_string(), "1".to_string()));
    assert_eq!(cmd.env_vars[1], ("BAR".to_string(), "baz qux".to_string()));
    assert_eq!(
        cmd.env_vars[2],
        ("SUDO_ASKPASS".to_string(), "/bin/false".to_string())
    );
    assert_eq!(
        cmd.env_vars[3],
        ("KEY_123".to_string(), "val456".to_string())
    );
    assert!(cmd.is_non_interactive);
}

#[test]
fn test_challenge_chained_and_nested_shells() {
    // Standard sh -c
    let cmd_sh = parse_semantic_command("sh -c \"sudo id\"");
    assert_eq!(
        cmd_sh.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert_eq!(cmd_sh.executable, "sudo");

    // bash -c with single quotes
    let cmd_bash = parse_semantic_command("bash -c 'wsl -u root id'");
    assert_eq!(
        cmd_bash.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert!(cmd_bash.is_cross_boundary);

    // cmd.exe /c
    let cmd_cmd = parse_semantic_command("cmd.exe /c \"runas /user:Administrator whoami\"");
    assert_eq!(
        cmd_cmd.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );

    // powershell.exe -Command
    let cmd_ps = parse_semantic_command("powershell.exe -Command \"sudo id\"");
    assert_eq!(
        cmd_ps.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );

    // Nested shell: sh -c "bash -c 'sudo id'"
    let cmd_nested = parse_semantic_command("sh -c \"bash -c 'sudo id'\"");
    assert_eq!(
        cmd_nested.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert_eq!(cmd_nested.executable, "sudo");
}

#[test]
fn test_challenge_target_user_delegation_variants() {
    // sudo -u username
    let cmd1 = parse_semantic_command("sudo -u www-data ls");
    assert_eq!(
        cmd1.privilege_class,
        PrivilegeEquivalenceClass::TargetUserDelegation
    );
    assert_eq!(cmd1.target_user.as_deref(), Some("www-data"));

    // sudo -u0 (root explicitly by UID)
    let cmd2 = parse_semantic_command("sudo -u0 id");
    assert_eq!(
        cmd2.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );

    // sudo --user=daemon
    let cmd3 = parse_semantic_command("sudo --user=daemon cat /dev/null");
    assert_eq!(
        cmd3.privilege_class,
        PrivilegeEquivalenceClass::TargetUserDelegation
    );
    assert_eq!(cmd3.target_user.as_deref(), Some("daemon"));

    // su with non-root user
    let cmd4 = parse_semantic_command("su alice");
    assert_eq!(
        cmd4.privilege_class,
        PrivilegeEquivalenceClass::TargetUserDelegation
    );
    assert_eq!(cmd4.target_user.as_deref(), Some("alice"));

    // su - (root)
    let cmd5 = parse_semantic_command("su -");
    assert_eq!(
        cmd5.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );

    // runas /user:Administrator
    let cmd6 = parse_semantic_command("runas /user:Administrator cmd.exe");
    assert_eq!(
        cmd6.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );

    // runas /user:bob
    let cmd7 = parse_semantic_command("runas /user:bob calc.exe");
    assert_eq!(
        cmd7.privilege_class,
        PrivilegeEquivalenceClass::TargetUserDelegation
    );
    assert_eq!(cmd7.target_user.as_deref(), Some("bob"));

    // wsl -u root
    let cmd8 = parse_semantic_command("wsl -u root id");
    assert_eq!(
        cmd8.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert!(cmd8.is_cross_boundary);

    // wsl -u 0
    let cmd9 = parse_semantic_command("wsl -u 0 whoami");
    assert_eq!(
        cmd9.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );

    // wsl --user guest
    let cmd10 = parse_semantic_command("wsl --user guest bash");
    assert_eq!(
        cmd10.privilege_class,
        PrivilegeEquivalenceClass::TargetUserDelegation
    );
    assert!(cmd10.is_cross_boundary);
}

// ============================================================================
// SUITE 2: Casing, Obscure Binary Names, and APC Fallthrough Resistance
// ============================================================================

#[test]
fn test_challenge_casing_variations_and_apc_classification() {
    let variants = [
        "SUDO id",
        "Sudo -n id",
        "sUdO -n id",
        "DOAS rm /var/log/syslog",
        "DoAs ls",
        "PKEXEC bash",
        "PkExec id",
        "WSL.EXE -u root id",
        "Wsl.Exe -u 0 id",
        "WSL -u root id",
        "RunAs /user:Administrator cmd.exe",
        "RUNAS /user:SYSTEM powershell.exe",
        "SU -",
        "Su -",
    ];

    for v in variants {
        let sem = parse_semantic_command(v);
        assert!(
            sem.privilege_class.is_privileged_execution(),
            "Expected '{}' to be privileged execution, got {:?}",
            v,
            sem.privilege_class
        );

        let action_class = classify_action_class(v);
        assert_eq!(
            action_class, "PRIVILEGED_EXECUTION",
            "CRITICAL: Variant '{}' slipped past APC classifier into '{}'",
            v, action_class
        );
    }
}

#[test]
fn test_challenge_benign_query_casing_and_flags() {
    let benign_queries = [
        "sudo -l",
        "sudo -V",
        "sudo --version",
        "sudo -h",
        "sudo --help",
        "wsl -l -v",
        "WSL --list --verbose",
        "wsl --status",
        "pkexec --version",
        "pkexec --help",
        "su --help",
        "su -V",
        "doas -V",
    ];

    for b in benign_queries {
        let sem = parse_semantic_command(b);
        assert_eq!(
            sem.privilege_class,
            PrivilegeEquivalenceClass::PrivilegeQueryOrBenign,
            "Benign query '{}' misclassified as {:?}",
            b,
            sem.privilege_class
        );

        let apc_class = classify_action_class(b);
        assert_eq!(
            apc_class, "READ_PUBLIC",
            "Benign query '{}' should classify as READ_PUBLIC in APC",
            b
        );
    }
}

// ============================================================================
// SUITE 3: Dynamic Binary Metadata Probing & Renamed Executables
// ============================================================================

#[test]
fn test_challenge_dynamic_binary_probe_suid_and_pe_manifest() {
    let dir = tempdir().unwrap();

    // 1. Renamed executable with SUID root
    let suid_probe = DynamicBinaryMetadataProbe::from_posix(0o104755, 0, 0);
    assert!(suid_probe.is_privileged_target());
    let cmd1 = parse_semantic_command_with_probe("/opt/custom/helper id", Some(&suid_probe));
    assert_eq!(
        cmd1.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );

    // 2. Renamed binary with PE manifest requireAdministrator
    let pe_manifest = r#"
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
            <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
                <security>
                    <requestedPrivileges>
                        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
                    </requestedPrivileges>
                </security>
            </trustInfo>
        </assembly>
    "#;
    let pe_probe = DynamicBinaryMetadataProbe::from_pe_manifest(pe_manifest, &[]);
    assert_eq!(
        pe_probe.elevation_requirement,
        ElevationRequirement::RequireAdministrator
    );
    assert!(pe_probe.is_privileged_target());

    let pe_file_path = dir.path().join("renamed_tool.exe");
    {
        let mut f = File::create(&pe_file_path).unwrap();
        f.write_all(pe_manifest.as_bytes()).unwrap();
    }

    let cmd2 = parse_semantic_command_with_probe(pe_file_path.to_str().unwrap(), Some(&pe_probe));
    assert_eq!(
        cmd2.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );

    // 3. Probing directly from file bytes on disk
    let on_disk_probe = DynamicBinaryMetadataProbe::probe_path(&pe_file_path).unwrap();
    assert_eq!(
        on_disk_probe.elevation_requirement,
        ElevationRequirement::RequireAdministrator
    );
    assert!(on_disk_probe.is_privileged_target());
}

// ============================================================================
// SUITE 4: Bounded Agents APC Condition C4 Elevation Token Enforcement
// ============================================================================

#[test]
fn test_challenge_bounded_agents_apc_c4_denies_elevation_without_token() {
    let key = b"test-signing-key-32bytes-secret!";
    let pdp = ApcPolicyDecisionPoint::new(key.to_vec(), "v1.0", true);
    let mut scope = default_enterprise_apc_scope();
    scope.actions.insert("sudo -n id".to_string());
    scope.actions.insert("wsl -u root whoami".to_string());
    scope
        .actions
        .insert("runas /user:Administrator cmd.exe".to_string());
    scope.actions.insert("su -".to_string());
    scope.actions.insert("doas rm /tmp/test".to_string());
    scope.actions.insert("pkexec /bin/sh".to_string());
    scope.resources.insert("internal/exec".to_string());

    let envelope = AuthorizationEnvelope::new_root(
        "env-root",
        "principal-alice",
        "actor-agent",
        "session-100",
        "v1.0",
        scope,
        DelegationBudgetSpec::default(),
        1000,
        2000,
        key,
    );

    let intent = permissive_intent();

    let privileged_commands = [
        "sudo -n id",
        "wsl -u root whoami",
        "runas /user:Administrator cmd.exe",
        "su -",
        "doas rm /tmp/test",
        "pkexec /bin/sh",
    ];

    for cmd in privileged_commands {
        let req = ApcActionRequest {
            actor_id: "actor-agent".to_string(),
            action: cmd.to_string(),
            resource: "internal/exec".to_string(),
            data_classification: "INTERNAL".to_string(),
            parameters_canonical: "{}".to_string(),
            task_session_id: "session-100".to_string(),
            policy_version: "v1.0".to_string(),
            now_unix: 1500,
            requires_approval: false, // Adversary attempts to omit flag
            approval_token: None,     // No elevation token provided
            is_irreversible: false,
            sensitivity_tier: 1,
            is_cross_domain: false,
            cost_delta: 0.1,
        };

        let decision = pdp.evaluate(&envelope, &intent, &req);
        assert!(
            !decision.allowed,
            "CRITICAL: Privileged command '{}' was ALLOWED without elevation approval token!",
            cmd
        );
        assert_eq!(
            decision.failed_condition.as_deref(),
            Some("C4_APPROVAL_MISSING"),
            "Expected failure on C4_APPROVAL_MISSING for '{}', got {:?}",
            cmd,
            decision.failed_condition
        );
    }
}

#[test]
fn test_challenge_bounded_agents_apc_c4_allows_with_valid_single_use_token() {
    let key = b"test-signing-key-32bytes-secret!";
    let pdp = ApcPolicyDecisionPoint::new(key.to_vec(), "v1.0", true);
    let mut scope = default_enterprise_apc_scope();
    scope.actions.insert("sudo -n id".to_string());
    scope.resources.insert("internal/exec".to_string());

    let envelope = AuthorizationEnvelope::new_root(
        "env-root-2",
        "principal-alice",
        "actor-agent",
        "session-200",
        "v1.0",
        scope,
        DelegationBudgetSpec::default(),
        1000,
        2000,
        key,
    );

    let intent = permissive_intent();

    let token = ApprovalToken::issue(
        "token-elev-1",
        "approver-human",
        "actor-agent",
        "sudo -n id",
        "internal/exec",
        "session-200",
        "{}",
        1900,
        key,
    );

    let req = ApcActionRequest {
        actor_id: "actor-agent".to_string(),
        action: "sudo -n id".to_string(),
        resource: "internal/exec".to_string(),
        data_classification: "INTERNAL".to_string(),
        parameters_canonical: "{}".to_string(),
        task_session_id: "session-200".to_string(),
        policy_version: "v1.0".to_string(),
        now_unix: 1500,
        requires_approval: true,
        approval_token: Some(token.clone()),
        is_irreversible: false,
        sensitivity_tier: 1,
        is_cross_domain: false,
        cost_delta: 0.1,
    };

    let decision = pdp.evaluate(&envelope, &intent, &req);
    assert!(
        decision.allowed,
        "Valid approval token should permit elevation: {:?}",
        decision.reason
    );

    // Replay attack with same single-use token MUST be rejected
    let decision_replay = pdp.evaluate(&envelope, &intent, &req);
    assert!(
        !decision_replay.allowed,
        "Replay attack with consumed single-use token MUST be rejected!"
    );
    assert_eq!(
        decision_replay.failed_condition.as_deref(),
        Some("C4_APPROVAL_REPLAY")
    );
}

// ============================================================================
// SUITE 5: Pairwise Composition Restrictions (READ_CONFIDENTIAL -> PRIVILEGED_EXECUTION)
// ============================================================================

#[test]
fn test_challenge_pairwise_privileged_execution_after_confidential_read() {
    let key = b"test-signing-key-32bytes-secret!";
    let pdp = ApcPolicyDecisionPoint::new(key.to_vec(), "v1.0", true);
    let mut scope = default_enterprise_apc_scope();
    scope.actions.insert("sudo -n id".to_string());
    scope.resources.insert("internal/exec".to_string());

    let envelope = AuthorizationEnvelope::new_root(
        "env-pw-1",
        "principal-carol",
        "actor-agent",
        "session-pw",
        "v1.0",
        scope,
        DelegationBudgetSpec::default(),
        1000,
        2000,
        key,
    );

    let intent = permissive_intent();

    // 1. Step 1: Read confidential data
    let req_read = ApcActionRequest {
        actor_id: "actor-agent".to_string(),
        action: "read_confidential".to_string(),
        resource: "docs/confidential.txt".to_string(),
        data_classification: "CONFIDENTIAL".to_string(),
        parameters_canonical: "{}".to_string(),
        task_session_id: "session-pw".to_string(),
        policy_version: "v1.0".to_string(),
        now_unix: 1100,
        requires_approval: false,
        approval_token: None,
        is_irreversible: false,
        sensitivity_tier: 2,
        is_cross_domain: false,
        cost_delta: 0.0,
    };

    let dec_read = pdp.evaluate(&envelope, &intent, &req_read);
    assert!(
        dec_read.allowed,
        "Confidential read should succeed: {:?}",
        dec_read.reason
    );

    // 2. Step 2: Attempt privileged execution in same session (even with valid token)
    let token = ApprovalToken::issue(
        "token-elev-pw",
        "approver-human",
        "actor-agent",
        "sudo -n id",
        "internal/exec",
        "session-pw",
        "{}",
        1900,
        key,
    );

    let req_elev = ApcActionRequest {
        actor_id: "actor-agent".to_string(),
        action: "sudo -n id".to_string(),
        resource: "internal/exec".to_string(),
        data_classification: "INTERNAL".to_string(),
        parameters_canonical: "{}".to_string(),
        task_session_id: "session-pw".to_string(),
        policy_version: "v1.0".to_string(),
        now_unix: 1200,
        requires_approval: true,
        approval_token: Some(token),
        is_irreversible: false,
        sensitivity_tier: 2,
        is_cross_domain: false,
        cost_delta: 0.1,
    };

    let dec_elev = pdp.evaluate(&envelope, &intent, &req_elev);
    assert!(
        !dec_elev.allowed,
        "CRITICAL: Privileged execution was permitted after confidential read!"
    );
    assert_eq!(
        dec_elev.failed_condition.as_deref(),
        Some("C2_COMPOSITION"),
        "Expected failure on C2_COMPOSITION, got {:?}",
        dec_elev.failed_condition
    );
    assert!(
        dec_elev
            .reason
            .contains("no_privileged_execution_after_confidential_read"),
        "Expected pairwise violation rule ID in reason: {}",
        dec_elev.reason
    );
}

#[test]
fn test_challenge_cross_session_lineage_blocks_privileged_execution_after_confidential_read() {
    let key = b"test-signing-key-32bytes-secret!";
    let pdp = ApcPolicyDecisionPoint::new(key.to_vec(), "v1.0", true);
    let mut scope = default_enterprise_apc_scope();
    scope.actions.insert("wsl -u root id".to_string());
    scope.resources.insert("internal/exec".to_string());

    // Session 1: Root principal carol performs confidential read
    let envelope1 = AuthorizationEnvelope::new_root(
        "env-sess-1",
        "principal-carol-lineage",
        "actor-agent-1",
        "session-lineage-1",
        "v1.0",
        scope.clone(),
        DelegationBudgetSpec::default(),
        1000,
        2000,
        key,
    );

    let intent = permissive_intent();

    let req1 = ApcActionRequest {
        actor_id: "actor-agent-1".to_string(),
        action: "read_confidential".to_string(),
        resource: "docs/secret.txt".to_string(),
        data_classification: "CONFIDENTIAL".to_string(),
        parameters_canonical: "{}".to_string(),
        task_session_id: "session-lineage-1".to_string(),
        policy_version: "v1.0".to_string(),
        now_unix: 1100,
        requires_approval: false,
        approval_token: None,
        is_irreversible: false,
        sensitivity_tier: 2,
        is_cross_domain: false,
        cost_delta: 0.0,
    };

    let dec1 = pdp.evaluate(&envelope1, &intent, &req1);
    assert!(dec1.allowed, "Session 1 read should succeed");

    // Session 2: Fresh session, but same root principal (cross-session lineage attack)
    let envelope2 = AuthorizationEnvelope::new_root(
        "env-sess-2",
        "principal-carol-lineage",
        "actor-agent-2",
        "session-lineage-2",
        "v1.0",
        scope,
        DelegationBudgetSpec::default(),
        1000,
        2000,
        key,
    );

    let token2 = ApprovalToken::issue(
        "token-elev-lineage",
        "approver-human",
        "actor-agent-2",
        "wsl -u root id",
        "internal/exec",
        "session-lineage-2",
        "{}",
        1900,
        key,
    );

    let req2 = ApcActionRequest {
        actor_id: "actor-agent-2".to_string(),
        action: "wsl -u root id".to_string(),
        resource: "internal/exec".to_string(),
        data_classification: "INTERNAL".to_string(),
        parameters_canonical: "{}".to_string(),
        task_session_id: "session-lineage-2".to_string(),
        policy_version: "v1.0".to_string(),
        now_unix: 1200,
        requires_approval: true,
        approval_token: Some(token2),
        is_irreversible: false,
        sensitivity_tier: 2,
        is_cross_domain: false,
        cost_delta: 0.1,
    };

    let dec2 = pdp.evaluate(&envelope2, &intent, &req2);
    assert!(
        !dec2.allowed,
        "CRITICAL: Cross-session lineage failed to block privileged execution after confidential read!"
    );
    assert_eq!(dec2.failed_condition.as_deref(), Some("C2_COMPOSITION"));
    assert!(
        dec2.reason.contains("CROSS_SESSION_LINEAGE"),
        "Expected CROSS_SESSION_LINEAGE in violation reason: {}",
        dec2.reason
    );
}

// ============================================================================
// SUITE 6: Empirical Findings & Vulnerability Evidence
// ============================================================================

#[test]
fn test_empirical_vulnerability_subcommand_flag_pollution_causes_read_public_fallthrough() {
    // REMEDIATED: Subcommand arguments containing benign flags (-l, -v, -h)
    // belong to the subcommand and no longer cause fallthrough to `READ_PUBLIC`.

    // Case 1: `sudo ls -l /root`
    let cmd1 = parse_semantic_command("sudo ls -l /root");
    let apc1 = classify_action_class("sudo ls -l /root");
    assert_eq!(
        cmd1.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        "Remediated: sudo ls -l is classified as RootOrAdminElevation"
    );
    assert_eq!(
        apc1, "PRIVILEGED_EXECUTION",
        "Remediated: sudo ls -l maps to PRIVILEGED_EXECUTION"
    );

    // Case 2: `sudo cat -v /etc/shadow`
    let cmd2 = parse_semantic_command("sudo cat -v /etc/shadow");
    let apc2 = classify_action_class("sudo cat -v /etc/shadow");
    assert_eq!(
        cmd2.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert_eq!(apc2, "PRIVILEGED_EXECUTION");

    // Case 3: `wsl -u root ls -l /root`
    let cmd3 = parse_semantic_command("wsl -u root ls -l /root");
    let apc3 = classify_action_class("wsl -u root ls -l /root");
    assert_eq!(
        cmd3.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert_eq!(apc3, "PRIVILEGED_EXECUTION");
}

#[test]
fn test_empirical_vulnerability_env_prefix_bypasses_privilege_detection() {
    // REMEDIATED: Invoking elevation binaries through `env` or `/usr/bin/env`
    // is unwrapped and properly classified as RootOrAdminElevation and PRIVILEGED_EXECUTION.

    let cmd_env = parse_semantic_command("env sudo id");
    let apc_env = classify_action_class("env sudo id");
    assert_eq!(
        cmd_env.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        "Remediated: env sudo id is treated as RootOrAdminElevation"
    );
    assert_eq!(
        apc_env, "PRIVILEGED_EXECUTION",
        "Remediated: env sudo id maps to PRIVILEGED_EXECUTION"
    );

    let cmd_env_full = parse_semantic_command("/usr/bin/env sudo id");
    let apc_env_full = classify_action_class("/usr/bin/env sudo id");
    assert_eq!(
        cmd_env_full.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert_eq!(apc_env_full, "PRIVILEGED_EXECUTION");
}

#[test]
fn test_empirical_vulnerability_shell_compound_flags_bypass_unwrapping() {
    // REMEDIATED: Shell wrappers using compound flags (e.g. bash -lc, sh -ec)
    // are unwrapped and correctly classified as RootOrAdminElevation and PRIVILEGED_EXECUTION.

    let cmd = parse_semantic_command("bash -lc 'sudo id'");
    let apc = classify_action_class("bash -lc 'sudo id'");
    assert_eq!(
        cmd.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        "Remediated: bash -lc is unwrapped and classified as RootOrAdminElevation"
    );
    assert_eq!(
        apc, "PRIVILEGED_EXECUTION",
        "Remediated: bash -lc 'sudo id' maps to PRIVILEGED_EXECUTION"
    );
}

#[test]
fn test_empirical_exploit_pairwise_rule_evasion_via_misclassified_command() {
    // REMEDIATED: Pairwise restriction evasion blocked.
    // Because `sudo ls -l /root` is correctly classified as `PRIVILEGED_EXECUTION`, an agent that has
    // executed `READ_CONFIDENTIAL` is denied from executing `sudo ls -l /root` by the
    // `no_privileged_execution_after_confidential_read` rule and Condition C4 token requirement!

    let key = b"test-signing-key-32bytes-secret!";
    let pdp = ApcPolicyDecisionPoint::new(key.to_vec(), "v1.0", true);
    let mut scope = default_enterprise_apc_scope();
    scope.actions.insert("sudo ls -l /root".to_string());
    scope.resources.insert("docs/confidential.txt".to_string());
    scope.resources.insert("system/root".to_string());

    let envelope = AuthorizationEnvelope::new_root(
        "env-exploit",
        "principal-victim",
        "actor-malicious-agent",
        "session-exploit",
        "v1.0",
        scope,
        DelegationBudgetSpec::default(),
        1000,
        2000,
        key,
    );

    let intent = permissive_intent();

    // Step 1: Malicious agent reads confidential file
    let req_read = ApcActionRequest {
        actor_id: "actor-malicious-agent".to_string(),
        action: "read_confidential".to_string(),
        resource: "docs/confidential.txt".to_string(),
        data_classification: "CONFIDENTIAL".to_string(),
        parameters_canonical: "{}".to_string(),
        task_session_id: "session-exploit".to_string(),
        policy_version: "v1.0".to_string(),
        now_unix: 1100,
        requires_approval: false,
        approval_token: None,
        is_irreversible: false,
        sensitivity_tier: 2,
        is_cross_domain: false,
        cost_delta: 0.0,
    };
    let dec_read = pdp.evaluate(&envelope, &intent, &req_read);
    assert!(dec_read.allowed, "Read confidential succeeds");

    // Step 2: Malicious agent attempts to execute `sudo ls -l /root` without approval token!
    // EXPECTED SECURITY POLICY: MUST BE DENIED!
    let req_exploit = ApcActionRequest {
        actor_id: "actor-malicious-agent".to_string(),
        action: "sudo ls -l /root".to_string(),
        resource: "system/root".to_string(),
        data_classification: "INTERNAL".to_string(),
        parameters_canonical: "{}".to_string(),
        task_session_id: "session-exploit".to_string(),
        policy_version: "v1.0".to_string(),
        now_unix: 1200,
        requires_approval: false,
        approval_token: None,
        is_irreversible: false,
        sensitivity_tier: 1,
        is_cross_domain: false,
        cost_delta: 0.0,
    };
    let dec_exploit = pdp.evaluate(&envelope, &intent, &req_exploit);

    // Verify that the exploit is cleanly BLOCKED:
    assert!(
        !dec_exploit.allowed,
        "Remediated: Privileged command with subcommand flag is blocked: {:?}",
        dec_exploit
    );
}

// ============================================================================
// SUITE 7: Adjudication Process Immunity Challenges
// ============================================================================

#[test]
fn test_challenge_adjudication_immunity_denied_patterns() {
    use killswitch_adjudication::immunity::inspect_process_lineage;

    // Standard elevation commands must NOT be immune
    let non_immune = [
        "sudo",
        "sudo -n id",
        "su",
        "su -",
        "wsl",
        "wsl.exe",
        "wsl -u root id",
        "doas",
        "pkexec",
        "runas",
        "runas.exe",
    ];

    for name in non_immune {
        let v = inspect_process_lineage(99999, Some(name));
        assert!(
            !v.is_immune(),
            "Binary '{}' must not receive blanket immunity, got {:?}",
            name,
            v
        );
    }
}
