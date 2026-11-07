//! EMPIRICAL ADVERSARIAL CHALLENGE — Milestone SEC-1
//! Telemetry, Immunity & Dynamic Context Observation
//!
//! Archetype: teamwork_challenger
//! Roles: critic, specialist
//! Author: Challenger SEC-1-1

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

use killswitch_adjudication::adjudicator::ZeroFalsePositiveAdjudicator;
use killswitch_adjudication::binary_probe::{
    inspect_binary_metadata, inspect_binary_metadata_from_bytes, DynamicBinaryMetadata,
    ElevationRequirement,
};
use killswitch_adjudication::immunity::{inspect_process_lineage, LineageImmunityVerdict};
use killswitch_adjudication::token_delta::{
    evaluate_security_context_delta, observe_parent_child_token_delta,
    query_process_security_context, ProcessSecurityContext, SecurityContextDelta,
};
use killswitch_core::freeze::NativeProcessFreezer;
use killswitch_core::killchain::{is_developer_or_agent_runtime, is_immutable_os_kernel_pid};
use killswitch_types::adjudication::{EvidenceClass, ThreatCandidate, VetoReason};
use killswitch_types::{KillSwitchError, ProcessFreezer};

// =============================================================================
// DOMAIN 1: DynamicBinaryMetadataProbe Adversarial Stress Tests
// =============================================================================

#[test]
fn test_challenge_synthetic_pe32_require_admin() {
    // Construct a synthetic 32-bit PE header (Magic 0x010B) with requireAdministrator manifest
    let mut pe = vec![0u8; 512];
    pe[0] = b'M';
    pe[1] = b'Z';
    // e_lfanew at 0x3C pointing to PE signature at offset 0x80
    pe[0x3C] = 0x80;
    pe[0x3D] = 0x00;
    pe[0x3E] = 0x00;
    pe[0x3F] = 0x00;

    // PE signature "PE\0\0"
    pe[0x80] = b'P';
    pe[0x81] = b'E';
    pe[0x82] = 0;
    pe[0x83] = 0;

    // Optional header magic at pe_offset + 24 (0x80 + 24 = 0x98) = 0x010B (PE32)
    pe[0x98] = 0x0B;
    pe[0x99] = 0x01;

    let manifest = br#"
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
    pe.extend_from_slice(manifest);

    let meta = inspect_binary_metadata_from_bytes(&pe);
    assert_eq!(
        meta.elevation_requirement,
        ElevationRequirement::RequireAdministrator,
        "Synthetic PE32 requireAdministrator manifest was not detected"
    );
    assert!(
        meta.is_privileged_target(),
        "PE32 with requireAdministrator must be flagged as privileged target"
    );
}

#[test]
fn test_challenge_synthetic_pe64_highest_available_utf16le() {
    // Construct a synthetic 64-bit PE header (Magic 0x020B) with highestAvailable in UTF-16 LE
    let mut pe = vec![0u8; 512];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3C] = 0x80;

    pe[0x80] = b'P';
    pe[0x81] = b'E';
    pe[0x82] = 0;
    pe[0x83] = 0;

    // Optional header magic at 0x98 = 0x020B (PE32+ / 64-bit)
    pe[0x98] = 0x0B;
    pe[0x99] = 0x02;

    let manifest_str = "<requestedExecutionLevel level='highestAvailable' uiAccess='false'/>";
    let mut utf16_manifest = Vec::new();
    for ch in manifest_str.encode_utf16() {
        utf16_manifest.extend_from_slice(&ch.to_le_bytes());
    }
    pe.extend_from_slice(&utf16_manifest);

    let meta = inspect_binary_metadata_from_bytes(&pe);
    assert_eq!(
        meta.elevation_requirement,
        ElevationRequirement::HighestAvailable,
        "Synthetic PE64 highestAvailable UTF-16 LE manifest was not detected"
    );
    assert!(
        meta.is_privileged_target(),
        "PE64 with highestAvailable must be flagged as privileged target"
    );
}

#[test]
fn test_challenge_synthetic_pe_as_invoker_not_privileged() {
    let mut pe = vec![0u8; 256];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3C] = 0x40;
    pe[0x40] = b'P';
    pe[0x41] = b'E';

    let manifest = br#"<requestedExecutionLevel level="asInvoker" uiAccess="false"/>"#;
    pe.extend_from_slice(manifest);

    let meta = inspect_binary_metadata_from_bytes(&pe);
    assert_eq!(meta.elevation_requirement, ElevationRequirement::AsInvoker);
    assert!(
        !meta.is_privileged_target(),
        "PE with asInvoker must NOT be flagged as privileged target"
    );
}

#[test]
fn test_challenge_truncated_and_corrupt_pe_headers() {
    // 1. Single byte
    let meta1 = inspect_binary_metadata_from_bytes(b"M");
    assert_eq!(meta1.elevation_requirement, ElevationRequirement::None);
    assert!(!meta1.is_privileged_target());

    // 2. Only MZ header (no e_lfanew)
    let meta2 = inspect_binary_metadata_from_bytes(b"MZ\x90\x00\x03\x00");
    assert_eq!(meta2.elevation_requirement, ElevationRequirement::None);

    // 3. Out of bounds e_lfanew
    let mut pe_oob = vec![0u8; 64];
    pe_oob[0] = b'M';
    pe_oob[1] = b'Z';
    pe_oob[0x3C] = 0xFF;
    pe_oob[0x3D] = 0xFF;
    pe_oob[0x3E] = 0x00;
    pe_oob[0x3F] = 0x00;
    let meta3 = inspect_binary_metadata_from_bytes(&pe_oob);
    assert_eq!(meta3.elevation_requirement, ElevationRequirement::None);

    // 4. Corrupted PE signature (b"NE\0\0" instead of "PE\0\0")
    let mut pe_bad_sig = vec![0u8; 128];
    pe_bad_sig[0] = b'M';
    pe_bad_sig[1] = b'Z';
    pe_bad_sig[0x3C] = 0x40;
    pe_bad_sig[0x40] = b'N';
    pe_bad_sig[0x41] = b'E';
    pe_bad_sig[0x42] = 0;
    pe_bad_sig[0x43] = 0;
    let meta4 = inspect_binary_metadata_from_bytes(&pe_bad_sig);
    assert_eq!(meta4.elevation_requirement, ElevationRequirement::None);

    // 5. Huge sparse buffer
    let huge = vec![0u8; 1024 * 1024];
    let meta5 = inspect_binary_metadata_from_bytes(&huge);
    assert_eq!(meta5.elevation_requirement, ElevationRequirement::None);
}

#[test]
fn test_challenge_renamed_binaries_on_disk() {
    let dir = tempdir().expect("tempdir");

    // Privileged binary payload
    let mut priv_pe = vec![0u8; 256];
    priv_pe[0] = b'M';
    priv_pe[1] = b'Z';
    priv_pe[0x3C] = 0x40;
    priv_pe[0x40] = b'P';
    priv_pe[0x41] = b'E';
    priv_pe.extend_from_slice(br#"<requestedExecutionLevel level="requireAdministrator" />"#);

    // Test 1: Renamed to innocent .txt
    let path_txt = dir.path().join("benign_notes.txt");
    File::create(&path_txt)
        .unwrap()
        .write_all(&priv_pe)
        .unwrap();
    let meta_txt = inspect_binary_metadata(&path_txt).expect("inspect metadata");
    assert_eq!(
        meta_txt.elevation_requirement,
        ElevationRequirement::RequireAdministrator
    );
    assert!(
        meta_txt.is_privileged_target(),
        "Renamed .txt file must be detected as privileged"
    );

    // Test 2: Renamed to extensionless file
    let path_no_ext = dir.path().join("innocent_worker");
    File::create(&path_no_ext)
        .unwrap()
        .write_all(&priv_pe)
        .unwrap();
    let meta_no_ext = inspect_binary_metadata(&path_no_ext).expect("inspect metadata");
    assert_eq!(
        meta_no_ext.elevation_requirement,
        ElevationRequirement::RequireAdministrator
    );
    assert!(
        meta_no_ext.is_privileged_target(),
        "Extensionless file must be detected as privileged"
    );

    // Test 3: Renamed to .pdf
    let path_pdf = dir.path().join("invoice.pdf");
    File::create(&path_pdf)
        .unwrap()
        .write_all(&priv_pe)
        .unwrap();
    let meta_pdf = inspect_binary_metadata(&path_pdf).expect("inspect metadata");
    assert!(meta_pdf.is_privileged_target());

    // Test 4: Benign file named `sudo.exe` or `wsl.exe` with asInvoker must NOT be flagged as privileged
    let mut benign_pe = vec![0u8; 256];
    benign_pe[0] = b'M';
    benign_pe[1] = b'Z';
    benign_pe[0x3C] = 0x40;
    benign_pe[0x40] = b'P';
    benign_pe[0x41] = b'E';
    benign_pe.extend_from_slice(br#"<requestedExecutionLevel level="asInvoker" />"#);

    let path_sudo = dir.path().join("sudo.exe");
    File::create(&path_sudo)
        .unwrap()
        .write_all(&benign_pe)
        .unwrap();
    let meta_sudo = inspect_binary_metadata(&path_sudo).expect("inspect metadata");
    assert!(
        !meta_sudo.is_privileged_target(),
        "Benign asInvoker binary named sudo.exe must NOT be flagged as privileged target by disk probe"
    );
}

#[test]
fn test_challenge_missing_and_corrupt_file_paths() {
    let dir = tempdir().expect("tempdir");
    let missing_path = dir.path().join("definitely_non_existent_binary_4242.exe");
    let res = inspect_binary_metadata(&missing_path);
    assert!(res.is_err(), "Non-existent path must return Err");
    assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn test_challenge_subsystem_traits_and_mixed_case() {
    // 1. WSL subsystem import with mixed casing
    let pe_wsl = b"Some binary header ... WsLaPi.DlL dynamic load ...";
    let meta_wsl = inspect_binary_metadata_from_bytes(pe_wsl);
    assert!(meta_wsl.invokes_wsl_subsystem);
    assert!(meta_wsl.is_privileged_target());

    // 2. Hyper-V compute subsystem with mixed casing
    let pe_hyperv = b"Some binary header ... VmCoMpUtE.dLL dynamic load ...";
    let meta_hyperv = inspect_binary_metadata_from_bytes(pe_hyperv);
    assert!(meta_hyperv.invokes_hyperv_compute);

    // 3. Linux lxss driver string
    let pe_lxss = b"Drivers\\Lxss\\wslhost.sys helper";
    let meta_lxss = inspect_binary_metadata_from_bytes(pe_lxss);
    assert!(meta_lxss.invokes_wsl_subsystem);
}

#[test]
fn test_challenge_non_canonical_suid_and_capabilities() {
    // 1. Canonical Root SUID
    let meta1 = DynamicBinaryMetadata {
        is_suid: true,
        file_uid: 0,
        ..Default::default()
    };
    assert!(meta1.is_privileged_target(), "Root SUID must be privileged");

    // 2. Non-root SUID (e.g. user 1000)
    let meta2 = DynamicBinaryMetadata {
        is_suid: true,
        file_uid: 1000,
        ..Default::default()
    };
    assert!(
        !meta2.is_privileged_target(),
        "Non-root SUID must NOT be privileged target"
    );

    // 3. SGID only without SUID
    let meta3 = DynamicBinaryMetadata {
        is_sgid: true,
        file_uid: 0,
        ..Default::default()
    };
    assert!(
        !meta3.is_privileged_target(),
        "SGID alone without SUID must NOT be privileged target"
    );

    // 4. Linux capability xattr present
    let meta4 = DynamicBinaryMetadata {
        has_linux_capabilities: true,
        linux_capabilities_mask: 0x00200000, // CAP_SYS_ADMIN
        ..Default::default()
    };
    assert!(
        meta4.is_privileged_target(),
        "Binary with Linux capabilities must be privileged target"
    );

    // 5. Default clean metadata
    let meta5 = DynamicBinaryMetadata::default();
    assert!(!meta5.is_privileged_target());
}

// =============================================================================
// DOMAIN 2: ParentChildTokenDeltaObserver Adversarial Stress Tests
// =============================================================================

#[test]
fn test_challenge_linux_euid_synthetic_contexts() {
    // 1. Escalated EUID: 1000 -> 0
    let p1 = ProcessSecurityContext {
        euid: 1000,
        ..Default::default()
    };
    let c1 = ProcessSecurityContext {
        euid: 0,
        ..Default::default()
    };
    let deltas1 = evaluate_security_context_delta(&p1, &c1);
    assert_eq!(
        deltas1,
        vec![SecurityContextDelta::LinuxEuidEscalation {
            parent_euid: 1000,
            child_euid: 0
        }]
    );
    assert!(deltas1[0].is_privilege_escalation());

    // 2. Same unprivileged EUID: 1000 -> 1000
    let p2 = ProcessSecurityContext {
        euid: 1000,
        ..Default::default()
    };
    let c2 = ProcessSecurityContext {
        euid: 1000,
        ..Default::default()
    };
    let deltas2 = evaluate_security_context_delta(&p2, &c2);
    assert_eq!(deltas2, vec![SecurityContextDelta::CleanIdentityPreserved]);
    assert!(!deltas2[0].is_privilege_escalation());

    // 3. Same Root EUID: 0 -> 0
    let p3 = ProcessSecurityContext {
        euid: 0,
        ..Default::default()
    };
    let c3 = ProcessSecurityContext {
        euid: 0,
        ..Default::default()
    };
    let deltas3 = evaluate_security_context_delta(&p3, &c3);
    assert_eq!(deltas3, vec![SecurityContextDelta::CleanIdentityPreserved]);

    // 4. De-escalated EUID (dropping privs): 0 -> 1000
    let p4 = ProcessSecurityContext {
        euid: 0,
        ..Default::default()
    };
    let c4 = ProcessSecurityContext {
        euid: 1000,
        ..Default::default()
    };
    let deltas4 = evaluate_security_context_delta(&p4, &c4);
    assert_eq!(
        deltas4,
        vec![SecurityContextDelta::CleanIdentityPreserved],
        "Privilege de-escalation must not be flagged as privilege escalation"
    );

    // 5. Lateral unprivileged user switch: 1000 -> 1001
    let p5 = ProcessSecurityContext {
        euid: 1000,
        ..Default::default()
    };
    let c5 = ProcessSecurityContext {
        euid: 1001,
        ..Default::default()
    };
    let deltas5 = evaluate_security_context_delta(&p5, &c5);
    assert_eq!(
        deltas5,
        vec![SecurityContextDelta::CleanIdentityPreserved],
        "Lateral non-root transition must not be flagged as root escalation"
    );
}

#[test]
fn test_challenge_windows_token_integrity_synthetic_contexts() {
    // 1. Medium (0x2000) -> High (0x3000)
    let p1 = ProcessSecurityContext {
        integrity_rid: 0x2000,
        ..Default::default()
    };
    let c1 = ProcessSecurityContext {
        integrity_rid: 0x3000,
        ..Default::default()
    };
    let deltas1 = evaluate_security_context_delta(&p1, &c1);
    assert!(
        deltas1.contains(&SecurityContextDelta::WindowsIntegrityEscalation {
            parent_rid: 0x2000,
            child_rid: 0x3000,
        })
    );
    assert!(deltas1.iter().any(|d| d.is_privilege_escalation()));

    // 2. Medium (0x2000) -> System (0x4000)
    let p2 = ProcessSecurityContext {
        integrity_rid: 0x2000,
        ..Default::default()
    };
    let c2 = ProcessSecurityContext {
        integrity_rid: 0x4000,
        ..Default::default()
    };
    let deltas2 = evaluate_security_context_delta(&p2, &c2);
    assert!(
        deltas2.contains(&SecurityContextDelta::WindowsIntegrityEscalation {
            parent_rid: 0x2000,
            child_rid: 0x4000,
        })
    );

    // 3. Low (0x1000) -> High (0x3000)
    let p3 = ProcessSecurityContext {
        integrity_rid: 0x1000,
        ..Default::default()
    };
    let c3 = ProcessSecurityContext {
        integrity_rid: 0x3000,
        ..Default::default()
    };
    let deltas3 = evaluate_security_context_delta(&p3, &c3);
    assert!(
        deltas3.contains(&SecurityContextDelta::WindowsIntegrityEscalation {
            parent_rid: 0x1000,
            child_rid: 0x3000,
        })
    );

    // 4. Low (0x1000) -> Medium (0x2000): Not high integrity escalation
    let p4 = ProcessSecurityContext {
        integrity_rid: 0x1000,
        ..Default::default()
    };
    let c4 = ProcessSecurityContext {
        integrity_rid: 0x2000,
        ..Default::default()
    };
    let deltas4 = evaluate_security_context_delta(&p4, &c4);
    assert_eq!(deltas4, vec![SecurityContextDelta::CleanIdentityPreserved]);

    // 5. High (0x3000) -> High (0x3000): Clean
    let p5 = ProcessSecurityContext {
        integrity_rid: 0x3000,
        ..Default::default()
    };
    let c5 = ProcessSecurityContext {
        integrity_rid: 0x3000,
        ..Default::default()
    };
    let deltas5 = evaluate_security_context_delta(&p5, &c5);
    assert_eq!(deltas5, vec![SecurityContextDelta::CleanIdentityPreserved]);

    // 6. High (0x3000) -> Medium (0x2000): Integrity drop is clean
    let p6 = ProcessSecurityContext {
        integrity_rid: 0x3000,
        ..Default::default()
    };
    let c6 = ProcessSecurityContext {
        integrity_rid: 0x2000,
        ..Default::default()
    };
    let deltas6 = evaluate_security_context_delta(&p6, &c6);
    assert_eq!(deltas6, vec![SecurityContextDelta::CleanIdentityPreserved]);
}

#[test]
fn test_challenge_windows_token_elevation_and_session0() {
    // 1. TokenElevation delta: false -> true
    let p1 = ProcessSecurityContext {
        is_elevated: false,
        ..Default::default()
    };
    let c1 = ProcessSecurityContext {
        is_elevated: true,
        ..Default::default()
    };
    let deltas1 = evaluate_security_context_delta(&p1, &c1);
    assert!(deltas1.contains(&SecurityContextDelta::WindowsTokenElevation));

    // 2. Both elevated: true -> true: No delta
    let p2 = ProcessSecurityContext {
        is_elevated: true,
        ..Default::default()
    };
    let c2 = ProcessSecurityContext {
        is_elevated: true,
        ..Default::default()
    };
    let deltas2 = evaluate_security_context_delta(&p2, &c2);
    assert_eq!(deltas2, vec![SecurityContextDelta::CleanIdentityPreserved]);

    // 3. Session 1 -> Session 0: Service isolation crossing
    let p3 = ProcessSecurityContext {
        session_id: 1,
        ..Default::default()
    };
    let c3 = ProcessSecurityContext {
        session_id: 0,
        ..Default::default()
    };
    let deltas3 = evaluate_security_context_delta(&p3, &c3);
    assert!(
        deltas3.contains(&SecurityContextDelta::WindowsSession0Transition { parent_session: 1 })
    );

    // 4. Session 2 (RDP/secondary user) -> Session 0
    let p4 = ProcessSecurityContext {
        session_id: 2,
        ..Default::default()
    };
    let c4 = ProcessSecurityContext {
        session_id: 0,
        ..Default::default()
    };
    let deltas4 = evaluate_security_context_delta(&p4, &c4);
    assert!(
        deltas4.contains(&SecurityContextDelta::WindowsSession0Transition { parent_session: 2 })
    );

    // 5. Session 0 -> Session 0: Clean service child
    let p5 = ProcessSecurityContext {
        session_id: 0,
        ..Default::default()
    };
    let c5 = ProcessSecurityContext {
        session_id: 0,
        ..Default::default()
    };
    let deltas5 = evaluate_security_context_delta(&p5, &c5);
    assert_eq!(deltas5, vec![SecurityContextDelta::CleanIdentityPreserved]);

    // 6. Session 1 -> Session 1: Clean desktop child
    let p6 = ProcessSecurityContext {
        session_id: 1,
        ..Default::default()
    };
    let c6 = ProcessSecurityContext {
        session_id: 1,
        ..Default::default()
    };
    let deltas6 = evaluate_security_context_delta(&p6, &c6);
    assert_eq!(deltas6, vec![SecurityContextDelta::CleanIdentityPreserved]);
}

#[test]
fn test_challenge_simultaneous_multi_vector_escalation() {
    let parent = ProcessSecurityContext {
        pid: 100,
        euid: 1000,
        capabilities: 0x00000000,
        namespaces: HashMap::from([("mnt".to_string(), 1001)]),
        integrity_rid: 0x2000, // Medium
        is_elevated: false,
        session_id: 1,
    };

    let child = ProcessSecurityContext {
        pid: 101,
        euid: 0,                                                // EUID escalation
        capabilities: 0x00200080,                               // CapEff expansion
        namespaces: HashMap::from([("mnt".to_string(), 1002)]), // Namespace divergence
        integrity_rid: 0x3000,                                  // Integrity escalation
        is_elevated: true,                                      // TokenElevation
        session_id: 0,                                          // Session 0 transition
    };

    let deltas = evaluate_security_context_delta(&parent, &child);

    assert!(deltas.contains(&SecurityContextDelta::LinuxEuidEscalation {
        parent_euid: 1000,
        child_euid: 0,
    }));
    assert!(
        deltas.contains(&SecurityContextDelta::LinuxCapabilityExpansion {
            added_capabilities: 0x00200080,
        })
    );
    assert!(
        deltas.contains(&SecurityContextDelta::LinuxNamespaceTransition {
            namespaces: vec!["mnt".to_string()],
        })
    );
    assert!(
        deltas.contains(&SecurityContextDelta::WindowsIntegrityEscalation {
            parent_rid: 0x2000,
            child_rid: 0x3000,
        })
    );
    assert!(deltas.contains(&SecurityContextDelta::WindowsTokenElevation));
    assert!(deltas.contains(&SecurityContextDelta::WindowsSession0Transition { parent_session: 1 }));

    // Every delta is confirmed as privilege escalation
    assert!(deltas.iter().all(|d| d.is_privilege_escalation()));
}

#[test]
fn test_challenge_live_process_security_context_query_boundaries() {
    // 1. Kernel PID 0 and PID 4 must return System context safely
    let ctx_pid0 = query_process_security_context(0).expect("PID 0 context");
    assert_eq!(ctx_pid0.integrity_rid, 0x4000); // System
    assert!(ctx_pid0.is_elevated);
    assert_eq!(ctx_pid0.session_id, 0);

    let ctx_pid4 = query_process_security_context(4).expect("PID 4 context");
    assert_eq!(ctx_pid4.integrity_rid, 0x4000);
    assert!(ctx_pid4.is_elevated);

    // 2. Querying current process must succeed without panic
    let cur_pid = std::process::id();
    let cur_ctx = query_process_security_context(cur_pid).expect("Current PID context");
    assert_eq!(cur_ctx.pid, cur_pid);

    // 3. Parent-child token delta on current process vs itself must yield clean identity
    let self_deltas = observe_parent_child_token_delta(cur_pid, cur_pid);
    assert_eq!(
        self_deltas,
        vec![SecurityContextDelta::CleanIdentityPreserved]
    );
}

// =============================================================================
// DOMAIN 3: Kernel Anchor Immunity vs Developer Tools Child Adjudication
// =============================================================================

#[test]
fn test_challenge_kernel_anchors_cannot_be_terminated_or_frozen() {
    let freezer = NativeProcessFreezer::new();

    let kernel_anchors = [
        (0, "System Idle Process"),
        (1, "systemd"),
        (4, "System"),
        (std::process::id(), "killswitch"),
        (100, "smss.exe"),
        (101, "csrss.exe"),
        (102, "wininit.exe"),
        (103, "winlogon.exe"),
        (104, "services.exe"),
        (105, "lsass.exe"),
        (106, "lsm.exe"),
        (107, "fontdrvhost.exe"),
        (108, "init"),
        (109, "systemd-journald"),
        (110, "systemd-udevd"),
        (111, "dbus-daemon"),
        (112, "kthreadd"),
        (113, "launchd"),
        (114, "kernel_task"),
        (115, "windowserver"),
        (116, "opendirectoryd"),
        (117, "killswitch.exe"),
        (118, "oshoosi"),
    ];

    // 1. Static name & PID catalog verification
    for &(pid, name) in &kernel_anchors {
        assert!(
            is_immutable_os_kernel_pid(pid, name),
            "Expected PID {} ({}) to be recognized as immutable OS kernel anchor",
            pid,
            name
        );
        assert!(
            freezer.is_immutable_os_kernel(pid, name),
            "Expected freezer to recognize PID {} ({}) as immutable OS kernel anchor",
            pid,
            name
        );
    }

    // 2. Guaranteed non-freezable PIDs (PID <= 4 and current process)
    for &pid in &[0, 1, 4, std::process::id()] {
        let freeze_res = freezer.freeze_process(pid);
        assert!(
            freeze_res.is_err(),
            "NativeProcessFreezer must NEVER freeze kernel PID {}",
            pid
        );
        match freeze_res.unwrap_err() {
            KillSwitchError::ProtectedProcessImmune { .. }
            | KillSwitchError::ParentLineageImmune { .. } => {
                // Expected protection
            }
            other => panic!(
                "Unexpected error variant when freezing kernel PID {}: {:?}",
                pid, other
            ),
        }
    }

    // 3. Live kernel processes running on host OS
    let mut sys = sysinfo::System::new();
    sys.refresh_processes();
    let mut tested_live = 0;
    for (pid_obj, proc) in sys.processes() {
        let live_pid = pid_obj.as_u32();
        let name = proc.name();
        if is_immutable_os_kernel_pid(live_pid, name) {
            let freeze_res = freezer.freeze_process(live_pid);
            assert!(
                freeze_res.is_err(),
                "NativeProcessFreezer must NEVER freeze live kernel anchor PID {} ({})",
                live_pid,
                name
            );
            assert!(
                matches!(
                    freeze_res.unwrap_err(),
                    KillSwitchError::ProtectedProcessImmune { .. }
                        | KillSwitchError::ParentLineageImmune { .. }
                ),
                "Live kernel process must fail with ProtectedProcessImmune or ParentLineageImmune"
            );
            tested_live += 1;
        }
    }
    assert!(
        tested_live > 0,
        "Must have tested at least one live immutable kernel process on host OS"
    );
}

#[test]
fn test_challenge_developer_tools_decoupled_from_kernel_anchors() {
    let dev_tools = [
        "cursor.exe",
        "cursor",
        "code.exe",
        "node.exe",
        "node",
        "python.exe",
        "python",
        "python3",
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "bash",
        "sh",
        "zsh",
        "fish",
        "docker.exe",
        "dockerd.exe",
        "wsl.exe",
        "wslservice.exe",
        "wslhost.exe",
        "sudo",
        "su",
    ];

    for &tool in &dev_tools {
        // Crucial invariant: Developer tools are NOT immutable kernel anchors
        assert!(
            !is_immutable_os_kernel_pid(9999, tool),
            "Critical vulnerability: Developer tool '{}' must NOT be classified as immutable OS kernel anchor",
            tool
        );

        // Must be recognized as developer or agent runtime
        assert!(
            is_developer_or_agent_runtime(tool),
            "Developer tool '{}' must be recognized by is_developer_or_agent_runtime",
            tool
        );
    }
}

#[test]
fn test_challenge_privilege_escalation_targets_denied_blanket_immunity() {
    let priv_escalation_targets = [
        "wsl.exe",
        "wslservice.exe",
        "wslhost.exe",
        "sudo",
        "su",
        "doas",
        "pkexec",
    ];

    for &target in &priv_escalation_targets {
        let verdict = inspect_process_lineage(5555, Some(target));
        assert!(
            !verdict.is_immune(),
            "CRITICAL: '{}' must NOT receive blanket target immunity",
            target
        );
        assert_eq!(
            verdict.to_veto_reason(),
            None,
            "Target '{}' must have None veto reason",
            target
        );
    }
}

#[test]
fn test_challenge_agent_runtime_child_verdict_properties() {
    let child_verdict = LineageImmunityVerdict::AgentRuntimeChild {
        ancestor_pid: 2048,
        ancestor_name: "cursor.exe".to_string(),
        depth: 2,
    };

    // AgentRuntimeChild must NOT be immune and must NOT veto
    assert!(!child_verdict.is_immune());
    assert_eq!(child_verdict.to_veto_reason(), None);
}

#[tokio::test]
async fn test_challenge_agent_child_process_adjudication_not_vetoed_at_layer1() {
    let adjudicator = ZeroFalsePositiveAdjudicator::new();

    // 1. Verify kernel anchor IS vetoed at Layer 1
    let kernel_candidate = ThreatCandidate::new(
        Some(4),
        "system",
        "TestDetector",
        "Kernel execution",
        0.99,
        EvidenceClass::Behavior,
    );
    let kernel_result = adjudicator
        .adjudicate_threat_candidate(&kernel_candidate, None)
        .await;
    assert!(kernel_result.is_vetoed());
    assert_eq!(kernel_result.confidence(), 0.0);

    // 2. Verify an unknown or malicious child under developer tooling is NOT vetoed at Layer 1
    // We target a high PID with a non-whitelisted binary name
    let child_candidate = ThreatCandidate::new(
        Some(8888),
        "suspicious_worker.bin",
        "AnomalousHeuristic",
        "High CPU and unmapped memory write",
        0.90,
        EvidenceClass::Behavior,
    );
    let child_result = adjudicator
        .adjudicate_threat_candidate(&child_candidate, None)
        .await;

    // It should NOT be vetoed under CriticalSystemPid
    if let killswitch_types::adjudication::AdjudicationResult::Vetoed { reason, .. } = child_result
    {
        assert_ne!(
            reason,
            VetoReason::CriticalSystemPid,
            "Untrusted child process was erroneously vetoed by CriticalSystemPid"
        );
    }
}

#[test]
fn test_challenge_corrupted_manifest_adversarial_variations() {
    // 1. Truncated XML: cuts off before keyword completion
    let truncated = b"<requestedExecutionLevel level=\"requireAdmin";
    let meta_trunc = inspect_binary_metadata_from_bytes(truncated);
    assert_eq!(
        meta_trunc.elevation_requirement,
        ElevationRequirement::None,
        "Truncated manifest keyword must not be parsed as RequireAdministrator"
    );

    // 2. XML with inverted attribute order and spacing
    let inverted = br#"<requestedExecutionLevel uiAccess="false"   level="highestAvailable" />"#;
    let meta_inv = inspect_binary_metadata_from_bytes(inverted);
    assert_eq!(
        meta_inv.elevation_requirement,
        ElevationRequirement::HighestAvailable,
        "Inverted attribute order and spacing must be parsed correctly"
    );

    // 3. XML with uppercase tag and attributes
    let uppercase = br#"<REQUESTEDEXECUTIONLEVEL UIACCESS="FALSE" LEVEL="REQUIREADMINISTRATOR"/>"#;
    let meta_upper = inspect_binary_metadata_from_bytes(uppercase);
    assert_eq!(
        meta_upper.elevation_requirement,
        ElevationRequirement::RequireAdministrator,
        "Uppercase manifest tag and attributes must be parsed correctly"
    );

    // 4. XML with single quotes
    let single_quotes = b"<requestedExecutionLevel level='requireAdministrator' uiAccess='false'/>";
    let meta_single = inspect_binary_metadata_from_bytes(single_quotes);
    assert_eq!(
        meta_single.elevation_requirement,
        ElevationRequirement::RequireAdministrator,
        "Single-quoted attributes must be parsed correctly"
    );

    // 5. XML containing arbitrary junk bytes around valid tag
    let mut junk = vec![0xFF, 0xFE, 0x00, 0x12, 0x34, 0x99];
    junk.extend_from_slice(b"<requestedExecutionLevel level=\"asInvoker\"/>");
    junk.extend_from_slice(&[0x00, 0xAA, 0xBB, 0xCC]);
    let meta_junk = inspect_binary_metadata_from_bytes(&junk);
    assert_eq!(
        meta_junk.elevation_requirement,
        ElevationRequirement::AsInvoker
    );
}

#[test]
fn test_challenge_hardlinks_on_disk() {
    let dir = tempdir().expect("tempdir");
    let target_path = dir.path().join("original_worker.exe");

    let mut priv_pe = vec![0u8; 256];
    priv_pe[0] = b'M';
    priv_pe[1] = b'Z';
    priv_pe[0x3C] = 0x40;
    priv_pe[0x40] = b'P';
    priv_pe[0x41] = b'E';
    priv_pe.extend_from_slice(br#"<requestedExecutionLevel level="requireAdministrator" />"#);

    File::create(&target_path)
        .unwrap()
        .write_all(&priv_pe)
        .unwrap();

    let hardlink_path = dir.path().join("hardlink_worker.bin");
    std::fs::hard_link(&target_path, &hardlink_path).expect("create hardlink");

    let meta_hardlink = inspect_binary_metadata(&hardlink_path).expect("inspect hardlink metadata");
    assert_eq!(
        meta_hardlink.elevation_requirement,
        ElevationRequirement::RequireAdministrator
    );
    assert!(meta_hardlink.is_privileged_target());
}

#[test]
fn test_challenge_parent_child_token_delta_extreme_values() {
    // 1. Extreme EUID delta: u32::MAX -> 0
    let p1 = ProcessSecurityContext {
        euid: u32::MAX,
        ..Default::default()
    };
    let c1 = ProcessSecurityContext {
        euid: 0,
        ..Default::default()
    };
    let deltas1 = evaluate_security_context_delta(&p1, &c1);
    assert_eq!(
        deltas1,
        vec![SecurityContextDelta::LinuxEuidEscalation {
            parent_euid: u32::MAX,
            child_euid: 0
        }]
    );

    // 2. Maximum capability bitmask expansion: 0 -> u64::MAX
    let p2 = ProcessSecurityContext {
        capabilities: 0,
        ..Default::default()
    };
    let c2 = ProcessSecurityContext {
        capabilities: u64::MAX,
        ..Default::default()
    };
    let deltas2 = evaluate_security_context_delta(&p2, &c2);
    assert_eq!(
        deltas2,
        vec![SecurityContextDelta::LinuxCapabilityExpansion {
            added_capabilities: u64::MAX
        }]
    );

    // 3. Extreme session transition: u32::MAX -> 0
    let p3 = ProcessSecurityContext {
        session_id: u32::MAX,
        ..Default::default()
    };
    let c3 = ProcessSecurityContext {
        session_id: 0,
        ..Default::default()
    };
    let deltas3 = evaluate_security_context_delta(&p3, &c3);
    assert_eq!(
        deltas3,
        vec![SecurityContextDelta::WindowsSession0Transition {
            parent_session: u32::MAX
        }]
    );
}
