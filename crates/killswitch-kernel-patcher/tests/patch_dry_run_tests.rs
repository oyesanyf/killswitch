//! Dedicated OS kernel patch orchestration, dry-run safety, and privilege boundary test suite.

mod common;
use killswitch_kernel_patcher::{is_elevated, KernelPatcher, PatchExecutionResult, PatcherError};

#[tokio::test]
async fn test_patch_dry_run_execution_structure() {
    let patcher = KernelPatcher::new();
    let res = patcher
        .apply_os_kernel_patch(true)
        .await
        .expect("Dry run failed");

    assert!(res.dry_run);
    assert!(res.success);
    assert!(!res.command.is_empty());
    assert!(!res.args.is_empty());
    assert!(!res.os_subsystem.is_empty());
    assert!(res.output.contains("[DRY-RUN]"));
}

#[tokio::test]
async fn test_patch_live_fails_closed_under_non_root() {
    let patcher = KernelPatcher::new();
    if !is_elevated() {
        let res = patcher.apply_os_kernel_patch(false).await;
        assert!(
            matches!(res, Err(PatcherError::InsufficientPrivileges)),
            "Expected InsufficientPrivileges under non-elevated user, got: {:?}",
            res
        );
    }
}

#[test]
fn test_patch_execution_result_json_roundtrip() {
    let original = PatchExecutionResult {
        dry_run: true,
        command: "UsoClient.exe".to_string(),
        args: vec!["StartInstall".to_string()],
        success: true,
        output: "[DRY-RUN] Planned execution: UsoClient.exe StartInstall".to_string(),
        os_subsystem: "UsoClient".to_string(),
    };

    let json = serde_json::to_string(&original).expect("Serialization failed");
    let deserialized: PatchExecutionResult =
        serde_json::from_str(&json).expect("Deserialization failed");

    assert_eq!(original.dry_run, deserialized.dry_run);
    assert_eq!(original.command, deserialized.command);
    assert_eq!(original.args, deserialized.args);
    assert_eq!(original.success, deserialized.success);
    assert_eq!(original.output, deserialized.output);
    assert_eq!(original.os_subsystem, deserialized.os_subsystem);
}

#[tokio::test]
async fn test_patch_dry_run_never_mutates_system() {
    let patcher = KernelPatcher::new();
    // In dry run mode, no privileged OS command or kernel package mutation occurs
    let res = patcher
        .apply_os_kernel_patch(true)
        .await
        .expect("Dry run failed");
    assert!(res.dry_run);
    assert!(res.output.contains("[DRY-RUN]"));
}

#[tokio::test]
async fn test_patch_dry_run_platform_routing() {
    let patcher = KernelPatcher::new();
    let res = patcher
        .apply_os_kernel_patch(true)
        .await
        .expect("Dry run failed");

    #[cfg(target_os = "windows")]
    {
        assert_eq!(res.os_subsystem, "UsoClient");
        assert_eq!(res.command, "UsoClient.exe");
    }
    #[cfg(target_os = "linux")]
    {
        assert!(["canonical-livepatch", "apt-get", "dnf"].contains(&res.os_subsystem.as_str()));
    }
    #[cfg(target_os = "macos")]
    {
        assert_eq!(res.os_subsystem, "softwareupdate");
        assert_eq!(res.command, "softwareupdate");
    }
}
