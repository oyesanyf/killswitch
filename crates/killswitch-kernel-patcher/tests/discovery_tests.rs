use killswitch_kernel_patcher::discovery::*;
use killswitch_kernel_patcher::types::*;

#[test]
fn test_synthetic_linux_discovery() {
    let os_release_mock = r#"
NAME="Ubuntu"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.4 LTS"
VERSION_ID="22.04"
HOME_URL="https://www.ubuntu.com/"
"#;

    let info = parse_linux_kernel_info("6.8.0-49-generic", Some(os_release_mock), "x86_64");
    assert_eq!(info.os_family, OsFamily::Linux);
    assert_eq!(info.kernel_release, "6.8.0-49-generic");
    assert_eq!(info.os_version, "22.04");
    assert_eq!(
        info.cpe23,
        "cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*"
    );
    assert_eq!(info.architecture, "x86_64");
    assert!(info.os_family.is_linux());
    assert!(!info.os_family.is_windows());
    assert!(!info.os_family.is_macos());
}

#[test]
fn test_synthetic_windows_11_discovery() {
    let info = parse_windows_kernel_info(
        10,
        0,
        22631,
        Some(3880),
        Some("Windows 11 Enterprise"),
        Some("23H2"),
        "x86_64",
    );
    assert_eq!(info.os_family, OsFamily::Windows);
    assert_eq!(info.kernel_release, "10.0.22631.3880");
    assert!(info.os_version.contains("Windows 11 Enterprise"));
    assert!(info.os_version.contains("23H2"));
    assert_eq!(
        info.cpe23,
        "cpe:2.3:o:microsoft:windows_11:23h2:*:*:*:*:*:*:*"
    );
    assert_eq!(info.architecture, "x86_64");
    assert!(info.os_family.is_windows());
}

#[test]
fn test_synthetic_windows_server_discovery() {
    let info = parse_windows_kernel_info(
        10,
        0,
        20348,
        Some(1200),
        Some("Windows Server 2022 Datacenter"),
        None,
        "x86_64",
    );
    assert_eq!(info.os_family, OsFamily::Windows);
    assert_eq!(info.kernel_release, "10.0.20348.1200");
    assert!(info.os_version.contains("Windows Server 2022 Datacenter"));
    assert_eq!(
        info.cpe23,
        "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*"
    );
    assert_eq!(info.architecture, "x86_64");
}

#[test]
fn test_synthetic_macos_discovery() {
    let info = parse_macos_kernel_info(Some("14.4.1"), "23.4.0", "aarch64");
    assert_eq!(info.os_family, OsFamily::MacOS);
    assert_eq!(info.kernel_release, "23.4.0");
    assert_eq!(info.os_version, "14.4.1");
    assert_eq!(info.cpe23, "cpe:2.3:o:apple:macos:14.4.1:*:*:*:*:*:*:*");
    assert_eq!(info.architecture, "aarch64");
    assert!(info.os_family.is_macos());
}

#[test]
fn test_parse_os_release_variations() {
    // Arch Linux (no VERSION_ID)
    let arch_content = r#"
NAME="Arch Linux"
PRETTY_NAME="Arch Linux"
ID=arch
BUILD_ID=rolling
"#;
    let arch_info = linux::parse_os_release_content(arch_content);
    assert_eq!(arch_info.id, "arch");
    assert_eq!(arch_info.version_id, "");
    assert_eq!(arch_info.pretty_name, "Arch Linux");

    // Fedora
    let fedora_content = r#"
NAME="Fedora Linux"
VERSION="39 (Workstation Edition)"
ID=fedora
VERSION_ID=39
PRETTY_NAME="Fedora Linux 39 (Workstation Edition)"
ID_LIKE="rhel fedora"
"#;
    let fedora_info = linux::parse_os_release_content(fedora_content);
    assert_eq!(fedora_info.id, "fedora");
    assert_eq!(fedora_info.version_id, "39");
    assert_eq!(fedora_info.id_like, vec!["rhel", "fedora"]);
}

#[test]
fn test_detect_architecture() {
    let arch = detect_architecture();
    assert_eq!(arch, std::env::consts::ARCH);
}

#[test]
fn test_live_host_kernel_detection() {
    let result = HostKernelInfo::detect_host_kernel();
    assert!(
        result.is_ok(),
        "detect_host_kernel() must succeed on host platform"
    );
    let info = result.unwrap();

    #[cfg(target_os = "windows")]
    assert_eq!(info.os_family, OsFamily::Windows);
    #[cfg(target_os = "linux")]
    assert_eq!(info.os_family, OsFamily::Linux);
    #[cfg(target_os = "macos")]
    assert_eq!(info.os_family, OsFamily::MacOS);

    assert!(
        !info.kernel_release.is_empty(),
        "kernel_release must not be empty"
    );
    assert!(
        !info.architecture.is_empty(),
        "architecture must not be empty"
    );
    assert!(
        info.cpe23.starts_with("cpe:2.3:o:"),
        "CPE must start with 'cpe:2.3:o:'"
    );
    assert_eq!(info.to_cpe23(), info.cpe23);
}
