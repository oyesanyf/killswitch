//! Dedicated CPE 2.3 formatting, mapping, and escaping test suite.

mod common;
use common::*;
use killswitch_kernel_patcher::cpe::{
    canonicalize_linux_kernel_version, canonicalize_macos_version, canonicalize_windows_cpe,
    escape_cpe_attribute, split_unescaped_colons, Cpe23, CpePart,
};
use killswitch_kernel_patcher::discovery::{
    parse_linux_kernel_info, parse_macos_kernel_info, parse_windows_kernel_info,
};
use killswitch_kernel_patcher::{HostKernelInfo, OsFamily};

#[test]
fn test_cpe_linux_standard_kernel() {
    let info = HostKernelInfo {
        os_family: OsFamily::Linux,
        kernel_release: "6.8.0-40-generic".to_string(),
        os_version: "Ubuntu 24.04 LTS".to_string(),
        cpe23: "cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*".to_string(),
        architecture: "x86_64".to_string(),
    };
    let cpe = info.to_cpe23();
    assert_valid_cpe23(&cpe);
    assert!(cpe.starts_with("cpe:2.3:o:linux:linux_kernel:6.8.0"));
}

#[test]
fn test_cpe_linux_version_canonicalization() {
    assert_eq!(
        canonicalize_linux_kernel_version("6.8.0-40-generic"),
        "6.8.0"
    );
    assert_eq!(
        canonicalize_linux_kernel_version("5.15.0-89-generic"),
        "5.15.0"
    );
    assert_eq!(canonicalize_linux_kernel_version("6.6.137+"), "6.6.137");
    assert_eq!(canonicalize_linux_kernel_version("5.4"), "5.4");
}

#[test]
fn test_cpe_windows_11_pro() {
    let info = HostKernelInfo {
        os_family: OsFamily::Windows,
        kernel_release: "10.0.26100".to_string(),
        os_version: "Windows 11 Pro 24H2".to_string(),
        cpe23: "cpe:2.3:o:microsoft:windows_11:24h2:*:*:*:*:*:*:*".to_string(),
        architecture: "x86_64".to_string(),
    };
    let cpe = info.to_cpe23();
    assert_valid_cpe23(&cpe);
    assert!(cpe.starts_with("cpe:2.3:o:microsoft:windows_11:"));
}

#[test]
fn test_cpe_windows_server_2022() {
    let (product, version) = canonicalize_windows_cpe(20348, true, None);
    assert_eq!(product, "windows_server_2022");
    assert_eq!(version, "*");

    let info = parse_windows_kernel_info(
        10,
        0,
        20348,
        Some(1607),
        Some("Windows Server 2022 Datacenter"),
        Some("21H2"),
        "x86_64",
    );
    assert_valid_cpe23(&info.cpe23);
    assert!(info.cpe23.contains("windows_server_2022"));
}

#[test]
fn test_cpe_macos_sonoma() {
    let info = HostKernelInfo {
        os_family: OsFamily::MacOS,
        kernel_release: "23.5.0".to_string(),
        os_version: "macOS 14.5".to_string(),
        cpe23: "cpe:2.3:o:apple:macos:14.5:*:*:*:*:*:*:*".to_string(),
        architecture: "aarch64".to_string(),
    };
    let cpe = info.to_cpe23();
    assert_valid_cpe23(&cpe);
    assert!(cpe.starts_with("cpe:2.3:o:apple:macos:14.5"));
}

#[test]
fn test_cpe_macos_canonicalize_version() {
    assert_eq!(canonicalize_macos_version("14.4.1 (a)"), "14.4.1");
    assert_eq!(canonicalize_macos_version("14.5"), "14.5");
    assert_eq!(canonicalize_macos_version("13.6.3"), "13.6.3");
}

#[test]
fn test_cpe_colon_escaping_invariant() {
    let escaped = escape_cpe_attribute("6.8.0:rc1");
    assert_eq!(escaped, r"6.8.0\:rc1");

    let cpe = Cpe23::new_os("linux", "linux_kernel", &escaped);
    let formatted = cpe.to_formatted_string();

    let parts = split_unescaped_colons(&formatted);
    assert_eq!(
        parts.len(),
        13,
        "Delimiter colons must remain 12 (13 parts)"
    );
    assert_eq!(parts[0], "cpe");
    assert_eq!(parts[1], "2.3");
    assert_eq!(parts[2], "o");
    assert_eq!(parts[3], "linux");
    assert_eq!(parts[4], "linux_kernel");
    assert_eq!(parts[5], r"6.8.0\:rc1");
}

#[test]
fn test_cpe_whitespace_and_special_char_escaping() {
    assert_eq!(escape_cpe_attribute("Windows 11 Pro"), "windows_11_pro");
    assert_eq!(escape_cpe_attribute(""), "*");
    assert_eq!(escape_cpe_attribute("   "), "*");
    assert_eq!(escape_cpe_attribute("*"), "*");
    assert_eq!(escape_cpe_attribute("-"), "-");
}

#[test]
fn test_cpe_structural_token_count_13_fields() {
    let cpe = Cpe23::new_os("vendor_x", "product_y", "1.0.0");
    let formatted = cpe.to_formatted_string();
    assert_valid_cpe23(&formatted);

    let parts = split_unescaped_colons(&formatted);
    assert_eq!(parts.len(), 13);
    assert_eq!(parts[0], "cpe");
    assert_eq!(parts[1], "2.3");
    assert_eq!(parts[2], "o");
    assert_eq!(parts[3], "vendor_x");
    assert_eq!(parts[4], "product_y");
    assert_eq!(parts[5], "1.0.0");
    for part in &parts[6..13] {
        assert_eq!(part.as_str(), "*");
    }
}

#[test]
fn test_cpe_part_representations() {
    assert_eq!(CpePart::Application.as_str(), "a");
    assert_eq!(CpePart::OperatingSystem.as_str(), "o");
    assert_eq!(CpePart::Hardware.as_str(), "h");
}

#[test]
fn test_parse_linux_kernel_info_pure() {
    let info = parse_linux_kernel_info(
        "6.8.0-45-generic",
        Some("ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n"),
        "x86_64",
    );
    assert_eq!(info.os_family, OsFamily::Linux);
    assert_eq!(info.kernel_release, "6.8.0-45-generic");
    assert_eq!(info.os_version, "24.04");
    assert_eq!(
        info.cpe23,
        "cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*"
    );
    assert_eq!(info.architecture, "x86_64");
}

#[test]
fn test_parse_macos_kernel_info_pure() {
    let info = parse_macos_kernel_info(Some("14.5"), "23.5.0", "aarch64");
    assert_eq!(info.os_family, OsFamily::MacOS);
    assert_eq!(info.kernel_release, "23.5.0");
    assert_eq!(info.os_version, "14.5");
    assert_eq!(info.cpe23, "cpe:2.3:o:apple:macos:14.5:*:*:*:*:*:*:*");
    assert_eq!(info.architecture, "aarch64");
}
