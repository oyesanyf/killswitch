//! Empirical Challenge Gate Verification Test Suite for Milestone 3 Iteration 2
//!
//! Adversarial stress harness verifying:
//! 1. Panic containment and robust error reporting in `binary_format.rs` under adversarial fuzzing.
//! 2. Binary masquerade spoof escalation to `MALICIOUS_MASQUERADE_SPOOF` across Windows, Linux, and macOS.
//! 3. Layer 3 resource bounds (`MAX_REA_FILE_BYTES`, `MAX_PE_SECTIONS`, `MAX_SINGLE_STRING_BYTES`, `MAX_EXTRACTED_STRINGS`).
//! 4. Huge sparse file defense (instant rejection without multi-gigabyte memory allocations).
//! 5. Process lineage sysinfo optimization benchmark (< 100ms average scan time).

use killswitch_adjudication::{
    detect_binary_masquerade_spoof, extract_printable_strings, get_process_ancestry_chain,
    inspect_binary_format_safe, inspect_process_lineage, verify_binary_cryptographic_trust,
    AutonomousReaEngine, BinaryFormatKind, BinaryTrustVerdict, LineageImmunityVerdict,
    MAX_EXTRACTED_STRINGS, MAX_PE_SECTIONS, MAX_REA_FILE_BYTES, MAX_SINGLE_STRING_BYTES,
};
use std::fs::File;
use std::time::Instant;

/// Helper to synthesize a minimal PE64 buffer with configurable sections and RWX flag.
fn make_pe64_test_buffer(num_sections: u16, rwx: bool) -> Vec<u8> {
    let header_size = 0x80 + 4 + 20 + 240;
    let sec_table_size = (num_sections as usize) * 40;
    let total_size = header_size + sec_table_size + 512;
    let mut buf = vec![0u8; total_size];

    // DOS Header
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3C] = 0x80;

    let pe_off = 0x80;
    buf[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");

    // COFF Header
    let coff_off = pe_off + 4;
    buf[coff_off..coff_off + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // x86_64
    buf[coff_off + 2..coff_off + 4].copy_from_slice(&num_sections.to_le_bytes());
    buf[coff_off + 16..coff_off + 18].copy_from_slice(&240u16.to_le_bytes()); // opt hdr size

    // Optional Header
    let opt_off = coff_off + 20;
    buf[opt_off..opt_off + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
    buf[opt_off + 16..opt_off + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry point

    // Section table
    let sec_start = opt_off + 240;
    for i in 0..num_sections as usize {
        let off = sec_start + i * 40;
        let name = format!(".sec{}", i);
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(8);
        buf[off..off + copy_len].copy_from_slice(&name_bytes[..copy_len]);

        buf[off + 8..off + 12].copy_from_slice(&0x200u32.to_le_bytes()); // virtual size
        buf[off + 12..off + 16].copy_from_slice(&((0x1000 + i * 0x1000) as u32).to_le_bytes()); // virtual address
        buf[off + 16..off + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
        buf[off + 20..off + 24].copy_from_slice(&(header_size as u32).to_le_bytes()); // ptr to raw data

        let chars: u32 = if rwx {
            0x2000_0000 | 0x8000_0000 | 0x20 // EXECUTE | WRITE | CODE
        } else {
            0x2000_0000 | 0x4000_0000 | 0x20 // EXECUTE | READ | CODE
        };
        buf[off + 36..off + 40].copy_from_slice(&chars.to_le_bytes());
    }

    buf
}

/// Helper to synthesize a minimal ELF64 buffer with configurable sections and RWX flag.
fn make_elf64_test_buffer(num_sections: u16, rwx: bool) -> Vec<u8> {
    let header_size = 64;
    let sec_table_size = (num_sections as usize) * 64;
    let total_size = header_size + sec_table_size + 256;
    let mut buf = vec![0u8; total_size];

    buf[0..4].copy_from_slice(b"\x7fELF");
    buf[4] = 2; // 64-bit
    buf[5] = 1; // Little endian
    buf[6] = 1; // EV_CURRENT

    buf[18..20].copy_from_slice(&0x003Eu16.to_le_bytes()); // EM_X86_64
    buf[24..32].copy_from_slice(&0x0040_1000u64.to_le_bytes()); // entry
    buf[40..48].copy_from_slice(&(header_size as u64).to_le_bytes()); // e_shoff
    buf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    buf[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    buf[60..62].copy_from_slice(&num_sections.to_le_bytes()); // e_shnum

    let sec_start = header_size;
    for i in 0..num_sections as usize {
        let off = sec_start + i * 64;
        let flags: u64 = if rwx {
            0x1 | 0x2 | 0x4 // WRITE | ALLOC | EXECINSTR
        } else {
            0x2 | 0x4 // ALLOC | EXECINSTR
        };
        buf[off + 8..off + 16].copy_from_slice(&flags.to_le_bytes());
        buf[off + 16..off + 24].copy_from_slice(&((0x0040_1000 + i * 0x1000) as u64).to_le_bytes());
        buf[off + 24..off + 32].copy_from_slice(&(header_size as u64).to_le_bytes());
        buf[off + 32..off + 40].copy_from_slice(&64u64.to_le_bytes());
    }

    buf
}

// ============================================================================
// 1. Adversarial PE Fuzzing & Panic Containment Stress Tests
// ============================================================================

#[test]
fn test_adversarial_pe_fuzzing_zero_panics_and_clean_errors() {
    // Test 1: Sub-64 byte buffers starting with MZ
    for len in [2, 3, 10, 32, 63] {
        let mut short_buf = vec![0u8; len];
        short_buf[0] = b'M';
        short_buf[1] = b'Z';
        let res = inspect_binary_format_safe(&short_buf);
        assert!(res.is_err(), "Sub-64 byte buffer must fail");
        assert!(res.unwrap_err().contains("DOS header truncated"));
    }

    // Test 2: Adversarial e_lfanew pointers
    let test_lfanew_offsets: Vec<u32> = vec![
        0, 1, 63, // Under minimum 64
        64, 100, // Valid range but buffer too small for PE signature
        0x0001_0000, 0x7FFF_FFFF, 0xFFFF_FFFC, 0xFFFF_FFFF,
    ];
    for lfanew in test_lfanew_offsets {
        let mut buf = vec![0u8; 128];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&lfanew.to_le_bytes());
        let res = inspect_binary_format_safe(&buf);
        assert!(res.is_err(), "Adversarial e_lfanew 0x{:x} must fail", lfanew);
    }

    // Test 3: Corrupt PE signatures
    let bad_signatures = [b"NE\0\0", b"LE\0\0", b"PE\0\x01", b"PE\x01\0", b"\0\0\0\0", b"DEAD"];
    for sig in bad_signatures {
        let mut buf = vec![0u8; 256];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C] = 0x80;
        buf[0x80..0x84].copy_from_slice(sig);
        let res = inspect_binary_format_safe(&buf);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Invalid PE signature"));
    }

    // Test 4: Section count boundary and bomb rejection
    // Section count = 96 (boundary: maximum allowed)
    let pe_valid_boundary = make_pe64_test_buffer(96, false);
    let info = inspect_binary_format_safe(&pe_valid_boundary).expect("96 sections is valid boundary");
    assert_eq!(info.section_count, 96);
    assert_eq!(info.kind, BinaryFormatKind::Pe64);

    // Section count = 97 (bomb: 1 above MAX_PE_SECTIONS)
    let pe_bomb_97 = make_pe64_test_buffer(97, false);
    let err_97 = inspect_binary_format_safe(&pe_bomb_97).unwrap_err();
    assert!(err_97.contains("exceeds MAX_PE_SECTIONS (96)"));

    // Section count = 65535 (u16::MAX bomb)
    let mut pe_bomb_max = make_pe64_test_buffer(1, false);
    pe_bomb_max[0x80 + 4 + 2..0x80 + 4 + 4].copy_from_slice(&0xFFFFu16.to_le_bytes());
    let err_max = inspect_binary_format_safe(&pe_bomb_max).unwrap_err();
    assert!(err_max.contains("exceeds MAX_PE_SECTIONS (96)"));

    // Test 5: Section table offset overflow attacks
    let mut pe_overflow = make_pe64_test_buffer(5, false);
    // Set SizeOfOptionalHeader to 0xFFFF causing offset calculation to reach end of memory
    pe_overflow[0x80 + 4 + 16..0x80 + 4 + 18].copy_from_slice(&0xFFFFu16.to_le_bytes());
    let err_overflow = inspect_binary_format_safe(&pe_overflow).unwrap_err();
    assert!(err_overflow.contains("truncated") || err_overflow.contains("overflow"));

    // Test 6: Section raw data pointer pointing beyond buffer (entropy calculation resilience)
    let mut pe_oob_raw = make_pe64_test_buffer(1, false);
    let sec_off = 0x80 + 4 + 20 + 240;
    // Set PointerToRawData to 0x7FFF_0000 (way beyond buffer length)
    pe_oob_raw[sec_off + 20..sec_off + 24].copy_from_slice(&0x7FFF_0000u32.to_le_bytes());
    pe_oob_raw[sec_off + 16..sec_off + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    let info_oob = inspect_binary_format_safe(&pe_oob_raw).expect("Should parse headers safely");
    assert_eq!(info_oob.sections[0].entropy, 0.0, "OOB raw data should yield 0.0 entropy without panic");
}

// ============================================================================
// 2. Adversarial ELF Fuzzing & Panic Containment Stress Tests
// ============================================================================

#[test]
fn test_adversarial_elf_fuzzing_zero_panics_and_clean_errors() {
    // Test 1: Sub-52 byte buffers starting with \x7fELF
    for len in [4, 10, 32, 51] {
        let mut short_buf = vec![0u8; len];
        short_buf[0..4].copy_from_slice(b"\x7fELF");
        let res = inspect_binary_format_safe(&short_buf);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("ELF header truncated"));
    }

    // Test 2: Invalid EI_CLASS
    for bad_class in [0, 3, 4, 99, 255] {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = bad_class;
        let res = inspect_binary_format_safe(&buf);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Invalid ELF class"));
    }

    // Test 3: Invalid EI_DATA (encoding)
    for bad_data in [0, 3, 99, 255] {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2; // 64-bit
        buf[5] = bad_data;
        let res = inspect_binary_format_safe(&buf);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Invalid ELF data encoding"));
    }

    // Test 4: ELF Section count boundary and bomb rejection
    let elf_valid_boundary = make_elf64_test_buffer(96, false);
    let info = inspect_binary_format_safe(&elf_valid_boundary).expect("96 sections is valid boundary");
    assert_eq!(info.section_count, 96);
    assert_eq!(info.kind, BinaryFormatKind::Elf64);

    let elf_bomb_97 = make_elf64_test_buffer(97, false);
    let err_97 = inspect_binary_format_safe(&elf_bomb_97).unwrap_err();
    assert!(err_97.contains("exceeds MAX_PE_SECTIONS (96)"));

    let mut elf_bomb_max = make_elf64_test_buffer(1, false);
    elf_bomb_max[60..62].copy_from_slice(&0xFFFFu16.to_le_bytes());
    let err_max = inspect_binary_format_safe(&elf_bomb_max).unwrap_err();
    assert!(err_max.contains("exceeds MAX_PE_SECTIONS (96)"));

    // Test 5: Section table offset overflow
    let mut elf_overflow = make_elf64_test_buffer(1, false);
    elf_overflow[40..48].copy_from_slice(&u64::MAX.to_le_bytes()); // e_shoff = u64::MAX
    let err_overflow = inspect_binary_format_safe(&elf_overflow).unwrap_err();
    assert!(err_overflow.contains("overflow") || err_overflow.contains("truncated"));
}

// ============================================================================
// 3. Masquerade Spoof Escalation to MALICIOUS_MASQUERADE_SPOOF Matrix
// ============================================================================

#[test]
fn test_adversarial_masquerade_spoof_escalation_across_platforms() {
    let engine = AutonomousReaEngine::new();

    // Matrix of protected targets across Windows, Linux, and macOS
    let protected_targets = [
        ("svchost.exe", b"MZ_malformed_trash_payload".as_slice()),
        ("lsass.exe", b"MZ\0\0\0\0\0\0_bad_header".as_slice()),
        ("explorer.exe", b"\x7fELF_linux_binary_posing_as_explorer".as_slice()),
        ("cargo.exe", b"NOT_EVEN_AN_EXECUTABLE_FILE".as_slice()),
        ("systemd", b"MZ_windows_binary_posing_as_systemd".as_slice()),
        ("sshd", b"\x7fELF\x01\x01_corrupt_elf32_header".as_slice()),
        ("launchd", b"RANDOM_CORRUPT_BYTES_FOR_MACOS_DAEMON".as_slice()),
        ("WindowServer", b"MZ_windows_binary_posing_as_windowserver".as_slice()),
    ];

    for (target_name, corrupt_payload) in protected_targets {
        // Direct masquerade check
        let spoof_reason = detect_binary_masquerade_spoof(target_name, None, Some(corrupt_payload));
        assert!(
            spoof_reason.is_some(),
            "Target '{}' must be detected as masquerade spoof",
            target_name
        );
        let reason_str = spoof_reason.unwrap();
        assert!(
            reason_str.contains("REA_MASQUERADE_SPOOF_DETECTED"),
            "Target '{}' reason must contain spoof alert: {}",
            target_name,
            reason_str
        );

        // REA Engine evaluation with payload
        let eval = engine.evaluate_detector_candidate_with_payload(
            "adversarial_test_detector",
            target_name,
            "Anomalous process invocation with payload",
            0.50,
            Some(corrupt_payload),
        );

        assert!(
            eval.masquerade_escalated,
            "Target '{}' must have masquerade_escalated == true",
            target_name
        );
        assert!(
            !eval.benign_veto,
            "Target '{}' masquerade spoof must NEVER be benign vetoed",
            target_name
        );
        assert_eq!(
            eval.verdict, "MALICIOUS_MASQUERADE_SPOOF",
            "Target '{}' must receive MALICIOUS_MASQUERADE_SPOOF verdict",
            target_name
        );
        assert!(
            eval.rea_threat_score >= 0.95,
            "Target '{}' score must be >= 0.95 (got {})",
            target_name,
            eval.rea_threat_score
        );
        assert!(
            eval.adjusted_score >= 0.92,
            "Target '{}' adjusted score must be >= 0.92 (got {})",
            target_name,
            eval.adjusted_score
        );
    }
}

// ============================================================================
// 4. Resource Bounds & Huge Sparse File Defense
// ============================================================================

#[test]
fn test_adversarial_resource_bounds_huge_sparse_files() {
    assert_eq!(MAX_REA_FILE_BYTES, 256 * 1024 * 1024);
    assert_eq!(MAX_PE_SECTIONS, 96);
    assert_eq!(MAX_EXTRACTED_STRINGS, 2048);
    assert_eq!(MAX_SINGLE_STRING_BYTES, 4096);

    let tmp = tempfile::tempdir().expect("Failed to create tempdir");

    // Case A: File exactly at MAX_REA_FILE_BYTES + 1 byte
    let file_path_256mb = tmp.path().join("file_256mb_plus_1.exe");
    let file_a = File::create(&file_path_256mb).expect("Failed to create file A");
    file_a
        .set_len(MAX_REA_FILE_BYTES + 1)
        .expect("Failed to set file length");

    let start_a = Instant::now();
    let verdict_a = verify_binary_cryptographic_trust(&file_path_256mb);
    let elapsed_a = start_a.elapsed();

    assert!(
        elapsed_a.as_millis() < 50,
        "File A size check must execute in < 50ms, took {:?}",
        elapsed_a
    );
    assert!(!verdict_a.is_trusted());
    match verdict_a {
        BinaryTrustVerdict::UntrustedIoError { error } => {
            assert!(error.contains("exceeds maximum allowed size"));
        }
        BinaryTrustVerdict::UntrustedWritableLocation { reason, .. } => {
            assert!(reason.contains("exceeds maximum allowed size"));
        }
        other => panic!("Expected UntrustedIoError or UntrustedWritableLocation, got {:?}", other),
    }

    // Case B: Massive 2.5 GiB sparse file (10x MAX_REA_FILE_BYTES)
    let file_path_2gb = tmp.path().join("file_massive_2gb.exe");
    let file_b = File::create(&file_path_2gb).expect("Failed to create file B");
    file_b
        .set_len(10 * MAX_REA_FILE_BYTES)
        .expect("Failed to set 2.5 GiB sparse file length");

    let start_b = Instant::now();
    let verdict_b = verify_binary_cryptographic_trust(&file_path_2gb);
    let elapsed_b = start_b.elapsed();

    // If it attempted to read 2.5 GiB into RAM, this would either take seconds or OOM crash
    assert!(
        elapsed_b.as_millis() < 50,
        "Massive file check must abort immediately (< 50ms), took {:?}",
        elapsed_b
    );
    assert!(!verdict_b.is_trusted());
    match verdict_b {
        BinaryTrustVerdict::UntrustedIoError { error } => {
            assert!(error.contains("exceeds maximum allowed size"));
        }
        BinaryTrustVerdict::UntrustedWritableLocation { reason, .. } => {
            assert!(reason.contains("exceeds maximum allowed size"));
        }
        other => panic!("Expected UntrustedIoError or UntrustedWritableLocation, got {:?}", other),
    }

    // Case C: String extraction bounds under adversarial 1,000,000 byte continuous character payload
    let huge_payload = vec![b'A'; 1_000_000];
    let start_str = Instant::now();
    let extracted = extract_printable_strings(&huge_payload, 4, 100);
    let elapsed_str = start_str.elapsed();

    assert!(
        elapsed_str.as_millis() < 100,
        "String extraction must complete quickly, took {:?}",
        elapsed_str
    );
    assert_eq!(extracted.len(), 1);
    assert_eq!(
        extracted[0].len(),
        MAX_SINGLE_STRING_BYTES,
        "Extracted string must be bounded to MAX_SINGLE_STRING_BYTES (4096)"
    );
}

// ============================================================================
// 5. Lineage Traversal Performance & Memory Benchmark
// ============================================================================

#[test]
fn test_process_lineage_performance_benchmark_and_sysinfo_optimization() {
    let current_pid = std::process::id();

    // Verify individual check performance: must execute under 150ms on real OS process table
    let single_start = Instant::now();
    let verdict = inspect_process_lineage(current_pid, Some("cargo_test"));
    let single_elapsed = single_start.elapsed();
    assert!(
        single_elapsed.as_millis() < 150,
        "Single lineage check took {:?}, must be under 150ms",
        single_elapsed
    );
    assert!(matches!(
        verdict,
        LineageImmunityVerdict::ImmuneTarget { .. }
            | LineageImmunityVerdict::ImmuneAncestor { .. }
            | LineageImmunityVerdict::NotImmune
    ));

    // Run 10 consecutive ancestry inspections to verify System::new() + refresh_processes()
    // does not cause thread contention, non-process I/O overhead, or memory leakage
    let start = Instant::now();
    const ITERATIONS: usize = 10;
    for _ in 0..ITERATIONS {
        let _ = inspect_process_lineage(current_pid, Some("cargo_test"));
        let chain = get_process_ancestry_chain(current_pid);
        assert!(chain.len() <= 5);
    }
    let elapsed = start.elapsed();
    let avg_ms = elapsed.as_millis() as f64 / (ITERATIONS as f64 * 2.0); // 2 scans per iteration

    // Each process scan must average well under 100ms
    assert!(
        avg_ms < 100.0,
        "Average process scan took {:.2}ms (total {:?}), must be under 100ms",
        avg_ms,
        elapsed
    );

    // Verify PID 0 and PID 4 retain immutable system immunity
    assert!(matches!(
        inspect_process_lineage(0, None),
        LineageImmunityVerdict::ImmuneTarget { pid: 0, .. }
    ));
    assert!(matches!(
        inspect_process_lineage(4, None),
        LineageImmunityVerdict::ImmuneTarget { pid: 4, .. }
    ));
}
