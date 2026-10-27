//! Integration and Empirical Verification Tests for REA Binary Format Parser,
//! Resource Bounds, and Lineage Sysinfo Optimization.

use killswitch_adjudication::{
    detect_binary_masquerade_spoof, extract_printable_strings, get_process_ancestry_chain,
    inspect_binary_format_safe, inspect_process_lineage, verify_binary_cryptographic_trust,
    AutonomousReaEngine, BinaryFormatKind, BinaryTrustVerdict, LineageImmunityVerdict,
    MAX_EXTRACTED_STRINGS, MAX_PE_SECTIONS, MAX_REA_FILE_BYTES, MAX_SINGLE_STRING_BYTES,
};
use std::fs::File;

/// Helper to synthesize a valid minimal 64-bit PE binary buffer.
fn create_valid_pe64_bytes(rwx: bool) -> Vec<u8> {
    let mut buf = vec![0u8; 1024];

    // 1. DOS Header
    buf[0] = b'M';
    buf[1] = b'Z';
    // e_lfanew at 0x3C = 128 (0x80)
    buf[0x3C] = 0x80;
    buf[0x3D] = 0x00;
    buf[0x3E] = 0x00;
    buf[0x3F] = 0x00;

    let pe_off = 0x80;
    // 2. PE Signature "PE\0\0"
    buf[pe_off] = b'P';
    buf[pe_off + 1] = b'E';
    buf[pe_off + 2] = 0;
    buf[pe_off + 3] = 0;

    // 3. COFF File Header (20 bytes)
    let coff_off = pe_off + 4;
    // Machine = x86_64 (0x8664)
    buf[coff_off] = 0x64;
    buf[coff_off + 1] = 0x86;
    // NumberOfSections = 1
    buf[coff_off + 2] = 0x01;
    buf[coff_off + 3] = 0x00;
    // SizeOfOptionalHeader = 240 (0x00F0)
    buf[coff_off + 16] = 0xF0;
    buf[coff_off + 17] = 0x00;

    // 4. Optional Header (PE32+)
    let opt_off = coff_off + 20;
    // Magic = 0x020b (PE32+)
    buf[opt_off] = 0x0B;
    buf[opt_off + 1] = 0x02;
    // AddressOfEntryPoint = 0x1000
    buf[opt_off + 16] = 0x00;
    buf[opt_off + 17] = 0x10;
    buf[opt_off + 18] = 0x00;
    buf[opt_off + 19] = 0x00;

    // 5. Section Table (1 section, 40 bytes)
    let sec_off = opt_off + 240;
    // Name = ".text\0\0\0"
    buf[sec_off..sec_off + 5].copy_from_slice(b".text");
    // VirtualSize = 0x200
    buf[sec_off + 8] = 0x00;
    buf[sec_off + 9] = 0x02;
    // VirtualAddress = 0x1000
    buf[sec_off + 12] = 0x00;
    buf[sec_off + 13] = 0x10;
    // SizeOfRawData = 0x200 (512)
    buf[sec_off + 16] = 0x00;
    buf[sec_off + 17] = 0x02;
    // PointerToRawData = 512 (0x0200)
    buf[sec_off + 20] = 0x00;
    buf[sec_off + 21] = 0x02;
    // Characteristics
    if rwx {
        // IMAGE_SCN_MEM_EXECUTE (0x20000000) | IMAGE_SCN_MEM_WRITE (0x80000000) | CODE (0x20)
        let chars: u32 = 0x2000_0000 | 0x8000_0000 | 0x20;
        buf[sec_off + 36..sec_off + 40].copy_from_slice(&chars.to_le_bytes());
    } else {
        // IMAGE_SCN_MEM_EXECUTE (0x20000000) | IMAGE_SCN_MEM_READ (0x40000000) | CODE (0x20)
        let chars: u32 = 0x2000_0000 | 0x4000_0000 | 0x20;
        buf[sec_off + 36..sec_off + 40].copy_from_slice(&chars.to_le_bytes());
    }

    // 6. Section raw payload
    let raw_start = 512;
    for (i, byte) in buf[raw_start..raw_start + 512].iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }

    buf
}

/// Helper to synthesize a valid minimal 64-bit ELF binary buffer.
fn create_valid_elf64_bytes(rwx: bool) -> Vec<u8> {
    let mut buf = vec![0u8; 512];

    // ELF header (64 bytes)
    buf[0..4].copy_from_slice(b"\x7fELF");
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // ELFDATA2LSB (little endian)
    buf[6] = 1; // EV_CURRENT

    // e_machine = EM_X86_64 (0x003E)
    buf[18] = 0x3E;
    buf[19] = 0x00;

    // e_entry = 0x00401000
    let entry: u64 = 0x0040_1000;
    buf[24..32].copy_from_slice(&entry.to_le_bytes());

    // e_shoff = 64 (section table starts right after header)
    let shoff: u64 = 64;
    buf[40..48].copy_from_slice(&shoff.to_le_bytes());

    // e_ehsize = 64
    buf[52] = 64;
    // e_shentsize = 64
    buf[58] = 64;
    // e_shnum = 1
    buf[60] = 1;

    // Section header 0 at offset 64 (64 bytes)
    let sec_off = 64;
    // sh_flags = SHF_WRITE (0x1) | SHF_ALLOC (0x2) | SHF_EXECINSTR (0x4)
    let flags: u64 = if rwx {
        0x1 | 0x2 | 0x4
    } else {
        0x2 | 0x4
    };
    buf[sec_off + 8..sec_off + 16].copy_from_slice(&flags.to_le_bytes());
    // sh_addr = 0x401000
    let addr: u64 = 0x40_1000;
    buf[sec_off + 16..sec_off + 24].copy_from_slice(&addr.to_le_bytes());
    // sh_offset = 128
    let off: u64 = 128;
    buf[sec_off + 24..sec_off + 32].copy_from_slice(&off.to_le_bytes());
    // sh_size = 64
    let sz: u64 = 64;
    buf[sec_off + 32..sec_off + 40].copy_from_slice(&sz.to_le_bytes());

    // Raw section content at 128..192
    for (i, byte) in buf[128..192].iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }

    buf
}

#[test]
fn test_valid_pe64_header_parsing_and_rwx() {
    let pe_rwx = create_valid_pe64_bytes(true);
    let info = inspect_binary_format_safe(&pe_rwx).expect("Failed to parse valid PE64");
    assert_eq!(info.kind, BinaryFormatKind::Pe64);
    assert_eq!(info.architecture, "x86_64 (AMD64)");
    assert!(info.is_64_bit);
    assert_eq!(info.section_count, 1);
    assert_eq!(info.entry_point, 0x1000);
    assert!(info.has_rwx_section);
    assert_eq!(info.sections.len(), 1);
    assert!(info.sections[0].is_rwx);
    assert!(info.sections[0].is_executable);
    assert!(info.sections[0].is_writable);
    assert!(info.sections[0].entropy > 0.0);

    let pe_ro = create_valid_pe64_bytes(false);
    let info_ro = inspect_binary_format_safe(&pe_ro).expect("Failed to parse valid PE64 RO");
    assert!(!info_ro.has_rwx_section);
    assert!(info_ro.sections[0].is_executable);
    assert!(!info_ro.sections[0].is_writable);
}

#[test]
fn test_valid_elf64_header_parsing_and_rwx() {
    let elf_rwx = create_valid_elf64_bytes(true);
    let info = inspect_binary_format_safe(&elf_rwx).expect("Failed to parse valid ELF64");
    assert_eq!(info.kind, BinaryFormatKind::Elf64);
    assert_eq!(info.architecture, "x86_64 (EM_X86_64)");
    assert!(info.is_64_bit);
    assert_eq!(info.section_count, 1);
    assert_eq!(info.entry_point, 0x0040_1000);
    assert!(info.has_rwx_section);
    assert_eq!(info.sections.len(), 1);
    assert!(info.sections[0].is_rwx);
    assert!(info.sections[0].entropy > 0.0);

    let elf_ro = create_valid_elf64_bytes(false);
    let info_ro = inspect_binary_format_safe(&elf_ro).expect("Failed to parse valid ELF64 RO");
    assert!(!info_ro.has_rwx_section);
    assert!(info_ro.sections[0].is_executable);
    assert!(!info_ro.sections[0].is_writable);
}

#[test]
fn test_macho_recognition() {
    let macho_64 = 0xfeedfacfu32.to_be_bytes();
    let info = inspect_binary_format_safe(&macho_64).expect("Mach-O should be recognized");
    assert_eq!(info.kind, BinaryFormatKind::MachO);
    assert!(info.is_64_bit);
    assert_eq!(info.endianness, "big");

    let macho_32 = 0xfeedfaceu32.to_be_bytes();
    let info32 = inspect_binary_format_safe(&macho_32).expect("Mach-O 32 should be recognized");
    assert_eq!(info32.kind, BinaryFormatKind::MachO);
    assert!(!info32.is_64_bit);
}

#[test]
fn test_pe_section_bomb_rejection() {
    let mut pe_bomb = create_valid_pe64_bytes(false);
    let coff_off = 0x80 + 4;
    // Set NumberOfSections to 120 (> MAX_PE_SECTIONS = 96)
    pe_bomb[coff_off + 2] = 120;
    pe_bomb[coff_off + 3] = 0;

    let result = inspect_binary_format_safe(&pe_bomb);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("exceeds MAX_PE_SECTIONS"));
    assert!(err.contains(&format!("({})", MAX_PE_SECTIONS)));
}

#[test]
fn test_elf_section_bomb_rejection() {
    let mut elf_bomb = create_valid_elf64_bytes(false);
    // Set e_shnum to 150 (> MAX_PE_SECTIONS = 96)
    elf_bomb[60] = 150;
    elf_bomb[61] = 0;

    let result = inspect_binary_format_safe(&elf_bomb);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("exceeds MAX_PE_SECTIONS"));
    assert!(err.contains(&format!("({})", MAX_PE_SECTIONS)));
}

#[test]
fn test_truncated_and_corrupt_binary_headers() {
    // Empty buffer
    assert!(inspect_binary_format_safe(&[]).is_err());

    // Truncated DOS header (< 64 bytes)
    assert!(inspect_binary_format_safe(b"MZ12345").is_err());

    // Invalid PE signature offset pointing out of bounds
    let mut bad_pe = vec![0u8; 128];
    bad_pe[0] = b'M';
    bad_pe[1] = b'Z';
    bad_pe[0x3C] = 0xFF;
    bad_pe[0x3D] = 0xFF;
    assert!(inspect_binary_format_safe(&bad_pe).is_err());

    // Truncated ELF header (< 52 bytes)
    assert!(inspect_binary_format_safe(b"\x7fELF_short").is_err());

    // Invalid ELF class
    let mut bad_elf = vec![0u8; 64];
    bad_elf[0..4].copy_from_slice(b"\x7fELF");
    bad_elf[4] = 99; // Invalid class
    assert!(inspect_binary_format_safe(&bad_elf).is_err());
}

#[test]
fn test_panic_containment_on_adversarial_corrupted_inputs() {
    // Malformed binary buffer with random noise and MZ magic
    let mut fuzzed = vec![0u8; 500];
    fuzzed[0] = b'M';
    fuzzed[1] = b'Z';
    fuzzed[0x3C] = 64; // e_lfanew
    fuzzed[64..68].copy_from_slice(b"PE\0\0");
    // Poison offsets and sizes
    fuzzed[68..500].fill(0xFF);

    // Must return Err without crashing/panicking the process
    let result = inspect_binary_format_safe(&fuzzed);
    assert!(result.is_err());
}

#[test]
fn test_resource_bounds_constants() {
    assert_eq!(MAX_REA_FILE_BYTES, 256 * 1024 * 1024);
    assert_eq!(MAX_PE_SECTIONS, 96);
    assert_eq!(MAX_EXTRACTED_STRINGS, 2048);
    assert_eq!(MAX_SINGLE_STRING_BYTES, 4096);
}

#[test]
fn test_single_string_length_bound_in_string_extraction() {
    // Create byte buffer with 10,000 continuous printable characters
    let long_bytes = vec![b'X'; 10_000];
    let extracted = extract_printable_strings(&long_bytes, 4, 10);
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].len(), MAX_SINGLE_STRING_BYTES);
}

#[test]
fn test_win_trust_file_size_bound_enforcement() {
    let tmp = tempfile::tempdir().expect("Failed to create tempdir");
    let huge_file_path = tmp.path().join("oversized_test_binary.exe");

    let file = File::create(&huge_file_path).expect("Failed to create temp file");
    // Set file length to MAX_REA_FILE_BYTES + 1024 (sparse file allocation)
    file.set_len(MAX_REA_FILE_BYTES + 1024)
        .expect("Failed to set sparse file len");

    let verdict = verify_binary_cryptographic_trust(&huge_file_path);
    assert!(!verdict.is_trusted());
    assert!(verdict.is_untrusted());

    match verdict {
        BinaryTrustVerdict::UntrustedIoError { error } => {
            assert!(
                error.contains("exceeds maximum allowed size"),
                "Error message should mention exceeding size: {}",
                error
            );
        }
        BinaryTrustVerdict::UntrustedWritableLocation { reason, .. } => {
            assert!(
                reason.contains("exceeds maximum allowed size"),
                "Reason should mention exceeding size: {}",
                reason
            );
        }
        other => panic!("Expected UntrustedIoError or UntrustedWritableLocation, got: {:?}", other),
    }
}

#[test]
fn test_process_lineage_refresh_optimization() {
    let current_pid = std::process::id();
    // Target immunity check for current process
    let verdict = inspect_process_lineage(current_pid, Some("cargo_test"));
    assert!(matches!(
        verdict,
        LineageImmunityVerdict::ImmuneTarget { .. }
            | LineageImmunityVerdict::ImmuneAncestor { .. }
            | LineageImmunityVerdict::NotImmune
    ));

    // Ancestry chain lookup
    let chain = get_process_ancestry_chain(current_pid);
    // Chain must be returned without panic or errors
    assert!(chain.len() <= 5);

    // Immunity check on PID 0 and 4
    let pid0_verdict = inspect_process_lineage(0, None);
    assert!(matches!(pid0_verdict, LineageImmunityVerdict::ImmuneTarget { pid: 0, .. }));

    let pid4_verdict = inspect_process_lineage(4, None);
    assert!(matches!(pid4_verdict, LineageImmunityVerdict::ImmuneTarget { pid: 4, .. }));
}

#[test]
fn test_end_to_end_masquerade_spoof_escalation_in_rea_engine() {
    let engine = AutonomousReaEngine::new();

    // Corrupted payload posing as protected svchost.exe
    let corrupted_payload = b"MZ\x00\x00_malformed_truncated_pe_header";
    let eval = engine.evaluate_detector_candidate_with_payload(
        "edr_process_anomaly",
        "svchost.exe",
        "Process spawned from unknown trigger",
        0.55,
        Some(corrupted_payload),
    );

    assert!(eval.masquerade_escalated);
    assert!(!eval.benign_veto);
    assert_eq!(eval.verdict, "MALICIOUS_MASQUERADE_SPOOF");
    assert!(eval.adjusted_score >= 0.92);
    assert!(eval.rea_threat_score >= 0.95);
    assert!(eval.explanation.contains("binary format validation"));

    // PE with section bomb posing as protected lsass.exe
    let mut pe_bomb = create_valid_pe64_bytes(false);
    let coff_off = 0x80 + 4;
    pe_bomb[coff_off + 2] = 100; // 100 > MAX_PE_SECTIONS (96)
    pe_bomb[coff_off + 3] = 0;

    let eval_bomb = engine.evaluate_detector_candidate_with_payload(
        "edr_section_anomaly",
        "lsass.exe",
        "Suspicious section headers detected",
        0.50,
        Some(&pe_bomb),
    );

    assert!(eval_bomb.masquerade_escalated);
    assert_eq!(eval_bomb.verdict, "MALICIOUS_MASQUERADE_SPOOF");
    assert!(eval_bomb.explanation.contains("excessive section count") || eval_bomb.explanation.contains("binary format validation"));

    // Completely non-executable header posing as protected explorer.exe
    let eval_bad_magic = engine.evaluate_detector_candidate_with_payload(
        "edr_magic_anomaly",
        "explorer.exe",
        "Unknown file header",
        0.50,
        Some(b"NOT_AN_EXECUTABLE"),
    );

    assert!(eval_bad_magic.masquerade_escalated);
    assert_eq!(eval_bad_magic.verdict, "MALICIOUS_MASQUERADE_SPOOF");
    assert!(eval_bad_magic.explanation.contains("non-executable payload header"));
}

#[test]
fn test_detect_binary_masquerade_spoof_disk_file_oversized() {
    let tmp = tempfile::tempdir().expect("Failed to create tempdir");
    let huge_protected = tmp.path().join("svchost.exe");
    let file = File::create(&huge_protected).expect("Failed to create file");
    file.set_len(MAX_REA_FILE_BYTES + 512).expect("set_len failed");

    let result = detect_binary_masquerade_spoof(
        huge_protected.to_str().unwrap(),
        Some(&huge_protected),
        None,
    );
    assert!(result.is_some());
    let reason = result.unwrap();
    // Must flag as masquerade spoof due to untrusted writable path or size exceeding max
    assert!(
        reason.contains("exceeds maximum allowed size")
            || reason.contains("untrusted writable/temp path")
    );
}
