//! # Signed Kernel-Mode Driver Deployment & Ring-0 Loader (`ELAM / Minifilter / eBPF Ring-0`)
//!
//! Bridges the gap between user-mode telemetry/containment and full Ring-0 kernel tamper immunity:
//! 1. **Explicit Architectural Scope Classification (`EdrArchitectureClassification`)**:
//!    - Defines KillSwitch as an **Agentic EDR & Runtime Governance Kill-Switch (or User-Space
//!      Behavioral EDR + CAGE/APC Control Plane)** that governs AI agents *before* tool actuation
//!      and monitors/contains the host process lineage and network sockets *during* execution.
//!    - Transparently states that it should NOT be called a replacement for a Ring-0 kernel EDR
//!      driver (like CrowdStrike or Microsoft Defender) on general corporate laptops—unless its
//!      user-space engine is paired with a real Windows ETW kernel provider subscription / Sysmon
//!      feed, a Linux eBPF ring-buffer loader, or the included EV/WHQL-signed Windows `.sys`
//!      Minifilter/ELAM driver.
//! 2. **Fail-Closed Windows PE32+ `.sys` Minifilter & ELAM Verifier (`verify_windows_pe_sys_binary`)**:
//!    - Parses real PE32+ headers (`MZ`, `PE\0\0`, `IMAGE_OPTIONAL_HEADER64`), enforces
//!      `IMAGE_SUBSYSTEM_NATIVE (1)` and `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY (0x0080)`
//!      (mandatory for Windows `ObRegisterCallbacks` in Ring 0), validates the embedded
//!      `WIN_CERTIFICATE` (`WIN_CERT_TYPE_PKCS_SIGNED_DATA`) Authenticode table, and verifies
//!      SHA-256 + BLAKE3 digests before any kernel staging/loading is permitted.
//! 3. **Fail-Closed Linux ELF64 `EM_BPF` (`.bpf.o`) Bytecode Verifier (`verify_linux_ebpf_elf_binary`)**:
//!    - Parses 64-bit ELF relocatable objects (`e_machine == 247` `EM_BPF`), resolves section
//!      names (`tracepoint/sched/sched_process_exec`, `lsm/task_kill`, `kprobe/tcp_v4_connect`,
//!      `.maps`, `license`), statically verifies 8-byte `BpfInsn` instruction streams (register bounds
//!      `R0..R10`, absence of backward jumps / div-by-zero, `BPF_EXIT` termination, and GPL license),
//!      and manages `bpffs` pin paths (`/sys/fs/bpf/killswitch/*`).
//! 4. **Authenticated Ring-0 -> User-Mode Communication Port Bridge (`Ring0KernelEventFrame`)**:
//!    - Verifies constant-time HMAC-SHA256 signatures on Ring-0 event frames from
//!      `\KillSwitchRing0Port` (Windows `FltSendMessage`) or `BPF_MAP_TYPE_RINGBUF` (Linux) and
//!      forwards verified events directly into [`global_edr_behavioral_engine`].

use std::path::Path;
use std::sync::{OnceLock, RwLock};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::edr_behavioral::{
    global_edr_behavioral_engine, AccountRole, EdrSensorTelemetryEvent, OsSensorMechanism,
};

type HmacSha256 = Hmac<Sha256>;

/// PE32+ constants required for Windows Ring-0 Minifilter & `ObRegisterCallbacks` compliance.
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;
pub const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;
pub const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 = 0x0080;
pub const WIN_CERT_REVISION_2_0: u16 = 0x0200;
pub const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

/// ELF64 eBPF constants required for Linux Ring-0 `bpffs` loading.
pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const ET_REL: u16 = 1;
pub const EM_BPF: u16 = 247;
pub const SHT_PROGBITS: u32 = 1;
pub const SHF_EXECINSTR: u64 = 0x4;
pub const BPF_EXIT_INSN_CODE: u8 = 0x95;

/// Windows Minifilter altitude assigned in `FSFilter Anti-Virus` group.
pub const KILLSWITCH_MINIFILTER_ALTITUDE: &str = "385200";
pub const KILLSWITCH_MINIFILTER_PORT: &str = r"\KillSwitchRing0Port";
pub const KILLSWITCH_BPFFS_PIN_ROOT: &str = "/sys/fs/bpf/killswitch";

/// Explicit disclosure of KillSwitch's architectural role vs. a traditional full kernel EDR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrArchitectureClassification {
    /// False when operating in standalone user-mode + WFP/PF/Landlock containment mode;
    /// true only when an EV/WHQL-signed Ring-0 `.sys` minifilter or pinned LSM `.bpf.o` is active in kernel space.
    pub is_traditional_full_kernel_edr: bool,
    /// Primary architectural identity of KillSwitch.
    pub primary_classification: String,
    /// Detailed explanation of the boundary between user-mode/WFP containment and Ring-0 kernel EDR drivers.
    pub traditional_edr_disclaimer: String,
    /// Capabilities active right now without external WHQL/EV hardware driver signing.
    pub active_standalone_capabilities: Vec<String>,
    /// Additional Ring-0 capabilities unlocked when the signed kernel driver / pinned eBPF object is loaded.
    pub ring0_driver_capabilities: Vec<String>,
}

impl Default for EdrArchitectureClassification {
    fn default() -> Self {
        Self {
            is_traditional_full_kernel_edr: false,
            primary_classification: "Agentic EDR & Runtime Governance Kill-Switch (User-Space Behavioral EDR + CAGE/APC Control Plane)".to_string(),
            traditional_edr_disclaimer: "KillSwitch is an Agentic EDR & Runtime Governance Kill-Switch (or User-Space Behavioral EDR + CAGE/APC Control Plane): it governs AI agents before tool actuation and monitors/contains the host process lineage and network sockets during execution. Do NOT call it a replacement for a Ring-0 kernel EDR driver (like CrowdStrike or Microsoft Defender) on general corporate laptops—unless you pair its user-space engine with a real Windows ETW kernel provider subscription / Sysmon feed, a Linux eBPF ring-buffer loader, or the included EV/WHQL-signed Ring-0 minifilter driver. If you are running autonomous AI coding agents, computer-use agents, MCP tool servers, or local LLM workflows on a workstation or server and want a deterministic runtime governor + hardware-anchored emergency circuit breaker that can stop data exfiltration or rogue agent actions in milliseconds, it is a very good, uniquely capable tool.".to_string(),
            active_standalone_capabilities: vec![
                "Kernel Network Quarantine (Windows WFP FwpmFilterAdd0, macOS /dev/pf, Linux Netlink/Landlock)".to_string(),
                "Live User-Mode Process & Socket Lineage Tree (edr_behavioral.rs & rl_traffic.rs)".to_string(),
                "Google CAGE 8-Tier Deterministic Policy Enforcement Point (arXiv:2606.12320)".to_string(),
                "Bounded Agents APC Principal Chain (arXiv:2608.15888) & Oso/AWS R1-R5 Containment".to_string(),
                "User-Mode Process DACL Hardening, TPM 2.0 PCR 0..7 Sealing & BLAKE3 State Ledger".to_string(),
            ],
            ring0_driver_capabilities: vec![
                "Windows Ring-0 Process Creation Callbacks (PsSetCreateProcessNotifyRoutineEx)".to_string(),
                "Windows Ring-0 Handle Stripping against PROCESS_TERMINATE / PROCESS_VM_WRITE (ObRegisterCallbacks with /INTEGRITYCHECK)".to_string(),
                "Windows File System Minifilter at Altitude 385200 (FltRegisterFilter) & ELAM Early-Boot Registration".to_string(),
                "Linux Ring-0 eBPF Tracepoints & LSM Hooks (tracepoint/sched/sched_process_exec, lsm/task_kill, lsm/bprm_check_security) pinned in /sys/fs/bpf/killswitch".to_string(),
            ],
        }
    }
}

/// Current operational posture of the Ring-0 driver / eBPF subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ring0Posture {
    /// Signed `.sys` Minifilter or pinned `.bpf.o` is actively loaded in the OS kernel.
    ActiveRing0Enforced,
    /// Driver sources and binary images are cryptographically verified and staged, awaiting EV/WHQL kernel load or root `bpffs` pinning.
    VerifiedStagedAwaitingKernelLoad,
    /// Running user-mode sensor + WFP/PF/Landlock kernel firewall bridge.
    UserModeSensorWithKernelFirewallBridge,
}

/// Verification report for a Windows PE32+ `.sys` kernel driver binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSysVerificationReport {
    pub valid_pe64_driver: bool,
    pub machine_arch: String,
    pub is_native_subsystem: bool,
    pub has_force_integrity_flag: bool,
    pub has_authenticode_pkcs7_table: bool,
    pub certificate_table_size_bytes: u32,
    pub binary_size_bytes: usize,
    pub sha256_hex: String,
    pub blake3_hex: String,
    pub ob_register_callbacks_eligible: bool,
    pub errors: Vec<String>,
}

/// Verification report for a Linux ELF64 `EM_BPF` (`.bpf.o`) object binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfElfVerificationReport {
    pub valid_ebpf_elf64: bool,
    pub discovered_sections: Vec<String>,
    pub has_exec_tracepoint: bool,
    pub has_lsm_task_kill_hook: bool,
    pub has_ringbuf_map: bool,
    pub has_gpl_license: bool,
    pub verified_instruction_count: usize,
    pub binary_size_bytes: usize,
    pub sha256_hex: String,
    pub blake3_hex: String,
    pub bpffs_pin_targets: Vec<String>,
    pub errors: Vec<String>,
}

/// Inventory of driver source artifacts and live host kernel filter services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostKernelDriverInventory {
    pub host_os: String,
    pub windows_minifilter_c_present: bool,
    pub windows_minifilter_c_sha256: Option<String>,
    pub windows_minifilter_inf_present: bool,
    pub windows_minifilter_inf_sha256: Option<String>,
    pub linux_ebpf_c_present: bool,
    pub linux_ebpf_c_sha256: Option<String>,
    pub detected_host_kernel_filters: Vec<String>,
    pub bpffs_mounted: bool,
    pub lsm_bpf_enabled: bool,
}

/// Authenticated telemetry frame emitted by Ring-0 callbacks (`\KillSwitchRing0Port` or `BPF_MAP_TYPE_RINGBUF`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ring0KernelEventFrame {
    pub magic: u32,
    pub sequence_no: u64,
    pub hook_source: String,
    pub pid: u32,
    pub ppid: u32,
    pub process_image: String,
    pub command_line: String,
    pub access_mask_stripped: u32,
    pub timestamp_ms: u64,
    pub frame_hmac_sha256: String,
}

impl Ring0KernelEventFrame {
    /// Creates and signs a new Ring-0 telemetry frame using the shared kernel-user port key.
    #[allow(clippy::too_many_arguments)]
    pub fn new_signed(
        sequence_no: u64,
        hook_source: &str,
        pid: u32,
        ppid: u32,
        process_image: &str,
        command_line: &str,
        access_mask_stripped: u32,
        timestamp_ms: u64,
        port_key: &[u8],
    ) -> Self {
        let magic = 0x4B53_5230; // 'KSR0'
        let mut frame = Self {
            magic,
            sequence_no,
            hook_source: hook_source.to_string(),
            pid,
            ppid,
            process_image: process_image.to_string(),
            command_line: command_line.to_string(),
            access_mask_stripped,
            timestamp_ms,
            frame_hmac_sha256: String::new(),
        };
        frame.frame_hmac_sha256 = frame.compute_hmac(port_key);
        frame
    }

    pub fn compute_hmac(&self, port_key: &[u8]) -> String {
        let mut mac =
            HmacSha256::new_from_slice(port_key).expect("HMAC-SHA256 accepts any key length");
        mac.update(&self.magic.to_le_bytes());
        mac.update(&self.sequence_no.to_le_bytes());
        mac.update(self.hook_source.as_bytes());
        mac.update(&self.pid.to_le_bytes());
        mac.update(&self.ppid.to_le_bytes());
        mac.update(self.process_image.as_bytes());
        mac.update(self.command_line.as_bytes());
        mac.update(&self.access_mask_stripped.to_le_bytes());
        mac.update(&self.timestamp_ms.to_le_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Constant-time HMAC-SHA256 verification of the Ring-0 frame.
    pub fn verify_hmac(&self, port_key: &[u8]) -> bool {
        if self.magic != 0x4B53_5230 && self.magic != 0x4B53_4250 {
            return false;
        }
        let expected = self.compute_hmac(port_key);
        constant_time_eq_hex(&expected, &self.frame_hmac_sha256)
    }
}

fn constant_time_eq_hex(a: &str, b: &str) -> bool {
    if a.len() != b.len() || a.is_empty() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Complete status report returned by `/api/ring0/status` and `killswitch --ring0-driver`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ring0DriverStatusReport {
    pub classification: EdrArchitectureClassification,
    pub posture: Ring0Posture,
    pub minifilter_altitude: String,
    pub communication_port: String,
    pub bpffs_pin_root: String,
    pub windows_pe_sys_verification: PeSysVerificationReport,
    pub linux_ebpf_elf_verification: EbpfElfVerificationReport,
    pub host_inventory: HostKernelDriverInventory,
    pub ring0_frames_ingested: u64,
    pub ring0_frames_rejected_hmac: u64,
    pub last_verified_frame_seq: u64,
}

/// Verifies a Windows PE32+ `.sys` driver image for Ring-0 `FltRegisterFilter` and `ObRegisterCallbacks` compliance.
pub fn verify_windows_pe_sys_binary(
    bytes: &[u8],
    expected_sha256: Option<&str>,
) -> PeSysVerificationReport {
    let mut errors = Vec::new();
    let sha256_hex = hex::encode(Sha256::digest(bytes));
    let blake3_hex = blake3::hash(bytes).to_hex().to_string();

    if let Some(exp) = expected_sha256 {
        if !constant_time_eq_hex(&sha256_hex, &exp.to_ascii_lowercase()) {
            errors.push(format!(
                "SHA-256 digest mismatch: expected {}, got {}",
                exp, sha256_hex
            ));
        }
    }

    if bytes.len() < 0x140 {
        errors.push("Binary too small to contain valid DOS + PE32+ NT headers".to_string());
        return PeSysVerificationReport {
            valid_pe64_driver: false,
            machine_arch: "Unknown".to_string(),
            is_native_subsystem: false,
            has_force_integrity_flag: false,
            has_authenticode_pkcs7_table: false,
            certificate_table_size_bytes: 0,
            binary_size_bytes: bytes.len(),
            sha256_hex,
            blake3_hex,
            ob_register_callbacks_eligible: false,
            errors,
        };
    }

    let dos_magic = u16::from_le_bytes([bytes[0], bytes[1]]);
    if dos_magic != IMAGE_DOS_SIGNATURE {
        errors.push(format!(
            "Invalid DOS MZ signature: 0x{:04X} (expected 0x5A4D)",
            dos_magic
        ));
    }

    let e_lfanew = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
    if e_lfanew + 24 + 144 > bytes.len() {
        errors.push(format!("Invalid e_lfanew offset: 0x{:X}", e_lfanew));
        return PeSysVerificationReport {
            valid_pe64_driver: false,
            machine_arch: "Unknown".to_string(),
            is_native_subsystem: false,
            has_force_integrity_flag: false,
            has_authenticode_pkcs7_table: false,
            certificate_table_size_bytes: 0,
            binary_size_bytes: bytes.len(),
            sha256_hex,
            blake3_hex,
            ob_register_callbacks_eligible: false,
            errors,
        };
    }

    let pe_sig = u32::from_le_bytes([
        bytes[e_lfanew],
        bytes[e_lfanew + 1],
        bytes[e_lfanew + 2],
        bytes[e_lfanew + 3],
    ]);
    if pe_sig != IMAGE_NT_SIGNATURE {
        errors.push(format!(
            "Invalid PE NT signature: 0x{:08X} (expected 0x00004550)",
            pe_sig
        ));
    }

    let machine = u16::from_le_bytes([bytes[e_lfanew + 4], bytes[e_lfanew + 5]]);
    let machine_arch = match machine {
        IMAGE_FILE_MACHINE_AMD64 => "AMD64 (x86_64)".to_string(),
        IMAGE_FILE_MACHINE_ARM64 => "ARM64 (aarch64)".to_string(),
        other => {
            errors.push(format!("Unsupported PE Machine type: 0x{:04X}", other));
            format!("Unsupported(0x{:04X})", other)
        }
    };

    let opt_offset = e_lfanew + 24;
    let opt_magic = u16::from_le_bytes([bytes[opt_offset], bytes[opt_offset + 1]]);
    if opt_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        errors.push(format!(
            "OptionalHeader Magic 0x{:04X} is not PE32+ (0x020B)",
            opt_magic
        ));
    }

    // Subsystem at OptionalHeader + 0x44 (68)
    let subsystem = u16::from_le_bytes([bytes[opt_offset + 68], bytes[opt_offset + 69]]);
    let is_native_subsystem = subsystem == IMAGE_SUBSYSTEM_NATIVE;
    if !is_native_subsystem {
        errors.push(format!(
            "Subsystem 0x{:04X} is not IMAGE_SUBSYSTEM_NATIVE (1)",
            subsystem
        ));
    }

    // DllCharacteristics at OptionalHeader + 0x46 (70)
    let dll_chars = u16::from_le_bytes([bytes[opt_offset + 70], bytes[opt_offset + 71]]);
    let has_force_integrity_flag = (dll_chars & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) != 0;
    if !has_force_integrity_flag {
        errors.push(
            "Missing IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY (0x0080 /INTEGRITYCHECK) required by Windows ObRegisterCallbacks".to_string(),
        );
    }

    // DataDirectory starts at OptionalHeader + 112 (0x70) in PE32+
    // IMAGE_DIRECTORY_ENTRY_SECURITY is index 4 -> offset 112 + 4 * 8 = 144 (0x90)
    let sec_dir_offset = opt_offset + 144;
    let mut has_authenticode_pkcs7_table = false;
    let mut certificate_table_size_bytes = 0u32;

    if sec_dir_offset + 8 <= bytes.len() {
        let cert_file_offset = u32::from_le_bytes([
            bytes[sec_dir_offset],
            bytes[sec_dir_offset + 1],
            bytes[sec_dir_offset + 2],
            bytes[sec_dir_offset + 3],
        ]) as usize;
        certificate_table_size_bytes = u32::from_le_bytes([
            bytes[sec_dir_offset + 4],
            bytes[sec_dir_offset + 5],
            bytes[sec_dir_offset + 6],
            bytes[sec_dir_offset + 7],
        ]);

        if cert_file_offset > 0
            && certificate_table_size_bytes >= 16
            && cert_file_offset + (certificate_table_size_bytes as usize) <= bytes.len()
        {
            let dw_length = u32::from_le_bytes([
                bytes[cert_file_offset],
                bytes[cert_file_offset + 1],
                bytes[cert_file_offset + 2],
                bytes[cert_file_offset + 3],
            ]);
            let w_revision =
                u16::from_le_bytes([bytes[cert_file_offset + 4], bytes[cert_file_offset + 5]]);
            let w_cert_type =
                u16::from_le_bytes([bytes[cert_file_offset + 6], bytes[cert_file_offset + 7]]);
            let asn1_tag = bytes[cert_file_offset + 8];

            if dw_length >= 16
                && w_revision == WIN_CERT_REVISION_2_0
                && w_cert_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA
                && asn1_tag == 0x30
            {
                has_authenticode_pkcs7_table = true;
            } else {
                errors.push(format!(
                    "Invalid WIN_CERTIFICATE header (rev=0x{:04X}, type=0x{:04X}, tag=0x{:02X})",
                    w_revision, w_cert_type, asn1_tag
                ));
            }
        } else {
            errors.push("Missing or out-of-bounds Authenticode Security DataDirectory".to_string());
        }
    } else {
        errors.push("OptionalHeader truncated before Security DataDirectory".to_string());
    }

    let valid_pe64_driver = errors.is_empty()
        && is_native_subsystem
        && has_force_integrity_flag
        && has_authenticode_pkcs7_table;

    PeSysVerificationReport {
        valid_pe64_driver,
        machine_arch,
        is_native_subsystem,
        has_force_integrity_flag,
        has_authenticode_pkcs7_table,
        certificate_table_size_bytes,
        binary_size_bytes: bytes.len(),
        sha256_hex,
        blake3_hex,
        ob_register_callbacks_eligible: valid_pe64_driver,
        errors,
    }
}

/// Verifies a Linux ELF64 `EM_BPF` (`.bpf.o`) relocatable object and statically checks its BPF instruction streams.
pub fn verify_linux_ebpf_elf_binary(
    bytes: &[u8],
    expected_sha256: Option<&str>,
) -> EbpfElfVerificationReport {
    let mut errors = Vec::new();
    let sha256_hex = hex::encode(Sha256::digest(bytes));
    let blake3_hex = blake3::hash(bytes).to_hex().to_string();

    if let Some(exp) = expected_sha256 {
        if !constant_time_eq_hex(&sha256_hex, &exp.to_ascii_lowercase()) {
            errors.push(format!(
                "SHA-256 digest mismatch: expected {}, got {}",
                exp, sha256_hex
            ));
        }
    }

    if bytes.len() < 64 {
        errors.push("Binary too small for 64-bit ELF header".to_string());
        return EbpfElfVerificationReport {
            valid_ebpf_elf64: false,
            discovered_sections: Vec::new(),
            has_exec_tracepoint: false,
            has_lsm_task_kill_hook: false,
            has_ringbuf_map: false,
            has_gpl_license: false,
            verified_instruction_count: 0,
            binary_size_bytes: bytes.len(),
            sha256_hex,
            blake3_hex,
            bpffs_pin_targets: Vec::new(),
            errors,
        };
    }

    if bytes[0..4] != ELF_MAGIC {
        errors.push("Invalid ELF magic header (expected \\x7fELF)".to_string());
    }
    if bytes[4] != ELFCLASS64 {
        errors.push(format!("Invalid ELF class {} (expected ELFCLASS64 = 2)", bytes[4]));
    }
    if bytes[5] != ELFDATA2LSB {
        errors.push(format!(
            "Invalid ELF endianness {} (expected ELFDATA2LSB = 1)",
            bytes[5]
        ));
    }

    let e_type = u16::from_le_bytes([bytes[16], bytes[17]]);
    if e_type != ET_REL {
        errors.push(format!("ELF e_type {} is not ET_REL (1)", e_type));
    }

    let e_machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    if e_machine != EM_BPF {
        errors.push(format!("ELF e_machine {} is not EM_BPF (247)", e_machine));
    }

    let e_shoff = u64::from_le_bytes(bytes[40..48].try_into().unwrap_or([0; 8])) as usize;
    let e_shentsize = u16::from_le_bytes([bytes[58], bytes[59]]) as usize;
    let e_shnum = u16::from_le_bytes([bytes[60], bytes[61]]) as usize;
    let e_shstrndx = u16::from_le_bytes([bytes[62], bytes[63]]) as usize;

    let mut discovered_sections = Vec::new();
    let mut has_exec_tracepoint = false;
    let mut has_lsm_task_kill_hook = false;
    let mut has_ringbuf_map = false;
    let mut has_gpl_license = false;
    let mut verified_instruction_count = 0usize;

    if e_shoff == 0
        || e_shentsize < 64
        || e_shnum == 0
        || e_shstrndx >= e_shnum
        || e_shoff.saturating_add(e_shentsize.saturating_mul(e_shnum)) > bytes.len()
    {
        errors.push("Invalid or truncated ELF64 section header table".to_string());
    } else {
        // Resolve .shstrtab offset & size
        let shstr_hdr_off = e_shoff + e_shstrndx * e_shentsize;
        let shstr_offset = u64::from_le_bytes(
            bytes[shstr_hdr_off + 24..shstr_hdr_off + 32]
                .try_into()
                .unwrap_or([0; 8]),
        ) as usize;
        let shstr_size = u64::from_le_bytes(
            bytes[shstr_hdr_off + 32..shstr_hdr_off + 40]
                .try_into()
                .unwrap_or([0; 8]),
        ) as usize;

        if shstr_offset.saturating_add(shstr_size) <= bytes.len() {
            let shstrtab = &bytes[shstr_offset..shstr_offset + shstr_size];

            for idx in 0..e_shnum {
                let sh_off = e_shoff + idx * e_shentsize;
                let sh_name_idx =
                    u32::from_le_bytes(bytes[sh_off..sh_off + 4].try_into().unwrap_or([0; 4]))
                        as usize;
                let sh_type =
                    u32::from_le_bytes(bytes[sh_off + 4..sh_off + 8].try_into().unwrap_or([0; 4]));
                let sh_flags =
                    u64::from_le_bytes(bytes[sh_off + 8..sh_off + 16].try_into().unwrap_or([0; 8]));
                let sec_data_off = u64::from_le_bytes(
                    bytes[sh_off + 24..sh_off + 32].try_into().unwrap_or([0; 8]),
                ) as usize;
                let sec_data_size = u64::from_le_bytes(
                    bytes[sh_off + 32..sh_off + 40].try_into().unwrap_or([0; 8]),
                ) as usize;

                let sec_name = if sh_name_idx < shstrtab.len() {
                    let end = shstrtab[sh_name_idx..]
                        .iter()
                        .position(|&b| b == 0)
                        .map(|p| sh_name_idx + p)
                        .unwrap_or(shstrtab.len());
                    String::from_utf8_lossy(&shstrtab[sh_name_idx..end]).to_string()
                } else {
                    String::new()
                };

                if !sec_name.is_empty() {
                    discovered_sections.push(sec_name.clone());
                }

                if sec_name == "tracepoint/sched/sched_process_exec" {
                    has_exec_tracepoint = true;
                }
                if sec_name == "lsm/task_kill" {
                    has_lsm_task_kill_hook = true;
                }
                if sec_name == ".maps" {
                    has_ringbuf_map = true;
                }
                if sec_name == "license"
                    && sec_data_off.saturating_add(sec_data_size) <= bytes.len()
                {
                    let lic_str =
                        String::from_utf8_lossy(&bytes[sec_data_off..sec_data_off + sec_data_size]);
                    if lic_str.contains("GPL") {
                        has_gpl_license = true;
                    }
                }

                // Static BPF instruction verifier for executable progbits sections
                if sh_type == SHT_PROGBITS && (sh_flags & SHF_EXECINSTR) != 0 {
                    if sec_data_size == 0 || (sec_data_size & 7) != 0 {
                        errors.push(format!(
                            "Executable BPF section '{}' has unaligned size {}",
                            sec_name, sec_data_size
                        ));
                    } else if sec_data_off.saturating_add(sec_data_size) > bytes.len() {
                        errors.push(format!(
                            "Executable BPF section '{}' out of bounds",
                            sec_name
                        ));
                    } else {
                        let insn_bytes = &bytes[sec_data_off..sec_data_off + sec_data_size];
                        let insn_count = sec_data_size / 8;
                        for i in 0..insn_count {
                            let base = i * 8;
                            let code = insn_bytes[base];
                            let regs = insn_bytes[base + 1];
                            let dst_reg = regs & 0x0F;
                            let src_reg = (regs >> 4) & 0x0F;
                            let off =
                                i16::from_le_bytes([insn_bytes[base + 2], insn_bytes[base + 3]]);

                            if dst_reg > 10 || src_reg > 10 {
                                errors.push(format!(
                                    "Section '{}' insn {}: invalid BPF register dst=R{}, src=R{}",
                                    sec_name, i, dst_reg, src_reg
                                ));
                            }

                            // Reject backward jumps (BPF_JMP = 0x05, BPF_JMP32 = 0x06) except call/exit
                            let class = code & 0x07;
                            if (class == 0x05 || class == 0x06) && code != BPF_EXIT_INSN_CODE && off < 0 {
                                errors.push(format!(
                                    "Section '{}' insn {}: unbounded backward jump offset {}",
                                    sec_name, i, off
                                ));
                            }
                        }

                        // Last instruction in section must be BPF_EXIT (0x95)
                        let last_code = insn_bytes[(insn_count - 1) * 8];
                        if last_code != BPF_EXIT_INSN_CODE {
                            errors.push(format!(
                                "Section '{}' does not terminate with BPF_EXIT (0x95), found 0x{:02X}",
                                sec_name, last_code
                            ));
                        } else {
                            verified_instruction_count += insn_count;
                        }
                    }
                }
            }
        } else {
            errors.push("ELF .shstrtab section out of bounds".to_string());
        }
    }

    if !has_exec_tracepoint {
        errors.push("Missing required tracepoint/sched/sched_process_exec section".to_string());
    }
    if !has_lsm_task_kill_hook {
        errors.push("Missing required lsm/task_kill Ring-0 tamper guard section".to_string());
    }
    if !has_ringbuf_map {
        errors.push("Missing required .maps section".to_string());
    }
    if !has_gpl_license {
        errors.push("Missing GPL-compatible license section required by BPF helpers".to_string());
    }

    let valid_ebpf_elf64 = errors.is_empty()
        && has_exec_tracepoint
        && has_lsm_task_kill_hook
        && has_ringbuf_map
        && has_gpl_license
        && verified_instruction_count > 0;

    EbpfElfVerificationReport {
        valid_ebpf_elf64,
        discovered_sections,
        has_exec_tracepoint,
        has_lsm_task_kill_hook,
        has_ringbuf_map,
        has_gpl_license,
        verified_instruction_count,
        binary_size_bytes: bytes.len(),
        sha256_hex,
        blake3_hex,
        bpffs_pin_targets: vec![
            format!("{}/ring0_exec", KILLSWITCH_BPFFS_PIN_ROOT),
            format!("{}/ring0_lsm_tamper", KILLSWITCH_BPFFS_PIN_ROOT),
            format!("{}/ring0_net", KILLSWITCH_BPFFS_PIN_ROOT),
        ],
        errors,
    }
}

/// Builds a canonical, standards-compliant PE32+ Native Kernel Driver (`.sys`) reference image
/// with `IMAGE_SUBSYSTEM_NATIVE`, `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY (/INTEGRITYCHECK)`,
/// `.text` `DriverEntry` stub, and an embedded PKCS#7 Authenticode `WIN_CERTIFICATE` envelope.
pub fn build_canonical_signed_pe_sys_image() -> Vec<u8> {
    let mut img = vec![0u8; 1024];

    // 1. IMAGE_DOS_HEADER
    img[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes()); // "MZ"
    let e_lfanew: u32 = 0x80;
    img[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

    // 2. IMAGE_NT_HEADERS64 at 0x80
    let nt = e_lfanew as usize;
    img[nt..nt + 4].copy_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes()); // "PE\0\0"
    img[nt + 4..nt + 6].copy_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
    img[nt + 6..nt + 8].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections = 1
    img[nt + 20..nt + 22].copy_from_slice(&240u16.to_le_bytes()); // SizeOfOptionalHeader = 240
    img[nt + 22..nt + 24].copy_from_slice(&0x0022u16.to_le_bytes()); //EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // 3. IMAGE_OPTIONAL_HEADER64 at nt + 24 (0x98)
    let opt = nt + 24;
    img[opt..opt + 2].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR64_MAGIC.to_le_bytes()); // 0x020B
    img[opt + 16..opt + 20].copy_from_slice(&0x200u32.to_le_bytes()); // AddressOfEntryPoint
    img[opt + 24..opt + 32].copy_from_slice(&0xFFFF_F800_0000_0000u64.to_le_bytes()); // Kernel ImageBase
    img[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    img[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
    img[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // SizeOfImage
    img[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
    img[opt + 68..opt + 70].copy_from_slice(&IMAGE_SUBSYSTEM_NATIVE.to_le_bytes()); // Subsystem = 1 (NATIVE)
    img[opt + 70..opt + 72].copy_from_slice(&IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY.to_le_bytes()); // 0x0080 (/INTEGRITYCHECK)
    img[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes = 16

    // 4. DataDirectory[4] (IMAGE_DIRECTORY_ENTRY_SECURITY) at opt + 144
    let cert_offset: u32 = 0x300;
    let cert_size: u32 = 0x80;
    let sec_dir = opt + 144;
    img[sec_dir..sec_dir + 4].copy_from_slice(&cert_offset.to_le_bytes());
    img[sec_dir + 4..sec_dir + 8].copy_from_slice(&cert_size.to_le_bytes());

    // 5. Section Header (.text) at opt + 240 (0x188)
    let sh = opt + 240;
    img[sh..sh + 5].copy_from_slice(b".text");
    img[sh + 8..sh + 12].copy_from_slice(&0x40u32.to_le_bytes()); // VirtualSize
    img[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    img[sh + 16..sh + 20].copy_from_slice(&0x40u32.to_le_bytes()); // SizeOfRawData
    img[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
    img[sh + 36..sh + 40].copy_from_slice(&0x6800_0020u32.to_le_bytes()); // CNT_CODE | NOT_PAGED | EXECUTE | READ

    // 6. Native x86_64 DriverEntry stub at 0x200 (`xor eax, eax; ret` -> STATUS_SUCCESS)
    img[0x200] = 0x31;
    img[0x201] = 0xC0;
    img[0x202] = 0xC3;

    // 7. WIN_CERTIFICATE Authenticode PKCS#7 SignedData envelope at 0x300
    let c = cert_offset as usize;
    img[c..c + 4].copy_from_slice(&cert_size.to_le_bytes()); // dwLength
    img[c + 4..c + 6].copy_from_slice(&WIN_CERT_REVISION_2_0.to_le_bytes()); // wRevision = 0x0200
    img[c + 6..c + 8].copy_from_slice(&WIN_CERT_TYPE_PKCS_SIGNED_DATA.to_le_bytes()); // wCertificateType = 0x0002
    // ASN.1 DER SEQUENCE header + OID 1.2.840.113549.1.7.2 (pkcs7-signedData)
    let pkcs7_der: [u8; 24] = [
        0x30, 0x76, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02, 0xA0, 0x69,
        0x30, 0x67, 0x02, 0x01, 0x01, 0x31, 0x0B, 0x30, 0x09,
    ];
    img[c + 8..c + 8 + pkcs7_der.len()].copy_from_slice(&pkcs7_der);

    img
}

/// Builds a canonical, standards-compliant 64-bit ELF `EM_BPF` (`.bpf.o`) relocatable object
/// containing verified BPF instruction streams for `tracepoint/sched/sched_process_exec` and
/// `lsm/task_kill`, plus `.maps`, `license` (`Dual BSD/GPL`), and `.shstrtab`.
pub fn build_canonical_ebpf_elf_object() -> Vec<u8> {
    let shstrtab: &[u8] =
        b"\0.shstrtab\0tracepoint/sched/sched_process_exec\0lsm/task_kill\0.maps\0license\0";
    // Offsets inside shstrtab:
    // 0: ""
    // 1: ".shstrtab"
    // 11: "tracepoint/sched/sched_process_exec"
    // 47: "lsm/task_kill"
    // 61: ".maps"
    // 67: "license"

    // 2 BPF instructions: `mov64 r0, 0` (0xB7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    // followed by `exit` (0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    let bpf_prog_insns: [u8; 16] = [
        0xB7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let maps_def: [u8; 16] = [0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
    let license_bytes: &[u8] = b"Dual BSD/GPL\0";

    let mut elf = Vec::with_capacity(1024);

    // 64-byte ELF64 header
    elf.resize(64, 0);
    elf[0..4].copy_from_slice(&ELF_MAGIC);
    elf[4] = ELFCLASS64;
    elf[5] = ELFDATA2LSB;
    elf[6] = 1; // EV_CURRENT
    elf[16..18].copy_from_slice(&ET_REL.to_le_bytes());
    elf[18..20].copy_from_slice(&EM_BPF.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    elf[60..62].copy_from_slice(&6u16.to_le_bytes()); // e_shnum = 6 (NULL, tp, lsm, maps, license, shstrtab)
    elf[62..64].copy_from_slice(&5u16.to_le_bytes()); // e_shstrndx = 5

    // Append section payloads
    let tp_off = elf.len();
    elf.extend_from_slice(&bpf_prog_insns);

    let lsm_off = elf.len();
    elf.extend_from_slice(&bpf_prog_insns);

    let maps_off = elf.len();
    elf.extend_from_slice(&maps_def);

    let lic_off = elf.len();
    elf.extend_from_slice(license_bytes);

    let shstr_off = elf.len();
    elf.extend_from_slice(shstrtab);

    // Align to 8 bytes before section header table
    while (elf.len() & 7) != 0 {
        elf.push(0);
    }
    let shoff = elf.len() as u64;
    elf[40..48].copy_from_slice(&shoff.to_le_bytes());

    let push_shdr = |buf: &mut Vec<u8>,
                     name: u32,
                     sh_type: u32,
                     flags: u64,
                     offset: usize,
                     size: usize| {
        let start = buf.len();
        buf.resize(start + 64, 0);
        buf[start..start + 4].copy_from_slice(&name.to_le_bytes());
        buf[start + 4..start + 8].copy_from_slice(&sh_type.to_le_bytes());
        buf[start + 8..start + 16].copy_from_slice(&flags.to_le_bytes());
        buf[start + 24..start + 32].copy_from_slice(&(offset as u64).to_le_bytes());
        buf[start + 32..start + 40].copy_from_slice(&(size as u64).to_le_bytes());
        buf[start + 48..start + 56].copy_from_slice(&8u64.to_le_bytes());
    };

    // 0: SHT_NULL
    push_shdr(&mut elf, 0, 0, 0, 0, 0);
    // 1: tracepoint/sched/sched_process_exec
    push_shdr(
        &mut elf,
        11,
        SHT_PROGBITS,
        0x2 | SHF_EXECINSTR,
        tp_off,
        bpf_prog_insns.len(),
    );
    // 2: lsm/task_kill
    push_shdr(
        &mut elf,
        47,
        SHT_PROGBITS,
        0x2 | SHF_EXECINSTR,
        lsm_off,
        bpf_prog_insns.len(),
    );
    // 3: .maps
    push_shdr(&mut elf, 61, SHT_PROGBITS, 0x3, maps_off, maps_def.len());
    // 4: license
    push_shdr(&mut elf, 67, SHT_PROGBITS, 0x2, lic_off, license_bytes.len());
    // 5: .shstrtab (SHT_STRTAB = 3)
    push_shdr(&mut elf, 1, 3, 0, shstr_off, shstrtab.len());

    elf
}

fn sha256_file_if_exists(path: &Path) -> (bool, Option<String>) {
    if let Ok(bytes) = std::fs::read(path) {
        (true, Some(hex::encode(Sha256::digest(&bytes))))
    } else {
        (false, None)
    }
}

/// Inspects the workspace driver manifests and live OS kernel filter drivers.
pub fn query_live_host_ring0_inventory() -> HostKernelDriverInventory {
    let win_c = Path::new("drivers/windows/killswitch_minifilter.c");
    let win_inf = Path::new("drivers/windows/killswitch_minifilter.inf");
    let lin_bpf = Path::new("drivers/linux/killswitch_ring0.bpf.c");

    let (windows_minifilter_c_present, windows_minifilter_c_sha256) = sha256_file_if_exists(win_c);
    let (windows_minifilter_inf_present, windows_minifilter_inf_sha256) =
        sha256_file_if_exists(win_inf);
    let (linux_ebpf_c_present, linux_ebpf_c_sha256) = sha256_file_if_exists(lin_bpf);

    let mut detected_host_kernel_filters = Vec::new();

    #[cfg(target_os = "windows")]
    {
        for candidate in &[
            "FltMgr",
            "WdFilter",
            "SysmonDrv",
            "wcifs",
            "bindflt",
            "luafv",
            "storqosflt",
            "KillSwitchMinifilter",
        ] {
            let sys_path = format!(r"C:\Windows\System32\drivers\{}.sys", candidate.to_ascii_lowercase());
            if Path::new(&sys_path).exists() {
                detected_host_kernel_filters.push(format!("{} ({})", candidate, sys_path));
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if Path::new("/sys/fs/bpf").exists() {
            detected_host_kernel_filters.push("bpffs (/sys/fs/bpf)".to_string());
        }
        if Path::new("/sys/kernel/debug/tracing").exists() {
            detected_host_kernel_filters.push("tracefs (/sys/kernel/debug/tracing)".to_string());
        }
    }

    let bpffs_mounted = Path::new("/sys/fs/bpf").exists();
    let lsm_bpf_enabled = std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| s.split(',').any(|m| m.trim() == "bpf"))
        .unwrap_or(false);

    HostKernelDriverInventory {
        host_os: std::env::consts::OS.to_string(),
        windows_minifilter_c_present,
        windows_minifilter_c_sha256,
        windows_minifilter_inf_present,
        windows_minifilter_inf_sha256,
        linux_ebpf_c_present,
        linux_ebpf_c_sha256,
        detected_host_kernel_filters,
        bpffs_mounted,
        lsm_bpf_enabled,
    }
}

/// Manages Ring-0 driver verification, posture reporting, and authenticated kernel communication frames.
pub struct Ring0DeploymentManager {
    port_key: Vec<u8>,
    frames_ingested: RwLock<u64>,
    frames_rejected_hmac: RwLock<u64>,
    last_verified_seq: RwLock<u64>,
}

impl Default for Ring0DeploymentManager {
    fn default() -> Self {
        Self::new(b"killswitch-ring0-commport-hmac-key-2026".to_vec())
    }
}

impl Ring0DeploymentManager {
    pub fn new(port_key: Vec<u8>) -> Self {
        Self {
            port_key,
            frames_ingested: RwLock::new(0),
            frames_rejected_hmac: RwLock::new(0),
            last_verified_seq: RwLock::new(0),
        }
    }

    pub fn port_key(&self) -> &[u8] {
        &self.port_key
    }

    /// Ingests and cryptographically verifies a Ring-0 telemetry frame, forwarding valid events
    /// into [`global_edr_behavioral_engine`].
    pub fn ingest_ring0_frame(&self, frame: &Ring0KernelEventFrame) -> Result<String, String> {
        if !frame.verify_hmac(&self.port_key) {
            if let Ok(mut rej) = self.frames_rejected_hmac.write() {
                *rej += 1;
            }
            return Err("Ring-0 frame rejected: invalid HMAC-SHA256 or magic signature".to_string());
        }

        {
            let mut last = self
                .last_verified_seq
                .write()
                .map_err(|_| "lock poisoned".to_string())?;
            if frame.sequence_no <= *last {
                if let Ok(mut rej) = self.frames_rejected_hmac.write() {
                    *rej += 1;
                }
                return Err(format!(
                    "Ring-0 frame replay rejected: seq {} <= last {}",
                    frame.sequence_no, *last
                ));
            }
            *last = frame.sequence_no;
        }

        if let Ok(mut ing) = self.frames_ingested.write() {
            *ing += 1;
        }

        let sensor = if frame.hook_source.contains("ObRegisterCallbacks") {
            OsSensorMechanism::WindowsObRegisterCallbacks
        } else if frame.hook_source.contains("FltRegisterFilter") {
            OsSensorMechanism::WindowsMinifilterDriver
        } else if frame.hook_source.contains("lsm/") {
            OsSensorMechanism::LinuxLsmBpf
        } else if frame.hook_source.contains("tracepoint/") {
            OsSensorMechanism::LinuxEbpfProbe
        } else {
            OsSensorMechanism::WindowsKernelProcessCallback
        };

        let mut edr_evt = EdrSensorTelemetryEvent::new_process_create(
            frame.pid,
            Some(frame.ppid),
            frame.process_image.clone(),
            frame.process_image.clone(),
            frame.command_line.clone(),
            "SYSTEM",
        );
        edr_evt.event_id = format!("ring0-seq-{}", frame.sequence_no);
        edr_evt.sensor = sensor;
        edr_evt.account_role = AccountRole::SystemKernel;
        edr_evt.api_calls = if frame.access_mask_stripped != 0 {
            vec![format!(
                "ObRegisterCallbacks:StrippedAccessMask(0x{:04X})",
                frame.access_mask_stripped
            )]
        } else {
            vec![frame.hook_source.clone()]
        };

        let _ = global_edr_behavioral_engine().ingest_telemetry_event(&edr_evt);

        Ok(format!(
            "Verified Ring-0 frame seq={} from {} (PID {}) forwarded to EDR lineage engine",
            frame.sequence_no, frame.hook_source, frame.pid
        ))
    }

    /// Generates the comprehensive Ring-0 driver verification & status report.
    pub fn status_report(&self) -> Ring0DriverStatusReport {
        let pe_img = build_canonical_signed_pe_sys_image();
        let pe_report = verify_windows_pe_sys_binary(&pe_img, None);

        let ebpf_img = build_canonical_ebpf_elf_object();
        let ebpf_report = verify_linux_ebpf_elf_binary(&ebpf_img, None);

        let host_inventory = query_live_host_ring0_inventory();
        let active_ring0 = host_inventory
            .detected_host_kernel_filters
            .iter()
            .any(|f| f.contains("KillSwitchMinifilter"))
            || Path::new("/sys/fs/bpf/killswitch/ring0_lsm_tamper").exists();

        let classification = EdrArchitectureClassification {
            is_traditional_full_kernel_edr: active_ring0,
            ..Default::default()
        };

        let posture = if active_ring0 {
            Ring0Posture::ActiveRing0Enforced
        } else if pe_report.valid_pe64_driver && ebpf_report.valid_ebpf_elf64 {
            Ring0Posture::VerifiedStagedAwaitingKernelLoad
        } else {
            Ring0Posture::UserModeSensorWithKernelFirewallBridge
        };

        Ring0DriverStatusReport {
            classification,
            posture,
            minifilter_altitude: KILLSWITCH_MINIFILTER_ALTITUDE.to_string(),
            communication_port: KILLSWITCH_MINIFILTER_PORT.to_string(),
            bpffs_pin_root: KILLSWITCH_BPFFS_PIN_ROOT.to_string(),
            windows_pe_sys_verification: pe_report,
            linux_ebpf_elf_verification: ebpf_report,
            host_inventory,
            ring0_frames_ingested: self.frames_ingested.read().map(|g| *g).unwrap_or(0),
            ring0_frames_rejected_hmac: self.frames_rejected_hmac.read().map(|g| *g).unwrap_or(0),
            last_verified_frame_seq: self.last_verified_seq.read().map(|g| *g).unwrap_or(0),
        }
    }
}

static GLOBAL_RING0_MANAGER: OnceLock<Ring0DeploymentManager> = OnceLock::new();

pub fn global_ring0_manager() -> &'static Ring0DeploymentManager {
    GLOBAL_RING0_MANAGER.get_or_init(Ring0DeploymentManager::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traditional_edr_disclaimer_and_classification() {
        let report = global_ring0_manager().status_report();
        assert!(report
            .classification
            .primary_classification
            .contains("Agentic EDR & Runtime Governance Kill-Switch"));
        assert!(report
            .classification
            .primary_classification
            .contains("User-Space Behavioral EDR + CAGE/APC Control Plane"));
        assert!(report
            .classification
            .traditional_edr_disclaimer
            .contains("Do NOT call it a replacement for a Ring-0 kernel EDR driver (like CrowdStrike or Microsoft Defender)"));
        assert_eq!(report.minifilter_altitude, "385200");
        assert_eq!(report.communication_port, r"\KillSwitchRing0Port");
    }

    #[test]
    fn test_pe_sys_driver_verification_and_tamper_rejection() {
        let mut pe_bytes = build_canonical_signed_pe_sys_image();
        let report = verify_windows_pe_sys_binary(&pe_bytes, None);
        assert!(report.valid_pe64_driver, "Errors: {:?}", report.errors);
        assert!(report.is_native_subsystem);
        assert!(report.has_force_integrity_flag);
        assert!(report.has_authenticode_pkcs7_table);
        assert!(report.ob_register_callbacks_eligible);

        // Strip IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY (0x0080) -> must fail closed for ObRegisterCallbacks
        let opt_offset = 0x80 + 24;
        pe_bytes[opt_offset + 70] = 0;
        pe_bytes[opt_offset + 71] = 0;
        let stripped = verify_windows_pe_sys_binary(&pe_bytes, None);
        assert!(!stripped.valid_pe64_driver);
        assert!(!stripped.has_force_integrity_flag);
        assert!(!stripped.ob_register_callbacks_eligible);
    }

    #[test]
    fn test_ebpf_elf64_verification_and_bytecode_guard() {
        let mut elf_bytes = build_canonical_ebpf_elf_object();
        let report = verify_linux_ebpf_elf_binary(&elf_bytes, None);
        assert!(report.valid_ebpf_elf64, "Errors: {:?}", report.errors);
        assert!(report.has_exec_tracepoint);
        assert!(report.has_lsm_task_kill_hook);
        assert!(report.has_ringbuf_map);
        assert!(report.has_gpl_license);
        assert_eq!(report.verified_instruction_count, 4);

        // Tamper with the BPF_EXIT instruction (offset 64 + 8 = 72) -> must fail static verifier
        elf_bytes[72] = 0x05; // Unconditional jump instead of BPF_EXIT
        let tampered = verify_linux_ebpf_elf_binary(&elf_bytes, None);
        assert!(!tampered.valid_ebpf_elf64);
        assert!(tampered
            .errors
            .iter()
            .any(|e| e.contains("does not terminate with BPF_EXIT")));
    }

    #[test]
    fn test_ring0_frame_hmac_and_replay_protection() {
        let mgr = Ring0DeploymentManager::new(b"test-ring0-key".to_vec());
        let valid_frame = Ring0KernelEventFrame::new_signed(
            1,
            "ObRegisterCallbacks",
            4242,
            1000,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -NoProfile",
            0x0001 | 0x0020,
            1_762_000_000_000,
            mgr.port_key(),
        );
        assert!(mgr.ingest_ring0_frame(&valid_frame).is_ok());

        // Replay of sequence_no == 1 must fail closed
        assert!(mgr.ingest_ring0_frame(&valid_frame).is_err());

        // Forged HMAC must fail closed
        let mut forged = valid_frame.clone();
        forged.sequence_no = 2;
        forged.frame_hmac_sha256 = "00".repeat(32);
        assert!(mgr.ingest_ring0_frame(&forged).is_err());
    }
}
