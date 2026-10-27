//! Autonomous REA (Reverse Engineering Automation) Subsystem.

pub mod binary_format;
pub mod engine;
pub mod path_security;
pub mod prompt_injection;

/// Maximum local file read limit for REA binary & archive inspection (256 MiB).
pub const MAX_REA_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Hard resource bound on maximum section count for PE and ELF parsers (Protection Layer 3).
pub const MAX_PE_SECTIONS: usize = 96;

/// Maximum number of extracted printable strings to inspect (Protection Layer 4).
pub const MAX_EXTRACTED_STRINGS: usize = 2048;

/// Maximum length in bytes for a single extracted printable string (Anti-OOM bound).
pub const MAX_SINGLE_STRING_BYTES: usize = 4096;

pub use binary_format::{
    inspect_binary_format_safe, BinaryFormatInfo, BinaryFormatKind, SectionInfo,
};
pub use engine::{
    has_active_lotl_or_exploit_indicators, is_rea_benign_system_or_dev_process,
    AutonomousReaEngine,
};
pub use path_security::{
    detect_binary_masquerade_spoof, get_canonical_protected_binary_names,
    is_canonical_protected_binary_name, is_untrusted_writable_or_temp_path,
    validate_rea_target_path,
};
pub use prompt_injection::{
    calculate_entropy, extract_printable_strings, scan_and_sanitize_counter_ai_strings,
};
