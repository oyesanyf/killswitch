//! REA Layer 1: Panic-Contained Binary Format Parser (PE & ELF).
//!
//! Provides pure-Rust, bounded executable format inspection wrapped inside
//! `std::panic::catch_unwind` to contain parser panics on corrupted or adversarial inputs.

use super::MAX_PE_SECTIONS;
use serde::{Deserialize, Serialize};

/// Supported binary executable format kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormatKind {
    Pe32,
    Pe64,
    Elf32,
    Elf64,
    MachO,
    Unknown,
}

/// Metadata describing an executable section.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub characteristics_or_flags: u64,
    pub is_executable: bool,
    pub is_writable: bool,
    pub is_rwx: bool,
    pub entropy: f64,
}

/// Structured inspection results for a binary artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BinaryFormatInfo {
    pub kind: BinaryFormatKind,
    pub architecture: String,
    pub is_64_bit: bool,
    pub endianness: String,
    pub entry_point: u64,
    pub section_count: usize,
    pub sections: Vec<SectionInfo>,
    pub has_rwx_section: bool,
    pub panic_contained: bool,
}

/// Calculate Shannon entropy (0.0 .. 8.0 bits/byte) for a byte slice.
fn calculate_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let len_f = bytes.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len_f;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Inspect binary headers and sections safely with `std::panic::catch_unwind` containment.
pub fn inspect_binary_format_safe(bytes: &[u8]) -> Result<BinaryFormatInfo, String> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        inspect_binary_format_internal(bytes)
    }));

    match result {
        Ok(inner_res) => inner_res,
        Err(panic_err) => {
            let msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_err.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic payload".to_string()
            };
            Err(format!(
                "PARSER_PANIC_CONTAINED: Binary format parser caught internal panic: {}",
                msg
            ))
        }
    }
}

/// Internal binary format inspection logic.
fn inspect_binary_format_internal(bytes: &[u8]) -> Result<BinaryFormatInfo, String> {
    if bytes.is_empty() {
        return Err("Empty binary buffer: cannot parse binary format".to_string());
    }

    // 1. Check for PE (MZ) header
    if bytes.starts_with(b"MZ") {
        return parse_pe_binary(bytes);
    }

    // 2. Check for ELF header
    if bytes.starts_with(b"\x7fELF") {
        return parse_elf_binary(bytes);
    }

    // 3. Check for Mach-O magic
    if bytes.len() >= 4 {
        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if matches!(
            magic,
            0xfeedface | 0xfeedfacf | 0xcefaedfe | 0xcffaedfe | 0xcafebabe
        ) {
            let is_64 = matches!(magic, 0xfeedfacf | 0xcffaedfe);
            return Ok(BinaryFormatInfo {
                kind: BinaryFormatKind::MachO,
                architecture: if is_64 {
                    "Mach-O 64-bit".to_string()
                } else {
                    "Mach-O 32-bit".to_string()
                },
                is_64_bit: is_64,
                endianness: if matches!(magic, 0xfeedface | 0xfeedfacf) {
                    "big".to_string()
                } else {
                    "little".to_string()
                },
                entry_point: 0,
                section_count: 0,
                sections: Vec::new(),
                has_rwx_section: false,
                panic_contained: false,
            });
        }
    }

    Err("Unrecognized binary format: missing PE 'MZ' or ELF magic header".to_string())
}

/// Safe PE (Portable Executable) parser.
fn parse_pe_binary(bytes: &[u8]) -> Result<BinaryFormatInfo, String> {
    if bytes.len() < 64 {
        return Err(format!(
            "DOS header truncated: file size is {} bytes (minimum 64 bytes required)",
            bytes.len()
        ));
    }

    let e_lfanew = u32::from_le_bytes(
        bytes[0x3C..0x40]
            .try_into()
            .map_err(|_| "Failed reading e_lfanew offset")?,
    ) as usize;

    if e_lfanew < 64 || e_lfanew + 4 > bytes.len() {
        return Err(format!(
            "Invalid PE header offset e_lfanew: 0x{:x} (file size: {} bytes)",
            e_lfanew,
            bytes.len()
        ));
    }

    if &bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(format!(
            "Invalid PE signature at offset 0x{:x}: expected 'PE\\0\\0'",
            e_lfanew
        ));
    }

    let coff_offset = e_lfanew + 4;
    if coff_offset + 20 > bytes.len() {
        return Err("COFF file header truncated".to_string());
    }

    let machine = u16::from_le_bytes(
        bytes[coff_offset..coff_offset + 2]
            .try_into()
            .map_err(|_| "Failed reading machine field")?,
    );
    let arch = match machine {
        0x014c => "x86 (i386)".to_string(),
        0x8664 => "x86_64 (AMD64)".to_string(),
        0xaa64 => "ARM64 (AArch64)".to_string(),
        0x01c0 => "ARM".to_string(),
        0x0200 => "Intel Itanium (IA64)".to_string(),
        other => format!("Unknown Machine (0x{:04x})", other),
    };

    let num_sections = u16::from_le_bytes(
        bytes[coff_offset + 2..coff_offset + 4]
            .try_into()
            .map_err(|_| "Failed reading NumberOfSections")?,
    ) as usize;

    if num_sections > MAX_PE_SECTIONS {
        return Err(format!(
            "PE section count {} exceeds MAX_PE_SECTIONS ({})",
            num_sections, MAX_PE_SECTIONS
        ));
    }

    let opt_hdr_size = u16::from_le_bytes(
        bytes[coff_offset + 16..coff_offset + 18]
            .try_into()
            .map_err(|_| "Failed reading SizeOfOptionalHeader")?,
    ) as usize;

    let opt_offset = coff_offset + 20;
    let mut is_64_bit = false;
    let mut kind = BinaryFormatKind::Pe32;
    let mut entry_point = 0u64;

    if opt_hdr_size > 0 {
        if opt_offset + opt_hdr_size > bytes.len() {
            return Err("PE optional header truncated".to_string());
        }
        let magic = u16::from_le_bytes(
            bytes[opt_offset..opt_offset + 2]
                .try_into()
                .map_err(|_| "Failed reading OptionalHeader Magic")?,
        );
        match magic {
            0x010b => {
                is_64_bit = false;
                kind = BinaryFormatKind::Pe32;
            }
            0x020b => {
                is_64_bit = true;
                kind = BinaryFormatKind::Pe64;
            }
            _ => {}
        }
        if opt_hdr_size >= 20 {
            entry_point = u32::from_le_bytes(
                bytes[opt_offset + 16..opt_offset + 20]
                    .try_into()
                    .map_err(|_| "Failed reading AddressOfEntryPoint")?,
            ) as u64;
        }
    }

    let sec_table_offset = opt_offset + opt_hdr_size;
    let table_size = num_sections
        .checked_mul(40)
        .ok_or_else(|| "Section table size overflow".to_string())?;

    let table_end = sec_table_offset
        .checked_add(table_size)
        .ok_or_else(|| "Section table offset overflow".to_string())?;

    if table_end > bytes.len() {
        return Err(format!(
            "PE section header table truncated: table ends at 0x{:x}, file length is {} bytes",
            table_end,
            bytes.len()
        ));
    }

    let mut sections = Vec::with_capacity(num_sections);
    let mut has_rwx = false;

    for i in 0..num_sections {
        let sec_offset = sec_table_offset + i * 40;
        let name_raw = &bytes[sec_offset..sec_offset + 8];
        let name = String::from_utf8_lossy(name_raw)
            .trim_matches('\0')
            .trim()
            .to_string();

        let v_size = u32::from_le_bytes(
            bytes[sec_offset + 8..sec_offset + 12]
                .try_into()
                .map_err(|_| "Failed reading VirtualSize")?,
        ) as u64;
        let v_addr = u32::from_le_bytes(
            bytes[sec_offset + 12..sec_offset + 16]
                .try_into()
                .map_err(|_| "Failed reading VirtualAddress")?,
        ) as u64;
        let r_size = u32::from_le_bytes(
            bytes[sec_offset + 16..sec_offset + 20]
                .try_into()
                .map_err(|_| "Failed reading SizeOfRawData")?,
        ) as u64;
        let r_ptr = u32::from_le_bytes(
            bytes[sec_offset + 20..sec_offset + 24]
                .try_into()
                .map_err(|_| "Failed reading PointerToRawData")?,
        ) as u64;
        let chars = u32::from_le_bytes(
            bytes[sec_offset + 36..sec_offset + 40]
                .try_into()
                .map_err(|_| "Failed reading Characteristics")?,
        );

        let is_exec = (chars & 0x2000_0000) != 0;
        let is_write = (chars & 0x8000_0000) != 0;
        let is_rwx = is_exec && is_write;
        if is_rwx {
            has_rwx = true;
        }

        let entropy = if let Some(end) = (r_ptr as usize).checked_add(r_size as usize) {
            if end <= bytes.len() && r_size > 0 {
                calculate_entropy(&bytes[r_ptr as usize..end])
            } else {
                0.0
            }
        } else {
            0.0
        };

        sections.push(SectionInfo {
            name,
            virtual_address: v_addr,
            virtual_size: v_size,
            raw_size: r_size,
            characteristics_or_flags: chars as u64,
            is_executable: is_exec,
            is_writable: is_write,
            is_rwx,
            entropy,
        });
    }

    Ok(BinaryFormatInfo {
        kind,
        architecture: arch,
        is_64_bit,
        endianness: "little".to_string(),
        entry_point,
        section_count: num_sections,
        sections,
        has_rwx_section: has_rwx,
        panic_contained: false,
    })
}

/// Safe ELF (Executable and Linkable Format) parser.
fn parse_elf_binary(bytes: &[u8]) -> Result<BinaryFormatInfo, String> {
    if bytes.len() < 52 {
        return Err(format!(
            "ELF header truncated: file size is {} bytes (minimum 52 bytes required)",
            bytes.len()
        ));
    }

    let ei_class = bytes[4];
    let (is_64_bit, kind) = match ei_class {
        1 => (false, BinaryFormatKind::Elf32),
        2 => (true, BinaryFormatKind::Elf64),
        other => {
            return Err(format!(
                "Invalid ELF class (0x{:02x}): neither 32-bit nor 64-bit",
                other
            ))
        }
    };

    let ei_data = bytes[5];
    let is_little = match ei_data {
        1 => true,
        2 => false,
        other => return Err(format!("Invalid ELF data encoding (0x{:02x})", other)),
    };

    if is_64_bit && bytes.len() < 64 {
        return Err(format!(
            "ELF64 header truncated: file size is {} bytes (minimum 64 bytes required)",
            bytes.len()
        ));
    }

    let machine = if is_little {
        u16::from_le_bytes(
            bytes[18..20]
                .try_into()
                .map_err(|_| "Failed reading ELF machine")?,
        )
    } else {
        u16::from_be_bytes(
            bytes[18..20]
                .try_into()
                .map_err(|_| "Failed reading ELF machine")?,
        )
    };
    let arch = match machine {
        0x03 => "x86 (EM_386)".to_string(),
        0x3E => "x86_64 (EM_X86_64)".to_string(),
        0x28 => "ARM (EM_ARM)".to_string(),
        0xB7 => "AArch64 (EM_AARCH64)".to_string(),
        0xF3 => "RISC-V (EM_RISCV)".to_string(),
        other => format!("Unknown Machine (0x{:04x})", other),
    };

    let (entry_point, e_shoff, e_shentsize, e_shnum) = if is_64_bit {
        let ep = if is_little {
            u64::from_le_bytes(
                bytes[24..32]
                    .try_into()
                    .map_err(|_| "Failed reading entry point")?,
            )
        } else {
            u64::from_be_bytes(
                bytes[24..32]
                    .try_into()
                    .map_err(|_| "Failed reading entry point")?,
            )
        };
        let shoff = if is_little {
            u64::from_le_bytes(
                bytes[40..48]
                    .try_into()
                    .map_err(|_| "Failed reading e_shoff")?,
            )
        } else {
            u64::from_be_bytes(
                bytes[40..48]
                    .try_into()
                    .map_err(|_| "Failed reading e_shoff")?,
            )
        };
        let shentsize = if is_little {
            u16::from_le_bytes(
                bytes[58..60]
                    .try_into()
                    .map_err(|_| "Failed reading e_shentsize")?,
            ) as usize
        } else {
            u16::from_be_bytes(
                bytes[58..60]
                    .try_into()
                    .map_err(|_| "Failed reading e_shentsize")?,
            ) as usize
        };
        let shnum = if is_little {
            u16::from_le_bytes(
                bytes[60..62]
                    .try_into()
                    .map_err(|_| "Failed reading e_shnum")?,
            ) as usize
        } else {
            u16::from_be_bytes(
                bytes[60..62]
                    .try_into()
                    .map_err(|_| "Failed reading e_shnum")?,
            ) as usize
        };
        (ep, shoff, shentsize, shnum)
    } else {
        let ep = if is_little {
            u32::from_le_bytes(
                bytes[24..28]
                    .try_into()
                    .map_err(|_| "Failed reading entry point")?,
            ) as u64
        } else {
            u32::from_be_bytes(
                bytes[24..28]
                    .try_into()
                    .map_err(|_| "Failed reading entry point")?,
            ) as u64
        };
        let shoff = if is_little {
            u32::from_le_bytes(
                bytes[32..36]
                    .try_into()
                    .map_err(|_| "Failed reading e_shoff")?,
            ) as u64
        } else {
            u32::from_be_bytes(
                bytes[32..36]
                    .try_into()
                    .map_err(|_| "Failed reading e_shoff")?,
            ) as u64
        };
        let shentsize = if is_little {
            u16::from_le_bytes(
                bytes[46..48]
                    .try_into()
                    .map_err(|_| "Failed reading e_shentsize")?,
            ) as usize
        } else {
            u16::from_be_bytes(
                bytes[46..48]
                    .try_into()
                    .map_err(|_| "Failed reading e_shentsize")?,
            ) as usize
        };
        let shnum = if is_little {
            u16::from_le_bytes(
                bytes[48..50]
                    .try_into()
                    .map_err(|_| "Failed reading e_shnum")?,
            ) as usize
        } else {
            u16::from_be_bytes(
                bytes[48..50]
                    .try_into()
                    .map_err(|_| "Failed reading e_shnum")?,
            ) as usize
        };
        (ep, shoff, shentsize, shnum)
    };

    if e_shnum > MAX_PE_SECTIONS {
        return Err(format!(
            "ELF section count {} exceeds MAX_PE_SECTIONS ({})",
            e_shnum, MAX_PE_SECTIONS
        ));
    }

    let mut sections = Vec::with_capacity(e_shnum);
    let mut has_rwx = false;

    if e_shnum > 0 && e_shoff > 0 {
        let table_size = e_shnum
            .checked_mul(e_shentsize)
            .ok_or_else(|| "ELF section table size overflow".to_string())?;

        let table_end = (e_shoff as usize)
            .checked_add(table_size)
            .ok_or_else(|| "ELF section table offset overflow".to_string())?;

        if table_end > bytes.len() {
            return Err(format!(
                "ELF section header table truncated: table ends at 0x{:x}, file length is {} bytes",
                table_end,
                bytes.len()
            ));
        }

        for i in 0..e_shnum {
            let sh_offset = (e_shoff as usize) + i * e_shentsize;
            let (sh_flags, sh_addr, sh_offset_val, sh_size) = if is_64_bit {
                if sh_offset + 40 > bytes.len() {
                    return Err(format!("ELF64 section header {} truncated", i));
                }
                let flags = if is_little {
                    u64::from_le_bytes(bytes[sh_offset + 8..sh_offset + 16].try_into().unwrap())
                } else {
                    u64::from_be_bytes(bytes[sh_offset + 8..sh_offset + 16].try_into().unwrap())
                };
                let addr = if is_little {
                    u64::from_le_bytes(bytes[sh_offset + 16..sh_offset + 24].try_into().unwrap())
                } else {
                    u64::from_be_bytes(bytes[sh_offset + 16..sh_offset + 24].try_into().unwrap())
                };
                let off = if is_little {
                    u64::from_le_bytes(bytes[sh_offset + 24..sh_offset + 32].try_into().unwrap())
                } else {
                    u64::from_be_bytes(bytes[sh_offset + 24..sh_offset + 32].try_into().unwrap())
                };
                let sz = if is_little {
                    u64::from_le_bytes(bytes[sh_offset + 32..sh_offset + 40].try_into().unwrap())
                } else {
                    u64::from_be_bytes(bytes[sh_offset + 32..sh_offset + 40].try_into().unwrap())
                };
                (flags, addr, off, sz)
            } else {
                if sh_offset + 24 > bytes.len() {
                    return Err(format!("ELF32 section header {} truncated", i));
                }
                let flags = if is_little {
                    u32::from_le_bytes(bytes[sh_offset + 8..sh_offset + 12].try_into().unwrap())
                        as u64
                } else {
                    u32::from_be_bytes(bytes[sh_offset + 8..sh_offset + 12].try_into().unwrap())
                        as u64
                };
                let addr = if is_little {
                    u32::from_le_bytes(bytes[sh_offset + 12..sh_offset + 16].try_into().unwrap())
                        as u64
                } else {
                    u32::from_be_bytes(bytes[sh_offset + 12..sh_offset + 16].try_into().unwrap())
                        as u64
                };
                let off = if is_little {
                    u32::from_le_bytes(bytes[sh_offset + 16..sh_offset + 20].try_into().unwrap())
                        as u64
                } else {
                    u32::from_be_bytes(bytes[sh_offset + 16..sh_offset + 20].try_into().unwrap())
                        as u64
                };
                let sz = if is_little {
                    u32::from_le_bytes(bytes[sh_offset + 20..sh_offset + 24].try_into().unwrap())
                        as u64
                } else {
                    u32::from_be_bytes(bytes[sh_offset + 20..sh_offset + 24].try_into().unwrap())
                        as u64
                };
                (flags, addr, off, sz)
            };

            // SHF_WRITE = 0x1, SHF_ALLOC = 0x2, SHF_EXECINSTR = 0x4
            let is_write = (sh_flags & 0x1) != 0;
            let is_exec = (sh_flags & 0x4) != 0;
            let is_rwx = is_write && is_exec;
            if is_rwx {
                has_rwx = true;
            }

            let entropy =
                if let Some(end) = (sh_offset_val as usize).checked_add(sh_size as usize) {
                    if end <= bytes.len() && sh_size > 0 {
                        calculate_entropy(&bytes[sh_offset_val as usize..end])
                    } else {
                        0.0
                    }
                } else {
                    0.0
                };

            sections.push(SectionInfo {
                name: format!("elf_sec_{}", i),
                virtual_address: sh_addr,
                virtual_size: sh_size,
                raw_size: sh_size,
                characteristics_or_flags: sh_flags,
                is_executable: is_exec,
                is_writable: is_write,
                is_rwx,
                entropy,
            });
        }
    }

    Ok(BinaryFormatInfo {
        kind,
        architecture: arch,
        is_64_bit,
        endianness: if is_little {
            "little".to_string()
        } else {
            "big".to_string()
        },
        entry_point,
        section_count: e_shnum,
        sections,
        has_rwx_section: has_rwx,
        panic_contained: false,
    })
}
