//! NIST IR 7695 Common Platform Enumeration (CPE 2.3) formatting, escaping, and canonicalization.

use serde::{Deserialize, Serialize};

/// CPE 2.3 part classification component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CpePart {
    /// Applications and packages ("a").
    Application,
    /// Operating system platforms and kernels ("o").
    OperatingSystem,
    /// Hardware devices and chipsets ("h").
    Hardware,
}

impl CpePart {
    /// Returns the single-character string representation for formatted string binding.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Application => "a",
            Self::OperatingSystem => "o",
            Self::Hardware => "h",
        }
    }
}

/// NIST IR 7695 compliant CPE 2.3 Formatted String Binding representation.
///
/// Contains exactly 11 attributes following the `cpe:2.3:` prefix, serialized
/// with 10 separating colons for a total of exactly 12 unescaped delimiter colons.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cpe23 {
    /// Part component (`a`, `o`, `h`).
    pub part: CpePart,
    /// Vendor identifier (e.g. `linux`, `microsoft`, `apple`).
    pub vendor: String,
    /// Product name (e.g. `linux_kernel`, `windows_11`, `macos`).
    pub product: String,
    /// Version identifier (e.g. `6.8.0`, `23h2`, `14.4.1`).
    pub version: String,
    /// Update/service pack identifier (or `*`).
    pub update: String,
    /// Edition identifier (or `*`).
    pub edition: String,
    /// Language code (or `*`).
    pub language: String,
    /// Software edition identifier (or `*`).
    pub sw_edition: String,
    /// Target software environment (or `*`).
    pub target_sw: String,
    /// Target hardware architecture (or `*`).
    pub target_hw: String,
    /// Other qualifiers (or `*`).
    pub other: String,
}

impl Default for Cpe23 {
    fn default() -> Self {
        Self {
            part: CpePart::OperatingSystem,
            vendor: "*".to_string(),
            product: "*".to_string(),
            version: "*".to_string(),
            update: "*".to_string(),
            edition: "*".to_string(),
            language: "*".to_string(),
            sw_edition: "*".to_string(),
            target_sw: "*".to_string(),
            target_hw: "*".to_string(),
            other: "*".to_string(),
        }
    }
}

impl Cpe23 {
    /// Creates a new operating system CPE 2.3 with specified vendor, product, and version.
    /// Remaining attributes default to wildcard ANY (`*`).
    pub fn new_os(
        vendor: impl Into<String>,
        product: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            part: CpePart::OperatingSystem,
            vendor: vendor.into(),
            product: product.into(),
            version: version.into(),
            ..Default::default()
        }
    }

    /// Serializes the CPE 2.3 instance into a NIST IR 7695 compliant formatted string binding.
    #[must_use]
    pub fn to_formatted_string(&self) -> String {
        format!(
            "cpe:2.3:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.part.as_str(),
            escape_cpe_attribute(&self.vendor),
            escape_cpe_attribute(&self.product),
            escape_cpe_attribute(&self.version),
            escape_cpe_attribute(&self.update),
            escape_cpe_attribute(&self.edition),
            escape_cpe_attribute(&self.language),
            escape_cpe_attribute(&self.sw_edition),
            escape_cpe_attribute(&self.target_sw),
            escape_cpe_attribute(&self.target_hw),
            escape_cpe_attribute(&self.other),
        )
    }
}

/// Escapes an attribute string for CPE 2.3 Formatted String Binding according to NIST IR 7695 Section 5.3.2.
#[must_use]
pub fn escape_cpe_attribute(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed == "*" {
        return "*".to_string();
    }
    if trimmed == "-" {
        return "-".to_string();
    }

    let mut out = String::with_capacity(trimmed.len() + 8);
    let mut chars = trimmed.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                if let Some(&next) = chars.peek() {
                    if matches!(
                        next,
                        ':' | '\\'
                            | '*'
                            | '?'
                            | '/'
                            | '%'
                            | ';'
                            | '!'
                            | '"'
                            | '#'
                            | '$'
                            | '&'
                            | '\''
                            | '('
                            | ')'
                            | '+'
                            | ','
                            | '<'
                            | '='
                            | '>'
                            | '@'
                            | '['
                            | ']'
                            | '^'
                            | '`'
                            | '{'
                            | '|'
                            | '}'
                            | '~'
                    ) {
                        out.push('\\');
                        out.push(chars.next().unwrap());
                        continue;
                    }
                }
                out.push('\\');
                out.push('\\');
            }
            ':' => {
                out.push('\\');
                out.push(':');
            }
            '*' => {
                out.push('\\');
                out.push('*');
            }
            '?' => {
                out.push('\\');
                out.push('?');
            }
            '/' => {
                out.push('\\');
                out.push('/');
            }
            '%' => {
                out.push('\\');
                out.push('%');
            }
            ';' => {
                out.push('\\');
                out.push(';');
            }
            '!' | '"' | '#' | '$' | '&' | '\'' | '(' | ')' | '+' | ',' | '<' | '=' | '>' | '@'
            | '[' | ']' | '^' | '`' | '{' | '|' | '}' | '~' => {
                out.push('\\');
                out.push(ch);
            }
            c if c.is_whitespace() => {
                if !out.ends_with('_') {
                    out.push('_');
                }
            }
            other => {
                out.push(other.to_ascii_lowercase());
            }
        }
    }

    if out.is_empty() {
        "*".to_string()
    } else {
        out
    }
}

/// Splits a CPE 2.3 string on delimiter colons while ignoring escaped colons (`\:`).
#[must_use]
pub fn split_unescaped_colons(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(&next) = chars.peek() {
                if next == ':' {
                    chars.next();
                    current.push('\\');
                    current.push(':');
                    continue;
                }
            }
            current.push('\\');
        } else if ch == ':' {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    parts.push(current);
    parts
}

/// Canonicalizes Linux kernel release strings (e.g. "6.8.0-49-generic" -> "6.8.0").
#[must_use]
pub fn canonicalize_linux_kernel_version(raw: &str) -> String {
    let trimmed = raw.trim();
    let mut parts = Vec::new();
    let mut current_num = String::new();

    for ch in trimmed.chars() {
        if ch.is_ascii_digit() {
            current_num.push(ch);
        } else if ch == '.' {
            if !current_num.is_empty() {
                parts.push(std::mem::take(&mut current_num));
                if parts.len() == 3 {
                    break;
                }
            } else {
                break;
            }
        } else {
            if !current_num.is_empty() {
                parts.push(std::mem::take(&mut current_num));
            }
            break;
        }
    }
    if !current_num.is_empty() && parts.len() < 3 {
        parts.push(current_num);
    }

    if parts.len() >= 2 {
        parts.join(".")
    } else if !trimmed.is_empty() {
        escape_cpe_attribute(trimmed)
    } else {
        "*".to_string()
    }
}

/// Canonicalizes Windows OS build number, server flag, and display version to NVD CPE product and version.
#[must_use]
pub fn canonicalize_windows_cpe(
    build: u32,
    is_server: bool,
    display_version: Option<&str>,
) -> (&'static str, String) {
    if is_server {
        let product = if build >= 26100 {
            "windows_server_2025"
        } else if build >= 20348 {
            "windows_server_2022"
        } else if build >= 17763 {
            "windows_server_2019"
        } else if build >= 14393 {
            "windows_server_2016"
        } else {
            "windows_server"
        };
        (product, "*".to_string())
    } else {
        let product = if build >= 22000 {
            "windows_11"
        } else if build >= 10240 {
            "windows_10"
        } else {
            "windows"
        };
        let version = display_version
            .map(escape_cpe_attribute)
            .filter(|v| v != "*")
            .unwrap_or_else(|| "*".to_string());
        (product, version)
    }
}

/// Canonicalizes macOS product version (e.g. "14.4.1 (a)" -> "14.4.1").
#[must_use]
pub fn canonicalize_macos_version(raw: &str) -> String {
    let trimmed = raw.trim();
    let clean = if let Some(idx) = trimmed.find('(') {
        trimmed[..idx].trim()
    } else if let Some(idx) = trimmed.find(' ') {
        trimmed[..idx].trim()
    } else {
        trimmed
    };
    if clean.is_empty() {
        "*".to_string()
    } else {
        escape_cpe_attribute(clean)
    }
}
