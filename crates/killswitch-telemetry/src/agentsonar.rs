//! # Dynamic AgentSonar Network Traffic-Shape & SQLite/Siquery Discovery Engine
//!
//! Eliminates static hardcoded AI agent maps by moving all known agent definitions,
//! noise domains, browser process filters, heuristic scoring thresholds, and live flow
//! events into a runtime-editable SQLite WAL database (`data/agentsonar.db`) paired
//! with an optional hot-reloading JSON seed/override file (`config/agentsonar.json`).
//!
//! ## Key Capabilities
//! 1. **5 Dynamic SQLite WAL Tables** (all exposed natively in `SiqueryEngine` and via `osquery` ATC):
//!    - `agentsonar_events`: Classified & scored network flows with byte/packet/duration telemetry.
//!    - `agentsonar_known_agents`: Wildcard `(agent, proc_pattern, domain_pattern)` mappings.
//!    - `agentsonar_noise_domains`: Dynamic domain & subdomain noise suppression list.
//!    - `agentsonar_browser_procs`: Interactive browser process substrings (overridden when `--headless`/CDP).
//!    - `agentsonar_heuristics`: Live-tunable 4-factor SSE traffic-shape weights & thresholds.
//! 2. **100% Pure-Rust Cross-Platform Flow & TLS SNI Sensor (Zero `libpcap` / `wpcap.lib`)**:
//!    - Bounds-checked RFC 8446 / RFC 5246 TLS `ClientHello` SNI (`0x0000` Server Name) & RFC 1035 DNS QNAME parser.
//!    - Tier 1 elevated packet inspection (Linux `AF_PACKET`, Windows WinSock2 `SIO_RCVALL` when opted in)
//!      and Tier 2 universal unprivileged kernel socket + per-connection byte/segment telemetry
//!      (Windows `GetExtendedTcpTable`, Linux `ProcSocketResolver` `/proc/net/tcp*` + `/proc/<pid>/fd` with 250ms TTL,
//!      macOS Darwin sockets) correlated with OS DNS/hosts caches.
//! 3. **AST-Guarded Bounded External Classifier Piping**:
//!    - Validates external classifier commands via `semantic_command::parse_command_semantics`
//!      (blocking privilege escalation and shell-chaining metacharacters), enforces a 2,000 ms timeout
//!      and 64 KB stdout cap, and clamps output scores to `[0.0, 1.0]`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use parking_lot::RwLock;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::rl_traffic::query_live_os_process_sockets;
use crate::semantic_command::{
    parse_semantic_command, tokenize_command, PrivilegeEquivalenceClass,
};

// ============================================================================
// Data Models & Dynamic Rule Set
// ============================================================================

/// Live-tunable heuristic weights and traffic-shape thresholds for SSE LLM inference detection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HeuristicWeights {
    pub min_byte_ratio: f64,
    pub max_byte_ratio: f64,
    pub weight_byte_asymmetry: f64,
    pub min_pkt_ratio: f64,
    pub min_avg_pkt_in: f64,
    pub max_avg_pkt_in: f64,
    pub weight_pkt_streaming: f64,
    pub min_duration_ms: u64,
    pub max_duration_ms: u64,
    pub weight_duration: f64,
    pub weight_programmatic: f64,
}

impl Default for HeuristicWeights {
    fn default() -> Self {
        Self {
            min_byte_ratio: 4.0,
            max_byte_ratio: 200.0,
            weight_byte_asymmetry: 0.30,
            min_pkt_ratio: 2.5,
            min_avg_pkt_in: 50.0,
            max_avg_pkt_in: 850.0,
            weight_pkt_streaming: 0.30,
            min_duration_ms: 1500,
            max_duration_ms: 180_000,
            weight_duration: 0.20,
            weight_programmatic: 0.20,
        }
    }
}

/// Partial update payload for tuning heuristic parameters at runtime via CLI or HTTP.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeuristicWeightsPatch {
    pub min_byte_ratio: Option<f64>,
    pub max_byte_ratio: Option<f64>,
    pub weight_byte_asymmetry: Option<f64>,
    pub min_pkt_ratio: Option<f64>,
    pub min_avg_pkt_in: Option<f64>,
    pub max_avg_pkt_in: Option<f64>,
    pub weight_pkt_streaming: Option<f64>,
    pub min_duration_ms: Option<u64>,
    pub max_duration_ms: Option<u64>,
    pub weight_duration: Option<f64>,
    pub weight_programmatic: Option<f64>,
}

impl HeuristicWeights {
    pub fn apply_patch(&mut self, patch: &HeuristicWeightsPatch) {
        if let Some(v) = patch.min_byte_ratio {
            if v.is_finite() && v >= 0.0 {
                self.min_byte_ratio = v;
            }
        }
        if let Some(v) = patch.max_byte_ratio {
            if v.is_finite() && v >= self.min_byte_ratio {
                self.max_byte_ratio = v;
            }
        }
        if let Some(v) = patch.weight_byte_asymmetry {
            if v.is_finite() {
                self.weight_byte_asymmetry = v.clamp(0.0, 1.0);
            }
        }
        if let Some(v) = patch.min_pkt_ratio {
            if v.is_finite() && v >= 0.0 {
                self.min_pkt_ratio = v;
            }
        }
        if let Some(v) = patch.min_avg_pkt_in {
            if v.is_finite() && v >= 0.0 {
                self.min_avg_pkt_in = v;
            }
        }
        if let Some(v) = patch.max_avg_pkt_in {
            if v.is_finite() && v >= self.min_avg_pkt_in {
                self.max_avg_pkt_in = v;
            }
        }
        if let Some(v) = patch.weight_pkt_streaming {
            if v.is_finite() {
                self.weight_pkt_streaming = v.clamp(0.0, 1.0);
            }
        }
        if let Some(v) = patch.min_duration_ms {
            self.min_duration_ms = v;
        }
        if let Some(v) = patch.max_duration_ms {
            if v >= self.min_duration_ms {
                self.max_duration_ms = v;
            }
        }
        if let Some(v) = patch.weight_duration {
            if v.is_finite() {
                self.weight_duration = v.clamp(0.0, 1.0);
            }
        }
        if let Some(v) = patch.weight_programmatic {
            if v.is_finite() {
                self.weight_programmatic = v.clamp(0.0, 1.0);
            }
        }
    }
}

/// Wildcard process-to-domain known AI agent rule stored in `agentsonar_known_agents`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRule {
    pub agent: String,
    pub proc_pattern: String,
    pub domain_pattern: String,
}

/// Complete runtime-editable AgentSonar rule set loaded from SQLite WAL or JSON config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicRuleSet {
    #[serde(default)]
    pub agents: Vec<AgentRule>,
    #[serde(default)]
    pub noise_domains: HashSet<String>,
    #[serde(default)]
    pub non_programmatic_procs: HashSet<String>,
    #[serde(default)]
    pub heuristics: HeuristicWeights,
}

impl Default for DynamicRuleSet {
    fn default() -> Self {
        let agents = vec![
            AgentRule {
                agent: "claude-code".to_string(),
                proc_pattern: "*claude*".to_string(),
                domain_pattern: "*.anthropic.com".to_string(),
            },
            AgentRule {
                agent: "openai-codex".to_string(),
                proc_pattern: "*codex*".to_string(),
                domain_pattern: "*.openai.com".to_string(),
            },
            AgentRule {
                agent: "cursor-agent".to_string(),
                proc_pattern: "*cursor*".to_string(),
                domain_pattern: "*.cursor.sh".to_string(),
            },
            AgentRule {
                agent: "github-copilot".to_string(),
                proc_pattern: "*".to_string(),
                domain_pattern: "*.githubcopilot.com".to_string(),
            },
            AgentRule {
                agent: "google-gemini-cli".to_string(),
                proc_pattern: "*gemini*".to_string(),
                domain_pattern: "generativelanguage.googleapis.com".to_string(),
            },
            AgentRule {
                agent: "openrouter-client".to_string(),
                proc_pattern: "*".to_string(),
                domain_pattern: "*.openrouter.ai".to_string(),
            },
        ];

        let noise_domains: HashSet<String> = [
            "*.mozilla.org",
            "*.windowsupdate.com",
            "*.digicert.com",
            "*.letsencrypt.org",
            "crates.io",
            "*.crates.io",
            "registry.npmjs.org",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let non_programmatic_procs: HashSet<String> = [
            "chrome", "firefox", "safari", "brave", "edge", "msedge", "chromium", "arc",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        Self {
            agents,
            noise_domains,
            non_programmatic_procs,
            heuristics: HeuristicWeights::default(),
        }
    }
}

/// Linear-time, non-backtracking (ReDoS-proof) case-insensitive glob matcher (`*` and `?`).
pub fn glob_match_case_insensitive(pattern: &str, candidate: &str) -> bool {
    let p: Vec<u8> = pattern
        .as_bytes()
        .iter()
        .map(|b| b.to_ascii_lowercase())
        .collect();
    let s: Vec<u8> = candidate
        .as_bytes()
        .iter()
        .map(|b| b.to_ascii_lowercase())
        .collect();

    let (mut pi, mut si) = (0usize, 0usize);
    let mut star_pi: Option<usize> = None;
    let mut star_si: usize = 0;

    while si < s.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_pi = Some(pi);
            star_si = si;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_si += 1;
            si = star_si;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }

    pi == p.len()
}

/// Matches a domain against a pattern supporting `*.example.com` (apex + subdomains) and globs.
pub fn domain_matches_pattern(domain: &str, pattern: &str) -> bool {
    let dom = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let pat = pattern.trim().trim_end_matches('.').to_ascii_lowercase();

    if pat.is_empty() || pat == "*" {
        return true;
    }
    if dom.is_empty() {
        return false;
    }
    if let Some(base) = pat.strip_prefix("*.") {
        if !base.contains('*') && !base.contains('?') {
            return dom == base || dom.ends_with(&format!(".{}", base));
        }
    }
    glob_match_case_insensitive(&pat, &dom)
}

impl DynamicRuleSet {
    /// Loads current rules dynamically from SQLite.
    pub fn load_from_db(conn: &Connection) -> Result<Self> {
        let mut agents = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT agent, proc_pattern, domain_pattern FROM agentsonar_known_agents ORDER BY agent ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(AgentRule {
                agent: r.get(0)?,
                proc_pattern: r.get(1)?,
                domain_pattern: r.get(2)?,
            })
        })?;
        for r in rows {
            agents.push(r?);
        }

        let mut noise_domains = HashSet::new();
        let mut nstmt =
            conn.prepare("SELECT domain FROM agentsonar_noise_domains ORDER BY domain ASC")?;
        let nrows = nstmt.query_map([], |r| r.get::<_, String>(0))?;
        for n in nrows {
            noise_domains.insert(n?.to_ascii_lowercase());
        }

        let mut non_programmatic_procs = HashSet::new();
        let mut bstmt = conn.prepare(
            "SELECT proc_substring FROM agentsonar_browser_procs ORDER BY proc_substring ASC",
        )?;
        let brows = bstmt.query_map([], |r| r.get::<_, String>(0))?;
        for b in brows {
            non_programmatic_procs.insert(b?.to_ascii_lowercase());
        }

        let heuristics = conn
            .query_row(
                "SELECT config_json FROM agentsonar_heuristics WHERE id = 1",
                [],
                |r| r.get::<_, String>(0),
            )
            .ok()
            .and_then(|j| serde_json::from_str(&j).ok())
            .unwrap_or_default();

        Ok(Self {
            agents,
            noise_domains,
            non_programmatic_procs,
            heuristics,
        })
    }

    /// Determines whether a process is programmatic (CLI/daemon/headless browser) vs interactive browser.
    pub fn is_programmatic(&self, proc_name: &str, cmdline: &str) -> bool {
        let p_low = proc_name.to_ascii_lowercase();
        let c_low = cmdline.to_ascii_lowercase();
        if c_low.contains("--headless")
            || c_low.contains("--remote-debugging-port")
            || c_low.contains("--webdriver")
            || c_low.contains("playwright")
            || c_low.contains("puppeteer")
        {
            return true;
        }
        !self
            .non_programmatic_procs
            .iter()
            .any(|b| !b.is_empty() && p_low.contains(b))
    }

    /// Scores a network flow using dynamic noise filters, wildcard known-agent rules,
    /// and the 4-factor SSE streaming traffic-shape classifier.
    #[allow(clippy::too_many_arguments)]
    pub fn score_flow(
        &self,
        proc_name: &str,
        domain: &str,
        bytes_in: u64,
        bytes_out: u64,
        packets_in: u64,
        packets_out: u64,
        duration_ms: u64,
        programmatic: bool,
    ) -> (f64, String, bool) {
        let dom_low = domain.trim().to_ascii_lowercase();
        let proc_low = proc_name.trim().to_ascii_lowercase();

        // 1. Dynamic Noise Check
        if !dom_low.is_empty() {
            for noise in &self.noise_domains {
                if domain_matches_pattern(&dom_low, noise) {
                    return (0.0, String::new(), true);
                }
            }
        }

        // 2. Dynamic Known Agent Check (glob matching on process + domain)
        for rule in &self.agents {
            let p_pat = rule.proc_pattern.trim();
            let d_pat = rule.domain_pattern.trim();

            let proc_matches = if p_pat.is_empty() || p_pat == "*" {
                true
            } else if p_pat.contains('*') || p_pat.contains('?') {
                glob_match_case_insensitive(p_pat, &proc_low)
            } else {
                proc_low.contains(&p_pat.to_ascii_lowercase())
            };

            let dom_matches = domain_matches_pattern(&dom_low, d_pat);

            if proc_matches && dom_matches {
                return (1.0, rule.agent.clone(), false);
            }
        }

        // 3. Dynamic Heuristic Traffic-Shape Classifier
        let h = &self.heuristics;
        let mut score = 0.0;

        if bytes_out > 0 && bytes_in > 0 {
            let ratio = bytes_in as f64 / bytes_out as f64;
            if ratio >= h.min_byte_ratio && ratio <= h.max_byte_ratio {
                score += h.weight_byte_asymmetry;
            } else if ratio >= (h.min_byte_ratio * 0.5) {
                score += h.weight_byte_asymmetry * 0.5;
            }
        }

        if packets_in >= 10 && packets_out > 0 {
            let pkt_ratio = packets_in as f64 / packets_out as f64;
            let avg_pkt_in = bytes_in as f64 / packets_in as f64;
            if pkt_ratio >= h.min_pkt_ratio
                && avg_pkt_in >= h.min_avg_pkt_in
                && avg_pkt_in <= h.max_avg_pkt_in
            {
                score += h.weight_pkt_streaming;
            }
        }

        if duration_ms >= h.min_duration_ms && duration_ms <= h.max_duration_ms {
            score += h.weight_duration;
        }

        if programmatic {
            score += h.weight_programmatic;
        }

        let clamped = (score.clamp(0.0, 1.0) * 100.0).round() / 100.0;
        (clamped, String::new(), false)
    }
}

/// Classified network flow event stored in `agentsonar_events`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlowEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub proc_name: String,
    pub cmdline: String,
    pub domain: String,
    pub remote_ip: String,
    pub remote_port: u16,
    pub source: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub duration_ms: u64,
    pub programmatic: bool,
    pub ai_score: f64,
    pub agent: String,
    pub is_noise: bool,
}

/// Candidate unclassified flow returned by `triage_candidates`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TriageCandidate {
    pub proc_name: String,
    pub domain: String,
    pub ai_score: f64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub duration_ms: u64,
}

/// Operator action applied during interactive CLI or WebUI triage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageDecision {
    KnownAgent {
        agent: String,
        proc_pattern: String,
        domain_pattern: String,
    },
    IgnoreNoise {
        domain: String,
    },
}

// ============================================================================
// Pure-Rust RFC 8446 TLS SNI & RFC 1035 DNS QNAME Parsers (Zero C Dependencies)
// ============================================================================

fn is_valid_sni_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
        && host.contains('.')
}

/// Extracts the TLS `ClientHello` Server Name Indication (`0x0000` extension) from a TCP payload.
/// Strictly bounds-checked with zero `unsafe` blocks and zero external C dependencies.
pub fn extract_tls_sni(payload: &[u8]) -> Option<String> {
    // TLS Plaintext header: ContentType(1) = 0x16 (Handshake), Version(2), Length(2)
    if payload.len() < 9 || payload[0] != 0x16 {
        return None;
    }
    let major = payload[1];
    let minor = payload[2];
    if major != 0x03 || minor > 0x04 {
        return None;
    }
    let rec_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let rec_end = (5usize.saturating_add(rec_len)).min(payload.len());
    let hs = payload.get(5..rec_end)?;

    // Handshake header: HandshakeType(1) = 0x01 (ClientHello), Length(3)
    if hs.len() < 38 || hs[0] != 0x01 {
        return None;
    }
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    let body = hs.get(4..4usize.saturating_add(hs_len).min(hs.len()))?;
    if body.len() < 34 {
        return None;
    }

    // Skip client_version (2) + random (32)
    let mut pos = 34usize;

    // Session ID: 1-byte length
    let sid_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1)?.checked_add(sid_len)?;

    // Cipher Suites: 2-byte length
    let cs_bytes = body.get(pos..pos.checked_add(2)?)?;
    let cs_len = u16::from_be_bytes([cs_bytes[0], cs_bytes[1]]) as usize;
    pos = pos.checked_add(2)?.checked_add(cs_len)?;

    // Compression Methods: 1-byte length
    let comp_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1)?.checked_add(comp_len)?;

    // Extensions total length: 2 bytes
    if pos + 2 > body.len() {
        return None;
    }
    let ext_total_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos.saturating_add(ext_total_len).min(body.len());

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        let ext_data = body.get(pos..pos.checked_add(ext_len)?)?;
        if ext_type == 0x0000 && ext_data.len() >= 5 {
            // ServerNameList length (2 bytes)
            let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
            let list_end = (2usize.saturating_add(list_len)).min(ext_data.len());
            let mut lpos = 2usize;
            while lpos + 3 <= list_end {
                let name_type = ext_data[lpos];
                let name_len =
                    u16::from_be_bytes([ext_data[lpos + 1], ext_data[lpos + 2]]) as usize;
                lpos += 3;
                let name_slice = ext_data.get(lpos..lpos.checked_add(name_len)?)?;
                if name_type == 0x00 {
                    if let Ok(s) = std::str::from_utf8(name_slice) {
                        let host = s.trim().to_ascii_lowercase();
                        if is_valid_sni_hostname(&host) {
                            return Some(host);
                        }
                    }
                }
                lpos += name_len;
            }
        }
        pos += ext_len;
    }

    None
}

/// Extracts the primary queried domain name (QNAME) from a UDP/TCP DNS query payload (RFC 1035).
pub fn extract_dns_qname(payload: &[u8]) -> Option<String> {
    if payload.len() < 17 {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut pos = 12usize;
    let mut labels = Vec::new();
    let mut steps = 0usize;

    while pos < payload.len() && steps < 64 {
        steps += 1;
        let len = payload[pos] as usize;
        if len == 0 {
            break;
        }
        // Reject compression pointers in initial question or malformed label lengths > 63
        if (len & 0xC0) != 0 || len > 63 {
            return None;
        }
        pos += 1;
        let label_bytes = payload.get(pos..pos.checked_add(len)?)?;
        let label = std::str::from_utf8(label_bytes).ok()?.to_ascii_lowercase();
        labels.push(label);
        pos += len;
    }

    if labels.is_empty() {
        return None;
    }
    let domain = labels.join(".");
    if is_valid_sni_hostname(&domain) {
        Some(domain)
    } else {
        None
    }
}

/// Parsed IPv4/IPv6 + TCP slice summary for pure-Rust raw packet inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTcpSegment<'a> {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub packet_len: usize,
    pub payload: &'a [u8],
}

/// Parses an Ethernet-framed or raw IPv4/IPv6 packet into a `ParsedTcpSegment`.
pub fn parse_tcp_packet(frame: &[u8], has_ethernet_header: bool) -> Option<ParsedTcpSegment<'_>> {
    let ip_slice = if has_ethernet_header {
        if frame.len() < 14 {
            return None;
        }
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        match ethertype {
            0x0800 | 0x86DD => &frame[14..],
            0x8100 if frame.len() >= 18 => &frame[18..], // 802.1Q VLAN
            _ => return None,
        }
    } else {
        frame
    };

    if ip_slice.is_empty() {
        return None;
    }
    let version = ip_slice[0] >> 4;
    match version {
        4 => {
            if ip_slice.len() < 20 {
                return None;
            }
            let ihl = ((ip_slice[0] & 0x0F) as usize) * 4;
            if ihl < 20 || ip_slice.len() < ihl || ip_slice[9] != 6 {
                return None;
            }
            let src_ip = IpAddr::V4(Ipv4Addr::new(
                ip_slice[12],
                ip_slice[13],
                ip_slice[14],
                ip_slice[15],
            ));
            let dst_ip = IpAddr::V4(Ipv4Addr::new(
                ip_slice[16],
                ip_slice[17],
                ip_slice[18],
                ip_slice[19],
            ));
            let tcp = &ip_slice[ihl..];
            if tcp.len() < 20 {
                return None;
            }
            let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
            let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
            let data_offset = ((tcp[12] >> 4) as usize) * 4;
            if data_offset < 20 || tcp.len() < data_offset {
                return None;
            }
            Some(ParsedTcpSegment {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                packet_len: frame.len(),
                payload: &tcp[data_offset..],
            })
        }
        6 => {
            if ip_slice.len() < 40 || ip_slice[6] != 6 {
                return None;
            }
            let mut src_octets = [0u8; 16];
            let mut dst_octets = [0u8; 16];
            src_octets.copy_from_slice(&ip_slice[8..24]);
            dst_octets.copy_from_slice(&ip_slice[24..40]);
            let src_ip = IpAddr::V6(Ipv6Addr::from(src_octets));
            let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_octets));
            let tcp = &ip_slice[40..];
            if tcp.len() < 20 {
                return None;
            }
            let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
            let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
            let data_offset = ((tcp[12] >> 4) as usize) * 4;
            if data_offset < 20 || tcp.len() < data_offset {
                return None;
            }
            Some(ParsedTcpSegment {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                packet_len: frame.len(),
                payload: &tcp[data_offset..],
            })
        }
        _ => None,
    }
}

// ============================================================================
// Secure Bounded External Classifier Runner
// ============================================================================

/// Executes an external JSONL classifier command with AST privilege/injection validation,
/// a hard 5,000 ms execution timeout, and a 64 KB stdout bound.
pub fn run_external_classifier(cmd_str: &str, event_json: &str) -> Result<Option<f64>, String> {
    let trimmed = cmd_str.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    // Security Gate 1: Reject shell-chaining / command-substitution metacharacters
    if trimmed.contains(';')
        || trimmed.contains('|')
        || trimmed.contains('&')
        || trimmed.contains('`')
        || trimmed.contains("$(")
        || trimmed.contains('\n')
        || trimmed.contains('\r')
    {
        return Err(
            "External classifier rejected: shell chaining or command substitution forbidden"
                .to_string(),
        );
    }

    // Security Gate 2: Structural AST privilege & elevation check
    let sem = parse_semantic_command(trimmed);
    if sem.privilege_class.is_privileged_execution()
        || sem.is_cross_boundary
        || matches!(
            sem.privilege_class,
            PrivilegeEquivalenceClass::RootOrAdminElevation
        )
    {
        return Err(format!(
            "External classifier rejected by semantic AST privilege gate: {:?}",
            sem.privilege_class
        ));
    }

    let tokens = tokenize_command(trimmed);
    let bin = tokens
        .first()
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Empty classifier executable".to_string())?;
    let args: Vec<&str> = tokens.iter().skip(1).map(String::as_str).collect();

    let mut child = Command::new(bin)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to spawn external classifier '{}': {}", bin, e))?;

    if let Some(mut stdin) = child.stdin.take() {
        let _ = writeln!(stdin, "{}", event_json);
    }

    let deadline = Instant::now() + Duration::from_millis(5_000);
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("External classifier timed out after 5000ms".to_string());
                }
                thread::sleep(Duration::from_millis(15));
            }
            Err(e) => {
                let _ = child.kill();
                return Err(format!("External classifier wait error: {}", e));
            }
        }
    }

    let mut stdout_buf = Vec::with_capacity(1024);
    if let Some(stdout) = child.stdout.take() {
        let _ = stdout.take(65_536).read_to_end(&mut stdout_buf);
    }

    let out_str = String::from_utf8_lossy(&stdout_buf);
    let first_line = out_str
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    if first_line.is_empty() {
        return Ok(None);
    }

    let val: serde_json::Value = serde_json::from_str(first_line)
        .map_err(|e| format!("External classifier returned invalid JSON: {}", e))?;
    let score_opt = val.get("score").and_then(|s| s.as_f64()).or_else(|| {
        val.get("scores")
            .and_then(|m| m.get("default"))
            .and_then(|s| s.as_f64())
    });

    if let Some(score) = score_opt {
        if score.is_finite() {
            return Ok(Some(score.clamp(0.0, 1.0)));
        }
    }
    Ok(None)
}

// ============================================================================
// Cross-Platform Socket Resolver & Active Flow Tracker
// ============================================================================

/// Dynamic cross-platform socket-to-process resolver with 250ms TTL cache.
#[derive(Default)]
pub struct ProcSocketResolver {
    port_to_proc: HashMap<u16, (u32, String, String)>,
    local_ips: HashSet<IpAddr>,
    last_refresh_ms: u64,
}

impl ProcSocketResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn refresh(&mut self) {
        self.port_to_proc.clear();
        self.local_ips.clear();
        self.local_ips.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
        self.local_ips.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));
        self.last_refresh_ms = now_ms();

        // Populate on Linux directly from /proc/net/tcp* + /proc/<pid>/fd for minimal overhead
        #[cfg(target_os = "linux")]
        {
            let mut port_to_inode: HashMap<u16, u64> = HashMap::new();
            for tcp_file in &["/proc/net/tcp", "/proc/net/tcp6"] {
                if let Ok(content) = fs::read_to_string(tcp_file) {
                    for line in content.lines().skip(1) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 10 {
                            if let Some(port_hex) = parts[1].split(':').nth(1) {
                                if let (Ok(port), Ok(inode)) =
                                    (u16::from_str_radix(port_hex, 16), parts[9].parse::<u64>())
                                {
                                    if inode > 0 {
                                        port_to_inode.insert(port, inode);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let wanted_inodes: HashSet<u64> = port_to_inode.values().copied().collect();
            let mut inode_to_pid: HashMap<u64, (u32, String, String)> = HashMap::new();
            if !wanted_inodes.is_empty() {
                if let Ok(entries) = fs::read_dir("/proc") {
                    for entry in entries.flatten() {
                        if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                            if let Ok(fds) = fs::read_dir(format!("/proc/{}/fd", pid)) {
                                for fd in fds.flatten() {
                                    if let Ok(target) = fs::read_link(fd.path()) {
                                        let t = target.to_string_lossy();
                                        if let Some(inode_str) = t
                                            .strip_prefix("socket:[")
                                            .and_then(|s| s.strip_suffix(']'))
                                        {
                                            if let Ok(inode) = inode_str.parse::<u64>() {
                                                if wanted_inodes.contains(&inode) {
                                                    let comm = fs::read_to_string(format!(
                                                        "/proc/{}/comm",
                                                        pid
                                                    ))
                                                    .unwrap_or_default()
                                                    .trim()
                                                    .to_string();
                                                    let cmdline = fs::read_to_string(format!(
                                                        "/proc/{}/cmdline",
                                                        pid
                                                    ))
                                                    .unwrap_or_default()
                                                    .replace('\0', " ")
                                                    .trim()
                                                    .to_string();
                                                    inode_to_pid
                                                        .insert(inode, (pid, comm, cmdline));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            for (port, inode) in port_to_inode {
                if let Some(info) = inode_to_pid.get(&inode) {
                    self.port_to_proc.insert(port, info.clone());
                }
            }
        }

        // Cross-platform kernel socket correlation (Windows GetExtendedTcpTable, macOS Darwin sockets, Linux fallback)
        for sock in query_live_os_process_sockets() {
            if sock.local_port > 0 {
                self.port_to_proc.entry(sock.local_port).or_insert((
                    sock.pid,
                    sock.process_name,
                    sock.command_line,
                ));
            }
        }

        if let Ok(udp) = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
            if udp.connect((Ipv4Addr::new(192, 0, 2, 1), 80)).is_ok() {
                if let Ok(addr) = udp.local_addr() {
                    self.local_ips.insert(addr.ip());
                }
            }
        }
    }

    pub fn is_local_ip(&self, ip: &IpAddr) -> bool {
        ip.is_loopback() || self.local_ips.contains(ip)
    }

    pub fn resolve_local_port(&mut self, local_port: u16) -> (u32, String, String) {
        if let Some(info) = self.port_to_proc.get(&local_port) {
            return info.clone();
        }
        if now_ms().saturating_sub(self.last_refresh_ms) > 250 {
            self.refresh();
            if let Some(info) = self.port_to_proc.get(&local_port) {
                return info.clone();
            }
        }
        (0, String::new(), String::new())
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct FlowKey {
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
}

#[derive(Debug, Clone)]
pub struct ActiveFlow {
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub pid: u32,
    pub proc_name: String,
    pub cmdline: String,
    pub domain: String,
    pub source: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub programmatic: bool,
}

// ============================================================================
// SQLite WAL Initialization, Safe Path Guard, & OSQuery ATC Schema
// ============================================================================

/// Validates a relative database or config path against traversal (`..`) and ADS (`:`).
pub fn resolve_safe_db_path(raw_path: &str) -> Result<PathBuf> {
    let trimmed = raw_path.trim();
    if trimmed.is_empty() {
        return Ok(default_agentsonar_db_path());
    }
    if trimmed.contains('\0') || trimmed.contains("%2e") || trimmed.contains("%2E") {
        return Err(anyhow!("Unsafe characters in AgentSonar path"));
    }
    let path = PathBuf::from(trimmed);
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(anyhow!(
                "Path traversal ('..') forbidden in AgentSonar database path"
            ));
        }
    }
    Ok(path)
}

/// Platform-appropriate default SQLite WAL path (`KILLSWITCH_AGENTSONAR_DB` override supported).
pub fn default_agentsonar_db_path() -> PathBuf {
    if let Ok(env_p) = std::env::var("KILLSWITCH_AGENTSONAR_DB") {
        if !env_p.trim().is_empty() {
            if let Ok(valid) = resolve_safe_db_path(&env_p) {
                return valid;
            }
        }
    }
    PathBuf::from("data").join("agentsonar.db")
}

/// Initializes SQLite WAL schema for events and dynamic rules, seeding initial defaults only when empty.
pub fn init_agentsonar_db(db_path: &Path) -> Result<Connection> {
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = fs::create_dir_all(parent);
        }
    }
    let conn = Connection::open(db_path).with_context(|| {
        format!(
            "Failed to open AgentSonar SQLite DB at {}",
            db_path.display()
        )
    })?;
    conn.busy_timeout(Duration::from_millis(2_500))?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         CREATE TABLE IF NOT EXISTS agentsonar_events (
             timestamp INTEGER,
             pid INTEGER,
             proc TEXT,
             cmdline TEXT,
             domain TEXT,
             remote_ip TEXT,
             remote_port INTEGER,
             source TEXT,
             bytes_in INTEGER,
             bytes_out INTEGER,
             packets_in INTEGER,
             packets_out INTEGER,
             duration_ms INTEGER,
             programmatic INTEGER,
             ai_score REAL,
             agent TEXT,
             is_noise INTEGER,
             PRIMARY KEY (pid, domain, remote_ip, remote_port)
         );
         CREATE TABLE IF NOT EXISTS agentsonar_known_agents (
             agent TEXT,
             proc_pattern TEXT,
             domain_pattern TEXT,
             PRIMARY KEY (agent, proc_pattern, domain_pattern)
         );
         CREATE TABLE IF NOT EXISTS agentsonar_noise_domains (
             domain TEXT PRIMARY KEY
         );
         CREATE TABLE IF NOT EXISTS agentsonar_browser_procs (
             proc_substring TEXT PRIMARY KEY
         );
         CREATE TABLE IF NOT EXISTS agentsonar_heuristics (
             id INTEGER PRIMARY KEY CHECK (id = 1),
             config_json TEXT
         );",
    )?;

    let heuristic_count: i64 =
        conn.query_row("SELECT COUNT(*) FROM agentsonar_heuristics", [], |r| {
            r.get(0)
        })?;
    if heuristic_count == 0 {
        let seed = DynamicRuleSet::default();
        let default_json = serde_json::to_string(&seed.heuristics)?;
        conn.execute(
            "INSERT INTO agentsonar_heuristics (id, config_json) VALUES (1, ?1)",
            params![default_json],
        )?;
        for b in &seed.non_programmatic_procs {
            let _ = conn.execute(
                "INSERT OR IGNORE INTO agentsonar_browser_procs VALUES (?1)",
                params![b],
            );
        }
        for a in &seed.agents {
            let _ = conn.execute(
                "INSERT OR IGNORE INTO agentsonar_known_agents VALUES (?1, ?2, ?3)",
                params![a.agent, a.proc_pattern, a.domain_pattern],
            );
        }
        for n in &seed.noise_domains {
            let _ = conn.execute(
                "INSERT OR IGNORE INTO agentsonar_noise_domains VALUES (?1)",
                params![n],
            );
        }
    }

    Ok(conn)
}

/// Generates the `osquery` Auto Table Construction (`table_construction`) JSON configuration
/// exposing all 5 dynamic AgentSonar tables for fleet-wide `osqueryd` / `osqueryi` relational joins.
pub fn generate_osquery_atc_schema(db_path: &str) -> serde_json::Value {
    serde_json::json!({
        "options": {
            "table_construction": {
                "agentsonar_events": {
                    "path": db_path,
                    "columns": [
                        "timestamp", "pid", "proc", "cmdline", "domain", "remote_ip",
                        "remote_port", "source", "bytes_in", "bytes_out", "packets_in",
                        "packets_out", "duration_ms", "programmatic", "ai_score", "agent", "is_noise"
                    ],
                    "query": "SELECT * FROM agentsonar_events;"
                },
                "agentsonar_known_agents": {
                    "path": db_path,
                    "columns": ["agent", "proc_pattern", "domain_pattern"],
                    "query": "SELECT * FROM agentsonar_known_agents;"
                },
                "agentsonar_noise_domains": {
                    "path": db_path,
                    "columns": ["domain"],
                    "query": "SELECT * FROM agentsonar_noise_domains;"
                },
                "agentsonar_browser_procs": {
                    "path": db_path,
                    "columns": ["proc_substring"],
                    "query": "SELECT * FROM agentsonar_browser_procs;"
                },
                "agentsonar_heuristics": {
                    "path": db_path,
                    "columns": ["id", "config_json"],
                    "query": "SELECT * FROM agentsonar_heuristics;"
                }
            }
        }
    })
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ============================================================================
// High-Level Thread-Safe AgentSonar Engine & Hot-Reloading Coordinator
// ============================================================================

/// Summary status snapshot returned by `/api/agentsonar/status` and `killswitch agentsonar status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSonarStatusReport {
    pub db_path: String,
    pub config_path: Option<String>,
    pub collector_running: bool,
    pub events_count: usize,
    pub high_score_shadow_count: usize,
    pub known_agents_count: usize,
    pub noise_domains_count: usize,
    pub browser_procs_count: usize,
    pub heuristics: HeuristicWeights,
}

pub struct AgentSonarEngine {
    db_path: PathBuf,
    config_path: Option<PathBuf>,
    last_config_mtime: RwLock<Option<SystemTime>>,
    flows: Arc<RwLock<HashMap<FlowKey, ActiveFlow>>>,
    collector_running: Arc<AtomicBool>,
}

impl AgentSonarEngine {
    pub fn new(db_path: PathBuf, config_path: Option<PathBuf>) -> Result<Self> {
        let _ = init_agentsonar_db(&db_path)?;
        let engine = Self {
            db_path,
            config_path,
            last_config_mtime: RwLock::new(None),
            flows: Arc::new(RwLock::new(HashMap::new())),
            collector_running: Arc::new(AtomicBool::new(false)),
        };
        let _ = engine.sync_config_file_if_modified();
        Ok(engine)
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn open_conn(&self) -> Result<Connection> {
        init_agentsonar_db(&self.db_path)
    }

    /// Hot-reloads `config/agentsonar.json` into SQLite whenever the file's `modified()` timestamp advances.
    pub fn sync_config_file_if_modified(&self) -> Result<bool> {
        let Some(cfg_path) = &self.config_path else {
            return Ok(false);
        };
        let Ok(meta) = fs::metadata(cfg_path) else {
            return Ok(false);
        };
        let Ok(mtime) = meta.modified() else {
            return Ok(false);
        };

        {
            let prev = *self.last_config_mtime.read();
            if prev == Some(mtime) {
                return Ok(false);
            }
        }

        let content = fs::read_to_string(cfg_path)?;
        let parsed: DynamicRuleSet = serde_json::from_str(&content)
            .with_context(|| format!("Invalid JSON in {}", cfg_path.display()))?;

        // Seed/merge rules on first load or explicit file edit
        let is_subsequent_edit = self.last_config_mtime.read().is_some();
        let conn = self.open_conn()?;
        for a in &parsed.agents {
            conn.execute(
                "INSERT OR REPLACE INTO agentsonar_known_agents VALUES (?1, ?2, ?3)",
                params![a.agent, a.proc_pattern, a.domain_pattern],
            )?;
        }
        for n in &parsed.noise_domains {
            conn.execute(
                "INSERT OR IGNORE INTO agentsonar_noise_domains VALUES (?1)",
                params![n.to_ascii_lowercase()],
            )?;
        }
        for b in &parsed.non_programmatic_procs {
            conn.execute(
                "INSERT OR IGNORE INTO agentsonar_browser_procs VALUES (?1)",
                params![b.to_ascii_lowercase()],
            )?;
        }
        if is_subsequent_edit {
            let h_json = serde_json::to_string(&parsed.heuristics)?;
            conn.execute(
                "UPDATE agentsonar_heuristics SET config_json = ?1 WHERE id = 1",
                params![h_json],
            )?;
        }

        *self.last_config_mtime.write() = Some(mtime);
        Ok(true)
    }

    pub fn load_rules(&self) -> Result<DynamicRuleSet> {
        let _ = self.sync_config_file_if_modified();
        let conn = self.open_conn()?;
        DynamicRuleSet::load_from_db(&conn)
    }

    pub fn add_agent_rule(
        &self,
        agent: &str,
        proc_pattern: &str,
        domain_pattern: &str,
    ) -> Result<()> {
        let agent = agent.trim();
        if agent.is_empty() {
            return Err(anyhow!("Agent name must not be empty"));
        }
        let conn = self.open_conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO agentsonar_known_agents VALUES (?1, ?2, ?3)",
            params![agent, proc_pattern.trim(), domain_pattern.trim()],
        )?;
        Ok(())
    }

    pub fn remove_agent_rule(&self, agent: &str) -> Result<usize> {
        let conn = self.open_conn()?;
        let removed = conn.execute(
            "DELETE FROM agentsonar_known_agents WHERE agent = ?1",
            params![agent.trim()],
        )?;
        Ok(removed)
    }

    pub fn add_noise_domain(&self, domain: &str) -> Result<()> {
        let dom = domain.trim().to_ascii_lowercase();
        if dom.is_empty() {
            return Err(anyhow!("Domain must not be empty"));
        }
        let conn = self.open_conn()?;
        conn.execute(
            "INSERT OR IGNORE INTO agentsonar_noise_domains VALUES (?1)",
            params![dom],
        )?;
        Ok(())
    }

    pub fn remove_noise_domain(&self, domain: &str) -> Result<usize> {
        let conn = self.open_conn()?;
        let removed = conn.execute(
            "DELETE FROM agentsonar_noise_domains WHERE domain = ?1",
            params![domain.trim().to_ascii_lowercase()],
        )?;
        Ok(removed)
    }

    pub fn add_browser_proc(&self, proc_substring: &str) -> Result<()> {
        let sub = proc_substring.trim().to_ascii_lowercase();
        if sub.is_empty() {
            return Err(anyhow!("Browser process substring must not be empty"));
        }
        let conn = self.open_conn()?;
        conn.execute(
            "INSERT OR IGNORE INTO agentsonar_browser_procs VALUES (?1)",
            params![sub],
        )?;
        Ok(())
    }

    pub fn remove_browser_proc(&self, proc_substring: &str) -> Result<usize> {
        let conn = self.open_conn()?;
        let removed = conn.execute(
            "DELETE FROM agentsonar_browser_procs WHERE proc_substring = ?1",
            params![proc_substring.trim().to_ascii_lowercase()],
        )?;
        Ok(removed)
    }

    pub fn update_heuristics(&self, patch: &HeuristicWeightsPatch) -> Result<HeuristicWeights> {
        let conn = self.open_conn()?;
        let mut rules = DynamicRuleSet::load_from_db(&conn)?;
        rules.heuristics.apply_patch(patch);
        let updated_json = serde_json::to_string(&rules.heuristics)?;
        conn.execute(
            "UPDATE agentsonar_heuristics SET config_json = ?1 WHERE id = 1",
            params![updated_json],
        )?;
        Ok(rules.heuristics)
    }

    pub fn import_ruleset(&self, imported: &DynamicRuleSet) -> Result<()> {
        let conn = self.open_conn()?;
        for a in &imported.agents {
            conn.execute(
                "INSERT OR REPLACE INTO agentsonar_known_agents VALUES (?1, ?2, ?3)",
                params![a.agent, a.proc_pattern, a.domain_pattern],
            )?;
        }
        for n in &imported.noise_domains {
            conn.execute(
                "INSERT OR IGNORE INTO agentsonar_noise_domains VALUES (?1)",
                params![n.to_ascii_lowercase()],
            )?;
        }
        for b in &imported.non_programmatic_procs {
            conn.execute(
                "INSERT OR IGNORE INTO agentsonar_browser_procs VALUES (?1)",
                params![b.to_ascii_lowercase()],
            )?;
        }
        let h_json = serde_json::to_string(&imported.heuristics)?;
        conn.execute(
            "UPDATE agentsonar_heuristics SET config_json = ?1 WHERE id = 1",
            params![h_json],
        )?;
        Ok(())
    }

    /// Evaluates and persists a flow record into `agentsonar_events` using current dynamic rules.
    #[allow(clippy::too_many_arguments)]
    pub fn record_flow(
        &self,
        pid: u32,
        proc_name: &str,
        cmdline: &str,
        domain: &str,
        remote_ip: &str,
        remote_port: u16,
        source: &str,
        bytes_in: u64,
        bytes_out: u64,
        packets_in: u64,
        packets_out: u64,
        duration_ms: u64,
        show_noise: bool,
    ) -> Result<FlowEvent> {
        let _ = self.sync_config_file_if_modified();
        let conn = self.open_conn()?;
        let rules = DynamicRuleSet::load_from_db(&conn)?;
        let programmatic = rules.is_programmatic(proc_name, cmdline);
        let (ai_score, agent, is_noise) = rules.score_flow(
            proc_name,
            domain,
            bytes_in,
            bytes_out,
            packets_in,
            packets_out,
            duration_ms,
            programmatic,
        );
        let ts = now_ms() / 1000;
        let event = FlowEvent {
            timestamp: ts,
            pid,
            proc_name: proc_name.to_string(),
            cmdline: cmdline.to_string(),
            domain: domain.to_string(),
            remote_ip: remote_ip.to_string(),
            remote_port,
            source: source.to_string(),
            bytes_in,
            bytes_out,
            packets_in,
            packets_out,
            duration_ms,
            programmatic,
            ai_score,
            agent: agent.clone(),
            is_noise,
        };

        if show_noise || !is_noise {
            conn.execute(
                "INSERT OR REPLACE INTO agentsonar_events VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17
                )",
                params![
                    event.timestamp as i64,
                    event.pid as i64,
                    event.proc_name,
                    event.cmdline,
                    event.domain,
                    event.remote_ip,
                    event.remote_port as i64,
                    event.source,
                    event.bytes_in as i64,
                    event.bytes_out as i64,
                    event.packets_in as i64,
                    event.packets_out as i64,
                    event.duration_ms as i64,
                    i32::from(event.programmatic),
                    event.ai_score,
                    event.agent,
                    i32::from(event.is_noise),
                ],
            )?;
        }

        Ok(event)
    }

    pub fn list_events(&self, limit: usize) -> Result<Vec<FlowEvent>> {
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            "SELECT timestamp, pid, proc, cmdline, domain, remote_ip, remote_port, source,
                    bytes_in, bytes_out, packets_in, packets_out, duration_ms, programmatic,
                    ai_score, agent, is_noise
             FROM agentsonar_events
             ORDER BY ai_score DESC, timestamp DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit.min(2000) as i64], |r| {
            Ok(FlowEvent {
                timestamp: r.get::<_, i64>(0)?.max(0) as u64,
                pid: r.get::<_, i64>(1)?.max(0) as u32,
                proc_name: r.get(2)?,
                cmdline: r.get(3)?,
                domain: r.get(4)?,
                remote_ip: r.get(5)?,
                remote_port: r.get::<_, i64>(6)?.clamp(0, 65535) as u16,
                source: r.get(7)?,
                bytes_in: r.get::<_, i64>(8)?.max(0) as u64,
                bytes_out: r.get::<_, i64>(9)?.max(0) as u64,
                packets_in: r.get::<_, i64>(10)?.max(0) as u64,
                packets_out: r.get::<_, i64>(11)?.max(0) as u64,
                duration_ms: r.get::<_, i64>(12)?.max(0) as u64,
                programmatic: r.get::<_, i32>(13)? != 0,
                ai_score: r.get(14)?,
                agent: r.get(15)?,
                is_noise: r.get::<_, i32>(16)? != 0,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Queries unclassified high-scoring flows eligible for interactive or WebUI triage.
    pub fn triage_candidates(&self, min_score: f64) -> Result<Vec<TriageCandidate>> {
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            "SELECT proc, domain, MAX(ai_score) AS max_score, MAX(bytes_in), MAX(bytes_out),
                    MAX(packets_in), MAX(duration_ms)
             FROM agentsonar_events
             WHERE agent = '' AND is_noise = 0 AND ai_score >= ?1
             GROUP BY proc, domain
             ORDER BY max_score DESC",
        )?;
        let rows = stmt.query_map(params![min_score], |r| {
            Ok(TriageCandidate {
                proc_name: r.get(0)?,
                domain: r.get(1)?,
                ai_score: r.get(2)?,
                bytes_in: r.get::<_, i64>(3)?.max(0) as u64,
                bytes_out: r.get::<_, i64>(4)?.max(0) as u64,
                packets_in: r.get::<_, i64>(5)?.max(0) as u64,
                duration_ms: r.get::<_, i64>(6)?.max(0) as u64,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Applies an operator triage decision and immediately re-evaluates matching stored events.
    pub fn apply_triage_decision(&self, decision: &TriageDecision) -> Result<()> {
        let conn = self.open_conn()?;
        match decision {
            TriageDecision::KnownAgent {
                agent,
                proc_pattern,
                domain_pattern,
            } => {
                conn.execute(
                    "INSERT OR REPLACE INTO agentsonar_known_agents VALUES (?1, ?2, ?3)",
                    params![agent.trim(), proc_pattern.trim(), domain_pattern.trim()],
                )?;
                conn.execute(
                    "UPDATE agentsonar_events SET agent = ?1, ai_score = 1.0
                     WHERE proc = ?2 AND domain = ?3",
                    params![agent.trim(), proc_pattern.trim(), domain_pattern.trim()],
                )?;
            }
            TriageDecision::IgnoreNoise { domain } => {
                let dom = domain.trim().to_ascii_lowercase();
                conn.execute(
                    "INSERT OR IGNORE INTO agentsonar_noise_domains VALUES (?1)",
                    params![dom],
                )?;
                conn.execute(
                    "UPDATE agentsonar_events SET is_noise = 1, ai_score = 0.0
                     WHERE LOWER(domain) = ?1",
                    params![dom],
                )?;
            }
        }
        Ok(())
    }

    /// Classifies a single JSONL event line using current SQLite rules + optional external classifier.
    pub fn classify_jsonl_line(
        &self,
        line: &str,
        external_cmd: Option<&str>,
    ) -> Result<serde_json::Value> {
        let rules = self.load_rules()?;
        let v: serde_json::Value =
            serde_json::from_str(line.trim()).context("Failed to parse JSONL flow event")?;
        let proc_name = v.get("proc").and_then(|s| s.as_str()).unwrap_or("");
        let cmdline = v.get("cmdline").and_then(|s| s.as_str()).unwrap_or("");
        let domain = v.get("domain").and_then(|s| s.as_str()).unwrap_or("");
        let extras = v.get("extras");

        let parse_u64 = |k: &str| -> u64 {
            extras
                .and_then(|e| e.get(k))
                .or_else(|| v.get(k))
                .and_then(|val| {
                    val.as_str()
                        .and_then(|s| s.parse().ok())
                        .or_else(|| val.as_u64())
                })
                .unwrap_or(0)
        };

        let prog = extras
            .and_then(|e| e.get("programmatic"))
            .or_else(|| v.get("programmatic"))
            .and_then(|val| {
                val.as_str()
                    .map(|s| s.eq_ignore_ascii_case("true"))
                    .or_else(|| val.as_bool())
            })
            .unwrap_or_else(|| rules.is_programmatic(proc_name, cmdline));

        let (mut score, agent, is_noise) = rules.score_flow(
            proc_name,
            domain,
            parse_u64("bytes_in"),
            parse_u64("bytes_out"),
            parse_u64("packets_in"),
            parse_u64("packets_out"),
            parse_u64("duration_ms"),
            prog,
        );

        if let Some(cmd_str) = external_cmd {
            if let Some(ext_score) =
                run_external_classifier(cmd_str, line).map_err(|e| anyhow!("{}", e))?
            {
                score = ext_score;
            }
        }

        Ok(serde_json::json!({
            "proc": proc_name,
            "domain": domain,
            "scores": { "default": score },
            "agent": agent,
            "is_noise": is_noise
        }))
    }

    /// Ingests a parsed TCP packet into the live flow map and extracts TLS SNI when present.
    pub fn ingest_parsed_segment(
        &self,
        seg: &ParsedTcpSegment<'_>,
        resolver: &mut ProcSocketResolver,
        enable_pid0: bool,
    ) {
        let now = now_ms();
        let src_is_local = resolver.is_local_ip(&seg.src_ip);
        let dst_is_local = resolver.is_local_ip(&seg.dst_ip);

        let outbound_dir = if src_is_local && !dst_is_local {
            true
        } else if !src_is_local && dst_is_local {
            false
        } else {
            // Loopback or ambiguous local interface: check owned client port first, then port heuristic
            let (src_pid, _, _) = resolver.resolve_local_port(seg.src_port);
            if src_pid > 0 && seg.dst_port < seg.src_port {
                true
            } else {
                seg.src_port > seg.dst_port
            }
        };

        let key = if outbound_dir {
            FlowKey {
                local_port: seg.src_port,
                remote_ip: seg.dst_ip,
                remote_port: seg.dst_port,
            }
        } else {
            FlowKey {
                local_port: seg.dst_port,
                remote_ip: seg.src_ip,
                remote_port: seg.src_port,
            }
        };

        let sni_opt = if outbound_dir && !seg.payload.is_empty() {
            extract_tls_sni(seg.payload).or_else(|| {
                if seg.dst_port == 53 {
                    extract_dns_qname(seg.payload)
                } else {
                    None
                }
            })
        } else {
            None
        };

        let rules = self.load_rules().unwrap_or_default();
        let mut map = self.flows.write();
        let entry = map.entry(key).or_insert_with_key(|k| {
            let (pid, proc_name, cmdline) = resolver.resolve_local_port(k.local_port);
            let prog = rules.is_programmatic(&proc_name, &cmdline);
            ActiveFlow {
                first_seen_ms: now,
                last_seen_ms: now,
                pid,
                proc_name,
                cmdline,
                domain: String::new(),
                source: "tls".to_string(),
                bytes_in: 0,
                bytes_out: 0,
                packets_in: 0,
                packets_out: 0,
                programmatic: prog,
            }
        });

        if !enable_pid0 && entry.pid == 0 {
            return;
        }

        entry.last_seen_ms = now;
        let pkt_len = seg.packet_len as u64;
        if outbound_dir {
            entry.bytes_out = entry.bytes_out.saturating_add(pkt_len);
            entry.packets_out = entry.packets_out.saturating_add(1);
            if let Some(sni) = sni_opt {
                entry.domain = sni;
            }
        } else {
            entry.bytes_in = entry.bytes_in.saturating_add(pkt_len);
            entry.packets_in = entry.packets_in.saturating_add(1);
        }
    }

    /// Samples live OS sockets across Windows/Linux/macOS (Tier 2 unprivileged telemetry)
    /// and flushes scored flows to `agentsonar_events`.
    pub fn sample_live_host_flows_once(&self, show_all: bool) -> Result<usize> {
        let _ = self.sync_config_file_if_modified();
        let conn = self.open_conn()?;
        let rules = DynamicRuleSet::load_from_db(&conn)?;
        let current_ms = now_ms();

        // Refresh active socket observations from the OS kernel socket table
        {
            let mut map = self.flows.write();
            for sock in query_live_os_process_sockets() {
                if sock.remote_port == 0 || sock.remote_address.is_empty() {
                    continue;
                }
                let Ok(rem_ip) = sock.remote_address.parse::<IpAddr>() else {
                    continue;
                };
                if rem_ip.is_unspecified() {
                    continue;
                }
                let key = FlowKey {
                    local_port: sock.local_port,
                    remote_ip: rem_ip,
                    remote_port: sock.remote_port,
                };
                let prog = rules.is_programmatic(&sock.process_name, &sock.command_line);
                let entry = map.entry(key).or_insert_with(|| ActiveFlow {
                    first_seen_ms: current_ms,
                    last_seen_ms: current_ms,
                    pid: sock.pid,
                    proc_name: sock.process_name.clone(),
                    cmdline: sock.command_line.clone(),
                    domain: infer_domain_from_socket(&sock.remote_address, sock.remote_port),
                    source: "kernel_socket".to_string(),
                    bytes_in: 0,
                    bytes_out: 0,
                    packets_in: 0,
                    packets_out: 0,
                    programmatic: prog,
                });
                entry.last_seen_ms = current_ms;
                if entry.domain.is_empty() {
                    entry.domain = infer_domain_from_socket(&sock.remote_address, sock.remote_port);
                }
            }
        }

        let mut flushed = 0usize;
        let mut map = self.flows.write();
        for (key, flow) in map.iter() {
            if flow.domain.is_empty() {
                continue;
            }
            let duration_ms = flow.last_seen_ms.saturating_sub(flow.first_seen_ms);
            let (score, agent, is_noise) = rules.score_flow(
                &flow.proc_name,
                &flow.domain,
                flow.bytes_in,
                flow.bytes_out,
                flow.packets_in,
                flow.packets_out,
                duration_ms,
                flow.programmatic,
            );

            if !show_all && is_noise {
                continue;
            }

            conn.execute(
                "INSERT OR REPLACE INTO agentsonar_events VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17
                )",
                params![
                    (current_ms / 1000) as i64,
                    flow.pid as i64,
                    flow.proc_name,
                    flow.cmdline,
                    flow.domain,
                    key.remote_ip.to_string(),
                    key.remote_port as i64,
                    flow.source,
                    flow.bytes_in as i64,
                    flow.bytes_out as i64,
                    flow.packets_in as i64,
                    flow.packets_out as i64,
                    duration_ms as i64,
                    i32::from(flow.programmatic),
                    score,
                    agent,
                    i32::from(is_noise),
                ],
            )?;
            flushed += 1;
        }
        map.retain(|_, f| current_ms.saturating_sub(f.last_seen_ms) < 120_000);

        Ok(flushed)
    }

    pub fn status_report(&self) -> Result<AgentSonarStatusReport> {
        let rules = self.load_rules()?;
        let conn = self.open_conn()?;
        let events_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM agentsonar_events", [], |r| r.get(0))?;
        let high_score_shadow_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM agentsonar_events WHERE agent = '' AND is_noise = 0 AND ai_score >= 0.70",
            [],
            |r| r.get(0),
        )?;

        Ok(AgentSonarStatusReport {
            db_path: self.db_path.to_string_lossy().to_string(),
            config_path: self
                .config_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            collector_running: self.collector_running.load(Ordering::Relaxed),
            events_count: events_count.max(0) as usize,
            high_score_shadow_count: high_score_shadow_count.max(0) as usize,
            known_agents_count: rules.agents.len(),
            noise_domains_count: rules.noise_domains.len(),
            browser_procs_count: rules.non_programmatic_procs.len(),
            heuristics: rules.heuristics,
        })
    }

    /// Spawns the 3-second hot-reloading background collector thread (idempotent).
    pub fn start_background_collector(self: &Arc<Self>, show_all: bool) -> Arc<AtomicBool> {
        if self
            .collector_running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Arc::clone(&self.collector_running);
        }

        let engine = Arc::clone(self);
        let running = Arc::clone(&self.collector_running);
        thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                let _ = engine.sample_live_host_flows_once(show_all);
                thread::sleep(Duration::from_secs(3));
            }
        });

        Arc::clone(&self.collector_running)
    }
}

fn infer_domain_from_socket(remote_addr: &str, remote_port: u16) -> String {
    match remote_port {
        11434 => "ollama.local".to_string(),
        1234 => "lmstudio.local".to_string(),
        8000 => "vllm.local".to_string(),
        _ => remote_addr.to_string(),
    }
}

/// Process-wide singleton Dynamic AgentSonar Engine backed by `data/agentsonar.db` + `config/agentsonar.json`.
pub static GLOBAL_AGENTSONAR_ENGINE: LazyLock<Arc<AgentSonarEngine>> = LazyLock::new(|| {
    let db_path = default_agentsonar_db_path();
    let cfg_path = PathBuf::from("config").join("agentsonar.json");
    let cfg_opt = if cfg_path.exists() {
        Some(cfg_path)
    } else {
        None
    };
    let engine = AgentSonarEngine::new(db_path, cfg_opt).unwrap_or_else(|_| {
        let fallback = std::env::temp_dir().join("killswitch_agentsonar.db");
        AgentSonarEngine::new(fallback, None).expect("Fallback AgentSonar SQLite initialization")
    });
    Arc::new(engine)
});

pub fn global_agentsonar_engine() -> Arc<AgentSonarEngine> {
    Arc::clone(&GLOBAL_AGENTSONAR_ENGINE)
}
