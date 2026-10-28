//! # Multi-Protocol EDR Rate-Limit, Truncated Exponential Backoff & Agent Velocity Engine
//!
//! Adapted from the EDR rate-limit correlation engine (`rate_limit_backoff.rs`),
//! `StatisticalScreener` (`screener.rs`), and `BehavioralSentinelArm`:
//! - **11 Supported Transport & Application Protocols**: `HttpHttps`, `Tcp`, `Udp`, `Quic`,
//!   `Dns`, `Grpc`, `WebSocket`, `Ssh`, `Smtp`, `SmbRdp`, `Icmp`.
//! - **RFC 6298 (TCP RTO), RFC 9002 (QUIC PTO), & Google API Exponential Backoff + Jitter**:
//!   Mathematically verifies $T_{\text{wait}} = \min(T_{\text{base}} \cdot 2^k + \text{jitter}, T_{\text{max}})$
//!   with 15% clock-skew tolerance, rejecting flat polling, linear progression, and collapsing intervals.
//! - **RETE Alpha-Beta Multi-Source Correlation (`ReteEngine`) & 3-Voter Ensemble (`RateLimitVoterEnsemble`)**:
//!   Joins Network Flow facts, live OSQuery Process facts, and Binary Forensics facts by PID,
//!   enforcing 4 Hard Invariants (User Override Allowlist, Compliant Exponential Backoff,
//!   Benign Interactive Developer Script Protection, and Hostile Flood Containment).
//! - **Agent Tool-Call & Token-Burst Sliding-Window Rate Limiter (`AgentVelocityRateLimiter`)**:
//!   Detects OWASP Agentic `ASI08` (Cascading Failure Loops) and `ASI09` (Runaway Tool/DNS/API Velocity)
//!   during autonomous AI agent breakout attempts.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{LazyLock, RwLock};

// ============================================================================
// 1. NetworkProtocol (11 Supported Transport & Application Protocols)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkProtocol {
    HttpHttps,
    Tcp,
    Udp,
    Quic,
    Dns,
    Grpc,
    WebSocket,
    Ssh,
    Smtp,
    SmbRdp,
    Icmp,
}

impl NetworkProtocol {
    /// Case-insensitively parses protocol string and infers protocol from destination port when ambiguous.
    pub fn from_str_or_port(proto: &str, dst_port: Option<u16>) -> Self {
        let p_lower = proto.trim().to_ascii_lowercase();
        match p_lower.as_str() {
            "http" | "https" | "http/https" | "http1" | "http2" | "h2" => Self::HttpHttps,
            "tcp" => match dst_port {
                Some(53) => Self::Dns,
                Some(22) => Self::Ssh,
                Some(25) | Some(465) | Some(587) => Self::Smtp,
                Some(445) | Some(3389) => Self::SmbRdp,
                Some(80) | Some(443) | Some(3030) | Some(8080) | Some(8443) => Self::HttpHttps,
                Some(50051) => Self::Grpc,
                _ => Self::Tcp,
            },
            "udp" => match dst_port {
                Some(53) => Self::Dns,
                Some(443) | Some(8443) => Self::Quic,
                _ => Self::Udp,
            },
            "quic" | "http3" | "h3" => Self::Quic,
            "dns" => Self::Dns,
            "grpc" => Self::Grpc,
            "ws" | "wss" | "websocket" => Self::WebSocket,
            "ssh" => Self::Ssh,
            "smtp" => Self::Smtp,
            "smb" | "rdp" | "smb/rdp" | "smbrdp" => Self::SmbRdp,
            "icmp" | "ping" => Self::Icmp,
            _ => {
                if let Some(port) = dst_port {
                    match port {
                        53 => Self::Dns,
                        22 => Self::Ssh,
                        25 | 465 | 587 => Self::Smtp,
                        445 | 3389 => Self::SmbRdp,
                        80 | 443 | 3030 | 8080 | 8443 => Self::HttpHttps,
                        50051 => Self::Grpc,
                        _ => Self::Tcp,
                    }
                } else {
                    Self::HttpHttps
                }
            }
        }
    }

    /// Base Retransmission Timeout (RTO) floor in milliseconds:
    /// - 200ms for transport layer (Tcp, Udp, Quic, Dns, Icmp)
    /// - 500ms for application layer (HttpHttps, Grpc, WebSocket, Ssh, Smtp, SmbRdp)
    pub const fn base_rto_floor_ms(&self) -> u64 {
        match self {
            Self::Tcp | Self::Udp | Self::Quic | Self::Dns | Self::Icmp => 200,
            Self::HttpHttps
            | Self::Grpc
            | Self::WebSocket
            | Self::Ssh
            | Self::Smtp
            | Self::SmbRdp => 500,
        }
    }

    /// Evaluates whether a numeric status or protocol error code signifies throttling/rate-limiting.
    pub fn is_throttle_status(&self, status: u32) -> bool {
        match self {
            Self::HttpHttps => status == 429 || status == 503,
            Self::Tcp => status == 104 || status == 111 || status == 0 || status == 504,
            Self::Udp => status == 1 || status == 11 || status == 503,
            Self::Quic => status == 0x02 || status == 0x0b || status == 429 || status == 503,
            Self::Dns => status == 2 || status == 5 || status == 429,
            Self::Grpc => status == 8 || status == 14,
            Self::WebSocket => status == 1013 || status == 1008 || status == 429,
            Self::Ssh => status == 1 || status == 429,
            Self::Smtp => status == 421 || status == 450 || status == 451 || status == 452,
            Self::SmbRdp => status == 0xC000005E || status == 429 || status == 503,
            Self::Icmp => status == 3 || status == 4,
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::HttpHttps => "HTTP/HTTPS",
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Quic => "QUIC",
            Self::Dns => "DNS",
            Self::Grpc => "gRPC",
            Self::WebSocket => "WebSocket",
            Self::Ssh => "SSH",
            Self::Smtp => "SMTP",
            Self::SmbRdp => "SMB/RDP",
            Self::Icmp => "ICMP",
        }
    }
}

// ============================================================================
// 2. Multi-Source Fact & Telemetry Structures
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarEntrySample {
    pub timestamp_ms: u64,
    pub status: u32,
    pub retry_after_ms: Option<u64>,
    pub url: String,
    pub method: String,
    pub protocol: NetworkProtocol,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarFlowFact {
    pub flow_id: String,
    pub pid: u32,
    pub protocol: NetworkProtocol,
    pub dst_host: String,
    pub dst_port: u16,
    pub samples: Vec<HarEntrySample>,
    pub backoff_compliant: bool,
    pub observed_jitter_present: bool,
    pub honors_retry_after: bool,
    pub flood_detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsqueryProcessFact {
    pub pid: u32,
    pub process_name: String,
    pub cmdline: String,
    pub is_interactive: bool,
    pub parent_pid: u32,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaBinaryFact {
    pub pid: u32,
    pub binary_path: String,
    pub is_packed: bool,
    pub direct_syscall_count: u32,
    pub obfuscation_entropy: f64,
    pub is_authenticode_signed: bool,
    pub yara_detections: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedEvidenceBundle {
    pub pid: u32,
    pub flow: Option<HarFlowFact>,
    pub process: Option<OsqueryProcessFact>,
    pub binary: Option<ReaBinaryFact>,
    pub protocol: NetworkProtocol,
    pub dst_host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackoffEvaluationReport {
    pub protocol: NetworkProtocol,
    pub total_samples: usize,
    pub throttle_count: usize,
    pub backoff_compliant: bool,
    pub observed_jitter_present: bool,
    pub honors_retry_after: bool,
    pub flood_detected: bool,
    pub calculated_rto_ms: u64,
    pub fit_slope: f64,
    pub avg_growth_ratio: f64,
    pub summary: String,
}

// ============================================================================
// 3. RFC 6298, RFC 9002, & Google API Exponential Backoff + Jitter Analyzer
// ============================================================================

pub fn calculate_exponential_backoff_ms(
    attempt: u32,
    base_ms: u64,
    max_ms: u64,
    jitter_ms: u64,
) -> u64 {
    let factor = 1u64.checked_shl(attempt).unwrap_or(u64::MAX);
    let exp_val = base_ms.saturating_mul(factor);
    let with_jitter = exp_val.saturating_add(jitter_ms);
    with_jitter.min(max_ms)
}

pub fn rfc6298_next_rto_ms(current_rto_ms: u64, max_rto_ms: u64) -> u64 {
    current_rto_ms.saturating_mul(2).min(max_rto_ms)
}

pub fn rfc6298_rto_after_attempts_ms(base_rto_ms: u64, attempts: u32, max_rto_ms: u64) -> u64 {
    let factor = 1u64.checked_shl(attempts).unwrap_or(u64::MAX);
    base_rto_ms.saturating_mul(factor).min(max_rto_ms)
}

pub fn rfc9002_next_pto_ms(base_pto_ms: u64, pto_count: u32, max_pto_ms: u64) -> u64 {
    let factor = 1u64.checked_shl(pto_count).unwrap_or(u64::MAX);
    base_pto_ms.saturating_mul(factor).min(max_pto_ms)
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CurveFitResult {
    pub backoff_compliant: bool,
    pub observed_jitter_present: bool,
    pub fit_slope: f64,
    pub avg_growth_ratio: f64,
}

pub struct GoogleApiBackoffAnalyzer;

impl GoogleApiBackoffAnalyzer {
    pub fn evaluate_har_stream(entries: &[HarEntrySample]) -> BackoffEvaluationReport {
        if entries.is_empty() {
            return BackoffEvaluationReport {
                protocol: NetworkProtocol::HttpHttps,
                total_samples: 0,
                throttle_count: 0,
                backoff_compliant: true,
                observed_jitter_present: false,
                honors_retry_after: true,
                flood_detected: false,
                calculated_rto_ms: 0,
                fit_slope: 0.0,
                avg_growth_ratio: 1.0,
                summary: "Empty traffic stream".to_string(),
            };
        }
        let proto = entries[0].protocol;
        Self::evaluate_protocol_stream(proto, entries)
    }

    pub fn verify_exponential_curve(
        intervals: &[u64],
        base_rto_ms: u64,
        max_backoff_ms: u64,
    ) -> CurveFitResult {
        if intervals.is_empty() {
            return CurveFitResult {
                backoff_compliant: true,
                observed_jitter_present: false,
                fit_slope: 0.0,
                avg_growth_ratio: 1.0,
            };
        }

        if intervals.len() == 1 {
            let compliant = intervals[0] >= ((base_rto_ms as f64) * 0.85) as u64;
            return CurveFitResult {
                backoff_compliant: compliant,
                observed_jitter_present: false,
                fit_slope: std::f64::consts::LN_2,
                avg_growth_ratio: 2.0,
            };
        }

        let first = intervals[0];
        let observed_jitter_present = intervals.iter().any(|&d| d != first);
        let saturation_threshold = ((max_backoff_ms as f64) * 0.85) as u64;
        let mut pre_saturation: Vec<u64> = intervals
            .iter()
            .copied()
            .take_while(|&d| d < saturation_threshold)
            .collect();

        if pre_saturation.is_empty() {
            pre_saturation.push(intervals[0]);
        } else if pre_saturation.len() < intervals.len() {
            pre_saturation.push(intervals[pre_saturation.len()]);
        }

        // Invariant 1: Reject Flat / Constant Intervals
        let min_val = *intervals.iter().min().unwrap_or(&0);
        let max_val = *intervals.iter().max().unwrap_or(&0);
        if max_val < saturation_threshold {
            let spread = max_val.saturating_sub(min_val) as f64;
            let rel_spread = spread / (min_val.max(1) as f64);
            if rel_spread < 0.15 && !observed_jitter_present {
                return CurveFitResult {
                    backoff_compliant: false,
                    observed_jitter_present: false,
                    fit_slope: 0.0,
                    avg_growth_ratio: 1.0,
                };
            }
        }

        // Invariant 2: Reject Collapsing Intervals
        for w in pre_saturation.windows(2) {
            let prev = w[0] as f64;
            let next = w[1] as f64;
            if next < prev * 0.70 {
                return CurveFitResult {
                    backoff_compliant: false,
                    observed_jitter_present,
                    fit_slope: 0.0,
                    avg_growth_ratio: next / prev.max(1.0),
                };
            }
        }

        // Invariant 3: Reject Flat or Linear Growth Ratios (< 1.40)
        let mut growth_ratios = Vec::new();
        for w in pre_saturation.windows(2) {
            let prev = w[0].max(1) as f64;
            let next = w[1] as f64;
            growth_ratios.push(next / prev);
        }
        let avg_growth_ratio: f64 = if !growth_ratios.is_empty() {
            growth_ratios.iter().sum::<f64>() / (growth_ratios.len() as f64)
        } else {
            1.0
        };
        if avg_growth_ratio < 1.40 {
            return CurveFitResult {
                backoff_compliant: false,
                observed_jitter_present,
                fit_slope: 0.0,
                avg_growth_ratio,
            };
        }

        // Invariant 4: Log-Linear Regression Slope ln(I_k) vs k around ln(2) = 0.69315
        let n = pre_saturation.len() as f64;
        let mut sum_k = 0.0;
        let mut sum_lnk = 0.0;
        let mut sum_k_sq = 0.0;
        let mut sum_k_lnk = 0.0;

        for (k_idx, &interval) in pre_saturation.iter().enumerate() {
            let k = k_idx as f64;
            let ln_val = (interval.max(1) as f64).ln();
            sum_k += k;
            sum_lnk += ln_val;
            sum_k_sq += k * k;
            sum_k_lnk += k * ln_val;
        }

        let denom = n * sum_k_sq - sum_k * sum_k;
        let fit_slope = if denom.abs() > 1e-9 {
            (n * sum_k_lnk - sum_k * sum_lnk) / denom
        } else {
            std::f64::consts::LN_2
        };

        let backoff_compliant = (0.38..=1.35).contains(&fit_slope);

        CurveFitResult {
            backoff_compliant,
            observed_jitter_present,
            fit_slope,
            avg_growth_ratio,
        }
    }

    pub fn evaluate_protocol_stream(
        proto: NetworkProtocol,
        samples: &[HarEntrySample],
    ) -> BackoffEvaluationReport {
        let total_samples = samples.len();
        let base_rto = proto.base_rto_floor_ms();

        if total_samples <= 1 {
            let throttled = samples.iter().any(|s| proto.is_throttle_status(s.status));
            return BackoffEvaluationReport {
                protocol: proto,
                total_samples,
                throttle_count: if throttled { 1 } else { 0 },
                backoff_compliant: true,
                observed_jitter_present: false,
                honors_retry_after: true,
                flood_detected: false,
                calculated_rto_ms: base_rto,
                fit_slope: std::f64::consts::LN_2,
                avg_growth_ratio: 2.0,
                summary: "Insufficient sample sequence to evaluate backoff delta".to_string(),
            };
        }

        let mut throttled_intervals: Vec<u64> = Vec::new();
        let mut retry_after_compliances: Vec<bool> = Vec::new();
        let mut throttle_count = 0;
        let mut consecutive_fast_retries = 0;
        let mut max_consecutive_fast_retries = 0;

        for i in 1..samples.len() {
            let prev = &samples[i - 1];
            let curr = &samples[i];

            if proto.is_throttle_status(prev.status) {
                throttle_count += 1;
                let delta = curr.timestamp_ms.saturating_sub(prev.timestamp_ms);
                throttled_intervals.push(delta);

                if delta < 50 {
                    consecutive_fast_retries += 1;
                    if consecutive_fast_retries > max_consecutive_fast_retries {
                        max_consecutive_fast_retries = consecutive_fast_retries;
                    }
                } else {
                    consecutive_fast_retries = 0;
                }

                if let Some(req_wait) = prev.retry_after_ms {
                    let min_skew_wait = ((req_wait as f64) * 0.85) as u64;
                    retry_after_compliances.push(delta >= min_skew_wait);
                }
            }
        }

        let flood_detected = max_consecutive_fast_retries >= 2
            || (throttled_intervals.len() >= 3
                && throttled_intervals.iter().all(|&d| d < base_rto / 2));

        let curve_res = Self::verify_exponential_curve(&throttled_intervals, base_rto, 60_000);
        let mut backoff_compliant = !flood_detected && curve_res.backoff_compliant;
        let observed_jitter_present = curve_res.observed_jitter_present;

        let honors_retry_after = if retry_after_compliances.is_empty() {
            true
        } else {
            retry_after_compliances.iter().all(|&c| c)
        };

        if !honors_retry_after {
            backoff_compliant = false;
        }

        let calculated_rto_ms = match proto {
            NetworkProtocol::Tcp => {
                let last_interval = throttled_intervals.last().copied().unwrap_or(base_rto);
                rfc6298_next_rto_ms(last_interval.max(base_rto), 60_000)
            }
            NetworkProtocol::Quic => {
                let pto_count = throttle_count as u32;
                rfc9002_next_pto_ms(base_rto, pto_count, 60_000)
            }
            _ => {
                let attempt = throttle_count as u32;
                let base = if let Some(last_req_wait) =
                    samples.iter().rev().find_map(|s| s.retry_after_ms)
                {
                    last_req_wait
                } else {
                    throttled_intervals.first().copied().unwrap_or(base_rto)
                };
                calculate_exponential_backoff_ms(attempt, base, 60_000, 0)
            }
        };

        let summary = format!(
            "[{}] evaluated {} samples ({} throttled). Compliant: {}, Retry-After: {}, Jitter: {}, Flood: {} (slope={:.2}, ratio={:.2})",
            proto.as_str(),
            total_samples,
            throttle_count,
            backoff_compliant,
            honors_retry_after,
            observed_jitter_present,
            flood_detected,
            curve_res.fit_slope,
            curve_res.avg_growth_ratio
        );

        BackoffEvaluationReport {
            protocol: proto,
            total_samples,
            throttle_count,
            backoff_compliant,
            observed_jitter_present,
            honors_retry_after,
            flood_detected,
            calculated_rto_ms,
            fit_slope: curve_res.fit_slope,
            avg_growth_ratio: curve_res.avg_growth_ratio,
            summary,
        }
    }
}

// ============================================================================
// 4. RETE Pattern-Matching Engine (Bounded 1024 Alpha Memories & Beta Join)
// ============================================================================

const MAX_ALPHA_ENTRIES: usize = 1024;

pub struct ReteEngine {
    har_alpha: RwLock<HashMap<u32, (u64, HarFlowFact)>>,
    osquery_alpha: RwLock<HashMap<u32, (u64, OsqueryProcessFact)>>,
    rea_alpha: RwLock<HashMap<u32, (u64, ReaBinaryFact)>>,
    eviction_queue_har: RwLock<VecDeque<u32>>,
    eviction_queue_osquery: RwLock<VecDeque<u32>>,
    eviction_queue_rea: RwLock<VecDeque<u32>>,
    sequence: AtomicU64,
}

impl Default for ReteEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ReteEngine {
    pub fn new() -> Self {
        Self {
            har_alpha: RwLock::new(HashMap::new()),
            osquery_alpha: RwLock::new(HashMap::new()),
            rea_alpha: RwLock::new(HashMap::new()),
            eviction_queue_har: RwLock::new(VecDeque::new()),
            eviction_queue_osquery: RwLock::new(VecDeque::new()),
            eviction_queue_rea: RwLock::new(VecDeque::new()),
            sequence: AtomicU64::new(1),
        }
    }

    pub fn insert_har_fact(&self, fact: HarFlowFact) {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let pid = fact.pid;
        let mut map = self.har_alpha.write().unwrap();
        let mut q = self.eviction_queue_har.write().unwrap();

        if !map.contains_key(&pid) {
            if map.len() >= MAX_ALPHA_ENTRIES {
                if let Some(oldest_pid) = q.pop_front() {
                    map.remove(&oldest_pid);
                }
            }
            q.push_back(pid);
        }
        map.insert(pid, (seq, fact));
    }

    pub fn insert_osquery_fact(&self, fact: OsqueryProcessFact) {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let pid = fact.pid;
        let mut map = self.osquery_alpha.write().unwrap();
        let mut q = self.eviction_queue_osquery.write().unwrap();

        if !map.contains_key(&pid) {
            if map.len() >= MAX_ALPHA_ENTRIES {
                if let Some(oldest_pid) = q.pop_front() {
                    map.remove(&oldest_pid);
                }
            }
            q.push_back(pid);
        }
        map.insert(pid, (seq, fact));
    }

    pub fn insert_rea_fact(&self, fact: ReaBinaryFact) {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let pid = fact.pid;
        let mut map = self.rea_alpha.write().unwrap();
        let mut q = self.eviction_queue_rea.write().unwrap();

        if !map.contains_key(&pid) {
            if map.len() >= MAX_ALPHA_ENTRIES {
                if let Some(oldest_pid) = q.pop_front() {
                    map.remove(&oldest_pid);
                }
            }
            q.push_back(pid);
        }
        map.insert(pid, (seq, fact));
    }

    pub fn evaluate_beta_join(&self, pid: u32) -> Option<CorrelatedEvidenceBundle> {
        let flow_opt = self
            .har_alpha
            .read()
            .unwrap()
            .get(&pid)
            .map(|(_, f)| f.clone());
        let proc_opt = self
            .osquery_alpha
            .read()
            .unwrap()
            .get(&pid)
            .map(|(_, p)| p.clone());
        let rea_opt = self
            .rea_alpha
            .read()
            .unwrap()
            .get(&pid)
            .map(|(_, r)| r.clone());

        if flow_opt.is_none() && proc_opt.is_none() && rea_opt.is_none() {
            return None;
        }

        let proto = flow_opt
            .as_ref()
            .map(|f| f.protocol)
            .unwrap_or(NetworkProtocol::HttpHttps);

        let dst_host = flow_opt
            .as_ref()
            .map(|f| f.dst_host.clone())
            .unwrap_or_else(|| "unknown_destination".to_string());

        Some(CorrelatedEvidenceBundle {
            pid,
            flow: flow_opt,
            process: proc_opt,
            binary: rea_opt,
            protocol: proto,
            dst_host,
        })
    }

    pub fn alpha_memory_sizes(&self) -> (usize, usize, usize) {
        (
            self.har_alpha.read().unwrap().len(),
            self.osquery_alpha.read().unwrap().len(),
            self.rea_alpha.read().unwrap().len(),
        )
    }

    pub fn clear(&self) {
        self.har_alpha.write().unwrap().clear();
        self.osquery_alpha.write().unwrap().clear();
        self.rea_alpha.write().unwrap().clear();
        self.eviction_queue_har.write().unwrap().clear();
        self.eviction_queue_osquery.write().unwrap().clear();
        self.eviction_queue_rea.write().unwrap().clear();
    }
}

// ============================================================================
// 5. 3-Voter Ensemble, Quorum, & 4 Hard Invariants
// ============================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EdrAction {
    AllowAndWhitelistWindow {
        duration_secs: u64,
        reason: String,
        final_malicious_prob: f64,
    },
    LogBenignThrottlingWarning {
        reason: String,
        final_malicious_prob: f64,
    },
    ContainProcessWfpBlock {
        pid: u32,
        dst_host: String,
        reason: String,
        final_malicious_prob: f64,
        wfp_rule_name: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoterVerdict {
    pub voter_name: String,
    pub weight: f64,
    pub malicious_prob: f64,
    pub confidence: f64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoterConsensus {
    pub action: EdrAction,
    pub final_malicious_prob: f64,
    pub confidence_score: f64,
    pub voters: Vec<VoterVerdict>,
    pub override_applied: bool,
    pub explanation: String,
}

pub struct DeterministicPhysicsVoter;

impl DeterministicPhysicsVoter {
    pub const WEIGHT: f64 = 1.0;

    pub fn vote(bundle: &CorrelatedEvidenceBundle) -> VoterVerdict {
        if let Some(ref flow) = bundle.flow {
            if flow.flood_detected {
                return VoterVerdict {
                    voter_name: "DeterministicPhysicsVoter".to_string(),
                    weight: Self::WEIGHT,
                    malicious_prob: 0.95,
                    confidence: 1.0,
                    reason: "Flood detected: physical retry intervals violated RTO floor and throttle signal".to_string(),
                };
            }
            if flow.backoff_compliant && flow.honors_retry_after {
                let jitter_adj = if flow.observed_jitter_present { 0.03 } else { 0.08 };
                return VoterVerdict {
                    voter_name: "DeterministicPhysicsVoter".to_string(),
                    weight: Self::WEIGHT,
                    malicious_prob: jitter_adj,
                    confidence: 0.98,
                    reason: "Compliant physical truncated exponential backoff and Retry-After satisfied".to_string(),
                };
            }
            if flow.backoff_compliant {
                return VoterVerdict {
                    voter_name: "DeterministicPhysicsVoter".to_string(),
                    weight: Self::WEIGHT,
                    malicious_prob: 0.15,
                    confidence: 0.90,
                    reason: "Exponential backoff compliant without explicit Retry-After".to_string(),
                };
            }
            return VoterVerdict {
                voter_name: "DeterministicPhysicsVoter".to_string(),
                weight: Self::WEIGHT,
                malicious_prob: 0.50,
                confidence: 0.75,
                reason: "Throttled requests without backoff compliance".to_string(),
            };
        }

        VoterVerdict {
            voter_name: "DeterministicPhysicsVoter".to_string(),
            weight: Self::WEIGHT,
            malicious_prob: 0.40,
            confidence: 0.50,
            reason: "No physical flow samples attached".to_string(),
        }
    }
}

pub struct OpenJevDecisionVoter;

impl OpenJevDecisionVoter {
    pub const WEIGHT: f64 = 1.0;

    pub fn vote(bundle: &CorrelatedEvidenceBundle) -> VoterVerdict {
        let mut score: f64 = 0.40;
        let mut reasons = Vec::new();

        if let Some(ref proc) = bundle.process {
            if proc.is_interactive {
                score -= 0.30;
                reasons.push("interactive_session");
            } else {
                score += 0.10;
                reasons.push("background_service");
            }
        }

        if let Some(ref rea) = bundle.binary {
            if rea.is_packed {
                score += 0.40;
                reasons.push("packed_binary");
            }
            if rea.direct_syscall_count > 0 {
                score += 0.40;
                reasons.push("direct_syscalls_present");
            }
            if rea.obfuscation_entropy >= 6.4 {
                score += 0.35;
                reasons.push("high_obfuscation_entropy");
            }
            if rea.is_authenticode_signed {
                score -= 0.30;
                reasons.push("authenticode_signed");
            }
            if !rea.yara_detections.is_empty() {
                score += 0.45;
                reasons.push("yara_detections");
            }
        }

        let prob = score.clamp(0.01, 0.99);
        VoterVerdict {
            voter_name: "OpenJevDecisionVoter".to_string(),
            weight: Self::WEIGHT,
            malicious_prob: prob,
            confidence: 0.95,
            reason: format!("Host context: [{}]", reasons.join(", ")),
        }
    }
}

pub struct GenerativeLlmVoter;

impl GenerativeLlmVoter {
    pub const WEIGHT: f64 = 0.8;

    pub fn vote(bundle: &CorrelatedEvidenceBundle) -> VoterVerdict {
        let proc_name = bundle
            .process
            .as_ref()
            .map(|p| p.process_name.to_ascii_lowercase())
            .unwrap_or_default();
        let cmdline = bundle
            .process
            .as_ref()
            .map(|p| p.cmdline.to_ascii_lowercase())
            .unwrap_or_default();

        let known_dev_tools = [
            "python",
            "python.exe",
            "python3",
            "python3.exe",
            "node",
            "node.exe",
            "npm",
            "npm.cmd",
            "curl",
            "curl.exe",
            "cargo",
            "cargo.exe",
            "git",
            "git.exe",
            "pytest",
            "powershell.exe",
            "cmd.exe",
            "rustc.exe",
            "killswitch.exe",
            "osoosi.exe",
        ];

        let has_yara = bundle
            .binary
            .as_ref()
            .map(|r| !r.yara_detections.is_empty())
            .unwrap_or(false);

        let is_dev_tool = known_dev_tools
            .iter()
            .any(|&tool| proc_name == tool || proc_name.ends_with(&format!("\\{}", tool)));

        let attack_keywords = [
            "stuff",
            "spray",
            "brute",
            "beacon",
            "infiltrate",
            "exfil",
            "reverse_shell",
            "breakout",
        ];
        if attack_keywords.iter().any(|&k| cmdline.contains(k)) || has_yara {
            return VoterVerdict {
                voter_name: "GenerativeLlmVoter".to_string(),
                weight: Self::WEIGHT,
                malicious_prob: 0.88,
                confidence: 0.92,
                reason: "Suspicious commandline semantics / credential-stuffing or breakout flood detected".to_string(),
            };
        }

        if is_dev_tool && !has_yara {
            return VoterVerdict {
                voter_name: "GenerativeLlmVoter".to_string(),
                weight: Self::WEIGHT,
                malicious_prob: 0.12,
                confidence: 0.85,
                reason: format!("Recognized benign developer tool semantics ({})", proc_name),
            };
        }

        VoterVerdict {
            voter_name: "GenerativeLlmVoter".to_string(),
            weight: Self::WEIGHT,
            malicious_prob: 0.45,
            confidence: 0.70,
            reason: "Neutral commandline semantics".to_string(),
        }
    }
}

pub struct RateLimitVoterEnsemble;

impl RateLimitVoterEnsemble {
    pub fn evaluate_and_vote(&self, bundle: &CorrelatedEvidenceBundle) -> VoterConsensus {
        // Hard Invariant 0: User Override Gate
        if RateLimitAllowlist::is_released(&bundle.dst_host, bundle.protocol, Some(bundle.pid)) {
            let action = EdrAction::AllowAndWhitelistWindow {
                duration_secs: 86400,
                reason: "User manual rate-limit release override active".to_string(),
                final_malicious_prob: 0.0,
            };
            return VoterConsensus {
                action,
                final_malicious_prob: 0.0,
                confidence_score: 1.0,
                voters: Vec::new(),
                override_applied: true,
                explanation: format!(
                    "Allowlisted by user manual override for {}",
                    bundle.dst_host
                ),
            };
        }

        let v1 = DeterministicPhysicsVoter::vote(bundle);
        let v2 = OpenJevDecisionVoter::vote(bundle);
        let v3 = GenerativeLlmVoter::vote(bundle);
        let voters = vec![v1, v2, v3];

        let mut weighted_prob_sum = 0.0;
        let mut weighted_conf_sum = 0.0;
        let mut total_weight = 0.0;

        for v in &voters {
            weighted_prob_sum += v.weight * v.malicious_prob * v.confidence;
            weighted_conf_sum += v.weight * v.confidence;
            total_weight += v.weight;
        }

        let final_malicious_prob = if weighted_conf_sum > 0.0 {
            (weighted_prob_sum / weighted_conf_sum).clamp(0.0, 1.0)
        } else {
            0.50
        };

        let confidence_score = if total_weight > 0.0 {
            (weighted_conf_sum / total_weight).clamp(0.0, 1.0)
        } else {
            0.50
        };

        let backoff_compliant = bundle
            .flow
            .as_ref()
            .map(|f| f.backoff_compliant)
            .unwrap_or(false);
        let honors_retry_after = bundle
            .flow
            .as_ref()
            .map(|f| f.honors_retry_after)
            .unwrap_or(false);
        let entropy = bundle
            .binary
            .as_ref()
            .map(|b| b.obfuscation_entropy)
            .unwrap_or(0.0);
        let is_interactive = bundle
            .process
            .as_ref()
            .map(|p| p.is_interactive)
            .unwrap_or(false);
        let is_packed = bundle.binary.as_ref().map(|b| b.is_packed).unwrap_or(false);
        let direct_syscalls = bundle
            .binary
            .as_ref()
            .map(|b| b.direct_syscall_count)
            .unwrap_or(0);

        let is_interactive_unpacked = is_interactive && !is_packed && direct_syscalls == 0;

        // Hard Invariant 1: Compliant Exponential Backoff
        if backoff_compliant && honors_retry_after && entropy < 6.4 {
            let action = EdrAction::AllowAndWhitelistWindow {
                duration_secs: 3600,
                reason: "Compliant exponential backoff with jitter and verified binary".to_string(),
                final_malicious_prob,
            };
            return VoterConsensus {
                action,
                final_malicious_prob,
                confidence_score,
                voters,
                override_applied: false,
                explanation: "Hard Invariant 1: Compliant exponential backoff satisfied; whitelisting window granted".to_string(),
            };
        }

        // Hard Invariant 2: Benign Developer Script Protection
        if is_interactive_unpacked {
            let action = EdrAction::LogBenignThrottlingWarning {
                reason: "Interactive developer process unthrottled: warning logged without containment".to_string(),
                final_malicious_prob,
            };
            return VoterConsensus {
                action,
                final_malicious_prob,
                confidence_score,
                voters,
                override_applied: false,
                explanation: "Hard Invariant 2: Interactive user session protected against false-positive containment".to_string(),
            };
        }

        // Hard Invariant 3: Hostile Containment via Native WFP
        if final_malicious_prob >= 0.82 && !is_interactive_unpacked {
            let rule_name = format!(
                "KILLSWITCH_RL_{}_{}",
                bundle.pid,
                bundle.dst_host.replace(':', "_")
            );
            let action = EdrAction::ContainProcessWfpBlock {
                pid: bundle.pid,
                dst_host: bundle.dst_host.clone(),
                reason: format!(
                    "Hostile flood, C2 beacon, or agent breakout rate violation detected (prob={:.2})",
                    final_malicious_prob
                ),
                final_malicious_prob,
                wfp_rule_name: rule_name,
            };
            return VoterConsensus {
                action,
                final_malicious_prob,
                confidence_score,
                voters,
                override_applied: false,
                explanation: "Hard Invariant 3: Hostile containment threshold exceeded; WFP containment required".to_string(),
            };
        }

        let action = if final_malicious_prob >= 0.60 {
            EdrAction::LogBenignThrottlingWarning {
                reason: format!("Elevated throttling risk detected (prob={:.2})", final_malicious_prob),
                final_malicious_prob,
            }
        } else {
            EdrAction::AllowAndWhitelistWindow {
                duration_secs: 1800,
                reason: "Nominal risk within tolerable baseline".to_string(),
                final_malicious_prob,
            }
        };

        VoterConsensus {
            action,
            final_malicious_prob,
            confidence_score,
            voters,
            override_applied: false,
            explanation: "Consensus quorum evaluated without invariant trigger".to_string(),
        }
    }
}

// ============================================================================
// 6. User Override Allowlist (`rate_limit_released_allowlist.json`)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitReleaseEntry {
    pub destination_host: String,
    pub protocol: String,
    pub pid: Option<u32>,
    pub operator: String,
    pub reason: String,
    pub timestamp_epoch_secs: u64,
}

static ALLOWLIST_CACHE: LazyLock<RwLock<Vec<RateLimitReleaseEntry>>> =
    LazyLock::new(|| RwLock::new(Vec::new()));
static ALLOWLIST_LOADED: AtomicBool = AtomicBool::new(false);

pub struct RateLimitAllowlist;

impl RateLimitAllowlist {
    pub fn file_path() -> PathBuf {
        PathBuf::from("rate_limit_released_allowlist.json")
    }

    pub fn reload() {
        let p = Self::file_path();
        let mut lock = ALLOWLIST_CACHE.write().unwrap();
        let entries: Vec<RateLimitReleaseEntry> = if p.exists() {
            fs::read_to_string(&p)
                .ok()
                .and_then(|c| serde_json::from_str(&c).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        *lock = entries;
        ALLOWLIST_LOADED.store(true, Ordering::SeqCst);
    }

    pub fn is_released(host: &str, proto: NetworkProtocol, pid: Option<u32>) -> bool {
        if !ALLOWLIST_LOADED.load(Ordering::SeqCst) {
            Self::reload();
        }
        let lock = ALLOWLIST_CACHE.read().unwrap();
        let h_lower = host.trim().to_ascii_lowercase();
        let proto_str = proto.as_str().to_ascii_lowercase();

        lock.iter().any(|entry| {
            let entry_host = entry.destination_host.trim().to_ascii_lowercase();
            let host_match = entry_host == "*" || entry_host == h_lower;

            let entry_proto = entry.protocol.trim().to_ascii_lowercase();
            let proto_match = entry_proto == "*" || entry_proto == proto_str;

            let pid_match = match (entry.pid, pid) {
                (Some(ep), Some(target_p)) => ep == target_p,
                (None, _) => true,
                _ => false,
            };

            host_match && proto_match && pid_match
        })
    }

    pub fn add_entry(entry: RateLimitReleaseEntry) {
        let p = Self::file_path();
        let mut lock = ALLOWLIST_CACHE.write().unwrap();
        lock.retain(|e| {
            !(e.destination_host.eq_ignore_ascii_case(&entry.destination_host)
                && e.protocol.eq_ignore_ascii_case(&entry.protocol)
                && e.pid == entry.pid)
        });
        lock.push(entry);
        if let Ok(json_str) = serde_json::to_string_pretty(&*lock) {
            let _ = fs::write(&p, json_str);
        }
        ALLOWLIST_LOADED.store(true, Ordering::SeqCst);
    }

    pub fn list_entries() -> Vec<RateLimitReleaseEntry> {
        if !ALLOWLIST_LOADED.load(Ordering::Relaxed) {
            Self::reload();
        }
        ALLOWLIST_CACHE.read().unwrap().clone()
    }

    pub fn clear() {
        let p = Self::file_path();
        let mut lock = ALLOWLIST_CACHE.write().unwrap();
        lock.clear();
        if let Ok(json_str) = serde_json::to_string_pretty(&*lock) {
            let _ = fs::write(&p, json_str);
        }
        ALLOWLIST_LOADED.store(true, Ordering::SeqCst);
    }
}

// ============================================================================
// 7. Agent Tool-Call & Token-Burst Sliding-Window Rate Limiter (OWASP ASI08/ASI09)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCallRecord {
    pub timestamp: DateTime<Utc>,
    pub items: u64,
    pub tokens: u32,
    pub is_error: bool,
    pub tool_name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentSessionWindow {
    pub records: Vec<AgentCallRecord>,
    pub consecutive_errors: u32,
    pub total_calls: u64,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentVelocityVerdict {
    pub session_id: String,
    pub is_anomalous: bool,
    pub owasp_risk: Option<String>,
    pub calls_in_60s: usize,
    pub calls_in_last_1s: usize,
    pub cumulative_items_60s: u64,
    pub cumulative_tokens_60s: u64,
    pub consecutive_errors: u32,
    pub reason: Option<String>,
}

/// Sliding-window rate limiter adapted from EDR `StatisticalScreener` (`screener.rs`)
/// and `BehavioralSentinelArm` (`behavioral_sentinel.rs`) to stop runaway AI agent
/// tool loops, DNS/API burst floods, and brute-force sandbox escape attempts.
pub struct AgentVelocityRateLimiter {
    pub sessions: DashMap<String, AgentSessionWindow>,
    pub rate_limit_per_minute: usize,
    pub subsecond_burst_limit: usize,
    pub batch_threshold: u64,
    pub token_burst_threshold: u64,
    pub max_consecutive_errors: u32,
}

impl Default for AgentVelocityRateLimiter {
    fn default() -> Self {
        Self::new(20, 10, 200, 50_000, 5)
    }
}

impl AgentVelocityRateLimiter {
    pub fn new(
        rate_limit_per_minute: usize,
        subsecond_burst_limit: usize,
        batch_threshold: u64,
        token_burst_threshold: u64,
        max_consecutive_errors: u32,
    ) -> Self {
        Self {
            sessions: DashMap::new(),
            rate_limit_per_minute,
            subsecond_burst_limit,
            batch_threshold,
            token_burst_threshold,
            max_consecutive_errors,
        }
    }

    pub fn record_and_check(
        &self,
        session_id: &str,
        tool_name: &str,
        items: u64,
        tokens: u32,
        is_error: bool,
    ) -> AgentVelocityVerdict {
        let now = Utc::now();
        let mut window = self
            .sessions
            .entry(session_id.to_string())
            .or_insert_with(|| AgentSessionWindow {
                records: Vec::new(),
                consecutive_errors: 0,
                total_calls: 0,
                last_seen: now,
            });

        window.last_seen = now;
        window.total_calls = window.total_calls.saturating_add(1);
        if is_error {
            window.consecutive_errors = window.consecutive_errors.saturating_add(1);
        } else {
            window.consecutive_errors = 0;
        }

        window.records.push(AgentCallRecord {
            timestamp: now,
            items,
            tokens,
            is_error,
            tool_name: tool_name.to_string(),
        });

        let window_60s = now - chrono::Duration::seconds(60);
        window.records.retain(|r| r.timestamp >= window_60s);

        let window_1s = now - chrono::Duration::milliseconds(1000);
        let calls_in_last_1s = window.records.iter().filter(|r| r.timestamp >= window_1s).count();
        let calls_in_60s = window.records.len();
        let cumulative_items_60s = window
            .records
            .iter()
            .fold(0u64, |acc, r| acc.saturating_add(r.items));
        let cumulative_tokens_60s = window
            .records
            .iter()
            .fold(0u64, |acc, r| acc.saturating_add(r.tokens as u64));
        let consecutive_errors = window.consecutive_errors;
        drop(window);

        if calls_in_last_1s > self.subsecond_burst_limit {
            return AgentVelocityVerdict {
                session_id: session_id.to_string(),
                is_anomalous: true,
                owasp_risk: Some("OWASP ASI09: Sub-Second Agent Invocation Burst".to_string()),
                calls_in_60s,
                calls_in_last_1s,
                cumulative_items_60s,
                cumulative_tokens_60s,
                consecutive_errors,
                reason: Some(format!(
                    "Agent burst call frequency exceeded: {} calls in < 1.0s (limit: {})",
                    calls_in_last_1s, self.subsecond_burst_limit
                )),
            };
        }

        if calls_in_60s > self.rate_limit_per_minute {
            return AgentVelocityVerdict {
                session_id: session_id.to_string(),
                is_anomalous: true,
                owasp_risk: Some("OWASP ASI09: Tool Call Rate Limit Exceeded".to_string()),
                calls_in_60s,
                calls_in_last_1s,
                cumulative_items_60s,
                cumulative_tokens_60s,
                consecutive_errors,
                reason: Some(format!(
                    "Tool call velocity exceeded: {} calls in 60s (threshold: {})",
                    calls_in_60s, self.rate_limit_per_minute
                )),
            };
        }

        if cumulative_items_60s > self.batch_threshold {
            return AgentVelocityVerdict {
                session_id: session_id.to_string(),
                is_anomalous: true,
                owasp_risk: Some("OWASP ASI09: Cumulative Batch Scraping / Exfiltration Burst".to_string()),
                calls_in_60s,
                calls_in_last_1s,
                cumulative_items_60s,
                cumulative_tokens_60s,
                consecutive_errors,
                reason: Some(format!(
                    "Cumulative batch items requested ({} in 60s) exceeded threshold ({})",
                    cumulative_items_60s, self.batch_threshold
                )),
            };
        }

        if cumulative_tokens_60s > self.token_burst_threshold {
            return AgentVelocityVerdict {
                session_id: session_id.to_string(),
                is_anomalous: true,
                owasp_risk: Some("OWASP ASI09: Token Consumption Spike".to_string()),
                calls_in_60s,
                calls_in_last_1s,
                cumulative_items_60s,
                cumulative_tokens_60s,
                consecutive_errors,
                reason: Some(format!(
                    "Cumulative tokens consumed ({} in 60s) exceeded burst threshold ({})",
                    cumulative_tokens_60s, self.token_burst_threshold
                )),
            };
        }

        if consecutive_errors >= self.max_consecutive_errors {
            return AgentVelocityVerdict {
                session_id: session_id.to_string(),
                is_anomalous: true,
                owasp_risk: Some("OWASP ASI08: Cascading Tool Execution Error Loop".to_string()),
                calls_in_60s,
                calls_in_last_1s,
                cumulative_items_60s,
                cumulative_tokens_60s,
                consecutive_errors,
                reason: Some(format!(
                    "Cascading failure / brute-force loop detected: {} consecutive tool execution errors",
                    consecutive_errors
                )),
            };
        }

        AgentVelocityVerdict {
            session_id: session_id.to_string(),
            is_anomalous: false,
            owasp_risk: None,
            calls_in_60s,
            calls_in_last_1s,
            cumulative_items_60s,
            cumulative_tokens_60s,
            consecutive_errors,
            reason: None,
        }
    }
}

static GLOBAL_RETE: LazyLock<ReteEngine> = LazyLock::new(ReteEngine::new);
static GLOBAL_ENSEMBLE: LazyLock<RateLimitVoterEnsemble> = LazyLock::new(|| RateLimitVoterEnsemble);
static GLOBAL_AGENT_VELOCITY: LazyLock<AgentVelocityRateLimiter> =
    LazyLock::new(AgentVelocityRateLimiter::default);

pub fn global_rete_engine() -> &'static ReteEngine {
    &GLOBAL_RETE
}

pub fn global_rate_limit_ensemble() -> &'static RateLimitVoterEnsemble {
    &GLOBAL_ENSEMBLE
}

pub fn global_agent_velocity_limiter() -> &'static AgentVelocityRateLimiter {
    &GLOBAL_AGENT_VELOCITY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edr_rate_limit_backoff_and_3_voter_invariants() {
        let rete = ReteEngine::new();

        // 1. Compliant Google API Exponential Backoff with Jitter -> AllowAndWhitelistWindow
        let compliant_samples = vec![
            HarEntrySample {
                timestamp_ms: 1000,
                status: 429,
                retry_after_ms: Some(1000),
                url: "https://fhir.epic.com/api/FHIR/R4/Patient".into(),
                method: "GET".into(),
                protocol: NetworkProtocol::HttpHttps,
                duration_ms: 12,
            },
            HarEntrySample {
                timestamp_ms: 2050, // +1050ms
                status: 429,
                retry_after_ms: Some(2000),
                url: "https://fhir.epic.com/api/FHIR/R4/Patient".into(),
                method: "GET".into(),
                protocol: NetworkProtocol::HttpHttps,
                duration_ms: 14,
            },
            HarEntrySample {
                timestamp_ms: 4180, // +2130ms (~2x growth + jitter)
                status: 200,
                retry_after_ms: None,
                url: "https://fhir.epic.com/api/FHIR/R4/Patient".into(),
                method: "GET".into(),
                protocol: NetworkProtocol::HttpHttps,
                duration_ms: 18,
            },
        ];
        let report = GoogleApiBackoffAnalyzer::evaluate_har_stream(&compliant_samples);
        assert!(report.backoff_compliant);
        assert!(report.honors_retry_after);
        assert!(!report.flood_detected);

        rete.insert_har_fact(HarFlowFact {
            flow_id: "flow_1".into(),
            pid: 501,
            protocol: NetworkProtocol::HttpHttps,
            dst_host: "fhir.epic.com".into(),
            dst_port: 443,
            samples: compliant_samples,
            backoff_compliant: report.backoff_compliant,
            observed_jitter_present: report.observed_jitter_present,
            honors_retry_after: report.honors_retry_after,
            flood_detected: report.flood_detected,
        });
        rete.insert_osquery_fact(OsqueryProcessFact {
            pid: 501,
            process_name: "ehr_sync.exe".into(),
            cmdline: "ehr_sync.exe --partner epic".into(),
            is_interactive: false,
            parent_pid: 1,
            username: "svc".into(),
        });
        rete.insert_rea_fact(ReaBinaryFact {
            pid: 501,
            binary_path: "C:\\Program Files\\EHR\\ehr_sync.exe".into(),
            is_packed: false,
            direct_syscall_count: 0,
            obfuscation_entropy: 4.9,
            is_authenticode_signed: true,
            yara_detections: vec![],
        });

        let bundle = rete.evaluate_beta_join(501).unwrap();
        let consensus = RateLimitVoterEnsemble.evaluate_and_vote(&bundle);
        assert!(matches!(
            consensus.action,
            EdrAction::AllowAndWhitelistWindow { .. }
        ));

        // 2. Hostile Non-Interactive Flood / Agent Breakout Beacon -> ContainProcessWfpBlock
        let flood_samples = vec![
            HarEntrySample {
                timestamp_ms: 1000,
                status: 429,
                retry_after_ms: Some(5000),
                url: "https://exfil-c2.org/beacon".into(),
                method: "POST".into(),
                protocol: NetworkProtocol::Dns,
                duration_ms: 5,
            },
            HarEntrySample {
                timestamp_ms: 1015, // 15ms flood retry ignoring Retry-After
                status: 429,
                retry_after_ms: Some(5000),
                url: "https://exfil-c2.org/beacon".into(),
                method: "POST".into(),
                protocol: NetworkProtocol::Dns,
                duration_ms: 5,
            },
            HarEntrySample {
                timestamp_ms: 1030, // 15ms flood retry
                status: 429,
                retry_after_ms: Some(5000),
                url: "https://exfil-c2.org/beacon".into(),
                method: "POST".into(),
                protocol: NetworkProtocol::Dns,
                duration_ms: 5,
            },
        ];
        let flood_rep = GoogleApiBackoffAnalyzer::evaluate_har_stream(&flood_samples);
        assert!(flood_rep.flood_detected);
        assert!(!flood_rep.backoff_compliant);

        rete.insert_har_fact(HarFlowFact {
            flow_id: "flow_flood".into(),
            pid: 666,
            protocol: NetworkProtocol::Dns,
            dst_host: "exfil-c2.org".into(),
            dst_port: 53,
            samples: flood_samples,
            backoff_compliant: flood_rep.backoff_compliant,
            observed_jitter_present: flood_rep.observed_jitter_present,
            honors_retry_after: flood_rep.honors_retry_after,
            flood_detected: flood_rep.flood_detected,
        });
        rete.insert_osquery_fact(OsqueryProcessFact {
            pid: 666,
            process_name: "agent_worker.exe".into(),
            cmdline: "agent_worker.exe --beacon --exfil".into(),
            is_interactive: false,
            parent_pid: 1,
            username: "agent".into(),
        });
        rete.insert_rea_fact(ReaBinaryFact {
            pid: 666,
            binary_path: "C:\\Temp\\agent_worker.exe".into(),
            is_packed: true,
            direct_syscall_count: 3,
            obfuscation_entropy: 6.8,
            is_authenticode_signed: false,
            yara_detections: vec!["AgentBreakoutFlood".into()],
        });

        let flood_bundle = rete.evaluate_beta_join(666).unwrap();
        let flood_consensus = RateLimitVoterEnsemble.evaluate_and_vote(&flood_bundle);
        assert!(matches!(
            flood_consensus.action,
            EdrAction::ContainProcessWfpBlock { .. }
        ));
    }

    #[test]
    fn test_agent_velocity_sliding_window_rate_limiter() {
        let limiter = AgentVelocityRateLimiter::new(20, 5, 200, 50_000, 5);
        for i in 0..5 {
            let v = limiter.record_and_check("agent-session-1", "bash_exec", 1, 100, false);
            assert!(!v.is_anomalous, "Call {} should be within burst limit", i + 1);
        }
        // 6th call within < 1 second exceeds subsecond_burst_limit (5)
        let burst = limiter.record_and_check("agent-session-1", "bash_exec", 1, 100, false);
        assert!(burst.is_anomalous);
        assert!(burst.owasp_risk.unwrap().contains("ASI09"));
    }
}
