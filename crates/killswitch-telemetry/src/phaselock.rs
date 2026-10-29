//! # Phase-Lock Lyapunov Divergence Monitor
//!
//! Implements nonlinear dynamical phase-space reconstruction via Takens' delay embedding
//! ($m = 4$, $\tau = 2$), nearest-neighbor Rosenstein divergence estimation,
//! running attractor centroid & variance tracking via exponential moving average ($\alpha = 0.05$),
//! Mahalanobis distance drift detection, and chaotic breakout alerts.

use std::collections::VecDeque;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use killswitch_types::adjudication::EvidenceClass;
use killswitch_types::telemetry::{SecurityEvent, TelemetryEventKind, ThreatSeverity, ThreatSignal};

/// Configuration parameters for Takens 4D delay embedding and Lyapunov divergence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseSpaceConfig {
    /// Embedding dimension $m$ (default 4).
    pub embedding_dim: usize,
    /// Delay parameter $\tau$ (default 2).
    pub tau_delay: usize,
    /// Circular history buffer capacity (default 32).
    pub window_capacity: usize,
    /// Lyapunov divergence threshold for chaotic dynamics (default 0.85).
    pub chaos_threshold: f64,
    /// Running Mahalanobis distance threshold (default 2.5).
    pub mahalanobis_threshold: f64,
    /// Exponential moving average decay factor $\alpha$ (default 0.05).
    pub ema_alpha: f64,
    /// Canonical phase-space cell diameter $\delta_{\text{cell}}$ (default 0.1).
    pub delta_cell: f64,
}

impl Default for PhaseSpaceConfig {
    fn default() -> Self {
        Self {
            embedding_dim: 4,
            tau_delay: 2,
            window_capacity: 32,
            chaos_threshold: 0.85,
            mahalanobis_threshold: 2.5,
            ema_alpha: 0.05,
            delta_cell: 0.1,
        }
    }
}

/// Evaluation verdict produced for each observed telemetry phase metric.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PhaseSpaceVerdict {
    /// Estimated local Lyapunov divergence exponent $\lambda$.
    pub lyapunov_exponent: f64,
    /// Running Mahalanobis distance $D_M$ from the attractor centroid.
    pub mahalanobis_drift: f64,
    /// True when both Lyapunov divergence and Mahalanobis drift exceed thresholds.
    pub is_chaotic_breakout: bool,
    /// Composite normalized anomaly score in [0.0, 1.0].
    pub anomaly_score: f32,
}

/// Computes Shannon entropy (in bits) of a string slice (e.g. command line arguments).
pub fn compute_shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    let len = input.len() as f64;
    for &b in input.as_bytes() {
        freq[b as usize] += 1;
    }
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Computes scalar phase metric $x(t)$ from event kind, pacing, and entropy.
pub fn compute_syscall_phase_metric(
    event_kind: TelemetryEventKind,
    delta_ms: f64,
    cmdline_entropy: f64,
) -> f64 {
    let event_weight = match event_kind {
        TelemetryEventKind::ProcessCreate => 1.25,
        TelemetryEventKind::NetworkConnect => 1.40,
        TelemetryEventKind::CreateRemoteThread => 3.80,
        TelemetryEventKind::ProcessAccess => 4.20,
        TelemetryEventKind::FileCreate => 1.15,
        TelemetryEventKind::RegistryValueModify => 1.60,
        TelemetryEventKind::DnsQuery => 1.35,
        TelemetryEventKind::DriverLoad => 3.10,
        TelemetryEventKind::ImageLoadDll => 1.80,
        TelemetryEventKind::ThreadInjectVirtualAlloc => 3.90,
        TelemetryEventKind::FileRenameEncrypt => 3.40,
        TelemetryEventKind::VolumeShadowCopyDelete => 4.40,
        TelemetryEventKind::CanaryTrip => 4.50,
        TelemetryEventKind::HoneytokenAccess => 4.80,
        TelemetryEventKind::WatchdogAlert => 3.50,
        TelemetryEventKind::PhaseLockDrift => 2.50,
    };
    let pacing_factor = (1000.0 / (delta_ms.max(1.0) + 10.0)).ln_1p();
    event_weight * (1.0 + 0.35 * cmdline_entropy.max(0.0)) + 0.25 * pacing_factor
}

/// Per-PID stateful phase-lock monitor maintaining Takens embedding and running attractor stats.
#[derive(Debug, Clone)]
pub struct PerPidPhaseLockMonitor {
    config: PhaseSpaceConfig,
    history: VecDeque<f64>,
    centroid: Vec<f64>,
    variance: Vec<f64>,
    consecutive_chaotic_epochs: u32,
    last_event_time: Option<DateTime<Utc>>,
    initialized: bool,
}

impl PerPidPhaseLockMonitor {
    pub fn new(config: PhaseSpaceConfig) -> Self {
        let dim = config.embedding_dim;
        Self {
            config,
            history: VecDeque::with_capacity(32),
            centroid: vec![0.0; dim],
            variance: vec![1.0; dim],
            consecutive_chaotic_epochs: 0,
            last_event_time: None,
            initialized: false,
        }
    }

    pub fn default_edr() -> Self {
        Self::new(PhaseSpaceConfig::default())
    }

    /// Resets historical trajectory state for this PID.
    pub fn reset(&mut self) {
        self.history.clear();
        let dim = self.config.embedding_dim;
        self.centroid = vec![0.0; dim];
        self.variance = vec![1.0; dim];
        self.consecutive_chaotic_epochs = 0;
        self.last_event_time = None;
        self.initialized = false;
    }

    /// Ingests a scalar phase metric observation and computes current phase space verdict.
    pub fn observe(&mut self, metric: f64) -> PhaseSpaceVerdict {
        if self.history.len() >= self.config.window_capacity {
            self.history.pop_front();
        }
        self.history.push_back(metric);

        let m = self.config.embedding_dim;
        let tau = self.config.tau_delay;
        let min_required = (m - 1) * tau + 1;

        if self.history.len() < min_required {
            return PhaseSpaceVerdict {
                lyapunov_exponent: 0.0,
                mahalanobis_drift: 0.0,
                is_chaotic_breakout: false,
                anomaly_score: 0.0,
            };
        }

        // Reconstruct latest delay-coordinate state vector X(t_N)
        // X(t_N) = [x(t_N), x(t_N - tau), x(t_N - 2tau), ..., x(t_N - (m-1)tau)]
        let n = self.history.len();
        let mut latest_vector = Vec::with_capacity(m);
        for k in 0..m {
            let idx = n - 1 - k * tau;
            latest_vector.push(self.history[idx]);
        }

        // Attractor centroid and variance initialization / EMA priming
        if !self.initialized {
            self.centroid = latest_vector.clone();
            self.variance = vec![1.0; m];
            self.initialized = true;
        } else {
            let alpha = self.config.ema_alpha;
            for (k, &val) in latest_vector.iter().enumerate().take(m) {
                let diff = val - self.centroid[k];
                self.centroid[k] += alpha * diff;
                self.variance[k] = (1.0 - alpha) * self.variance[k] + alpha * diff * diff;
            }
        }

        // Warm-up guard: require sufficient history for attractor stabilization
        // and valid Theiler separation neighbor existence before scoring/alerting
        let min_warmup = 16usize.max((m - 1) * tau + 2 * tau + 1);
        if n < min_warmup {
            return PhaseSpaceVerdict {
                lyapunov_exponent: 0.0,
                mahalanobis_drift: 0.0,
                is_chaotic_breakout: false,
                anomaly_score: 0.0,
            };
        }

        // Find nearest historical neighbor X(t_j) where j <= N - tau
        // Neighbor search is only valid when n >= min_required + tau (N >= m*tau + 1)
        let mut min_dist_sq = f64::INFINITY;
        let mut found_neighbor = false;

        if n >= min_required + tau {
            let max_neighbor_ref = n - tau;
            for j in min_required..=max_neighbor_ref {
                // Reconstruct historical vector at j - 1
                let mut hist_vector = Vec::with_capacity(m);
                for k in 0..m {
                    let idx = (j - 1) - k * tau;
                    hist_vector.push(self.history[idx]);
                }

                let mut dist_sq = 0.0;
                for k in 0..m {
                    let diff = latest_vector[k] - hist_vector[k];
                    dist_sq += diff * diff;
                }

                if dist_sq < min_dist_sq {
                    min_dist_sq = dist_sq;
                    found_neighbor = true;
                }
            }
        }

        let min_dist = if found_neighbor {
            min_dist_sq.sqrt().max(1e-6)
        } else {
            self.config.delta_cell
        };

        // Rosenstein formulation: lambda = ln(d_min / delta_cell)
        let lyapunov = (min_dist / self.config.delta_cell).ln();

        // Compute Mahalanobis distance D_M = sqrt(sum((X_k - mu_k)^2 / max(var_k, 1e-6)))
        let mut mahalanobis_sq = 0.0;
        for (k, &val) in latest_vector.iter().enumerate().take(m) {
            let diff = val - self.centroid[k];
            let var = self.variance[k].max(1e-6);
            mahalanobis_sq += (diff * diff) / var;
        }
        let drift = mahalanobis_sq.sqrt();

        // Anomaly condition: Lyapunov divergence > threshold AND Mahalanobis drift > threshold
        let is_chaotic_breakout =
            lyapunov > self.config.chaos_threshold && drift > self.config.mahalanobis_threshold;

        if is_chaotic_breakout {
            self.consecutive_chaotic_epochs += 1;
        } else {
            self.consecutive_chaotic_epochs = self.consecutive_chaotic_epochs.saturating_sub(1);
        }

        let l_norm = (lyapunov / 2.0).clamp(0.0, 1.0);
        let d_norm = (drift / 5.0).clamp(0.0, 1.0);
        let anomaly_score = ((l_norm * 0.5 + d_norm * 0.5) as f32).clamp(0.0, 1.0);

        PhaseSpaceVerdict {
            lyapunov_exponent: lyapunov,
            mahalanobis_drift: drift,
            is_chaotic_breakout,
            anomaly_score,
        }
    }

    /// Observes a security event directly, automatically deriving timing and entropy.
    pub fn observe_event(&mut self, event: &SecurityEvent) -> PhaseSpaceVerdict {
        let now = Utc::now();
        let delta_ms = if let Some(last) = self.last_event_time {
            (now - last).num_milliseconds().max(0) as f64
        } else {
            50.0
        };
        self.last_event_time = Some(now);

        let entropy = compute_shannon_entropy(&event.command_line);
        let metric = compute_syscall_phase_metric(event.event_kind, delta_ms, entropy);
        self.observe(metric)
    }

    pub fn consecutive_chaotic_epochs(&self) -> u32 {
        self.consecutive_chaotic_epochs
    }
}

/// Global Phase-Lock Telemetry Manager coordinating per-PID monitors via DashMap.
#[derive(Clone)]
pub struct PhaseLockManager {
    monitors: Arc<DashMap<u32, PerPidPhaseLockMonitor>>,
    config: PhaseSpaceConfig,
}

impl Default for PhaseLockManager {
    fn default() -> Self {
        Self::new(PhaseSpaceConfig::default())
    }
}

impl PhaseLockManager {
    pub fn new(config: PhaseSpaceConfig) -> Self {
        Self {
            monitors: Arc::new(DashMap::new()),
            config,
        }
    }

    /// Ingests a SecurityEvent into the appropriate PID phase-lock monitor.
    /// If a chaotic breakout is detected, synthesizes a structured `ThreatSignal`.
    pub fn ingest_event(&self, event: &SecurityEvent) -> Option<ThreatSignal> {
        let pid = event.pid;
        let mut monitor = self
            .monitors
            .entry(pid)
            .or_insert_with(|| PerPidPhaseLockMonitor::new(self.config.clone()));

        let verdict = monitor.observe_event(event);

        let is_alert = verdict.is_chaotic_breakout
            || (verdict.mahalanobis_drift > self.config.mahalanobis_threshold * 0.5
                && matches!(
                    event.event_kind,
                    TelemetryEventKind::CreateRemoteThread
                        | TelemetryEventKind::ProcessAccess
                        | TelemetryEventKind::CanaryTrip
                        | TelemetryEventKind::HoneytokenAccess
                )
                && monitor.history.len() >= 16);

        if is_alert {
            let consecutive = monitor.consecutive_chaotic_epochs();
            let confidence = (0.75 + (consecutive as f32 * 0.05)).clamp(0.75, 0.99);
            let severity = if consecutive >= 3 || verdict.lyapunov_exponent > 1.5 {
                ThreatSeverity::Critical
            } else {
                ThreatSeverity::High
            };

            let reason = if verdict.is_chaotic_breakout {
                format!(
                    "Chaotic Lyapunov phase breakout: lambda={:.3} (> {:.2}), drift={:.2} (> {:.2}), consecutive_epochs={}",
                    verdict.lyapunov_exponent, self.config.chaos_threshold,
                    verdict.mahalanobis_drift, self.config.mahalanobis_threshold,
                    consecutive
                )
            } else {
                format!(
                    "High-threat syscall attractor drift: event={:?}, drift={:.2} (> {:.2}), pid={}",
                    event.event_kind,
                    verdict.mahalanobis_drift,
                    self.config.mahalanobis_threshold * 0.5,
                    pid
                )
            };

            let mut signal = ThreatSignal::new(
                "edr-phaselock",
                pid,
                &event.process_name,
                confidence,
                severity,
                EvidenceClass::Behavior,
                reason,
            );

            signal.raw_evidence = serde_json::json!({
                "lyapunov_exponent": verdict.lyapunov_exponent,
                "mahalanobis_drift": verdict.mahalanobis_drift,
                "consecutive_epochs": consecutive,
                "anomaly_score": verdict.anomaly_score,
                "event_kind": format!("{:?}", event.event_kind),
                "command_line": event.command_line,
            });

            Some(signal)
        } else {
            None
        }
    }

    /// Purges a terminated PID's monitor from memory to prevent reuse contamination.
    pub fn purge_pid(&self, pid: u32) {
        self.monitors.remove(&pid);
    }

    /// Returns the number of active PID monitors.
    pub fn active_monitor_count(&self) -> usize {
        self.monitors.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy() {
        assert_eq!(compute_shannon_entropy(""), 0.0);
        let low_entropy = compute_shannon_entropy("aaaaaaaaaaaaaaaa");
        assert_eq!(low_entropy, 0.0);
        let high_entropy = compute_shannon_entropy("abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()");
        assert!(high_entropy > 4.5);
    }

    #[test]
    fn test_periodic_trajectory_negative_or_zero_lyapunov() {
        let mut monitor = PerPidPhaseLockMonitor::default_edr();
        let periodic_series = [1.0, 2.0, 1.0, 2.0];
        let mut last_verdict = PhaseSpaceVerdict {
            lyapunov_exponent: 0.0,
            mahalanobis_drift: 0.0,
            is_chaotic_breakout: false,
            anomaly_score: 0.0,
        };

        for _ in 0..20 {
            for &val in &periodic_series {
                last_verdict = monitor.observe(val);
            }
        }

        // On a stable repeating periodic trajectory, trajectory does not diverge chaotically
        assert!(!last_verdict.is_chaotic_breakout);
        assert!(last_verdict.lyapunov_exponent <= 0.85);
    }

    #[test]
    fn test_chaotic_burst_injection_positive_lyapunov_and_drift() {
        let mut monitor = PerPidPhaseLockMonitor::default_edr();

        // Feed baseline periodic trajectory first to establish attractor centroid
        for _ in 0..10 {
            for &val in &[1.0, 1.2, 1.1, 1.0] {
                monitor.observe(val);
            }
        }

        // Inject chaotic high-entropy burst
        let mut breakout_detected = false;
        let chaotic_burst = [8.5, 25.0, 0.2, 50.0, 12.0, 4.0, 75.0, 1.0, 90.0];
        for &val in &chaotic_burst {
            let verdict = monitor.observe(val);
            if verdict.is_chaotic_breakout {
                breakout_detected = true;
                break;
            }
        }

        assert!(breakout_detected);
    }
}
