//! # Time-Decay Security Event Correlator
//!
//! Aggregates discrete telemetry events into per-process correlation contexts,
//! applying continuous exponential time-decay ($w(\Delta t) = e^{-\Delta t / \tau_{\text{decay}}}$ with $\tau = 300$s)
//! and multi-stage sequence amplification to synthesize high-confidence threat signals.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use chrono::{DateTime, Utc};
use dashmap::DashMap;

use killswitch_types::adjudication::EvidenceClass;
use killswitch_types::telemetry::{SecurityEvent, ThreatSeverity, ThreatSignal};

use crate::attack::{AttackGraphMatcher, AttackStage, ProcessTimelineEvent};

/// Per-process correlation context tracking temporal events, ATT&CK stages, and decayed score.
#[derive(Debug, Clone)]
pub struct ProcessCorrelationContext {
    pub pid: u32,
    pub image_path: String,
    pub instance_id: Option<String>,
    pub stages_observed: HashSet<AttackStage>,
    pub timeline: VecDeque<ProcessTimelineEvent>,
    pub current_score: f32,
    pub last_updated: DateTime<Utc>,
    pub last_alerted: Option<DateTime<Utc>>,
}

impl ProcessCorrelationContext {
    pub fn new(pid: u32, image_path: impl Into<String>, instance_id: Option<String>) -> Self {
        Self {
            pid,
            image_path: image_path.into(),
            instance_id,
            stages_observed: HashSet::new(),
            timeline: VecDeque::with_capacity(32),
            current_score: 0.0,
            last_updated: Utc::now(),
            last_alerted: None,
        }
    }

    /// Applies continuous exponential decay: S(t) = S(t_prev) * exp(-(t - t_prev) / tau).
    pub fn apply_decay(&mut self, now: DateTime<Utc>, tau_decay_secs: f32) {
        let elapsed_secs = (now - self.last_updated).num_milliseconds().max(0) as f32 / 1000.0;
        if elapsed_secs > 0.0 {
            let decay_factor = (-elapsed_secs / tau_decay_secs.max(1.0)).exp();
            self.current_score = (self.current_score * decay_factor).max(0.0);
            self.last_updated = now;
        }
    }
}

/// Continuous time-decay correlator managing concurrent process contexts via DashMap.
#[derive(Clone)]
pub struct EventCorrelator {
    processes: Arc<DashMap<u32, ProcessCorrelationContext>>,
    tau_decay_secs: f32,
    alert_threshold: f32,
    matcher: AttackGraphMatcher,
}

impl Default for EventCorrelator {
    fn default() -> Self {
        Self::new(300.0, 0.75)
    }
}

impl EventCorrelator {
    pub fn new(tau_decay_secs: f32, alert_threshold: f32) -> Self {
        Self {
            processes: Arc::new(DashMap::new()),
            tau_decay_secs,
            alert_threshold,
            matcher: AttackGraphMatcher::new(),
        }
    }

    /// Ingests a security event into the correlator, updates decayed score, and returns
    /// a ThreatSignal if the combined multi-stage confidence crosses the alert threshold.
    pub fn ingest_event(
        &self,
        event: &SecurityEvent,
        stage: AttackStage,
        base_score: f32,
    ) -> Option<ThreatSignal> {
        let now = Utc::now();
        let pid = event.pid;

        let mut entry = self.processes.entry(pid).or_insert_with(|| {
            ProcessCorrelationContext::new(
                pid,
                &event.image_path,
                event.process_identity.as_ref().map(|i| i.instance_id.clone()),
            )
        });

        let ctx = entry.value_mut();

        // 1. Apply continuous exponential decay to existing accumulated score
        ctx.apply_decay(now, self.tau_decay_secs);

        // 2. Accumulate incoming event score
        ctx.current_score = (ctx.current_score + base_score).min(1.0);
        ctx.stages_observed.insert(stage);

        // 3. Append to timeline (bounded to 32 events)
        if ctx.timeline.len() >= 32 {
            ctx.timeline.pop_front();
        }
        ctx.timeline.push_back(ProcessTimelineEvent {
            timestamp: now,
            stage,
            event_kind: event.event_kind,
            details: format!("{}: {}", event.process_name, event.command_line),
            raw_score: base_score,
        });

        // 4. Run multi-stage attack pattern evaluation
        let timeline_slice: Vec<ProcessTimelineEvent> = ctx.timeline.iter().cloned().collect();
        let eval = self.matcher.evaluate_sequence(&timeline_slice);

        // Combine decayed score with multi-stage multiplier
        let composite_confidence = (ctx.current_score * eval.multi_stage_multiplier).clamp(0.0, 1.0);

        // Check if confidence exceeds threshold
        if composite_confidence >= self.alert_threshold {
            // Check debouncing: do not re-alert within 30 seconds unless late-stage
            let should_alert = match ctx.last_alerted {
                Some(last) => {
                    let elapsed = (now - last).num_seconds();
                    elapsed > 30 || stage.is_late_stage()
                }
                None => true,
            };

            if should_alert {
                ctx.last_alerted = Some(now);

                let severity = if composite_confidence >= 0.90 || stage.is_late_stage() {
                    ThreatSeverity::Critical
                } else {
                    ThreatSeverity::High
                };

                let pattern_desc = if !eval.matched_patterns.is_empty() {
                    format!(" Patterns matched: [{}]", eval.matched_patterns.join(", "))
                } else {
                    String::new()
                };

                let mut signal = ThreatSignal::new(
                    "correlator",
                    pid,
                    &event.process_name,
                    composite_confidence,
                    severity,
                    EvidenceClass::Behavior,
                    format!(
                        "Correlated multi-stage attack sequence across {} stages (confidence: {:.2}).{}",
                        eval.stages_count, composite_confidence, pattern_desc
                    ),
                );

                signal.raw_evidence = serde_json::json!({
                    "stages_count": eval.stages_count,
                    "stages": eval.stages_present.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                    "composite_score": composite_confidence,
                    "decayed_base_score": ctx.current_score,
                    "multi_stage_multiplier": eval.multi_stage_multiplier,
                    "matched_patterns": eval.matched_patterns,
                    "timeline_length": ctx.timeline.len(),
                });

                return Some(signal);
            }
        }

        None
    }

    /// Purges a terminated PID's correlation context.
    pub fn purge_pid(&self, pid: u32) {
        self.processes.remove(&pid);
    }

    /// Retrieves current accumulated score for a PID.
    pub fn get_process_score(&self, pid: u32) -> Option<f32> {
        self.processes.get(&pid).map(|p| p.current_score)
    }

    /// Returns the number of currently tracked processes.
    pub fn active_process_count(&self) -> usize {
        self.processes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use killswitch_types::telemetry::TelemetryEventKind;

    #[test]
    fn test_correlator_time_decay() {
        let correlator = EventCorrelator::new(10.0, 0.75); // tau = 10s
        let ev = SecurityEvent::new(
            TelemetryEventKind::ProcessCreate,
            1234,
            "suspicious.exe",
            "C:\\Temp\\suspicious.exe",
            "suspicious.exe --stage1",
        );

        // Ingest initial event
        correlator.ingest_event(&ev, AttackStage::Discovery, 0.50);
        let initial_score = correlator.get_process_score(1234).unwrap();
        assert!((initial_score - 0.50).abs() < 1e-4);

        // Manually simulate elapsed time
        let mut entry = correlator.processes.get_mut(&1234).unwrap();
        let past = Utc::now() - chrono::Duration::seconds(10);
        entry.last_updated = past;
        entry.apply_decay(Utc::now(), 10.0);

        // S(10s) = 0.50 * exp(-10/10) = 0.50 * exp(-1) ~= 0.1839
        assert!(entry.current_score < 0.25);
    }

    #[test]
    fn test_multi_stage_threshold_crossing() {
        let correlator = EventCorrelator::new(300.0, 0.75);
        let ev1 = SecurityEvent::new(
            TelemetryEventKind::FileCreate,
            5555,
            "stealer.exe",
            "stealer.exe",
            "stealer.exe",
        );
        let ev2 = SecurityEvent::new(
            TelemetryEventKind::NetworkConnect,
            5555,
            "stealer.exe",
            "stealer.exe",
            "stealer.exe",
        );

        // Stage 1: Collection
        let sig1 = correlator.ingest_event(&ev1, AttackStage::Collection, 0.40);
        assert!(sig1.is_none()); // 0.40 < 0.75

        // Stage 2: Exfiltration
        let sig2 = correlator.ingest_event(&ev2, AttackStage::Exfiltration, 0.40);
        // Base score = 0.80, stages = 2 -> multiplier = 1.35 -> confidence > 0.75 -> emits ThreatSignal
        assert!(sig2.is_some());
        let signal = sig2.unwrap();
        assert_eq!(signal.target_pid, 5555);
        assert_eq!(signal.severity, ThreatSeverity::Critical);
    }
}
