//! # MITRE ATT&CK 10-Stage Killchain Graph
//!
//! Models the 10 canonical MITRE ATT&CK killchain stages, sequence pattern matching,
//! multi-stage progression tracking, and composite confidence amplification.

use std::collections::HashSet;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use killswitch_types::telemetry::{TelemetryEventKind, ThreatSeverity};

/// The 10 canonical MITRE ATT&CK killchain stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AttackStage {
    InitialAccess = 1,
    Persistence = 2,
    PrivilegeEscalation = 3,
    DefenseEvasion = 4,
    CredentialAccess = 5,
    Discovery = 6,
    LateralMovement = 7,
    Collection = 8,
    Exfiltration = 9,
    Impact = 10,
}

impl AttackStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InitialAccess => "InitialAccess",
            Self::Persistence => "Persistence",
            Self::PrivilegeEscalation => "PrivilegeEscalation",
            Self::DefenseEvasion => "DefenseEvasion",
            Self::CredentialAccess => "CredentialAccess",
            Self::Discovery => "Discovery",
            Self::LateralMovement => "LateralMovement",
            Self::Collection => "Collection",
            Self::Exfiltration => "Exfiltration",
            Self::Impact => "Impact",
        }
    }

    pub fn stage_order(&self) -> usize {
        *self as usize
    }

    /// Indicates whether this stage represents late-stage execution or exfiltration.
    pub fn is_late_stage(&self) -> bool {
        matches!(self, Self::Collection | Self::Exfiltration | Self::Impact)
    }

    /// Base severity weight for scoring killchain progression.
    pub fn base_severity_weight(&self) -> f32 {
        match self {
            Self::InitialAccess => 1.0,
            Self::Persistence => 1.2,
            Self::PrivilegeEscalation => 1.5,
            Self::DefenseEvasion => 1.4,
            Self::CredentialAccess => 1.8,
            Self::Discovery => 0.8,
            Self::LateralMovement => 1.6,
            Self::Collection => 1.3,
            Self::Exfiltration => 2.0,
            Self::Impact => 2.2,
        }
    }
}

/// An individual timeline event mapped to an ATT&CK stage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessTimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub stage: AttackStage,
    pub event_kind: TelemetryEventKind,
    pub details: String,
    pub raw_score: f32,
}

/// Specific attack pattern template.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttackPattern {
    pub pattern_id: String,
    pub name: String,
    pub stages_required: Vec<AttackStage>,
    pub min_confidence: f32,
    pub severity: ThreatSeverity,
    pub description: String,
}

/// Sequence matching result for a process attack trajectory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttackSequenceEvaluation {
    pub stages_present: Vec<AttackStage>,
    pub stages_count: usize,
    pub has_killchain_progression: bool,
    pub multi_stage_multiplier: f32,
    pub composite_score: f32,
    pub matched_patterns: Vec<String>,
}

/// Evaluator maintaining standard MITRE ATT&CK patterns and scoring killchain transitions.
#[derive(Clone)]
pub struct AttackGraphMatcher {
    patterns: Vec<AttackPattern>,
}

impl Default for AttackGraphMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl AttackGraphMatcher {
    pub fn new() -> Self {
        let patterns = vec![
            // 1. Ransomware Staging to Impact
            AttackPattern {
                pattern_id: "AP-RANSOM-01".to_string(),
                name: "Ransomware Destruction Sequence".to_string(),
                stages_required: vec![
                    AttackStage::DefenseEvasion,
                    AttackStage::Discovery,
                    AttackStage::Impact,
                ],
                min_confidence: 0.85,
                severity: ThreatSeverity::Critical,
                description: "Process evades defense, discovers volume assets, and triggers mass destruction or shadow copy deletion".to_string(),
            },
            // 2. Data Exfiltration Pipeline
            AttackPattern {
                pattern_id: "AP-EXFIL-01".to_string(),
                name: "Multi-Hop Data Exfiltration Pipeline".to_string(),
                stages_required: vec![
                    AttackStage::Collection,
                    AttackStage::Exfiltration,
                ],
                min_confidence: 0.90,
                severity: ThreatSeverity::Critical,
                description: "Process stages sensitive or crown-jewel assets and initiates egress to external endpoint".to_string(),
            },
            // 3. Credential Harvesting & Lateral Spread
            AttackPattern {
                pattern_id: "AP-LATERAL-01".to_string(),
                name: "Credential Harvesting and Lateral Movement".to_string(),
                stages_required: vec![
                    AttackStage::CredentialAccess,
                    AttackStage::LateralMovement,
                ],
                min_confidence: 0.80,
                severity: ThreatSeverity::High,
                description: "Process extracts credentials and attempts lateral named pipe or remote thread propagation".to_string(),
            },
            // 4. Persistence with Privilege Escalation
            AttackPattern {
                pattern_id: "AP-ESC-01".to_string(),
                name: "Privilege Escalation and Persistence".to_string(),
                stages_required: vec![
                    AttackStage::PrivilegeEscalation,
                    AttackStage::Persistence,
                ],
                min_confidence: 0.80,
                severity: ThreatSeverity::High,
                description: "Process escalates token privileges and establishes persistence in system registry or services".to_string(),
            },
        ];

        Self { patterns }
    }

    /// Evaluates a collection of observed stages and raw scores for a process.
    pub fn evaluate_sequence(&self, timeline: &[ProcessTimelineEvent]) -> AttackSequenceEvaluation {
        if timeline.is_empty() {
            return AttackSequenceEvaluation {
                stages_present: Vec::new(),
                stages_count: 0,
                has_killchain_progression: false,
                multi_stage_multiplier: 1.0,
                composite_score: 0.0,
                matched_patterns: Vec::new(),
            };
        }

        let mut unique_stages: HashSet<AttackStage> = HashSet::new();
        let mut sum_scores = 0.0f32;

        for event in timeline {
            unique_stages.insert(event.stage);
            sum_scores += event.raw_score * event.stage.base_severity_weight();
        }

        let mut sorted_stages: Vec<AttackStage> = unique_stages.into_iter().collect();
        sorted_stages.sort_by_key(|s| s.stage_order());

        let k = sorted_stages.len();
        // Multi-stage boost formula: 1.0 + 0.35 * (k - 1)
        let multi_stage_multiplier = if k > 1 {
            1.0 + 0.35 * ((k - 1) as f32)
        } else {
            1.0
        };

        // Check if there is strict forward temporal progression in the timeline
        let mut forward_progression_count = 0;
        for window in timeline.windows(2) {
            if window[1].stage.stage_order() >= window[0].stage.stage_order() {
                forward_progression_count += 1;
            }
        }
        let has_killchain_progression = forward_progression_count > 0 && k >= 2;

        // Check matched pattern templates
        let mut matched_patterns = Vec::new();
        for pat in &self.patterns {
            let matches_all = pat
                .stages_required
                .iter()
                .all(|req| sorted_stages.contains(req));
            if matches_all {
                matched_patterns.push(pat.name.clone());
            }
        }

        let base_avg = sum_scores / (timeline.len() as f32).max(1.0);
        let composite_score = (base_avg * multi_stage_multiplier).clamp(0.0, 1.0);

        AttackSequenceEvaluation {
            stages_present: sorted_stages,
            stages_count: k,
            has_killchain_progression,
            multi_stage_multiplier,
            composite_score,
            matched_patterns,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_stage_amplification() {
        let matcher = AttackGraphMatcher::new();

        let timeline = vec![
            ProcessTimelineEvent {
                timestamp: Utc::now(),
                stage: AttackStage::Collection,
                event_kind: TelemetryEventKind::FileCreate,
                details: "Staged zip file".to_string(),
                raw_score: 0.6,
            },
            ProcessTimelineEvent {
                timestamp: Utc::now(),
                stage: AttackStage::Exfiltration,
                event_kind: TelemetryEventKind::NetworkConnect,
                details: "Outbound socket to external drop".to_string(),
                raw_score: 0.8,
            },
        ];

        let eval = matcher.evaluate_sequence(&timeline);
        assert_eq!(eval.stages_count, 2);
        assert!(eval.multi_stage_multiplier > 1.3);
        assert!(eval.matched_patterns.contains(&"Multi-Hop Data Exfiltration Pipeline".to_string()));
    }
}
