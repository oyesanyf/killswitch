use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::adjudication::EvidenceClass;
use crate::identity::ProcessInstanceIdentity;

/// Unique event identifier for system and EDR telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TelemetryEventKind {
    ProcessCreate = 1,
    FileCreate = 11,
    NetworkConnect = 3,
    CreateRemoteThread = 8,
    ProcessAccess = 10,
    RegistryValueModify = 13,
    DnsQuery = 22,
    DriverLoad = 6,
    ImageLoadDll = 7,
    ThreadInjectVirtualAlloc = 14,
    FileRenameEncrypt = 15,
    VolumeShadowCopyDelete = 16,
    CanaryTrip = 100,
    HoneytokenAccess = 101,
    WatchdogAlert = 102,
    PhaseLockDrift = 103,
}

/// Generic host telemetry event ingested into the EDR and graph pipeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_id: String,
    pub timestamp: String,
    pub event_kind: TelemetryEventKind,
    pub pid: u32,
    pub process_identity: Option<ProcessInstanceIdentity>,
    pub process_name: String,
    pub image_path: String,
    pub command_line: String,
    pub parent_pid: Option<u32>,
    pub target_path: Option<String>,
    pub destination_ip: Option<String>,
    pub destination_port: Option<u16>,
    pub raw_payload_bytes: Option<Vec<u8>>,
    pub attributes: HashMap<String, String>,
}

impl SecurityEvent {
    pub fn new(
        event_kind: TelemetryEventKind,
        pid: u32,
        process_name: impl Into<String>,
        image_path: impl Into<String>,
        command_line: impl Into<String>,
    ) -> Self {
        Self {
            event_id: format!("event-{}", uuid::Uuid::new_v4()),
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_kind,
            pid,
            process_identity: None,
            process_name: process_name.into(),
            image_path: image_path.into(),
            command_line: command_line.into(),
            parent_pid: None,
            target_path: None,
            destination_ip: None,
            destination_port: None,
            raw_payload_bytes: None,
            attributes: HashMap::new(),
        }
    }
}

/// Severity classification for security threat signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatSeverity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Threat signal synthesized from correlating one or more telemetry events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatSignal {
    pub signal_id: String,
    pub timestamp: String,
    pub source_detector: String, // e.g. "edr-phaselock", "canary", "correlator"
    pub target_pid: u32,
    pub target_process_name: String,
    pub confidence: f32, // 0.0 - 1.0
    pub severity: ThreatSeverity,
    pub indicator_class: EvidenceClass,
    pub blast_radius_estimate: f32,
    pub description: String,
    pub raw_evidence: serde_json::Value,
}

impl ThreatSignal {
    pub fn new(
        source_detector: impl Into<String>,
        target_pid: u32,
        target_process_name: impl Into<String>,
        confidence: f32,
        severity: ThreatSeverity,
        indicator_class: EvidenceClass,
        description: impl Into<String>,
    ) -> Self {
        Self {
            signal_id: format!("sig-{}", uuid::Uuid::new_v4()),
            timestamp: chrono::Utc::now().to_rfc3339(),
            source_detector: source_detector.into(),
            target_pid,
            target_process_name: target_process_name.into(),
            confidence: confidence.clamp(0.0, 1.0),
            severity,
            indicator_class,
            blast_radius_estimate: 0.5,
            description: description.into(),
            raw_evidence: serde_json::Value::Null,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_event_construction() {
        let ev = SecurityEvent::new(
            TelemetryEventKind::ProcessCreate,
            1024,
            "cmd.exe",
            "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe /c whoami",
        );

        assert_eq!(ev.pid, 1024);
        assert_eq!(ev.event_kind, TelemetryEventKind::ProcessCreate);
        assert!(ev.event_id.starts_with("event-"));
    }

    #[test]
    fn test_threat_signal_clamping() {
        let sig = ThreatSignal::new(
            "edr-phaselock",
            5000,
            "suspicious.exe",
            1.75, // Clamped to 1.0
            ThreatSeverity::Critical,
            EvidenceClass::Behavior,
            "Lyapunov drift anomaly",
        );

        assert_eq!(sig.confidence, 1.0);
        assert_eq!(sig.severity, ThreatSeverity::Critical);
    }
}
