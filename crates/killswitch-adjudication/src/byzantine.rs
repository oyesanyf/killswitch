//! Byzantine KillSwitch Fraud Proof Builder and Peer Proposal Veto.
//!
//! Protects against malicious or compromised peer nodes weaponizing the KillSwitch
//! against protected infrastructure. Emits cryptographically sealed fraud proofs.

use killswitch_core::killchain::is_critical_system_pid;
use killswitch_types::adjudication::{ByzantineKillSwitchFraudProof, VetoReason};

/// Slashed stake amount for peers broadcasting fraudulent kill-switch proposals.
pub const PEER_SLASHED_STAKE: f64 = 100.0;

/// Validates an incoming peer kill-switch candidate.
///
/// If targeting a protected binary hash, critical system PID, protected parent lineage,
/// or poisoned YARA rule, rejects the candidate and emits a sealed `ByzantineKillSwitchFraudProof`.
pub fn veto_peer_kill_switch_candidate(
    accused_peer_id: Option<&str>,
    target_pid: Option<u32>,
    proc_name: Option<&str>,
    candidate_blake3: Option<&str>,
    candidate_yara: Option<&str>,
    _reason: Option<&str>,
) -> Option<(VetoReason, ByzantineKillSwitchFraudProof)> {
    let peer_id = accused_peer_id.unwrap_or("unknown-peer");

    // 1. Target Binary Hash Check
    if let Some(h) = candidate_blake3 {
        let h_trim = h.trim();
        if !h_trim.is_empty() && crate::inventory::is_protected_local_binary_hash(h_trim) {
            let fraud_reason = format!(
                "PROTECTED_LOCAL_BINARY_HASH_VETO: target hash {} matches protected local OS/developer binary (process label was {:?})",
                h_trim, proc_name
            );
            let proof = build_kill_switch_fraud_proof(
                peer_id,
                proc_name.unwrap_or(""),
                h_trim,
                &fraud_reason,
            );
            return Some((VetoReason::ProtectedBinaryHash, proof));
        }
    }

    // 2. Critical System PID & Lineage Check
    if let Some(pid) = target_pid {
        let lineage = crate::immunity::inspect_process_lineage(pid, proc_name);
        if let Some(veto_reason) = lineage.to_veto_reason() {
            let fraud_reason = format!(
                "{}: target PID {} with process name {:?} is protected by lineage immunity",
                veto_reason.as_str(),
                pid,
                proc_name
            );
            let proof = build_kill_switch_fraud_proof(
                peer_id,
                proc_name.unwrap_or(""),
                candidate_blake3.unwrap_or(""),
                &fraud_reason,
            );
            return Some((veto_reason, proof));
        }
    } else if let Some(p) = proc_name {
        if is_critical_system_pid(0, p) {
            let fraud_reason = format!(
                "CRITICAL_SYSTEM_PID_VETO: process name '{}' matches critical system catalog",
                p
            );
            let proof = build_kill_switch_fraud_proof(
                peer_id,
                p,
                candidate_blake3.unwrap_or(""),
                &fraud_reason,
            );
            return Some((VetoReason::CriticalSystemPid, proof));
        }
    }

    // 3. Poisoned YARA Rule Veto
    if let Some(yara_src) = candidate_yara {
        let yara_lower = yara_src.to_ascii_lowercase();
        for token in yara_lower.split(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-' && c != '_') {
            if (token.ends_with(".exe") || token.ends_with(".dll") || token.ends_with(".so"))
                && is_critical_system_pid(0, token)
            {
                let fraud_reason = format!(
                    "POISONED_YARA_TARGET_VETO: YARA rule targets protected OS/developer binary {}",
                    token
                );
                let proof = build_kill_switch_fraud_proof(
                    peer_id,
                    token,
                    candidate_blake3.unwrap_or(""),
                    &fraud_reason,
                );
                return Some((VetoReason::PoisonedYaraRuleTarget, proof));
            }
        }
    }

    None
}

/// Constructs a non-repudiable Byzantine Kill-Switch Fraud Proof.
pub fn build_kill_switch_fraud_proof(
    accused_peer_id: &str,
    target_proc: &str,
    target_binary_hash: &str,
    fraud_reason: &str,
) -> ByzantineKillSwitchFraudProof {
    let local_peer_id = format!("killswitch-node-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    ByzantineKillSwitchFraudProof::new(
        local_peer_id,
        accused_peer_id,
        target_binary_hash,
        target_proc,
        fraud_reason,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_veto_peer_targeting_critical_pid() {
        let result = veto_peer_kill_switch_candidate(
            Some("rogue-node-99"),
            Some(4),
            Some("system"),
            None,
            None,
            Some("Anomalous activity"),
        );

        assert!(result.is_some());
        let (reason, proof) = result.unwrap();
        assert_eq!(reason, VetoReason::CriticalSystemPid);
        assert!(proof.verify_seal());
        assert_eq!(proof.accused_peer_id, "rogue-node-99");
    }

    #[test]
    fn test_veto_peer_targeting_protected_hash() {
        let test_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        crate::inventory::register_protected_binary_hash(test_hash);

        let result = veto_peer_kill_switch_candidate(
            Some("rogue-node-77"),
            None,
            Some("custom-tool.exe"),
            Some(test_hash),
            None,
            None,
        );

        assert!(result.is_some());
        let (reason, proof) = result.unwrap();
        assert_eq!(reason, VetoReason::ProtectedBinaryHash);
        assert!(proof.verify_seal());
    }

    #[test]
    fn test_veto_peer_poisoned_yara() {
        let yara = r#"
            rule TargetSvchost {
                strings:
                    $a = "svchost.exe"
                condition:
                    $a
            }
        "#;

        let result = veto_peer_kill_switch_candidate(
            Some("rogue-node-42"),
            None,
            None,
            None,
            Some(yara),
            None,
        );

        assert!(result.is_some());
        let (reason, proof) = result.unwrap();
        assert_eq!(reason, VetoReason::PoisonedYaraRuleTarget);
        assert!(proof.verify_seal());
    }
}
