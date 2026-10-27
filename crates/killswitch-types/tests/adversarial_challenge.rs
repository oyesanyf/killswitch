use killswitch_types::{
    adjudication::{
        calculate_consensus, corroboration_multiplier, AuthenticodeChainStatus,
        AuthenticodeStatus, BinaryTrustVerdict, ByzantineKillSwitchFraudProof,
        EvidenceClass, VoteAction, VoteResult,
    },
    identity::ProcessInstanceIdentity,
    status::constant_time_eq,
};

/// ---------------------------------------------------------------------------
/// Challenge Vector 1: ByzantineKillSwitchFraudProof Adversarial Tampering
/// ---------------------------------------------------------------------------

#[test]
fn test_adversarial_fraud_proof_exhaustive_seal_bitflips() {
    let proof = ByzantineKillSwitchFraudProof::new(
        "validator-node-alpha-001",
        "rogue-subagent-beta-666",
        "4b42b102b4d4b1a457c0e5a8f4c2c77f02d0cf3b1b6cf7f8e3f94a5e01b34a12",
        "explorer.exe",
        "Host shell process falsely marked for immediate termination",
    );

    // Baseline: virgin seal must be cryptographically valid
    assert!(proof.verify_seal(), "Virgin fraud proof seal must verify");

    let seal_bytes = proof.proof_seal.as_bytes();
    assert_eq!(seal_bytes.len(), 64, "BLAKE3 hex seal must be 64 characters");

    // Exhaustively flip every single bit in every hex character of the seal
    let mut total_bitflips_tested = 0;
    for byte_idx in 0..seal_bytes.len() {
        for bit in 0..8 {
            let mut tampered_bytes = seal_bytes.to_vec();
            tampered_bytes[byte_idx] ^= 1 << bit;

            let tampered_seal = String::from_utf8_lossy(&tampered_bytes).to_string();
            let mut tampered_proof = proof.clone();
            tampered_proof.proof_seal = tampered_seal;

            assert!(
                !tampered_proof.verify_seal(),
                "Single-bit flip at byte {} bit {} in proof_seal MUST cause verify_seal() to return false",
                byte_idx,
                bit
            );
            total_bitflips_tested += 1;
        }
    }

    assert_eq!(total_bitflips_tested, 64 * 8); // 512 single-bit mutations tested
}

#[test]
fn test_adversarial_fraud_proof_field_level_mutations() {
    let baseline = ByzantineKillSwitchFraudProof::new(
        "validator-node-alpha-001",
        "rogue-subagent-beta-666",
        "4b42b102b4d4b1a457c0e5a8f4c2c77f02d0cf3b1b6cf7f8e3f94a5e01b34a12",
        "svchost.exe",
        "Critical Windows Service Host targeted by rogue actor",
    );

    assert!(baseline.verify_seal());

    // 1. Mutate peer_id
    {
        let mut p = baseline.clone();
        p.peer_id = "validator-node-alpha-002".to_string();
        assert!(!p.verify_seal());
        p.peer_id.clear();
        assert!(!p.verify_seal());
        p.peer_id = "validator-node-alpha-001\0".to_string();
        assert!(!p.verify_seal());
    }

    // 2. Mutate accused_peer_id
    {
        let mut p = baseline.clone();
        p.accused_peer_id = "rogue-subagent-beta-667".to_string();
        assert!(!p.verify_seal());
        p.accused_peer_id.clear();
        assert!(!p.verify_seal());
    }

    // 3. Mutate target_binary_hash
    {
        let mut p = baseline.clone();
        p.target_binary_hash = "4b42b102b4d4b1a457c0e5a8f4c2c77f02d0cf3b1b6cf7f8e3f94a5e01b34a13".to_string();
        assert!(!p.verify_seal());
        p.target_binary_hash = "4B42B102B4D4B1A457C0E5A8F4C2C77F02D0CF3B1B6CF7F8E3F94A5E01B34A12".to_string();
        assert!(!p.verify_seal(), "Case variation must invalidate hash");
    }

    // 4. Mutate proc_name
    {
        let mut p = baseline.clone();
        p.proc_name = "svchost.EXE".to_string();
        assert!(!p.verify_seal());
        p.proc_name = "svchost.exe ".to_string();
        assert!(!p.verify_seal());
        p.proc_name = "explorer.exe".to_string();
        assert!(!p.verify_seal());
    }

    // 5. Mutate fraud_reason
    {
        let mut p = baseline.clone();
        p.fraud_reason = format!("{} ", p.fraud_reason);
        assert!(!p.verify_seal());
    }

    // 6. Mutate timestamp
    {
        let mut p = baseline.clone();
        p.timestamp = "2026-10-26T00:00:00Z".to_string();
        assert!(!p.verify_seal());
    }

    // 7. Empty or truncated seal
    {
        let mut p = baseline.clone();
        p.proof_seal.clear();
        assert!(!p.verify_seal());
        p.proof_seal = baseline.proof_seal[..32].to_string();
        assert!(!p.verify_seal());
        p.proof_seal = format!("{}aa", baseline.proof_seal);
        assert!(!p.verify_seal());
    }
}

#[test]
fn test_adversarial_keyed_fraud_proof_key_and_seal_perturbations() {
    let key = [0x77u8; 32];
    let mut proof = ByzantineKillSwitchFraudProof::new(
        "validator-01",
        "rogue-02",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "code.exe",
        "IDE binary protected by dev toolchain whitelist",
    );

    // Apply keyed seal
    let keyed_seal = ByzantineKillSwitchFraudProof::compute_keyed_seal(
        &key,
        &proof.peer_id,
        &proof.accused_peer_id,
        &proof.target_binary_hash,
        &proof.proc_name,
        &proof.fraud_reason,
        &proof.timestamp,
    );
    proof.proof_seal = keyed_seal;

    assert!(proof.verify_keyed_seal(&key));

    // Exhaustive single-bit flips across the 256-bit key
    for byte_idx in 0..32 {
        for bit in 0..8 {
            let mut corrupted_key = key;
            corrupted_key[byte_idx] ^= 1 << bit;
            assert!(
                !proof.verify_keyed_seal(&corrupted_key),
                "Key bit flip at byte {} bit {} must fail verification",
                byte_idx,
                bit
            );
        }
    }
}

/// ---------------------------------------------------------------------------
/// Challenge Vector 2: Consensus Scoring & Strict Single-Voter Penalty
/// ---------------------------------------------------------------------------

#[test]
fn test_adversarial_single_voter_penalty_exact_math_and_threshold() {
    // A single voter presenting maximum possible confidence (0.99)
    let lone_voter = VoteResult::new(
        Some(1234),
        VoteAction::Isolate,
        0.99,
        EvidenceClass::LiveNetwork,
        "Command and Control beaconing pattern detected",
        "SoleNetworkVoter",
    );

    let (score, class_count) = calculate_consensus(&[lone_voter]);

    assert_eq!(class_count, 1, "Must report exactly 1 evidence class");

    // Theoretical exact calculation:
    // mass = 1.0 * 0.95 = 0.95
    // support = 0.99 * 0.95 = 0.9405
    // base_score = 0.9405 / 0.95 = 0.99
    // corroboration multiplier for 1 class = 0.52
    // final_confidence = 0.99 * 0.52 = 0.5148
    let expected = 0.99f32 * 0.52f32; // 0.5148
    let diff = (score - expected).abs();
    assert!(
        diff < 1e-5,
        "Consensus score for lone voter must match 0.5148, got: {}, expected: {}",
        score,
        expected
    );

    // Invariant: The killswitch requires >= 0.94 for auto-isolation, and >= 0.82 for manual confirmation.
    // A single voter must NEVER reach either threshold under any circumstances!
    assert!(score < 0.55);
    assert!(score < 0.82, "Lone voter must NEVER reach manual confirmation threshold (0.82)");
    assert!(score < 0.94, "Lone voter must NEVER trigger autonomous isolation threshold (0.94)");
}

#[test]
fn test_adversarial_same_class_multi_voter_sybil_attack() {
    // Attack scenario: Rogue or duplicate voters all in the SAME evidence class (LiveNetwork)
    // flooding 10 votes with 1.0 confidence to spoof consensus.
    let mut sybil_votes = Vec::new();
    for i in 0..10 {
        sybil_votes.push(VoteResult::new(
            Some(9999),
            VoteAction::Isolate,
            1.0,
            EvidenceClass::LiveNetwork,
            format!("Sybil network probe {}", i),
            format!("NetworkDetector_{}", i),
        ));
    }

    let (score, class_count) = calculate_consensus(&sybil_votes);

    assert_eq!(class_count, 1, "Even 10 voters in LiveNetwork must count as only 1 distinct class");

    // Even with 10 x 1.0 votes, multiplier is 0.52 -> max score is 0.52
    let expected = 1.0f32 * 0.52f32;
    let diff = (score - expected).abs();
    assert!(
        diff < 1e-5,
        "Sybil attack with 10 same-class voters must remain penalized at 0.52, got: {}",
        score
    );
    assert!(score < 0.82);
    assert!(score < 0.94);
}

#[test]
fn test_adversarial_corroboration_multiplier_step_function() {
    assert_eq!(corroboration_multiplier(0), 0.0);
    assert_eq!(corroboration_multiplier(1), 0.52);
    assert_eq!(corroboration_multiplier(2), 0.82);
    assert_eq!(corroboration_multiplier(3), 1.00);
    assert_eq!(corroboration_multiplier(4), 1.00);
    assert_eq!(corroboration_multiplier(100), 1.00);
}

#[test]
fn test_adversarial_two_classes_cannot_trigger_auto_isolate() {
    // Two distinct classes at 1.0 confidence -> 1.0 * 0.82 = 0.82
    let v1 = VoteResult::new(
        Some(5555),
        VoteAction::Isolate,
        1.0,
        EvidenceClass::LiveNetwork,
        "C2 exfil",
        "NetVoter",
    );
    let v2 = VoteResult::new(
        Some(5555),
        VoteAction::Isolate,
        1.0,
        EvidenceClass::Behavior,
        "Volume shadow copy deletion",
        "BehaviorVoter",
    );

    let (score, count) = calculate_consensus(&[v1, v2]);
    assert_eq!(count, 2);
    let expected = 0.82f32;
    assert!((score - expected).abs() < 1e-4);
    // 0.82 can trigger AwaitingManualConfirmation (>= 0.82), but NOT autonomous Isolate (>= 0.94)
    assert!(score < 0.94, "Two evidence classes must never breach auto-isolation threshold (0.94)");
}

#[test]
fn test_adversarial_veto_vote_hard_override() {
    // 5 high-confidence isolate votes across 5 orthogonal classes
    let mut votes = vec![
        VoteResult::new(Some(4), VoteAction::Isolate, 1.0, EvidenceClass::LiveNetwork, "raw socket", "V1"),
        VoteResult::new(Some(4), VoteAction::Isolate, 1.0, EvidenceClass::Behavior, "code injection", "V2"),
        VoteResult::new(Some(4), VoteAction::Isolate, 1.0, EvidenceClass::Memory, "reflective dll", "V3"),
        VoteResult::new(Some(4), VoteAction::Isolate, 1.0, EvidenceClass::StaticArtifact, "yara match", "V4"),
        VoteResult::new(Some(4), VoteAction::Isolate, 1.0, EvidenceClass::ThreatIntel, "cve match", "V5"),
    ];

    // Single Veto vote injected (negative weight)
    let veto = VoteResult::new_veto(
        Some(4),
        "PID 4 is the System Kernel process and is immutable",
        "SystemAnchorVoter",
        EvidenceClass::StaticArtifact,
    );
    votes.push(veto);

    let (score, count) = calculate_consensus(&votes);
    assert_eq!(score, 0.0, "Veto vote must collapse composite score to 0.0 immediately");
    assert_eq!(count, 0, "Vetoed consensus must return 0 classes");
}

/// ---------------------------------------------------------------------------
/// Challenge Vector 3: BinaryTrustVerdict Invariant Verification
/// ---------------------------------------------------------------------------

#[test]
fn test_adversarial_binary_trust_verdict_strict_classification() {
    // 1. All Trusted variants
    let trusted_variants = [
        BinaryTrustVerdict::TrustedAuthenticode {
            signer_subject: Some("Microsoft Corporation".to_string()),
            thumbprint: Some("1234567890abcdef".to_string()),
        },
        BinaryTrustVerdict::TrustedCatalog {
            catalog_name: Some("delta.cat".to_string()),
        },
        BinaryTrustVerdict::TrustedProtectedHash {
            blake3_hash: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string(),
        },
        BinaryTrustVerdict::TrustedSystemPackage {
            package_name: Some("systemd".to_string()),
            digest: Some("fedcba9876543210".to_string()),
        },
    ];

    for (idx, tv) in trusted_variants.iter().enumerate() {
        assert!(
            tv.is_trusted(),
            "Trusted variant {} must return is_trusted() == true",
            idx
        );
        assert!(
            !tv.is_untrusted(),
            "Trusted variant {} must return is_untrusted() == false",
            idx
        );
        assert!(
            tv.category().starts_with("trusted_"),
            "Category must start with trusted_"
        );
    }

    // 2. All Untrusted variants
    let untrusted_variants = [
        BinaryTrustVerdict::UntrustedSignature {
            status: AuthenticodeStatus {
                subject: Some("Malicious Rogue".to_string()),
                issuer: Some("Self Signed".to_string()),
                serial: None,
                thumbprint: None,
                chain_status: AuthenticodeChainStatus::UntrustedRoot,
            },
            reason: "Untrusted root CA".to_string(),
        },
        BinaryTrustVerdict::UntrustedSignature {
            status: AuthenticodeStatus {
                subject: None,
                issuer: None,
                serial: None,
                thumbprint: None,
                chain_status: AuthenticodeChainStatus::TamperedBadDigest,
            },
            reason: "Digest tampered".to_string(),
        },
        BinaryTrustVerdict::UntrustedSignature {
            status: AuthenticodeStatus::not_signed(),
            reason: "Not signed".to_string(),
        },
        BinaryTrustVerdict::UntrustedWritableLocation {
            path: "C:\\Windows\\Temp\\dropper.exe".to_string(),
            reason: "World writable temp folder".to_string(),
        },
        BinaryTrustVerdict::UntrustedUnsigned {
            blake3_hash: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        },
        BinaryTrustVerdict::UntrustedIoError {
            error: "Access is denied (os error 5)".to_string(),
        },
    ];

    for (idx, uv) in untrusted_variants.iter().enumerate() {
        assert!(
            !uv.is_trusted(),
            "Untrusted variant {} MUST NOT report is_trusted() == true",
            idx
        );
        assert!(
            uv.is_untrusted(),
            "Untrusted variant {} MUST report is_untrusted() == true",
            idx
        );
        assert!(
            uv.category().starts_with("untrusted_"),
            "Category must start with untrusted_"
        );
    }
}

#[test]
fn test_adversarial_binary_trust_verdict_serde_roundtrip() {
    let variants = vec![
        BinaryTrustVerdict::TrustedAuthenticode {
            signer_subject: Some("Rust Project".to_string()),
            thumbprint: Some("thumb123".to_string()),
        },
        BinaryTrustVerdict::TrustedCatalog {
            catalog_name: Some("ntoskrnl.cat".to_string()),
        },
        BinaryTrustVerdict::TrustedProtectedHash {
            blake3_hash: "abc".to_string(),
        },
        BinaryTrustVerdict::TrustedSystemPackage {
            package_name: Some("glibc".to_string()),
            digest: Some("hash".to_string()),
        },
        BinaryTrustVerdict::UntrustedWritableLocation {
            path: "/tmp/evil".to_string(),
            reason: "tmpfs".to_string(),
        },
        BinaryTrustVerdict::UntrustedUnsigned {
            blake3_hash: "bad".to_string(),
        },
        BinaryTrustVerdict::UntrustedIoError {
            error: "not found".to_string(),
        },
    ];

    for v in variants {
        let json = serde_json::to_string(&v).expect("serialization failed");
        let deserialized: BinaryTrustVerdict = serde_json::from_str(&json).expect("deserialization failed");
        assert_eq!(v, deserialized);
        assert_eq!(v.is_trusted(), deserialized.is_trusted());
    }
}

/// ---------------------------------------------------------------------------
/// Challenge Vector 4: ProcessInstanceIdentity 100ns & Parent ID Entropy
/// ---------------------------------------------------------------------------

#[test]
fn test_adversarial_process_instance_100ns_avalanche_effect() {
    let base_start_time: u64 = 133500000000000000; // Windows 100ns timestamp
    let pid: u32 = 4096;
    let digest = "5d41402abc4b2a76b9719d911017c5925d41402abc4b2a76b9719d911017c592";
    let session = "Session-1";

    let id_t0 = ProcessInstanceIdentity::new(
        pid,
        base_start_time,
        digest,
        Some("parent-instance-uuid-root".to_string()),
        Some("job-container-01".to_string()),
        session,
    );

    // Delta of exactly 1 unit (100 nanoseconds)
    let id_t1 = ProcessInstanceIdentity::new(
        pid,
        base_start_time + 1,
        digest,
        Some("parent-instance-uuid-root".to_string()),
        Some("job-container-01".to_string()),
        session,
    );

    assert_ne!(
        id_t0.instance_id, id_t1.instance_id,
        "100ns timestamp change MUST yield a completely distinct BLAKE3 UUID"
    );

    // Verify cryptographic avalanche: compare raw bytes and compute Hamming distance
    let bytes_t0 = hex::decode(&id_t0.instance_id).expect("valid hex");
    let bytes_t1 = hex::decode(&id_t1.instance_id).expect("valid hex");
    assert_eq!(bytes_t0.len(), 32);
    assert_eq!(bytes_t1.len(), 32);

    let mut bit_flips = 0;
    for i in 0..32 {
        bit_flips += (bytes_t0[i] ^ bytes_t1[i]).count_ones();
    }

    // A good cryptographic hash (BLAKE3) exhibits ~50% bit flips (128 out of 256).
    // It should be strictly between 80 and 176 bits flipped (>= 30% and <= 70%).
    assert!(
        (80..=180).contains(&bit_flips),
        "BLAKE3 avalanche effect failed: expected ~128 bit flips, got {}",
        bit_flips
    );
}

#[test]
fn test_adversarial_process_instance_parent_id_sensitivity() {
    let pid: u32 = 8192;
    let start_time: u64 = 133500000000000000;
    let digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let session = "Session-2";

    // 1. None parent
    let id_no_parent = ProcessInstanceIdentity::new(pid, start_time, digest, None, None, session);

    // 2. Parent A
    let id_parent_a = ProcessInstanceIdentity::new(
        pid,
        start_time,
        digest,
        Some("00000000-0000-0000-0000-000000000001".to_string()),
        None,
        session,
    );

    // 3. Parent B (1 char difference)
    let id_parent_b = ProcessInstanceIdentity::new(
        pid,
        start_time,
        digest,
        Some("00000000-0000-0000-0000-000000000002".to_string()),
        None,
        session,
    );

    assert_ne!(id_no_parent.instance_id, id_parent_a.instance_id);
    assert_ne!(id_parent_a.instance_id, id_parent_b.instance_id);
    assert_ne!(id_no_parent.instance_id, id_parent_b.instance_id);

    // Both must verify internal integrity
    assert!(id_no_parent.verify_integrity());
    assert!(id_parent_a.verify_integrity());
    assert!(id_parent_b.verify_integrity());
}

#[test]
fn test_adversarial_process_instance_all_fields_integrity() {
    let mut id = ProcessInstanceIdentity::new(
        1000,
        50000000,
        "digest0001",
        Some("parent01".to_string()),
        Some("job01".to_string()),
        "sess01",
    );

    assert!(id.verify_integrity());

    // 1. Tamper PID
    id.pid += 1;
    assert!(!id.verify_integrity());
    id.pid -= 1;
    assert!(id.verify_integrity());

    // 2. Tamper start time
    id.start_time_100ns += 1;
    assert!(!id.verify_integrity());
    id.start_time_100ns -= 1;
    assert!(id.verify_integrity());

    // 3. Tamper digest
    id.image_digest_blake3 = "digest0002".to_string();
    assert!(!id.verify_integrity());
    id.image_digest_blake3 = "digest0001".to_string();
    assert!(id.verify_integrity());

    // 4. Tamper parent
    id.parent_instance_id = Some("parent02".to_string());
    assert!(!id.verify_integrity());
    id.parent_instance_id = None;
    assert!(!id.verify_integrity());
    id.parent_instance_id = Some("parent01".to_string());
    assert!(id.verify_integrity());

    // 5. Tamper job
    id.job_object_id = None;
    assert!(!id.verify_integrity());
    id.job_object_id = Some("job01".to_string());
    assert!(id.verify_integrity());

    // 6. Tamper session
    id.origin_session_id = "sess02".to_string();
    assert!(!id.verify_integrity());
}

#[test]
fn test_adversarial_constant_time_eq_side_channel_defense() {
    let secret = "SECRET_OPERATOR_AUTH_TOKEN_999";
    let same = "SECRET_OPERATOR_AUTH_TOKEN_999";
    let diff_prefix = "XECRET_OPERATOR_AUTH_TOKEN_999";
    let diff_suffix = "SECRET_OPERATOR_AUTH_TOKEN_998";
    let diff_len = "SECRET_OPERATOR_AUTH_TOKEN_99";

    assert!(constant_time_eq(secret, same));
    assert!(!constant_time_eq(secret, diff_prefix));
    assert!(!constant_time_eq(secret, diff_suffix));
    assert!(!constant_time_eq(secret, diff_len));
}
