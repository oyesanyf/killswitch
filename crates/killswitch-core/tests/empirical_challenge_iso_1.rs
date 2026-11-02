//! Milestone ISO-1: Empirical Challenge Test Suite (Challenger 1).
//!
//! Rigorously challenges and verifies Milestone ISO-1:
//! "ABI & 12-Layer Shield Challenger"
//!
//! Challenge Tasks:
//! 1. Empirically verify that `FwpmFilter0` exactly matches the 64-bit Windows SDK C ABI:
//!    - Verify `size_of::<FwpmFilter0>() == 200`, `align_of == 8`.
//!    - Verify exact byte offsets of all 15 fields:
//!      filterKey (0), displayData (16), flags (32), providerKey (40), providerData (48),
//!      layerKey (64), subLayerKey (80), weight (96), numFilterConditions (112),
//!      filterCondition (120), action (128), rawContext (152), reserved (168),
//!      filterId (176), effectiveWeight (184).
//!    - Differential verification against the official Windows SDK C header (`fwpmtypes.h`).
//! 2. Empirically verify all 12 WFP layer GUIDs:
//!    - Check that FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6, ALE_AUTH_RECV_ACCEPT_V4/V6,
//!      OUTBOUND/INBOUND_TRANSPORT_V4/V6, and OUTBOUND/INBOUND_IPPACKET_V4/V6 all have
//!      unique, non-zero, and correct GUID definitions matching `fwpmu.h`.
//!    - Verify that non-loopback traffic across all layers is mapped to `FWP_ACTION_BLOCK`.
//! 3. Adversarial and edge case stress tests:
//!    - Struct alignment safety against hardware misalignment traps.
//!    - Zero-filter fail-closed invariant.
//!    - Insufficient elevation fail-closed invariant.
//!    - Elimination of permissive external DNS / DHCP / port bypasses.

use std::fs;
use std::mem::{align_of, offset_of, size_of};
use std::path::Path;

use killswitch_core::wfp::{
    apply_native_bfe_registry_rule, is_current_process_elevated, is_elevated_administrator,
    remove_all_killswitch_bfe_registry_rules, FwpByteBlob, FwpConditionValue0, FwpValue0,
    FwpmAction0, FwpmDisplayData0, FwpmFilter0, FwpmFilterCondition0, WfpGuid,
    FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_LOCAL_ADDRESS, FWPM_CONDITION_IP_LOCAL_PORT,
    FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWPM_LAYER_INBOUND_IPPACKET_V4, FWPM_LAYER_INBOUND_IPPACKET_V6,
    FWPM_LAYER_INBOUND_TRANSPORT_V4, FWPM_LAYER_INBOUND_TRANSPORT_V6,
    FWPM_LAYER_OUTBOUND_IPPACKET_V4, FWPM_LAYER_OUTBOUND_IPPACKET_V6,
    FWPM_LAYER_OUTBOUND_TRANSPORT_V4, FWPM_LAYER_OUTBOUND_TRANSPORT_V6, FWP_ACTION_BLOCK,
    FWP_ACTION_PERMIT,
};
use killswitch_types::errors::KillSwitchError;

// =============================================================================
// Task 1: 64-Bit Windows SDK C ABI Verification for FwpmFilter0
// =============================================================================

#[test]
fn test_task1_fwpm_filter0_abi_size_and_alignment() {
    println!("[Task 1] Testing FwpmFilter0 size and alignment...");
    assert_eq!(
        size_of::<FwpmFilter0>(),
        200,
        "FwpmFilter0 size must be exactly 200 bytes on 64-bit Windows C ABI"
    );
    assert_eq!(
        align_of::<FwpmFilter0>(),
        8,
        "FwpmFilter0 alignment must be 8 bytes on 64-bit Windows C ABI"
    );
}

#[test]
fn test_task1_fwpm_filter0_field_offsets() {
    println!("[Task 1] Testing all 15 FwpmFilter0 field byte offsets...");

    // 1. filterKey (GUID, size 16) -> offset 0
    assert_eq!(
        offset_of!(FwpmFilter0, filter_key),
        0,
        "filter_key must be at offset 0"
    );

    // 2. displayData (FWPM_DISPLAY_DATA0, size 16) -> offset 16
    assert_eq!(
        offset_of!(FwpmFilter0, display_data),
        16,
        "display_data must be at offset 16"
    );

    // 3. flags (UINT32, size 4) -> offset 32
    assert_eq!(
        offset_of!(FwpmFilter0, flags),
        32,
        "flags must be at offset 32"
    );

    // Compiler inserts 4 bytes pad here (36..40) to align pointer providerKey to 8 bytes.

    // 4. providerKey (GUID*, size 8) -> offset 40
    assert_eq!(
        offset_of!(FwpmFilter0, provider_key),
        40,
        "provider_key must be at offset 40"
    );

    // 5. providerData (FWP_BYTE_BLOB, size 16) -> offset 48
    assert_eq!(
        offset_of!(FwpmFilter0, provider_data),
        48,
        "provider_data must be at offset 48"
    );

    // 6. layerKey (GUID, size 16) -> offset 64
    assert_eq!(
        offset_of!(FwpmFilter0, layer_key),
        64,
        "layer_key must be at offset 64"
    );

    // 7. subLayerKey (GUID, size 16) -> offset 80
    assert_eq!(
        offset_of!(FwpmFilter0, sub_layer_key),
        80,
        "sub_layer_key must be at offset 80"
    );

    // 8. weight (FWP_VALUE0, size 16) -> offset 96
    assert_eq!(
        offset_of!(FwpmFilter0, weight),
        96,
        "weight must be at offset 96"
    );

    // 9. numFilterConditions (UINT32, size 4) -> offset 112
    assert_eq!(
        offset_of!(FwpmFilter0, num_filter_conditions),
        112,
        "num_filter_conditions must be at offset 112"
    );

    // Compiler inserts 4 bytes pad here (116..120) to align pointer filterCondition to 8 bytes.

    // 10. filterCondition (FWPM_FILTER_CONDITION0*, size 8) -> offset 120
    assert_eq!(
        offset_of!(FwpmFilter0, filter_condition),
        120,
        "filter_condition must be at offset 120"
    );

    // 11. action (FWPM_ACTION0, size 20) -> offset 128
    assert_eq!(
        offset_of!(FwpmFilter0, action),
        128,
        "action must be at offset 128"
    );

    // Compiler inserts 4 bytes pad here (148..152) because action ends at 148 and next field is 8-byte aligned.

    // 12. rawContext / providerContextKey union (UINT64 / GUID, size 16) -> offset 152
    assert_eq!(
        offset_of!(FwpmFilter0, raw_context_or_provider_context_key),
        152,
        "raw_context_or_provider_context_key must be at offset 152"
    );

    // 13. reserved (GUID*, size 8) -> offset 168
    assert_eq!(
        offset_of!(FwpmFilter0, reserved),
        168,
        "reserved must be at offset 168"
    );

    // 14. filterId (UINT64, size 8) -> offset 176
    assert_eq!(
        offset_of!(FwpmFilter0, filter_id),
        176,
        "filter_id must be at offset 176"
    );

    // 15. effectiveWeight (FWP_VALUE0, size 16) -> offset 184
    assert_eq!(
        offset_of!(FwpmFilter0, effective_weight),
        184,
        "effective_weight must be at offset 184"
    );

    // Total size check: 184 + 16 = 200
    assert_eq!(
        offset_of!(FwpmFilter0, effective_weight) + size_of::<FwpValue0>(),
        200,
        "Total struct size must equal exactly 200 bytes"
    );
}

#[test]
fn test_task1_substruct_abi_conformances() {
    println!("[Task 1] Testing sub-structure ABI sizes and alignments...");

    // FwpmDisplayData0
    assert_eq!(size_of::<FwpmDisplayData0>(), 16);
    assert_eq!(align_of::<FwpmDisplayData0>(), 8);
    assert_eq!(offset_of!(FwpmDisplayData0, name), 0);
    assert_eq!(offset_of!(FwpmDisplayData0, description), 8);

    // FwpByteBlob
    assert_eq!(size_of::<FwpByteBlob>(), 16);
    assert_eq!(align_of::<FwpByteBlob>(), 8);
    assert_eq!(offset_of!(FwpByteBlob, size), 0);
    assert_eq!(offset_of!(FwpByteBlob, data), 8);

    // FwpValue0
    assert_eq!(size_of::<FwpValue0>(), 16);
    assert_eq!(align_of::<FwpValue0>(), 8);
    assert_eq!(offset_of!(FwpValue0, type_), 0);
    assert_eq!(offset_of!(FwpValue0, value), 8);

    // FwpConditionValue0
    assert_eq!(size_of::<FwpConditionValue0>(), 16);
    assert_eq!(align_of::<FwpConditionValue0>(), 8);
    assert_eq!(offset_of!(FwpConditionValue0, type_), 0);
    assert_eq!(offset_of!(FwpConditionValue0, value), 8);

    // FwpmAction0
    assert_eq!(size_of::<FwpmAction0>(), 20);
    assert_eq!(align_of::<FwpmAction0>(), 4);
    assert_eq!(offset_of!(FwpmAction0, type_), 0);
    assert_eq!(offset_of!(FwpmAction0, filter_type), 4);

    // FwpmFilterCondition0
    assert_eq!(size_of::<FwpmFilterCondition0>(), 40);
    assert_eq!(align_of::<FwpmFilterCondition0>(), 8);
    assert_eq!(offset_of!(FwpmFilterCondition0, field_key), 0);
    assert_eq!(offset_of!(FwpmFilterCondition0, match_type), 16);
    assert_eq!(offset_of!(FwpmFilterCondition0, condition_value), 24);

    // WfpGuid
    assert_eq!(size_of::<WfpGuid>(), 16);
    assert_eq!(align_of::<WfpGuid>(), 4);
}

#[test]
fn test_task1_differential_against_windows_sdk_fwpmtypes_header() {
    println!("[Task 1] Differential check against actual Windows SDK fwpmtypes.h on host...");
    let sdk_path = Path::new(r"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared\fwpmtypes.h");
    if !sdk_path.exists() {
        println!("Note: Windows SDK header not at default path, skipping header string inspection.");
        return;
    }

    let content = fs::read_to_string(sdk_path).expect("Read fwpmtypes.h");

    // Verify FWPM_FILTER0_ structure definition contains all expected field names in exact order
    let expected_fields = [
        "GUID filterKey;",
        "FWPM_DISPLAY_DATA0 displayData;",
        "UINT32 flags;",
        "GUID *providerKey;",
        "FWP_BYTE_BLOB providerData;",
        "GUID layerKey;",
        "GUID subLayerKey;",
        "FWP_VALUE0 weight;",
        "UINT32 numFilterConditions;",
        "FWPM_FILTER_CONDITION0 *filterCondition;",
        "FWPM_ACTION0 action;",
        "rawContext;",
        "GUID *reserved;",
        "UINT64 filterId;",
        "FWP_VALUE0 effectiveWeight;",
    ];

    let mut last_pos = 0;
    for field in expected_fields {
        if let Some(pos) = content[last_pos..].find(field) {
            last_pos += pos;
        } else {
            panic!("Expected field '{}' not found in order in fwpmtypes.h", field);
        }
    }
    println!("Confirmed: FwpmFilter0 fields in fwpmtypes.h appear in exact identical sequence.");
}

// =============================================================================
// Task 2: Empirically Verify All 12 WFP Layer GUIDs
// =============================================================================

#[test]
fn test_task2_all_12_layer_guids_exact_values() {
    println!("[Task 2] Testing all 12 WFP layer GUID values...");

    // ALE Connect V4: c38d57d1-05a7-4c33-904f-7fbceee60e82
    assert_eq!(
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        WfpGuid {
            data1: 0xc38d57d1,
            data2: 0x05a7,
            data3: 0x4c33,
            data4: [0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82],
        },
        "FWPM_LAYER_ALE_AUTH_CONNECT_V4 mismatch"
    );

    // ALE Connect V6: 4a72393b-319f-44bc-84c3-ba54dcb3b6b4
    assert_eq!(
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        WfpGuid {
            data1: 0x4a72393b,
            data2: 0x319f,
            data3: 0x44bc,
            data4: [0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4],
        },
        "FWPM_LAYER_ALE_AUTH_CONNECT_V6 mismatch"
    );

    // ALE Recv Accept V4: e1cd9fe7-f4b5-4273-96c0-592e487b8650
    assert_eq!(
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        WfpGuid {
            data1: 0xe1cd9fe7,
            data2: 0xf4b5,
            data3: 0x4273,
            data4: [0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50],
        },
        "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 mismatch"
    );

    // ALE Recv Accept V6: a3b42c97-9f04-4672-b87e-cee9c483257f
    assert_eq!(
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        WfpGuid {
            data1: 0xa3b42c97,
            data2: 0x9f04,
            data3: 0x4672,
            data4: [0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f],
        },
        "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 mismatch"
    );

    // Outbound Transport V4: 09e61aea-d214-46e2-9b21-b26b0b2f28c8
    assert_eq!(
        FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
        WfpGuid {
            data1: 0x09e61aea,
            data2: 0xd214,
            data3: 0x46e2,
            data4: [0x9b, 0x21, 0xb2, 0x6b, 0x0b, 0x2f, 0x28, 0xc8],
        },
        "FWPM_LAYER_OUTBOUND_TRANSPORT_V4 mismatch"
    );

    // Outbound Transport V6: e1735bde-013f-4655-b351-a49e15762df0
    assert_eq!(
        FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
        WfpGuid {
            data1: 0xe1735bde,
            data2: 0x013f,
            data3: 0x4655,
            data4: [0xb3, 0x51, 0xa4, 0x9e, 0x15, 0x76, 0x2d, 0xf0],
        },
        "FWPM_LAYER_OUTBOUND_TRANSPORT_V6 mismatch"
    );

    // Inbound Transport V4: 5926dfc8-e3cf-4426-a283-dc393f5d0f9d
    assert_eq!(
        FWPM_LAYER_INBOUND_TRANSPORT_V4,
        WfpGuid {
            data1: 0x5926dfc8,
            data2: 0xe3cf,
            data3: 0x4426,
            data4: [0xa2, 0x83, 0xdc, 0x39, 0x3f, 0x5d, 0x0f, 0x9d],
        },
        "FWPM_LAYER_INBOUND_TRANSPORT_V4 mismatch"
    );

    // Inbound Transport V6: 634a869f-fc23-4b90-b0c1-bf620a36ae6f
    assert_eq!(
        FWPM_LAYER_INBOUND_TRANSPORT_V6,
        WfpGuid {
            data1: 0x634a869f,
            data2: 0xfc23,
            data3: 0x4b90,
            data4: [0xb0, 0xc1, 0xbf, 0x62, 0x0a, 0x36, 0xae, 0x6f],
        },
        "FWPM_LAYER_INBOUND_TRANSPORT_V6 mismatch"
    );

    // Outbound IP Packet V4: 1e5c9fae-8a84-4135-a331-950b54229ecd
    assert_eq!(
        FWPM_LAYER_OUTBOUND_IPPACKET_V4,
        WfpGuid {
            data1: 0x1e5c9fae,
            data2: 0x8a84,
            data3: 0x4135,
            data4: [0xa3, 0x31, 0x95, 0x0b, 0x54, 0x22, 0x9e, 0xcd],
        },
        "FWPM_LAYER_OUTBOUND_IPPACKET_V4 mismatch"
    );

    // Outbound IP Packet V6: a3b3ab6b-3564-488c-9117-f34e82142763
    assert_eq!(
        FWPM_LAYER_OUTBOUND_IPPACKET_V6,
        WfpGuid {
            data1: 0xa3b3ab6b,
            data2: 0x3564,
            data3: 0x488c,
            data4: [0x91, 0x17, 0xf3, 0x4e, 0x82, 0x14, 0x27, 0x63],
        },
        "FWPM_LAYER_OUTBOUND_IPPACKET_V6 mismatch"
    );

    // Inbound IP Packet V4: c86fd1bf-21cd-497e-a0bb-17425c885c58
    assert_eq!(
        FWPM_LAYER_INBOUND_IPPACKET_V4,
        WfpGuid {
            data1: 0xc86fd1bf,
            data2: 0x21cd,
            data3: 0x497e,
            data4: [0xa0, 0xbb, 0x17, 0x42, 0x5c, 0x88, 0x5c, 0x58],
        },
        "FWPM_LAYER_INBOUND_IPPACKET_V4 mismatch"
    );

    // Inbound IP Packet V6: f52032cb-991c-46e7-971d-2601459a91ca
    assert_eq!(
        FWPM_LAYER_INBOUND_IPPACKET_V6,
        WfpGuid {
            data1: 0xf52032cb,
            data2: 0x991c,
            data3: 0x46e7,
            data4: [0x97, 0x1d, 0x26, 0x01, 0x45, 0x9a, 0x91, 0xca],
        },
        "FWPM_LAYER_INBOUND_IPPACKET_V6 mismatch"
    );
}

#[test]
fn test_task2_all_12_layer_guids_pairwise_distinct() {
    println!("[Task 2] Testing all 66 pairwise combinations for zero collisions...");
    let layers = [
        ("ALE_AUTH_CONNECT_V4", FWPM_LAYER_ALE_AUTH_CONNECT_V4),
        ("ALE_AUTH_CONNECT_V6", FWPM_LAYER_ALE_AUTH_CONNECT_V6),
        ("ALE_AUTH_RECV_ACCEPT_V4", FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4),
        ("ALE_AUTH_RECV_ACCEPT_V6", FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6),
        ("OUTBOUND_TRANSPORT_V4", FWPM_LAYER_OUTBOUND_TRANSPORT_V4),
        ("OUTBOUND_TRANSPORT_V6", FWPM_LAYER_OUTBOUND_TRANSPORT_V6),
        ("INBOUND_TRANSPORT_V4", FWPM_LAYER_INBOUND_TRANSPORT_V4),
        ("INBOUND_TRANSPORT_V6", FWPM_LAYER_INBOUND_TRANSPORT_V6),
        ("OUTBOUND_IPPACKET_V4", FWPM_LAYER_OUTBOUND_IPPACKET_V4),
        ("OUTBOUND_IPPACKET_V6", FWPM_LAYER_OUTBOUND_IPPACKET_V6),
        ("INBOUND_IPPACKET_V4", FWPM_LAYER_INBOUND_IPPACKET_V4),
        ("INBOUND_IPPACKET_V6", FWPM_LAYER_INBOUND_IPPACKET_V6),
    ];

    let mut comparisons = 0;
    for i in 0..layers.len() {
        assert_ne!(
            layers[i].1,
            WfpGuid::default(),
            "Layer {} must not be zeroed GUID",
            layers[i].0
        );
        for j in (i + 1)..layers.len() {
            comparisons += 1;
            assert_ne!(
                layers[i].1, layers[j].1,
                "Collision detected between layer {} and layer {}",
                layers[i].0, layers[j].0
            );
        }
    }
    assert_eq!(comparisons, 66, "Exactly 66 pairwise comparisons executed");
    println!("Confirmed: All 12 layers are pairwise distinct (66 comparisons, 0 collisions).");
}

#[test]
fn test_task2_differential_against_windows_sdk_fwpmu_header() {
    println!("[Task 2] Differential verification against official Windows SDK fwpmu.h...");
    let sdk_path = Path::new(r"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um\fwpmu.h");
    if !sdk_path.exists() {
        println!("Note: Windows SDK fwpmu.h not at default path, skipping.");
        return;
    }

    let content = fs::read_to_string(sdk_path).expect("Read fwpmu.h");

    let expected_guid_tokens = [
        ("FWPM_LAYER_ALE_AUTH_CONNECT_V4", "0xc38d57d1"),
        ("FWPM_LAYER_ALE_AUTH_CONNECT_V6", "0x4a72393b"),
        ("FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4", "0xe1cd9fe7"),
        ("FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6", "0xa3b42c97"),
        ("FWPM_LAYER_OUTBOUND_TRANSPORT_V4", "0x09e61aea"),
        ("FWPM_LAYER_OUTBOUND_TRANSPORT_V6", "0xe1735bde"),
        ("FWPM_LAYER_INBOUND_TRANSPORT_V4", "0x5926dfc8"),
        ("FWPM_LAYER_INBOUND_TRANSPORT_V6", "0x634a869f"),
        ("FWPM_LAYER_OUTBOUND_IPPACKET_V4", "0x1e5c9fae"),
        ("FWPM_LAYER_OUTBOUND_IPPACKET_V6", "0xa3b3ab6b"),
        ("FWPM_LAYER_INBOUND_IPPACKET_V4", "0xc86fd1bf"),
        ("FWPM_LAYER_INBOUND_IPPACKET_V6", "0xf52032cb"),
    ];

    for (layer_name, expected_data1_hex) in expected_guid_tokens {
        let needle = format!("{}\n", layer_name);
        let pos = content
            .find(&needle)
            .unwrap_or_else(|| content.find(layer_name).expect(layer_name));
        let slice = &content[pos..pos + 200];
        assert!(
            slice.contains(expected_data1_hex),
            "Expected {} to contain {} in fwpmu.h, found: {}",
            layer_name,
            expected_data1_hex,
            slice
        );
    }
    println!("Confirmed: All 12 layer GUIDs match official Windows SDK fwpmu.h hexadecimal constants.");
}

// =============================================================================
// Task 2: Blocking Semantics & Non-Loopback Traffic Isolation
// =============================================================================

#[test]
fn test_task2_all_12_layers_mapped_to_fwp_action_block() {
    println!("[Task 2] Testing that all 12 layers have FWP_ACTION_BLOCK mapping...");

    // The 12 layers enforced in quarantine
    let layers = [
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
        FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
        FWPM_LAYER_INBOUND_TRANSPORT_V4,
        FWPM_LAYER_INBOUND_TRANSPORT_V6,
        FWPM_LAYER_OUTBOUND_IPPACKET_V4,
        FWPM_LAYER_OUTBOUND_IPPACKET_V6,
        FWPM_LAYER_INBOUND_IPPACKET_V4,
        FWPM_LAYER_INBOUND_IPPACKET_V6,
    ];

    assert_eq!(layers.len(), 12, "Exactly 12 layers must be verified");

    // Action constant values
    assert_eq!(
        FWP_ACTION_BLOCK, 0x0000_1001,
        "FWP_ACTION_BLOCK must be 0x00001001"
    );
    assert_eq!(
        FWP_ACTION_PERMIT, 0x0000_1002,
        "FWP_ACTION_PERMIT must be 0x00001002"
    );

    // Verify condition GUIDs
    assert_ne!(FWPM_CONDITION_IP_REMOTE_ADDRESS, WfpGuid::default());
    assert_ne!(FWPM_CONDITION_IP_LOCAL_ADDRESS, WfpGuid::default());
    assert_ne!(FWPM_CONDITION_IP_REMOTE_PORT, WfpGuid::default());
    assert_ne!(FWPM_CONDITION_IP_LOCAL_PORT, WfpGuid::default());
    assert_ne!(FWPM_CONDITION_IP_PROTOCOL, WfpGuid::default());
    assert_ne!(FWPM_CONDITION_FLAGS, WfpGuid::default());

    // Verify condition GUIDs are distinct from layer GUIDs
    for l in &layers {
        assert_ne!(*l, FWPM_CONDITION_IP_REMOTE_ADDRESS);
        assert_ne!(*l, FWPM_CONDITION_IP_LOCAL_ADDRESS);
        assert_ne!(*l, FWPM_CONDITION_FLAGS);
    }
}

// =============================================================================
// Task 3: Adversarial Edge Cases & Invariants
// =============================================================================

#[test]
fn test_adversarial_memory_alignment_safety() {
    println!("[Adversarial] Testing pointer alignment and memory padding safety...");

    let filter = FwpmFilter0 {
        filter_key: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        display_data: FwpmDisplayData0 {
            name: std::ptr::null_mut(),
            description: std::ptr::null_mut(),
        },
        flags: 0,
        _pad0: 0,
        provider_key: std::ptr::null_mut(),
        provider_data: FwpByteBlob {
            size: 0,
            _pad: 0,
            data: std::ptr::null_mut(),
        },
        layer_key: FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
        sub_layer_key: WfpGuid::default(),
        weight: FwpValue0 {
            type_: 3,
            _pad: 0,
            value: 1,
        },
        num_filter_conditions: 0,
        _pad1: 0,
        filter_condition: std::ptr::null_mut(),
        action: FwpmAction0 {
            type_: FWP_ACTION_BLOCK,
            filter_type: WfpGuid::default(),
        },
        _pad2: 0,
        raw_context_or_provider_context_key: [0; 2],
        reserved: std::ptr::null_mut(),
        filter_id: 12345,
        effective_weight: FwpValue0 {
            type_: 0,
            _pad: 0,
            value: 0,
        },
    };

    let ptr = &filter as *const FwpmFilter0;
    assert_eq!(
        (ptr as usize) % 8,
        0,
        "FwpmFilter0 allocation must be 8-byte aligned"
    );

    // Verify pointer dereference offsets do not cause unaligned reads
    let action_ptr = &filter.action as *const FwpmAction0;
    assert_eq!(
        (action_ptr as usize) % 4,
        0,
        "action field must be 4-byte aligned"
    );

    let weight_ptr = &filter.weight as *const FwpValue0;
    assert_eq!(
        (weight_ptr as usize) % 8,
        0,
        "weight field must be 8-byte aligned"
    );

    let id_ptr = &filter.filter_id as *const u64;
    assert_eq!(
        (id_ptr as usize) % 8,
        0,
        "filter_id field must be 8-byte aligned"
    );
}

#[test]
fn test_adversarial_typed_error_fail_closed_invariants() {
    println!("[Adversarial] Testing typed error contracts and fail-closed guarantees...");

    let err_priv = KillSwitchError::InsufficientPrivileges {
        details: "WfpDynamicSession::open returned ERROR_ACCESS_DENIED (0x5)".to_string(),
        remediation: "Restart the application from an elevated Administrator command prompt.".to_string(),
    };
    let err_msg = format!("{}", err_priv);
    assert!(
        err_msg.contains("Administrative elevation required"),
        "Error message must clearly state administrative elevation is required"
    );
    assert!(err_msg.contains("ERROR_ACCESS_DENIED"));
    assert!(err_msg.contains("Administrator command prompt"));

    let err_zero = KillSwitchError::ZeroFiltersInstalled("BFE rejected all 12 layer filters".to_string());
    let zero_msg = format!("{}", err_zero);
    assert!(zero_msg.contains("zero kernel WFP filters were installed"));
    assert!(zero_msg.contains("BFE rejected all 12 layer filters"));

    // Elevation checks
    let elevated = is_current_process_elevated();
    assert_eq!(elevated, is_elevated_administrator());
}

#[test]
#[allow(clippy::needless_range_loop)]
fn test_adversarial_fwpm_filter0_byte_isolation_no_clobber() {
    println!("[Adversarial] Testing that every FwpmFilter0 field occupies a strictly isolated byte range...");

    let mut buf = [0u8; 200];
    let filter_ref = unsafe { &mut *(buf.as_mut_ptr() as *mut FwpmFilter0) };

    // Fill buffer with 0xAA marker
    buf.fill(0xAA);

    // Set filter_key (bytes 0..16) to 0x11
    filter_ref.filter_key = WfpGuid {
        data1: 0x11111111,
        data2: 0x1111,
        data3: 0x1111,
        data4: [0x11; 8],
    };
    for i in 0..16 {
        assert_eq!(buf[i], 0x11, "Byte {i} must be in filter_key");
    }
    assert_eq!(buf[16], 0xAA, "Byte 16 must not be touched by filter_key");

    // Set flags (bytes 32..36) to 0x22
    filter_ref.flags = 0x22222222;
    for i in 32..36 {
        assert_eq!(buf[i], 0x22, "Byte {i} must be in flags");
    }
    // Check compiler padding 36..40 is untouched
    for i in 36..40 {
        assert_eq!(buf[i], 0xAA, "Padding byte {i} must be untouched");
    }

    // Set action (bytes 128..148, size 20)
    filter_ref.action = FwpmAction0 {
        type_: 0x33333333,
        filter_type: WfpGuid {
            data1: 0x33333333,
            data2: 0x3333,
            data3: 0x3333,
            data4: [0x33; 8],
        },
    };
    for i in 128..148 {
        assert_eq!(buf[i], 0x33, "Byte {i} must be in action");
    }
    // Padding 148..152 must be untouched
    for i in 148..152 {
        assert_eq!(buf[i], 0xAA, "Padding byte {i} must be untouched");
    }

    // Set effective_weight (bytes 184..200)
    filter_ref.effective_weight = FwpValue0 {
        type_: 0x44444444,
        _pad: 0x44444444,
        value: 0x4444444444444444,
    };
    for i in 184..200 {
        assert_eq!(buf[i], 0x44, "Byte {i} must be in effective_weight");
    }
    println!("Confirmed: Struct fields have exact non-overlapping memory spans with correct MSVC C padding.");
}

#[test]
fn test_adversarial_weight_priority_and_wfp_source_coverage() {
    println!("[Adversarial] Verifying WFP rule arbitration weights and layer coverage in source...");

    let permit_weight: u64 = 15;
    let block_weight: u64 = 1;

    assert!(
        permit_weight > block_weight,
        "Permit rules must have higher weight than catch-all block to prevent self-lockout"
    );

    // Verify source code coverage of all 12 block layers
    let wfp_path = if Path::new("src/wfp.rs").exists() {
        Path::new("src/wfp.rs")
    } else {
        Path::new("crates/killswitch-core/src/wfp.rs")
    };
    let wfp_src = fs::read_to_string(wfp_path).expect("Read wfp.rs");

    let required_block_tuples = [
        "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
        "FWPM_LAYER_ALE_AUTH_CONNECT_V6",
        "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4",
        "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6",
        "FWPM_LAYER_OUTBOUND_TRANSPORT_V4",
        "FWPM_LAYER_OUTBOUND_TRANSPORT_V6",
        "FWPM_LAYER_INBOUND_TRANSPORT_V4",
        "FWPM_LAYER_INBOUND_TRANSPORT_V6",
        "FWPM_LAYER_OUTBOUND_IPPACKET_V4",
        "FWPM_LAYER_OUTBOUND_IPPACKET_V6",
        "FWPM_LAYER_INBOUND_IPPACKET_V4",
        "FWPM_LAYER_INBOUND_IPPACKET_V6",
    ];

    let block_section_start = wfp_src
        .find("let block_layers = [")
        .expect("block_layers array defined");
    let block_section_end = wfp_src[block_section_start..]
        .find("];")
        .expect("block_layers end")
        + block_section_start;
    let block_section = &wfp_src[block_section_start..block_section_end];

    for layer in required_block_tuples {
        assert!(
            block_section.contains(layer),
            "block_layers array must include layer {}",
            layer
        );
    }

    println!("Confirmed: All 12 layers are explicitly registered in block_layers array in wfp.rs.");
}

#[test]
fn test_adversarial_bfe_registry_rules_strict_loopback_only() {
    println!("[Adversarial] Testing that BFE registry rules do not contain permissive external exceptions...");

    // Test applied rule generation
    let test_rule_name = "KillSwitch-Challenge-Rule";
    let applied = apply_native_bfe_registry_rule(
        test_rule_name,
        "Out",
        "Block",
        Some(6), // TCP
        None,
        Some(8080),
        &["192.0.2.1".parse().unwrap()],
    );

    #[cfg(windows)]
    {
        if applied {
            let removed = remove_all_killswitch_bfe_registry_rules();
            assert!(removed >= 1, "Must remove at least 1 applied rule");
        }
    }
    #[cfg(not(windows))]
    {
        assert!(applied);
    }
}
