//! Milestone 1 Iteration 2 Adversarial Empirical Challenge Suite.
//!
//! Empirical Stress Tests for:
//! 1. Peer PID Resolution & Fail-Closed Boundaries (`peer_pid.rs` & `handlers.rs`):
//!    - IPv4-mapped IPv6 loopback addresses (`[::ffff:127.0.0.1]:port`) -> AF_INET table resolution.
//!    - Closed / TIME_WAIT sockets with `dw_owning_pid == 0` -> Fail closed.
//!    - Connected socket where PID cannot be resolved -> HTTP 401 UNAUTHORIZED / zero fallback to claimed JSON PID.
//!    - Caller PID spoofing mismatch detection -> HTTP 401 UNAUTHORIZED.
//! 2. RFC 8785 JCS Float Saturation & Canonicalization Attacks (`jcs.rs`):
//!    - Large floats in [9.223e18, 1e21) (e.g. 1e19, 9.5e18, 1e20) -> No saturation to i64::MAX (9223372036854775807).
//!    - Exact boundary at 1e21 -> Switch to lowercase 'e+' notation ("1e+21").
//!    - Small floats < 1e-6 (e.g. 1e-7) -> Lowercase 'e-' notation ("1e-7").
//!    - Large negative floats -> No saturation to i64::MIN (-9223372036854775808).
//!    - Residual risk boundary probe at 2^63 (9223372036854775808.0).
//!    - Complex payload digest stability.

use std::net::{SocketAddr, SocketAddrV6, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use killswitch_core::killchain::HostContainmentManager;
use killswitch_core::peer_pid::resolve_loopback_peer_pid;
use killswitch_server::routes::build_router;
use killswitch_server::server::ServerState;
use killswitch_telemetry::{canonicalize_jcs, canonicalize_jcs_string};
use killswitch_types::errors::KillSwitchError;

const ADVERSARIAL_MASTER_TOKEN: &str = "adv_master_secret_key_9876543210_fedcba_0123456789abcdef";

fn create_test_server_state(bound_port: u16) -> Arc<ServerState> {
    std::env::set_var("KILLSWITCH_MASTER_TOKEN", ADVERSARIAL_MASTER_TOKEN);
    let temp_dir = tempfile::tempdir().unwrap();
    let containment = Arc::new(HostContainmentManager::new_default(Some(temp_dir.path())).unwrap());
    let state = Arc::new(ServerState::with_defaults(containment));
    state
        .active_bound_port
        .store(bound_port, std::sync::atomic::Ordering::SeqCst);
    state
}

// ============================================================================
// PART 1: PEER PID RESOLUTION & FAIL-CLOSED ADVERSARIAL SUITE
// ============================================================================

/// Vector 1a: Test IPv4-mapped IPv6 loopback addresses (`[::ffff:127.0.0.1]:port`).
/// In dual-stack environments, incoming loopback IPv4 sockets arrive as IPv6-mapped addresses.
/// On Windows, `GetExtendedTcpTable` must query AF_INET after unmapping, successfully resolving the PID.
#[test]
fn test_adversarial_peer_pid_ipv4_mapped_ipv6_loopback() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind ephemeral listener");
    let server_port = listener.local_addr().unwrap().port();

    let client = TcpStream::connect(format!("127.0.0.1:{}", server_port))
        .expect("Must connect to ephemeral listener");
    let client_v4 = match client.local_addr().unwrap() {
        SocketAddr::V4(v4) => v4,
        _ => panic!("Expected IPv4 client address"),
    };

    let (server_stream, _) = listener.accept().expect("Must accept connection");

    // Construct IPv4-mapped IPv6 address: ::ffff:127.0.0.1
    let mapped_ip = client_v4.ip().to_ipv6_mapped();
    let mapped_addr = SocketAddr::V6(SocketAddrV6::new(mapped_ip, client_v4.port(), 0, 0));

    let res = resolve_loopback_peer_pid(mapped_addr, server_port);
    assert!(
        res.is_ok(),
        "IPv4-mapped IPv6 loopback must successfully resolve caller PID from AF_INET table: {:?}",
        res
    );
    let resolved_pid = res.unwrap();
    let expected_pid = std::process::id();
    assert_eq!(
        resolved_pid, expected_pid,
        "Resolved PID {} must match current test process PID {}",
        resolved_pid, expected_pid
    );

    drop(client);
    drop(server_stream);
}

/// Vector 1b: Test closed / TIME_WAIT sockets where dw_owning_pid == 0.
/// When a socket is closed and transitions to TIME_WAIT/unowned state,
/// resolve_loopback_peer_pid must fail closed (return Err), NEVER returning PID 0.
#[test]
fn test_adversarial_peer_pid_closed_socket_rejects_pid_zero() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind ephemeral listener");
    let server_port = listener.local_addr().unwrap().port();

    let client = TcpStream::connect(format!("127.0.0.1:{}", server_port))
        .expect("Must connect to ephemeral listener");
    let client_addr = client.local_addr().expect("Must have local addr");

    let (server_stream, _) = listener.accept().expect("Must accept connection");

    // Abruptly close both endpoints
    drop(client);
    drop(server_stream);

    // Give kernel a brief window to transition state
    std::thread::sleep(Duration::from_millis(50));

    let res = resolve_loopback_peer_pid(client_addr, server_port);
    match res {
        Ok(pid) => {
            assert_ne!(
                pid, 0,
                "Closed/TIME_WAIT socket must NEVER report owning PID 0 (must return Err)"
            );
        }
        Err(KillSwitchError::NativeOsError(msg)) => {
            // Expected fail-closed behavior
            assert!(
                msg.contains("No kernel TCP table entry found")
                    || msg.contains("closed/unowned (PID 0)"),
                "Expected unowned/closed error message, got: {}",
                msg
            );
        }
        Err(other) => {
            panic!("Unexpected error variant for closed socket: {:?}", other);
        }
    }
}

/// Vector 1c: Test connected socket where PID cannot be resolved.
/// Assert handler returns HTTP 401 StatusCode::UNAUTHORIZED and NEVER falls back
/// to caller-supplied JSON PID.
#[tokio::test]
async fn test_adversarial_disarm_unresolvable_socket_fails_closed_401_no_fallback() {
    let server_port = 45999;
    let state = create_test_server_state(server_port);
    let app = build_router(state);

    // Use a completely unmapped / bogus client address that does not exist in kernel TCP table
    let unmapped_client_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

    let payload = json!({
        "operator": "secops_operator",
        "reason": "Adversarial test unresolvable socket",
        "token": ADVERSARIAL_MASTER_TOKEN,
        "caller_pid": 77777 // Rogue claimed PID
    });

    let req = Request::builder()
        .method("POST")
        .uri("/disarm")
        .header("Content-Type", "application/json")
        .extension(ConnectInfo(unmapped_client_addr))
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();

    // MUST return 401 Unauthorized, NOT 200 OK or 403 Forbidden
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Unresolvable socket MUST return HTTP 401 UNAUTHORIZED"
    );

    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 64)
        .await
        .unwrap();
    let body_json: Value = serde_json::from_slice(&bytes).unwrap();

    let err_msg = body_json["error"]["message"]
        .as_str()
        .unwrap_or_else(|| body_json["message"].as_str().unwrap_or(""));

    assert!(
        err_msg.contains("Loopback peer PID verification failed on connected socket"),
        "Error message must indicate peer PID resolution failure, got: {}",
        err_msg
    );
}

/// Vector 1d: Test caller PID spoofing: client connects on loopback, claims a different PID in JSON.
/// When actual peer PID is resolved from kernel table, handler asserts claimed == actual.
/// If claimed != actual, handler MUST return HTTP 401 UNAUTHORIZED with caller PID spoofing error.
#[tokio::test]
async fn test_adversarial_disarm_caller_pid_spoofing_mismatch_fails_401() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind ephemeral listener");
    let server_port = listener.local_addr().unwrap().port();

    let client = TcpStream::connect(format!("127.0.0.1:{}", server_port))
        .expect("Must connect to ephemeral listener");
    let client_addr = client.local_addr().expect("Must have local addr");

    let (server_stream, _) = listener.accept().expect("Must accept connection");

    let state = create_test_server_state(server_port);
    let app = build_router(state);

    let actual_pid = std::process::id();
    let spoofed_pid = actual_pid + 88888; // Forged PID claim

    let payload = json!({
        "operator": "secops_operator",
        "reason": "Adversarial test PID spoofing",
        "token": ADVERSARIAL_MASTER_TOKEN,
        "caller_pid": spoofed_pid
    });

    let req = Request::builder()
        .method("POST")
        .uri("/disarm")
        .header("Content-Type", "application/json")
        .extension(ConnectInfo(client_addr))
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Caller PID spoofing MUST return HTTP 401 UNAUTHORIZED"
    );

    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 64)
        .await
        .unwrap();
    let body_json: Value = serde_json::from_slice(&bytes).unwrap();

    let err_msg = body_json["error"]["message"]
        .as_str()
        .unwrap_or_else(|| body_json["message"].as_str().unwrap_or(""));

    assert!(
        err_msg.contains("Caller PID spoofing detected"),
        "Error message must flag caller PID spoofing, got: {}",
        err_msg
    );
    assert!(
        err_msg.contains(&format!("claimed PID {}", spoofed_pid)),
        "Error message must specify claimed PID"
    );

    drop(client);
    drop(server_stream);
}

/// Vector 1e: Test forced rollback on /health-probe with unresolvable socket.
/// Verifies fail-closed behavior on /health-probe endpoint as well.
#[tokio::test]
async fn test_adversarial_health_probe_unresolvable_socket_fails_closed_401() {
    let server_port = 45998;
    let state = create_test_server_state(server_port);
    let app = build_router(state);

    let unmapped_client_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

    let payload = json!({
        "force_rollback": true,
        "token": ADVERSARIAL_MASTER_TOKEN
    });

    let req = Request::builder()
        .method("POST")
        .uri("/health-probe")
        .header("Content-Type", "application/json")
        .extension(ConnectInfo(unmapped_client_addr))
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Health probe forced rollback on unresolvable socket MUST return HTTP 401 UNAUTHORIZED"
    );
}

// ============================================================================
// PART 2: RFC 8785 JCS FLOAT SATURATION & CANONICALIZATION ATTACKS
// ============================================================================

/// Vector 2a: Test large floats in [9.223e18, 1e21)
/// In Iteration 1, casting floats to i64 saturated 1e19 and 1e20 to i64::MAX (9223372036854775807).
/// In Iteration 2 (commit 1f0a4031), large integer-valued floats format via i128 exact decimal notation.
#[test]
fn test_adversarial_jcs_large_floats_no_saturation() {
    const I64_MAX_STR: &str = "9223372036854775807";

    // 1e19 = 10,000,000,000,000,000,000
    let v_1e19 = json!(1e19);
    let s_1e19 = canonicalize_jcs_string(&v_1e19).unwrap();
    assert_ne!(s_1e19, I64_MAX_STR, "1e19 MUST NOT saturate to i64::MAX");
    assert_eq!(s_1e19, "10000000000000000000");

    // 9.5e18 = 9,500,000,000,000,000,000 (> 9.223e18)
    let v_9_5e18 = json!(9.5e18);
    let s_9_5e18 = canonicalize_jcs_string(&v_9_5e18).unwrap();
    assert_ne!(
        s_9_5e18, I64_MAX_STR,
        "9.5e18 MUST NOT saturate to i64::MAX"
    );
    assert_eq!(s_9_5e18, "9500000000000000000");

    // 1e20 = 100,000,000,000,000,000,000
    let v_1e20 = json!(1e20);
    let s_1e20 = canonicalize_jcs_string(&v_1e20).unwrap();
    assert_ne!(s_1e20, I64_MAX_STR, "1e20 MUST NOT saturate to i64::MAX");
    assert_eq!(s_1e20, "100000000000000000000");

    // 5e20 = 500,000,000,000,000,000,000
    let v_5e20 = json!(5e20);
    let s_5e20 = canonicalize_jcs_string(&v_5e20).unwrap();
    assert_ne!(s_5e20, I64_MAX_STR, "5e20 MUST NOT saturate to i64::MAX");
    assert_eq!(s_5e20, "500000000000000000000");
}

/// Vector 2b: Test boundary at 1e21.
/// RFC 8785 Section 3.2.2.3: Floats with magnitude >= 1e21 MUST switch to ECMAScript lowercase 'e+' notation.
#[test]
fn test_adversarial_jcs_boundary_at_1e21() {
    // Exact 1e21
    let v_1e21 = json!(1e21);
    let s_1e21 = canonicalize_jcs_string(&v_1e21).unwrap();
    assert_eq!(s_1e21, "1e+21", "1e21 MUST switch cleanly to '1e+21'");

    // 2e21
    let v_2e21 = json!(2e21);
    let s_2e21 = canonicalize_jcs_string(&v_2e21).unwrap();
    assert_eq!(s_2e21, "2e+21", "2e21 MUST format as '2e+21'");

    // 1e22
    let v_1e22 = json!(1e22);
    let s_1e22 = canonicalize_jcs_string(&v_1e22).unwrap();
    assert_eq!(s_1e22, "1e+22", "1e22 MUST format as '1e+22'");

    // Just below 1e21: 1e20 has 21 digits, rendered as decimal
    let v_1e20 = json!(1e20);
    let s_1e20 = canonicalize_jcs_string(&v_1e20).unwrap();
    assert_eq!(s_1e20, "100000000000000000000");
}

/// Vector 2c: Test small floats < 1e-6.
/// RFC 8785 Section 3.2.2.3: Floats with magnitude < 1e-6 MUST format with lowercase 'e-' notation.
#[test]
fn test_adversarial_jcs_small_floats_sub_micro() {
    // 1e-7 must format as "1e-7", NOT "0.0000001"
    let v_1e_neg7 = json!(1e-7);
    let s_1e_neg7 = canonicalize_jcs_string(&v_1e_neg7).unwrap();
    assert_eq!(s_1e_neg7, "1e-7", "1e-7 MUST format with 'e-' notation");

    // 5e-7
    let v_5e_neg7 = json!(5e-7);
    let s_5e_neg7 = canonicalize_jcs_string(&v_5e_neg7).unwrap();
    assert_eq!(s_5e_neg7, "5e-7", "5e-7 MUST format with 'e-' notation");

    // 1e-8
    let v_1e_neg8 = json!(1e-8);
    let s_1e_neg8 = canonicalize_jcs_string(&v_1e_neg8).unwrap();
    assert_eq!(s_1e_neg8, "1e-8", "1e-8 MUST format with 'e-' notation");

    // Boundary: 1e-6 (magnitude == 1e-6, NOT < 1e-6) formats as standard decimal
    let v_1e_neg6 = json!(1e-6);
    let s_1e_neg6 = canonicalize_jcs_string(&v_1e_neg6).unwrap();
    assert_eq!(s_1e_neg6, "0.000001", "1e-6 formats as '0.000001'");
}

/// Vector 2d: Test negative large floats.
/// Casting negative large floats to i64 previously saturated to i64::MIN (-9223372036854775808).
#[test]
fn test_adversarial_jcs_negative_large_floats() {
    const I64_MIN_STR: &str = "-9223372036854775808";

    // -1e19
    let v_neg_1e19 = json!(-1e19);
    let s_neg_1e19 = canonicalize_jcs_string(&v_neg_1e19).unwrap();
    assert_ne!(
        s_neg_1e19, I64_MIN_STR,
        "-1e19 MUST NOT saturate to i64::MIN"
    );
    assert_eq!(s_neg_1e19, "-10000000000000000000");

    // -9.5e18
    let v_neg_9_5e18 = json!(-9.5e18);
    let s_neg_9_5e18 = canonicalize_jcs_string(&v_neg_9_5e18).unwrap();
    assert_ne!(
        s_neg_9_5e18, I64_MIN_STR,
        "-9.5e18 MUST NOT saturate to i64::MIN"
    );
    assert_eq!(s_neg_9_5e18, "-9500000000000000000");

    // -1e20
    let v_neg_1e20 = json!(-1e20);
    let s_neg_1e20 = canonicalize_jcs_string(&v_neg_1e20).unwrap();
    assert_ne!(
        s_neg_1e20, I64_MIN_STR,
        "-1e20 MUST NOT saturate to i64::MIN"
    );
    assert_eq!(s_neg_1e20, "-100000000000000000000");

    // -1e21 -> "-1e+21"
    let v_neg_1e21 = json!(-1e21);
    let s_neg_1e21 = canonicalize_jcs_string(&v_neg_1e21).unwrap();
    assert_eq!(s_neg_1e21, "-1e+21");

    // -1e-7 -> "-1e-7"
    let v_neg_1e_neg7 = json!(-1e-7);
    let s_neg_1e_neg7 = canonicalize_jcs_string(&v_neg_1e_neg7).unwrap();
    assert_eq!(s_neg_1e_neg7, "-1e-7");
}

/// Vector 2e: Residual risk boundary probe at 2^63 (9223372036854775808.0).
/// Investigates IEEE 754 precision boundary where i64::MAX as f64 rounds up to 2^63.
/// Documents the exact single-point edge condition in format_ecma_float.
#[test]
fn test_residual_risk_ieee754_exact_2pow63_boundary() {
    let f_2pow63: f64 = 9223372036854775808.0;
    let i64_max_as_f64 = i64::MAX as f64;
    assert_eq!(
        i64_max_as_f64, f_2pow63,
        "i64::MAX as f64 rounds up to 2^63"
    );

    let val = json!(f_2pow63);
    let serialized = canonicalize_jcs_string(&val).unwrap();
    assert_ne!(
        serialized, "9223372036854775807",
        "2^63 MUST NOT saturate to i64::MAX"
    );
    assert_eq!(
        serialized, "9223372036854775808",
        "2^63 MUST format exactly as '9223372036854775808'"
    );

    let val_neg = json!(-f_2pow63);
    let serialized_neg = canonicalize_jcs_string(&val_neg).unwrap();
    assert_eq!(
        serialized_neg, "-9223372036854775808",
        "-2^63 MUST format exactly as '-9223372036854775808'"
    );
}

/// Vector 2f: Test composite nested payload serialization and cryptographic digest stability.
#[test]
fn test_adversarial_jcs_composite_payload_digest_stability() {
    use sha2::{Digest, Sha256};

    let payload = json!({
        "directive": "QUARANTINE_ADVERSARIAL",
        "actor": {
            "name": "challenger_m1_it2",
            "session_id": "01234567-89ab-cdef-0123-456789abcdef"
        },
        "metrics": {
            "large_exposure": 1e19,
            "threshold_limit": 1e20,
            "scientific_upper": 1e21,
            "drift_epsilon": 1e-7,
            "negative_offset": -1e19
        },
        "flags": [true, false, null]
    });

    let canonical_str = canonicalize_jcs_string(&payload).unwrap();

    // Verify properties of canonical output
    assert!(canonical_str.contains(r#""large_exposure":10000000000000000000"#));
    assert!(canonical_str.contains(r#""threshold_limit":100000000000000000000"#));
    assert!(canonical_str.contains(r#""scientific_upper":1e+21"#));
    assert!(canonical_str.contains(r#""drift_epsilon":1e-7"#));
    assert!(canonical_str.contains(r#""negative_offset":-10000000000000000000"#));

    // Digest determinism
    let mut hasher = Sha256::new();
    hasher.update(canonical_str.as_bytes());
    let digest1 = format!("{:x}", hasher.finalize());

    let canonical_bytes = canonicalize_jcs(&payload).unwrap();
    let mut hasher2 = Sha256::new();
    hasher2.update(&canonical_bytes);
    let digest2 = format!("{:x}", hasher2.finalize());

    assert_eq!(
        digest1, digest2,
        "Byte and string canonicalization digests MUST match exactly"
    );
}
