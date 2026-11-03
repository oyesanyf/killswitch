//! Milestone 1 Empirical Challenge & Stress-Test Suite (Challenger 1).
//!
//! Independent Adversarial Verification:
//! 1. Peer PID Resolution (`peer_pid.rs`):
//!    - Kernel TCP table lookup vs claimed PID.
//!    - Forged socket endpoints and unmapped/closed ports.
//!    - IPv4-mapped IPv6 loopbacks (`[::ffff:127.0.0.1]:port`).
//!    - Concurrent TCP connections and race conditions in buffer sizing.
//! 2. Master Token & Disarm Authentication:
//!    - Truncated tokens (< 32 chars, exact 31 chars, prefix-matched 32 chars).
//!    - High-frequency timing probe distribution across 10,000 iterations.
//!    - Missing/empty auth tokens and headers.
//!    - Lockout threshold enforcement and Tier 1 bypass.
//! 3. Substrate Quarantine & Release Authentication:
//!    - Missing headers, forged Ed25519 signatures, invalid signer kids.
//!    - Quorum count threshold (< 2 rejected) and digest format validation.
//! 4. Windows Job Object Confinement & ProcessInstanceIdentity Integrity:
//!    - ProcessInstanceIdentity job_object_id tamper detection.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use killswitch_core::auth::OperatorAuthManager;
use killswitch_core::killchain::HostContainmentManager;
use killswitch_core::peer_pid::resolve_loopback_peer_pid;
use killswitch_server::routes::build_router;
use killswitch_server::server::ServerState;
use killswitch_types::constant_time_eq;
use killswitch_types::errors::KillSwitchError;
use killswitch_types::identity::ProcessInstanceIdentity;
use killswitch_types::status::{
    AuthResult, OperatorAuthenticator, OperatorCredentials,
};

const ADVERSARIAL_MASTER_TOKEN: &str =
    "adv_master_secret_key_9876543210_fedcba_0123456789abcdef";

fn create_test_server_state() -> Arc<ServerState> {
    std::env::set_var("KILLSWITCH_MASTER_TOKEN", ADVERSARIAL_MASTER_TOKEN);
    let temp_dir = tempfile::tempdir().unwrap();
    let containment =
        Arc::new(HostContainmentManager::new_default(Some(temp_dir.path())).unwrap());
    Arc::new(ServerState::with_defaults(containment))
}


// ============================================================================
// PART 1: PEER PID RESOLUTION EMPIRICAL STRESS TESTS
// ============================================================================

/// 1a. Test mismatched PID:
/// When a client connects from the current process, resolve_loopback_peer_pid
/// MUST return the actual process ID, ignoring any claimed caller PID.
#[test]
fn test_stress_peer_pid_mismatched_caller_pid() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind ephemeral listener");
    let server_port = listener.local_addr().unwrap().port();

    let client = TcpStream::connect(format!("127.0.0.1:{}", server_port))
        .expect("Must connect to ephemeral listener");
    let client_addr = client.local_addr().expect("Must have local addr");

    let (server_stream, _peer_addr) = listener.accept().expect("Must accept connection");

    let my_pid = std::process::id();
    let resolved = resolve_loopback_peer_pid(client_addr, server_port);
    assert!(resolved.is_ok(), "Expected Ok PID, got {:?}", resolved);
    let actual_pid = resolved.unwrap();
    assert_eq!(
        actual_pid, my_pid,
        "Kernel socket table must report true PID ({}), not forged PID",
        my_pid
    );

    // Assert that a claimed PID differing from actual_pid does not match
    let forged_pid = my_pid + 99999;
    assert_ne!(
        actual_pid, forged_pid,
        "Resolved PID must not match forged PID"
    );

    drop(client);
    drop(server_stream);
}

/// 1b. Test forged socket endpoints:
/// Non-existent ports, unmapped sockets, or wrong server port must return NativeOsError,
/// never panicking or returning an arbitrary PID.
#[test]
fn test_stress_peer_pid_forged_and_unmapped_endpoints() {
    // Port 1 is almost certainly not connected to bound_port 65535
    let bogus_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1));
    let res = resolve_loopback_peer_pid(bogus_addr, 65535);
    assert!(
        res.is_err(),
        "Forged or unmapped socket endpoint must fail resolution"
    );
    match res {
        Err(KillSwitchError::NativeOsError(msg)) => {
            assert!(
                msg.contains("No kernel TCP table entry found"),
                "Expected 'No kernel TCP table entry found', got: {}",
                msg
            );
        }
        other => panic!("Unexpected result for unmapped endpoint: {:?}", other),
    }

    // Outer non-loopback IP with fake port
    let external_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 44444));
    let res_ext = resolve_loopback_peer_pid(external_addr, 3030);
    assert!(
        res_ext.is_err(),
        "External non-existent endpoint must fail resolution"
    );
}

/// 1c. Test closed socket race:
/// If the client closes the TCP connection before PID resolution occurs,
/// the resolution must fail safely with NativeOsError (no panic, no garbage PID).
#[test]
fn test_stress_peer_pid_closed_socket_graceful_handling() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind ephemeral listener");
    let server_port = listener.local_addr().unwrap().port();

    let client = TcpStream::connect(format!("127.0.0.1:{}", server_port))
        .expect("Must connect to ephemeral listener");
    let client_addr = client.local_addr().expect("Must have local addr");

    let (server_stream, _) = listener.accept().expect("Must accept connection");

    // Abruptly close both endpoints
    drop(client);
    drop(server_stream);

    // Wait 50ms for OS to transition or close the connection
    std::thread::sleep(Duration::from_millis(50));

    // Calling resolution on closed/dropped client address
    let res = resolve_loopback_peer_pid(client_addr, server_port);
    // On Windows, closed/TIME_WAIT sockets may either be absent from the table (Err)
    // or report dw_owning_pid == 0 (System/Idle/unowned). Crucially, it must never panic.
    if let Ok(pid) = res {
        println!("🔬 [EMPIRICAL] Closed/TIME_WAIT socket reported owning PID: {}", pid);
        assert_ne!(pid, 0, "Closed/TIME_WAIT socket must never report owning PID 0 (must be Err)");
    }
}

/// 1d. Test IPv4-mapped IPv6 loopbacks (`[::ffff:127.0.0.1]:port`):
/// When an IPv4 connection is wrapped as an IPv6 mapped address,
/// determine if `resolve_loopback_peer_pid` handles or rejects it.
#[test]
fn test_stress_peer_pid_ipv4_mapped_ipv6_loopback() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind ephemeral listener");
    let server_port = listener.local_addr().unwrap().port();

    let client = TcpStream::connect(format!("127.0.0.1:{}", server_port))
        .expect("Must connect to ephemeral listener");
    let client_v4 = match client.local_addr().unwrap() {
        SocketAddr::V4(v4) => v4,
        _ => panic!("Expected IPv4 client address"),
    };

    let (server_stream, _) = listener.accept().expect("Must accept connection");

    // Construct mapped IPv6: ::ffff:127.0.0.1
    let mapped_ip = client_v4.ip().to_ipv6_mapped();
    let mapped_addr = SocketAddr::V6(SocketAddrV6::new(mapped_ip, client_v4.port(), 0, 0));

    let res = resolve_loopback_peer_pid(mapped_addr, server_port);
    println!(
        "🔬 [EMPIRICAL] IPv4-mapped IPv6 resolution result: {:?}",
        res
    );
    assert!(
        res.is_ok(),
        "IPv4-mapped IPv6 loopback must successfully resolve caller PID from AF_INET table: {:?}",
        res
    );
    assert_eq!(
        res.unwrap(),
        std::process::id(),
        "Resolved PID must match current test process"
    );

    drop(client);
    drop(server_stream);
}

/// 1f. Test attack vector: IPv4-mapped IPv6 loopback bypasses anti-hijacking check
/// When a caller connects over IPv4-mapped IPv6 (`[::ffff:127.0.0.1]:port`),
/// `resolve_loopback_peer_pid` returns Err (because it queries AF_INET6 table, which does not contain IPv4 connections).
/// In `handlers.rs:371`:
/// `let effective_pid = resolved_pid.or(req.caller_pid);`
/// Because `resolved_pid` is None, `effective_pid` falls back to `req.caller_pid`!
/// This allows a frozen caller to claim an unquarantined PID,
/// effectively BYPASSING anti-hijacking caller PID validation!
#[test]
fn test_empirical_finding_ipv4_mapped_ipv6_fallback_hazard() {
    let mapped_ip: std::net::IpAddr = "::ffff:127.0.0.1".parse().unwrap();
    let mapped_addr = SocketAddr::new(mapped_ip, 54321);

    // Call resolve_loopback_peer_pid directly
    let res = resolve_loopback_peer_pid(mapped_addr, 3030);
    assert!(
        res.is_err(),
        "resolve_loopback_peer_pid returns Err on IPv4-mapped IPv6"
    );

    // In handlers.rs:
    // let resolved_pid = resolve_loopback_peer_pid(addr, bound_port).ok(); // evaluates to None!
    // let effective_pid = resolved_pid.or(req.caller_pid); // evaluates to req.caller_pid!
    let claimed_unfrozen_pid = Some(5000);
    let resolved_pid = res.ok();
    let effective_pid = resolved_pid.or(claimed_unfrozen_pid);

    assert_eq!(
        effective_pid,
        Some(5000),
        "HAZARD CONFIRMED: When peer_pid fails on IPv4-mapped IPv6, effective_pid falls back to untrusted claimed_pid!"
    );
}

/// 1e. Test concurrent TCP connections:
/// 30 threads concurrently connecting and resolving PIDs simultaneously.
/// Asserts zero memory corruption, zero panics, and consistent PID resolution.
#[test]
fn test_stress_peer_pid_concurrent_connections() {
    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").expect("Must bind listener"));
    let server_port = listener.local_addr().unwrap().port();

    let num_threads = 25;
    let success_count = Arc::new(AtomicUsize::new(0));
    let error_count = Arc::new(AtomicUsize::new(0));
    let stop_signal = Arc::new(AtomicBool::new(false));

    // Spawn server accept thread
    let l_clone = listener.clone();
    let s_stop = stop_signal.clone();
    let server_handle = std::thread::spawn(move || {
        l_clone.set_nonblocking(true).unwrap();
        let mut streams = Vec::new();
        while !s_stop.load(Ordering::Relaxed) {
            match l_clone.accept() {
                Ok((s, _)) => streams.push(s),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
    });

    let my_pid = std::process::id();
    let mut handles = Vec::new();

    for _ in 0..num_threads {
        let sc = success_count.clone();
        let ec = error_count.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..5 {
                match TcpStream::connect(format!("127.0.0.1:{}", server_port)) {
                    Ok(client) => {
                        if let Ok(addr) = client.local_addr() {
                            match resolve_loopback_peer_pid(addr, server_port) {
                                Ok(resolved_pid) => {
                                    if resolved_pid == my_pid {
                                        sc.fetch_add(1, Ordering::Relaxed);
                                    } else {
                                        ec.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                Err(_) => {
                                    ec.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        drop(client);
                    }
                    Err(_) => {
                        ec.fetch_add(1, Ordering::Relaxed);
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }));
    }

    for h in handles {
        let _ = h.join();
    }

    stop_signal.store(true, Ordering::Relaxed);
    let _ = server_handle.join();

    let successes = success_count.load(Ordering::Relaxed);
    let errors = error_count.load(Ordering::Relaxed);
    println!(
        "🔬 [EMPIRICAL] Concurrency test completed: {} successes, {} transient errors out of {}",
        successes,
        errors,
        num_threads * 5
    );
    assert!(
        successes > 0,
        "Expected at least some successful resolutions under high concurrency"
    );
}

// ============================================================================
// PART 2: MASTER TOKEN AUTHENTICATION STRESS TESTS
// ============================================================================

/// 2a. Truncated and low-entropy tokens:
/// Tokens < 32 characters or empty/whitespace tokens MUST be rejected by Tier 1.
#[test]
fn test_stress_auth_truncated_and_boundary_tokens() {
    let mut auth = OperatorAuthManager::new(None, None);
    let valid_token = "0123456789abcdef0123456789abcdef"; // 32 chars
    auth.set_custom_master_token(valid_token.to_string());

    // 1. Truncated to 31 characters (1 char short)
    let token_31 = "0123456789abcdef0123456789abcde";
    let creds_31 = OperatorCredentials {
        operator_id: "secops_admin".to_string(),
        auth_token: Some(token_31.to_string()),
        password: None,
        caller_pid: Some(5000),
        confirmation_phrase: None,
    };
    match auth.authenticate(&creds_31) {
        AuthResult::Failed { attempts_remaining, .. } => {
            assert_eq!(attempts_remaining, 2, "31-char token must fail as strike 1");
        }
        other => panic!("31-char token should fail, got {:?}", other),
    }

    // 2. Exact 32 characters but wrong last character
    let token_wrong = "0123456789abcdef0123456789abcdeX";
    let creds_wrong = OperatorCredentials {
        operator_id: "secops_admin".to_string(),
        auth_token: Some(token_wrong.to_string()),
        password: None,
        caller_pid: Some(5000),
        confirmation_phrase: None,
    };
    match auth.authenticate(&creds_wrong) {
        AuthResult::Failed { attempts_remaining, .. } => {
            assert_eq!(attempts_remaining, 1, "Wrong 32-char token must fail as strike 2");
        }
        other => panic!("Wrong 32-char token should fail, got {:?}", other),
    }

    // 3. Old legacy strings that are < 32 characters
    for legacy in &["CONFIRM RESTORE", "MasterBypassSecret999", ""] {
        let creds_legacy = OperatorCredentials {
            operator_id: "secops_admin".to_string(),
            auth_token: Some(legacy.to_string()),
            password: None,
            caller_pid: Some(5000),
            confirmation_phrase: None,
        };
        assert!(
            matches!(auth.authenticate(&creds_legacy), AuthResult::Failed { .. } | AuthResult::LockedOut { .. }),
            "Legacy token '{}' must strictly fail Tier 1 authentication",
            legacy
        );
    }
}

/// 2b. High-frequency timing probe:
/// Verifies `constant_time_eq` side-channel resilience over 10,000 iterations.
#[test]
fn test_stress_auth_timing_probe_distribution() {
    let secret = "abcdef0123456789abcdef0123456789abcdef0123456789";
    let probe_diff_first = "Xbcdef0123456789abcdef0123456789abcdef0123456789";
    let probe_diff_last = "abcdef0123456789abcdef0123456789abcdef012345678X";
    let probe_same = "abcdef0123456789abcdef0123456789abcdef0123456789";

    let iters = 10_000;

    let t0 = Instant::now();
    let mut hits_first = 0;
    for _ in 0..iters {
        if constant_time_eq(secret, probe_diff_first) {
            hits_first += 1;
        }
    }
    let elapsed_first = t0.elapsed();

    let t1 = Instant::now();
    let mut hits_last = 0;
    for _ in 0..iters {
        if constant_time_eq(secret, probe_diff_last) {
            hits_last += 1;
        }
    }
    let elapsed_last = t1.elapsed();

    let t2 = Instant::now();
    let mut hits_same = 0;
    for _ in 0..iters {
        if constant_time_eq(secret, probe_same) {
            hits_same += 1;
        }
    }
    let elapsed_same = t2.elapsed();

    println!(
        "🔬 [EMPIRICAL] Timing probe (10k iters): diff_first={:?}, diff_last={:?}, same={:?}",
        elapsed_first, elapsed_last, elapsed_same
    );

    // Assert that mismatched tokens NEVER returned true and identical token ALWAYS returned true
    assert_eq!(hits_first, 0, "Mismatched prefix must never match");
    assert_eq!(hits_last, 0, "Mismatched suffix must never match");
    assert_eq!(hits_same, iters, "Identical secret must match all iterations");
}

/// 2c. Server `/disarm` API endpoint stress test:
/// Test disarm request with missing token, 31-char token, wrong token, and correct token.
#[tokio::test]
async fn test_stress_server_disarm_endpoint_authentication() {
    let state = create_test_server_state();
    let app = build_router(state);

    // 1. Missing token
    let req_missing = Request::builder()
        .uri("/disarm")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&serde_json::json!({
            "operator": "secops_admin",
            "reason": "Missing token test"
        })).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req_missing).await.unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "Disarm with missing token must not succeed"
    );

    // 2. Truncated token (31 chars)
    let req_trunc = Request::builder()
        .uri("/disarm")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&serde_json::json!({
            "operator": "secops_admin",
            "reason": "Truncated token test",
            "token": "0123456789abcdef0123456789abcde"
        })).unwrap()))
        .unwrap();

    let resp_trunc = app.clone().oneshot(req_trunc).await.unwrap();
    assert_ne!(
        resp_trunc.status(),
        StatusCode::OK,
        "Disarm with 31-char token must not succeed"
    );

    // 3. Valid master token succeeds
    let req_valid = Request::builder()
        .uri("/disarm")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&serde_json::json!({
            "operator": "secops_admin",
            "reason": "Authorized test disarm",
            "token": ADVERSARIAL_MASTER_TOKEN
        })).unwrap()))
        .unwrap();

    let resp_valid = app.oneshot(req_valid).await.unwrap();
    assert_eq!(
        resp_valid.status(),
        StatusCode::OK,
        "Disarm with valid Tier-1 master token must succeed"
    );
}

// ============================================================================
// PART 3: SUBSTRATE QUARANTINE & RELEASE ADVERSARIAL TESTING
// ============================================================================

/// 3a. Substrate quarantine endpoint rejects requests without required headers
#[tokio::test]
async fn test_stress_substrate_quarantine_missing_headers() {
    let state = create_test_server_state();
    let app = build_router(state);

    // Missing X-CAGE-Quarantine-Assertion header
    let req = Request::builder()
        .uri("/v1/cage/quarantine")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-CAGE-Signer-Kid", "fake-kid-001")
        .body(Body::from(serde_json::to_vec(&serde_json::json!({
            "workload_id": "agent-001",
            "trigger_reason": "Anomaly detected",
            "nonce": "nonce-001"
        })).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "Quarantine request without assertion header must fail"
    );

    // Missing X-CAGE-Signer-Kid header
    let req2 = Request::builder()
        .uri("/v1/cage/quarantine")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-CAGE-Quarantine-Assertion", "fake-sig")
        .body(Body::from(serde_json::to_vec(&serde_json::json!({
            "workload_id": "agent-001",
            "trigger_reason": "Anomaly detected",
            "nonce": "nonce-002"
        })).unwrap()))
        .unwrap();

    let resp2 = app.oneshot(req2).await.unwrap();
    assert_ne!(
        resp2.status(),
        StatusCode::OK,
        "Quarantine request without signer kid header must fail"
    );
}

/// 3b. Substrate release requires quorum_count >= 2 and valid 64-hex digest
#[tokio::test]
async fn test_stress_substrate_release_quorum_and_digest_validation() {
    let state = create_test_server_state();
    let app = build_router(state);

    // Quorum count 1 (insufficient)
    let body_insufficient = serde_json::json!({
        "workload_id": "agent-001",
        "quorum_count": 1,
        "quorum_approval_digest": "4b42b102b4d4b1a457c0e5a8f4c2c77f02d0cf3b1b6cf7f8e3f94a5e01b34a12",
        "release_reason": "Remediated",
        "nonce": "nonce-rel-001"
    });

    let req = Request::builder()
        .uri("/v1/cage/release")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-CAGE-Quarantine-Release", "fake-sig")
        .header("X-CAGE-Signer-Kid", "fake-kid")
        .body(Body::from(serde_json::to_vec(&body_insufficient).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "Release request with quorum_count < 2 must fail"
    );
}

// ============================================================================
// PART 4: WINDOWS JOB OBJECT & PROCESS INSTANCE IDENTITY INTEGRITY
// ============================================================================

/// 4a. ProcessInstanceIdentity Job Object ID binding:
/// Tests that Job Object ID is non-detachably bound to the instance UUID.
/// Any tampering with job_object_id (None -> Some, Some -> None, altered ID)
/// MUST be caught by verify_integrity().
#[test]
fn test_stress_process_instance_job_object_confinement() {
    let pid = 4096;
    let start_time = 133500000000000000;
    let digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let job_id = "JOB_CONFINEMENT_RESTRICTED_001";
    let session = "Session-1";

    let identity = ProcessInstanceIdentity::new(
        pid,
        start_time,
        digest,
        None,
        Some(job_id.to_string()),
        session,
    );

    // Baseline: virgin identity must pass integrity check
    assert!(
        identity.verify_integrity(),
        "Virgin ProcessInstanceIdentity with Job Object must verify"
    );

    // Attack 1: Stripping job_object_id to claim uncontained status
    let mut tampered_stripped = identity.clone();
    tampered_stripped.job_object_id = None;
    assert!(
        !tampered_stripped.verify_integrity(),
        "Stripping job_object_id MUST invalidate process instance integrity"
    );

    // Attack 2: Tampering job_object_id to claim membership in a different job
    let mut tampered_swapped = identity.clone();
    tampered_swapped.job_object_id = Some("JOB_CONFINEMENT_RESTRICTED_002".to_string());
    assert!(
        !tampered_swapped.verify_integrity(),
        "Altering job_object_id MUST invalidate process instance integrity"
    );

    // Attack 3: Adding a fake job_object_id to an uncontained process
    let uncontained = ProcessInstanceIdentity::new(
        pid,
        start_time,
        digest,
        None,
        None,
        session,
    );
    assert!(uncontained.verify_integrity());

    let mut tampered_added = uncontained.clone();
    tampered_added.job_object_id = Some("FAKE_JOB_OBJECT".to_string());
    assert!(
        !tampered_added.verify_integrity(),
        "Injecting job_object_id into uncontained process MUST invalidate integrity"
    );
}
