# E2E Test Infrastructure: Standalone Cross-Platform Rust KillSwitch Security Agent

## Document Metadata
- **Project**: Standalone Cross-Platform (Windows & Linux) Rust KillSwitch Security Agent Workspace
- **Workspace Root**: `d:\harfile\killswitch`
- **Role**: E2E Test Suite Architect
- **Authoritative Sources**: `ORIGINAL_REQUEST.md` (Requirements R1–R4), `PROJECT.md` (Architecture, Feature Inventory 1–28, Interface Contracts)
- **Specification Status**: Active / Definitive Design

---

## 1. Test Philosophy & Architectural Invariants

### 1.1 Opaque-Box & Requirement-Driven Testing
All tests in the E2E test suite are strictly opaque-box (black-box) and requirement-driven. Tests verify external observable behavior, public API contracts, system state transitions, network packet disposition, process scheduling states, cryptographic ledger records, and CLI/HTTP interactions. Test logic derives exclusively from user requirements in `ORIGINAL_REQUEST.md` and system invariants in `PROJECT.md`, without coupling to internal crate private functions, helper structs, or transient code details.

### 1.2 Zero-OS-Tool Native Invariant
The KillSwitch workspace operates under a strict Zero-OS-Tool law:
- Under **no circumstances** may containment, firewalling, process management, or authentication spawn external OS command-line utilities.
- Prohibited tools include: `netsh`, `iptables`, `nft`, `taskkill`, `kill`, `powershell`, `cmd`, `sh`, `bash`, `unix_chkpwd`, `dscl`, `LogonUserW`.
- All operations must execute through direct OS kernel/syscall APIs:
  - Windows: `fwpuclnt.dll` (WFP dynamic sessions), `iphlpapi.dll` (`SetTcpEntry`), `winreg` (BFE registry), `ntdll.dll` (`NtSuspendProcess`, `NtResumeProcess`), WinTrust (`WinVerifyTrust`).
  - Linux: Netlink raw sockets (`AF_NETLINK`, `NETLINK_NETFILTER`), Landlock LSM syscalls, `/proc/net/tcp`, `libc::kill(pid, SIGSTOP/SIGCONT)`, `/etc/shadow` `crypt(3)` FFI.
  - Rust Standard / Pure Cryptography: `subtle::ConstantTimeEq`, `blake3`, `ring` / `hmac-sha256`.

### 1.3 "Never Wrong" Zero-False-Positive Invariant
- A false positive that isolates critical system infrastructure or developer tools is treated as a critical system defect.
- Critical processes (`explorer.exe`, `svchost.exe`, `lsass.exe`, `dwm.exe`, `systemd`, `sshd`, `cargo`, `rustc`, `code.exe`, `antigravity.exe`), current execution PID, and parent process ancestry up to depth 5 are protected by an inalienable veto.
- Any peer candidate targeting a protected binary hash or critical PID must be deterministically rejected with a cryptographically sealed `ByzantineKillSwitchFraudProof`.

### 1.4 Production Code & Zero-Mock Invariant
Tests must never execute against hardcoded dummy personas, stubbed fake sockets, or mock detection rules. All tests exercise real network interfaces (using loopback `127.0.0.1` and bound test listeners), genuine suspended threads/processes, real cryptographic calculations, and genuine Axum HTTP endpoints.

### 1.5 Environmental Safety & PATH Protection
- No test or build script may overwrite, append to, or truncate user or machine environment variables (`HKCU\Environment`, `HKLM\SYSTEM\...\Environment`, `setx`).
- All environment manipulations must be process-scoped (`std::env::set_var`).
- Every test must employ an RAII guard (`EmpiricalStressTestGuard`) that records registry and environment state at initialization, ensures unauthenticated disarm on teardown, and asserts zero registry drift upon drop.

---

## 2. Feature Inventory & 4-Tier Master Mapping Matrix

Every feature from `PROJECT.md § Feature Inventory` (Features 1 through 28) is systematically mapped across all 4 testing tiers plus specialized acceptance suites.

| Feature # | Feature Name | Requirement Source | Tier 1 (>=5) | Tier 2 (>=5) | Tier 3 (Pairwise) | Tier 4 (Scenario) | Specialized Suite |
|:---------:|:-------------|:-------------------|:------------:|:------------:|:-----------------:|:-----------------:|:-----------------:|
| **F01** | Workspace Cargo & Types | ORIGINAL_REQUEST §R1-R4 | 5 | 5 | T3_PAIR_01 | S1, S2, S3, S4, S5 | `zero_os_tool_audit` |
| **F02** | Windows Native WFP Isolation | ORIGINAL_REQUEST §R1 | 5 | 5 | T3_PAIR_01, T3_PAIR_02 | S1, S2, S5 | `zero_os_tool_audit` |
| **F03** | Windows Native BFE Registry | ORIGINAL_REQUEST §R1 | 5 | 5 | T3_PAIR_02 | S5 | `zero_os_tool_audit` |
| **F04** | Windows Direct TCP Reset | ORIGINAL_REQUEST §R1 | 5 | 5 | T3_PAIR_03 | S1, S2 | `zero_os_tool_audit` |
| **F05** | Linux Netlink & Landlock Isolation | ORIGINAL_REQUEST §R1 | 5 | 5 | T3_PAIR_27 | S1, S5 | `zero_os_tool_audit` |
| **F06** | Native Process Freeze & Resume | ORIGINAL_REQUEST §R1 | 5 | 5 | T3_PAIR_01, T3_PAIR_04 | S1, S2 | `never_wrong_veto_suite` |
| **F07** | Active Process Tarpit | ORIGINAL_REQUEST §R1 | 5 | 5 | T3_PAIR_04 | S2 | `never_wrong_veto_suite` |
| **F08** | Operator Credential Verification | ORIGINAL_REQUEST §R1 | 5 | 5 | T3_PAIR_05, T3_PAIR_26 | S5 | `anti_lockout_suite` |
| **F09** | Anti-Lockout & Caller Validation | ORIGINAL_REQUEST §R1 | 5 | 5 | T3_PAIR_05, T3_PAIR_06 | S4, S5 | `anti_lockout_suite` |
| **F10** | BLAKE3 State Ledger | ORIGINAL_REQUEST §R3 | 5 | 5 | T3_PAIR_03, T3_PAIR_07, T3_PAIR_20 | S1, S2, S5 | `never_wrong_veto_suite` |
| **F11** | REA Adjudication Engine | ORIGINAL_REQUEST §R2 | 5 | 5 | T3_PAIR_08, T3_PAIR_09 | S1, S3 | `never_wrong_veto_suite` |
| **F12** | Multi-Voter Consensus | ORIGINAL_REQUEST §R2 | 5 | 5 | T3_PAIR_08, T3_PAIR_10, T3_PAIR_23 | S1, S3, S4 | `never_wrong_veto_suite` |
| **F13** | Authenticode & Catalog Validation | ORIGINAL_REQUEST §R2 | 5 | 5 | T3_PAIR_11 | S3 | `never_wrong_veto_suite` |
| **F14** | Protected Binary Inventory & Lineage | ORIGINAL_REQUEST §R2 | 5 | 5 | T3_PAIR_09, T3_PAIR_11, T3_PAIR_12 | S3, S4 | `never_wrong_veto_suite` |
| **F15** | Byzantine Fraud Proof Builder | ORIGINAL_REQUEST §R2 | 5 | 5 | T3_PAIR_12, T3_PAIR_13 | S4 | `never_wrong_veto_suite` |
| **F16** | EDR Phase-Lock Monitor | ORIGINAL_REQUEST §R2 | 5 | 5 | T3_PAIR_10, T3_PAIR_14 | S1 | - |
| **F17** | Causal & Attack Graph Correlation | ORIGINAL_REQUEST §R2 | 5 | 5 | T3_PAIR_14, T3_PAIR_15 | S1, S2 | - |
| **F18** | Canaries, Watchdog & Honeytokens | ORIGINAL_REQUEST §R2 | 5 | 5 | T3_PAIR_15, T3_PAIR_16 | S2 | - |
| **F19** | Octopus Arm Containment Ring | ORIGINAL_REQUEST §R2 | 5 | 5 | T3_PAIR_16, T3_PAIR_17 | S1, S4 | - |
| **F20** | MeshGuard & Boundary Audit | ORIGINAL_REQUEST §R2 | 5 | 5 | T3_PAIR_13, T3_PAIR_17, T3_PAIR_18 | S4 | - |
| **F21** | Breakout Defense & SSRF / Path Guards | ORIGINAL_REQUEST §R2 | 5 | 5 | T3_PAIR_18, T3_PAIR_19, T3_PAIR_20 | S1, S4 | - |
| **F22** | Native Rust LangGraph StateGraph | ORIGINAL_REQUEST §R2 | 5 | 5 | T3_PAIR_21, T3_PAIR_22 | S1, S5 | - |
| **F23** | Local Ollama Reasoning Node | ORIGINAL_REQUEST §R2 | 5 | 5 | T3_PAIR_21, T3_PAIR_23 | S1 | - |
| **F24** | Autonomous & Manual Reversible Modes | ORIGINAL_REQUEST §R3 | 5 | 5 | T3_PAIR_06, T3_PAIR_07, T3_PAIR_22, T3_PAIR_24 | S1, S5 | `anti_lockout_suite` |
| **F25** | Local HTTP/JSON API on Port 3030 | ORIGINAL_REQUEST §R3 | 5 | 5 | T3_PAIR_02, T3_PAIR_19, T3_PAIR_25 | S1, S5 | `anti_lockout_suite` |
| **F26** | CLI Binary Interface | ORIGINAL_REQUEST §R3 | 5 | 5 | T3_PAIR_25, T3_PAIR_26 | S5 | `zero_os_tool_audit` |
| **F27** | Opaque-Box E2E Testing Suite (T1-4) | ORIGINAL_REQUEST §Acceptance | 5 | 5 | T3_PAIR_28 | S1-S6 | All Suites |
| **F28** | Adversarial Coverage Hardening (T5) | ORIGINAL_REQUEST §Acceptance | 5 | 5 | T3_PAIR_28 | S1-S6 | All Suites |
| **F29** | macOS Native PF Isolation | ORIGINAL_REQUEST §Follow-up | 5 | 5 | T3_PAIR_29 | S1, S5 | `zero_os_tool_audit` |
| **F30** | macOS Process Freeze & System Whitelist | ORIGINAL_REQUEST §Follow-up | 5 | 5 | T3_PAIR_30 | S3 | `never_wrong_veto_suite` |
| **F31** | Native OS Service Lifecycle & Auto-Disarm | ORIGINAL_REQUEST §Follow-up | 5 | 5 | T3_PAIR_31 | S6 | `zero_os_tool_audit`, `anti_lockout_suite` |
| **F32** | OpenTelemetry & OpenLineage DLP Engine | ORIGINAL_REQUEST §Follow-up #2 | 5 | 5 | T3_PAIR_32 | S7 | `zero_os_tool_audit`, `anti_lockout_suite` |
| **F33** | Unified `start.exe` All-In-One Loader | ORIGINAL_REQUEST §Follow-up #4 | 5 | 5 | T3_PAIR_33 | S8 | `zero_os_tool_audit`, `anti_lockout_suite` |
| **F34** | Automatic Port Fallback & Dynamic Allowlist | ORIGINAL_REQUEST §Follow-up #5 | 5 | 5 | T3_PAIR_34 | S9 | `anti_lockout_suite` |

### Quantitative Summary of Test Inventory:
- **Tier 1 (Feature Coverage)**: 34 features × 5 tests = **170 test cases**
- **Tier 2 (Boundary & Corner)**: 34 features × 5 tests = **170 test cases**
- **Tier 3 (Cross-Feature Combinations)**: **34 pairwise test cases**
- **Tier 4 (Real-World Application Scenarios)**: **9 end-to-end multi-stage scenarios** (including Scenario 9: Automatic Port Fallback & Dynamic Allowlist)
- **Specialized Acceptance Suites**:
  - `zero_os_tool_audit`: **5 tests**
  - `never_wrong_veto_suite`: **5 tests**
  - `anti_lockout_suite`: **5 tests**
- **Total Test Suite Volume**: **386 test cases** planned and tracked.
  - `zero_os_tool_audit`: **5 test cases**
  - `never_wrong_veto_suite`: **5 test cases**
  - `anti_lockout_suite`: **5 test cases**
- **Total Test Cases Planned**: **374 distinct test cases**

---

## 3. Tier 1: Isolated Feature Coverage Catalog (140 Test Cases)

### Feature 1: Workspace Cargo & Types (`killswitch-types`)
- `T1-F01-01`: Serialization and deserialization roundtrip for `ByzantineKillSwitchFraudProof` preserving BLAKE3 digest and signature fidelity.
- `T1-F01-02`: `BinaryTrustVerdict` variant exhaustive parsing (Authenticode, Catalog, ProtectedHash, SystemPackage, Untrusted).
- `T1-F01-03`: `KillChainStatus` JSON schema compliance asserting fields: `is_isolated`, `active_filters`, `frozen_pids`, `quarantined_arms`.
- `T1-F01-04`: `ProcessInstanceIdentity` BLAKE3 cryptographic binding across PID, process start time, and image hash.
- `T1-F01-05`: `VoteResult` and `EvidenceClass` enumeration integrity across all 6 evidence classes.

### Feature 2: Windows Native WFP Isolation (`killswitch-core`)
- `T1-F02-01`: Create dynamic WFP session with `FWPM_SESSION_FLAG_DYNAMIC` and verify handle validity.
- `T1-F02-02`: Atomic `FwpmTransactionBegin0` and `FwpmTransactionCommit0` for filter addition.
- `T1-F02-03`: Egress block filter insertion and verification of drop action on non-loopback outbound traffic.
- `T1-F02-04`: Loopback exception filter insertion permitting bidirectional `127.0.0.1` and `::1` traffic.
- `T1-F02-05`: Dynamic session drop cleanup: verify all dynamic filters automatically evaporate upon session handle closure.

### Feature 3: Windows Native BFE Registry (`killswitch-core`)
- `T1-F03-01`: Read and parse existing rules from `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules`.
- `T1-F03-02`: Insert persistent BFE rule via `winreg` preserving existing rule keys.
- `T1-F03-03`: Delete specific BFE rule via `winreg` and verify key deletion without registry corruption.
- `T1-F03-04`: Verify registry transaction rollback on failed rule injection.
- `T1-F03-05`: Validate that BFE registry manipulation does not alter system PATH or unrelated environment registry hives.

### Feature 4: Windows Direct TCP Reset (`killswitch-core`)
- `T1-F04-01`: Query TCP connection table via `iphlpapi.dll` `GetTcpTable` and verify parsed connection entries.
- `T1-F04-02`: Terminate established outbound TCP socket via `SetTcpEntry` with `MIB_TCP_STATE_DELETE_TCB = 12`.
- `T1-F04-03`: Verify loopback sockets (`127.0.0.1:3030`) are preserved and never targeted by TCP reset routine.
- `T1-F04-04`: Verify `SetTcpEntry` error code handling when connection has already transitioned to CLOSED/TIME_WAIT.
- `T1-F04-05`: Execute rapid sequential TCP resets across 50 simulated connections and verify non-blocking completion.

### Feature 5: Linux Netlink & Landlock Isolation (`killswitch-core`)
- `T1-F05-01`: Open Netlink socket (`AF_NETLINK`, `SOCK_RAW`, `NETLINK_NETFILTER`) and verify file descriptor.
- `T1-F05-02`: Parse active sockets from `/proc/net/tcp` and `/proc/net/tcp6`.
- `T1-F05-03`: Landlock ruleset creation via `landlock_create_ruleset` with TCP bind/connect restrictions.
- `T1-F05-04`: Apply `landlock_restrict_self` and assert sandboxed network capability restriction.
- `T1-F05-05`: Verify zero fork/exec subprocess calls to `iptables` or `nft` during Linux quarantine cycle.

### Feature 6: Native Process Freeze & Resume (`killswitch-core`)
- `T1-F06-01`: Windows `NtSuspendProcess` on child test process; verify CPU thread consumption drops to 0.
- `T1-F06-02`: Windows `NtResumeProcess` on child test process; verify thread execution resumes normally.
- `T1-F06-03`: Linux `libc::kill(pid, SIGSTOP)` on child test process; verify `T` (stopped) state in `/proc/<pid>/stat`.
- `T1-F06-04`: Linux `libc::kill(pid, SIGCONT)` on child test process; verify `R` (running) state restored.
- `T1-F06-05`: Freeze and resume idempotency: calling freeze twice on already-frozen process does not panic or deadlock.

### Feature 7: Active Process Tarpit (`killswitch-core`)
- `T1-F07-01`: Thread-level enumeration of target process via `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`.
- `T1-F07-02`: Apply duty-cycle throttling (e.g. 95% suspend, 5% execution) to target process threads.
- `T1-F07-03`: Measure execution slowdown factor on compute loop under tarpit throttling (> 10x slowdown).
- `T1-F07-04`: Release all threads from tarpit and verify restoration of 100% compute throughput.
- `T1-F07-05`: Verify protected system threads and debugger threads are filtered out and immune from tarpit throttling.

### Feature 8: Operator Credential Verification (`killswitch-core`)
- `T1-F08-01`: Constant-time string comparison (`subtle::ConstantTimeEq`) with matching valid operator token.
- `T1-F08-02`: Constant-time string comparison with mismatched invalid token rejecting in constant execution time.
- `T1-F08-03`: Verify BLAKE3 stored administrator password digest verification.
- `T1-F08-04`: Linux `/etc/shadow` `crypt(3)` FFI verification with valid crypt hash.
- `T1-F08-05`: Verify zero subprocess calls to `unix_chkpwd`, `dscl`, or Windows `LogonUserW`.

### Feature 9: Anti-Lockout & Caller Validation (`killswitch-core`)
- `T1-F09-01`: Successful authentication within rate-limit window resets failed attempts counter to 0.
- `T1-F09-02`: Record 3 consecutive failed authentication attempts and verify transition to Locked state.
- `T1-F09-03`: Verify that during 300-second lockout window, even valid credentials are rejected with `LockoutActive`.
- `T1-F09-04`: `validate_killchain_caller` checks caller PID: allow non-quarantined legitimate PID.
- `T1-F09-05`: `validate_killchain_caller` checks caller PID: reject frozen/quarantined PID with `CallerQuarantined`.

### Feature 10: BLAKE3 State Ledger (`killswitch-core`)
- `T1-F10-01`: Initialize atomic `killchain_state.json` with initial genesis block hash.
- `T1-F10-02`: Append state change event (e.g. `Engaged`, `PIDsFrozen`) and verify BLAKE3 hash chaining: $H_n = \text{BLAKE3}(H_{n-1} \parallel \text{Entry}_n)$.
- `T1-F10-03`: Verify cryptographic ledger integrity: detect single-bit corruption in past state entry and fail verification.
- `T1-F10-04`: Atomic write guarantee: verify temp-file write and rename avoids partial writes under simulated kill.
- `T1-F10-05`: State ledger recovery on process restart: reconstruct active quarantine state from ledger JSON.

### Feature 11: REA Adjudication Engine (`killswitch-adjudication`)
- `T1-F11-01`: Evaluate multi-signal malicious candidate through 4-layer defense: confirm candidate promotion.
- `T1-F11-02`: Evaluate developer compiler process (`cargo`, `rustc`): verify anti-masquerade dev calibration vetoes containment.
- `T1-F11-03`: Evaluate single uncorroborated anomaly signal: verify confidence threshold failure.
- `T1-F11-04`: Verify behavioral anomaly layer score weighting across file, network, and execution events.
- `T1-F11-05`: Adjudication decision telemetry generation containing complete rationale and sub-scores.

### Feature 12: Multi-Voter Consensus (`killswitch-adjudication`)
- `T1-F12-01`: Multi-voter consensus with 4 agreeing voters across distinct evidence classes: output `Confirmed` (mass >= 0.94).
- `T1-F12-02`: Single-voter trigger isolation: apply single-voter penalty multiplier (`0.52`), ensuring score < 0.94 threshold.
- `T1-F12-03`: Conflicting voter inputs: verify conservative veto when high-integrity voter votes `Benign`.
- `T1-F12-04`: Support and mass weight normalization across all 6 evidence classes.
- `T1-F12-05`: Consensus convergence timeout handling: return safe unconfirmed fallback when voters do not respond.

### Feature 13: Authenticode & Catalog Validation (`killswitch-adjudication`)
- `T1-F13-01`: Validate Microsoft-signed binary via `WinVerifyTrust` returning valid trusted signature.
- `T1-F13-02`: Validate Windows system binary hash via CatRoot catalog lookup returning signed verdict.
- `T1-F13-03`: Validate unsigned or self-signed test binary returning `Untrusted` verdict.
- `T1-F13-04`: Validate revoked certificate binary returning `UntrustedRevoked` verdict.
- `T1-F13-05`: Offline fallback mode: verify catalog validation does not hang when network CRL is unreachable.

### Feature 14: Protected Binary Inventory & Lineage Immunity (`killswitch-adjudication`)
- `T1-F14-01`: Query protected binary hash inventory (`PROTECTED_LOCAL_BINARY_HASHES`) for known system digests.
- `T1-F14-02`: `is_critical_system_pid` evaluation for system core processes (`explorer.exe`, `svchost.exe`, `lsass.exe`, `dwm.exe`).
- `T1-F14-03`: Current agent self-PID and supervisor parent PID immunity check.
- `T1-F14-04`: Walk process parent lineage up to depth 5: parent `explorer.exe` confers immunity to direct child prompt.
- `T1-F14-05`: Parent lineage recursion boundary: cleanly terminate traversal at root PID (0 or 4) without infinite loop.

### Feature 15: Byzantine Fraud Proof Builder (`killswitch-adjudication`)
- `T1-F15-01`: `veto_peer_kill_switch_candidate` detects rogue peer targeting protected hash: trigger veto.
- `T1-F15-02`: Construct `ByzantineKillSwitchFraudProof` containing offending peer ID, target hash, and veto reason.
- `T1-F15-03`: Cryptographically seal fraud proof with local BLAKE3 attestation digest.
- `T1-F15-04`: Validate fraud proof verification function on receiving nodes.
- `T1-F15-05`: Reject invalid or tampered fraud proof where target hash does not match protected inventory.

### Feature 16: EDR Phase-Lock Monitor (`killswitch-telemetry`)
- `T1-F16-01`: Initialize phase-lock state with 4D delay embedding parameters ($m = 4$, $\tau = 2$).
- `T1-F16-02`: Stream periodic telemetry events and verify reconstructed phase space trajectory.
- `T1-F16-03`: Compute Lyapunov exponent on stable periodic trajectory: assert exponent $\lambda \le 0$.
- `T1-F16-04`: Inject chaotic burst events into trajectory: observe positive Lyapunov divergence $\lambda > 0$.
- `T1-F16-05`: Trigger `ChaosDriftAlert` when Lyapunov divergence exceeds configured threshold for 3 consecutive epochs.

### Feature 17: Causal & Attack Graph Correlation (`killswitch-telemetry`)
- `T1-F17-01`: Ingest security events and construct causal graph nodes with `ProcessInstanceIdentity`.
- `T1-F17-02`: Correlate parent-child process creation edges and socket connection edges.
- `T1-F17-03`: Match attack graph patterns (e.g. PowerShell download -> exe spawn -> outbound connection).
- `T1-F17-04`: Time-decay correlator: verify old uncorroborated event scores decay towards zero over 10-minute window.
- `T1-F17-05`: Multi-stage kill-chain score aggregation reaches trigger threshold when 3 kill-chain stages fire.

### Feature 18: Canaries, Watchdog & Honeytokens (`killswitch-telemetry`)
- `T1-F18-01`: Deploy filesystem ghost canary trap in temporary directory.
- `T1-F18-02`: Trigger canary modification and verify immediate detection event emission.
- `T1-F18-03`: Deploy memory honeytoken string and verify read/access tripwire trigger.
- `T1-F18-04`: Hardware watchdog HMAC-SHA256 challenge-response cycle verification.
- `T1-F18-05`: Hardware watchdog missed heartbeat detection: emit alert after timeout window expires.

### Feature 19: Octopus Arm Containment Ring (`killswitch-telemetry`)
- `T1-F19-01`: Register agent arm with initial generation epoch `Gen 0` and designated `ArmRole`.
- `T1-F19-02`: Surgical autotomy execution: advance arm generation epoch from `Gen N` to `Gen N+1`.
- `T1-F19-03`: Verify that messages and tool calls stamped with stale `Gen N` are rejected by containment ring.
- `T1-F19-04`: Arm role isolation: verify untrusted sandbox arm cannot invoke administrative host capabilities.
- `T1-F19-05`: Quarantined arm status persistence and query verification.

### Feature 20: MeshGuard & Boundary Audit (`killswitch-telemetry`)
- `T1-F20-01`: Compute and verify HMAC-SHA256 signature on inter-arm message using derived epoch key.
- `T1-F20-02`: Reject inter-arm message with invalid HMAC signature using constant-time comparison.
- `T1-F20-03`: Case-insensitive lateral sink isolation: verify lowercased sink names block tainted role access.
- `T1-F20-04`: Homological boundary audit ($\partial^2 = 0$): verify cycle boundary closure on valid message chains.
- `T1-F20-05`: Sticky taint enforcement (`LAW1_STICKY_TAINT_VETO`): verify tainted arm cannot clear its own taint.

### Feature 21: Breakout Defense & SSRF / Path Guards (`killswitch-telemetry`)
- `T1-F21-01`: Mathematical IPv4 parser blocks RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- `T1-F21-02`: Mathematical IPv6 parser blocks loopback (`::1`), link-local (`fe80::/10`), and unique local (`fc00::/7`).
- `T1-F21-03`: IPv4-mapped IPv6 literal parser blocks embedded loopback (`::ffff:127.0.0.1`).
- `T1-F21-04`: Safe `Path::join` defense rejects drive letters, UNC paths (`\\`), and leading slashes.
- `T1-F21-05`: Safe `Path::join` defense rejects percent-encoded traversals (`%2e%2e%2f`) and NTFS alternate data streams (`::$DATA`).

### Feature 22: Native Rust LangGraph StateGraph (`killswitch-orchestrator`)
- `T1-F22-01`: Initialize `StateGraph` with typed state `KillSwitchGraphState` in `Monitoring` state.
- `T1-F22-02`: Execute node transition: `Monitoring` -> `IngestingSignals` -> `CorrelatingEdrAndOctopus`.
- `T1-F22-03`: Conditional edge evaluation: route to `VetoedWithFraudProof` when veto condition met.
- `T1-F22-04`: Cyclic health-probing loop: transition between `IsolatedHealthProbing` and next probe iteration.
- `T1-F22-05`: BLAKE3-chained execution trace: verify every node transition generates an append-only trace digest.

### Feature 23: Local Ollama Reasoning Node (`killswitch-orchestrator`)
- `T1-F23-01`: Sizing law evaluation: select `qwen2.5:32b` when free RAM >= 48 GB or free VRAM >= 24 GB.
- `T1-F23-02`: Sizing law evaluation: select `qwen2.5:14b`, `7b`, `3b`, or `1.5b` based on runtime free memory brackets.
- `T1-F23-03`: Health probe timeout: enforce strict 400ms timeout on Ollama `/api/tags` connection.
- `T1-F23-04`: Offline deterministic fallback: return rule-based fallback decision when Ollama daemon is absent.
- `T1-F23-05`: Model tag verification: verify no `-coder` suffix is appended to model names.

### Feature 24: Autonomous & Manual Reversible Modes (`killswitch-orchestrator`)
- `T1-F24-01`: Autonomous mode: multi-signal trigger automatically transitions graph to `EngagingContainment`.
- `T1-F24-02`: Autonomous mode: 3 consecutive healthy process-tree probes trigger automatic disarm and restoration.
- `T1-F24-03`: Autonomous mode: 30-minute dead-man failsafe timeout ceiling triggers automatic restoration.
- `T1-F24-04`: Manual mode: candidate threat pauses execution at `AwaitingManualConfirmation` HITL checkpoint.
- `T1-F24-05`: Manual mode: operator supplies `CONFIRM ISOLATE` + valid token to proceed with containment.

### Feature 25: Local HTTP/JSON API on Port 3030 (`killswitch-server`)
- `T1-F25-01`: `GET /status` returns HTTP 200 with current `KillChainStatus` JSON payload.
- `T1-F25-02`: `GET /history` returns HTTP 200 with array of BLAKE3-chained state ledger transitions.
- `T1-F25-03`: `POST /engage` with valid auth token initiates host containment and returns isolation receipt.
- `T1-F25-04`: `POST /disarm` with valid auth token disarms containment and returns HTTP 200.
- `T1-F25-05`: Loopback survival: verify HTTP API remains fully reachable on `http://127.0.0.1:3030` while host is quarantined.

### Feature 26: CLI Binary Interface (`killswitch-cli`)
- `T1-F26-01`: CLI `killswitch status` outputs current containment state and JSON representation with `--json`.
- `T1-F26-02`: CLI `killswitch isolate --token <TOKEN>` triggers containment and prints receipt.
- `T1-F26-03`: CLI `killswitch restore --token <TOKEN>` disarms containment.
- `T1-F26-04`: CLI `killswitch probe` triggers an on-demand process tree health probe.
- `T1-F26-05`: CLI `killswitch mode set autonomous` and `manual` switches orchestrator operating mode.

### Feature 27: Opaque-Box E2E Testing Suite (`tests/`)
- `T1-F27-01`: Test runner successfully discovers and executes `tier1_feature_coverage` test suite.
- `T1-F27-02`: RAII test guard cleans up any residual test processes and firewall rules on test completion.
- `T1-F27-03`: Registry audit confirms 0 bytes of drift in `HKCU\Environment` and `HKLM` hives across test run.
- `T1-F27-04`: Test execution generates structured JSON report with test durations and pass/fail counts.
- `T1-F27-05`: Multi-trial test runner executes protocol and timing checks across 3 repeated trials.

### Feature 28: Adversarial Coverage Hardening (`tests/`)
- `T1-F28-01`: Concurrent trigger burst: 50 simultaneous killswitch evaluation requests processed without deadlock.
- `T1-F28-02`: Simulated power-loss/process crash during quarantine: state ledger recovers cleanly.
- `T1-F28-03`: Fuzz test JSON input parsers with malformed UTF-8, truncated JSON, and deeply nested objects.
- `T1-F28-04`: Unauthenticated emergency disarm (`execute_host_disarm_unauthenticated`) always restores system state.
- `T1-F28-05`: Verify zero memory leaks or unclosed OS handles across 1,000 continuous cycle iterations.

### Feature 29: macOS Native PF Isolation (`killswitch-core`)
- `T1-F29-01`: Open `/dev/pf` character device descriptor with `O_RDWR` and execute `DIOCSTART` ioctl with zero `pfctl` CLI subprocess calls.
- `T1-F29-02`: Transactional rule insertion via `DIOCXBEGIN`, `DIOCADDRULE`, and `DIOCXCOMMIT` ioctl sequence creating a dedicated `anchor "killswitch"`.
- `T1-F29-03`: Loopback (`lo0`, `127.0.0.1`, `::1`) and control port 3030 explicit pass rules preservation during PF isolation.
- `T1-F29-04`: Darwin socket inspection via `proc_pidinfo` and `sysctl` (`NET_RT_IFLIST2`) identifying active sockets.
- `T1-F29-05`: Transactional teardown and rollback: flush `anchor "killswitch"` rules via `DIOCXBEGIN`/`DIOCXCOMMIT` returning PF state to baseline.

### Feature 30: macOS Process Freeze & System Whitelist (`killswitch-core`, `killswitch-adjudication`)
- `T1-F30-01`: Non-destructive process freeze using `libc::kill(pid, libc::SIGSTOP)` on macOS target PID.
- `T1-F30-02`: Process unfreeze using `libc::kill(pid, libc::SIGCONT)` cleanly resuming execution without zombie processes.
- `T1-F30-03`: System whitelist immunity in `is_critical_system_pid` on macOS: `launchd` (PID 1), `kernel_task` (PID 0), `WindowServer`, `loginwindow` vetoed unconditionally.
- `T1-F30-04`: Desktop & user daemon immunity: `UserEventAgent`, `cfprefsd`, `opendirectoryd`, `mds`, `Finder`, `Dock`, `Terminal`, `iTerm2` vetoed unconditionally.
- `T1-F30-05`: Parent ancestry traversal on macOS: child process spawned by `Terminal` or `iTerm2` inherits developer session immunity up to depth 5.

### Feature 31: Native OS Service Lifecycle & Auto-Disarm (`killswitch-core`, `killswitch-cli`, `killswitch-server`)
- `T1-F31-01`: Windows SCM installation & status: direct Win32 `advapi32.dll` `CreateServiceW` / `QueryServiceStatusEx` without `sc.exe`.
- `T1-F31-02`: Linux systemd service unit: generate valid systemd unit file and install to `/etc/systemd/system/` (or test root) with `sd_notify` socket support without `systemctl`.
- `T1-F31-03`: macOS launchd plist generation: generate valid XML `.plist` and install to `/Library/LaunchDaemons/com.oshoosi.killswitch.plist` (or test root) without `launchctl`.
- `T1-F31-04`: Unconditional host disarm on service stop/shutdown: service shutdown signal (`SERVICE_CONTROL_STOP`, `SIGTERM`, `SIGINT`) automatically triggers `execute_host_disarm_unauthenticated()`.
- `T1-F31-05`: CLI & HTTP API exposure: CLI commands (`killswitch service install|uninstall|start|stop|status`) and HTTP endpoint (`GET /service/status`) report service health.

### Feature 32: OpenTelemetry & OpenLineage DLP Engine (`killswitch-telemetry`)
- `T1-F32-01`: `seed_sensitive_file` registers file in `file_table`, emits OpenTelemetry `SeedAsset` span, and attaches `TaintBaggage`.
- `T1-F32-02`: `on_process_create` creates `ProcessTaintState`, inherits parent `active_span_context` and baggage, and emits `ProcessExec` span.
- `T1-F32-03`: `on_file_read` pushes `OpenLineageDataset`, creates W3C causal link, and merges sticky `TaintBaggage` into reader process state.
- `T1-F32-04`: `on_file_write` synthesizes `FileWrite` span carrying input/output dataset facets, propagating baggage and derived `SpanContext` to the created file.
- `T1-F32-05`: `evaluate_egress` fast DashMap check emits `EgressAttempt` span; returns `EgressVerdict::Block` with propagated `trace_id` when `DlpPolicy::Quarantine` is present.

---

## 4. Tier 2: Boundary, Extreme & Corner Cases Catalog (140 Test Cases)

### Feature 1: Workspace Cargo & Types
- `T2-F01-01`: Empty JSON string deserialization into `KillChainStatus`: fails gracefully with descriptive parse error.
- `T2-F01-02`: Maximum size payload (10 MB string in metadata): parses without stack overflow.
- `T2-F01-03`: Zero PID, maximum `u32::MAX` PID in `ProcessInstanceIdentity`: handles without arithmetic overflow.
- `T2-F01-04`: All-zero BLAKE3 hash string ("000000...00"): accepted as syntactically valid but distinct hash.
- `T2-F01-05`: Unicode bidirectional override control characters in process names: sanitized without corrupting logs.

### Feature 2: Windows Native WFP Isolation
- `T2-F02-01`: Rapid open/close of 100 WFP sessions in a tight loop: no Win32 handle leaks.
- `T2-F02-02`: Simultaneous dynamic session creation across 16 threads: no transaction conflict crashes.
- `T2-F02-03`: Attempt to filter invalid IP family (0xFF): returns structured OS error, does not panic.
- `T2-F02-04`: Network quarantine engaged when host has 0 active external adapters: succeeds cleanly.
- `T2-F02-05`: WFP service (BFE) temporarily stopped/restarting: engine returns `ServiceUnavailable` error.

### Feature 3: Windows Native BFE Registry
- `T2-F03-01`: Attempt to write rule with empty name string: rejected with validation error.
- `T2-F03-02`: Write rule string exceeding 65,535 characters: truncated safely or rejected without buffer overflow.
- `T2-F03-03`: Read from non-existent subkey: returns `KeyNotFound`, does not panic.
- `T2-F03-04`: Attempt to delete non-existent rule: returns `Ok(false)` or `NotFound` idempotently.
- `T2-F03-05`: Simultaneous registry writes from multiple threads: handled via atomic registry APIs.

### Feature 4: Windows Direct TCP Reset
- `T2-F04-01`: Query TCP table with 0 active connections: returns empty array without error.
- `T2-F04-02`: Query TCP table with > 10,000 active connections: reallocates buffer dynamically without truncation.
- `T2-F04-03`: Invoke `SetTcpEntry` on non-existent endpoint (`198.51.100.1:9999`): returns OS error cleanly.
- `T2-F04-04`: Reset connection that is already in `CLOSED` state: ignores or reports benign status.
- `T2-F04-05`: Rapid burst of 500 TCP resets on localhost loopback: loopback preservation filter prevents all drops.

### Feature 5: Linux Netlink & Landlock Isolation
- `T2-F05-01`: Linux kernel without Landlock support (older kernel): falls back gracefully to Netlink/cgroup.
- `T2-F05-02`: Netlink socket buffer exhaustion (`ENOBUFS`): retries with exponential backoff.
- `T2-F05-03`: `/proc/net/tcp` contains malformed line: parser skips corrupted line and processes remaining.
- `T2-F05-04`: Landlock rule with empty path: returns invalid argument error.
- `T2-F05-05`: Netlink raw socket permission denied (`EPERM` when non-root): returns typed `PermissionDenied` error.

### Feature 6: Native Process Freeze & Resume
- `T2-F06-01`: Attempt to freeze PID 0 (System Idle Process): rejected by critical system PID guard.
- `T2-F06-02`: Attempt to freeze PID 4 (System) or current process PID: rejected immediately.
- `T2-F06-03`: Attempt to freeze non-existent PID (e.g. 9999999): returns `ProcessNotFound` error.
- `T2-F06-04`: Process exits immediately between lookup and `NtSuspendProcess`: handles stale handle cleanly.
- `T2-F06-05`: Rapid freeze-resume alternating 100 times in 10ms: process remains stable and consistent.

### Feature 7: Active Process Tarpit
- `T2-F07-01`: Tarpit target process with 0 user threads: handles empty thread snapshot without error.
- `T2-F07-02`: Tarpit target process with 500 active threads: applies duty cycle across all threads.
- `T2-F07-03`: Target thread terminates while suspended in tarpit: snapshot updates cleanly on next cycle.
- `T2-F07-04`: Tarpit duty cycle set to 0% or 100%: clamps to safe operating bounds (1%–99%).
- `T2-F07-05`: Simultaneous tarpit requests for 20 distinct processes: runs without thread pool starvation.

### Feature 8: Operator Credential Verification
- `T2-F08-01`: Zero-length password and zero-length token: rejected immediately.
- `T2-F08-02`: 100 KB long password input: processed in constant time without memory exhaustion.
- `T2-F08-03`: Token containing null bytes (`\0`) and format string specifiers (`%s%n`): handled verbatim.
- `T2-F08-04`: Verification when master token environment variable is unset: fails closed with `TokenNotConfigured`.
- `T2-F08-05`: Timing variance test: 1,000 comparisons of 1-byte mismatch vs 31-byte mismatch show < 5% timing delta.

### Feature 9: Anti-Lockout & Caller Validation
- `T2-F09-01`: 2 failed attempts followed by 1 successful attempt: failure counter resets to 0 (no lockout).
- `T2-F09-02`: Exactly 3 failed attempts: lockout triggers at 3rd failure; 4th attempt rejected instantly.
- `T2-F09-03`: Lockout timer expiration boundary: attempt at 299s rejected; attempt at 301s permitted.
- `T2-F09-04`: Caller PID is `None` (unattributed): denied or requires elevated master token.
- `T2-F09-05`: 100 concurrent threads attempting auth during lockout: all 100 rejected in constant time.

### Feature 10: BLAKE3 State Ledger
- `T2-F10-01`: State file is completely empty (0 bytes): creates fresh ledger with genesis record.
- `T2-F10-02`: State file contains trailing corrupted bytes: detects integrity failure and alerts operator.
- `T2-F10-03`: Disk full / read-only directory simulation: returns IO error without corrupting in-memory state.
- `T2-F10-04`: Ledger with 100,000 historical events: loads and verifies hash chain in < 500ms.
- `T2-F10-05`: Non-ASCII / Unicode UTF-8 metadata strings in ledger entries: serializes and hashes deterministically.

### Feature 11: REA Adjudication Engine
- `T2-F11-01`: Threat candidate with 0 evidence items: produces `InsufficientEvidence` verdict.
- `T2-F11-02`: Threat candidate with conflicting evidence (99% benign voter, 99% malicious voter): vetoes containment.
- `T2-F11-03`: Extreme high-frequency threat candidate stream (1,000 candidates/sec): evaluates without dropping events.
- `T2-F11-04`: Candidate targeting developer tool with disguised name (e.g. `cargo.exe.scr`): correctly detects masquerade.
- `T2-F11-05`: Floating point score edge values (NaN, infinity, -0.0): clamped to valid [0.0, 1.0] range.

### Feature 12: Multi-Voter Consensus
- `T2-F12-01`: All 6 voters report score of 0.0: unanimous benign verdict.
- `T2-F12-02`: All 6 voters report score of 1.0: unanimous isolate verdict.
- `T2-F12-03`: Single voter reports 1.0, remaining 5 report no data: score penalized to 0.52 (< 0.94 threshold).
- `T2-F12-04`: Two voters report 1.0, remaining voters silent: combined mass evaluated against threshold.
- `T2-F12-05`: Voter returns error / panic: isolated by catch-unwind, remaining voters complete consensus.

### Feature 13: Authenticode & Catalog Validation
- `T2-F13-01`: File is 0 bytes: returns `InvalidImage` verdict.
- `T2-F13-02`: File is corrupted PE binary with invalid DOS/NT headers: returns `CorruptBinary`.
- `T2-F13-03`: File is 10 GB disk image: streams hash calculation without loading entire file into memory.
- `T2-F13-04`: File with valid Authenticode signature but expired timestamp certificate: evaluates expiration policy.
- `T2-F13-05`: Non-PE file on Windows (e.g. Python script, shell script): routes to catalog / hash inventory.

### Feature 14: Protected Binary Inventory & Lineage Immunity
- `T2-F14-01`: Process lineage depth exactly 5: immunity granted.
- `T2-F14-02`: Process lineage depth 6: parent beyond cutoff not granted automatic ancestral immunity.
- `T2-F14-03`: Circular process parentage loop (PID A -> PID B -> PID A in compromised table): terminates safely.
- `T2-F14-04`: Uppercase vs lowercase process name matching (`EXPLORER.EXE` vs `explorer.exe`): case-insensitive match.
- `T2-F14-05`: Binary hash in protected set matches with leading/trailing whitespace in query: trimmed and matched.

### Feature 15: Byzantine Fraud Proof Builder
- `T2-F15-01`: Rogue peer ID is empty string: rejected as malformed peer proposal.
- `T2-F15-02`: Target hash is invalid hex string: rejected with format validation error.
- `T2-F15-03`: Fraud proof with future timestamp (> 5 minutes ahead): rejected as clock-skew fraud.
- `T2-F15-04`: Fraud proof with past timestamp (> 24 hours behind): rejected as replay attack.
- `T2-F15-05`: 100 simultaneous Byzantine proposals for different protected binaries: all 100 vetoed with proofs.

### Feature 16: EDR Phase-Lock Monitor
- `T2-F16-01`: Telemetry stream with constant zero values: Lyapunov calculation handles zero variance without NaN.
- `T2-F16-02`: Telemetry stream with extreme high variance / white noise: Lyapunov divergence bounded.
- `T2-F16-03`: Timestamp intervals varying from 1ms to 1 hour: delay embedding normalizes variable sample rates.
- `T2-F16-04`: Buffer wrap-around in circular trajectory buffer: continuous computation without memory reallocation.
- `T2-F16-05`: Sudden 1,000x surge in telemetry packet rate: phase-lock window maintains stable CPU budget (< 5%).

### Feature 17: Causal & Attack Graph Correlation
- `T2-F17-01`: Causal graph with 100,000 nodes: pathfinding between trigger and root completes in < 50ms.
- `T2-F17-02`: Disconnected graph components: correlation ignores orphaned benign subtrees.
- `T2-F17-03`: Event timestamp arrives out-of-order (past event delayed by network): inserted into correct causal slot.
- `T2-F17-04`: Attack graph rule with 10 required stages: only 9 stages satisfied -> does not fire.
- `T2-F17-05`: Cyclic process spawning (Process A spawns B which spawns A): cycle detection prevents traversal freeze.

### Feature 18: Canaries, Watchdog & Honeytokens
- `T2-F18-01`: Canary file deleted rather than modified: deletion detected as canary tripwire breach.
- `T2-F18-02`: Canary file renamed or moved: rename detected as tripwire breach.
- `T2-F18-03`: Honeytoken accessed with read-only permissions: read access detected.
- `T2-F18-04`: Watchdog challenged with invalid key: HMAC verification failure raises security alert.
- `T2-F18-05`: System sleep / hibernation resume: watchdog accounts for suspension delta without false alarm.

### Feature 19: Octopus Arm Containment Ring
- `T2-F19-01`: Arm generation epoch at `u64::MAX`: safe error or rollover prevention (no panic).
- `T2-F19-02`: 10 consecutive autotomy commands in 1ms: epoch advances monotonically by exactly 10.
- `T2-F19-03`: Tool call with negative execution duration in telemetry: sanitized to 0.
- `T2-F19-04`: Quarantined arm attempts to spawn child thread/arm: child inherits quarantine state.
- `T2-F19-05`: Message sent to non-existent arm ID: returns `UnknownArmId` error.

### Feature 20: MeshGuard & Boundary Audit
- `T2-F20-01`: Inter-arm message with empty payload: HMAC computed and verified over empty slice.
- `T2-F20-02`: Inter-arm message with 16 MB payload: HMAC computed in streaming chunks without buffer blowout.
- `T2-F20-03`: Single bit flipped in 32-byte HMAC signature: verification fails deterministically.
- `T2-F20-04`: Homological boundary audit with broken boundary ($\partial^2 \ne 0$): detects topology fracture.
- `T2-F20-05`: Lateral movement attempt with mixed casing (`aCcoUntingLedGerWrite`): matched and blocked.

### Feature 21: Breakout Defense & SSRF / Path Guards
- `T2-F21-01`: IPv4 address with leading zeros (`010.000.000.001`): parsed correctly as octal/decimal and blocked.
- `T2-F21-02`: IPv6 address with mixed case hex (`Fe80::1`): parsed and blocked.
- `T2-F21-03`: Path containing multiple `..` segments (`a/b/../../c/../../etc/passwd`): normalized and blocked.
- `T2-F21-04`: Path with null byte (`foo.txt\0.exe`): rejected as invalid path syntax.
- `T2-F21-05`: Cloud metadata endpoint IP (`169.254.169.254`): strictly blocked across IPv4 and IPv6-mapped IPv4.

### Feature 22: Native Rust LangGraph StateGraph
- `T2-F22-01`: Graph execution reaches terminal node: clean stop without hanging execution loop.
- `T2-F22-02`: Node handler panics: catch-unwind transitions graph to `SafeDegraded` mode and writes ledger.
- `T2-F22-03`: Cyclic edge loops 10,000 times: bounded by max iteration limit to prevent infinite run.
- `T2-F22-04`: Checkpoint deserialization from partially corrupted file: falls back to last known good checkpoint.
- `T2-F22-05`: State transition with 0 state delta: recorded without inflating trace ledger size.

### Feature 23: Local Ollama Reasoning Node
- `T2-F23-01`: System has 512 MB free RAM: selects lowest bracket `qwen2.5:1.5b` without crashing.
- `T2-F23-02`: System has 128 GB free RAM: selects `qwen2.5:32b` capped at maximum validated size.
- `T2-F23-03`: Ollama server responds with HTTP 500 / 404: triggers deterministic offline fallback immediately.
- `T2-F23-04`: Ollama connection hangs for 399ms vs 401ms: 400ms timeout boundary strictly enforced.
- `T2-F23-05`: Ollama output contains hallucinations / unstructured prose: extracted by strict JSON schema parser.

### Feature 24: Autonomous & Manual Reversible Modes
- `T2-F24-01`: Autonomous mode: 2 healthy probes followed by 1 unhealthy probe: reset healthy counter to 0.
- `T2-F24-02`: Exactly 3 consecutive healthy probes: triggers automatic disarm transition.
- `T2-F24-03`: Dead-man timer at 1,799 seconds (still active) vs 1,800 seconds (expired): disarms at 1,800s.
- `T2-F24-04`: Manual mode: confirmation string has trailing whitespace (`CONFIRM ISOLATE `): trimmed and accepted.
- `T2-F24-05`: Manual mode: confirmation string has casing typo (`confirm isolate`): rejected (strict match).

### Feature 25: Local HTTP/JSON API on Port 3030
- `T2-F25-01`: Bind to port 3030 when port already in use: returns `PortInUse` error cleanly without panic.
- `T2-F25-02`: HTTP request with payload > 10 MB to `/edr/ingest`: rejected with `413 Payload Too Large`.
- `T2-F25-03`: HTTP request with missing `Authorization` header on `/engage`: rejected with `401 Unauthorized`.
- `T2-F25-04`: 500 concurrent HTTP requests to `/status`: all receive HTTP 200 within 200ms.
- `T2-F25-05`: Slowloris attack (holding connection open with 1 byte/sec): connection closed by read timeout.

### Feature 26: CLI Binary Interface
- `T2-F26-01`: Run CLI with `--help` and `--version`: returns 0 exit code with formatted text.
- `T2-F26-02`: Run CLI with invalid unknown subcommand (`killswitch foo`): returns non-zero exit code with help hint.
- `T2-F26-03`: Run CLI with empty argument string (`""`): returns non-zero error.
- `T2-F26-04`: Pass `--json` flag to non-query command: outputs JSON receipt on stdout.
- `T2-F26-05`: Interrupted via SIGINT (Ctrl+C) during CLI operation: exits gracefully without orphan handles.

### Feature 27: Opaque-Box E2E Testing Suite
- `T2-F27-01`: Execute test suite with `--nocapture`: prints all progress messages cleanly.
- `T2-F27-02`: Run test suite in parallel (`--test-threads=8`): test isolation mutexes prevent state cross-talk.
- `T2-F27-03`: Force test failure in child assertion: RAII drop guard executes and disarms host.
- `T2-F27-04`: Test execution in restricted permissions environment: reports skipped tests cleanly.
- `T2-F27-05`: Run full suite 5 times consecutively: zero flaky tests, 100% identical pass results.

### Feature 28: Adversarial Coverage Hardening
- `T2-F28-01`: Inject 10,000 randomized bit mutations into state ledger file: all detected by BLAKE3 verify.
- `T2-F28-02`: Rapid multi-threaded freeze/resume on 100 dummy worker threads: zero deadlocks.
- `T2-F28-03`: Fuzz HTTP headers with arbitrary non-ASCII characters: HTTP server handles safely.
- `T2-F28-04`: Simulate system time jump backwards (NTP sync -1 hour): dead-man timer handles monotonically.
- `T2-F28-05`: Memory leak stress: run 10,000 state transitions; resident memory growth < 5 MB.

### Feature 29: macOS Native PF Isolation
- `T2-F29-01`: Rapid open/ioctl/close of 100 `/dev/pf` sessions in a tight loop: zero Darwin file descriptor leaks.
- `T2-F29-02`: Concurrent `DIOCXBEGIN` transaction conflict: second transaction fails closed with descriptive busy error without corrupting active rules.
- `T2-F29-03`: Malformed CIDR or extreme port range (`0..=65535`) in PF rule struct: safely rejected by validation logic.
- `T2-F29-04`: Disarm invoked when `/dev/pf` was already closed or disarmed: idempotent no-op returning `Ok(())`.
- `T2-F29-05`: Non-root/unprivileged execution: returns clean `PermissionDenied` error without panic or crash.

### Feature 30: macOS Process Freeze & System Whitelist
- `T2-F30-01`: Attempt to freeze PID 0 (`kernel_task`) or PID 1 (`launchd`): deterministically rejected by kernel immunity gate before any `kill()` call.
- `T2-F30-02`: Process terminates spontaneously between candidate check and `SIGSTOP`: handles `ESRCH` gracefully without error cascade.
- `T2-F30-03`: Rapid freeze/resume cycles (1,000 repetitions): process state transitions cleanly without orphaned signals.
- `T2-F30-04`: Process with 200 child threads on macOS: thread tree frozen uniformly via process-level `SIGSTOP`.
- `T2-F30-05`: Unicode and path traversal in process name (`../../bin/malware`): safely canonicalized.

### Feature 31: Native OS Service Lifecycle & Auto-Disarm
- `T2-F31-01`: Install service when service already exists: returns structured `ServiceAlreadyExists` error without overwriting.
- `T2-F31-02`: Uninstall non-existent service: returns structured `ServiceNotFound` error gracefully.
- `T2-F31-03`: Service start failure (binary missing): handles failure cleanly and reports descriptive status.
- `T2-F31-04`: Simulated abrupt SIGKILL to daemon vs graceful SIGTERM: verify SIGTERM path executes automatic unauthenticated disarm before exit.
- `T2-F31-05`: Read-only filesystem test for systemd unit / launchd plist: reports permission error cleanly.

### Feature 32: OpenTelemetry & OpenLineage DLP Engine
- `T2-F32-01`: Composite key hash collision resistance: two distinct processes sharing PID but different start times generate distinct `ProcessKey` entries.
- `T2-F32-02`: Deep process ancestry inheritance (100 child processes spawned in sequence): span context and baggage propagate without stack overflow.
- `T2-F32-03`: Cyclic file read/write operations (proc reads file A, writes file B, another proc reads B and overwrites A): taints merge monotonically without infinite loops.
- `T2-F32-04`: Concurrent `evaluate_egress` calls across 50 threads on same `ProcessKey`: lockless `DashMap` lookups execute without contention or deadlocks.
- `T2-F32-05`: Malformed egress destination URLs (empty string, unicode, local file URIs, IP without port): safely handled and evaluated.

---

## 5. Tier 3: Cross-Feature Pairwise Combinations (32 Test Cases)

| Test ID | Feature Pair | Interaction Scope & Invariant |
|:-------:|:------------:|:------------------------------|
| `T3-PAIR-01` | F02 (WFP) + F06 (Freeze) | Synchronous engagement: when WFP network isolation engages, untrusted target PID is atomically suspended via `NtSuspendProcess`. Neither operation leaves partial state if the other fails. |
| `T3-PAIR-02` | F02 (WFP) + F25 (Axum API) | Loopback port preservation: engage hermetic WFP network isolation and verify `http://127.0.0.1:3030/status` responds with HTTP 200 while external connections to `1.1.1.1:80` are dropped. |
| `T3-PAIR-03` | F04 (TCP Reset) + F10 (Ledger) | Reset logging: direct TCP resets executed via `SetTcpEntry` are hashed and appended to `killchain_state.json` with remote IP, port, and BLAKE3 chaining. |
| `T3-PAIR-04` | F06 (Freeze) + F07 (Tarpit) | Graduated containment: process transitions from active tarpit (95% duty cycle) to full freeze (`NtSuspendProcess`), and returns cleanly upon disarm without thread deadlocks. |
| `T3-PAIR-05` | F08 (Auth) + F09 (Lockout) | Constant-time rate limiting: 3 failed attempts using invalid tokens trigger 300s lockout; during lockout, constant-time verification still executes to prevent timing side channels. |
| `T3-PAIR-06` | F09 (Caller Val) + F24 (Manual Mode) | Quarantined caller rejection: a frozen/quarantined caller PID attempting to supply `CONFIRM RESTORE` in Manual Mode is blocked by `validate_killchain_caller`. |
| `T3-PAIR-07` | F10 (Ledger) + F24 (Reversible Disarm) | Restoration receipt: disarm event (manual or 3-probe autonomous) writes an unseal record to `killchain_state.json` verifying all filters and PIDs were restored. |
| `T3-PAIR-08` | F11 (REA) + F12 (Multi-Voter) | Consensus weighting: REA adjudication engine aggregates 6 voter inputs; single-voter penalty reduces score to 0.52 unless confirmed by independent voters. |
| `T3-PAIR-09` | F11 (REA) + F14 (Lineage Immunity) | Developer immunity override: candidate threat detected by REA targeting `rustc.exe` is overridden and vetoed by parent-lineage immunity check (depth <= 5). |
| `T3-PAIR-10` | F12 (Multi-Voter) + F16 (Phase-Lock) | Telemetry voting: Lyapunov exponent drift alert from `edr-phaselock` casts vote in voter consensus; requires corroboration from at least one non-telemetry voter. |
| `T3-PAIR-11` | F13 (Authenticode) + F14 (Protected Set) | Dual-layer trust: binary passes if either signed by verified Microsoft Authenticode certificate or present in `PROTECTED_LOCAL_BINARY_HASHES`. |
| `T3-PAIR-12` | F14 (Critical PID) + F15 (Fraud Proof) | Peer veto & fraud generation: candidate proposal targeting `lsass.exe` (PID 600) triggers `veto_peer_kill_switch_candidate` and emits sealed `ByzantineKillSwitchFraudProof`. |
| `T3-PAIR-13` | F15 (Fraud Proof) + F20 (MeshGuard) | Rogue peer isolation: upon receipt and verification of `ByzantineKillSwitchFraudProof`, MeshGuard immediately blacklists the offending peer ID across the mesh. |
| `T3-PAIR-14` | F16 (Phase-Lock) + F17 (Causal Graph) | Anomaly-to-provenance correlation: phase-lock chaos drift triggers causal graph backwards-trace to locate the spawning parent process identity. |
| `T3-PAIR-15` | F17 (Attack Graph) + F18 (Canaries) | Tripwire escalation: canary file modification event in `tripwires` is correlated by `attack_graph` as high-confidence Stage 4 (Impact/Encryption). |
| `T3-PAIR-16` | F18 (Watchdog) + F19 (Arm Ring) | Hardware failure autotomy: hardware watchdog challenge timeout triggers surgical autotomy (`Gen N -> Gen N+1`) of the host monitoring arm. |
| `T3-PAIR-17` | F19 (Arm Ring) + F20 (MeshGuard) | Generation epoch gating: when `ArmContainmentRing` advances an arm from `Gen 1` to `Gen 2`, MeshGuard rejects messages signed with `Gen 1` keys. |
| `T3-PAIR-18` | F20 (MeshGuard) + F21 (Breakout Defense) | Lateral sink containment: breakout defense detects lateral traversal and MeshGuard enforces `LAW1_STICKY_TAINT_VETO` to block sensitive sink access. |
| `T3-PAIR-19` | F21 (SSRF Guard) + F25 (Axum API) | API proxy defense: API endpoints accepting webhook URLs or remote targets route through mathematical IPv4/IPv6 parser to prevent SSRF against localhost/cloud metadata. |
| `T3-PAIR-20` | F21 (Safe Path) + F10 (Ledger) | Database path traversal guard: configuring `OSOOSI_DATABASE_DIR` validates base path using safe `Path::join`, blocking traversal outside allowed directory. |
| `T3-PAIR-21` | F22 (LangGraph) + F23 (Ollama Node) | Graph node execution: LangGraph invokes Ollama reasoning node; if Ollama times out (400ms), graph edge routes to deterministic rule voter node. |
| `T3-PAIR-22` | F22 (LangGraph) + F24 (Autonomous Mode) | Lifecycle transitions: LangGraph state transitions from `Monitoring` -> `Adjudicating` -> `Engaging` -> `IsolatedHealthProbing` -> `Restoring` -> `Monitoring`. |
| `T3-PAIR-23` | F23 (Ollama Fallback) + F12 (Multi-Voter) | Offline voter equivalence: deterministic rule fallback voter produces identical `VoteResult` structure to Ollama node, preserving consensus schema. |
| `T3-PAIR-24` | F24 (Dead-Man Timeout) + F02 (WFP) | Failsafe teardown: 30-minute dead-man timeout triggers automatic unauthenticated WFP session closure, dropping all isolation filters. |
| `T3-PAIR-25` | F25 (Axum API) + F26 (Clap CLI) | Client-Server parity: running `killswitch status --json` produces identical JSON output to querying `GET /status` via HTTP. |
| `T3-PAIR-26` | F26 (CLI Disarm) + F08 (Token Auth) | CLI authenticated disarm: `killswitch restore --token <TOKEN>` sends constant-time verified token to server; disarms host on match. |
| `T3-PAIR-27` | F05 (Linux Landlock) + F06 (SIGSTOP) | Linux dual-containment: Landlock network/filesystem sandbox restrictions paired with `libc::kill(pid, SIGSTOP)` process freeze on Linux hosts. |
| `T3-PAIR-28` | F27 (E2E Runner) + F28 (Tier 5 Fuzzing) | E2E test harness invokes adversarial chaos tests, capturing memory metrics and verifying zero state leaks between test runs. |
| `T3-PAIR-29` | F29 (macOS PF) + F30 (macOS Freeze) | macOS dual containment: `/dev/pf` network isolation paired with `libc::kill(pid, SIGSTOP)` freeze; disarm restores both. |
| `T3-PAIR-30` | F30 (macOS Whitelist) + F14 (Lineage Immunity) | macOS developer lineage immunity: `cargo test` executed inside `Terminal.app` or `iTerm2` inherits whitelist immunity up to depth 5. |
| `T3-PAIR-31` | F31 (Service Daemon) + F24 (Auto-Disarm on Shutdown) | Unconditional host disarm: service stop or shutdown signal triggers `execute_host_disarm_unauthenticated()` before service termination. |
| `T3-PAIR-32` | F32 (DLP Engine) + F22 (LangGraph) | Data exfiltration veto & isolation: `EndpointLineageEngine::evaluate_egress` returning `EgressVerdict::Block` feeds LangGraph as high-weight trigger, transitioning state to `EngagingContainment` while preserving critical system PIDs. |

---

## 6. Tier 4: Real-World Application Scenarios (5 Comprehensive Scenarios)

### Scenario 1: Multi-Stage APT Attack Simulation (`S1_APT_Simulation`)
- **Objective**: Verify end-to-end multi-signal detection, zero-false-positive adjudication, autonomous graduated containment, and automatic reversible recovery during a simulated Advanced Persistent Threat (APT).
- **Execution Workflow**:
  1. *Reconnaissance & Ingestion*: Simulated attacker performs process enumeration and local port probing. Telemetry engine ingests low-level events.
  2. *Lateral Movement & Tripwire*: Attacker attempts to access honeytoken in memory and touches filesystem canary trap. `tripwires` and `causal_graph` record high-severity signals.
  3. *Phase-Lock Divergence*: Rapid command burst causes phase-lock Lyapunov monitor to detect chaotic drift ($\lambda > 0.85$).
  4. *Multi-Voter Consensus*: Voters (EDR, Tripwire, Anomaly) cast agreeing votes; total mass reaches $0.96 \ge 0.94$.
  5. *Lineage & Protected Binary Check*: Candidate target PID verified against critical system PID whitelist and parent lineage up to depth 5; target is an untrusted payload (`payload.exe`).
  6. *Autonomous Containment Engagement*: LangGraph transitions to `EngagingContainment`. Native WFP dynamic session blocks outbound traffic (preserving loopback `127.0.0.1` and port `3030`). `NtSuspendProcess` freezes `payload.exe`. `SetTcpEntry` terminates active C2 connection.
  7. *State Ledger Audit*: `killchain_state.json` records isolation receipt with BLAKE3 chained hash.
  8. *Periodic Health Probing*: Host health probe runs every 5 seconds. Process tree indicates no further malicious activity.
  9. *Automatic Reversible Restoration*: After 3 consecutive clean health probes, LangGraph triggers `DisarmingAndRestoring`. WFP dynamic session is cleanly closed; `payload.exe` is un-frozen (or transitioned to forensic quarantine); state ledger records clean restoration.
- **Verification Invariants**:
  - Zero CLI tools invoked (`netsh`, `taskkill`, etc.).
  - Port 3030 and loopback were 100% operational throughout quarantine.
  - Full restoration achieved automatically without operator intervention.

### Scenario 2: Ransomware Burst Containment & Active Tarpit (`S2_Ransomware_Burst`)
- **Objective**: Verify immediate containment of rapid file encryption bursts using thread-level tarpitting, process freezing, and network isolation.
- **Execution Workflow**:
  1. *Burst Initiation*: Test worker process generates rapid file modification events (> 100 files/sec) in a canary directory.
  2. *Immediate Tarpit Activation*: Telemetry engine triggers `ActiveProcessTarpit`. Target process threads are placed in a 95% suspend duty cycle via Toolhelp32 snapshot.
  3. *Throughput Measurement*: File encryption throughput drops by > 90% immediately.
  4. *Escalation to Freeze*: Adjudication engine confirms malicious burst pattern; escalates from tarpit to full freeze via `NtSuspendProcess`.
  5. *Network Severing*: Direct TCP reset (`SetTcpEntry`) severs any key-exchange socket connections to remote C2.
  6. *Ledger Persistence*: State ledger records process freeze, tarpit duty cycle, and severed socket endpoints.
  7. *Clean Disarm*: Operator issues authenticated disarm; target threads released and restored.
- **Verification Invariants**:
  - Legitimate processes outside the target tree experience 0% degradation.
  - Tarpit duty cycle operates entirely in-memory using native thread handles.

### Scenario 3: Developer Workflow Immunity Under Heavy Compilation (`S3_Developer_Immunity`)
- **Objective**: Guarantee the "Never Wrong" invariant: heavy compilation, test running, and IDE operations must never trigger false-positive isolation or process throttling.
- **Execution Workflow**:
  1. *Heavy Compilation Load*: Execute concurrent compilation workloads spawning `cargo`, `rustc`, `link.exe`, `cl.exe`, and git commands consuming > 90% CPU and memory.
  2. *Simulated Anomaly Trigger*: Anomaly detector flags sudden CPU surge, high memory allocation, and rapid temporary file creation.
  3. *REA Engine & Lineage Traversal*: REA adjudication evaluates the candidate process. Lineage tracker walks parent ancestry up to depth 5, identifying parent `cargo` and root `code.exe` / `cmd.exe`.
  4. *Protected Binary Match*: Compiler binaries matched against `PROTECTED_LOCAL_BINARY_HASHES` and developer whitelist.
  5. *Deterministic Veto*: REA engine issues a deterministic veto: `AdjudicationResult::VetoedProtectedLineage`.
  6. *Zero Disruption Assertion*: Zero compilation threads are frozen, zero network sockets are dropped, and compilation finishes with 0 errors.
- **Verification Invariants**:
  - The KillSwitch never fires against protected developer ancestry.
  - Adjudication completes in < 5ms without slowing compilation.

### Scenario 4: Byzantine Compromised Peer Attack & Fraud Proof (`S4_Byzantine_Peer_Attack`)
- **Objective**: Detect and defeat a compromised cluster peer attempting to weaponize the killswitch against critical system binaries.
- **Execution Workflow**:
  1. *Rogue Proposal Injection*: Simulated compromised peer broadcasts a killswitch candidate proposal targeting `lsass.exe` (or `systemd` on Linux) with a spoofed YARA rule trigger.
  2. *Peer Candidate Veto Gate*: Receiving node routes proposal through `veto_peer_kill_switch_candidate`.
  3. *Critical PID & Hash Detection*: Evaluator detects that target is a critical system binary (`is_critical_system_pid == true`).
  4. *Fraud Proof Construction*: Node invokes `build_kill_switch_fraud_proof`, generating a `ByzantineKillSwitchFraudProof` containing offending peer ID, target hash, timestamp, and veto reason.
  5. *Cryptographic Attestation*: Fraud proof is hashed and signed with local node's BLAKE3 key.
  6. *Peer Mesh Isolation*: MeshGuard immediately marks the offending peer ID as compromised and applies `LAW1_STICKY_TAINT_VETO`, dropping all future messages from this peer.
- **Verification Invariants**:
  - Critical system process is completely unaffected.
  - Byzantine fraud proof is cryptographically verifiable by all honest nodes.

### Scenario 5: Hermetic Host Isolation with Remote Operator Restore (`S5_Hermetic_Remote_Restore`)
- **Objective**: Verify full hermetic host network isolation while preserving local HTTP control on port 3030, followed by authenticated remote restoration.
- **Execution Workflow**:
  1. *Isolation Engagement*: Operator triggers manual containment via CLI: `killswitch isolate --token <ADMIN_TOKEN>`.
  2. *Native WFP Hermetic Block*: WFP dynamic session applies default-deny on all IP interfaces, blocking all outbound and inbound traffic.
  3. *Loopback & Control Preservation*: Dynamic session explicitly preserves loopback `127.0.0.1` and port `3030`.
  4. *Network Ingress/Egress Test*:
     - Outbound connection to `8.8.8.8:53` drops immediately (connection refused / timeout).
     - Local connection to `http://127.0.0.1:3030/status` responds in < 10ms with HTTP 200 and `is_isolated: true`.
  5. *Remote Authentication & Disarm*:
     - Operator sends `POST /disarm` with valid constant-time token.
     - Containment engine validates caller PID and verifies master token in constant time.
     - Dynamic WFP session is committed to rollback and closed.
  6. *Full Connectivity Restoration*:
     - Outbound connection to `8.8.8.8:53` succeeds immediately.
     - `GET /status` reports `is_isolated: false`.
- **Verification Invariants**:
  - Zero lingering firewall rules in Windows BFE or Linux Netlink.
  - Complete restoration achieved within < 100ms of disarm call.

### Scenario 6: Native OS Service Daemon Lifecycle & Unconditional Shutdown Disarm (`S6_Service_Daemon_Disarm`)
- **Objective**: Verify native service daemon installation, startup, runtime containment, and unconditional automatic host disarm when the service is stopped or shut down.
- **Execution Workflow**:
  1. *Service Installation*: Install native service via `killswitch service install` (Win32 SCM FFI on Windows, systemd unit generation on Linux, launchd plist on macOS) with zero CLI tools.
  2. *Daemon Startup & Status*: Start service via `killswitch service start`; query status via `GET /service/status` and `killswitch service status` confirming `Running`.
  3. *Containment Engagement*: Service daemon encounters candidate threat; engages host isolation (WFP on Windows, Netlink on Linux, `/dev/pf` on macOS).
  4. *Shutdown Signal Injection*: Supervisor or OS sends stop signal (`SERVICE_CONTROL_STOP` on Windows, `SIGTERM`/`SIGINT` on POSIX).
  5. *Unconditional Automatic Disarm*: Daemon service signal handler intercepts shutdown; immediately invokes `execute_host_disarm_unauthenticated()`.
  6. *Post-Shutdown Verification*: Verify host network filters are completely flushed, frozen PIDs are resumed, and endpoint is 100% restored.
- **Verification Invariants**:
  - Zero `sc.exe`, `systemctl`, `launchctl` calls.
  - Endpoint is never left quarantined on service stop or host reboot.

### Scenario 7: Multi-Hop Endpoint DLP Exfiltration Fan-In & Containment (`S7_DLP_Exfiltration_Containment`)
- **Objective**: Verify that multi-hop file/process data taint propagation through OpenTelemetry & OpenLineage (`EndpointLineageEngine`) blocks unauthorized network exfiltration and triggers KillSwitch containment.
- **Execution Workflow**:
  1. *Seed Sensitive Assets*:
     - `seed_sensitive_file` seeds `secret_roadmap.docx` (inode 101, classification: `CrownJewel`, policy: `Quarantine`).
     - `seed_sensitive_file` seeds `q4_financials.xlsx` (inode 102, classification: `Confidential`, policy: `Audit`).
  2. *Process Hierarchy & Fan-In Taint*:
     - `powershell.exe` (PID 2104) spawns `7z.exe` (PID 4812) via `on_process_create`.
     - `7z.exe` executes `on_file_read` on both inode 101 and 102.
     - `TaintBaggage::merge` escalates `classification` to `CrownJewel`, `policy` to `Quarantine`, and concatenates both distinct SHA-256 digests.
  3. *Tainted Output Synthesis*:
     - `7z.exe` executes `on_file_write` to create `staging_upload.zip` (inode 999).
     - Engine attaches W3C causal links and OpenLineage datasets/facets, marking `staging_upload.zip` with the derived `SpanContext` and `CrownJewel` + `Quarantine` baggage.
  4. *Exfiltration Attempt*:
     - `curl.exe` (PID 5001) reads `staging_upload.zip` via `on_file_read`, inheriting the tainted baggage and trace ID.
     - `curl.exe` attempts egress: `evaluate_egress(curl_proc, "https://external-drop.example.com/upload")`.
  5. *Synchronous Block & KillSwitch Containment*:
     - Fast DashMap lookup evaluates `policy == DlpPolicy::Quarantine`.
     - Returns `EgressVerdict::Block { reason, trace_id }` with concatenated source SHA-256 hashes.
     - Egress block event is fed into KillSwitch LangGraph, transitioning state to `EngagingContainment` and freezing PID 5001 (`curl.exe`).
  6. *Reversible Recovery*:
     - Operator issues authenticated disarm; endpoint network and processes cleanly restore.
- **Verification Invariants**:
  - Taint baggage survives process-to-file-to-process propagation across multiple hops.
  - Zero false positives on untainted files; instant blocking on quarantined traces.

---

## 7. Specialized Acceptance Test Suites

### 7.1 Zero OS Tool Execution Audit Suite (`tests/zero_os_tool_audit.rs`)
Programmatic static and runtime verification enforcing that no external OS CLI commands are ever executed by the KillSwitch codebase.
- `AUDIT_01`: Programmatic AST and regex scan across all Rust files in `crates/` and `tests/`:
  - Assert zero occurrences of `std::process::Command::new` or `tokio::process::Command::new` invoking:
    `netsh`, `iptables`, `nft`, `taskkill`, `kill`, `powershell`, `cmd`, `sh`, `bash`, `unix_chkpwd`, `dscl`, `LogonUserW`.
- `AUDIT_02`: Binary symbol table inspection (`dumpbin` / `nm`) of compiled `killswitch` binaries:
  - Assert zero imports of prohibited shell execution wrappers.
- `AUDIT_03`: Runtime execution tracing:
  - Intercept or hook process creation during full containment/disarm cycle and assert zero child processes are spawned.
- `AUDIT_04`: Cross-platform verification:
  - Assert `#[cfg(target_os = "windows")]` modules use only `fwpuclnt.dll`, `iphlpapi.dll`, `winreg`, and `ntdll.dll`.
  - Assert `#[cfg(target_os = "linux")]` modules use only Netlink raw sockets, Landlock LSM syscalls, and `libc`.
- `AUDIT_05`: Operator authentication audit:
  - Assert authentication uses pure Rust `subtle::ConstantTimeEq` and BLAKE3, with zero invocations of `unix_chkpwd` or `LogonUserW`.

### 7.2 "Never Wrong" Protected Binary & Lineage Veto Suite (`tests/never_wrong_veto_suite.rs`)
Empirical verification of critical system process immunity and anti-false-positive gates.
- `VETO_01`: Critical System PID Immunity:
  - Test explicit PID lookups for PIDs 0 (System Idle), 4 (System), and active PIDs for `explorer.exe`, `svchost.exe`, `lsass.exe`, `dwm.exe`.
  - Assert `is_critical_system_pid` returns `true` and any containment attempt returns `Err(ProtectedProcessImmunity)`.
- `VETO_02`: Parent Lineage Traversal (Depth 1 to 5):
  - Spawn multi-level process hierarchy (Grandparent -> Parent -> Child).
  - Verify parentage walking confers immunity to children of `explorer.exe`, `cargo.exe`, and `code.exe` up to depth 5.
- `VETO_03`: Protected Binary BLAKE3 Inventory:
  - Compute BLAKE3 hashes for known development binaries and system utilities.
  - Insert into `PROTECTED_LOCAL_BINARY_HASHES`; assert any candidate threat matching hash is instantly vetoed.
- `VETO_04`: Uncalibrated Single-Voter Rejection:
  - Feed single anomalous signal with confidence 0.95 into adjudication engine without supporting evidence.
  - Assert single-voter penalty reduces mass to 0.52 and candidate is vetoed (`AdjudicationResult::VetoedSingleVoter`).
- `VETO_05`: Byzantine Fraud Proof Generation:
  - Issue simulated peer containment request targeting protected binary hash.
  - Assert `build_kill_switch_fraud_proof` emits valid `ByzantineKillSwitchFraudProof` with non-empty BLAKE3 attestation.

### 7.3 Anti-Lockout & Quarantined Caller Defense Suite (`tests/anti_lockout_suite.rs`)
Verification of rate-limited lockout protection and caller integrity.
- `LOCKOUT_01`: 3-Strike Lockout Escalation:
  - Submit 3 invalid tokens in succession.
  - Assert attempts 1 and 2 return `InvalidCredentials`; attempt 3 returns `LockoutEngaged`.
- `LOCKOUT_02`: 300-Second Lockout Duration:
  - Verify subsequent attempts within 300 seconds are immediately rejected with `LockoutActive` without checking credentials.
- `LOCKOUT_03`: Constant-Time Verification:
  - Execute 1,000 token comparisons with varying matching prefixes.
  - Assert standard deviation of response times is within acceptable statistical noise floor (timing-attack resistant).
- `LOCKOUT_04`: Quarantined Caller Blocking:
  - Simulate caller PID that is currently marked as frozen or quarantined.
  - Assert `validate_killchain_caller` returns `Err(CallerQuarantined)` and denies disarm capability.
- `LOCKOUT_05`: Master Token Bypass & Emergency Reset:
  - Verify valid emergency master token authenticates and resets lockout state when supplied from un-quarantined operator session.

---

## 8. Test Infrastructure Architecture & Test Harness Implementation

### 8.1 Directory Layout
The E2E test suite resides in the `tests/` directory at the workspace root, structured as follows:

```
d:\harfile\killswitch\
├── tests/
│   ├── common/
│   │   ├── mod.rs                  # Shared test harness, assertions, RAII guards
│   │   ├── env_guard.rs            # Process-isolated environment & registry snapshot guard
│   │   ├── network_helper.rs       # Real loopback TCP socket listeners & probes
│   │   └── process_helper.rs       # Child test process spawner and monitor
│   ├── tier1_feature_coverage.rs   # Tier 1: 140 isolated feature tests (F01–F28)
│   ├── tier2_boundary_corner.rs    # Tier 2: 140 boundary & extreme case tests (F01–F28)
│   ├── tier3_cross_feature.rs      # Tier 3: 28 pairwise combination tests
│   ├── tier4_real_world.rs         # Tier 4: 5 real-world complex application scenarios
│   ├── zero_os_tool_audit.rs       # Specialized Suite: Zero OS CLI utility invocation audit
│   ├── never_wrong_veto_suite.rs   # Specialized Suite: Protected binary & lineage immunity
│   └── anti_lockout_suite.rs       # Specialized Suite: Anti-lockout & caller defense
├── Cargo.toml
└── PROJECT.md
```

### 8.2 Common Test Harness & RAII Guard (`tests/common/env_guard.rs`)
Every test must execute within an isolated `EmpiricalStressTestGuard` to guarantee:
1. Mutex-protected serialized execution for tests modifying system network or process state (`STRESS_MUTEX`).
2. Snapshot of environment variables and registry hives (`HKCU\Environment`, `HKLM\SYSTEM\...\Environment`).
3. Automatic unauthenticated disarm on drop to prevent leaving system in isolated state if a test fails.
4. Cryptographic assertion that zero registry drift occurred during the test run.

```rust
// Pattern for tests/common/env_guard.rs
pub struct EmpiricalStressTestGuard {
    _lock: parking_lot::MutexGuard<'static, ()>,
    initial_env: HashMap<String, String>,
    #[cfg(windows)]
    initial_hkcu_env: HashMap<String, String>,
    #[cfg(windows)]
    initial_hklm_env: HashMap<String, String>,
}

impl EmpiricalStressTestGuard {
    pub fn new() -> Self {
        let lock = STRESS_MUTEX.lock();
        // Disarm any leftover isolation from previous crashed runs
        let _ = execute_host_disarm_unauthenticated();

        let initial_env: HashMap<String, String> = std::env::vars().collect();
        #[cfg(windows)]
        let initial_hkcu_env = Self::read_registry_env(HKEY_CURRENT_USER, "Environment");
        #[cfg(windows)]
        let initial_hklm_env = Self::read_registry_env(
            HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        );

        Self {
            _lock: lock,
            initial_env,
            #[cfg(windows)]
            initial_hkcu_env,
            #[cfg(windows)]
            initial_hklm_env,
        }
    }
}

impl Drop for EmpiricalStressTestGuard {
    fn drop(&mut self) {
        // Guarantee host is restored on drop
        let _ = execute_host_disarm_unauthenticated();

        #[cfg(windows)]
        {
            let current_hkcu = Self::read_registry_env(HKEY_CURRENT_USER, "Environment");
            assert_eq!(self.initial_hkcu_env, current_hkcu, "FATAL: HKCU Environment modified!");
            let current_hklm = Self::read_registry_env(
                HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            );
            assert_eq!(self.initial_hklm_env, current_hklm, "FATAL: HKLM Environment modified!");
        }
    }
}
```

### 8.3 Test Runner Commands & CI Integration
The entire E2E test suite is executed using standard Cargo commands with no external dependencies:

```powershell
# 1. Execute Zero-OS-Tool Audit (Fast static/AST check)
cargo test --test zero_os_tool_audit

# 2. Execute Specialized Acceptance Suites
cargo test --test never_wrong_veto_suite
cargo test --test anti_lockout_suite

# 3. Execute Tier 1 (Feature Coverage)
cargo test --test tier1_feature_coverage

# 4. Execute Tier 2 (Boundary & Corner Cases)
cargo test --test tier2_boundary_corner

# 5. Execute Tier 3 (Cross-Feature Pairwise Combinations)
cargo test --test tier3_cross_feature

# 6. Execute Tier 4 (Real-World Application Scenarios)
cargo test --test tier4_real_world

# 7. Execute Complete Workspace Test Suite (Single Command)
cargo test --workspace --all-targets -- --nocapture
```

### 8.4 Pass / Fail Semantics & Reporting Format
- **Zero-Tolerance Invariant**: 100% of tests must pass (0 failures, 0 panics). A single failure fails the entire gate.
- **Structured JSON Output**: When executed with `--format=json` or under CI runner, results are formatted into structured JSON records with test duration, memory delta, and assertion status.
- **Multi-Trial Repeatability**: All timing, protocol, and adversarial proof tests require $\ge 3$ consecutive agreeing trials to confirm non-transient reproducibility.

---

## 9. Progressive Testability & Milestone Integration

To ensure progressive testability across the implementation lifecycle without circular dependencies:

1. **Milestone M1 (Types & Workspace Foundation)**:
   - Validated by `T1-F01-01..05`, `T2-F01-01..05`, and `zero_os_tool_audit`.
   - Tests require only `killswitch-types`.
2. **Milestone M2 (Native Containment Engine)**:
   - Validated by Features F02–F10 across Tier 1, Tier 2, and `anti_lockout_suite`.
   - Tests require `killswitch-core` and native OS kernel handles.
3. **Milestone M3 (Zero-False-Positive Adjudication)**:
   - Validated by Features F11–F15 and `never_wrong_veto_suite`.
   - Tests require `killswitch-adjudication`.
4. **Milestone M4 (EDR & Octopus Telemetry Triggers)**:
   - Validated by Features F16–F21 across Tier 1 and Tier 2.
   - Tests require `killswitch-telemetry`.
5. **Milestone M5 (LangGraph Orchestrator, CLI & HTTP API)**:
   - Validated by Features F22–F26, Tier 3 pairwise matrix, and Tier 4 scenarios S1–S5.
   - Tests require `killswitch-orchestrator`, `killswitch-server`, and `killswitch-cli`.
6. **Milestone M6 (Final Verification & Acceptance)**:
   - Validated by 100% pass across all 328 test cases in Tiers 1–4 and Tier 5 Adversarial Hardening.

---

## 10. Publication & Handoff Signoff
This document serves as the complete, authoritative specification for the KillSwitch E2E Testing Infrastructure. Upon acceptance by the parent orchestrator, test implementation agents will construct the test suites in `tests/` adhering strictly to this blueprint.
