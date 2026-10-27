# Project: Standalone Rust KillSwitch Security Agent Workspace

## Architecture
Standalone, three-platform native (Windows, Linux, macOS) Rust KillSwitch security agent workspace extracted and adapted from `D:\harfile\OshoosiClaw\`.
Zero external OS CLI utilities (`netsh`, `iptables`, `nft`, `taskkill`, `kill`, `powershell`, `cmd`, `sh`, `bash`, `unix_chkpwd`, `dscl`, `sc.exe`, `systemctl`, `launchctl`). All isolation, restoration, and service lifecycle operations use pure Rust and direct OS kernel/syscall APIs.

### Workspace Crate Structure
1. `crates/killswitch-types`: Common types, traits, enums (`ByzantineKillSwitchFraudProof`, `BinaryTrustVerdict`, `KillChainStatus`, `KillChainHealthProbeReport`, `ProcessInstanceIdentity`, `VoteResult`, `EvidenceClass`, `ArmRole`, `TrustTier`, `ServiceStatus`, `ServiceConfig`).
2. `crates/killswitch-core`: Native containment and service engine:
   - Windows: Dynamic WFP sessions (`fwpuclnt.dll` with `FWPM_SESSION_FLAG_DYNAMIC`), Win32 BFE registry (`winreg`), direct TCP termination (`iphlpapi.dll` `SetTcpEntry` with `MIB_TCP_STATE_DELETE_TCB = 12`).
   - Linux: Netlink raw sockets, `/proc/net/tcp` parsing, Landlock LSM syscalls.
   - macOS: Darwin BSD packet filter `/dev/pf` ioctl (`DIOCSTART`, `DIOCXBEGIN`, `DIOCADDRULE`, `DIOCXCOMMIT`), `sysctl`/`proc_pidinfo` socket inspection, loopback/DNS/DHCP/port 3030 preservation, zero `pfctl`.
   - Non-destructive process freeze & resume: `NtSuspendProcess`/`NtResumeProcess` (Windows), `libc::kill(pid, SIGSTOP/SIGCONT)` (Linux & macOS), `ActiveProcessTarpit`.
   - macOS critical system process immunity in `is_critical_system_pid` (`launchd`, `WindowServer`, `loginwindow`, `kernel_task`, `UserEventAgent`, `cfprefsd`, `opendirectoryd`, `mds`, `Finder`, `Dock`, `Terminal`, `iTerm2`).
   - Credential & auth: `subtle::ConstantTimeEq`, BLAKE3 / SHA-256 hashes, shadow `crypt(3)` FFI, 3-strike 300s lockout, caller PID validation (`validate_killchain_caller`).
   - State ledger: atomic `killchain_state.json` with BLAKE3 hash chaining.
   - Native OS service lifecycle (`service.rs`):
     - Windows: Direct Win32 SCM FFI (`advapi32.dll`: `OpenSCManagerW`, `CreateServiceW`, `OpenServiceW`, `StartServiceW`, `ControlService`, `DeleteService`, `QueryServiceStatusEx`, `StartServiceCtrlDispatcherW`, `RegisterServiceCtrlHandlerExW`, `SetServiceStatus`).
     - Linux: Pure Rust `systemd` service unit generation and direct filesystem installation (`/etc/systemd/system/killswitch.service` or user unit) + `NOTIFY_SOCKET` (`sd_notify` UNIX datagram) + POSIX signals. Zero `systemctl`.
     - macOS: Pure Rust `launchd` `.plist` XML generation and direct filesystem installation (`/Library/LaunchDaemons/com.oshoosi.killswitch.plist` or LaunchAgents) + POSIX signals. Zero `launchctl`.
     - Unconditional automatic host disarm on service stop/shutdown (`execute_host_disarm_unauthenticated()`).
3. `crates/killswitch-adjudication`: Zero-false-positive adjudication engine:
   - REA engine (`AutonomousReaEngine`) with 4-layer defense.
   - Multi-voter consensus (`orchestrate_evidence`) across evidence classes with single-voter penalty, integrating DLP Lineage Evidence from `EndpointLineageEngine`.
   - Authenticode & Windows Catalog validation (`win_trust.rs`).
   - Protected binary BLAKE3 inventory (`PROTECTED_LOCAL_BINARY_HASHES`) & critical PID whitelist (`is_critical_system_pid`) with parent ancestry traversal up to depth 5.
   - Byzantine killswitch fraud proof builder (`build_kill_switch_fraud_proof`) and peer veto (`veto_peer_kill_switch_candidate`).
4. `crates/killswitch-telemetry`: EDR, DLP Lineage, and Octopus anomaly multi-ring triggers:
   - EDR: Phase-lock Lyapunov monitor (`edr-phaselock`), causal graph provenance (`ProcessInstanceIdentity`), attack graph, event correlator, canaries, hardware watchdog, honeytokens.
   - Hybrid OpenTelemetry & OpenLineage DLP Engine (`otel_lineage.rs`): `EndpointLineageEngine`, composite `ProcessKey`/`FileKey`, sticky W3C `TaintBaggage` escalation & merge, OpenLineage datasets/facets, `seed_sensitive_file`, `on_process_create`, `on_file_read`, `on_file_write`, fast inline `evaluate_egress` DashMap check returning `EgressVerdict::Block { reason, trace_id }`.
   - Octopus: `ArmContainmentRing` with monotonic generation epoch advancement (`Gen N -> Gen N+1`), HMAC-SHA256 `MeshGuard`, `HomologicalBoundaryAuditor`, case-insensitive lateral sink isolation (`LAW1_STICKY_TAINT_VETO`), `BreakoutDefenseCoordinator`, mathematical IPv4/IPv6 SSRF guards and safe `Path::join` traversal defenses.
5. `crates/killswitch-orchestrator`: Native Rust LangGraph stateful execution engine:
   - Cyclic `StateGraph` with typed state (`KillSwitchGraphState`), 10-node lifecycle transitions, persistent checkpointer, BLAKE3 execution trace.
   - DLP Lineage Trigger Node: evaluates `EgressVerdict::Block` and routes high-confidence exfiltration to containment while preserving critical system PIDs.
   - Local Ollama node adhering to Dynamic Available Memory Law with 400ms timeout and offline fallback.
   - Autonomous mode (3 clean probes early restore, 30-min failsafe) and Manual mode (HITL checkpoint, constant-time `CONFIRM ISOLATE`/`RESTORE`).
6. `crates/killswitch-server`: Local HTTP/JSON control API on port 3030 (Axum) preserving loopback and port 3030 during quarantine, plus `/service/status` and `/lineage/*`.
7. `crates/killswitch-cli`: Command-line interface tool (`killswitch-cli` / `killswitch`) including `killswitch service` and `killswitch lineage`.

---

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Workspace Cargo & Types | Scaffolding Cargo workspace, crates layout, common types, traits, error definitions | M1 | ORIGINAL_REQUEST §R1-R4 |
| 2 | Windows Native WFP Isolation | `fwpuclnt.dll` dynamic sessions with `FWPM_SESSION_FLAG_DYNAMIC` and atomic transactions, preserving loopback, DNS/DHCP, port 3030 | M2 | ORIGINAL_REQUEST §R1 |
| 3 | Windows Native BFE Registry | `HKLM\SYSTEM\...\FirewallRules` management via `winreg` | M2 | ORIGINAL_REQUEST §R1 |
| 4 | Windows Direct TCP Reset | `iphlpapi.dll` `GetTcpTable` + `SetTcpEntry` (`MIB_TCP_STATE_DELETE_TCB = 12`) | M2 | ORIGINAL_REQUEST §R1 |
| 5 | Linux Netlink & Landlock Isolation | Raw Netlink sockets, `/proc/net/tcp` parsing, and Landlock LSM syscalls with zero `iptables`/`nft` calls | M2 | ORIGINAL_REQUEST §R1 |
| 6 | Native Process Freeze & Resume | `NtSuspendProcess`/`NtResumeProcess` (Windows), `SIGSTOP`/`SIGCONT` (Linux & macOS) | M2 | ORIGINAL_REQUEST §R1, Follow-up |
| 7 | Active Process Tarpit | Thread-level Toolhelp32 snapshot, suspend/resume duty cycle | M2 | ORIGINAL_REQUEST §R1 |
| 8 | Operator Credential Verification | `subtle::ConstantTimeEq`, BLAKE3/SHA-256 hashes, shadow `crypt(3)` FFI, no `unix_chkpwd`/`dscl`/`LogonUserW` | M2 | ORIGINAL_REQUEST §R1 |
| 9 | Anti-Lockout & Caller Validation | 3-strike 300s rate-limit lockout, `validate_killchain_caller` blocking frozen/quarantined callers | M2 | ORIGINAL_REQUEST §R1 |
| 10 | BLAKE3 State Ledger | Atomic `killchain_state.json` persistence with BLAKE3 cryptographic hash chaining | M2 | ORIGINAL_REQUEST §R3 |
| 11 | REA Adjudication Engine | `AutonomousReaEngine` 4-layer defense, anti-masquerade, dev process calibration | M3 | ORIGINAL_REQUEST §R2 |
| 12 | Multi-Voter Consensus | 6 evidence classes + DLP Lineage, support/mass weighting, single-voter penalty (`0.52`), threshold >= 0.94 | M3 | ORIGINAL_REQUEST §R2, Follow-up #2 |
| 13 | Authenticode & Catalog Validation | WinVerifyTrust and CatRoot hash verification with offline fallback | M3 | ORIGINAL_REQUEST §R2 |
| 14 | Protected Binary Inventory & Lineage Immunity | In-memory BLAKE3 set, `is_critical_system_pid` whitelist (Windows, Linux, macOS), parent ancestry traversal up to depth 5 | M3 | ORIGINAL_REQUEST §R2, Follow-up |
| 15 | Byzantine Fraud Proof Builder | `build_kill_switch_fraud_proof` BLAKE3 seal, `veto_peer_kill_switch_candidate` | M3 | ORIGINAL_REQUEST §R2 |
| 16 | EDR Phase-Lock Monitor | 4D delay embedding ($m=4$, $\tau=2$), Lyapunov exponent divergence calculation | M4 | ORIGINAL_REQUEST §R2 |
| 17 | Causal & Attack Graph Correlation | `ProcessInstanceIdentity` BLAKE3 provenance, multi-stage kill-chain correlation, time-decay correlator | M4 | ORIGINAL_REQUEST §R2 |
| 18 | Canaries, Watchdog & Honeytokens | Ghost traps, dynamic assets, hardware CPU/memory watchdog HMAC-SHA256 challenge | M4 | ORIGINAL_REQUEST §R2 |
| 19 | Octopus Arm Containment Ring | Monotonic generation epoch advancement (`Gen N -> Gen N+1`), surgical autotomy | M4 | ORIGINAL_REQUEST §R2 |
| 20 | MeshGuard & Boundary Audit | Constant-time HMAC-SHA256 message verification, homological boundary audit ($\partial^2 = 0$), sticky taint veto | M4 | ORIGINAL_REQUEST §R2 |
| 21 | Breakout Defense & SSRF / Path Guards | 4-category breakout coordinator, mathematical IPv4/IPv6 literal parser, safe `Path::join` traversal defense | M4 | ORIGINAL_REQUEST §R2 |
| 22 | Native Rust LangGraph StateGraph | Typed state, node registry, conditional edges, cyclic health-probing loops, checkpointer, BLAKE3 trace | M5 | ORIGINAL_REQUEST §R2 |
| 23 | Local Ollama Reasoning Node | Dynamic free RAM/VRAM sizing law, 400ms timeout, deterministic offline fallback | M5 | ORIGINAL_REQUEST §R2 |
| 24 | Autonomous & Manual Reversible Modes | 3 clean probes early restoration, 30-min failsafe; HITL `CONFIRM ISOLATE`/`RESTORE` | M5 | ORIGINAL_REQUEST §R3 |
| 25 | Local HTTP/JSON API on Port 3030 | Axum API (`/status`, `/history`, `/engage`, `/disarm`, `/health-probe`, `/graph/step`, `/graph/state`, `/mode`, `/octopus/arms`, `/edr/ingest`, `/service/status`, `/lineage/*`) | M5 | ORIGINAL_REQUEST §R3, Follow-up #1 & #2 |
| 26 | CLI Binary Interface | Clap CLI (`killswitch-cli` / `killswitch`) commands, flags, `service`, and `lineage` | M5 | ORIGINAL_REQUEST §R3, Follow-up #1 & #2 |
| 27 | Opaque-Box E2E Testing Suite (Tiers 1-4) | Comprehensive Category-Partition, BVA, Pairwise, Real-World test suite in `tests/` | M6 / E2E Track | ORIGINAL_REQUEST §Acceptance |
| 28 | Adversarial Coverage Hardening (Tier 5) | White-box stress testing, chaos fuzzing, gap analysis | M6 / E2E Track | ORIGINAL_REQUEST §Acceptance |
| 29 | macOS Native PF Isolation | Darwin `/dev/pf` device ioctl (`DIOCSTART`, `DIOCXBEGIN`, `DIOCADDRULE`, `DIOCXCOMMIT`), `sysctl`/`proc_pidinfo` sockets, loopback/DNS/DHCP/port 3030 | M2 | ORIGINAL_REQUEST §Follow-up |
| 30 | macOS Process Freeze & System Whitelist | `libc::kill(SIGSTOP/SIGCONT)`, macOS system whitelist (`launchd`, `WindowServer`, `loginwindow`, etc.) | M2 | ORIGINAL_REQUEST §Follow-up |
| 31 | Native OS Service Lifecycle & Auto-Disarm | Win32 SCM FFI, systemd unit + sd_notify, launchd plist, zero CLI tools, unconditional shutdown disarm, CLI & HTTP service commands | M2, M5 | ORIGINAL_REQUEST §Follow-up |
| 32 | OpenTelemetry & OpenLineage DLP Engine | `EndpointLineageEngine`: composite keys, sticky `TaintBaggage` merge, OpenLineage datasets/facets, W3C trace propagation, fast inline `evaluate_egress` DashMap block, LangGraph DLP trigger | M3, M4, M5 | ORIGINAL_REQUEST §Follow-up #2 |
| 33 | Unified `killswitch.exe` / `start.exe` All-In-One Loader | Binary targets `killswitch` and `start`, unified executable `killswitch.exe` ("load it all" + CLI) and alias `start.exe`, boots and wires 100% of subsystems into single unified runtime, supports `--verify`/`--check`, copied to `d:\harfile\killswitch\killswitch.exe` and `d:\harfile\killswitch\start.exe` | M5, M6 | ORIGINAL_REQUEST §Follow-up #4 & #6 |
| 34 | Automatic Port Fallback & Dynamic Allowlist | When port 3030 is in use, automatically fall back to ports 3031..=3050 (or ephemeral 0), log clear message, dynamically allowlist actual port in WFP/Netlink/PF quarantine, persist in active_port.txt for CLI discovery | M5, M6 | ORIGINAL_REQUEST §Follow-up #5 |


---

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Workspace Foundation & Common Types | Cargo workspace setup, `crates/killswitch-types`, error definitions, core traits | none | DONE (commit `141ad63`, 54 tests passed, 0 warnings) |
| M2 | Zero-OS-Tool Native Containment & Service Engine | `crates/killswitch-core`: WFP/BFE/iphlpapi, Netlink/Landlock, macOS /dev/pf, Native Freeze/Resume (Win/Linux/macOS), Tarpit, Auth & Anti-Lockout, BLAKE3 Ledger, Native OS Service Engine | M1 | DONE (commit `0708dfe`, 149 tests passed workspace-wide, 0 clippy warnings, Gate PASSED) |
| M3 | Zero-False-Positive Adjudication & Veto | `crates/killswitch-adjudication`: REA engine, Multi-Voter consensus (including DLP Lineage evidence), WinTrust, Lineage immunity (depth 5, including Win/Linux/macOS), Byzantine fraud proofs | M1 | DONE (commit `139d9d0`, 198 tests passed workspace-wide, 0 clippy warnings, Gate PASSED) |
| M4 | EDR Telemetry, DLP Lineage & Octopus Triggers | `crates/killswitch-telemetry`: Phase-lock, Causal/Attack graph, Correlator, Canaries/Watchdog, EndpointLineageEngine (OTel + OpenLineage), ArmContainmentRing, MeshGuard, Breakout Defense, SSRF/Path guards | M1 | DONE (commit `fa2d34c`, 81 crate tests, 328 workspace tests passed, 0 clippy warnings, Gate PASSED) |
| M5 | LangGraph Stateful Orchestrator, CLI & HTTP API, start.exe Loader | `crates/killswitch-orchestrator`, `crates/killswitch-server`, `crates/killswitch-cli`: StateGraph (including DLP lineage trigger node), Ollama node, Reversible modes, Axum API (port 3030 with `/service/status` and `/lineage/*`), CLI (including `service` and `lineage`), and unified `start.exe` all-in-one loader | M2, M3, M4 | IN_PROGRESS |
| M6 | Final Verification, 100% E2E Test Pass & Tier 5 Hardening | Complete E2E integration test pass (Tiers 1-4, including Multi-Hop DLP Exfiltration Fan-In test and `start.exe --verify`), Tier 5 Adversarial Coverage Hardening, Zero-OS-Tool audit, Sentinel report | M5, TEST_READY.md | PLANNED |

In parallel:
- **E2E Testing Track**: Dispatched independently to develop `TEST_INFRA.md`, test harness, and Tiers 1-4 test suites, publishing `TEST_READY.md`. (Status: `TEST_INFRA.md` published).

---

## Interface Contracts
### `killswitch-core` Service Manager Interface
- `NativeServiceManager`:
  - `fn install_service(&self, config: &ServiceConfig) -> Result<(), ServiceError>;`
  - `fn uninstall_service(&self, service_name: &str) -> Result<(), ServiceError>;`
  - `fn start_service(&self, service_name: &str) -> Result<(), ServiceError>;`
  - `fn stop_service(&self, service_name: &str) -> Result<(), ServiceError>;`
  - `fn service_status(&self, service_name: &str) -> Result<ServiceStatus, ServiceError>;`
  - `fn run_service_daemon(&self) -> Result<(), ServiceError>;`
- Unconditional shutdown hook: When receiving stop/shutdown signal (`SERVICE_CONTROL_STOP`, `SIGTERM`, `SIGINT`), invokes `execute_host_disarm_unauthenticated()`.

### `killswitch-telemetry` Endpoint Lineage Engine Interface
- `EndpointLineageEngine`:
  - `fn seed_sensitive_file(&self, file_key: FileKey, path: &str, sha256: &str, classification: DlpClassification, policy: DlpPolicy);`
  - `fn on_process_create(&self, parent_key: Option<ProcessKey>, child_key: ProcessKey, exe_path: &str);`
  - `fn on_file_read(&self, proc_key: ProcessKey, file_key: FileKey);`
  - `fn on_file_write(&self, proc_key: ProcessKey, out_file_key: FileKey, out_path: &str, out_sha256: &str);`
  - `fn evaluate_egress(&self, proc_key: ProcessKey, destination_url: &str) -> EgressVerdict;`

