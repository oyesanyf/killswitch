# Project: KillSwitch Cross-Platform Service, Launcher & Multi-Repo Migration

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
3. `crates/killswitch-adjudication`: Zero-false-positive adjudication engine.
4. `crates/killswitch-telemetry`: EDR, DLP Lineage, and Octopus anomaly multi-ring triggers.
5. `crates/killswitch-orchestrator`: Native Rust LangGraph stateful execution engine.
6. `crates/killswitch-server`: Local HTTP/JSON control API on port 3030 (Axum) preserving loopback and port 3030 during quarantine, plus `/service/status` and `/lineage/*`.
7. `crates/killswitch-cli`: Command-line interface tool (`killswitch-cli` / `killswitch`) including `killswitch service` and `killswitch lineage`.

---

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Workspace Cargo & Types | Scaffolding Cargo workspace, crates layout, common types, traits, error definitions | M0 (Prior) | ORIGINAL_REQUEST |
| 2 | Windows Native WFP Isolation | `fwpuclnt.dll` dynamic sessions with loopback, DNS/DHCP, port 3030 preservation | M0 (Prior) | ORIGINAL_REQUEST |
| 3 | Windows Native BFE Registry | `HKLM\SYSTEM\...\FirewallRules` management via `winreg` | M0 (Prior) | ORIGINAL_REQUEST |
| 4 | Windows Direct TCP Reset | `iphlpapi.dll` `GetTcpTable` + `SetTcpEntry` (`MIB_TCP_STATE_DELETE_TCB = 12`) | M0 (Prior) | ORIGINAL_REQUEST |
| 5 | Linux Netlink & Landlock Isolation | Raw Netlink sockets, `/proc/net/tcp` parsing, Landlock LSM syscalls | M0 (Prior) | ORIGINAL_REQUEST |
| 6 | Native Process Freeze & Resume | `NtSuspendProcess`/`NtResumeProcess`, `SIGSTOP`/`SIGCONT` | M0 (Prior) | ORIGINAL_REQUEST |
| 7 | Active Process Tarpit | Thread-level Toolhelp32 snapshot, suspend/resume duty cycle | M0 (Prior) | ORIGINAL_REQUEST |
| 8 | Operator Credential Verification | `subtle::ConstantTimeEq`, BLAKE3/SHA-256 hashes, shadow `crypt(3)` FFI | M0 (Prior) | ORIGINAL_REQUEST |
| 9 | Anti-Lockout & Caller Validation | 3-strike 300s rate-limit lockout, `validate_killchain_caller` | M0 (Prior) | ORIGINAL_REQUEST |
| 10 | BLAKE3 State Ledger | Atomic `killchain_state.json` persistence with BLAKE3 hash chaining | M0 (Prior) | ORIGINAL_REQUEST |
| 11 | REA Adjudication Engine | `AutonomousReaEngine` 4-layer defense, anti-masquerade | M0 (Prior) | ORIGINAL_REQUEST |
| 12 | Multi-Voter Consensus | 6 evidence classes + DLP Lineage, support/mass weighting | M0 (Prior) | ORIGINAL_REQUEST |
| 13 | Authenticode & Catalog Validation | WinVerifyTrust and CatRoot hash verification | M0 (Prior) | ORIGINAL_REQUEST |
| 14 | Protected Binary Inventory | In-memory BLAKE3 set, `is_critical_system_pid` whitelist (Win/Linux/macOS) | M0 (Prior) | ORIGINAL_REQUEST |
| 15 | Byzantine Fraud Proof Builder | `build_kill_switch_fraud_proof` BLAKE3 seal, peer veto | M0 (Prior) | ORIGINAL_REQUEST |
| 16 | EDR Phase-Lock Monitor | 4D delay embedding, Lyapunov exponent divergence calculation | M0 (Prior) | ORIGINAL_REQUEST |
| 17 | Causal & Attack Graph Correlation | `ProcessInstanceIdentity` BLAKE3 provenance, multi-stage correlation | M0 (Prior) | ORIGINAL_REQUEST |
| 18 | Canaries, Watchdog & Honeytokens | Ghost traps, dynamic assets, hardware CPU/memory watchdog | M0 (Prior) | ORIGINAL_REQUEST |
| 19 | Octopus Arm Containment Ring | Monotonic generation epoch advancement (`Gen N -> Gen N+1`) | M0 (Prior) | ORIGINAL_REQUEST |
| 20 | MeshGuard & Boundary Audit | Constant-time HMAC-SHA256 message verification, boundary audit | M0 (Prior) | ORIGINAL_REQUEST |
| 21 | Breakout Defense & SSRF / Path Guards | 4-category breakout coordinator, mathematical IPv4/IPv6 parser | M0 (Prior) | ORIGINAL_REQUEST |
| 22 | Native Rust LangGraph StateGraph | Typed state, node registry, cyclic health-probing loops | M0 (Prior) | ORIGINAL_REQUEST |
| 23 | Local Ollama Reasoning Node | Dynamic free RAM/VRAM sizing law, 400ms timeout | M0 (Prior) | ORIGINAL_REQUEST |
| 24 | Autonomous & Manual Reversible Modes | 3 clean probes early restoration, 30-min failsafe; HITL mode | M0 (Prior) | ORIGINAL_REQUEST |
| 25 | Local HTTP/JSON API on Port 3030 | Axum API preserving loopback and port 3030 | M0 (Prior) | ORIGINAL_REQUEST |
| 26 | CLI Binary Interface | Clap CLI (`killswitch-cli` / `killswitch`) | M0 (Prior) | ORIGINAL_REQUEST |
| 27 | Opaque-Box E2E Testing Suite | Comprehensive Category-Partition, BVA, Pairwise test suite in `tests/` | M0 (Prior) | ORIGINAL_REQUEST |
| 28 | Adversarial Coverage Hardening | White-box stress testing, chaos fuzzing, gap analysis | M0 (Prior) | ORIGINAL_REQUEST |
| 29 | macOS Native PF Isolation | Darwin `/dev/pf` device ioctl, loopback/port 3030 preservation | M0 (Prior) | ORIGINAL_REQUEST |
| 30 | macOS Process Freeze & System Whitelist | `libc::kill(SIGSTOP/SIGCONT)`, macOS system whitelist | M0 (Prior) | ORIGINAL_REQUEST |
| 31 | Native OS Service Lifecycle Engine | Win32 SCM FFI, systemd unit + sd_notify, launchd plist | M0 (Prior) | ORIGINAL_REQUEST |
| 32 | OpenTelemetry & OpenLineage DLP Engine | `EndpointLineageEngine`: composite keys, sticky `TaintBaggage` | M0 (Prior) | ORIGINAL_REQUEST |
| 33 | Unified `killswitch.exe` / `start.exe` Loader | Binary targets `killswitch` and `start`, unified runtime loader | M0 (Prior) | ORIGINAL_REQUEST |
| 34 | Automatic Port Fallback & Dynamic Allowlist | Fallback ports 3031..=3050, `active_port.txt`, dynamic allowlist | M0 (Prior) | ORIGINAL_REQUEST |
| 35 | Cross-Platform `--service` Lifecycle | `--service install`, `delete`, `uninstall`, `start`, `stop`, `restart`, `status`, `run` on `killswitch` and `start` across Windows SCM, systemd, launchd | M1 | ORIGINAL_REQUEST §R1 |
| 36 | CLI vs Launcher Browser Launch Behavior | `killswitch` CLI headless by default (`--open-browser` / `--browser` required); `start.exe` auto-opens `http://127.0.0.1:3030` | M1 | ORIGINAL_REQUEST §R1 |
| 37 | Zero-Touch PATH WiX Packaging | `installer/killswitch.wxs` installing native Windows service with `--service run` and post-install browser launch; zero `<Environment Id="PATH">` | M1 | ORIGINAL_REQUEST §R1 |
| 38 | Release Workflow Packaging | Linux `.deb` (systemd unit, postinst/prerm, browser launch) & macOS `.pkg` (launchd plist, postinstall, browser launch) in `.github/workflows/release.yml` | M1 | ORIGINAL_REQUEST §R1 |
| 39 | WebUI Button Auth & Route Alignment | `POST /disarm` control-plane auth accepting `KILLCHAIN_RESTORE_CONFIRMATION_PHRASE`, clean UTF-8 strings, scenario and preset aliases in handlers | M2 | ORIGINAL_REQUEST §R2 |
| 40 | Release Builds & Button Verification | Build release `killswitch.exe` and `start.exe`; run `verify_all_webui_buttons.py` with 100% pass rate & 0 fetch errors | M2 | ORIGINAL_REQUEST §R2 |
| 41 | Killswitch Shipping & CI Remediation | Stage, commit, ship via `scripts/solo_pr_ship.ps1`, verify and remediate GitHub Actions workflows to 100% green | M2 | ORIGINAL_REQUEST §R2 |
| 42 | OshoosiClaw Sequential Migration | Migrate service management, browser behavior, and WebUI fixes to `D:\harfile\OshoosiClaw`, build `osoosi.exe`, run `cargo test --workspace`, ship via solo PR, verify 100% green CI | M3 | ORIGINAL_REQUEST §R3 |
| 43 | AgentOctopus Sequential Migration | Migrate service management, browser behavior, and WebUI fixes to `D:\harfile\AgentOctopus`, build `agent_octopus.exe` and `start.exe`, run `cargo test`, ship, verify 100% green CI | M4 | ORIGINAL_REQUEST §R4 |
| 44 | Cross-Repository Forensic Integrity Audit | Independent verification of zero mocks, repository boundary compliance, and final completion handoff to Sentinel | M5 | ORIGINAL_REQUEST §Acceptance |

---

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Killswitch Service Management, Browser Behavior & Installer Packaging | Features 35, 36, 37, 38 in `killswitch` (R1) | none | DONE (Gate PASSED: 132/132 tests passed, 0 clippy warnings, Reviewers APPROVE, Challengers APPROVE, Auditor CLEAN) |
| M2 | Killswitch WebUI Button Fixes, Release Builds, Button Verification & CI Remediation | Features 39, 40, 41 in `killswitch` (R2) | M1 | DONE (Gate PASSED: 73/73 WebUI buttons passed, CI run 42432666169 100% green across all 5 jobs, Auditor CLEAN) |
| M3 | OshoosiClaw Sequential Migration, Verification & Remote CI | Feature 42 in `D:\harfile\OshoosiClaw` (R3) | M2 | DONE (Gate PASSED: PR #434 merged at 0f64765d, 7/7 genuine self-diagnostics verified, 6/6 remote CI green, Auditor CLEAN) |
| M4 | AgentOctopus Sequential Migration, Verification & Remote CI | Feature 43 in `D:\harfile\AgentOctopus` (R4) | M3 | DONE (Gate PASSED: Commit `3fa5faa` pushed, 7/7 genuine verify exit 0, remote CI 100% green, Auditor CLEAN) |
| M5 | Final Cross-Repository Forensic Integrity Audit & Sentinel Handoff | Feature 44 across all three repositories | M4 | IN_PROGRESS |

---

## Code Layout
### `d:\harfile\killswitch`
- `crates/killswitch-core/src/service.rs`: Pure Win32 SCM, Linux systemd, macOS launchd service engine
- `crates/killswitch-server/src/server.rs`: Axum HTTP server configuration (`open_browser: bool`), browser launcher
- `crates/killswitch-server/src/handlers.rs`: REST API endpoints, control-plane auth, service control handlers
- `crates/killswitch-cli/src/loader.rs`: Unified runtime config and bootloader
- `crates/killswitch-cli/src/bin/killswitch.rs`: CLI binary entry point (`--open-browser`, `--service <action>`, `service <action>`)
- `crates/killswitch-cli/src/bin/start.rs`: Launcher binary entry point (auto-open browser default, `--no-browser`, `--service <action>`, `service <action>`)
- `crates/killswitch-cli/src/commands/mod.rs`: Native service CLI handler invoking `default_service_manager()` directly
- `installer/killswitch.wxs`: Windows WiX MSI installer definition (Zero-Touch PATH compliant)
- `.github/workflows/release.yml`: GitHub Actions release pipeline for Linux deb and macOS pkg

### `D:\harfile\OshoosiClaw`
- CLI binary `osoosi` / `start`
- Crate structure: `osoosi-core`, `osoosi-dp`, `osoosi-telemetry`, `osoosi-agent-anomaly`, `osoosi-dashboard`, `osoosi-cli`

### `D:\harfile\AgentOctopus`
- CLI binary `agent_octopus` / `start`
- Crate structure: `crates/octopus-core`, `crates/octopus-server`, etc.
