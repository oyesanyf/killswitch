# 🛡️ KillSwitch — Standalone Autonomous & Reversible Endpoint Security Agent

**KillSwitch** is a self-contained, zero-external-dependency endpoint protection and emergency network containment system written in **100% pure Rust** for **Windows, macOS, and Linux**.

It runs **100% independently** without requiring any external EDR, antivirus, or OS CLI wrapper tools (`netsh`, `iptables`, `nft`, `pfctl`, `taskkill`, or `sc.exe`). When started, it automatically launches a **plain-English WebUI Dashboard** in your default browser, explains **what caused the KillSwitch to activate** in clear everyday language, and preserves access to the local dashboard port (`-p 4040` / `3030`) even when the computer is under full internet lockdown.

---

## ✨ Key Capabilities

### 1. Plain-English WebUI Dashboard (Auto-Launches Browser on Startup)
- **Automatic Browser Launch**: Running `killswitch.exe` (or `killswitch.exe -p 4040`) automatically binds the local control server (with automatic fallback if a port is already in use) and opens `http://127.0.0.1:<port>` in your default browser across **Windows** (`explorer.exe`), **macOS** (`open`), and **Linux** (`xdg-open` / `gio`).
- **"What Caused the KillSwitch?" Root-Cause Forensics**: Displays a prominent plain-English explanation at the top of the page (and in `killswitch status`) showing **what triggered the KillSwitch**, **who/what caused it** (e.g., manual disconnect vs. automatic private file leak prevention), **which app/PID and destination URL were blocked**, and **when it happened**.
- **One-Click Internet Disconnect & Restore**:
  - **🚨 Disconnect Internet Now (Turn On KillSwitch)**: Instantly blocks all external internet traffic (TCP, UDP/QUIC HTTP/3, DNS, and ICMP `ping`) while keeping the local WebUI Dashboard port open.
  - **🟢 Reconnect Internet & Restore Normal Use**: Immediately removes all kernel firewall filters and restores full internet access.
  - **🩺 Check Computer & App Health**: Scans running apps natively to verify all core operating system processes are healthy.

### 2. 100% OpenTelemetry & OpenLineage Endpoint DLP Data Lineage Engine
- **100% Autonomous Voter**: Tracks sensitive files (`CrownJewel`, `Confidential`, `Internal`, `Public`) using SHA-256 content digests, OpenLineage dataset facets, and W3C Trace Context / Sticky Baggage (`dlp.classification`, `dlp.policy`, `dlp.source_sha256`).
- **Multi-Hop Taint Propagation**: Propagates taint across child processes and intermediate file writes with anti-taint-creep TTL guards for long-lived processes.
- **Sub-10µs Inline Egress Block & Auto-KillSwitch**: When any tainted process attempts to upload a `CrownJewel` / `Quarantine` file to an external URL, the DLP Lineage Engine blocks the egress inline and—when Automatic Protection is ON—autonomously triggers the host KillSwitch and logs the exact offending PID, file path, SHA-256 hash, and destination URL as the KillSwitch root cause.

### 3. Standalone Cross-Platform Kernel Isolation (Windows, macOS, Linux)
- **Windows (`killswitch-core::wfp`)**:
  - Dynamic **Windows Filtering Platform (WFP)** kernel sessions via `fwpuclnt.dll` (`FwpmEngineOpen0`, `FwpmTransactionBegin0`, `FwpmFilterAdd0`, `FwpmFilterDeleteById0`) across `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`, `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6`, and `FWPM_LAYER_OUTBOUND_TRANSPORT_V4/V6` (blocking pooled TCP, UDP/QUIC HTTP/3, and ICMP).
  - Native **BFE Registry** rule persistence and immediate active TCP socket reset via `iphlpapi.dll` (`GetExtendedTcpTable` + `SetTcpEntry` `MIB_TCP_STATE_DELETE_TCB`).
  - Non-destructive process suspension via `ntdll.dll` (`NtSuspendProcess` / `NtResumeProcess`) and asymmetric thread tarpitting (`SuspendThread` / `ResumeThread`).
- **macOS (`killswitch-core::pf`)**:
  - Native `/dev/pf` ioctl (`DIOCADDRULE` / `DIOCCHANGERULE`) anchor rules (`com.killswitch.quarantine`), Darwin `proc_pidinfo` socket inspection, `launchd` plist management, and `SIGSTOP` / `SIGCONT` process containment with full immunity for `launchd`, `WindowServer`, `loginwindow`, `Finder`, `Dock`, `Terminal`, and `iTerm2`.
- **Linux (`killswitch-core::landlock`)**:
  - Native `AF_NETLINK` routing/NFQUEUE isolation, `/proc/net/tcp` & `/proc/net/tcp6` hex socket parsing, Linux **Landlock LSM (ABI v1–v5)** filesystem sandboxing, `systemd` unit generation, and `SIGSTOP` / `SIGCONT` process freezing.

### 4. Zero-False-Positive Multi-Voter Adjudication & 10-Node LangGraph Orchestrator
- **Depth-5 Process Ancestry & Critical OS Anchor Immunity**: Hardcoded immunity for PIDs `0`, `1`, `4`, the agent itself, up to 5 parent generations, and critical system/developer processes (`explorer.exe`, `svchost.exe`, `lsass.exe`, `csrss.exe`, `WindowServer`, `systemd`, shells, browsers, IDEs).
- **10-Node Cyclic LangGraph State Machine**: Deterministic cyclic transitions (`Monitoring` → `IngestingSignals` → `CorrelatingEdrAndOctopus` → `AdjudicatingZeroFalsePositive` → `OptionalOllamaReasoning` → `EngagingContainment` → `IsolatedHealthProbing` → `DisarmingAndRestoring`) with BLAKE3-chained execution trace verification.
- **Octopus 18-Arm Containment Mesh**: Constant-time HMAC-SHA256 inter-agent verification and monotonic epoch advancement across 18 specialized defense arms.

---

## 📦 Workspace Architecture (7 Rust Crates)

| Crate | Description |
| :--- | :--- |
| `crates/killswitch-types` | Core traits (`NetworkIsolator`, `ProcessFreezer`, `HealthProbeRunner`), DTOs, and error types |
| `crates/killswitch-core` | Native Windows WFP/BFE, Linux Netlink/Landlock, macOS `/dev/pf`, `NtSuspendProcess`/`SIGSTOP`, 4-tier operator auth, and BLAKE3 state ledger |
| `crates/killswitch-adjudication` | 3-Voter consensus engine, native WinTrust (`wintrust.dll`) signature/catalog verifier, and Byzantine fraud proofs |
| `crates/killswitch-telemetry` | 100% OpenTelemetry & OpenLineage DLP Engine, Octopus 18-arm HMAC-SHA256 rings, and PhaseLock correlation |
| `crates/killswitch-orchestrator` | 10-node cyclic LangGraph orchestrator, durable atomic checkpointer, and dynamic-memory Ollama reasoning |
| `crates/killswitch-server` | Axum HTTP control server (15 REST endpoints) and embedded plain-English WebUI Dashboard (`GET /` & `GET /ui`) |
| `crates/killswitch-cli` | Unified loader (`killswitch` / `start`) booting all 6 subsystems, auto-opening the browser, and providing CLI subcommands |

---

## 🚀 Quick Start (Build & Run)

### 1. Build Release Binaries
```powershell
cargo build --release
```
This produces `target/release/killswitch.exe` and `target/release/start.exe` (on Windows) or `target/release/killswitch` and `target/release/start` (on macOS/Linux).

### 2. Start the Agent & Open the WebUI Dashboard
Run as **Administrator** (Windows) or `sudo` (macOS/Linux) so kernel firewall filters can be applied:
```powershell
# Default port 3030 (automatically falls back to the next free port if 3030 is in use)
.\target\release\killswitch.exe

# Or specify a custom port (e.g. 4040):
.\target\release\killswitch.exe -p 4040
```
- The agent boots all 6 subsystems, writes the bound port to `active_port.txt`, and **automatically opens `http://127.0.0.1:4040` in your default web browser**.
- Even when you click **🚨 Disconnect Internet Now (Turn On KillSwitch)**, `http://127.0.0.1:4040` stays 100% reachable so you can inspect what caused the KillSwitch and click **🟢 Reconnect Internet & Restore Normal Use** at any time.

### 3. CLI Subcommands
```powershell
# Run the 6-phase in-memory self-diagnostic suite (exits 0 when all 6 phases pass)
.\target\release\killswitch.exe --verify

# Check current status & what caused the KillSwitch
.\target\release\killswitch.exe status

# Engage emergency internet & host isolation from the terminal
.\target\release\killswitch.exe isolate

# Disarm KillSwitch & restore internet connectivity
.\target\release\killswitch.exe restore
```

---

## 🛡️ SWE-Bench Two-Gate (`FAIL_TO_PASS` & `PASS_TO_PASS`) Anti-Blind-KillSwitch Harness

To guarantee that KillSwitch **never blindly isolates a computer on a false alarm**, `killswitch-adjudication::edr_bench` adapts the **SWE-bench** two-gate verification paradigm directly into the autonomous containment pipeline:

1. **Gate 1 (`FAIL_TO_PASS` — Threat Precision Gate)**:
   - Every candidate detection rule or autonomous containment trigger must accurately detect the target threat binary (`benchmarks/artifacts/threats/ebpf_container_escape.elf`, verified via SHA-256) with the required rule tag/verdict within strict `HarnessBounds` (`max_compile_time_ms: 150`, `max_scan_latency_us: 50000`, `max_arena_memory_bytes: 16 MB`).
2. **Gate 2 (`PASS_TO_PASS` — Benign Baseline Continuity / Anti-Blind-KillSwitch Gate)**:
   - The candidate rule is scanned against the golden signed system/developer binary baseline (`benchmarks/artifacts/golden_baseline/usr_bin_signed/ls_benign.elf`, `ssh_benign.elf`).
   - Requires **0 false positives (`max_allowed_false_positives: 0`)**.
   - Overly broad rules (for example, matching any ELF `{ 7F 45 4C 46 }` header) pass `FAIL_TO_PASS` but **fail `PASS_TO_PASS`**, immediately vetoing blind KillSwitch isolation (`blind_killswitch_prevented: true`).
3. **Compiler-in-the-Loop Feedback Refinement & Cryptographic BFT Promotion**:
   - `evaluate_with_compiler_feedback_loop()` automatically refines overly broad rules into surgical multi-token rules that pass both `FAIL_TO_PASS` and `PASS_TO_PASS` (`0` false positives) and issues a constant-time verified `BLAKE3` + `SHA-256` BFT Promotion Receipt.

### REST API Endpoints
- **`GET /api/edr-bench/tasks`** (also aliased at `/edr-bench/tasks` and `/api/killswitch-bench/tasks`):
  - Returns the active SWE-bench / EDR-Bench task definitions (`OSHOOSI-BENCH-2026-0042` and `KILLSWITCH-BENCH-2026-0001`) along with canonical broad vs. verified multi-token rules.
- **`POST /api/edr-bench/evaluate`** (also aliased at `/edr-bench/evaluate` and `/api/killswitch-bench/evaluate`):
  - Evaluates a `candidate_yara_rule` or `preset` (`"overbroad_blind"` or `"surgical_verified"`) through Gate 1 (`FAIL_TO_PASS`) and Gate 2 (`PASS_TO_PASS`), optionally running compiler-in-the-loop refinement (`"auto_refine": true`).

