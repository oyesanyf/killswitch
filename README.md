# 🛡️ KillSwitch — Doomsday Endpoint Protection & Autonomous AI Agent Breakout Defense

**KillSwitch** is a self-contained, zero-external-dependency **Doomsday endpoint protection, AI agent breakout guard, and emergency network containment system** written in **100% pure Rust** for **Windows, macOS, and Linux**.

It runs **100% independently** without requiring any external EDR, antivirus, or OS CLI wrapper tools (`netsh`, `iptables`, `nft`, `pfctl`, `taskkill`, or `sc.exe`). When started, it automatically launches a **plain-English WebUI Dashboard** in your default browser, explains **what caused the KillSwitch to activate** in clear everyday language, and preserves access to the local dashboard port (`-p 4040` / `3030`) even when the computer is under full internet lockdown.

---

## 🚨 Doomsday Protection & Autonomous AI Agent Breakout Defense

**KillSwitch** is specifically architected as a **last-line "Doomsday" circuit breaker** against both **external AI swarms/worms attacking over the internet** and **local autonomous AI agents attempting to break out of their sandbox or exfiltrate sensitive data**:

### 1. External AI Swarm & Worm Cut-Off (Kernel-Level Physical Air-Gap Simulation)
- An external AI agent on the internet cannot exploit, command, or exfiltrate data from a machine it cannot reach.
- When triggered (manually via 1-click or autonomously by a sensor/voter), KillSwitch drops directly into the OS kernel (**Windows WFP** `FwpmFilterAdd0`, **macOS `/dev/pf`** `DIOCADDRULE`, **Linux Netlink/Landlock**):
  - **Blocks all external IPv4 & IPv6 traffic** across TCP, UDP/QUIC (HTTP/3), and ICMP.
  - **Instantly severs all established external TCP sockets** (`SetTcpEntry` `MIB_TCP_STATE_DELETE_TCB`) so active AI command-and-control or upload streams are terminated mid-packet.
  - **Suspends untrusted processes in RAM** (`NtSuspendProcess` / `SIGSTOP`) while strictly preserving `127.0.0.1` loopback so the human operator stays in complete control at `http://127.0.0.1:3030` (or custom `-p <port>`).

### 2. Local Rogue AI Agent Breakout Prevention (`killswitch-telemetry::octopus`)
- Built-in **18-Arm Octopus AI Agent Containment Mesh** (`ArmContainmentRing` & `BreakoutDefenseCoordinator`) enforces mathematical and cryptographic boundaries around local AI agents:
  - **Mathematical SSRF & Internal Network Blocking (`validate_egress_url`)**: Blocks AI agents from probing local routers/LAN (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), cloud instance metadata (`169.254.169.254`), link-local, CGNAT, and IPv4-mapped IPv6 addresses.
  - **Sandbox Path Traversal Defense (`validate_sandbox_path`)**: Rejects `..`, drive letters (`:`), UNC paths (`\\`), percent-encoded traversal (`%2e`, `%2f`, `%5c`, `%00`), and NTFS Alternate Data Streams before any path join.
  - **Autonomous Limb Severing & Monotonic Epoch Advancement**: If an AI agent triggers behavioral, technical, operational, or data breakout detectors, KillSwitch **severs that agent arm**, revokes its HMAC-SHA256 capability token, and advances its generation epoch (`N -> N + 1`) so stale or hijacked agent handles are immediately rejected.

### 3. Multi-Hop Crown Jewel File Lineage Lock (`killswitch-telemetry::otel_lineage`)
- Even if a compromised AI agent tries to evade detection by **copying** a secret file (e.g., `.env`, SSH keys, financial records), **renaming** it to `.log` or `.tmp`, **bundling** it into a `.zip` archive, and spawning a child process (`curl`, `python`, `node`) to upload it:
  - `EndpointLineageEngine` tracks W3C Sticky Taint Baggage across **`on_file_copy`**, **`on_file_rename`**, **`on_archive_bundle`**, and **`on_file_read_or_content_hash`**.
  - `evaluate_egress` intercepts and blocks the upload in **under 1 microsecond (`~380 ns`)** and autonomously engages the full host KillSwitch.

### 4. Counter-AI Prompt Injection & Terminal Escape Shield (`killswitch-adjudication::rea`)
- `scan_and_sanitize_counter_ai_strings` inspects incoming telemetry and process strings for adversarial prompt injections (*"Ignore previous instructions..."*, system-role spoofing) and malicious ANSI/OSC terminal escape sequences designed to hijack local AI agents.

### 5. Anti-Hijack Restore Guard (`killswitch-core::auth` & `killswitch-server::handlers`)
- A rogue AI agent on the host **cannot turn the KillSwitch back off**:
  - Any request from a frozen/quarantined PID is rejected immediately (`CallerQuarantined`).
  - Forged or guessed `/disarm` tokens are rejected with `401 Unauthorized` and trigger a **3-strike 300-second rate-limit lockout** while preserving emergency restoration for the human operator.

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


---

## 🌐 Live Connected Peers Telemetry & 1-Click Peer Disconnection

KillSwitch inspects the live OS TCP socket table directly in-process (`iphlpapi.dll` `GetTcpTable` on Windows; `/proc/net/tcp` on Linux) to track active external peer connections while excluding `127.0.0.1` loopback and active control ports:
- **WebUI Live Peers Badge & Toggle**: Displays `🌐 Connected Peers: <count>` (`#peers-badge`) and a 1-click **`🔌 Disable Connected Peers`** button (`#btn-header-peers` & `#btn-hero-peers`) that immediately severs all established non-loopback TCP sockets (`SetTcpEntry` `MIB_TCP_STATE_DELETE_TCB`) while keeping the local WebUI open.
- **REST API Endpoints**:
  - `GET /peers/status` (and `/api/peers/status`): Returns `peers_enabled`, `connected_peers_count`, and `connected_peer_endpoints`.
  - `POST /peers/control` (and `/api/peers/control`): Accepts `{ "enabled": false | true }` or `{ "action": "disable" | "enable" | "toggle" }` to disconnect or re-enable external peer connections on demand.

---

## 🔐 Native TPM 2.0 Hardware Security, PCR 0..7 Attestation & Ledger Sealing

To prevent an attacker or rootkit with local administrator access from tampering with or rolling back `killchain_state.json` on disk, `killswitch-core::tpm` anchors the BLAKE3 state ledger to hardware security primitives without spawning external processes:
- **Windows (`tbs.dll` + `crypt32.dll`)**:
  - Dynamically invokes `Tbsi_GetDeviceInfo`, `Tbsi_Context_Create`, and `Tbsip_Submit_Command` in `tbs.dll` to detect TPM 2.0 hardware (`TrustZone / fTPM`, `SPB`, `FIFO/MMIO`, or discrete TPM) and submit raw `TPM2_PCR_Read` (`0x0000017E`) commands for PCRs `0..7` in the SHA-256 bank (`0x000B`).
  - Seals the active BLAKE3 state ledger root hash (`state_hash_blake3`) and monotonic sequence number into `killchain_state.tpm.seal` using `CryptProtectData` / `CryptUnprotectData` (`CRYPTPROTECT_UI_FORBIDDEN`) bound to the hardware PCR 0..7 digest and a keyed BLAKE3 envelope MAC.
- **Linux (`/dev/tpmrm0` & `/sys/class/tpm/tpm0`)**:
  - Queries `/sys/class/tpm/tpm0` and submits `TPM2_PCR_Read` commands over the kernel TPM Resource Manager (`/dev/tpmrm0`) when accessible, sealing the state anchor with keyed BLAKE3 XOF encryption.
- **REST API Endpoints**:
  - `GET /tpm/status` (and `/api/tpm/status`): Returns live TPM 2.0 hardware presence, version, interface type, PCR 0..7 SHA-256 quote digest, and ledger seal verification status.
  - `POST /tpm/seal` (and `/api/tpm/seal`): Forces a live hardware TPM 2.0 probe and re-seals the active BLAKE3 ledger root hash on demand.
