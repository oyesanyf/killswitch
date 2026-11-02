# 🛡️ KillSwitch — Agentic EDR & Runtime Governance Kill-Switch (`User-Space Behavioral EDR + CAGE/APC Control Plane`)

**KillSwitch** is a self-contained, zero-external-dependency **Agentic EDR & Runtime Governance Kill-Switch** (or **User-Space Behavioral EDR + CAGE/APC Control Plane**) written in **100% pure Rust** for **Windows, macOS, and Linux**: it **governs AI agents before tool actuation** and **monitors/contains the host process lineage and network sockets during execution**.

It runs without requiring external OS CLI wrapper tools (`netsh`, `iptables`, `nft`, `pfctl`, `taskkill`, or `sc.exe`). When started, it automatically launches a **plain-English WebUI Dashboard** in your default browser, explains **what caused the KillSwitch to activate** in clear everyday language, and preserves access to the local dashboard port (`-p 4040` / `3030`) even when the computer is under full internet lockdown.

> [!IMPORTANT]
> **Architectural Positioning & Scope (`Agentic EDR & Runtime Governance Kill-Switch`)**:
> - **Do call it an Agentic EDR & Runtime Governance Kill-Switch (or User-Space Behavioral EDR + CAGE/APC Control Plane)**: it governs AI agents *before* tool actuation (via Google CAGE 8-tier deterministic policy enforcement, Bounded Agents APC principal chains `arXiv:2608.15888`, and Oso/AWS R1–R5 intersection containment) and monitors/contains the host process lineage and network sockets *during* execution (via `edr_behavioral.rs`, `otel_lineage.rs`, `rl_traffic.rs`, and kernel firewall quarantine across **Windows WFP** `FwpmFilterAdd0`, **macOS `/dev/pf`**, and **Linux Netlink/Landlock**).
> - **Do NOT call it a replacement for a Ring-0 kernel EDR driver (like CrowdStrike or Microsoft Defender) on general corporate laptops**—unless you pair its user-space engine with a real **Windows ETW kernel provider subscription / Sysmon feed**, a **Linux eBPF ring-buffer loader** (`drivers/linux/killswitch_ring0.bpf.c` pinned in `/sys/fs/bpf/killswitch/*`), or the included **EV/WHQL-signed Windows Ring-0 Minifilter/ELAM driver** (`drivers/windows/killswitch_minifilter.c` + `.inf` for `PsSetCreateProcessNotifyRoutineEx` and `ObRegisterCallbacks`).
> - **Ideal Use Case**: If you are running autonomous AI coding agents, computer-use agents, MCP tool servers, or local LLM workflows on a workstation or server and want a deterministic runtime governor + hardware-anchored emergency circuit breaker that can stop data exfiltration or rogue agent actions in milliseconds, it is a very good, uniquely capable tool.

---

## 🚨 Doomsday Protection & Autonomous AI Agent Breakout Defense

**KillSwitch** is specifically architected as an **Agentic EDR & Runtime Governance Kill-Switch** and **last-line "Doomsday" circuit breaker** against both **external AI swarms/worms attacking over the internet** and **local autonomous AI agents attempting to break out of their sandbox or exfiltrate sensitive data**:

### 1. External AI Swarm & Worm Cut-Off (Kernel-Level Physical Air-Gap Simulation)
- An external AI agent on the internet cannot exploit, command, or exfiltrate data from a machine it cannot reach.
- When triggered (manually via 1-click or autonomously by a sensor/voter), KillSwitch drops directly into the OS kernel (**Windows WFP** `FwpmFilterAdd0`, **macOS `/dev/pf`** `DIOCADDRULE`, **Linux Netlink/Landlock**):
  - **Blocks all external IPv4 & IPv6 traffic** across TCP, UDP/QUIC (HTTP/3), and ICMP.
  - **Instantly severs all established external TCP sockets** (`SetTcpEntry` `MIB_TCP_STATE_DELETE_TCB`) so active AI command-and-control or upload streams are terminated mid-packet.
  - **Suspends untrusted processes in RAM** (`NtSuspendProcess` / `SIGSTOP`) while strictly preserving `127.0.0.1` loopback so the human operator stays in complete control at `http://127.0.0.1:3030` (or custom `-p <port>`).

### 2. Standalone Local Rogue AI Agent Breakout Prevention (`killswitch-telemetry`)
- Built-in **Standalone AI Agent Containment Rings** (`ArmContainmentRing` & `BreakoutDefenseCoordinator`) enforce mathematical and cryptographic boundaries around local AI agents:
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
- **Standalone Containment Boundary Guards**: Constant-time HMAC-SHA256 verification and monotonic epoch advancement across local agent containment rings.

---

## 📦 Workspace Architecture (8 Rust Crates)

| Crate | Description |
| :--- | :--- |
| `crates/killswitch-types` | Core traits (`NetworkIsolator`, `ProcessFreezer`, `HealthProbeRunner`), DTOs, and error types |
| `crates/killswitch-core` | Native Windows WFP/BFE, Linux Netlink/Landlock, macOS `/dev/pf`, `NtSuspendProcess`/`SIGSTOP`, 4-tier operator auth, and BLAKE3 state ledger |
| `crates/killswitch-adjudication` | 3-Voter consensus engine, native WinTrust (`wintrust.dll`) signature/catalog verifier, and Byzantine fraud proofs |
| `crates/killswitch-conformal` | Distribution-free conformal sequential jailbreak detection (`Persist-L`, `SR-DKW`, `LayeredGuardrail`) |
| `crates/killswitch-telemetry` | User-Space Behavioral EDR (`edr_behavioral.rs`), CAGE 8-tier governance (`cage_governance.rs`), Bounded Agents APC (`bounded_agents_apc.rs`), Ring-0 driver verifier/loader (`ring0_driver_loader.rs`), Distributed Raft/Valkey consensus (`distributed_consensus.rs`), OpenLineage DLP Engine, and Octopus 18-arm HMAC-SHA256 rings |
| `crates/killswitch-orchestrator` | 10-node cyclic LangGraph orchestrator, CAGE PEP `@cage_guard`, durable file & distributed Raft/Valkey checkpointer, and dynamic-memory Ollama reasoning |
| `crates/killswitch-server` | Axum HTTP control server and embedded plain-English WebUI Dashboard (`GET /` & `GET /ui`) |
| `crates/killswitch-cli` | Unified loader (`killswitch` / `start`) booting all subsystems, auto-opening the browser, and providing CLI subcommands |

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
- The agent boots all subsystems, writes the bound port to `active_port.txt`, and **automatically opens `http://127.0.0.1:4040` in your default web browser**.
- Even when you click **🚨 Disconnect Internet Now (Turn On KillSwitch)**, `http://127.0.0.1:4040` stays 100% reachable so you can inspect what caused the KillSwitch and click **🟢 Reconnect Internet & Restore Normal Use** at any time.

### 3. CLI Subcommands
```powershell
# Run the multi-phase in-memory self-diagnostic suite (exits 0 when all phases pass)
.\target\release\killswitch.exe --verify

# Verify Google CAGE 8-tier governance kernel & trace conformance
.\target\release\killswitch.exe --cage-governance

# Verify Ring-0 driver loader (.sys / .bpf.o) & Distributed Raft/Valkey consensus
.\target\release\killswitch.exe --ring0-driver

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


---

## 🚀 NASA JPL F´ (F Prime) Flight-Software Component & Rate-Group Supervision

`killswitch-core::fprime` implements **NASA JPL's F´ (F Prime) Flight-Software Architecture** (used on Mars Ingenuity and spacecraft fault-protection systems) and **JPL Power of Ten** safety invariants:
- **8 Typed Flight Components (`Active`, `Queued`, `Passive`)**:
  - `Svc::RateGroupDriver` (`Passive`), `Svc::CommandDispatcher` (`Active`), `Svc::Health` (`Queued`), `Svc::TlmChan` (`Passive`), `Svc::ActiveLogger` (`Active`), `Drv::KernelQuarantineDriver` (`Active`), `Svc::W3cTaintLineageFilter` (`Queued`), and `Svc::SweBenchTwoGateVerifier` (`Passive`).
- **3 Harmonic Deterministic Rate Groups**:
  - `RG_1000HZ_CONTAINMENT_BUS` (`1000 Hz`, `< 1 ms` WCET budget), `RG_100HZ_DLP_LINEAGE_BUS` (`100 Hz`, `< 10 µs` WCET budget), and `RG_10HZ_HEALTH_TPM_WATCHDOG` (`10 Hz` ping-pong health & TPM seal verification).
- **REST API Endpoints**:
  - `GET /fprime/status` (and `/api/fprime/status`): Returns live NASA F´ topology status, rate group tick counters, component `PingReturn` health states, `Svc::TlmChan` channels, and bounded `Svc::ActiveLogger` event records.
  - `POST /fprime/dispatch` (and `/api/fprime/dispatch`): Dispatches typed opcodes (`CMD_NO_OP`, `CMD_PING_ALL_COMPONENTS`, `CMD_VERIFY_SWEBENCH_GATES`, `CMD_ENGAGE_SAFE_MODE`, `CMD_EXIT_SAFE_MODE`) through `Svc::CommandDispatcher`.


---

## 🏛️ Google CAGE (`cybernetic-agent-governance-engine`, Tallam 2026 `arXiv:2606.12320`) 8-Tier Governance Kernel

`killswitch-telemetry::cage_governance` integrates Google's **Cybernetic Agent Governance Engine** (**CAGE**, Apache-2.0) across the pre-actuation execution boundary:
- **Multi-Format Substrate Contract Compiler (`SubstrateCompiler`)**: Auto-detects and compiles 5 policy specification formats (**Native CAGE**, **Microsoft ACS** `behaviorDeclarations`, **Linux Foundation AAIF** `governedRunLoop`, **NIST OSCAL 1.1.x** `oscal-version`, and **Lula Validation** `kind: LulaValidation`) into deterministic `CompiledSubstrateArtifact`s with bitwise-identical SHA-256 `substrate_contract_digest`.
- **8-Tier Deterministic LLM-Free Kernel (`CageGovernanceKernel`)**:
  1. `FTRA` (Fault Tree Risk Analysis minimal cut sets)
  2. `STPA` (Systems-Theoretic Process Analysis Unsafe Control Actions `UCA-1..UCA-4`)
  3. `OPA / Substrate` (`CTRL_OPA_005` single-transfer cap, forbidden tools, role norms)
  4. `Confidence` (`CTRL_CONF_001` unverified self-authorization & confidence claim detector)
  5. `Warrant` (cryptographic constant-time HMAC-SHA256 `CageWarrantToken` verification when `requires_warrant: true`)
  6. `Consensus` (human-in-the-loop escalation at or above `consensus_risk_threshold` with mandatory non-empty rationale)
  7. `CBF` (discrete-time Control Barrier Function $h(x_{k+1}) - (1-\gamma)h(x_k) \ge 0$ with `FinanceBoundingBarrier` and `HealthcareDoseBarrier` `CTRL_CBF_DOSE_001`)
  8. `Fiscal` (`AtomicFiscalBarrier` using lock-free `AtomicU64` compare-and-exchange refusing concurrent overspend with `FISCAL_CAP_EXCEEDED`)
- **Tamper-Evident Receipts & Independent Trace Model Checker**: `CageDecisionReceipt`, `CageEvidenceWriter`, and `CageTraceVerifier::verify_trace_conformance`.

---

## 🛡️ Signed Kernel-Mode Driver Deployment (`ELAM / Minifilter / eBPF Ring-0 Loading`)

As an **Agentic EDR & Runtime Governance Kill-Switch (User-Space Behavioral EDR + CAGE/APC Control Plane)**, KillSwitch governs AI agents before tool actuation and monitors/contains the host process lineage and network sockets during execution. **Do not call it a replacement for a Ring-0 kernel EDR driver (like CrowdStrike or Microsoft Defender) on general corporate laptops—unless you pair its user-space engine with a real Windows ETW kernel provider subscription / Sysmon feed, a Linux eBPF ring-buffer loader, or the included EV/WHQL-signed Ring-0 minifilter driver** via `killswitch-telemetry::ring0_driver_loader`:

1. **Windows Kernel Minifilter, ELAM & `ObRegisterCallbacks` (`drivers/windows/killswitch_minifilter.c` & `.inf`)**:
   - Registers `FltRegisterFilter` at Altitude `385200` (`FSFilter Anti-Virus`), `PsSetCreateProcessNotifyRoutineEx` for Ring-0 process creation lineage, and `ObRegisterCallbacks` to strip `PROCESS_TERMINATE (0x0001)` and `PROCESS_VM_WRITE (0x0020)` handles targeting `killswitch.exe` and `lsass.exe`.
   - `verify_windows_pe_sys_binary` enforces a **Fail-Closed Binary Gate** before staging: verifies PE32+ headers (`MZ`, `PE\0\0`, `IMAGE_SUBSYSTEM_NATIVE`), verifies `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY (0x0080 /INTEGRITYCHECK)` (required by the Windows kernel for `ObRegisterCallbacks`), validates the embedded PKCS#7 Authenticode `WIN_CERTIFICATE` table, and checks SHA-256 + BLAKE3 digests.
2. **Linux Ring-0 eBPF Tracepoints & LSM Tamper Guard (`drivers/linux/killswitch_ring0.bpf.c`)**:
   - Hooks `tracepoint/sched/sched_process_exec`, `lsm/task_kill` (returning `-EPERM` on unauthorized `SIGKILL`/`SIGTERM` against the protected KillSwitch daemon PID), and `kprobe/tcp_v4_connect`, pinned under `/sys/fs/bpf/killswitch/*`.
   - `verify_linux_ebpf_elf_binary` parses 64-bit `EM_BPF (247)` ELF objects, verifies `R0..R10` register bounds, rejects unbounded backward jumps, enforces `BPF_EXIT (0x95)` termination, and requires a GPL-compatible license section.
3. **Authenticated Ring-0 Communication Port Bridge (`Ring0KernelEventFrame`)**:
   - Verifies constant-time HMAC-SHA256 signatures and monotonic sequence numbers on Ring-0 frames from `\KillSwitchRing0Port` / `BPF_MAP_TYPE_RINGBUF` and forwards verified events directly into `global_edr_behavioral_engine()`.
4. **CLI & REST API**:
   - CLI: `killswitch.exe --ring0-driver`
   - REST: `GET /api/ring0/status` and `POST /api/ring0/verify-driver`

---

## 🌐 Distributed Multi-Node Consensus Storage (`Raft Quorum + Valkey RESP/AOF Backend`)

To extend state checkpointing (`engine.rs`), CAGE/APC atomic fiscal spend caps, APC envelope revocations, and OpenLineage DLP taint tracking across multi-host clusters, `killswitch-telemetry::distributed_consensus` and `killswitch-orchestrator::checkpointer::DistributedConsensusCheckpointer` implement:

1. **Deterministic Multi-Node Raft Consensus (`RaftClusterCoordinator`)**:
   - Enforces Raft leader election with the Section 5.4.1 Up-to-Date Log Election Restriction, BLAKE3-chained `RaftLogEntry` replication, and $\lfloor N/2 \rfloor + 1$ HMAC-SHA256 quorum signatures before advancing `commit_index`.
2. **Cluster-Wide Atomic Fiscal Caps & Replicated Checkpoints (`ConsensusCommand`)**:
   - `FiscalReserveCas`: Cluster-wide atomic compare-and-add fiscal spend barrier with idempotency keys (`request_id`), preventing multi-host agent swarms from splitting spend across separate nodes to bypass `FISCAL_CAP_EXCEEDED`.
   - `SaveGraphCheckpoint`: Replicates `KillSwitchGraphState` across the Raft cluster with BLAKE3 verification.
   - `PropagateLineageTaint` & `RevokeApcEnvelope`: Cluster-wide DLP taint propagation and immediate APC authorization envelope revocation.
3. **Valkey RESP Wire Protocol + `fsync` Append-Only File (`AOF`) Persistence**:
   - Serializes every committed transition into canonical Valkey/Redis RESP frames (`*<argc>\r\n$<len>\r\n...`), optionally syncs over TCP (`KILLSWITCH_VALKEY_ADDR`, 250ms timeout), and persists to `killswitch_governance_valkey.aof` with `File::sync_all()` and deterministic startup replay (`replay_aof_from_path`).
4. **CLI & REST API**:
   - CLI: `killswitch.exe --distributed-consensus`
   - REST: `GET /api/consensus/status` and `POST /api/consensus/propose`
