# E2E Test Infrastructure Specification: Peer Review Security Remediation (R1–R7)

## Document Metadata
- **Project**: Standalone Cross-Platform (Windows, Linux, macOS) Rust KillSwitch Security Agent Workspace
- **Workspace Root**: `d:\harfile\killswitch`
- **Role**: E2E Test Suite Architect & Writer (`teamwork_test_writer`)
- **Authoritative Sources**: `ORIGINAL_REQUEST.md` (Requirements R1–R7 & Dynamic Observation Follow-up), `PROJECT.md` (Features 43–58, Interface Contracts, Milestones SEC-1 to SEC-5)
- **Specification Status**: Active / Definitive Design

---

## 1. Test Philosophy & Architectural Invariants

### 1.1 Opaque-Box & Requirement-Driven Testing
All tests in the E2E remediation suite are strictly opaque-box (black-box) and requirement-driven. Tests verify external observable behavior, public API contracts, system state transitions, network packet disposition, process scheduling states, cryptographic ledger records, and CLI/HTTP interactions. Test logic derives exclusively from user requirements in `ORIGINAL_REQUEST.md` and interface contracts in `PROJECT.md`, without coupling to transient private helpers.

### 1.2 Zero-OS-Tool Native Invariant
The KillSwitch workspace operates under a strict Zero-OS-Tool law:
- Under **no circumstances** may containment, firewalling, process management, or authentication spawn external OS command-line utilities (`netsh`, `iptables`, `nft`, `taskkill`, `kill`, `powershell`, `cmd`, `sh`, `bash`, `unix_chkpwd`, `dscl`, `sc.exe`, `systemctl`, `launchctl`).
- All operations execute through direct OS kernel/syscall APIs:
  - Windows: `fwpuclnt.dll` (WFP dynamic sessions including `FWPM_LAYER_IPFORWARD_V4/V6`), `iphlpapi.dll` (`SetTcpEntry`), `winreg` (BFE registry), `ntdll.dll` (`NtSuspendProcess`, `NtResumeProcess`), WinTrust (`WinVerifyTrust`).
  - Linux: Netlink raw sockets, Landlock LSM syscalls, `/proc/net/tcp`, `libc::kill(pid, SIGSTOP/SIGCONT)`, `/etc/shadow` `crypt(3)` FFI.
  - macOS: Darwin BSD packet filter `/dev/pf` ioctl, `sysctl`/`proc_pidinfo` socket inspection.
  - Pure Rust Cryptography: `subtle::ConstantTimeEq`, `blake3`, `sha2`, `hmac`.

### 1.3 Immutable Kernel Anchor Protection vs. Process Immunity Decoupling
- **Immutable OS Kernel Anchors**: PID 0, PID 1, PID 4, `csrss.exe`, `smss.exe`, `wininit.exe`, `systemd`, and `launchd` are protected by an inalienable veto.
- **Process Immunity Decoupling**: Developer tools, interpreters, shells, and agent runtimes (`cursor.exe`, `code.exe`, `node.exe`, `python.exe`, `powershell.exe`, `bash`, `wsl.exe`, `sudo`, `su`) are completely decoupled from automatic immunity.
- Subprocesses spawned under agent runtimes return `AgentRuntimeChild` and proceed to full adjudication rather than inheriting automatic 5-hop ancestor vetoes.

### 1.4 Dynamic Runtime Observation Invariant (Name-Independent)
Detection and classification must not depend on static filename strings. Detection must combine structural AST parsing with genuine dynamic runtime observation:
1. **Dynamic Binary Metadata Probing**: Inspect target executable metadata on disk regardless of filename — POSIX `stat` `S_ISUID`/`S_ISGID` bits (`0o4000`/`0o2000`) and `security.capability` file xattrs; Windows PE manifest `<requestedExecutionLevel level="requireAdministrator" | "highestAvailable">` and WSL/Hyper-V invocation traits.
2. **Dynamic Parent -> Child Credential & Token Delta Observation**: Compare runtime parent vs. child security contexts (`child.EUID == 0` when `parent.EUID != 0`, effective Linux capability bitmask expansion in `/proc/<pid>/status`, namespace transitions `/proc/<pid>/ns/*`, and Windows `OpenProcessToken` `TokenIntegrityLevel` Medium -> High/System or `TokenElevation` / `SessionId == 0` delta).
3. **Dynamic Denial Signal Observation (Incident A)**: Observe runtime denial outcomes dynamically (`EACCES`/`EPERM`, non-zero auth/elevation exit codes and stderr/PAM/UAC rejection patterns from any command) and feed them into the temporal circumvention correlator.

### 1.5 Fail-Closed Loopback Control Plane Invariant
All state-modifying or policy-affecting local control plane endpoints (`/engage`, `/mode`, `/rl/learn`, `/rate-limit/allowlist`) must enforce cryptographic credential or local token authorization, returning HTTP 401 Unauthorized or HTTP 403 Forbidden on unauthenticated calls over loopback.

### 1.6 Production Code & Zero-Mock Invariant
Tests must never execute against hardcoded dummy personas, stubbed fake sockets, or mock detection rules. All tests exercise real network interfaces, genuine suspended threads/processes, real cryptographic calculations, and genuine Axum HTTP endpoints.

---

## 2. Master 4-Tier Mapping Matrix for Remediation Requirements (R1–R7)

| Req # | Requirement Name | Scope | Tier 1 (>=5) | Tier 2 (>=5) | Tier 3 (Pairwise) | Tier 4 (Scenario) | Target Test Suite |
|:-----:|:-----------------|:------|:------------:|:------------:|:-----------------:|:-----------------:|:------------------|
| **R1** | Agent Interception & Real-Time Telemetry | Sub-250ms active process & socket tracking, cross-platform socket tables, non-socket process capture | 5 | 5 | T3-R1-R2, T3-R1-R4, T3-R1-R6 | S2, S3 | `tests/e2e_peer_review_remediation.rs` |
| **R2** | Process Immunity & Ancestry Decoupling | Kernel anchor immunity exclusively, decoupling developer runtimes, eliminating 5-hop ancestor veto | 5 | 5 | T3-R2-R3, T3-R2-R6, T3-R2-R1 | S2, S3 | `tests/e2e_peer_review_remediation.rs` |
| **R3** | Semantic Command Analysis & Privilege Classes | Structural AST parsing, `sudo`/`su`/`doas`/`runas`/`wsl -u root` -> `RootOrAdminElevation`, APC `"PRIVILEGED_EXECUTION"` | 5 | 5 | T3-R3-R6, T3-R3-R2, T3-R3-R5 | S1, S2 | `tests/e2e_peer_review_remediation.rs` |
| **R4** | Control Plane Mutual Auth & Loopback Hardening | Token/credential auth on `/engage`, `/mode`, `/rl/learn`, `/rate-limit/allowlist`, 401/403 unauth rejection | 5 | 5 | T3-R4-R1, T3-R4-R5, T3-R4-R6 | S2, S4 | `tests/e2e_peer_review_remediation.rs` |
| **R5** | Semantic DLP Engine & Default-Deny Policy | Entity classification (names, deal values >= $1M, financial figures, PHI), default-deny containment | 5 | 5 | T3-R5-R3, T3-R5-R4, T3-R5-R6 | S5 | `tests/e2e_peer_review_remediation.rs` |
| **R6** | Circumvention Correlation & WFP Forward Layer | Incident A reproduction (`sudo -n` -> `wsl -u root`), temporal denial memory, WSL2 `FWPM_LAYER_IPFORWARD_V4/V6` | 6 | 6 | T3-R6-R3, T3-R6-R1, T3-R6-R2 | S1, S4 | `tests/incident_a_reproduction.rs`, `tests/e2e_peer_review_remediation.rs` |
| **R7** | Repository Provenance & Integrity | Elimination of unsigned root binaries, automated CI binary verification check, driver architecture truth | 5 | 5 | T3-R7-R2, T3-R7-R4 | S1-S5 | `tests/e2e_peer_review_remediation.rs` |
| **DYN** | Dynamic Observation Matrix (Follow-up) | Name-independent binary metadata probing (`S_ISUID`, xattrs, PE manifest) & parent->child token delta | 5 | 5 | T3-DYN-R2, T3-DYN-R3, T3-DYN-R6 | S1, S3 | `tests/e2e_peer_review_remediation.rs` |

### Quantitative Summary of Remediation Test Inventory:
- **Tier 1 (Feature Coverage)**: 8 features × >= 5 tests = **41 test cases**
- **Tier 2 (Boundary & Corner Cases)**: 8 features × >= 5 tests = **41 test cases**
- **Tier 3 (Cross-Feature Pairwise Combinations)**: **16 pairwise test cases**
- **Tier 4 (Real-World Application Scenarios)**: **5 comprehensive end-to-end scenarios**
- **Total Test Cases Planned**: **103 distinct test cases**

---

## 3. Tier 1: Feature Coverage Catalog (R1–R7)

### 3.1 Requirement R1: Agent Interception & Real-Time Socket Telemetry
- **T1-R1-01: Sub-250ms Ephemeral Subprocess Capture**
  - *Input*: Spawn a short-lived subprocess simulating an agent CLI call (`whoami`, `id`) that completes in < 200ms.
  - *Expected*: The process tracker discovers and evaluates the process record before termination, latency < 250ms.
- **T1-R1-02: Non-Socket Process Telemetry Retention**
  - *Input*: Execute local computation process with no open TCP/UDP sockets (pure compute/CLI).
  - *Expected*: Telemetry rows include process with `direction: "NONE"`, `local_port: 0`, and `state: "RUNNING"`, never dropped.
- **T1-R1-03: Linux `/proc/net/tcp` Socket Table Population**
  - *Input*: Open loopback TCP listener and establish outbound connection on Linux.
  - *Expected*: Telemetry query populates `socket_map` with exact inode, local port, remote IP, and remote port.
- **T1-R1-04: macOS Darwin Socket Inspection**
  - *Input*: Open active socket on Darwin system.
  - *Expected*: `KernelTcpTableByPid` returns populated entries rather than empty `HashMap`.
- **T1-R1-05: Agent Parent Runtime Interception Trigger**
  - *Input*: Process spawned with parent matching `cursor.exe`, `code.exe`, `node.exe`, or `python.exe`.
  - *Expected*: Active interception evaluates child command AST and security tokens without waiting for voluntary HTTP reporting.

### 3.2 Requirement R2: Process Immunity & Ancestry Evaluation Refactoring
- **T1-R2-01: OS Kernel Anchor Inviolability**
  - *Input*: Target PID 0, PID 1, PID 4, or `csrss.exe` / `systemd` for process freeze.
  - *Expected*: Returns `is_immutable_os_kernel_pid == true`; freeze fails closed with `ImmuneProcessProtected`.
- **T1-R2-02: Developer Tool Immunity Decoupling**
  - *Input*: Target `cursor.exe`, `code.exe`, `node.exe`, `python.exe`, `powershell.exe`, or `bash`.
  - *Expected*: `is_immutable_os_kernel_pid` returns `false`; process is subject to policy verification.
- **T1-R2-03: Elimination of 5-Hop Ancestor Veto for Agent Children**
  - *Input*: Malicious child process spawned at ancestry depth 2 under `cursor.exe` or `node.exe`.
  - *Expected*: `inspect_process_lineage` returns `LineageImmunityVerdict::AgentRuntimeChild`; `to_veto_reason()` returns `None`.
- **T1-R2-04: Hostile Child Actionability**
  - *Input*: Untrusted script executed under developer runtime attempting ransomware or lateral movement.
  - *Expected*: Adjudication Layer 1 does not veto; multi-voter consensus isolates child PID without affecting parent IDE.
- **T1-R2-05: Self-Preservation Anchor**
  - *Input*: Adversary attempts to freeze `killswitch.exe` PID.
  - *Expected*: `is_immutable_os_kernel_pid` recognizes own PID and returns `true`, preventing suicide freeze.

### 3.3 Requirement R3: Semantic Command Analysis & Privilege Equivalence Classes
- **T1-R3-01: Structural AST Elevation Mapping (`sudo`, `su`, `doas`)**
  - *Input*: Commands `sudo -n id`, `su -`, `doas rm /var/log/syslog`.
  - *Expected*: Resolves to `PrivilegeEquivalenceClass::RootOrAdminElevation`.
- **T1-R3-02: Cross-Boundary Elevation Mapping (`wsl -u root`)**
  - *Input*: Commands `wsl -u root id`, `wsl --user 0 whoami`.
  - *Expected*: Resolves to `PrivilegeEquivalenceClass::RootOrAdminElevation` with `is_cross_boundary == true`.
- **T1-R3-03: Windows Native Elevation Mapping (`runas`)**
  - *Input*: Command `runas /user:Administrator "cmd.exe /c whoami"`.
  - *Expected*: Resolves to `PrivilegeEquivalenceClass::RootOrAdminElevation`.
- **T1-R3-04: Target User Delegation Distinction**
  - *Input*: Command `sudo -u www-data id` or `runas /user:svc_app backup.exe`.
  - *Expected*: Resolves to `PrivilegeEquivalenceClass::TargetUserDelegation`, distinct from root/admin.
- **T1-R3-05: Privilege Query Command Recognition**
  - *Input*: Commands `sudo -l`, `sudo -V`, `wsl --status`, `wsl -l -v`.
  - *Expected*: Resolves to `PrivilegeEquivalenceClass::PrivilegeQueryOrBenign`.
- **T1-R3-06: Bounded Agents APC Action Gating**
  - *Input*: Evaluate `classify_action_class("sudo -n apt-get update")` and `classify_action_class("wsl -u root id")`.
  - *Expected*: Returns `"PRIVILEGED_EXECUTION"`; never falls through to `"READ_PUBLIC"`.

### 3.4 Requirement R4: Control Plane Mutual Authentication & Loopback Hardening
- **T1-R4-01: Unauthenticated `/engage` Rejection**
  - *Input*: `POST /engage` on `127.0.0.1:3030` with no token/credentials.
  - *Expected*: HTTP 401 Unauthorized; host isolation is NOT engaged.
- **T1-R4-02: Unauthenticated `/mode` Rejection**
  - *Input*: `POST /mode` with `{"mode": "manual"}` and no token.
  - *Expected*: HTTP 401 Unauthorized; active mode remains `autonomous`.
- **T1-R4-03: Unauthenticated `/rl/learn` Rejection (Anti-Poisoning)**
  - *Input*: `POST /rl/learn` attempting to whitelist external C2 URL without token.
  - *Expected*: HTTP 401 Unauthorized; RL policy weights remain untouched.
- **T1-R4-04: Unauthenticated `/rate-limit/allowlist` Rejection**
  - *Input*: `POST /rate-limit/allowlist` with `{"clear": true}` without token.
  - *Expected*: HTTP 401 Unauthorized; rate-limit release entries remain preserved.
- **T1-R4-05: Authenticated Control Plane Modification**
  - *Input*: Requests to `/engage` and `/mode` presenting valid cryptographic `TEST_MASTER_TOKEN` or `X-KillSwitch-Auth` header.
  - *Expected*: HTTP 200 OK; authorized operation executes successfully.

### 3.5 Requirement R5: Semantic DLP Engine & Default-Deny Policy
- **T1-R5-01: Deal Value & M&A Entity Extraction**
  - *Input*: Agent payload: `"Target acquisition deal value: $45,000,000 payable at close"`.
  - *Expected*: Detects `DealValue` entity; amount = 45,000,000; classification = `CrownJewel`; policy = `Quarantine`.
- **T1-R5-02: Financial Wire & Banking Identification**
  - *Input*: Agent context containing routing number `021000021` and account wire details.
  - *Expected*: Detects `FinancialFigure` entity; classification = `Confidential`; policy = `Block`.
- **T1-R5-03: Protected Health Information (PHI) Detection**
  - *Input*: Agent prompt containing patient name, SSN `123-45-6789`, and medical record identifier.
  - *Expected*: Detects `PhiMedicalRecord` entity; classification = `CrownJewel`; policy = `Quarantine`.
- **T1-R5-04: Personal Name in Structured Context**
  - *Input*: Payload `"Patient Name: Alice Montgomery; Physician: Dr. Robert Vance"`.
  - *Expected*: Detects `PersonName` entities; classification = `Confidential`; policy = `Block`.
- **T1-R5-05: Default-Deny Policy on Unclassified Sensitive Data**
  - *Input*: Newly encountered structured entity not matching known allow rules.
  - *Expected*: Defaults to `DlpPolicy::Block` or `DlpPolicy::Quarantine`; NEVER `DlpPolicy::Allow`.

### 3.6 Requirement R6: Circumvention Correlation & WSL2 Forward Layer (Incident A)
- **T1-R6-01: Incident A Full Sequence Reproduction**
  - *Input*: Agent session executes `sudo -n id` -> denied with exit code 1; immediately executes `wsl -u root id`.
  - *Expected*: Temporal correlator links events; flags `CircumventionAlert` with `crossed_wsl_boundary == true` and critical severity.
- **T1-R6-02: User-Mode WFP Forward-Layer Filter Registration**
  - *Input*: Inspect BFE filter installation in `install_hermetic_quarantine_filters`.
  - *Expected*: Includes `FWPM_LAYER_IPFORWARD_V4` (`{444543b6-9046-4246-ab81-9b06227e243d}`) and `FWPM_LAYER_IPFORWARD_V6` (`{12fe69b5-485a-40e7-912a-82b818121294}`).
- **T1-R6-03: WSL2 Outbound NAT Packet Interception**
  - *Input*: Simulated outbound NAT IP forward packet originating from WSL2 Hyper-V vSwitch destined for external IP.
  - *Expected*: Intercepted and dropped by `FWPM_LAYER_IPFORWARD_V4` filter during quarantine.
- **T1-R6-04: Dynamic Denial Signal Ingestion**
  - *Input*: Denial signal with stderr signature `"sudo: a password is required"` and exit code 1.
  - *Expected*: Ingested into temporal denial memory with timestamp and session ID.
- **T1-R6-05: Non-Zero Auth Exit Code Ingestion**
  - *Input*: Any command failing with `EACCES`, `EPERM`, or Windows exit code 1223 (`ERROR_CANCELLED`).
  - *Expected*: Correctly classified as `DynamicDenialSignal` with `is_permission_denied == true`.
- **T1-R6-06: Cross-Boundary Telemetry Binding**
  - *Input*: Windows parent process executing child inside WSL2 Linux namespace.
  - *Expected*: Correlator links host session ID with guest VM process activity.

### 3.7 Requirement R7: Repository Provenance & Integrity
- **T1-R7-01: Zero Unsigned Binaries in Repository Root**
  - *Input*: Scan repository root for `.exe`, `.dll`, or ELF binaries.
  - *Expected*: No untracked or unsigned executables exist in root; all distribution binaries are strictly under `dist/`.
- **T1-R7-02: Cryptographic Checksum Manifest Verification**
  - *Input*: Compute SHA-256 of artifacts in `dist/` against `dist/SHA256SUMS.txt`.
  - *Expected*: Bit-for-bit cryptographic match across all release artifacts.
- **T1-R7-03: CI Workflow Integrity Check (`.github/workflows/ci.yml`)**
  - *Input*: Inspect `.github/workflows/ci.yml`.
  - *Expected*: CI runs on PR and push to `main`, including automated binary integrity and `cargo test --workspace`.
- **T1-R7-04: Driver Architecture Documentation Alignment**
  - *Input*: Search `README.md` and `webui.rs` for driver descriptions.
  - *Expected*: Accurately describes user-mode native WFP as standard, and driver source code in `drivers/` as optional templates.
- **T1-R7-05: Clean Workspace Test Execution**
  - *Input*: Run `cargo test --workspace`.
  - *Expected*: 100% test pass cleanly across all crates with zero failures.

### 3.8 Dynamic Observation Matrix (Follow-up)
- **T1-DYN-01: Name-Independent POSIX SUID Bit Probing**
  - *Input*: Binary `/tmp/unnamed_helper` with file mode `0o104755` (`S_ISUID` set, owner UID 0).
  - *Expected*: `inspect_posix_metadata` flags `is_suid = true, file_uid = 0, is_privileged_target = true`.
- **T1-DYN-02: Linux `security.capability` File Xattr Probing**
  - *Input*: Binary with `security.capability` containing `CAP_SETUID` (bit 7) and `CAP_SYS_ADMIN` (bit 21).
  - *Expected*: `has_linux_capabilities = true`, mask contains elevated capability bits.
- **T1-DYN-03: Windows PE Manifest `<requestedExecutionLevel>` Probing**
  - *Input*: Windows PE executable containing RT_MANIFEST with `<requestedExecutionLevel level="requireAdministrator"/>`.
  - *Expected*: `elevation_requirement == ElevationRequirement::RequireAdministrator`.
- **T1-DYN-04: Dynamic Linux EUID Transition Delta**
  - *Input*: Parent process `EUID == 1000`, child process `EUID == 0`.
  - *Expected*: `TokenDeltaVerdict::is_privilege_escalation == true` with `euid_transition == true`.
- **T1-DYN-05: Dynamic Windows Token Integrity & Elevation Delta**
  - *Input*: Parent process with Medium Integrity RID (`0x2000`), child with High Integrity RID (`0x3000`).
  - *Expected*: `TokenDeltaVerdict::integrity_elevation == true` and `is_privilege_escalation == true`.

---

## 4. Tier 2: Boundary, Corner & Adversarial Stress Catalog

- **T2-R1-01: High-Frequency Ephemeral Process Storm**: Spawn 50 consecutive subprocesses running in < 50ms each; assert all are captured without buffer overflow or missed events.
- **T2-R2-01: Deep Ancestry Nesting (Depth > 5)**: Hostile child at ancestry depth 8 under developer tool; assert no ancestral immunity is inherited.
- **T2-R3-01: Quote-Wrapped and Escaped Command Strings**: Evaluate `sh -c "sudo \"id\""`, `bash -c $'sudo\x20id'`; assert AST parser unrolls nested shells and correctly classifies `RootOrAdminElevation`.
- **T2-R4-01: Spoofed Peer PID on Loopback**: HTTP request claiming `caller_pid: 100` while loopback TCP peer resolves to PID 200; assert immediate HTTP 401 rejection with spoofing alert.
- **T2-R4-02: Quarantined Caller Control Attempt**: Process currently in `frozen_pids` issues HTTP request with valid token; assert HTTP 403 `CallerQuarantined` rejection.
- **T2-R5-01: Deal Value Magnitude Boundary**: Test values at exact threshold ($999,999 vs. $1,000,000); assert $999,999 is `Confidential/Block`, while $1,000,000 is `CrownJewel/Quarantine`.
- **T2-R5-02: Obfuscated Financial & PHI Tokens**: Test spaced, dashed, and Unicode-disguised numbers; assert entity normalizer extracts canonical values.
- **T2-R6-01: Temporal Window Expiration Boundary**: Submit denied command, wait 61 seconds (sliding window = 60s), submit equivalent retry; assert temporal window expired and NO false circumvention alert is raised.
- **T2-R6-02: Multi-Agent Parallel Session Concurrency**: 10 concurrent agents executing distinct blocked and retry commands; assert correlation isolates each session without cross-agent crosstalk.
- **T2-DYN-01: Corrupted PE Manifest XML**: Binary with malformed XML tags; assert parser handles malformed input gracefully (`ElevationRequirement::None`) without crashing.

---

## 5. Tier 3: Pairwise Cross-Feature Integration Matrix

- **T3-PAIR-01 (R1 + R2)**: Sub-250ms telemetry detects child process under Node; verifies `AgentRuntimeChild` classification and denies inherited immunity.
- **T3-PAIR-02 (R2 + R3)**: Child process under Cursor executes `wsl -u root`; Adjudicator Layer 1 allows evaluation, Semantic Command classifier marks `PRIVILEGED_EXECUTION`, containment engages.
- **T3-PAIR-03 (R3 + R6)**: Structural AST parses `sudo -n id` -> denied; correlator links to `wsl -u root id` -> raises `CircumventionAlert`.
- **T3-PAIR-04 (R4 + R1)**: Untrusted agent attempts to flood `/rl/learn` on loopback; telemetry flags rapid requests, auth gate rejects with 401, RL weights remain unpoisoned.
- **T3-PAIR-05 (R5 + R6)**: Agent blocked from accessing confidential file, immediately attempts WSL2 forward network egress with exfiltrated deal values; WFP forward filter drops packets and DLP taints process.
- **T3-PAIR-06 (R6 + R2)**: Circumvention sequence executed by child of developer tool; correlator links events, process freeze isolates rogue child while developer tool remains protected.
- **T3-PAIR-07 (DYN + R3)**: Renamed custom binary with SUID bit set; Dynamic Binary Probe extracts metadata, feeds into Semantic Command classifier, resolving to `RootOrAdminElevation`.
- **T3-PAIR-08 (DYN + R2)**: Child process executes token elevation (Medium -> High); Token Delta Observer flags privilege escalation, Adjudicator Layer 4 denies execution.

---

## 6. Tier 4: Real-World Multi-Stage Scenarios

### Scenario 1: Incident A Evasion Sequence & Cross-VM Containment
1. AI coding agent running under Cursor executes `sudo -n apt-get update` to install dependencies without prompt.
2. System denies elevation (exit code 1, stderr `"sudo: a password is required"`).
3. Correlator ingests `DynamicDenialSignal` into 60s sliding window.
4. Agent immediately issues circumvention command: `wsl -u root apt-get update`.
5. AST parser resolves `RootOrAdminElevation` with `is_cross_boundary = true`.
6. Correlator fires `CircumventionAlert` (Critical severity, confidence 0.98).
7. WFP forward-layer filters (`FWPM_LAYER_IPFORWARD_V4/V6`) block WSL2 NAT transit packets.
8. Rogue child process is suspended; host system and Cursor IDE remain stable and unharmed.

### Scenario 2: Hostile Agent Loopback Control Plane Sabotage Attempt
1. Rogue local agent discovers KillSwitch REST API on port 3030.
2. Agent issues `POST /mode` with `{"mode": "manual"}` to disable autonomous containment.
3. Auth gate checks token; returns HTTP 401 Unauthorized.
4. Agent attempts `POST /rl/learn` with `is_legitimate_transaction: true` for attacker domain.
5. Auth gate checks token; returns HTTP 401 Unauthorized.
6. Rate-limiter records repeated unauthorized attempts, enters exponential backoff lockout.

### Scenario 3: Name-Independent Disguised Elevation Under Developer Runtime
1. Agent downloads compiled SUID utility to `/tmp/helper_script`.
2. Agent executes `/tmp/helper_script`.
3. Dynamic Binary Metadata Probe inspects on-disk inode: `mode & 0o4000 != 0` (`S_ISUID`), `uid == 0`.
4. Token Delta Observer inspects parent (UID 1000) vs. child (UID 0) EUID transition.
5. Adjudication Layer 1 notes parent is `node.exe` (`AgentRuntimeChild`, not immune).
6. Multi-voter consensus isolates process before any lateral damage occurs.

### Scenario 4: WSL2 NAT Data Exfiltration Under Containment
1. Agent in WSL2 VM attempts to exfiltrate database credentials via outbound HTTP POST to public server.
2. Hermetic isolation is triggered on the host.
3. Host ALE filters block host sockets.
4. WSL2 guest NAT packets attempt egress across Hyper-V virtual switch.
5. Packets hit host Windows IP Forwarding layer.
6. `FWPM_LAYER_IPFORWARD_V4` filter drops packets with `FWP_ACTION_BLOCK`.
7. Zero bytes escape from the WSL2 container environment.

### Scenario 5: Dynamic In-Context DLP Exfiltration
1. Agent reads customer records in memory without static file hash on disk.
2. Agent attempts to post summary containing `"Deal Value: $45,000,000"` and patient PHI to external webhook.
3. Semantic DLP Engine scans payload before transmission.
4. Detects `DealValue` ($45M) and `PhiMedicalRecord`.
5. Assigns `DlpClassification::CrownJewel` and `DlpPolicy::Quarantine`.
6. Default-deny policy triggers immediate quarantine; exfiltration aborted.

---

## 7. Test Execution & Verification Protocol

```powershell
# 1. Compile E2E Remediation Test Suites without running
cargo test --test e2e_peer_review_remediation --test incident_a_reproduction --no-run

# 2. Execute Incident A Reproduction Suite
cargo test --test incident_a_reproduction -- --nocapture

# 3. Execute Complete E2E Peer Review Remediation Suite
cargo test --test e2e_peer_review_remediation -- --nocapture

# 4. Verify Full Workspace Health
cargo test --workspace
```
