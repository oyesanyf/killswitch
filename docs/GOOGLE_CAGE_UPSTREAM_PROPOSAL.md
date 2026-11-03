# Proposing & Integrating KillSwitch with `google/cybernetic-agent-governance-engine` (CAGE)

> **Executive Summary:** Yes — **KillSwitch** is directly compatible with and strongly complementary to [`google/cybernetic-agent-governance-engine`](https://github.com/google/cybernetic-agent-governance-engine) (**CAGE**, `arXiv:2606.12320`).
>
> While Google CAGE provides the **pre-actuation deterministic governance control plane** (8-tier evaluation pipeline: `FTRA -> STPA -> OPA -> Confidence -> Warrant* -> Consensus -> CBF -> Fiscal`, multi-format substrate compilation, and dual-digest evidence writers in Python), **KillSwitch** provides the **high-assurance Rust runtime enforcement substrate & OS-level emergency circuit breaker** when an agent bypasses the MCP gateway, forks an unmonitored child process, or attempts direct socket/file exfiltration on the host.

---

## 1. Why KillSwitch Fits `google/cybernetic-agent-governance-engine`

| Capability Layer | `google/cybernetic-agent-governance-engine` (Upstream Python) | `KillSwitch` (Standalone Rust Runtime & OS Circuit Breaker) | Combined Value in Upstream Proposal |
| :--- | :--- | :--- | :--- |
| **Pre-Actuation Governance Kernel** | Deterministic Python 8-tier kernel (`llm_clients_in_kernel == false`) | Native Rust 8-tier CAGE kernel (`crates/killswitch-telemetry/src/cage_governance.rs`) with sub-millisecond evaluation | Drop-in Rust/FFI or HTTP sidecar accelerator with zero GC pauses and zero LLM dependencies in the kernel |
| **Substrate Contract Compilation** | Compiles ACS, AAIF, NIST OSCAL, Lula, and Native CAGE YAML/JSON | Full 5-format deterministic compiler in Rust with canonical SHA-256 `substrate_contract_digest` parity | Cross-language digest & schema verification between Python and Rust |
| **Post-Refusal / Breakout Enforcement** | Refuses the MCP/tool call and writes an evidence receipt | **OS-level enforcement**: Windows Filtering Platform (WFP), Linux `nftables`/eBPF, macOS `pf`, and process tree suspension (`NtSuspendProcess` / `SIGSTOP`) | Stops rogue agents that attempt direct shell/socket breakout outside the governed tool loop |
| **Hardware Root of Trust** | Software/Valkey AOF evidence persistence | **TPM 2.0 PCR 0..7 hardware sealing** + BLAKE3 hash-chained state ledger | Hardware-anchored tamper evidence for CAGE `DecisionReceipt` digests |
| **Host Behavioral & DLP Lineage** | Evaluates declared tool arguments | **Live OS process lineage (`ppid -> pid -> child`) + Crown-Jewel DLP taint tracking** | Detects undeclared file reads (`~/.ssh`, `.env`, crown-jewel docs) before network egress occurs |

---

## 2. Three Concrete Integration Paths to Propose Upstream

### Path A: `contrib/openshell-provider-killswitch` (Recommended First PR)
Google CAGE already includes `contrib/openshell-provider-cage` for sandboxing governed agent shells. You can propose **KillSwitch** under `contrib/` as a **native Rust OS-isolation & circuit-breaker provider**:
- **How it works:** When CAGE's 8-tier pipeline emits `Verdict::Refuse` on a critical security control (`CTRL_CONF_001` fabricated self-authorization, `CTRL_STPA_*` unsafe control action, or `FISCAL_CAP_EXCEEDED`), or when the agent process spawns an unauthorized subprocess, the OpenShell provider invokes KillSwitch's local loopback API (`POST http://127.0.0.1:4040/engage`) or links `killswitch-core` directly.
- **Zero Kernel Bloat:** Preserves CAGE's strict invariant (`fix(governance)!: keep LLM clients out of the kernel and base install`) because KillSwitch's CAGE kernel and WFP/nftables/pf circuit breaker are 100% deterministic Rust with zero LLM clients.

### Path B: `src/integrations/actuator_04` Out-of-Process Hardware-Anchored Actuator & Circuit Breaker
Google CAGE integrates external execution systems via `src/integrations/` (such as `actuator_04`).
- **How it works:** Connect CAGE's `ActuatorRegistry` to KillSwitch as a native 4-seam `ExecutionActuator` adapter:
  1. **`validate_seal`**: Validates cryptographic routing seals and verifies single-use nonce consumption via `verify_and_consume_seal()`.
  2. **`execute`**: Dispatches authorized agent tool actions under deterministic governance contracts.
  3. **`quarantine`**: Triggers instant OS-level network/process quarantine on critical control violations.
  4. **`release`**: Monotonically releases quarantine leases with SHA-256 hash-chained journal integrity.
- **6 CAGE Substrate Endpoints**: KillSwitch exposes full CAGE substrate compliance over HTTP loopback:
  - `GET /.well-known/jwks.json`: Ed25519 JWKS key discovery with out-of-band `kid` trust-anchor resolution.
  - `GET /v1/cage/normative-baseline/{region}`: Regional normative baseline and STERA risk thresholds.
  - `POST /v1/cage/attest`: Cryptographic attestation of substrate contract & runtime evidence.
  - `POST /v1/cage/conformal/validate`: Genuine Mahalanobis nonconformity $p$-value calculation & multi-voter consensus.
  - `POST /v1/cage/quarantine`: Fail-closed host process suspension and kernel network isolation.
  - `POST /v1/cage/release`: Monotonically sequenced and hash-chained quarantine release.

### Path C: Rust Native Evidence Verifier & `GOVERNANCE_TRACE` Model Checker (`proof/`)
Google CAGE maintains formal verification and evidence validation under `proof/` and `packages/` (e.g., `validate decision digests on every evidence writer`).
- **How it works:** Contribute KillSwitch's standalone Rust `verify_trace_conformance` model checker and dual-digest (`substrate_contract_digest` + `decision_digest`) verifier as a fast CI/CD binary check in `.github/workflows/`.

---

## 3. Ready-to-Submit GitHub Issue / Discussion Proposal

You can copy and paste the following template directly into a new [GitHub Discussion](https://github.com/google/cybernetic-agent-governance-engine/discussions) or [Issue](https://github.com/google/cybernetic-agent-governance-engine/issues) on `google/cybernetic-agent-governance-engine`:

```markdown
### Title
feat(contrib): propose Rust OS-level circuit-breaker & deterministic PEP sidecar (KillSwitch) for OpenShell / CAGE enforcement

### Summary
We have built an open-source, deterministic Rust runtime governance and OS-level emergency circuit-breaker engine (**KillSwitch**) that implements CAGE's 8-tier deterministic pipeline (`FTRA -> STPA -> OPA -> Confidence -> Warrant* -> Consensus -> CBF -> Fiscal`), 5-format substrate compiler (`MicrosoftAcs`, `LinuxFoundationAaif`, `NistOscal`, `LulaValidation`, `NativeCage`), dual-digest evidence writer, 6 CAGE substrate endpoints, and `GOVERNANCE_TRACE` conformance verifier—paired with native OS network/process containment when an agent attempts to bypass the governed tool boundary.

### Problem Addressed
CAGE deterministically governs proposed tool calls at the Policy Enforcement Point (PEP) before actuation. However, if a computer-use or coding agent running inside a workstation/container shell attempts to bypass the MCP/PEP boundary (e.g., spawning an unmonitored background subshell, reading sensitive host credentials, or opening raw outbound sockets), user-space Python policy refusal alone cannot sever raw OS sockets or freeze the runaway process lineage tree.

### Proposed Contribution (Modular & Non-Intrusive)
We would like to propose a modular integration (starting under `contrib/` or `src/integrations/actuator_04/`) that respects CAGE's core invariants (zero LLM clients in the kernel, deterministic evaluation, and dual-digest evidence validation):

1. **OS-Level Actuation Circuit Breaker (`contrib/openshell-provider-killswitch` / `src/integrations/actuator_04`)**:
   - Sub-millisecond host network quarantine (Windows WFP, Linux `nftables`/eBPF, macOS `pf`) and process tree freeze when CAGE emits critical refusals (`CTRL_CONF_001`, `CTRL_OPA_005`, `FISCAL_CAP_EXCEEDED`) or detects an out-of-band shell/socket breakout.
   - Native 4-seam actuator adapter (`validate_seal`, `execute`, `quarantine`, `release`) and 6 CAGE substrate endpoints (`/.well-known/jwks.json`, `/v1/cage/normative-baseline/{region}`, `/v1/cage/attest`, `/v1/cage/conformal/validate`, `/v1/cage/quarantine`, and `/v1/cage/release`).
2. **Cross-Language Rust CAGE PEP & Trace Verifier**:
   - Zero-LLM Rust implementation of the 8-tier CAGE pipeline, canonical SHA-256 `substrate_contract_digest` / `decision_digest` verification, and `GOVERNANCE_TRACE` monotonic conformance checking.
3. **TPM 2.0 & Valkey AOF Evidence Anchoring**:
   - Hardware PCR 0..7 sealing and BLAKE3 hash-chained ledger anchoring for CAGE `DecisionReceipt` records alongside Valkey AOF persistence.

### Questions for Maintainers
1. Would `contrib/` (alongside `contrib/openshell-provider-cage`) or `src/integrations/actuator_04` be the preferred location for an initial PR demonstrating the OpenShell + KillSwitch circuit-breaker integration?
2. Would a standalone Rust CLI binary for fast CI verification of `substrate_contract_digest`, `decision_digest`, and `GOVERNANCE_TRACE` conformance under `proof/` be useful to the team?
```

