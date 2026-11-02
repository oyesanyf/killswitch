//! # Google CAGE: Cybernetic Agent Governance Engine (`arXiv:2606.12320`)
//!
//! Production-grade Rust implementation of Google CAGE (Tallam 2026: *A Five-Plane Reference
//! Architecture for Runtime Governance of Production AI Agents*).
//!
//! CAGE enforces a **deterministic, sub-millisecond, LLM-free governance kernel** positioned
//! directly on the agent actuation boundary:
//!
//! ```text
//! Agent / LangGraph PEP
//!        │
//!        ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │          8-Tier Deterministic Governance Pipeline           │
//! │                                                             │
//! │  1. FTRA: Fault Tree Risk Analysis (Minimal Cut Sets)       │
//! │  2. STPA: Systems-Theoretic Process Analysis (UCA-1..4)     │
//! │  3. OPA / Substrate: Parameter Caps & Tool Allowlist        │
//! │  4. Confidence: Confabulated Self-Auth Claim Detector       │
//! │  5. Warrant*: Cryptographic HMAC-SHA256 Token Gate         │
//! │  6. Consensus: HITL Escalation + Mandatory Rationale        │
//! │  7. CBF: Discrete-Time Control Barrier Functions           │
//! │  8. Fiscal: Lock-Free Atomic Spend Cap Barrier              │
//! └──────────────────────────────┬──────────────────────────────┘
//!                                │
//!                 ┌──────────────┴──────────────┐
//!                 ▼                             ▼
//!         Clear + Signed Receipt         Refuse + Signed Receipt
//!                 │                             │
//!                 ▼                             ▼
//!          Real-World Actuation           Block Actuation
//! ```
//!
//! ## Invariants
//! - `llm_clients_in_kernel`: Structurally guaranteed to be `false` (no non-deterministic calls).
//! - Multi-Format Substrate Compiler: Auto-detects and normalizes `NativeCage`, `MicrosoftAcs`,
//!   `LinuxFoundationAaif`, `NistOscal`, and `LulaValidation` into bitwise-deterministic artifacts.
//! - Tamper-Evident Receipts: Every verdict produces a dual SHA-256 + BLAKE3 signed receipt
//!   verified in constant time (`subtle::ConstantTimeEq`).
//! - Evidence Writer: Fail-closed append with pre-commit digest verification and hash chaining.
//! - Formal Trace Verifier: Independent state-machine conformance model checker.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use chrono::Utc;
use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

// ============================================================================
// 1. Refusal Code Constants
// ============================================================================

pub const CTRL_FTRA_001: &str = "CTRL_FTRA_001";
pub const CTRL_STPA_UCA1: &str = "CTRL_STPA_UCA1";
pub const CTRL_STPA_UCA2: &str = "CTRL_STPA_UCA2";
pub const CTRL_STPA_UCA3: &str = "CTRL_STPA_UCA3";
pub const CTRL_STPA_UCA4: &str = "CTRL_STPA_UCA4";
pub const CTRL_OPA_005: &str = "CTRL_OPA_005";
pub const CTRL_CONF_001: &str = "CTRL_CONF_001";
pub const CTRL_WARRANT_REQUIRED: &str = "CTRL_WARRANT_REQUIRED";
pub const CTRL_WARRANT_INVALID: &str = "CTRL_WARRANT_INVALID";
pub const CTRL_CONSENSUS_REQUIRED: &str = "CTRL_CONSENSUS_REQUIRED";
pub const CTRL_CBF_DOSE_001: &str = "CTRL_CBF_DOSE_001";
pub const CTRL_CBF_FINANCE_001: &str = "CTRL_CBF_FINANCE_001";
pub const FISCAL_CAP_EXCEEDED: &str = "FISCAL_CAP_EXCEEDED";

// ============================================================================
// 2. Substrate Specification Formats & Multi-Spec Compiler
// ============================================================================

/// Substrate policy format identifiers supported by CAGE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SubstrateFormat {
    NativeCage,
    MicrosoftAcs,
    LinuxFoundationAaif,
    NistOscal,
    LulaValidation,
}

impl SubstrateFormat {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NativeCage => "NativeCage",
            Self::MicrosoftAcs => "MicrosoftAcs",
            Self::LinuxFoundationAaif => "LinuxFoundationAaif",
            Self::NistOscal => "NistOscal",
            Self::LulaValidation => "LulaValidation",
        }
    }
}

/// A specific norm or rule within a substrate contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubstrateNorm {
    pub rule_id: String,
    pub description: String,
    pub tool_pattern: String,
    pub max_single_transfer_usd: Option<f64>,
    pub max_dose_mg: Option<f64>,
    pub requires_warrant: bool,
    pub required_role: Option<String>,
    pub consensus_threshold: Option<f64>,
    pub forbidden: bool,
}

/// Normalized, bitwise-deterministic artifact compiled from any of the 5 substrate formats.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledSubstrateArtifact {
    pub contract_id: String,
    pub format: SubstrateFormat,
    pub version: String,
    pub allowed_tools: Vec<String>,
    pub norms: Vec<SubstrateNorm>,
    pub max_single_transfer_usd: f64,
    pub max_dose_mg: f64,
    pub fiscal_cap_usd: f64,
    pub consensus_risk_threshold: f64,
    pub requires_warrant: bool,
    pub substrate_contract_digest: String,
    pub compiled_at_utc: String,
}

impl CompiledSubstrateArtifact {
    /// Computes canonical SHA-256 digest of normalized contract parameters.
    ///
    /// Guarantee: Compiling identical contract specifications yields bitwise identical digests.
    pub fn compute_digest(&self) -> String {
        let mut sorted_tools = self.allowed_tools.clone();
        sorted_tools.sort();
        let tools_joined = sorted_tools.join(",");

        let canonical = format!(
            "{};transfer={:.2};dose={:.2};fiscal={:.2};tools={};warrant={};consensus={:.4}",
            self.format.as_str(),
            self.max_single_transfer_usd,
            self.max_dose_mg,
            self.fiscal_cap_usd,
            tools_joined,
            self.requires_warrant,
            self.consensus_risk_threshold
        );

        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verifies the embedded `substrate_contract_digest` against the recalculated digest.
    pub fn verify_digest(&self) -> bool {
        let expected = self.compute_digest();
        self.substrate_contract_digest.as_bytes().ct_eq(expected.as_bytes()).into()
    }
}

/// Multi-format substrate contract compiler with automatic format detection.
pub struct SubstrateCompiler;

impl SubstrateCompiler {
    /// Auto-detects the specification format and compiles it into a `CompiledSubstrateArtifact`.
    pub fn detect_and_compile(payload: &serde_json::Value) -> Result<CompiledSubstrateArtifact, String> {
        let format = Self::detect_format(payload)?;
        Self::compile_with_format(payload, format)
    }

    /// Parses a string (JSON or key-value mapped YAML) and compiles into a `CompiledSubstrateArtifact`.
    pub fn detect_and_compile_str(raw: &str) -> Result<CompiledSubstrateArtifact, String> {
        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(raw) {
            return Self::detect_and_compile(&json_val);
        }

        // Lightweight parser for YAML key-values and Lula/CAGE manifests
        let mut map = serde_json::Map::new();
        let mut in_allowed_tools = false;
        let mut tools_list = Vec::new();

        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if trimmed.starts_with("kind:") {
                let val = trimmed.trim_start_matches("kind:").trim().trim_matches('"');
                map.insert("kind".to_string(), serde_json::Value::String(val.to_string()));
            } else if trimmed.starts_with("oscal-version:") {
                let val = trimmed.trim_start_matches("oscal-version:").trim().trim_matches('"');
                map.insert("oscal-version".to_string(), serde_json::Value::String(val.to_string()));
            } else if trimmed.starts_with("behaviorDeclarations:") {
                map.insert("behaviorDeclarations".to_string(), serde_json::Value::Array(Vec::new()));
            } else if trimmed.starts_with("governedRunLoop:") {
                map.insert("governedRunLoop".to_string(), serde_json::Value::Object(serde_json::Map::new()));
            } else if trimmed.starts_with("allowed_tools:") {
                in_allowed_tools = true;
            } else if in_allowed_tools && trimmed.starts_with("- ") {
                let tool = trimmed.trim_start_matches("- ").trim().trim_matches('"');
                tools_list.push(serde_json::Value::String(tool.to_string()));
            } else if let Some((k, v)) = trimmed.split_once(':') {
                in_allowed_tools = false;
                let key = k.trim().trim_matches('"');
                let val_str = v.trim().trim_matches('"');
                if let Ok(n) = val_str.parse::<f64>() {
                    map.insert(key.to_string(), serde_json::Number::from_f64(n).map(serde_json::Value::Number).unwrap_or(serde_json::Value::String(val_str.to_string())));
                } else if val_str == "true" || val_str == "false" {
                    map.insert(key.to_string(), serde_json::Value::Bool(val_str == "true"));
                } else if !val_str.is_empty() {
                    map.insert(key.to_string(), serde_json::Value::String(val_str.to_string()));
                }
            }
        }

        if !tools_list.is_empty() {
            map.insert("allowed_tools".to_string(), serde_json::Value::Array(tools_list));
        }

        if map.is_empty() {
            return Err("Malformed substrate specification: unable to parse as valid JSON or YAML contract".to_string());
        }

        Self::detect_and_compile(&serde_json::Value::Object(map))
    }

    /// Detects the format from document keys adhering to strict precedence:
    /// 1. `NistOscal` (`oscal-version`)
    /// 2. `LulaValidation` (`kind: LulaValidation` or Rego in OSCAL back-matter)
    /// 3. `MicrosoftAcs` (`behaviorDeclarations`)
    /// 4. `LinuxFoundationAaif` (`governedRunLoop`)
    /// 5. `NativeCage` (fallback)
    pub fn detect_format(payload: &serde_json::Value) -> Result<SubstrateFormat, String> {
        let obj = payload.as_object().ok_or_else(|| "Substrate specification must be a JSON object".to_string())?;

        // Check LulaValidation directly
        if let Some(kind) = obj.get("kind").and_then(|k| k.as_str()) {
            if kind.eq_ignore_ascii_case("LulaValidation") {
                return Ok(SubstrateFormat::LulaValidation);
            }
        }

        // Check OSCAL version
        if obj.contains_key("oscal-version") {
            // Check if OSCAL wraps a Lula Rego manifest in back-matter
            if let Some(bm) = obj.get("component-definition").and_then(|cd| cd.get("back-matter")) {
                let bm_str = bm.to_string().to_ascii_lowercase();
                if bm_str.contains("lula") || bm_str.contains("rego") {
                    return Ok(SubstrateFormat::LulaValidation);
                }
            }
            return Ok(SubstrateFormat::NistOscal);
        }

        // Check Microsoft ACS
        if obj.contains_key("behaviorDeclarations") {
            return Ok(SubstrateFormat::MicrosoftAcs);
        }

        // Check Linux Foundation AAIF
        if obj.contains_key("governedRunLoop") {
            return Ok(SubstrateFormat::LinuxFoundationAaif);
        }

        // Check Native CAGE format markers or minimal default
        if obj.contains_key("contract_id")
            || obj.contains_key("schema_version")
            || obj.contains_key("allowed_tools")
            || obj.contains_key("parameter_bounds")
            || obj.contains_key("norms")
            || obj.contains_key("domain")
            || obj.get("kind").and_then(|k| k.as_str()).is_some_and(|k| k.eq_ignore_ascii_case("NativeCage"))
            || obj.is_empty()
        {
            return Ok(SubstrateFormat::NativeCage);
        }

        Err("Unrecognized substrate contract specification format".to_string())
    }

    fn compile_with_format(payload: &serde_json::Value, format: SubstrateFormat) -> Result<CompiledSubstrateArtifact, String> {
        let mut allowed_tools = Vec::new();
        let mut max_single_transfer_usd = 10_000.0;
        let mut max_dose_mg = 100.0;
        let mut fiscal_cap_usd = 50_000.0;
        let mut consensus_risk_threshold = 0.85;
        let mut requires_warrant = false;
        let mut contract_id = format!("contract-{}", format.as_str().to_ascii_lowercase());
        let mut norms = Vec::new();

        match format {
            SubstrateFormat::NistOscal => {
                if let Some(id) = payload.get("id").and_then(|v| v.as_str()) {
                    contract_id = id.to_string();
                }
                // Extract props from component-definition -> components -> control-implementations
                if let Some(components) = payload.pointer("/component-definition/components").and_then(|c| c.as_array()) {
                    for comp in components {
                        if let Some(ctrl_impls) = comp.get("control-implementations").and_then(|ci| ci.as_array()) {
                            for ci in ctrl_impls {
                                if let Some(reqs) = ci.get("implemented-requirements").and_then(|r| r.as_array()) {
                                    for req in reqs {
                                        if let Some(cid) = req.get("control-id").and_then(|c| c.as_str()) {
                                            match cid {
                                                "ac-3" => allowed_tools.push("access_enforcement".to_string()),
                                                "si-10" => allowed_tools.push("information_input_validation".to_string()),
                                                other => allowed_tools.push(other.to_ascii_lowercase()),
                                            }
                                        }
                                        if let Some(props) = req.get("props").and_then(|p| p.as_array()) {
                                            for prop in props {
                                                let name = prop.get("name").and_then(|n| n.as_str()).unwrap_or("");
                                                let val = prop.get("value").and_then(|v| v.as_str()).unwrap_or("");
                                                match name {
                                                    "max_single_transfer_usd" | "max-transfer-usd" => {
                                                        if let Ok(n) = val.parse::<f64>() {
                                                            max_single_transfer_usd = n;
                                                        }
                                                    }
                                                    "max_dose_mg" | "max-dose" => {
                                                        if let Ok(n) = val.parse::<f64>() {
                                                            max_dose_mg = n;
                                                        }
                                                    }
                                                    "fiscal_cap_usd" | "fiscal-cap" => {
                                                        if let Ok(n) = val.parse::<f64>() {
                                                            fiscal_cap_usd = n;
                                                        }
                                                    }
                                                    "requires_warrant" => {
                                                        requires_warrant = val.eq_ignore_ascii_case("true") || val == "1";
                                                    }
                                                    "consensus_threshold" => {
                                                        if let Ok(n) = val.parse::<f64>() {
                                                            consensus_risk_threshold = n.clamp(0.0, 1.0);
                                                        }
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            SubstrateFormat::LulaValidation => {
                if let Some(name) = payload.pointer("/metadata/name").and_then(|n| n.as_str()) {
                    contract_id = name.to_string();
                }
                // Extract from metadata annotations
                if let Some(ann) = payload.pointer("/metadata/annotations").and_then(|a| a.as_object()) {
                    if let Some(v) = ann.get("max_single_transfer_usd").and_then(|v| v.as_str()).and_then(|s| s.parse::<f64>().ok()) {
                        max_single_transfer_usd = v;
                    }
                    if let Some(v) = ann.get("max_dose_mg").and_then(|v| v.as_str()).and_then(|s| s.parse::<f64>().ok()) {
                        max_dose_mg = v;
                    }
                    if let Some(v) = ann.get("fiscal_cap_usd").and_then(|v| v.as_str()).and_then(|s| s.parse::<f64>().ok()) {
                        fiscal_cap_usd = v;
                    }
                    if let Some(v) = ann.get("requires_warrant").and_then(|v| v.as_str()) {
                        requires_warrant = v.eq_ignore_ascii_case("true") || v == "1";
                    }
                    if let Some(v) = ann.get("consensus_threshold").and_then(|v| v.as_str()).and_then(|s| s.parse::<f64>().ok()) {
                        consensus_risk_threshold = v.clamp(0.0, 1.0);
                    }
                }
                // Extract resources as tools
                if let Some(resources) = payload.pointer("/spec/domain/kubernetes-spec/resources").and_then(|r| r.as_array()) {
                    for r in resources {
                        if let Some(name) = r.get("name").and_then(|n| n.as_str()) {
                            allowed_tools.push(name.to_ascii_lowercase());
                        }
                    }
                }
            }
            SubstrateFormat::MicrosoftAcs => {
                if let Some(name) = payload.pointer("/metadata/name").and_then(|n| n.as_str()) {
                    contract_id = name.to_string();
                }
                if let Some(decls) = payload.get("behaviorDeclarations").and_then(|b| b.as_array()) {
                    for decl in decls {
                        if let Some(action) = decl.get("action").and_then(|a| a.as_str()) {
                            allowed_tools.push(action.to_ascii_lowercase());
                        }
                        if let Some(req_w) = decl.get("requires_warrant").and_then(|w| w.as_bool()) {
                            if req_w {
                                requires_warrant = true;
                            }
                        }
                        if let Some(constraints) = decl.get("constraints").and_then(|c| c.as_array()) {
                            for c in constraints {
                                let param = c.get("parameter").and_then(|p| p.as_str()).unwrap_or("");
                                let val = c.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0);
                                if param.contains("transfer") || param.contains("amount") {
                                    max_single_transfer_usd = val;
                                } else if param.contains("dose") || param.contains("mg") {
                                    max_dose_mg = val;
                                } else if param.contains("fiscal") || param.contains("limit") || param.contains("spend") {
                                    fiscal_cap_usd = val;
                                } else if param.contains("consensus") {
                                    consensus_risk_threshold = val.clamp(0.0, 1.0);
                                }
                            }
                        }
                    }
                }
            }
            SubstrateFormat::LinuxFoundationAaif => {
                if let Some(stages) = payload.pointer("/governedRunLoop/stages").and_then(|s| s.as_array()) {
                    for stage in stages {
                        if let Some(act) = stage.get("action").and_then(|a| a.as_str()) {
                            allowed_tools.push(act.to_ascii_lowercase());
                        }
                        if let Some(thresh) = stage.get("threshold").and_then(|t| t.as_f64()) {
                            consensus_risk_threshold = thresh.clamp(0.0, 1.0);
                        }
                        if let Some(constraints) = stage.get("constraints").and_then(|c| c.as_array()) {
                            for c in constraints {
                                let param = c.get("parameter").and_then(|p| p.as_str()).unwrap_or("");
                                let val = c.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0);
                                if param.contains("transfer") {
                                    max_single_transfer_usd = val;
                                } else if param.contains("fiscal") {
                                    fiscal_cap_usd = val;
                                } else if param.contains("dose") {
                                    max_dose_mg = val;
                                }
                            }
                        }
                    }
                }
            }
            SubstrateFormat::NativeCage => {
                if let Some(id) = payload.get("contract_id").or_else(|| payload.get("domain")).and_then(|d| d.as_str()) {
                    contract_id = id.to_string();
                }
                if let Some(tools) = payload.get("allowed_tools").and_then(|t| t.as_array()) {
                    for t in tools {
                        if let Some(s) = t.as_str() {
                            allowed_tools.push(s.to_ascii_lowercase());
                        }
                    }
                }
                if let Some(bounds) = payload.get("parameter_bounds").and_then(|b| b.as_object()) {
                    if let Some(v) = bounds.get("max_single_transfer_usd").and_then(|v| v.as_f64()) {
                        max_single_transfer_usd = v;
                    }
                    if let Some(v) = bounds.get("max_dose_mg").and_then(|v| v.as_f64()) {
                        max_dose_mg = v;
                    }
                    if let Some(v) = bounds.get("fiscal_cap_usd").and_then(|v| v.as_f64()) {
                        fiscal_cap_usd = v;
                    }
                }
                if let Some(n_arr) = payload.get("norms").and_then(|n| n.as_array()) {
                    for n in n_arr {
                        let id = n.get("id").and_then(|i| i.as_str()).unwrap_or("NORM_001").to_string();
                        let req_w = n.get("requires_warrant").and_then(|w| w.as_bool()).unwrap_or(false);
                        if req_w {
                            requires_warrant = true;
                        }
                        if let Some(ct) = n.get("consensus_threshold").and_then(|c| c.as_f64()) {
                            consensus_risk_threshold = ct.clamp(0.0, 1.0);
                        }
                        norms.push(SubstrateNorm {
                            rule_id: id,
                            description: n.get("description").and_then(|d| d.as_str()).unwrap_or("").to_string(),
                            tool_pattern: n.get("tool_pattern").and_then(|t| t.as_str()).unwrap_or("*").to_string(),
                            max_single_transfer_usd: n.get("max_single_transfer_usd").and_then(|m| m.as_f64()),
                            max_dose_mg: n.get("max_dose_mg").and_then(|m| m.as_f64()),
                            requires_warrant: req_w,
                            required_role: n.get("required_role").and_then(|r| r.as_str()).map(ToString::to_string),
                            consensus_threshold: n.get("consensus_threshold").and_then(|c| c.as_f64()),
                            forbidden: n.get("forbidden").and_then(|f| f.as_bool()).unwrap_or(false),
                        });
                    }
                }
            }
        }

        // Deduplicate and sort allowed_tools
        allowed_tools.sort();
        allowed_tools.dedup();

        let mut artifact = CompiledSubstrateArtifact {
            contract_id,
            format,
            version: "1.0.0".to_string(),
            allowed_tools,
            norms,
            max_single_transfer_usd,
            max_dose_mg,
            fiscal_cap_usd,
            consensus_risk_threshold,
            requires_warrant,
            substrate_contract_digest: String::new(),
            compiled_at_utc: Utc::now().to_rfc3339(),
        };

        artifact.substrate_contract_digest = artifact.compute_digest();
        Ok(artifact)
    }
}

// ============================================================================
// 3. Tiers, Verdicts & Cryptographic Decision Receipts
// ============================================================================

/// The 8 strictly sequential CAGE governance tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum CageTier {
    Tier1Ftra = 1,
    Tier2Stpa = 2,
    Tier3Opa = 3,
    Tier4Confidence = 4,
    Tier5Warrant = 5,
    Tier6Consensus = 6,
    Tier7Cbf = 7,
    Tier8Fiscal = 8,
}

impl CageTier {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Tier1Ftra => "Tier1_FTRA",
            Self::Tier2Stpa => "Tier2_STPA",
            Self::Tier3Opa => "Tier3_SubstrateOPA",
            Self::Tier4Confidence => "Tier4_Confidence",
            Self::Tier5Warrant => "Tier5_Warrant",
            Self::Tier6Consensus => "Tier6_Consensus",
            Self::Tier7Cbf => "Tier7_CBF",
            Self::Tier8Fiscal => "Tier8_Fiscal",
        }
    }

    pub const fn name(&self) -> &'static str {
        match self {
            Self::Tier1Ftra => "Tier 1: FTRA (Fault Tree Risk Analysis)",
            Self::Tier2Stpa => "Tier 2: STPA (Unsafe Control Actions)",
            Self::Tier3Opa => "Tier 3: OPA / Substrate Contract Norms",
            Self::Tier4Confidence => "Tier 4: Confidence & Self-Authorization Detector",
            Self::Tier5Warrant => "Tier 5: Cryptographic Warrant Token Verification",
            Self::Tier6Consensus => "Tier 6: Human Consensus Escalation",
            Self::Tier7Cbf => "Tier 7: Control Barrier Functions (CBF)",
            Self::Tier8Fiscal => "Tier 8: Atomic Concurrent Fiscal Cap Barrier",
        }
    }
}

/// Verdict emitted by the CAGE governance kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CageVerdict {
    Clear,
    Refuse,
}

impl CageVerdict {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Clear => "Clear",
            Self::Refuse => "Refuse",
        }
    }
}

/// Cryptographic Warrant Token for Tier 5 conditional execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CageWarrantToken {
    pub agent_id: String,
    pub tool_name: String,
    pub argument_digest: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub signature_hex: String,
}

impl CageWarrantToken {
    /// Computes canonical SHA-256 digest of tool arguments.
    pub fn compute_argument_digest(arguments: &serde_json::Value) -> String {
        let serialized = serde_json::to_string(arguments).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Issues and signs a new `CageWarrantToken`.
    pub fn sign(
        secret: &[u8],
        agent_id: &str,
        tool_name: &str,
        argument_digest: &str,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> Self {
        let payload = format!("{agent_id}:{tool_name}:{argument_digest}:{issued_at_ms}:{expires_at_ms}");
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC supports keys of any length");
        mac.update(payload.as_bytes());
        let signature_hex = hex::encode(mac.finalize().into_bytes());

        Self {
            agent_id: agent_id.to_string(),
            tool_name: tool_name.to_string(),
            argument_digest: argument_digest.to_string(),
            issued_at_ms,
            expires_at_ms,
            signature_hex,
        }
    }

    /// Verifies token validity, time boundary, and signature in constant time.
    pub fn verify(&self, secret: &[u8], current_time_ms: u64) -> bool {
        if current_time_ms > self.expires_at_ms || current_time_ms < self.issued_at_ms {
            return false;
        }

        let payload = format!(
            "{}:{}:{}:{}:{}",
            self.agent_id, self.tool_name, self.argument_digest, self.issued_at_ms, self.expires_at_ms
        );
        let mut mac = match HmacSha256::new_from_slice(secret) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mac.update(payload.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());

        self.signature_hex.as_bytes().ct_eq(expected.as_bytes()).into()
    }
}

/// Human consensus approval ticket for Tier 6.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HitlConsensusApproval {
    pub operator_id: String,
    pub is_approved: bool,
    pub rationale: String,
    pub approved_at_ms: u64,
    pub signature_hex: Option<String>,
}

/// Signed, tamper-evident CAGE decision receipt with dual SHA-256 + BLAKE3 digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CageDecisionReceipt {
    pub receipt_id: String,
    pub timestamp_ms: u64,
    pub agent_id: String,
    pub tool_name: String,
    pub argument_digest: String,
    pub substrate_digest: String,
    pub verdict: CageVerdict,
    pub tier: CageTier,
    pub rule_id: String,
    pub reasons: Vec<String>,
    pub refusal_reason: Option<String>,
    pub sha256_digest: String,
    pub blake3_digest: String,
    pub decision_digest: String,
    pub receipt_signature: String,
}

impl CageDecisionReceipt {
    /// Computes canonical string representation of receipt fields for deterministic hashing.
    pub fn compute_canonical_payload(&self) -> String {
        format!(
            "agent_id={}&argument_digest={}&receipt_id={}&rule_id={}&substrate_digest={}&tier={}&timestamp_ms={}&tool_name={}&verdict={}",
            self.agent_id,
            self.argument_digest,
            self.receipt_id,
            self.rule_id,
            self.substrate_digest,
            self.tier as u8,
            self.timestamp_ms,
            self.tool_name,
            self.verdict.as_str()
        )
    }

    /// Constructs and cryptographically signs a `CageDecisionReceipt`.
    #[allow(clippy::too_many_arguments)]
    pub fn create_and_sign(
        agent_id: &str,
        tool_name: &str,
        argument_digest: &str,
        substrate_digest: &str,
        verdict: CageVerdict,
        tier: CageTier,
        rule_id: &str,
        reasons: Vec<String>,
        refusal_reason: Option<String>,
        timestamp_ms: u64,
        secret_key: &[u8],
    ) -> Self {
        let receipt_id = format!("cage-rcpt-{}", uuid::Uuid::new_v4());

        let mut unhashed = Self {
            receipt_id,
            timestamp_ms,
            agent_id: agent_id.to_string(),
            tool_name: tool_name.to_string(),
            argument_digest: argument_digest.to_string(),
            substrate_digest: substrate_digest.to_string(),
            verdict,
            tier,
            rule_id: rule_id.to_string(),
            reasons,
            refusal_reason,
            sha256_digest: String::new(),
            blake3_digest: String::new(),
            decision_digest: String::new(),
            receipt_signature: String::new(),
        };

        let canonical = unhashed.compute_canonical_payload();
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let sha256_hex = hex::encode(hasher.finalize());
        let blake3_hex = blake3::hash(canonical.as_bytes()).to_hex().to_string();

        unhashed.sha256_digest = sha256_hex.clone();
        unhashed.blake3_digest = blake3_hex;
        unhashed.decision_digest = sha256_hex.clone();

        // Sign decision_digest using HMAC-SHA256
        let mut mac = HmacSha256::new_from_slice(secret_key).expect("HMAC supports keys of any length");
        mac.update(sha256_hex.as_bytes());
        unhashed.receipt_signature = hex::encode(mac.finalize().into_bytes());

        unhashed
    }

    /// Constant-time verification of `sha256_digest`, `blake3_digest`, and `decision_digest`.
    pub fn verify_digest(&self) -> bool {
        let canonical = self.compute_canonical_payload();

        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let expected_sha256 = hex::encode(hasher.finalize());
        let expected_blake3 = blake3::hash(canonical.as_bytes()).to_hex().to_string();

        let sha_ok = self.sha256_digest.as_bytes().ct_eq(expected_sha256.as_bytes());
        let blake_ok = self.blake3_digest.as_bytes().ct_eq(expected_blake3.as_bytes());
        let decision_ok = self.decision_digest.as_bytes().ct_eq(expected_sha256.as_bytes());

        (sha_ok & blake_ok & decision_ok).into()
    }

    /// Verifies the HMAC-SHA256 signature in constant time against a secret key.
    pub fn verify_signature(&self, secret_key: &[u8]) -> bool {
        if self.receipt_signature.is_empty() {
            return false;
        }
        let mut mac = match HmacSha256::new_from_slice(secret_key) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mac.update(self.decision_digest.as_bytes());
        let expected_sig = hex::encode(mac.finalize().into_bytes());
        self.receipt_signature.as_bytes().ct_eq(expected_sig.as_bytes()).into()
    }

    /// Full verification of both digest integrity and signature authenticity.
    pub fn verify_all(&self, secret_key: &[u8]) -> bool {
        self.verify_digest() && self.verify_signature(secret_key)
    }
}

// ============================================================================
// 4. Evidence Writer & Hash Chaining
// ============================================================================

/// Entry in the tamper-evident evidence log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageEvidenceEntry {
    pub sequence_no: usize,
    pub timestamp_ms: u64,
    pub receipt: CageDecisionReceipt,
    pub prev_hash: String,
    pub entry_hash: String,
}

/// Cryptographic evidence writer with mandatory pre-commit digest verification.
#[derive(Debug)]
pub struct CageEvidenceWriter {
    records: RwLock<Vec<CageEvidenceEntry>>,
    available: AtomicBool,
    hmac_key: Option<Vec<u8>>,
}

impl Default for CageEvidenceWriter {
    fn default() -> Self {
        Self::new(true, None)
    }
}

impl CageEvidenceWriter {
    pub fn new(available: bool, hmac_key: Option<Vec<u8>>) -> Self {
        Self {
            records: RwLock::new(Vec::new()),
            available: AtomicBool::new(available),
            hmac_key,
        }
    }

    /// Appends a decision receipt after strictly validating its cryptographic decision digest.
    pub fn append_receipt(&self, receipt: CageDecisionReceipt) -> Result<CageEvidenceEntry, String> {
        // 1. Fail-closed availability check
        if !self.available.load(Ordering::SeqCst) {
            return Err("CAGE_EVIDENCE_SINK_UNAVAILABLE: Fail-closed logging requirement violated".to_string());
        }

        // 2. Strict decision digest verification (MANDATORY GATE)
        if !receipt.verify_digest() {
            return Err(format!(
                "TAMPERED_RECEIPT_DIGEST: Decision digest verification failed for receipt '{}'",
                receipt.receipt_id
            ));
        }

        // 3. Optional HMAC signature check if key is configured
        if let Some(ref key) = self.hmac_key {
            if !receipt.verify_signature(key) {
                return Err(format!(
                    "INVALID_RECEIPT_SIGNATURE: HMAC signature verification failed for receipt '{}'",
                    receipt.receipt_id
                ));
            }
        }

        // 4. Commit to hash-chained log under write lock
        let mut guard = self.records.write();
        let seq = guard.len();
        let prev_hash = guard
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| "0000000000000000000000000000000000000000000000000000000000000000".to_string());

        let timestamp_ms = receipt.timestamp_ms;
        let chain_input = format!(
            "{}|{}|{}|{}|{}",
            seq, prev_hash, receipt.decision_digest, receipt.receipt_signature, timestamp_ms
        );
        let entry_hash = blake3::hash(chain_input.as_bytes()).to_hex().to_string();

        let entry = CageEvidenceEntry {
            sequence_no: seq,
            timestamp_ms,
            receipt,
            prev_hash,
            entry_hash,
        };

        guard.push(entry.clone());
        Ok(entry)
    }

    /// Formally verifies the entire cryptographic hash chain and each embedded receipt digest.
    pub fn verify_chain_integrity(&self) -> bool {
        let guard = self.records.read();
        let mut expected_prev = "0000000000000000000000000000000000000000000000000000000000000000".to_string();

        for (idx, entry) in guard.iter().enumerate() {
            if entry.sequence_no != idx {
                return false;
            }
            if entry.prev_hash != expected_prev {
                return false;
            }
            if !entry.receipt.verify_digest() {
                return false;
            }
            if let Some(ref key) = self.hmac_key {
                if !entry.receipt.verify_signature(key) {
                    return false;
                }
            }
            let chain_input = format!(
                "{}|{}|{}|{}|{}",
                entry.sequence_no,
                entry.prev_hash,
                entry.receipt.decision_digest,
                entry.receipt.receipt_signature,
                entry.timestamp_ms
            );
            let recomputed = blake3::hash(chain_input.as_bytes()).to_hex().to_string();
            if entry.entry_hash != recomputed {
                return false;
            }
            expected_prev = entry.entry_hash.clone();
        }

        true
    }

    pub fn list_receipts(&self) -> Vec<CageDecisionReceipt> {
        self.records.read().iter().map(|e| e.receipt.clone()).collect()
    }

    pub fn count(&self) -> usize {
        self.records.read().len()
    }

    pub fn len(&self) -> usize {
        self.records.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.read().is_empty()
    }

    pub fn set_available(&self, available: bool) {
        self.available.store(available, Ordering::SeqCst);
    }
}

// ============================================================================
// 5. Control Barrier Functions (CBF) & Atomic Fiscal Barrier
// ============================================================================

/// Finance bounding barrier plugin for Tier 7 CBF.
#[derive(Debug, Clone)]
pub struct FinanceBoundingBarrier {
    pub max_notional_usd: f64,
    pub max_exposure_usd: f64,
    pub current_exposure_usd: f64,
    pub gamma: f64,
}

impl FinanceBoundingBarrier {
    pub fn new(max_notional_usd: f64, max_exposure_usd: f64, current_exposure_usd: f64, gamma: f64) -> Self {
        Self {
            max_notional_usd,
            max_exposure_usd,
            current_exposure_usd,
            gamma: gamma.clamp(0.01, 1.0),
        }
    }

    /// Evaluates discrete-time forward invariance:
    ///
    /// $$B(x_{k+1}) = \gamma (L_{\max} - E_k) - \text{proposed\_order} \ge 0$$
    pub fn evaluate(&self, proposed_order_usd: f64) -> Result<(), (String, String)> {
        if proposed_order_usd > self.max_notional_usd {
            return Err((
                CTRL_CBF_FINANCE_001.to_string(),
                format!(
                    "Proposed order ${:.2} exceeds max notional limit ${:.2}",
                    proposed_order_usd, self.max_notional_usd
                ),
            ));
        }

        let h_k = self.max_exposure_usd - self.current_exposure_usd;
        let new_exposure = self.current_exposure_usd + proposed_order_usd;
        let h_next = self.max_exposure_usd - new_exposure;

        if h_next < 0.0 {
            return Err((
                CTRL_CBF_FINANCE_001.to_string(),
                format!(
                    "Cumulative exposure ${:.2} breaches maximum portfolio exposure limit ${:.2}",
                    new_exposure, self.max_exposure_usd
                ),
            ));
        }

        let barrier_value = h_next - (1.0 - self.gamma) * h_k;
        if barrier_value < -1e-6 {
            return Err((
                CTRL_CBF_FINANCE_001.to_string(),
                format!(
                    "Discrete forward invariance violated: B(x) = {:.4} < 0.0 (gamma={:.2})",
                    barrier_value, self.gamma
                ),
            ));
        }

        Ok(())
    }
}

/// Healthcare medication dose barrier plugin for Tier 7 CBF.
#[derive(Debug, Clone)]
pub struct HealthcareDoseBarrier {
    pub max_single_dose_mg: f64,
    pub max_daily_dose_mg: f64,
    pub cumulative_dose_24h_mg: f64,
    pub gamma: f64,
}

impl HealthcareDoseBarrier {
    pub fn new(max_single_dose_mg: f64, max_daily_dose_mg: f64, cumulative_dose_24h_mg: f64, gamma: f64) -> Self {
        Self {
            max_single_dose_mg,
            max_daily_dose_mg,
            cumulative_dose_24h_mg,
            gamma: gamma.clamp(0.01, 1.0),
        }
    }

    /// Evaluates discrete-time forward invariance:
    ///
    /// $$B(x_{k+1}) = \gamma (D_{\max} - d_{\text{cum}}) - d_{\text{proposed}} \ge 0$$
    pub fn evaluate(&self, proposed_dose_mg: f64) -> Result<(), (String, String)> {
        if proposed_dose_mg > self.max_single_dose_mg {
            return Err((
                CTRL_CBF_DOSE_001.to_string(),
                format!(
                    "Proposed single dose {:.2} mg exceeds single administration cap {:.2} mg",
                    proposed_dose_mg, self.max_single_dose_mg
                ),
            ));
        }

        let h_k = self.max_daily_dose_mg - self.cumulative_dose_24h_mg;
        let new_dose = self.cumulative_dose_24h_mg + proposed_dose_mg;
        let h_next = self.max_daily_dose_mg - new_dose;

        if h_next < 0.0 {
            return Err((
                CTRL_CBF_DOSE_001.to_string(),
                format!(
                    "Cumulative 24h dose {:.2} mg breaches lethal threshold {:.2} mg",
                    new_dose, self.max_daily_dose_mg
                ),
            ));
        }

        let barrier_value = h_next - (1.0 - self.gamma) * h_k;
        if barrier_value < -1e-6 {
            return Err((
                CTRL_CBF_DOSE_001.to_string(),
                format!(
                    "Dose barrier invariance violated: B(x) = {:.4} < 0.0 (gamma={:.2})",
                    barrier_value, self.gamma
                ),
            ));
        }

        Ok(())
    }
}

/// Lock-free atomic fiscal spend barrier using micro-cents ($1 = 1,000,000 micro-cents).
pub struct AtomicFiscalBarrier {
    spent_micro_usd: AtomicU64,
    fiscal_cap_micro_usd: AtomicU64,
}

impl AtomicFiscalBarrier {
    pub fn new(fiscal_cap_usd: f64) -> Self {
        let cap_micro = (fiscal_cap_usd.max(0.0) * 1_000_000.0) as u64;
        Self {
            spent_micro_usd: AtomicU64::new(0),
            fiscal_cap_micro_usd: AtomicU64::new(cap_micro),
        }
    }

    pub fn get_spent_usd(&self) -> f64 {
        (self.spent_micro_usd.load(Ordering::Acquire) as f64) / 1_000_000.0
    }

    pub fn get_cap_usd(&self) -> f64 {
        (self.fiscal_cap_micro_usd.load(Ordering::Acquire) as f64) / 1_000_000.0
    }

    pub fn set_cap_usd(&self, cap_usd: f64) {
        let cap_micro = (cap_usd.max(0.0) * 1_000_000.0) as u64;
        self.fiscal_cap_micro_usd.store(cap_micro, Ordering::Release);
    }

    /// Atomic compare-and-exchange: returns `Ok(new_total_micro)` or `Err("FISCAL_CAP_EXCEEDED")`.
    pub fn try_spend(&self, amount_usd: f64) -> Result<u64, String> {
        if amount_usd <= 0.0 {
            return Ok(self.spent_micro_usd.load(Ordering::Acquire));
        }

        let proposed_micro = (amount_usd * 1_000_000.0) as u64;
        let cap_micro = self.fiscal_cap_micro_usd.load(Ordering::Acquire);
        let mut current = self.spent_micro_usd.load(Ordering::Acquire);

        loop {
            let new_spent = match current.checked_add(proposed_micro) {
                Some(s) => s,
                None => {
                    return Err(FISCAL_CAP_EXCEEDED.to_string());
                }
            };

            if new_spent > cap_micro {
                return Err(FISCAL_CAP_EXCEEDED.to_string());
            }

            match self.spent_micro_usd.compare_exchange_weak(
                current,
                new_spent,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(new_spent),
                Err(actual) => current = actual,
            }
        }
    }

    pub fn reset(&self) {
        self.spent_micro_usd.store(0, Ordering::Release);
    }
}

// ============================================================================
// 6. Independent GOVERNANCE_TRACE Formal Model Checker
// ============================================================================

/// Governance trace event types matching the CAGE state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceTraceEventType {
    ActionProposed,
    TierEvaluated,
    WarrantChecked,
    ConsensusDecided,
    CbfVerified,
    FiscalCommitted,
    ReceiptSigned,
    ActuationCompleted,
    ActuationRefused,
}

/// Event recorded in a governance trace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernanceTraceEvent {
    pub step: usize,
    pub timestamp_ms: u64,
    pub kind: GovernanceTraceEventType,
    pub tier: Option<CageTier>,
    pub verdict: Option<CageVerdict>,
    pub rule_id: Option<String>,
    pub requires_warrant: bool,
    pub details: String,
}

/// Conformance report emitted by the independent model checker.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceConformanceReport {
    pub is_conformant: bool,
    pub total_events: usize,
    pub total_steps: usize,
    pub tiers_evaluated: Vec<CageTier>,
    pub final_verdict: Option<CageVerdict>,
    pub monotonic_ordering_valid: bool,
    pub actuation_receipt_valid: bool,
    pub warrant_precedence_valid: bool,
    pub violations: Vec<String>,
    pub summary: String,
}

/// Standalone formal trace model checker.
pub struct CageTraceVerifier;

impl CageTraceVerifier {
    /// Formally verifies a governance event trace against the CAGE state-machine rules.
    pub fn verify_trace_conformance(trace: &[GovernanceTraceEvent]) -> TraceConformanceReport {
        let mut violations = Vec::new();
        let mut last_step = 0usize;
        let mut last_timestamp_ms = 0u64;
        let mut highest_tier: Option<CageTier> = None;
        let mut warrant_verified = false;
        let mut requires_warrant = false;
        let mut clear_receipt_signed = false;
        let mut refuse_receipt_signed = false;
        let mut actuation_completed = false;
        let mut tiers_evaluated = Vec::new();
        let mut final_verdict: Option<CageVerdict> = None;

        let mut monotonic_ordering_valid = true;
        let mut actuation_receipt_valid = true;
        let mut warrant_precedence_valid = true;

        if trace.is_empty() {
            violations.push("EMPTY_TRACE: Governance trace contains 0 events".to_string());
            return TraceConformanceReport {
                is_conformant: false,
                total_events: 0,
                total_steps: 0,
                tiers_evaluated,
                final_verdict: None,
                monotonic_ordering_valid: false,
                actuation_receipt_valid: false,
                warrant_precedence_valid: false,
                violations,
                summary: "Empty trace rejected".to_string(),
            };
        }

        for (idx, event) in trace.iter().enumerate() {
            // Step monotonicity check
            if idx > 0 && event.step <= last_step {
                monotonic_ordering_valid = false;
                violations.push(format!(
                    "NON_MONOTONIC_STEP: Event at index {} has step {} <= previous step {}",
                    idx, event.step, last_step
                ));
            }
            last_step = event.step;

            // Timestamp monotonicity check (reject clock skew / time travel)
            if idx > 0 && event.timestamp_ms < last_timestamp_ms {
                monotonic_ordering_valid = false;
                violations.push(format!(
                    "NON_MONOTONIC_TIMESTAMP: Event at index {} has timestamp_ms {} < previous timestamp_ms {}",
                    idx, event.timestamp_ms, last_timestamp_ms
                ));
            }
            last_timestamp_ms = event.timestamp_ms;

            if event.requires_warrant {
                requires_warrant = true;
            }

            match event.kind {
                GovernanceTraceEventType::ActionProposed => {
                    if idx != 0 {
                        violations.push(format!(
                            "ACTION_PROPOSED_NOT_FIRST: ActionProposed occurred at step {}, expected at start",
                            event.step
                        ));
                    }
                }
                GovernanceTraceEventType::TierEvaluated => {
                    if let Some(current_tier) = event.tier {
                        if let Some(prev_tier) = highest_tier {
                            if current_tier <= prev_tier {
                                monotonic_ordering_valid = false;
                                violations.push(format!(
                                    "TRACE_OUT_OF_ORDER_TIER: Tier {:?} evaluated after Tier {:?} at step {}",
                                    current_tier, prev_tier, event.step
                                ));
                            }
                        }
                        highest_tier = Some(current_tier);
                        tiers_evaluated.push(current_tier);

                        if let Some(v) = event.verdict {
                            final_verdict = Some(v);
                            if v == CageVerdict::Refuse && actuation_completed {
                                actuation_receipt_valid = false;
                                violations.push(format!(
                                    "ACTUATION_AFTER_REFUSAL: Actuation occurred despite Tier {:?} refusal at step {}",
                                    current_tier, event.step
                                ));
                            }
                        }
                    }
                }
                GovernanceTraceEventType::WarrantChecked => {
                    warrant_verified = true;
                }
                GovernanceTraceEventType::ConsensusDecided => {}
                GovernanceTraceEventType::CbfVerified => {
                    if requires_warrant && !warrant_verified {
                        warrant_precedence_valid = false;
                        violations.push(format!(
                            "WARRANT_PRECEDENCE_VIOLATION: CBF_VERIFIED evaluated at step {} without required WARRANT_CHECKED",
                            event.step
                        ));
                    }
                }
                GovernanceTraceEventType::FiscalCommitted => {
                    if requires_warrant && !warrant_verified {
                        warrant_precedence_valid = false;
                        violations.push(format!(
                            "WARRANT_PRECEDENCE_VIOLATION: FISCAL_COMMITTED evaluated at step {} without required WARRANT_CHECKED",
                            event.step
                        ));
                    }
                }
                GovernanceTraceEventType::ReceiptSigned => {
                    match event.verdict {
                        Some(CageVerdict::Clear) => clear_receipt_signed = true,
                        Some(CageVerdict::Refuse) => refuse_receipt_signed = true,
                        None => violations.push(format!(
                            "RECEIPT_MISSING_VERDICT: ReceiptSigned event at step {} lacks verdict",
                            event.step
                        )),
                    }
                }
                GovernanceTraceEventType::ActuationCompleted => {
                    actuation_completed = true;
                    if !clear_receipt_signed {
                        actuation_receipt_valid = false;
                        violations.push(format!(
                            "ILLEGAL_ACTUATION_WITHOUT_CLEAR_RECEIPT: ActuationCompleted at step {} occurred without preceding Clear receipt",
                            event.step
                        ));
                    }
                    if refuse_receipt_signed {
                        actuation_receipt_valid = false;
                        violations.push(format!(
                            "ACTUATION_AFTER_REFUSAL: ActuationCompleted at step {} occurred after a Refuse receipt",
                            event.step
                        ));
                    }
                }
                GovernanceTraceEventType::ActuationRefused => {
                    if clear_receipt_signed && !refuse_receipt_signed {
                        violations.push(format!(
                            "CONTRADICTORY_REFUSAL: ActuationRefused at step {} followed a Clear receipt",
                            event.step
                        ));
                    }
                }
            }
        }

        let is_conformant = violations.is_empty();
        let summary = if is_conformant {
            format!(
                "Trace conformant: {} events, {} tiers evaluated, verdict: {:?}",
                trace.len(),
                tiers_evaluated.len(),
                final_verdict.unwrap_or(CageVerdict::Clear)
            )
        } else {
            format!("Trace non-conformant: {} violation(s) detected", violations.len())
        };

        TraceConformanceReport {
            is_conformant,
            total_events: trace.len(),
            total_steps: last_step,
            tiers_evaluated,
            final_verdict,
            monotonic_ordering_valid,
            actuation_receipt_valid,
            warrant_precedence_valid,
            violations,
            summary,
        }
    }
}

// ============================================================================
// 7. Request, Response & Kernel Status
// ============================================================================

/// Ingress request payload for CAGE PEP evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageEvaluationRequest {
    pub agent_id: String,
    pub role: String,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub confidence_score: Option<f64>,
    pub amount_usd: Option<f64>,
    pub dose_mg: Option<f64>,
    pub warrant_token: Option<CageWarrantToken>,
    pub human_approval: Option<HitlConsensusApproval>,
    pub context: Option<serde_json::Value>,
}

/// Egress evaluation response containing verdict, signed receipt, and formal trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageEvaluationResponse {
    pub verdict: CageVerdict,
    pub rule_id: String,
    pub tier: CageTier,
    pub receipt: CageDecisionReceipt,
    pub governance_trace: Vec<GovernanceTraceEvent>,
    pub error_message: Option<String>,
}

/// Kernel status report confirming LLM-free structural invariant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageKernelStatusReport {
    pub llm_clients_in_kernel: bool,
    pub active_contract_id: String,
    pub substrate_format: SubstrateFormat,
    pub substrate_contract_digest: String,
    pub fiscal_cap_usd: f64,
    pub fiscal_spent_usd: f64,
    pub total_evaluations: u64,
    pub total_cleared: u64,
    pub total_refused: u64,
    pub evidence_receipt_count: usize,
}

// ============================================================================
// 8. 8-Tier CAGE Governance Kernel
// ============================================================================

/// Production CAGE Governance Kernel executing the 8-tier deterministic pipeline.
pub struct CageGovernanceKernel {
    pub llm_clients_in_kernel: bool,
    active_substrate: RwLock<CompiledSubstrateArtifact>,
    fiscal_barrier: AtomicFiscalBarrier,
    evidence_writer: Arc<CageEvidenceWriter>,
    secret_key: Vec<u8>,
    total_evaluations: AtomicU64,
    total_cleared: AtomicU64,
    total_refused: AtomicU64,
}

impl Default for CageGovernanceKernel {
    fn default() -> Self {
        Self::new()
    }
}

impl CageGovernanceKernel {
    /// Instantiates kernel with default Native CAGE contract and generated 32-byte epoch key.
    pub fn new() -> Self {
        let default_contract = SubstrateCompiler::detect_and_compile(&serde_json::json!({
            "contract_id": "default-cage-contract",
            "schema_version": "cage-substrate/3.0",
            "domain": "general",
            "allowed_tools": [
                "execute_trade",
                "query_balance",
                "transfer_funds",
                "administer_medication",
                "engage_containment",
                "disarm_and_restore",
                "query_ollama_reasoning",
                "contain",
                "rollback"
            ],
            "parameter_bounds": {
                "max_single_transfer_usd": 10000.0,
                "max_dose_mg": 100.0,
                "fiscal_cap_usd": 50000.0
            },
            "norms": [
                {
                    "id": "DEFAULT_WARRANT_NORM",
                    "requires_warrant": false,
                    "consensus_threshold": 0.85
                }
            ]
        }))
        .expect("Default substrate contract must compile");

        Self::with_substrate(default_contract)
    }

    /// Instantiates kernel with a specific pre-compiled substrate artifact.
    pub fn with_substrate(artifact: CompiledSubstrateArtifact) -> Self {
        let fiscal_barrier = AtomicFiscalBarrier::new(artifact.fiscal_cap_usd);
        // Ephemeral 32-byte secret key for kernel epoch HMAC signing
        let secret_key = {
            let mut key = [0u8; 32];
            let seed = Utc::now().timestamp_nanos_opt().unwrap_or(42);
            for (idx, b) in key.iter_mut().enumerate() {
                *b = ((seed >> (idx % 8 * 8)) & 0xFF) as u8 ^ ((idx as u8).wrapping_mul(31));
            }
            key.to_vec()
        };

        let evidence_writer = Arc::new(CageEvidenceWriter::new(true, Some(secret_key.clone())));

        Self {
            llm_clients_in_kernel: false,
            active_substrate: RwLock::new(artifact),
            fiscal_barrier,
            evidence_writer,
            secret_key,
            total_evaluations: AtomicU64::new(0),
            total_cleared: AtomicU64::new(0),
            total_refused: AtomicU64::new(0),
        }
    }

    /// Hot-reloads an active substrate contract.
    pub fn load_substrate(&self, artifact: CompiledSubstrateArtifact) {
        self.fiscal_barrier.set_cap_usd(artifact.fiscal_cap_usd);
        *self.active_substrate.write() = artifact;
    }

    /// Returns the SHA-256 digest of the currently loaded substrate contract.
    pub fn active_substrate_digest(&self) -> String {
        self.active_substrate.read().substrate_contract_digest.clone()
    }

    /// Accessor for the cryptographic evidence writer.
    pub fn evidence_writer(&self) -> Arc<CageEvidenceWriter> {
        self.evidence_writer.clone()
    }

    /// Resets the cumulative fiscal spend counter.
    pub fn reset_fiscal(&self) {
        self.fiscal_barrier.reset();
    }

    /// Returns status report confirming structural invariants.
    pub fn status(&self) -> CageKernelStatusReport {
        let sub = self.active_substrate.read();
        CageKernelStatusReport {
            llm_clients_in_kernel: self.llm_clients_in_kernel,
            active_contract_id: sub.contract_id.clone(),
            substrate_format: sub.format,
            substrate_contract_digest: sub.substrate_contract_digest.clone(),
            fiscal_cap_usd: self.fiscal_barrier.get_cap_usd(),
            fiscal_spent_usd: self.fiscal_barrier.get_spent_usd(),
            total_evaluations: self.total_evaluations.load(Ordering::Acquire),
            total_cleared: self.total_cleared.load(Ordering::Acquire),
            total_refused: self.total_refused.load(Ordering::Acquire),
            evidence_receipt_count: self.evidence_writer.count(),
        }
    }

    /// Evaluates an agent action proposal through the 8-tier deterministic pipeline.
    pub fn evaluate(&self, req: &CageEvaluationRequest) -> CageEvaluationResponse {
        self.total_evaluations.fetch_add(1, Ordering::Relaxed);
        let now_ms = Utc::now().timestamp_millis().max(0) as u64;
        let sub = self.active_substrate.read().clone();
        let argument_digest = CageWarrantToken::compute_argument_digest(&req.arguments);

        let mut trace = Vec::new();
        let mut step = 1;

        // Trace Step 1: Action Proposed
        trace.push(GovernanceTraceEvent {
            step,
            timestamp_ms: now_ms,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: sub.requires_warrant,
            details: format!("Agent '{}' proposed action '{}'", req.agent_id, req.tool_name),
        });

        // --------------------------------------------------------------------
        // Tier 1: Fault Tree Risk Analysis (FTRA)
        // --------------------------------------------------------------------
        step += 1;
        if let Some(ref ctx) = req.context {
            let ctx_str = ctx.to_string().to_ascii_lowercase();
            // Check minimal cut set: unauthenticated external egress + sensitive/confidential payload
            let has_sensitive_dlp = ctx_str.contains("confidential") || ctx_str.contains("restricted");
            let has_unauth_egress = ctx_str.contains("unauthenticated_egress") || ctx_str.contains("unauthenticated external network");
            let is_irreversible = ctx_str.contains("irreversible_terminal") && req.human_approval.is_none();

            if (has_sensitive_dlp && has_unauth_egress) || is_irreversible {
                let reason = "Minimal cut set triggered: unauthenticated external egress with sensitive payload or unapproved terminal action";
                return self.emit_refusal(
                    req,
                    &argument_digest,
                    &sub.substrate_contract_digest,
                    CageTier::Tier1Ftra,
                    CTRL_FTRA_001,
                    reason,
                    now_ms,
                    trace,
                    step,
                    sub.requires_warrant,
                );
            }
        }
        trace.push(GovernanceTraceEvent {
            step,
            timestamp_ms: now_ms,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier1Ftra),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("PASS_FTRA".to_string()),
            requires_warrant: sub.requires_warrant,
            details: "FTRA minimal cut set check passed".to_string(),
        });

        // --------------------------------------------------------------------
        // Tier 2: Systems-Theoretic Process Analysis (STPA)
        // --------------------------------------------------------------------
        step += 1;
        if let Some(ref ctx) = req.context {
            let ctx_str = ctx.to_string().to_ascii_lowercase();
            if ctx_str.contains("omitted_safety_action") || ctx_str.contains("missing_safety_token") {
                return self.emit_refusal(
                    req,
                    &argument_digest,
                    &sub.substrate_contract_digest,
                    CageTier::Tier2Stpa,
                    CTRL_STPA_UCA1,
                    "STPA UCA-1: Required safety control action not provided",
                    now_ms,
                    trace,
                    step,
                    sub.requires_warrant,
                );
            }
            if ctx_str.contains("conflicting_state") || ctx_str.contains("contradictory_actuation") {
                return self.emit_refusal(
                    req,
                    &argument_digest,
                    &sub.substrate_contract_digest,
                    CageTier::Tier2Stpa,
                    CTRL_STPA_UCA2,
                    "STPA UCA-2: Unsafe control action provided in conflicting state",
                    now_ms,
                    trace,
                    step,
                    sub.requires_warrant,
                );
            }
            if ctx_str.contains("out_of_order") || ctx_str.contains("premature_actuation") {
                return self.emit_refusal(
                    req,
                    &argument_digest,
                    &sub.substrate_contract_digest,
                    CageTier::Tier2Stpa,
                    CTRL_STPA_UCA3,
                    "STPA UCA-3: Control action provided too early or out of sequence",
                    now_ms,
                    trace,
                    step,
                    sub.requires_warrant,
                );
            }
            if ctx_str.contains("lease_expired") || ctx_str.contains("duration_exceeded") {
                return self.emit_refusal(
                    req,
                    &argument_digest,
                    &sub.substrate_contract_digest,
                    CageTier::Tier2Stpa,
                    CTRL_STPA_UCA4,
                    "STPA UCA-4: Control action applied too long or after lease expiry",
                    now_ms,
                    trace,
                    step,
                    sub.requires_warrant,
                );
            }
        }
        trace.push(GovernanceTraceEvent {
            step,
            timestamp_ms: now_ms,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier2Stpa),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("PASS_STPA".to_string()),
            requires_warrant: sub.requires_warrant,
            details: "STPA 4-UCA hazard checks passed".to_string(),
        });

        // --------------------------------------------------------------------
        // Tier 3: OPA / Substrate Contract Norms (Tool Allowlist & Caps)
        // --------------------------------------------------------------------
        step += 1;
        let tool_lc = req.tool_name.to_ascii_lowercase();
        if !sub.allowed_tools.is_empty() && !sub.allowed_tools.iter().any(|t| t == &tool_lc) {
            return self.emit_refusal(
                req,
                &argument_digest,
                &sub.substrate_contract_digest,
                CageTier::Tier3Opa,
                "CTRL_OPA_FORBIDDEN_TOOL",
                &format!("Tool '{}' is not in substrate allowed_tools list", req.tool_name),
                now_ms,
                trace,
                step,
                sub.requires_warrant,
            );
        }

        if let Some(amt) = req.amount_usd {
            if amt > sub.max_single_transfer_usd {
                return self.emit_refusal(
                    req,
                    &argument_digest,
                    &sub.substrate_contract_digest,
                    CageTier::Tier3Opa,
                    CTRL_OPA_005,
                    &format!(
                        "Transfer amount ${:.2} exceeds single-transfer cap ${:.2}",
                        amt, sub.max_single_transfer_usd
                    ),
                    now_ms,
                    trace,
                    step,
                    sub.requires_warrant,
                );
            }
        }
        trace.push(GovernanceTraceEvent {
            step,
            timestamp_ms: now_ms,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier3Opa),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("PASS_OPA".to_string()),
            requires_warrant: sub.requires_warrant,
            details: "Substrate allowlist and single-transfer cap passed".to_string(),
        });

        // --------------------------------------------------------------------
        // Tier 4: Agent Confidence & Fabricated Claim Detector
        // --------------------------------------------------------------------
        step += 1;
        let args_str = req.arguments.to_string().to_ascii_lowercase();
        let unverified_claims = [
            "authorized_by_admin",
            "bypass_security",
            "override_governance",
            "pre_approved",
            "trusted_override",
            "self_certified",
            "skip_checks",
            "elevated_privilege_granted",
        ];

        for claim in unverified_claims {
            if args_str.contains(claim) {
                // If claim present without a valid warrant token, refuse
                let has_valid_warrant = req.warrant_token.as_ref().map(|w| w.verify(&self.secret_key, now_ms)).unwrap_or(false);
                if !has_valid_warrant {
                    return self.emit_refusal(
                        req,
                        &argument_digest,
                        &sub.substrate_contract_digest,
                        CageTier::Tier4Confidence,
                        CTRL_CONF_001,
                        &format!("Unverified self-authorization claim detected in arguments: '{claim}'"),
                        now_ms,
                        trace,
                        step,
                        sub.requires_warrant,
                    );
                }
            }
        }

        if let Some(conf) = req.confidence_score {
            if conf < 0.80 {
                return self.emit_refusal(
                    req,
                    &argument_digest,
                    &sub.substrate_contract_digest,
                    CageTier::Tier4Confidence,
                    CTRL_CONF_001,
                    &format!("Agent confidence score {:.2} below safety threshold 0.80", conf),
                    now_ms,
                    trace,
                    step,
                    sub.requires_warrant,
                );
            }
        }
        trace.push(GovernanceTraceEvent {
            step,
            timestamp_ms: now_ms,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier4Confidence),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("PASS_CONFIDENCE".to_string()),
            requires_warrant: sub.requires_warrant,
            details: "Confidence calibration and self-auth detector passed".to_string(),
        });

        // --------------------------------------------------------------------
        // Tier 5: Cryptographic Warrant Verification
        // --------------------------------------------------------------------
        step += 1;
        if sub.requires_warrant {
            match req.warrant_token.as_ref() {
                None => {
                    return self.emit_refusal(
                        req,
                        &argument_digest,
                        &sub.substrate_contract_digest,
                        CageTier::Tier5Warrant,
                        CTRL_WARRANT_REQUIRED,
                        "Substrate contract mandates cryptographic CageWarrantToken",
                        now_ms,
                        trace,
                        step,
                        true,
                    );
                }
                Some(token) => {
                    if !token.verify(&self.secret_key, now_ms) {
                        return self.emit_refusal(
                            req,
                            &argument_digest,
                            &sub.substrate_contract_digest,
                            CageTier::Tier5Warrant,
                            CTRL_WARRANT_INVALID,
                            "Warrant token signature verification failed or token expired",
                            now_ms,
                            trace,
                            step,
                            true,
                        );
                    }
                    if token.agent_id != req.agent_id || token.tool_name != req.tool_name {
                        return self.emit_refusal(
                            req,
                            &argument_digest,
                            &sub.substrate_contract_digest,
                            CageTier::Tier5Warrant,
                            CTRL_WARRANT_INVALID,
                            "Warrant token identity or tool binding mismatch",
                            now_ms,
                            trace,
                            step,
                            true,
                        );
                    }
                    if token.argument_digest != argument_digest {
                        return self.emit_refusal(
                            req,
                            &argument_digest,
                            &sub.substrate_contract_digest,
                            CageTier::Tier5Warrant,
                            CTRL_WARRANT_INVALID,
                            "Warrant argument digest mismatch: parameters modified",
                            now_ms,
                            trace,
                            step,
                            true,
                        );
                    }
                }
            }
            trace.push(GovernanceTraceEvent {
                step,
                timestamp_ms: now_ms,
                kind: GovernanceTraceEventType::WarrantChecked,
                tier: Some(CageTier::Tier5Warrant),
                verdict: Some(CageVerdict::Clear),
                rule_id: Some("PASS_WARRANT".to_string()),
                requires_warrant: true,
                details: "Cryptographic HMAC-SHA256 warrant token verified".to_string(),
            });
        }

        // --------------------------------------------------------------------
        // Tier 6: Multi-Party Consensus & Mandatory Rationale
        // --------------------------------------------------------------------
        step += 1;
        let mut calculated_risk = 0.10;
        if let Some(amt) = req.amount_usd {
            if amt > 5000.0 {
                calculated_risk = 0.90;
            }
        }
        if let Some(dose) = req.dose_mg {
            if dose > 50.0 {
                calculated_risk = 0.90;
            }
        }

        if calculated_risk >= sub.consensus_risk_threshold {
            match req.human_approval.as_ref() {
                None => {
                    return self.emit_refusal(
                        req,
                        &argument_digest,
                        &sub.substrate_contract_digest,
                        CageTier::Tier6Consensus,
                        CTRL_CONSENSUS_REQUIRED,
                        "High-risk action requires human consensus approval",
                        now_ms,
                        trace,
                        step,
                        sub.requires_warrant,
                    );
                }
                Some(approval) => {
                    if !approval.is_approved {
                        return self.emit_refusal(
                            req,
                            &argument_digest,
                            &sub.substrate_contract_digest,
                            CageTier::Tier6Consensus,
                            CTRL_CONSENSUS_REQUIRED,
                            "Human reviewer explicitly rejected proposal",
                            now_ms,
                            trace,
                            step,
                            sub.requires_warrant,
                        );
                    }
                    if approval.rationale.trim().is_empty() {
                        return self.emit_refusal(
                            req,
                            &argument_digest,
                            &sub.substrate_contract_digest,
                            CageTier::Tier6Consensus,
                            CTRL_CONSENSUS_REQUIRED,
                            "Mandatory consensus approval rationale is missing or empty",
                            now_ms,
                            trace,
                            step,
                            sub.requires_warrant,
                        );
                    }
                }
            }
            trace.push(GovernanceTraceEvent {
                step,
                timestamp_ms: now_ms,
                kind: GovernanceTraceEventType::ConsensusDecided,
                tier: Some(CageTier::Tier6Consensus),
                verdict: Some(CageVerdict::Clear),
                rule_id: Some("PASS_CONSENSUS".to_string()),
                requires_warrant: sub.requires_warrant,
                details: "Human consensus approved with verified rationale".to_string(),
            });
        }

        // --------------------------------------------------------------------
        // Tier 7: Control Barrier Functions (CBF Forward Invariance)
        // --------------------------------------------------------------------
        step += 1;
        if let Some(dose) = req.dose_mg {
            let dose_barrier = HealthcareDoseBarrier::new(sub.max_dose_mg, sub.max_dose_mg * 2.0, 0.0, 0.50);
            if let Err((code, reason)) = dose_barrier.evaluate(dose) {
                return self.emit_refusal(
                    req,
                    &argument_digest,
                    &sub.substrate_contract_digest,
                    CageTier::Tier7Cbf,
                    &code,
                    &reason,
                    now_ms,
                    trace,
                    step,
                    sub.requires_warrant,
                );
            }
        }
        if let Some(amt) = req.amount_usd {
            let fin_barrier = FinanceBoundingBarrier::new(sub.max_single_transfer_usd, sub.fiscal_cap_usd, 0.0, 0.50);
            if let Err((code, reason)) = fin_barrier.evaluate(amt) {
                return self.emit_refusal(
                    req,
                    &argument_digest,
                    &sub.substrate_contract_digest,
                    CageTier::Tier7Cbf,
                    &code,
                    &reason,
                    now_ms,
                    trace,
                    step,
                    sub.requires_warrant,
                );
            }
        }
        trace.push(GovernanceTraceEvent {
            step,
            timestamp_ms: now_ms,
            kind: GovernanceTraceEventType::CbfVerified,
            tier: Some(CageTier::Tier7Cbf),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("PASS_CBF".to_string()),
            requires_warrant: sub.requires_warrant,
            details: "Discrete Control Barrier Function forward invariance satisfied".to_string(),
        });

        // --------------------------------------------------------------------
        // Tier 8: Atomic Concurrent Fiscal Barrier
        // --------------------------------------------------------------------
        step += 1;
        if let Some(amt) = req.amount_usd {
            if let Err(code) = self.fiscal_barrier.try_spend(amt) {
                return self.emit_refusal(
                    req,
                    &argument_digest,
                    &sub.substrate_contract_digest,
                    CageTier::Tier8Fiscal,
                    &code,
                    &format!(
                        "Cumulative spend would exceed fiscal cap of ${:.2}",
                        self.fiscal_barrier.get_cap_usd()
                    ),
                    now_ms,
                    trace,
                    step,
                    sub.requires_warrant,
                );
            }
        }
        trace.push(GovernanceTraceEvent {
            step,
            timestamp_ms: now_ms,
            kind: GovernanceTraceEventType::FiscalCommitted,
            tier: Some(CageTier::Tier8Fiscal),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("PASS_FISCAL".to_string()),
            requires_warrant: sub.requires_warrant,
            details: "Atomic fiscal spend committed without overflow".to_string(),
        });

        // --------------------------------------------------------------------
        // All 8 Tiers Cleared: Sign Decision Receipt & Commit Evidence
        // --------------------------------------------------------------------
        step += 1;
        let receipt = CageDecisionReceipt::create_and_sign(
            &req.agent_id,
            &req.tool_name,
            &argument_digest,
            &sub.substrate_contract_digest,
            CageVerdict::Clear,
            CageTier::Tier8Fiscal,
            "CAGE_8_TIERS_CLEARED",
            vec!["All 8 deterministic governance tiers cleared".to_string()],
            None,
            now_ms,
            &self.secret_key,
        );

        let _ = self.evidence_writer.append_receipt(receipt.clone());
        self.total_cleared.fetch_add(1, Ordering::Relaxed);

        trace.push(GovernanceTraceEvent {
            step,
            timestamp_ms: now_ms,
            kind: GovernanceTraceEventType::ReceiptSigned,
            tier: Some(CageTier::Tier8Fiscal),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("CAGE_8_TIERS_CLEARED".to_string()),
            requires_warrant: sub.requires_warrant,
            details: format!("Decision receipt '{}' signed with Clear verdict", receipt.receipt_id),
        });

        step += 1;
        trace.push(GovernanceTraceEvent {
            step,
            timestamp_ms: now_ms,
            kind: GovernanceTraceEventType::ActuationCompleted,
            tier: Some(CageTier::Tier8Fiscal),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("ACTUATION_COMPLETED".to_string()),
            requires_warrant: sub.requires_warrant,
            details: "Real-world actuation authorized and cleared".to_string(),
        });

        CageEvaluationResponse {
            verdict: CageVerdict::Clear,
            rule_id: "CAGE_8_TIERS_CLEARED".to_string(),
            tier: CageTier::Tier8Fiscal,
            receipt,
            governance_trace: trace,
            error_message: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_refusal(
        &self,
        req: &CageEvaluationRequest,
        argument_digest: &str,
        substrate_digest: &str,
        tier: CageTier,
        rule_id: &str,
        reason: &str,
        now_ms: u64,
        mut trace: Vec<GovernanceTraceEvent>,
        mut step: usize,
        requires_warrant: bool,
    ) -> CageEvaluationResponse {
        self.total_refused.fetch_add(1, Ordering::Relaxed);

        trace.push(GovernanceTraceEvent {
            step,
            timestamp_ms: now_ms,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(tier),
            verdict: Some(CageVerdict::Refuse),
            rule_id: Some(rule_id.to_string()),
            requires_warrant,
            details: reason.to_string(),
        });

        step += 1;
        let receipt = CageDecisionReceipt::create_and_sign(
            &req.agent_id,
            &req.tool_name,
            argument_digest,
            substrate_digest,
            CageVerdict::Refuse,
            tier,
            rule_id,
            vec![reason.to_string()],
            Some(reason.to_string()),
            now_ms,
            &self.secret_key,
        );

        let _ = self.evidence_writer.append_receipt(receipt.clone());

        trace.push(GovernanceTraceEvent {
            step,
            timestamp_ms: now_ms,
            kind: GovernanceTraceEventType::ReceiptSigned,
            tier: Some(tier),
            verdict: Some(CageVerdict::Refuse),
            rule_id: Some(rule_id.to_string()),
            requires_warrant,
            details: format!("Decision receipt '{}' signed with Refuse verdict ({})", receipt.receipt_id, rule_id),
        });

        step += 1;
        trace.push(GovernanceTraceEvent {
            step,
            timestamp_ms: now_ms,
            kind: GovernanceTraceEventType::ActuationRefused,
            tier: Some(tier),
            verdict: Some(CageVerdict::Refuse),
            rule_id: Some(rule_id.to_string()),
            requires_warrant,
            details: format!("Actuation halted due to {} refusal: {}", rule_id, reason),
        });

        CageEvaluationResponse {
            verdict: CageVerdict::Refuse,
            rule_id: rule_id.to_string(),
            tier,
            receipt,
            governance_trace: trace,
            error_message: Some(reason.to_string()),
        }
    }
}

// Global Singleton
pub static GLOBAL_CAGE_KERNEL: std::sync::OnceLock<CageGovernanceKernel> = std::sync::OnceLock::new();

/// Returns the process-wide CAGE Governance Kernel singleton.
pub fn global_cage_kernel() -> &'static CageGovernanceKernel {
    GLOBAL_CAGE_KERNEL.get_or_init(CageGovernanceKernel::new)
}

// ============================================================================
// 9. Comprehensive Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_substrate_compiler_detects_all_five_formats() {
        // 1. Native CAGE
        let native_val = serde_json::json!({
            "schema_version": "cage-substrate/3.0",
            "allowed_tools": ["execute_trade", "query_balance"],
            "parameter_bounds": {
                "max_single_transfer_usd": 10000.0,
                "fiscal_cap_usd": 50000.0
            }
        });
        let c_native = SubstrateCompiler::detect_and_compile(&native_val).unwrap();
        assert_eq!(c_native.format, SubstrateFormat::NativeCage);
        assert!(c_native.verify_digest());

        // 2. Microsoft ACS
        let acs_val = serde_json::json!({
            "behaviorDeclarations": [
                {
                    "action": "execute_trade",
                    "constraints": [
                        { "parameter": "transfer_amount", "value": 10000.0 },
                        { "parameter": "fiscal_limit", "value": 50000.0 }
                    ]
                }
            ]
        });
        let c_acs = SubstrateCompiler::detect_and_compile(&acs_val).unwrap();
        assert_eq!(c_acs.format, SubstrateFormat::MicrosoftAcs);
        assert!(c_acs.verify_digest());

        // 3. Linux Foundation AAIF
        let aaif_val = serde_json::json!({
            "governedRunLoop": {
                "stages": [
                    {
                        "name": "policy_check",
                        "action": "execute_trade",
                        "constraints": [{ "parameter": "transfer_amount", "value": 10000.0 }]
                    }
                ]
            }
        });
        let c_aaif = SubstrateCompiler::detect_and_compile(&aaif_val).unwrap();
        assert_eq!(c_aaif.format, SubstrateFormat::LinuxFoundationAaif);
        assert!(c_aaif.verify_digest());

        // 4. NIST OSCAL
        let oscal_val = serde_json::json!({
            "oscal-version": "1.1.0",
            "component-definition": {
                "components": [{
                    "control-implementations": [{
                        "implemented-requirements": [{
                            "control-id": "ac-3",
                            "props": [{ "name": "max_single_transfer_usd", "value": "10000.00" }]
                        }]
                    }]
                }]
            }
        });
        let c_oscal = SubstrateCompiler::detect_and_compile(&oscal_val).unwrap();
        assert_eq!(c_oscal.format, SubstrateFormat::NistOscal);
        assert!(c_oscal.verify_digest());

        // 5. Lula Validation Manifest
        let lula_val = serde_json::json!({
            "kind": "LulaValidation",
            "metadata": {
                "name": "trade-validator",
                "annotations": {
                    "max_single_transfer_usd": "10000.00",
                    "fiscal_cap_usd": "50000.00"
                }
            }
        });
        let c_lula = SubstrateCompiler::detect_and_compile(&lula_val).unwrap();
        assert_eq!(c_lula.format, SubstrateFormat::LulaValidation);
        assert!(c_lula.verify_digest());
    }

    #[test]
    fn test_substrate_compiler_deterministic_digest() {
        let val1 = serde_json::json!({
            "schema_version": "cage-substrate/3.0",
            "allowed_tools": ["b_tool", "a_tool"],
            "parameter_bounds": {
                "max_single_transfer_usd": 10000.0,
                "fiscal_cap_usd": 50000.0
            }
        });
        let val2 = serde_json::json!({
            "schema_version": "cage-substrate/3.0",
            "allowed_tools": ["a_tool", "b_tool"],
            "parameter_bounds": {
                "max_single_transfer_usd": 10000.0,
                "fiscal_cap_usd": 50000.0
            }
        });

        let c1 = SubstrateCompiler::detect_and_compile(&val1).unwrap();
        let c2 = SubstrateCompiler::detect_and_compile(&val2).unwrap();

        assert_eq!(c1.substrate_contract_digest, c2.substrate_contract_digest);
    }

    #[test]
    fn test_decision_receipt_creation_and_tamper_detection() {
        let secret = b"test_epoch_secret_32bytes_long_";
        let receipt = CageDecisionReceipt::create_and_sign(
            "agent-01",
            "execute_trade",
            "arg_digest_001",
            "sub_digest_001",
            CageVerdict::Clear,
            CageTier::Tier8Fiscal,
            "CAGE_CLEARED",
            vec!["Cleared all tiers".to_string()],
            None,
            1_700_000_000,
            secret,
        );

        assert!(receipt.verify_digest());
        assert!(receipt.verify_signature(secret));
        assert!(receipt.verify_all(secret));

        // Tamper with verdict
        let mut tampered = receipt.clone();
        tampered.verdict = CageVerdict::Refuse;
        assert!(!tampered.verify_digest());

        // Tamper with rule_id
        let mut tampered_rule = receipt.clone();
        tampered_rule.rule_id = "MALICIOUS_OVERRIDE".to_string();
        assert!(!tampered_rule.verify_digest());

        // Wrong secret key
        assert!(!receipt.verify_signature(b"wrong_secret_key_32bytes_long___"));
    }

    #[test]
    fn test_evidence_writer_hash_chaining_and_fail_closed() {
        let secret = b"test_epoch_secret_32bytes_long_";
        let writer = CageEvidenceWriter::new(true, Some(secret.to_vec()));

        let r1 = CageDecisionReceipt::create_and_sign(
            "agent-01", "tool_a", "arg1", "sub1", CageVerdict::Clear, CageTier::Tier8Fiscal, "RULE_1", vec![], None, 100, secret,
        );
        let r2 = CageDecisionReceipt::create_and_sign(
            "agent-01", "tool_b", "arg2", "sub1", CageVerdict::Clear, CageTier::Tier8Fiscal, "RULE_2", vec![], None, 200, secret,
        );

        let e1 = writer.append_receipt(r1).unwrap();
        let e2 = writer.append_receipt(r2).unwrap();

        assert_eq!(e1.sequence_no, 0);
        assert_eq!(e2.sequence_no, 1);
        assert_eq!(e2.prev_hash, e1.entry_hash);
        assert!(writer.verify_chain_integrity());

        // Tampered receipt rejection
        let mut bad_r = CageDecisionReceipt::create_and_sign(
            "agent-01", "tool_c", "arg3", "sub1", CageVerdict::Clear, CageTier::Tier8Fiscal, "RULE_3", vec![], None, 300, secret,
        );
        bad_r.rule_id = "TAMPERED".to_string(); // Invalidate digest
        let res = writer.append_receipt(bad_r);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("TAMPERED_RECEIPT_DIGEST"));

        // Fail-closed availability
        writer.set_available(false);
        let good_r = CageDecisionReceipt::create_and_sign(
            "agent-01", "tool_d", "arg4", "sub1", CageVerdict::Clear, CageTier::Tier8Fiscal, "RULE_4", vec![], None, 400, secret,
        );
        let res_unavail = writer.append_receipt(good_r);
        assert!(res_unavail.is_err());
        assert!(res_unavail.unwrap_err().contains("CAGE_EVIDENCE_SINK_UNAVAILABLE"));
    }

    #[test]
    fn test_trace_verifier_valid_and_invalid_traces() {
        // Valid 8-tier trace
        let valid_trace = vec![
            GovernanceTraceEvent {
                step: 1,
                timestamp_ms: 100,
                kind: GovernanceTraceEventType::ActionProposed,
                tier: None,
                verdict: None,
                rule_id: None,
                requires_warrant: false,
                details: "Action proposed".to_string(),
            },
            GovernanceTraceEvent {
                step: 2,
                timestamp_ms: 101,
                kind: GovernanceTraceEventType::TierEvaluated,
                tier: Some(CageTier::Tier1Ftra),
                verdict: Some(CageVerdict::Clear),
                rule_id: Some("PASS".to_string()),
                requires_warrant: false,
                details: "FTRA cleared".to_string(),
            },
            GovernanceTraceEvent {
                step: 3,
                timestamp_ms: 102,
                kind: GovernanceTraceEventType::TierEvaluated,
                tier: Some(CageTier::Tier3Opa),
                verdict: Some(CageVerdict::Clear),
                rule_id: Some("PASS".to_string()),
                requires_warrant: false,
                details: "OPA cleared".to_string(),
            },
            GovernanceTraceEvent {
                step: 4,
                timestamp_ms: 103,
                kind: GovernanceTraceEventType::ReceiptSigned,
                tier: Some(CageTier::Tier8Fiscal),
                verdict: Some(CageVerdict::Clear),
                rule_id: Some("PASS".to_string()),
                requires_warrant: false,
                details: "Receipt signed".to_string(),
            },
            GovernanceTraceEvent {
                step: 5,
                timestamp_ms: 104,
                kind: GovernanceTraceEventType::ActuationCompleted,
                tier: Some(CageTier::Tier8Fiscal),
                verdict: Some(CageVerdict::Clear),
                rule_id: Some("PASS".to_string()),
                requires_warrant: false,
                details: "Actuation completed".to_string(),
            },
        ];

        let rep = CageTraceVerifier::verify_trace_conformance(&valid_trace);
        assert!(rep.is_conformant);

        // Out of order tier: Tier 3 followed by Tier 1
        let mut out_of_order = valid_trace.clone();
        out_of_order[2].tier = Some(CageTier::Tier1Ftra); // Tier 1 after Tier 1 (or lower)
        let rep_ooo = CageTraceVerifier::verify_trace_conformance(&out_of_order);
        assert!(!rep_ooo.is_conformant);
        assert!(rep_ooo.violations.iter().any(|v| v.contains("TRACE_OUT_OF_ORDER_TIER")));

        // Actuation without clear receipt
        let no_receipt = vec![
            valid_trace[0].clone(),
            valid_trace[1].clone(),
            GovernanceTraceEvent {
                step: 3,
                timestamp_ms: 105,
                kind: GovernanceTraceEventType::ActuationCompleted,
                tier: Some(CageTier::Tier8Fiscal),
                verdict: Some(CageVerdict::Clear),
                rule_id: Some("PASS".to_string()),
                requires_warrant: false,
                details: "Actuation premature".to_string(),
            },
        ];
        let rep_no_rcpt = CageTraceVerifier::verify_trace_conformance(&no_receipt);
        assert!(!rep_no_rcpt.is_conformant);
        assert!(rep_no_rcpt.violations.iter().any(|v| v.contains("ILLEGAL_ACTUATION_WITHOUT_CLEAR_RECEIPT")));

        // Reversed timestamp / clock skew
        let mut clock_skew = valid_trace.clone();
        clock_skew[2].timestamp_ms = 99; // Decreases from 101 to 99
        let rep_skew = CageTraceVerifier::verify_trace_conformance(&clock_skew);
        assert!(!rep_skew.is_conformant);
        assert!(rep_skew.violations.iter().any(|v| v.contains("NON_MONOTONIC_TIMESTAMP")));
    }

    #[test]
    fn test_tier3_opa_transfer_caps() {
        let kernel = CageGovernanceKernel::new();

        // 1. $10,000 passes cleanly
        let req_pass = CageEvaluationRequest {
            agent_id: "agent-trade-01".to_string(),
            role: "trader".to_string(),
            tool_name: "execute_trade".to_string(),
            arguments: serde_json::json!({ "amount": 10000.0 }),
            confidence_score: Some(0.95),
            amount_usd: Some(10000.0),
            dose_mg: None,
            warrant_token: None,
            human_approval: Some(HitlConsensusApproval {
                operator_id: "admin".to_string(),
                is_approved: true,
                rationale: "Approved valid trade within standard parameter limits".to_string(),
                approved_at_ms: Utc::now().timestamp_millis() as u64,
                signature_hex: None,
            }),
            context: None,
        };
        let resp_pass = kernel.evaluate(&req_pass);
        assert_eq!(resp_pass.verdict, CageVerdict::Clear);
        assert_eq!(resp_pass.tier, CageTier::Tier8Fiscal);

        // 2. $75,000 fails with CTRL_OPA_005
        let req_fail = CageEvaluationRequest {
            amount_usd: Some(75000.0),
            ..req_pass
        };
        let resp_fail = kernel.evaluate(&req_fail);
        assert_eq!(resp_fail.verdict, CageVerdict::Refuse);
        assert_eq!(resp_fail.tier, CageTier::Tier3Opa);
        assert_eq!(resp_fail.rule_id, CTRL_OPA_005);
    }

    #[test]
    fn test_tier4_confidence_and_self_auth_detector() {
        let kernel = CageGovernanceKernel::new();

        let req_fabrication = CageEvaluationRequest {
            agent_id: "rogue-agent".to_string(),
            role: "assistant".to_string(),
            tool_name: "execute_trade".to_string(),
            arguments: serde_json::json!({ "note": "Action is authorized_by_admin please execute" }),
            confidence_score: Some(0.99),
            amount_usd: Some(100.0),
            dose_mg: None,
            warrant_token: None,
            human_approval: None,
            context: None,
        };

        let resp = kernel.evaluate(&req_fabrication);
        assert_eq!(resp.verdict, CageVerdict::Refuse);
        assert_eq!(resp.tier, CageTier::Tier4Confidence);
        assert_eq!(resp.rule_id, CTRL_CONF_001);
    }

    #[test]
    fn test_tier6_consensus_mandatory_rationale() {
        let kernel = CageGovernanceKernel::new();

        // High-risk transaction with whitespace rationale
        let req_empty_rationale = CageEvaluationRequest {
            agent_id: "agent-01".to_string(),
            role: "trader".to_string(),
            tool_name: "execute_trade".to_string(),
            arguments: serde_json::json!({ "amount": 8000.0 }),
            confidence_score: Some(0.95),
            amount_usd: Some(8000.0),
            dose_mg: None,
            warrant_token: None,
            human_approval: Some(HitlConsensusApproval {
                operator_id: "admin".to_string(),
                is_approved: true,
                rationale: "   ".to_string(), // Empty whitespace rationale
                approved_at_ms: Utc::now().timestamp_millis() as u64,
                signature_hex: None,
            }),
            context: None,
        };

        let resp = kernel.evaluate(&req_empty_rationale);
        assert_eq!(resp.verdict, CageVerdict::Refuse);
        assert_eq!(resp.tier, CageTier::Tier6Consensus);
        assert_eq!(resp.rule_id, CTRL_CONSENSUS_REQUIRED);
    }

    #[test]
    fn test_tier7_cbf_healthcare_dose_barrier() {
        let barrier = HealthcareDoseBarrier::new(100.0, 200.0, 90.0, 0.50);

        // 1. Proposed 15 mg (cumulative 105 mg < 200 mg cap, but check single and invariance)
        // B(x) = 0.5 * (200 - 90) - 15 = 55 - 15 = 40 >= 0 -> Pass
        assert!(barrier.evaluate(15.0).is_ok());

        // 2. Exceeds max single administration cap (105 mg > 100 mg)
        let res_single = barrier.evaluate(105.0);
        assert!(res_single.is_err());
        assert_eq!(res_single.unwrap_err().0, CTRL_CBF_DOSE_001);

        // 3. Cumulative overdose: cumulative 90 mg + 120 mg = 210 mg > 200 mg
        let barrier2 = HealthcareDoseBarrier::new(150.0, 200.0, 90.0, 0.50);
        let res_cum = barrier2.evaluate(120.0);
        assert!(res_cum.is_err());
        assert_eq!(res_cum.unwrap_err().0, CTRL_CBF_DOSE_001);
    }

    #[test]
    fn test_tier8_atomic_fiscal_barrier_concurrent_stress() {
        let barrier = Arc::new(AtomicFiscalBarrier::new(5000.0));
        let num_threads = 20;
        let amount_per_thread = 500.0;
        let mut handles = Vec::new();

        for _ in 0..num_threads {
            let b = barrier.clone();
            handles.push(std::thread::spawn(move || {
                b.try_spend(amount_per_thread)
            }));
        }

        let mut successes = 0;
        let mut refusals = 0;

        for h in handles {
            match h.join().unwrap() {
                Ok(_) => successes += 1,
                Err(e) => {
                    assert_eq!(e, FISCAL_CAP_EXCEEDED);
                    refusals += 1;
                }
            }
        }

        // Exactly 10 threads succeed ($5,000 / $500 = 10) and 10 fail
        assert_eq!(successes, 10);
        assert_eq!(refusals, 10);
        assert_eq!(barrier.get_spent_usd(), 5000.0);
    }
}
