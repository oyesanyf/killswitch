//! # Inline Synchronous Agent Hooks & Wire Format Interception Engine
//!
//! Provides zero-latency (<1ms) inline pre-execution and post-execution interception
//! for AI coding agents (Claude Code, Cursor, GitHub Copilot, OpenCode, and MCP stdio tools)
//! eliminating the blind spots of voluntary reporting and interval polling.
//!
//! ## 6-Layer Synchronous In-Memory Pipeline:
//! 1. `SemanticCommandAst` (privilege escalation AST/flag parsing)
//! 2. `DynamicBinaryMetadataProbe` (SUID/SGID, Linux capabilities, Windows requireAdministrator)
//! 3. `SemanticDlpEngine` (character/span-level entity and PHI/PII classification)
//! 4. `TemporalCircumventionCorrelator` (Incident A sliding-window circumvention memory)
//! 5. `ApcPolicyDecisionPoint` (Bounded Agents APC action class gating)
//! 6. `CageGovernanceKernel` (CAGE 8-tier formal invariant verification)

use std::collections::VecDeque;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::bounded_agents_apc::classify_action_class;
use crate::cage_governance::{global_cage_kernel, CageEvaluationRequest, CageVerdict};
use crate::circumvention::{
    is_cross_boundary_invocation, DynamicDenialSignal, TemporalCircumventionCorrelator,
};
use crate::semantic_command::{
    parse_semantic_command, DynamicBinaryMetadataProbe, PrivilegeEquivalenceClass,
};
use crate::semantic_dlp::SemanticDlpEngine;

/// Capacity for in-memory ring buffer of agent interception events.
pub const AGENT_INTERCEPTION_CAPACITY: usize = 1024;

/// Global shared temporal circumvention correlator for hook-observed denials.
pub static GLOBAL_CORRELATOR: LazyLock<TemporalCircumventionCorrelator> =
    LazyLock::new(|| TemporalCircumventionCorrelator::new(Duration::from_secs(60)));

// ============================================================================
// Data Structures
// ============================================================================

/// Supported AI coding agent runtime kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SupportedAgentKind {
    Claude,
    Cursor,
    Copilot,
    OpenCode,
    Mcp,
}

impl SupportedAgentKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Cursor => "cursor",
            Self::Copilot => "copilot",
            Self::OpenCode => "opencode",
            Self::Mcp => "mcp",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "claude" | "claudecode" | "claude-code" => Some(Self::Claude),
            "cursor" => Some(Self::Cursor),
            "copilot" | "github-copilot" => Some(Self::Copilot),
            "opencode" => Some(Self::OpenCode),
            "mcp" | "mcp-proxy" => Some(Self::Mcp),
            _ => None,
        }
    }
}

impl fmt::Display for SupportedAgentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Agent lifecycle event type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookEventType {
    PreToolUse,
    PostToolUse,
    BeforeShellExecution,
    AfterShellExecution,
    BeforeMCPExecution,
    BeforeReadFile,
    Custom(String),
}

impl HookEventType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::PreToolUse => "PreToolUse",
            Self::PostToolUse => "PostToolUse",
            Self::BeforeShellExecution => "beforeShellExecution",
            Self::AfterShellExecution => "afterShellExecution",
            Self::BeforeMCPExecution => "beforeMCPExecution",
            Self::BeforeReadFile => "beforeReadFile",
            Self::Custom(s) => s.as_str(),
        }
    }

    pub fn is_post(&self) -> bool {
        matches!(self, Self::PostToolUse | Self::AfterShellExecution)
    }

    pub fn from_name(name: &str) -> Self {
        match name.trim() {
            "PreToolUse" | "preToolUse" | "pre" => Self::PreToolUse,
            "PostToolUse" | "postToolUse" | "post" => Self::PostToolUse,
            "beforeShellExecution" => Self::BeforeShellExecution,
            "afterShellExecution" => Self::AfterShellExecution,
            "beforeMCPExecution" => Self::BeforeMCPExecution,
            "beforeReadFile" => Self::BeforeReadFile,
            other => Self::Custom(other.to_string()),
        }
    }
}

/// Canonical normalized hook request across all agent wire formats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedHookRequest {
    pub agent: SupportedAgentKind,
    pub event_type: HookEventType,
    pub tool_name: Option<String>,
    pub command: Option<String>,
    pub file_path: Option<String>,
    pub arguments: Option<serde_json::Value>,
    pub exit_code: Option<i32>,
    pub stderr: Option<String>,
    pub cwd: Option<String>,
    pub session_id: Option<String>,
    #[serde(default)]
    pub rpc_id: Option<serde_json::Value>,
}

impl Default for NormalizedHookRequest {
    fn default() -> Self {
        Self {
            agent: SupportedAgentKind::Claude,
            event_type: HookEventType::PreToolUse,
            tool_name: None,
            command: None,
            file_path: None,
            arguments: None,
            exit_code: None,
            stderr: None,
            cwd: None,
            session_id: None,
            rpc_id: None,
        }
    }
}

/// Synchronous evaluation decision returned to agent wire format adapters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookEvaluationDecision {
    pub allowed: bool,
    pub rationale: String,
    pub denied_by_layer: Option<String>,
    pub remediation: Option<String>,
    pub execution_duration_us: u64,
}

impl HookEvaluationDecision {
    pub fn allow(rationale: impl Into<String>, duration_us: u64) -> Self {
        Self {
            allowed: true,
            rationale: rationale.into(),
            denied_by_layer: None,
            remediation: None,
            execution_duration_us: duration_us,
        }
    }

    pub fn deny(
        rationale: impl Into<String>,
        denied_by_layer: Option<&str>,
        remediation: Option<&str>,
        duration_us: u64,
    ) -> Self {
        Self {
            allowed: false,
            rationale: rationale.into(),
            denied_by_layer: denied_by_layer.map(|s| s.to_string()),
            remediation: remediation.map(|s| s.to_string()),
            execution_duration_us: duration_us,
        }
    }
}

/// Persistent record of an interception stored in the in-memory ring buffer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInterceptionRecord {
    pub event_id: String,
    pub timestamp_ns: u64,
    pub timestamp_utc: String,
    pub agent: String,
    pub event_type: String,
    pub tool_name: String,
    pub command: String,
    pub allowed: bool,
    pub rationale: String,
    pub denied_by_layer: Option<String>,
}

// ============================================================================
// Ring Buffer for Siquery & EDR Visibility
// ============================================================================

pub static AGENT_INTERCEPTION_EVENTS: LazyLock<RwLock<VecDeque<AgentInterceptionRecord>>> =
    LazyLock::new(|| RwLock::new(VecDeque::with_capacity(AGENT_INTERCEPTION_CAPACITY)));

static EVENT_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Records an interception record into the global ring buffer (FIFO eviction).
pub fn record_interception_event(record: AgentInterceptionRecord) {
    let mut buf = AGENT_INTERCEPTION_EVENTS.write();
    while buf.len() >= AGENT_INTERCEPTION_CAPACITY {
        buf.pop_front();
    }
    buf.push_back(record);
}

/// Retrieves the most recent `limit` records in reverse-chronological order.
pub fn get_recent_interceptions(limit: usize) -> Vec<AgentInterceptionRecord> {
    AGENT_INTERCEPTION_EVENTS
        .read()
        .iter()
        .rev()
        .take(limit)
        .cloned()
        .collect()
}

/// Returns a full snapshot of all current interception records.
pub fn snapshot_interceptions() -> Vec<AgentInterceptionRecord> {
    AGENT_INTERCEPTION_EVENTS.read().iter().cloned().collect()
}

/// Clears all interception records from the ring buffer.
pub fn clear_interceptions() {
    AGENT_INTERCEPTION_EVENTS.write().clear();
}

// ============================================================================
// Wire Format Parsers
// ============================================================================

/// Extracts tool name matching canonical synonyms: `tool_name`, `name`, `tool`.
pub fn extract_wire_tool_name(val: &serde_json::Value) -> Option<String> {
    val.get("tool_name")
        .or_else(|| val.get("name"))
        .or_else(|| val.get("tool"))
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Extracts tool arguments / parameter object matching canonical synonyms:
/// `arguments`, `tool_input`, `args`, `parameters`, `input`.
pub fn extract_wire_arguments(val: &serde_json::Value) -> Option<serde_json::Value> {
    val.get("arguments")
        .or_else(|| val.get("tool_input"))
        .or_else(|| val.get("args"))
        .or_else(|| val.get("parameters"))
        .or_else(|| val.get("input"))
        .cloned()
}

/// Extracts tool response object matching canonical synonyms:
/// `tool_response`, `result`, `output`, `content`.
pub fn extract_wire_tool_response(val: &serde_json::Value) -> Option<&serde_json::Value> {
    val.get("tool_response")
        .or_else(|| val.get("result"))
        .or_else(|| val.get("output"))
        .or_else(|| val.get("content"))
}

/// Extracts command string matching canonical synonyms: `command`, `cmd`.
/// Supports both string literals and token arrays (`["bash", "-c", ...]`).
pub fn extract_wire_command(val: &serde_json::Value) -> Option<String> {
    let field = val.get("command").or_else(|| val.get("cmd"));
    if let Some(f) = field {
        if let Some(s) = f.as_str() {
            return Some(s.to_string());
        }
        if let Some(arr) = f.as_array() {
            let parts: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
            if !parts.is_empty() {
                return Some(parts.join(" "));
            }
        }
    }
    None
}

/// Extracts file path matching canonical synonyms: `file_path`, `path`, `filePath`, `uri`.
pub fn extract_wire_file_path(val: &serde_json::Value) -> Option<String> {
    val.get("file_path")
        .or_else(|| val.get("path"))
        .or_else(|| val.get("filePath"))
        .or_else(|| val.get("uri"))
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Extracts session ID matching canonical synonyms:
/// `session_id`, `sessionId`, `conversation_id`, `cursor_trace_id`.
pub fn extract_wire_session_id(val: &serde_json::Value) -> Option<String> {
    val.get("session_id")
        .or_else(|| val.get("sessionId"))
        .or_else(|| val.get("conversation_id"))
        .or_else(|| val.get("cursor_trace_id"))
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Extracts exit code matching canonical synonyms: `exit_code`, `exitCode`.
pub fn extract_wire_exit_code(val: &serde_json::Value) -> Option<i32> {
    val.get("exit_code")
        .or_else(|| val.get("exitCode"))
        .and_then(|v| v.as_i64())
        .map(|i| i as i32)
}

/// Extracts stderr or error message string matching: `stderr`, `error`.
pub fn extract_wire_stderr(val: &serde_json::Value) -> Option<String> {
    val.get("stderr")
        .or_else(|| val.get("error"))
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Extracts working directory matching canonical synonyms: `cwd`, `working_dir`, `workingDirectory`.
pub fn extract_wire_cwd(val: &serde_json::Value) -> Option<String> {
    val.get("cwd")
        .or_else(|| val.get("working_dir"))
        .or_else(|| val.get("workingDirectory"))
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Parses Claude Code `.claude/settings.json` hook payload from JSON on stdin.
pub fn parse_claude_request(raw_json: &str, is_post: bool) -> Result<NormalizedHookRequest, String> {
    let val: serde_json::Value = serde_json::from_str(raw_json)
        .map_err(|e| format!("Invalid Claude Code hook JSON: {e}"))?;

    let tool_name = extract_wire_tool_name(&val);
    let arguments = extract_wire_arguments(&val);
    let command = arguments
        .as_ref()
        .and_then(extract_wire_command)
        .or_else(|| extract_wire_command(&val));
    let file_path = arguments
        .as_ref()
        .and_then(extract_wire_file_path)
        .or_else(|| extract_wire_file_path(&val));

    let tool_resp = extract_wire_tool_response(&val);
    let exit_code = tool_resp
        .and_then(extract_wire_exit_code)
        .or_else(|| extract_wire_exit_code(&val));
    let stderr = tool_resp
        .and_then(extract_wire_stderr)
        .or_else(|| extract_wire_stderr(&val));

    let cwd = extract_wire_cwd(&val)
        .or_else(|| arguments.as_ref().and_then(extract_wire_cwd));
    let session_id = extract_wire_session_id(&val);

    Ok(NormalizedHookRequest {
        agent: SupportedAgentKind::Claude,
        event_type: if is_post {
            HookEventType::PostToolUse
        } else {
            HookEventType::PreToolUse
        },
        tool_name,
        command,
        file_path,
        arguments,
        exit_code,
        stderr,
        cwd,
        session_id,
        rpc_id: None,
    })
}

/// Parses Cursor `.cursor/hooks.json` payload.
pub fn parse_cursor_request(raw_json: &str, event_name: &str) -> Result<NormalizedHookRequest, String> {
    let val: serde_json::Value = serde_json::from_str(raw_json)
        .map_err(|e| format!("Invalid Cursor hook JSON: {e}"))?;

    let event_type = HookEventType::from_name(event_name);
    let tool_name = extract_wire_tool_name(&val);
    let arguments = extract_wire_arguments(&val);
    let command = extract_wire_command(&val)
        .or_else(|| arguments.as_ref().and_then(extract_wire_command));
    let file_path = extract_wire_file_path(&val)
        .or_else(|| arguments.as_ref().and_then(extract_wire_file_path));

    let tool_resp = extract_wire_tool_response(&val);
    let exit_code = tool_resp
        .and_then(extract_wire_exit_code)
        .or_else(|| extract_wire_exit_code(&val));
    let stderr = tool_resp
        .and_then(extract_wire_stderr)
        .or_else(|| extract_wire_stderr(&val));

    let cwd = extract_wire_cwd(&val)
        .or_else(|| arguments.as_ref().and_then(extract_wire_cwd));
    let session_id = extract_wire_session_id(&val);

    Ok(NormalizedHookRequest {
        agent: SupportedAgentKind::Cursor,
        event_type,
        tool_name,
        command,
        file_path,
        arguments,
        exit_code,
        stderr,
        cwd,
        session_id,
        rpc_id: None,
    })
}

/// Parses GitHub Copilot `.github/hooks/killswitch.json` payload.
pub fn parse_copilot_request(raw_json: &str, event_name: &str) -> Result<NormalizedHookRequest, String> {
    let val: serde_json::Value = serde_json::from_str(raw_json)
        .map_err(|e| format!("Invalid GitHub Copilot hook JSON: {e}"))?;

    let event_type = HookEventType::from_name(event_name);
    let tool_name = extract_wire_tool_name(&val);
    let arguments = extract_wire_arguments(&val);
    let command = arguments
        .as_ref()
        .and_then(extract_wire_command)
        .or_else(|| extract_wire_command(&val));
    let file_path = arguments
        .as_ref()
        .and_then(extract_wire_file_path)
        .or_else(|| extract_wire_file_path(&val));

    let tool_resp = extract_wire_tool_response(&val);
    let exit_code = tool_resp
        .and_then(extract_wire_exit_code)
        .or_else(|| extract_wire_exit_code(&val));
    let stderr = tool_resp
        .and_then(extract_wire_stderr)
        .or_else(|| extract_wire_stderr(&val));

    let cwd = extract_wire_cwd(&val)
        .or_else(|| arguments.as_ref().and_then(extract_wire_cwd));
    let session_id = extract_wire_session_id(&val);

    Ok(NormalizedHookRequest {
        agent: SupportedAgentKind::Copilot,
        event_type,
        tool_name,
        command,
        file_path,
        arguments,
        exit_code,
        stderr,
        cwd,
        session_id,
        rpc_id: None,
    })
}

/// Parses OpenCode plugin payload.
pub fn parse_opencode_request(raw_json: &str) -> Result<NormalizedHookRequest, String> {
    let val: serde_json::Value = serde_json::from_str(raw_json)
        .map_err(|e| format!("Invalid OpenCode hook JSON: {e}"))?;

    let typ = val.get("type").and_then(|v| v.as_str()).unwrap_or("before");
    let event_type = if typ.eq_ignore_ascii_case("after") || typ.eq_ignore_ascii_case("post") {
        HookEventType::PostToolUse
    } else {
        HookEventType::PreToolUse
    };

    let tool_name = extract_wire_tool_name(&val);
    let arguments = extract_wire_arguments(&val);
    let command = arguments
        .as_ref()
        .and_then(extract_wire_command)
        .or_else(|| extract_wire_command(&val));
    let file_path = arguments
        .as_ref()
        .and_then(extract_wire_file_path)
        .or_else(|| extract_wire_file_path(&val));

    let tool_resp = extract_wire_tool_response(&val);
    let exit_code = tool_resp
        .and_then(extract_wire_exit_code)
        .or_else(|| extract_wire_exit_code(&val));
    let stderr = tool_resp
        .and_then(extract_wire_stderr)
        .or_else(|| extract_wire_stderr(&val));

    let cwd = extract_wire_cwd(&val)
        .or_else(|| arguments.as_ref().and_then(extract_wire_cwd));
    let session_id = extract_wire_session_id(&val);

    Ok(NormalizedHookRequest {
        agent: SupportedAgentKind::OpenCode,
        event_type,
        tool_name,
        command,
        file_path,
        arguments,
        exit_code,
        stderr,
        cwd,
        session_id,
        rpc_id: None,
    })
}

/// Parses MCP `tools/call` JSON-RPC line.
pub fn parse_mcp_call_request(raw_json: &str) -> Result<NormalizedHookRequest, String> {
    let val: serde_json::Value = serde_json::from_str(raw_json)
        .map_err(|e| format!("Invalid MCP JSON-RPC: {e}"))?;

    let method = val.get("method").and_then(|v| v.as_str()).unwrap_or("");
    if method != "tools/call" {
        return Err("Not a tools/call method".to_string());
    }

    let rpc_id = val.get("id").cloned();
    let params = val.get("params").cloned().unwrap_or(serde_json::Value::Null);

    let tool_name = extract_wire_tool_name(&params)
        .or_else(|| extract_wire_tool_name(&val));
    let arguments = extract_wire_arguments(&params)
        .or_else(|| extract_wire_arguments(&val));

    let command = arguments
        .as_ref()
        .and_then(extract_wire_command)
        .or_else(|| extract_wire_command(&params))
        .or_else(|| extract_wire_command(&val));
    let file_path = arguments
        .as_ref()
        .and_then(extract_wire_file_path)
        .or_else(|| extract_wire_file_path(&params))
        .or_else(|| extract_wire_file_path(&val));

    let cwd = extract_wire_cwd(&params)
        .or_else(|| extract_wire_cwd(&val))
        .or_else(|| arguments.as_ref().and_then(extract_wire_cwd));
    let session_id = extract_wire_session_id(&params)
        .or_else(|| extract_wire_session_id(&val));

    Ok(NormalizedHookRequest {
        agent: SupportedAgentKind::Mcp,
        event_type: HookEventType::BeforeMCPExecution,
        tool_name,
        command,
        file_path,
        arguments,
        exit_code: None,
        stderr: None,
        cwd,
        session_id,
        rpc_id,
    })
}

// ============================================================================
// Wire Format Formatters
// ============================================================================

/// Formats Claude Code response: exit code `0` on allow, exit code `2` with stderr rationale on deny.
pub fn format_claude_response(decision: &HookEvaluationDecision) -> (i32, String) {
    if decision.allowed {
        (0, String::new())
    } else {
        (2, format!("KillSwitch Hook Policy Denied: {}\n", decision.rationale))
    }
}

/// Formats Cursor response: JSON on stdout with `permission: "allow" | "deny"`.
pub fn format_cursor_response(decision: &HookEvaluationDecision) -> (i32, String) {
    let obj = if decision.allowed {
        serde_json::json!({
            "permission": "allow",
            "user_message": "Authorized by KillSwitch PEP",
            "agent_message": ""
        })
    } else {
        serde_json::json!({
            "permission": "deny",
            "user_message": format!("KillSwitch Containment: {}", decision.rationale),
            "agent_message": decision.rationale
        })
    };
    (0, obj.to_string())
}

/// Formats GitHub Copilot response: JSON on stdout with `permissionDecision: "allow" | "deny"`.
pub fn format_copilot_response(decision: &HookEvaluationDecision) -> (i32, String) {
    let obj = if decision.allowed {
        serde_json::json!({
            "permissionDecision": "allow",
            "permissionDecisionReason": "KillSwitch cleared execution"
        })
    } else {
        serde_json::json!({
            "permissionDecision": "deny",
            "permissionDecisionReason": format!("KillSwitch Policy Violation: {}", decision.rationale)
        })
    };
    (0, obj.to_string())
}

/// Formats OpenCode response: JSON on stdout with `allow: true | false`.
pub fn format_opencode_response(decision: &HookEvaluationDecision) -> (i32, String) {
    let obj = if decision.allowed {
        serde_json::json!({
            "allow": true,
            "reason": "KillSwitch cleared execution"
        })
    } else {
        serde_json::json!({
            "allow": false,
            "reason": format!("KillSwitch Policy Violation: {}", decision.rationale)
        })
    };
    (0, obj.to_string())
}

/// Formats MCP JSON-RPC response for `tools/call` compliant with JSON-RPC 2.0 §5.1 and MCP CallToolResult.
pub fn format_mcp_error_response(id: &serde_json::Value, decision: &HookEvaluationDecision) -> String {
    let mut error_obj = serde_json::json!({
        "code": -32000,
        "message": format!("KillSwitch Policy Violation: {}", decision.rationale)
    });

    if decision.denied_by_layer.is_some() || decision.remediation.is_some() {
        error_obj["data"] = serde_json::json!({
            "denied_by_layer": decision.denied_by_layer.as_deref().unwrap_or("Unknown"),
            "suggested_remediation": decision.remediation.as_deref().unwrap_or("None"),
        });
    }

    let resp = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": error_obj,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": format!("KillSwitch Policy Violation: {}", decision.rationale)
                }
            ],
            "isError": true
        }
    });
    resp.to_string()
}

// ============================================================================
// 6-Layer Zero-Latency Synchronous In-Memory Evaluation Pipeline
// ============================================================================

/// Evaluates a normalized hook request synchronously through the 6-layer in-memory pipeline.
pub fn evaluate_hook_synchronously(req: &NormalizedHookRequest) -> HookEvaluationDecision {
    let start_instant = Instant::now();
    let session_id = req.session_id.as_deref().unwrap_or("agent-session-default");

    // ------------------------------------------------------------------------
    // Post-Execution Handling (Capture dynamic denials for Incident A memory)
    // ------------------------------------------------------------------------
    if req.event_type.is_post() {
        let is_denial = req.exit_code.map(|c| c != 0).unwrap_or(false)
            || req
                .stderr
                .as_ref()
                .map(|e| {
                    let l = e.to_ascii_lowercase();
                    l.contains("password is required")
                        || l.contains("permission denied")
                        || l.contains("eacces")
                        || l.contains("eperm")
                        || l.contains("access denied")
                })
                .unwrap_or(false);

        if is_denial {
            let cmd_str = req.command.as_deref().unwrap_or("unknown_command");
            let sem = parse_semantic_command(cmd_str);
            let signal = DynamicDenialSignal::new(
                format!("denial-{}", EVENT_COUNTER.fetch_add(1, Ordering::SeqCst)),
                session_id,
                None,
                std::process::id(),
                cmd_str,
                sem.privilege_class,
                req.exit_code,
                true,
                req.stderr.clone(),
                Instant::now(),
            );
            GLOBAL_CORRELATOR.record_denial(signal);
            debug!("PostToolUse recorded dynamic denial for Incident A memory");
        }

        let duration_us = start_instant.elapsed().as_micros() as u64;
        let decision = HookEvaluationDecision::allow("PostToolUse completed and recorded", duration_us);
        record_decision(req, &decision);
        return decision;
    }

    // ------------------------------------------------------------------------
    // PreToolUse Guard: Sensitive System Path & Credential Store Interception
    // ------------------------------------------------------------------------
    let mut detected_sensitive_store: Option<(crate::sensitive_paths::SensitiveCredentialStoreKind, String)> = None;

    if let Some(path) = &req.file_path {
        if let Some(kind) = crate::sensitive_paths::classify_sensitive_system_path(path) {
            detected_sensitive_store = Some((kind, path.clone()));
        } else if let Some(found) = crate::sensitive_paths::scan_for_sensitive_system_path(path) {
            detected_sensitive_store = Some(found);
        }
    }

    if detected_sensitive_store.is_none() {
        if let Some(args) = &req.arguments {
            if let Some(found) = crate::sensitive_paths::scan_json_for_sensitive_path(args) {
                detected_sensitive_store = Some(found);
            }
        }
    }

    if detected_sensitive_store.is_none() {
        if let Some(cmd) = &req.command {
            if let Some(found) = crate::sensitive_paths::scan_for_sensitive_system_path(cmd) {
                detected_sensitive_store = Some(found);
            }
        }
    }

    if let Some((store_kind, matched_path)) = detected_sensitive_store {
        let duration_us = start_instant.elapsed().as_micros() as u64;
        let decision = HookEvaluationDecision::deny(
            format!(
                "Access to sensitive system credential store blocked: {} ('{}')",
                store_kind.description(),
                matched_path
            ),
            Some("SensitiveSystemPathGuard"),
            Some("Access to root credential databases (/etc/shadow, SAM, SYSTEM) is strictly forbidden"),
            duration_us,
        );
        record_decision(req, &decision);
        return decision;
    }

    // ------------------------------------------------------------------------
    // Layer 1: SemanticCommandAst (Structural privilege escalation AST parsing)
    // ------------------------------------------------------------------------
    if let Some(cmd) = &req.command {
        let sem = parse_semantic_command(cmd);
        if sem.privilege_class == PrivilegeEquivalenceClass::RootOrAdminElevation
            || sem.privilege_class == PrivilegeEquivalenceClass::TargetUserDelegation
        {
            let duration_us = start_instant.elapsed().as_micros() as u64;
            let decision = HookEvaluationDecision::deny(
                format!("Privileged command elevation rejected: '{cmd}'"),
                Some("Layer 1: SemanticCommandAst"),
                Some("Execute unprivileged commands or obtain signed authorization"),
                duration_us,
            );
            record_decision(req, &decision);
            return decision;
        }
    }

    // ------------------------------------------------------------------------
    // Layer 2: DynamicBinaryMetadataProbe (On-disk SUID/SGID/Capabilities/PE)
    // ------------------------------------------------------------------------
    if let Some(cmd) = &req.command {
        let tokens = crate::semantic_command::tokenize_command(cmd);
        if let Some(first) = tokens.first() {
            let target_path = Path::new(first);
            if target_path.exists() {
                if let Ok(probe) = DynamicBinaryMetadataProbe::probe_path(target_path) {
                    if probe.is_privileged_target() {
                        let duration_us = start_instant.elapsed().as_micros() as u64;
                        let decision = HookEvaluationDecision::deny(
                            format!("Target binary on disk requires administrator privileges: '{}'", target_path.display()),
                            Some("Layer 2: DynamicBinaryMetadataProbe"),
                            Some("Target unprivileged binaries"),
                            duration_us,
                        );
                        record_decision(req, &decision);
                        return decision;
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------------
    // Layer 3: SemanticDlpEngine (Structured entity and PHI/PII classification)
    // ------------------------------------------------------------------------
    let mut payload_to_inspect = String::new();
    if let Some(cmd) = &req.command {
        payload_to_inspect.push_str(cmd);
        payload_to_inspect.push(' ');
    }
    if let Some(path) = &req.file_path {
        payload_to_inspect.push_str(path);
        payload_to_inspect.push(' ');
    }
    if let Some(args) = &req.arguments {
        // Expand compact JSON with space boundaries around structural delimiters to prevent tokenization evasion
        let s = args.to_string();
        for ch in s.chars() {
            if ch == '{' || ch == '}' || ch == '[' || ch == ']' || ch == ':' || ch == ',' || ch == '"' {
                payload_to_inspect.push(' ');
                payload_to_inspect.push(ch);
                payload_to_inspect.push(' ');
            } else {
                payload_to_inspect.push(ch);
            }
        }
    }

    if !payload_to_inspect.trim().is_empty() {
        let dlp = SemanticDlpEngine::default();
        let verdict = dlp.evaluate_verdict_fail_closed(&payload_to_inspect);
        if !verdict.is_allow() {
            let duration_us = start_instant.elapsed().as_micros() as u64;
            let decision = HookEvaluationDecision::deny(
                format!("Sensitive data or PHI/PII entity detected: {:?}", verdict.entities()),
                Some("Layer 3: SemanticDlpEngine"),
                Some("Scrub sensitive records before tool execution"),
                duration_us,
            );
            record_decision(req, &decision);
            return decision;
        }
    }

    // ------------------------------------------------------------------------
    // Layer 4: TemporalCircumventionCorrelator (Incident A circumvention memory)
    // ------------------------------------------------------------------------
    if let Some(cmd) = &req.command {
        let now = Instant::now();
        if let Some(alert) = GLOBAL_CORRELATOR.check_candidate(session_id, None, cmd, now) {
            let duration_us = start_instant.elapsed().as_micros() as u64;
            let decision = HookEvaluationDecision::deny(
                alert.summary,
                Some("Layer 4: TemporalCircumventionCorrelator"),
                Some("Incident A cross-boundary circumvention attempt blocked"),
                duration_us,
            );
            record_decision(req, &decision);
            return decision;
        }

        let sem = parse_semantic_command(cmd);
        // Cross-boundary without recent denial check
        if is_cross_boundary_invocation(cmd, &sem) && GLOBAL_CORRELATOR.active_denial_count() > 0 {
            let duration_us = start_instant.elapsed().as_micros() as u64;
            let decision = HookEvaluationDecision::deny(
                format!("Incident A cross-boundary execution denied: '{cmd}'"),
                Some("Layer 4: TemporalCircumventionCorrelator"),
                Some("Do not attempt cross-boundary retry"),
                duration_us,
            );
            record_decision(req, &decision);
            return decision;
        }
    }

    // ------------------------------------------------------------------------
    // Layer 5: ApcPolicyDecisionPoint (Bounded Agents APC action class gating)
    // ------------------------------------------------------------------------
    let action_candidate = req
        .command
        .as_deref()
        .or(req.tool_name.as_deref())
        .unwrap_or("READ_PUBLIC");
    let action_class = classify_action_class(action_candidate);
    if action_class == "PRIVILEGED_EXECUTION" {
        let duration_us = start_instant.elapsed().as_micros() as u64;
        let decision = HookEvaluationDecision::deny(
            format!("Bounded Agents APC Action Class 'PRIVILEGED_EXECUTION' blocked for '{action_candidate}'"),
            Some("Layer 5: ApcPolicyDecisionPoint"),
            Some("Action requires signed approval token envelope"),
            duration_us,
        );
        record_decision(req, &decision);
        return decision;
    }

    // ------------------------------------------------------------------------
    // Layer 6: CageGovernanceKernel (CAGE 8-tier safety rules)
    // ------------------------------------------------------------------------
    let cage = global_cage_kernel();
    let has_fiscal = req.arguments.as_ref().and_then(|a| a.get("amount_usd")).is_some();
    let has_dose = req.arguments.as_ref().and_then(|a| a.get("dose_mg")).is_some();
    let is_governed_tool = req.tool_name.as_ref().map(|t| cage.is_tool_governed(t)).unwrap_or(false);

    if has_fiscal || has_dose || is_governed_tool {
        let cage_req = CageEvaluationRequest {
            agent_id: req.agent.as_str().to_string(),
            role: "developer_agent".to_string(),
            tool_name: req.tool_name.clone().unwrap_or_else(|| "default_tool".to_string()),
            arguments: req.arguments.clone().unwrap_or(serde_json::Value::Null),
            confidence_score: Some(0.95),
            amount_usd: req.arguments.as_ref().and_then(|a| a.get("amount_usd")).and_then(|v| v.as_f64()),
            dose_mg: req.arguments.as_ref().and_then(|a| a.get("dose_mg")).and_then(|v| v.as_f64()),
            warrant_token: None,
            human_approval: None,
            context: None,
        };

        let cage_resp = cage.evaluate(&cage_req);
        if cage_resp.verdict == CageVerdict::Refuse {
            let duration_us = start_instant.elapsed().as_micros() as u64;
            let decision = HookEvaluationDecision::deny(
                format!("CAGE 8-tier governance kernel refused tool call: rule '{}'", cage_resp.rule_id),
                Some("Layer 6: CageGovernanceKernel"),
                Some("Verify CAGE contract invariants"),
                duration_us,
            );
            record_decision(req, &decision);
            return decision;
        }
    }

    // All 6 layers cleared
    let duration_us = start_instant.elapsed().as_micros() as u64;
    let decision = HookEvaluationDecision::allow(
        "Execution cleared all 6 KillSwitch security layers",
        duration_us,
    );
    record_decision(req, &decision);
    decision
}

/// Helper to record the interception decision in the ring buffer.
fn record_decision(req: &NormalizedHookRequest, decision: &HookEvaluationDecision) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let event_id = format!("intercept-{}", EVENT_COUNTER.fetch_add(1, Ordering::SeqCst));
    let record = AgentInterceptionRecord {
        event_id,
        timestamp_ns: now,
        timestamp_utc: chrono::Utc::now().to_rfc3339(),
        agent: req.agent.as_str().to_string(),
        event_type: req.event_type.as_str().to_string(),
        tool_name: req.tool_name.clone().unwrap_or_default(),
        command: req.command.clone().unwrap_or_default(),
        allowed: decision.allowed,
        rationale: decision.rationale.clone(),
        denied_by_layer: decision.denied_by_layer.clone(),
    };
    record_interception_event(record);
}

// ============================================================================
// Agent Hook Configuration Installer
// ============================================================================

/// Installs hook configurations across specified agent configuration files in a workspace.
pub fn install_agent_hooks(
    workspace: &Path,
    agents: &[SupportedAgentKind],
    killswitch_bin: &Path,
) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut installed_paths = Vec::new();
    let bin_path_str = killswitch_bin.to_string_lossy().into_owned();

    for agent in agents {
        match agent {
            SupportedAgentKind::Claude => {
                let dir = workspace.join(".claude");
                std::fs::create_dir_all(&dir)?;
                let file_path = dir.join("settings.json");
                let config = serde_json::json!({
                    "hooks": {
                        "PreToolUse": [
                            {
                                "matcher": ".*",
                                "command": format!("\"{}\" hook evaluate --agent claude", bin_path_str)
                            }
                        ],
                        "PostToolUse": [
                            {
                                "matcher": ".*",
                                "command": format!("\"{}\" hook evaluate --agent claude --post", bin_path_str)
                            }
                        ]
                    }
                });
                std::fs::write(&file_path, serde_json::to_string_pretty(&config)?)?;
                installed_paths.push(file_path);
            }
            SupportedAgentKind::Cursor => {
                let dir = workspace.join(".cursor");
                std::fs::create_dir_all(&dir)?;
                let file_path = dir.join("hooks.json");
                let config = serde_json::json!({
                    "version": 1,
                    "hooks": {
                        "beforeShellExecution": [
                            {
                                "command": format!("\"{}\" hook evaluate --agent cursor --event beforeShellExecution", bin_path_str)
                            }
                        ],
                        "afterShellExecution": [
                            {
                                "command": format!("\"{}\" hook evaluate --agent cursor --event afterShellExecution", bin_path_str)
                            }
                        ],
                        "beforeMCPExecution": [
                            {
                                "command": format!("\"{}\" hook evaluate --agent cursor --event beforeMCPExecution", bin_path_str)
                            }
                        ],
                        "beforeReadFile": [
                            {
                                "command": format!("\"{}\" hook evaluate --agent cursor --event beforeReadFile", bin_path_str)
                            }
                        ]
                    }
                });
                std::fs::write(&file_path, serde_json::to_string_pretty(&config)?)?;
                installed_paths.push(file_path);
            }
            SupportedAgentKind::Copilot => {
                let dir = workspace.join(".github").join("hooks");
                std::fs::create_dir_all(&dir)?;
                let file_path = dir.join("killswitch.json");
                let config = serde_json::json!({
                    "version": "1.0",
                    "hooks": {
                        "preToolUse": [
                            {
                                "type": "command",
                                "exec": format!("\"{}\" hook evaluate --agent copilot --event preToolUse", bin_path_str)
                            }
                        ],
                        "postToolUse": [
                            {
                                "type": "command",
                                "exec": format!("\"{}\" hook evaluate --agent copilot --event postToolUse", bin_path_str)
                            }
                        ]
                    }
                });
                std::fs::write(&file_path, serde_json::to_string_pretty(&config)?)?;
                installed_paths.push(file_path);
            }
            SupportedAgentKind::OpenCode => {
                let dir = workspace.join(".opencode").join("plugin");
                std::fs::create_dir_all(&dir)?;
                let file_path = dir.join("killswitch-guard.js");
                let script = format!(
                    r#"// OpenCode KillSwitch PEP Guard Plugin
const {{ execFileSync }} = require('child_process');

module.exports = {{
    name: 'killswitch-guard',
    onToolExecuteBefore(tool, args) {{
        const payload = JSON.stringify({{ tool, args, type: 'before' }});
        try {{
            const out = execFileSync('{bin}', ['hook', 'evaluate', '--agent', 'opencode'], {{
                input: payload,
                encoding: 'utf-8'
            }});
            const res = JSON.parse(out);
            if (!res.allow) {{
                throw new Error('KillSwitch PEP Denied: ' + res.reason);
            }}
        }} catch (err) {{
            throw new Error('KillSwitch Tool Execution Blocked: ' + err.message);
        }}
    }},
    onToolExecuteAfter(tool, args, result) {{
        const payload = JSON.stringify({{ tool, args, exit_code: result.exitCode, stderr: result.stderr, type: 'after' }});
        try {{
            execFileSync('{bin}', ['hook', 'evaluate', '--agent', 'opencode', '--post'], {{
                input: payload,
                encoding: 'utf-8'
            }});
        }} catch (_) {{}}
    }}
}};
"#,
                    bin = bin_path_str.replace('\\', "\\\\")
                );
                std::fs::write(&file_path, script)?;
                installed_paths.push(file_path);
            }
            SupportedAgentKind::Mcp => {
                // MCP is configured per-server via killswitch mcp-proxy wrapper
            }
        }
    }

    Ok(installed_paths)
}
