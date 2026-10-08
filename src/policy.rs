//! Policy evaluation — declarative policy manifest + run context → report.
//!
//! policy-gate is the "Policy" pillar of the agent kernel: mechanical,
//! declarative guardrails evaluated against a run's observations. The shape
//! is modeled after InstantDB's CEL permission system (parse-time
//! validation, explicit allow/deny, scoped rules) but P0 uses structured
//! rule kinds only — no free-form expression DSL (see
//! dsfolder/POLICY-GATE-DESIGN-2026-08-23.md).
//!
//! Purity: manifest + context → outcomes. No side effects. Evaluation
//! timing (pre/post run) is the caller's concern.
//!
//! Exit contract is owned by the CLI: 0 all pass · 1 any violation ·
//! 2 tool error (manifest/context parse, regex compile, engine bug).
//! The ledger carries evidence hashes only — matched secret text is never
//! written to the report detail or the ledger.

use std::collections::HashMap;
use std::fmt;

use serde::Deserialize;

use crate::check::Outcome;

// ---------------------------------------------------------------------------
// Run context (JSON, provided by the caller: DSH plugin / CI)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RunContext {
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub workspace: Option<String>,
    #[serde(default)]
    pub retries: HashMap<String, u64>,
    #[serde(default)]
    pub tool_calls: Vec<ToolCall>,
    #[serde(default)]
    pub outputs: Vec<ToolOutput>,
    #[serde(default)]
    pub cmd_lines: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolCall {
    pub name: String,
    /// Input-schema field (provenance for future rules); not read in P0.
    #[allow(dead_code)]
    #[serde(default)]
    pub args: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolOutput {
    pub tool: String,
    pub text: String,
}

// ---------------------------------------------------------------------------
// Policy manifest (TOML)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyManifest {
    pub meta: Option<PolicyMeta>,
    #[serde(default)]
    pub rule: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyMeta {
    pub name: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Scope {
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub workspace: Option<String>,
}

impl Scope {
    /// A rule whose scope does not match the context is `na`, never a failure.
    pub fn matches(&self, ctx: &RunContext) -> bool {
        if let Some(p) = &self.profile {
            if ctx.profile.as_deref() != Some(p.as_str()) {
                return false;
            }
        }
        if let Some(w) = &self.workspace {
            let hit = ctx
                .workspace
                .as_deref()
                .map(|ws| ws.contains(w.as_str()))
                .unwrap_or(false);
            if !hit {
                return false;
            }
        }
        true
    }
}

pub fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum Rule {
    #[serde(rename = "tool-denylist")]
    ToolDenylist(ToolDenylistRule),
    #[serde(rename = "tool-allowlist")]
    ToolAllowlist(ToolAllowlistRule),
    #[serde(rename = "output-regex-deny")]
    OutputRegexDeny(OutputRegexDenyRule),
    #[serde(rename = "tool-call-limit")]
    ToolCallLimit(ToolCallLimitRule),
    #[serde(rename = "retry-limit")]
    RetryLimit(RetryLimitRule),
    #[serde(rename = "cmd-deny")]
    CmdDeny(CmdDenyRule),
}

impl Rule {
    pub fn id(&self) -> &str {
        match self {
            Rule::ToolDenylist(r) => &r.id,
            Rule::ToolAllowlist(r) => &r.id,
            Rule::OutputRegexDeny(r) => &r.id,
            Rule::ToolCallLimit(r) => &r.id,
            Rule::RetryLimit(r) => &r.id,
            Rule::CmdDeny(r) => &r.id,
        }
    }

    pub fn enabled(&self) -> bool {
        match self {
            Rule::ToolDenylist(r) => r.enabled,
            Rule::ToolAllowlist(r) => r.enabled,
            Rule::OutputRegexDeny(r) => r.enabled,
            Rule::ToolCallLimit(r) => r.enabled,
            Rule::RetryLimit(r) => r.enabled,
            Rule::CmdDeny(r) => r.enabled,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Rule::ToolDenylist(_) => "tool-denylist",
            Rule::ToolAllowlist(_) => "tool-allowlist",
            Rule::OutputRegexDeny(_) => "output-regex-deny",
            Rule::ToolCallLimit(_) => "tool-call-limit",
            Rule::RetryLimit(_) => "retry-limit",
            Rule::CmdDeny(_) => "cmd-deny",
        }
    }

    pub fn scope(&self) -> &Scope {
        match self {
            Rule::ToolDenylist(r) => &r.scope,
            Rule::ToolAllowlist(r) => &r.scope,
            Rule::OutputRegexDeny(r) => &r.scope,
            Rule::ToolCallLimit(r) => &r.scope,
            Rule::RetryLimit(r) => &r.scope,
            Rule::CmdDeny(r) => &r.scope,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolDenylistRule {
    pub id: String,
    /// Human description; provenance only in P0.
    #[allow(dead_code)]
    #[serde(default)]
    pub desc: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub scope: Scope,
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolAllowlistRule {
    pub id: String,
    /// Human description; provenance only in P0.
    #[allow(dead_code)]
    #[serde(default)]
    pub desc: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub scope: Scope,
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OutputRegexDenyRule {
    pub id: String,
    /// Human description; provenance only in P0.
    #[allow(dead_code)]
    #[serde(default)]
    pub desc: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub scope: Scope,
    pub regex: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolCallLimitRule {
    pub id: String,
    /// Human description; provenance only in P0.
    #[allow(dead_code)]
    #[serde(default)]
    pub desc: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub scope: Scope,
    pub max: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RetryLimitRule {
    pub id: String,
    /// Human description; provenance only in P0.
    #[allow(dead_code)]
    #[serde(default)]
    pub desc: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub scope: Scope,
    pub field: String,
    pub max: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CmdDenyRule {
    pub id: String,
    /// Human description; provenance only in P0.
    #[allow(dead_code)]
    #[serde(default)]
    pub desc: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub scope: Scope,
    pub regex: String,
}

#[derive(Debug)]
pub struct PolicyError(pub String);

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Parse + structurally validate a policy manifest.
pub fn parse(text: &str) -> Result<PolicyManifest, PolicyError> {
    let manifest: PolicyManifest =
        toml::from_str(text).map_err(|e| PolicyError(format!("TOML parse error: {e}")))?;
    validate(&manifest)?;
    Ok(manifest)
}

fn validate(m: &PolicyManifest) -> Result<(), PolicyError> {
    if m.rule.is_empty() {
        return Err(PolicyError(
            "policy defines no rules (empty policy = false confidence)".into(),
        ));
    }
    for (i, rule) in m.rule.iter().enumerate() {
        let ctx = format!("rule[{}] \"{}\" ({})", i, rule.id(), rule.kind());
        if rule.id().trim().is_empty() {
            return Err(PolicyError(format!("{ctx}: id is required")));
        }
        match rule {
            Rule::ToolDenylist(r) => {
                if r.deny.is_empty() {
                    return Err(PolicyError(format!("{ctx}: deny list is empty")));
                }
                for t in &r.deny {
                    if t.trim().is_empty() {
                        return Err(PolicyError(format!("{ctx}: deny contains empty tool name")));
                    }
                }
            }
            Rule::ToolAllowlist(r) => {
                if r.allow.is_empty() {
                    return Err(PolicyError(format!("{ctx}: allow list is empty")));
                }
            }
            Rule::OutputRegexDeny(r) => {
                compile(&r.regex).map_err(|e| PolicyError(format!("{ctx}: invalid regex {e}")))?;
            }
            Rule::ToolCallLimit(r) => {
                if r.max == 0 {
                    return Err(PolicyError(format!("{ctx}: max must be > 0")));
                }
            }
            Rule::RetryLimit(r) => {
                if r.field.trim().is_empty() {
                    return Err(PolicyError(format!("{ctx}: field is required")));
                }
            }
            Rule::CmdDeny(r) => {
                compile(&r.regex).map_err(|e| PolicyError(format!("{ctx}: invalid regex {e}")))?;
            }
        }
    }
    Ok(())
}

fn compile(pat: &str) -> Result<regex::Regex, String> {
    regex::Regex::new(pat).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// Evaluate every rule against the context. Returns (index, id, kind, outcome).
/// `Err` is a tool error (regex compile, engine bug) → exit 2.
pub fn evaluate(
    manifest: &PolicyManifest,
    ctx: &RunContext,
) -> Result<Vec<(usize, String, String, Outcome)>, String> {
    let mut results = Vec::with_capacity(manifest.rule.len());
    for (index, rule) in manifest.rule.iter().enumerate() {
        let id = rule.id().to_string();
        let kind = rule.kind().to_string();
        let outcome = if !rule.enabled() {
            Outcome::na("disabled", 0)
        } else if !rule.scope().matches(ctx) {
            Outcome::na(
                format!(
                    "scope mismatch (profile={:?} workspace={:?})",
                    ctx.profile, ctx.workspace
                ),
                0,
            )
        } else {
            eval_rule(rule, ctx)?
        };
        results.push((index, id, kind, outcome));
    }
    Ok(results)
}

fn eval_rule(rule: &Rule, ctx: &RunContext) -> Result<Outcome, String> {
    let out = match rule {
        Rule::ToolDenylist(r) => {
            let hits: Vec<&str> = ctx
                .tool_calls
                .iter()
                .filter(|t| r.deny.iter().any(|d| d == &t.name))
                .map(|t| t.name.as_str())
                .collect();
            if hits.is_empty() {
                Outcome::pass("no denied tools called", 0)
            } else {
                Outcome::fail(format!("denied tool(s) called: {}", hits.join(", ")), 0)
            }
        }
        Rule::ToolAllowlist(r) => {
            let off: Vec<&str> = ctx
                .tool_calls
                .iter()
                .filter(|t| !r.allow.iter().any(|a| a == &t.name))
                .map(|t| t.name.as_str())
                .collect();
            if off.is_empty() {
                Outcome::pass("only allowed tools called", 0)
            } else {
                Outcome::fail(format!("tool(s) outside allowlist: {}", off.join(", ")), 0)
            }
        }
        Rule::OutputRegexDeny(r) => {
            let re = compile(&r.regex)?;
            let mut hits = 0usize;
            let mut tools: Vec<&str> = Vec::new();
            for o in &ctx.outputs {
                if re.is_match(&o.text) {
                    hits += 1;
                    if !tools.contains(&o.tool.as_str()) {
                        tools.push(o.tool.as_str());
                    }
                }
            }
            if hits == 0 {
                Outcome::pass("no output matched", 0)
            } else {
                // Deliberately no matched text in the detail: the matched
                // content may itself be a secret (secret-redact alignment).
                Outcome::fail(
                    format!("{hits} output(s) matched in tool(s): {}", tools.join(", ")),
                    0,
                )
            }
        }
        Rule::ToolCallLimit(r) => {
            let n = ctx.tool_calls.len();
            if n <= r.max {
                Outcome::pass(format!("{n} tool calls within limit {}", r.max), 0)
            } else {
                Outcome::fail(format!("{n} tool calls exceed limit {}", r.max), 0)
            }
        }
        Rule::RetryLimit(r) => {
            let n = ctx.retries.get(&r.field).copied().unwrap_or(0);
            if n <= r.max {
                Outcome::pass(
                    format!("retries[{:?}] = {n} within limit {}", r.field, r.max),
                    0,
                )
            } else {
                Outcome::fail(
                    format!("retries[{:?}] = {n} exceeds limit {}", r.field, r.max),
                    0,
                )
            }
        }
        Rule::CmdDeny(r) => {
            let re = compile(&r.regex)?;
            let hits: Vec<&str> = ctx
                .cmd_lines
                .iter()
                .filter(|l| re.is_match(l))
                .map(|l| l.as_str())
                .collect();
            if hits.is_empty() {
                Outcome::pass("no denied command matched", 0)
            } else {
                Outcome::fail(format!("denied command(s): {}", hits.join(" ⏎ ")), 0)
            }
        }
    };
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::Res;

    fn manifest(text: &str) -> PolicyManifest {
        parse(text).expect("manifest parses")
    }

    fn ctx(json: &str) -> RunContext {
        serde_json::from_str(json).expect("context parses")
    }

    fn outcomes(m: &PolicyManifest, c: &RunContext) -> Vec<Res> {
        evaluate(m, c)
            .expect("evaluation succeeds")
            .into_iter()
            .map(|(_, _, _, o)| o.result)
            .collect()
    }

    #[test]
    fn tool_denylist_hits_and_misses() {
        let m = manifest(
            r#"
[[rule]]
id = "no-channel"
type = "tool-denylist"
deny = ["de_channel_send", "de_notify"]
"#,
        );
        let clean = ctx(r#"{"tool_calls": [{"name": "bash"}]}"#);
        assert_eq!(outcomes(&m, &clean), vec![Res::Pass]);
        let bad = ctx(r#"{"tool_calls": [{"name": "de_channel_send"}]}"#);
        assert_eq!(outcomes(&m, &bad), vec![Res::Fail]);
    }

    #[test]
    fn tool_allowlist_flags_offlist() {
        let m = manifest(
            r#"
[[rule]]
id = "only-media"
type = "tool-allowlist"
allow = ["media_generate", "media_list"]
"#,
        );
        let ok = ctx(r#"{"tool_calls": [{"name": "media_list"}]}"#);
        assert_eq!(outcomes(&m, &ok), vec![Res::Pass]);
        let bad = ctx(r#"{"tool_calls": [{"name": "bash"}]}"#);
        assert_eq!(outcomes(&m, &bad), vec![Res::Fail]);
    }

    #[test]
    fn output_regex_deny_flags_secret_without_leaking_text() {
        let m = manifest(
            r#"
[[rule]]
id = "no-secret"
type = "output-regex-deny"
regex = "sk-[A-Za-z0-9]{20,}"
"#,
        );
        let ok = ctx(r#"{"outputs": [{"tool": "bash", "text": "hello world"}]}"#);
        assert_eq!(outcomes(&m, &ok), vec![Res::Pass]);
        let bad = ctx(
            r#"{"outputs": [{"tool": "bash", "text": "token=sk-abcdefghijklmnopqrstuvwxyz123456"}]}"#,
        );
        let evals = evaluate(&m, &bad).expect("ok");
        assert_eq!(evals[0].3.result, Res::Fail);
        assert!(
            !evals[0].3.detail.contains("sk-"),
            "detail must not echo the secret"
        );
    }

    #[test]
    fn tool_call_limit_and_retry_limit() {
        let m = manifest(
            r#"
[[rule]]
id = "cap-calls"
type = "tool-call-limit"
max = 2

[[rule]]
id = "cap-retries"
type = "retry-limit"
field = "llm_request"
max = 3
"#,
        );
        let over = ctx(
            r#"{"tool_calls": [{"name":"a"},{"name":"b"},{"name":"c"}], "retries": {"llm_request": 4}}"#,
        );
        assert_eq!(outcomes(&m, &over), vec![Res::Fail, Res::Fail]);
        let within = ctx(r#"{"tool_calls": [{"name":"a"}], "retries": {"llm_request": 1}}"#);
        assert_eq!(outcomes(&m, &within), vec![Res::Pass, Res::Pass]);
        // missing retry field counts as 0 → pass
        let missing = ctx(r#"{"tool_calls": []}"#);
        assert_eq!(outcomes(&m, &missing), vec![Res::Pass, Res::Pass]);
    }

    #[test]
    fn cmd_deny_matches_command_lines() {
        let m = manifest(
            r#"
[[rule]]
id = "no-prod-restart"
type = "cmd-deny"
regex = "los\\.sh\\s+restart|restart\\s+/governance"
"#,
        );
        let ok = ctx(r#"{"cmd_lines": ["pnpm dsh --profile web --dump-config"]}"#);
        assert_eq!(outcomes(&m, &ok), vec![Res::Pass]);
        let bad = ctx(r#"{"cmd_lines": ["bash tools/los.sh restart"]}"#);
        assert_eq!(outcomes(&m, &bad), vec![Res::Fail]);
    }

    #[test]
    fn scope_mismatch_is_na_not_fail() {
        let m = manifest(
            r#"
[[rule]]
id = "headless-only"
type = "tool-denylist"
scope = { profile = "headless" }
deny = ["de_channel_send"]
"#,
        );
        let web = ctx(r#"{"profile": "web", "tool_calls": [{"name": "de_channel_send"}]}"#);
        let evals = evaluate(&m, &web).expect("ok");
        assert_eq!(evals[0].3.result, Res::Na);
        let headless =
            ctx(r#"{"profile": "headless", "tool_calls": [{"name": "de_channel_send"}]}"#);
        assert_eq!(outcomes(&m, &headless), vec![Res::Fail]);
    }

    #[test]
    fn disabled_rule_is_na() {
        let m = manifest(
            r#"
[[rule]]
id = "off"
type = "tool-denylist"
enabled = false
deny = ["bash"]
"#,
        );
        let c = ctx(r#"{"tool_calls": [{"name": "bash"}]}"#);
        assert_eq!(outcomes(&m, &c), vec![Res::Na]);
    }

    #[test]
    fn empty_policy_rejected() {
        let err = parse("").expect_err("empty policy rejected");
        assert!(err.0.contains("no rules"));
    }

    #[test]
    fn invalid_regex_rejected_at_parse() {
        let err = parse(
            r#"
[[rule]]
id = "bad-re"
type = "output-regex-deny"
regex = "[unclosed"
"#,
        )
        .expect_err("bad regex rejected");
        assert!(err.0.contains("invalid regex"));
    }

    #[test]
    fn workspace_scope_substring_match() {
        let m = manifest(
            r#"
[[rule]]
id = "srv-demo-only"
type = "retry-limit"
scope = { workspace = "srv-demo" }
field = "tool_call"
max = 9
"#,
        );
        // 用合成路径：scope.workspace 是**子串**匹配，不需要真实本机路径。
        // （原夹具硬编码 /Users/... 的本机项目路径，既不可移植也把项目名带进工具层。）
        let hit = ctx(r#"{"workspace": "/srv/work/srv-demo"}"#);
        assert_eq!(outcomes(&m, &hit), vec![Res::Pass]);
        let miss = ctx(r#"{"workspace": "/srv/work/other-app"}"#);
        assert_eq!(outcomes(&m, &miss), vec![Res::Na]);
    }

    #[test]
    fn context_is_lenient_on_missing_fields() {
        let m = manifest(
            r#"
[[rule]]
id = "r1"
type = "tool-call-limit"
max = 10
"#,
        );
        let empty = ctx(r#"{}"#);
        assert_eq!(outcomes(&m, &empty), vec![Res::Pass]);
    }
}
