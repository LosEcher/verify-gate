//! Report aggregation — per-check results plus a verdict, emitted as
//! machine JSON (`--emit json`) or human pretty text (default).

use serde::Serialize;

use crate::check::Outcome;

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub tool: &'static str,
    pub version: String,
    pub manifest: String,
    pub manifest_name: Option<String>,
    pub started_at: u64,
    pub duration_ms: u64,
    pub verdict: String,
    /// 真正 pass 的条数。**此前报告里没有任何 na 计数**，于是"全 na 的 pass"
    /// 与"真 pass"在 JSON 上完全不可区分（2026-10-08 修复）。
    pub passed: usize,
    /// 本轮新被静音的检查名（上一条完成运行里判过，这次 `enabled = false`），
    /// 已扣掉 manifest `[meta] silence-ok` 里声明过的。非空即 verdict 为
    /// `inconclusive`（exit 2）：**"不再判"不是"通过"**。
    pub silenced: Vec<String>,
    pub checks: Vec<CheckReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckReport {
    pub index: usize,
    pub name: String,
    pub r#type: String,
    pub result: String,
    pub duration_ms: u64,
    pub detail: String,
}

/// `verdict` 与 `pass` 由**调用方**决定（不再在此自算）。
///
/// 为什么改（2026-10-08）：原先这里用 `if failed == 0 { "pass" }` 自算 verdict，
/// 会把调用方算出的 `"inconclusive"`（全部 na）覆盖回 `"pass"` —— 退出码对了但
/// **JSON 契约错了**，而下游插件消费的正是 JSON。同一状态被两处决定即两处真相，
/// 与 ADR 0047 R3 相悖。现统一由 main.rs 决定并传入。
pub fn build(
    manifest_path: &str,
    manifest_name: Option<&str>,
    started_at: u64,
    duration_ms: u64,
    verdict: &str,
    pass: usize,
    checks: Vec<(usize, String, String, Outcome)>,
) -> Report {
    let check_reports: Vec<CheckReport> = checks
        .into_iter()
        .map(|(index, name, kind, o)| CheckReport {
            index,
            name,
            r#type: kind,
            result: o.result.as_str().into(),
            duration_ms: o.duration_ms,
            detail: o.detail,
        })
        .collect();
    Report {
        tool: "verify-gate",
        version: env!("CARGO_PKG_VERSION").into(),
        manifest: manifest_path.into(),
        manifest_name: manifest_name.map(|s| s.to_string()),
        started_at,
        duration_ms,
        verdict: verdict.to_string(),
        passed: pass,
        silenced: Vec::new(),
        checks: check_reports,
    }
}

pub fn render_pretty(r: &Report) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "verify-gate {} — {} — verdict: {}\n",
        r.version,
        r.manifest_name
            .as_deref()
            .map(|n| format!("{} ({})", n, r.manifest))
            .unwrap_or_else(|| r.manifest.clone()),
        r.verdict
    ));
    let failed = r.checks.iter().filter(|c| c.result == "fail").count();
    let na = r.checks.iter().filter(|c| c.result == "na").count();
    out.push_str(&format!(
        "  {} checks · {} passed · {} failed · {} na · {} ms\n",
        r.checks.len(),
        r.passed,
        failed,
        na,
        r.duration_ms
    ));
    for c in &r.checks {
        let mark = match c.result.as_str() {
            "pass" => "✔",
            "fail" => "✘",
            _ => "·",
        };
        out.push_str(&format!(
            "  {mark} [{}] {:<3} {:<28} {:>5}ms  {}\n",
            c.result,
            c.r#type,
            truncate(&c.name, 28),
            c.duration_ms,
            one_line(&c.detail, 100)
        ));
    }
    out
}

fn truncate(s: &str, n: usize) -> String {
    let t: String = s.chars().take(n).collect();
    if s.chars().count() > n {
        format!("{t}…")
    } else {
        t
    }
}

fn one_line(s: &str, n: usize) -> String {
    let flat = s.replace('\n', "⏎");
    truncate(&flat, n)
}
