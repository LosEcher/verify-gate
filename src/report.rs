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

pub fn build(
    manifest_path: &str,
    manifest_name: Option<&str>,
    started_at: u64,
    duration_ms: u64,
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
    let failed = check_reports.iter().filter(|c| c.result == "fail").count();
    Report {
        tool: "verify-gate",
        version: env!("CARGO_PKG_VERSION").into(),
        manifest: manifest_path.into(),
        manifest_name: manifest_name.map(|s| s.to_string()),
        started_at,
        duration_ms,
        verdict: if failed == 0 {
            "pass".into()
        } else {
            "fail".into()
        },
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
    out.push_str(&format!(
        "  {} checks · {} ms\n",
        r.checks.len(),
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
