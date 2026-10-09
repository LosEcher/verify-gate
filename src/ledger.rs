//! Ledger projections: `status` (run list with dangling-start repair) and
//! `log <runId>` (one run's full event chain + rebuilt summary).

use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct RunSummary {
    pub run_id: String,
    /// Manifest this run was executed against. Two manifests can share one log
    /// (`.verify-gate/runs.jsonl`), so history comparisons must be per-manifest.
    pub manifest: Option<String>,
    pub started_ts: Option<u64>,
    pub finished_ts: Option<u64>,
    pub verdict: Option<String>,
    pub check_count: Option<usize>,
    pub failed: Option<usize>,
    pub na: Option<usize>,
    pub checks: Vec<CheckSummary>,
    pub interrupted: bool,
}

#[derive(Debug, Clone)]
pub struct CheckSummary {
    pub index: usize,
    pub name: String,
    pub kind: String,
    pub result: Option<String>,
    pub duration_ms: Option<u64>,
}

pub enum Line {
    RunStart {
        run_id: String,
        ts: u64,
        check_count: usize,
        manifest: String,
    },
    CheckStart {
        run_id: String,
        index: usize,
        name: String,
        kind: String,
    },
    CheckFinish {
        run_id: String,
        index: usize,
        result: String,
        duration_ms: u64,
    },
    RunFinish {
        run_id: String,
        verdict: String,
        failed: usize,
        na: usize,
        ts: u64,
    },
    #[allow(dead_code)]
    Unknown(String),
}

/// Parse one JSONL line into a typed Line. Malformed lines are kept as
/// Unknown so the projection is lossless (a torn write stays visible).
pub fn parse_line(raw: &str) -> Line {
    let v: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return Line::Unknown(raw.to_string()),
    };
    let t = v.get("t").and_then(|x| x.as_str()).unwrap_or("");
    match t {
        "run.start" => Line::RunStart {
            run_id: v["run_id"].as_str().unwrap_or("?").into(),
            ts: v["ts"].as_u64().unwrap_or(0),
            check_count: v["check_count"].as_u64().unwrap_or(0) as usize,
            manifest: v["manifest"].as_str().unwrap_or("").into(),
        },
        "check.start" => Line::CheckStart {
            run_id: v["run_id"].as_str().unwrap_or("?").into(),
            index: v["index"].as_u64().unwrap_or(0) as usize,
            name: v["name"].as_str().unwrap_or("?").into(),
            kind: v["type"].as_str().unwrap_or("?").into(),
        },
        "check.finish" => Line::CheckFinish {
            run_id: v["run_id"].as_str().unwrap_or("?").into(),
            index: v["index"].as_u64().unwrap_or(0) as usize,
            result: v["result"].as_str().unwrap_or("?").into(),
            duration_ms: v["duration_ms"].as_u64().unwrap_or(0),
        },
        "run.finish" => Line::RunFinish {
            run_id: v["run_id"].as_str().unwrap_or("?").into(),
            verdict: v["verdict"].as_str().unwrap_or("?").into(),
            failed: v["failed"].as_u64().unwrap_or(0) as usize,
            na: v["na"].as_u64().unwrap_or(0) as usize,
            ts: v["ts"].as_u64().unwrap_or(0),
        },
        _ => Line::Unknown(raw.to_string()),
    }
}

/// Fold the ledger into run summaries. Runs without run.finish are repaired
/// as `interrupted` (DSH repair semantics: dangling start is kept visible,
/// not silently dropped).
pub fn fold(lines: &[Line]) -> Vec<RunSummary> {
    let mut runs: BTreeMap<String, RunSummary> = BTreeMap::new();
    for line in lines {
        match line {
            Line::RunStart {
                run_id,
                ts,
                check_count,
                manifest,
            } => {
                runs.entry(run_id.clone()).or_insert_with(|| RunSummary {
                    run_id: run_id.clone(),
                    manifest: Some(manifest.clone()),
                    started_ts: Some(*ts),
                    finished_ts: None,
                    verdict: None,
                    check_count: Some(*check_count),
                    failed: None,
                    na: None,
                    checks: Vec::new(),
                    interrupted: false,
                });
            }
            Line::CheckStart {
                run_id,
                index,
                name,
                kind,
            } => {
                if let Some(r) = runs.get_mut(run_id) {
                    r.checks.push(CheckSummary {
                        index: *index,
                        name: name.clone(),
                        kind: kind.clone(),
                        result: None,
                        duration_ms: None,
                    });
                }
            }
            Line::CheckFinish {
                run_id,
                index,
                result,
                duration_ms,
            } => {
                if let Some(r) = runs.get_mut(run_id) {
                    if let Some(c) = r.checks.iter_mut().find(|c| c.index == *index) {
                        c.result = Some(result.clone());
                        c.duration_ms = Some(*duration_ms);
                    }
                }
            }
            Line::RunFinish {
                run_id,
                verdict,
                failed,
                na,
                ts,
            } => {
                if let Some(r) = runs.get_mut(run_id) {
                    r.verdict = Some(verdict.clone());
                    r.finished_ts = Some(*ts);
                    r.failed = Some(*failed);
                    r.na = Some(*na);
                }
            }
            Line::Unknown(_) => {}
        }
    }
    for r in runs.values_mut() {
        if r.verdict.is_none() {
            r.interrupted = true;
        }
    }
    // Newest run first: sort by start time desc, run_id as tiebreak.
    let mut runs: Vec<RunSummary> = runs.into_values().collect();
    runs.sort_by(|a, b| {
        b.started_ts
            .unwrap_or(0)
            .cmp(&a.started_ts.unwrap_or(0))
            .then_with(|| b.run_id.cmp(&a.run_id))
    });
    runs
}

pub fn load(path: &Path) -> Result<Vec<Line>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("read ledger {}: {e}", path.display()))?;
    Ok(text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(parse_line)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(lines: &[&str]) -> Vec<Line> {
        lines.iter().map(|l| parse_line(l)).collect()
    }

    #[test]
    fn dangling_start_repaired_as_interrupted() {
        let lines = mk(&[r#"{"t":"run.start","run_id":"r1","ts":1,"check_count":1}"#]);
        let runs = fold(&lines);
        assert_eq!(runs.len(), 1);
        assert!(runs[0].interrupted);
        assert_eq!(runs[0].verdict, None);
    }

    #[test]
    fn complete_run_folded() {
        let lines = mk(&[
            r#"{"t":"run.start","run_id":"r1","ts":1,"check_count":1}"#,
            r#"{"t":"check.start","run_id":"r1","index":0,"name":"a","type":"file"}"#,
            r#"{"t":"check.finish","run_id":"r1","index":0,"name":"a","result":"pass","duration_ms":5,"evidence_hash":"h"}"#,
            r#"{"t":"run.finish","run_id":"r1","verdict":"pass","failed":0,"na":0,"ts":9}"#,
        ]);
        let runs = fold(&lines);
        assert_eq!(runs.len(), 1);
        assert!(!runs[0].interrupted);
        assert_eq!(runs[0].verdict.as_deref(), Some("pass"));
        assert_eq!(runs[0].checks.len(), 1);
        assert_eq!(runs[0].checks[0].result.as_deref(), Some("pass"));
    }

    #[test]
    fn malformed_line_kept_as_unknown() {
        let lines = mk(&["not json"]);
        assert!(matches!(lines[0], Line::Unknown(_)));
        // fold is lossless: no crash, no runs
        assert!(fold(&lines).is_empty());
    }

    #[test]
    fn newest_first() {
        let lines = mk(&[
            r#"{"t":"run.start","run_id":"old","ts":1,"check_count":0}"#,
            r#"{"t":"run.finish","run_id":"old","verdict":"pass","failed":0,"na":0,"ts":2}"#,
            r#"{"t":"run.start","run_id":"new","ts":3,"check_count":0}"#,
            r#"{"t":"run.finish","run_id":"new","verdict":"fail","failed":1,"na":0,"ts":4}"#,
        ]);
        let runs = fold(&lines);
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].run_id, "new");
    }
}
