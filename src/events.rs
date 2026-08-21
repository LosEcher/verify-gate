//! Event-sourced run ledger. Append-only JSONL is the single source of
//! truth; `status`/`log` are derived projections. A dangling run.start
//! (crash before run.finish) is repaired as `interrupted`, mirroring DSH
//! repair semantics. Ledger events carry only evidence hashes — never
//! plaintext check output (secrets must not leak into the audit trail).

use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

pub fn new_run_id() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("run-{now:013}-{seq}")
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Event<'a> {
    #[serde(rename = "run.start")]
    RunStart {
        run_id: String,
        version: &'a str,
        ts: u64,
        cwd: &'a str,
        manifest: &'a str,
        check_count: usize,
    },
    #[serde(rename = "check.start")]
    CheckStart {
        run_id: &'a str,
        index: usize,
        name: &'a str,
        r#type: &'a str,
    },
    #[serde(rename = "check.finish")]
    CheckFinish {
        run_id: &'a str,
        index: usize,
        name: &'a str,
        result: &'a str,
        duration_ms: u64,
        evidence_hash: &'a str,
    },
    #[serde(rename = "run.finish")]
    RunFinish {
        run_id: &'a str,
        verdict: &'a str,
        failed: usize,
        na: usize,
        duration_ms: u64,
    },
}

/// Append one event to the JSONL log (no-op if path is None).
pub fn append(log_path: Option<&Path>, event: &Event<'_>) -> std::io::Result<()> {
    let Some(path) = log_path else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    let mut line =
        serde_json::to_string(event).map_err(|e| std::io::Error::other(e.to_string()))?;
    line.push('\n');
    f.write_all(line.as_bytes())?;
    f.flush()
}
