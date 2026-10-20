//! Check executors — run one assertion against reality and produce an
//! outcome. Execution semantics reuse the unirun/sandbox-run family:
//! per-check timeout, output cap with keep-tail truncation, and a strict
//! three-state result (pass | fail | na).

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::manifest::{Check, CmdCheck, FileCheck, GitCheck, HttpCheck, JsonCheck};

pub const OUTPUT_CAP: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Res {
    Pass,
    Fail,
    /// 活着但超过 `idle_secs` 没有新输出（沉默超时）。
    ///
    /// 与 `Fail` 同属失败类（退出码 1），但字符串不同：`timeout` = 总预算耗尽，
    /// `stalled` = 中途不出声。两者补救方向完全不同（加预算 vs 查死锁/等锁/等
    /// 网络的点），压成一个标签会让报告指向错的嫌疑人。
    Stalled,
    Na,
}

impl Res {
    pub fn as_str(&self) -> &'static str {
        match self {
            Res::Pass => "pass",
            Res::Fail => "fail",
            Res::Stalled => "stalled",
            Res::Na => "na",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Outcome {
    pub result: Res,
    /// human-readable evidence (shown in the report, not the ledger)
    pub detail: String,
    pub duration_ms: u64,
}

impl Outcome {
    pub fn pass(detail: impl Into<String>, duration_ms: u64) -> Self {
        Outcome {
            result: Res::Pass,
            detail: detail.into(),
            duration_ms,
        }
    }
    pub fn fail(detail: impl Into<String>, duration_ms: u64) -> Self {
        Outcome {
            result: Res::Fail,
            detail: detail.into(),
            duration_ms,
        }
    }
    pub fn na(detail: impl Into<String>, duration_ms: u64) -> Self {
        Outcome {
            result: Res::Na,
            detail: detail.into(),
            duration_ms,
        }
    }
    /// 沉默超时：不是 `na`（它确实被判了），也不是 `timeout`（总预算没用完）。
    pub fn stalled(detail: impl Into<String>, duration_ms: u64) -> Self {
        Outcome {
            result: Res::Stalled,
            detail: detail.into(),
            duration_ms,
        }
    }
    /// sha256 of the detail — ledger stores only the hash (no plaintext
    /// evidence in the log; secrets must not leak into the audit trail).
    pub fn evidence_hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.detail.as_bytes());
        format!("{:x}", h.finalize())
    }
}

/// Run one check. Returns None only on tool-side errors (I/O failures,
/// regex runtime errors, ...) — the caller maps that to exit 2 (G0: a tool
/// error is not a verification failure).
pub fn run(check: &Check, cwd: &Path) -> Result<Outcome, String> {
    let start = Instant::now();
    let outcome = match check {
        Check::File(c) => run_file(c, cwd),
        Check::Cmd(c) => run_cmd(c, cwd),
        Check::Http(c) => run_http(c),
        Check::Git(c) => run_git(c, cwd),
        Check::Json(c) => run_json(c, cwd),
    };
    let duration_ms = start.elapsed().as_millis() as u64;
    Ok(outcome
        .map_err(|e| format!("{}: {e}", check.name()))?
        .with_duration(duration_ms))
}

trait WithDuration {
    fn with_duration(self, ms: u64) -> Outcome;
}

impl WithDuration for Outcome {
    fn with_duration(self, ms: u64) -> Outcome {
        Outcome {
            duration_ms: ms,
            ..self
        }
    }
}

// ---------------------------------------------------------------- file

fn run_file(c: &FileCheck, cwd: &Path) -> Result<Outcome, String> {
    let path = cwd.join(&c.path);
    let expect_exists = c.expect.as_deref().unwrap_or("exists") == "exists";
    let exists = path.is_file();
    if expect_exists && !exists {
        return Ok(Outcome::fail(
            format!("missing file: {}", path.display()),
            0,
        ));
    }
    if !expect_exists && exists {
        return Ok(Outcome::fail(
            format!("file exists but expected absent: {}", path.display()),
            0,
        ));
    }
    if let Some(hay) = &c.contains {
        let text = read_utf8_lossy(&path)?;
        if !text.contains(hay) {
            return Ok(Outcome::fail(
                format!(
                    "{}: expected to contain {hay:?}; first 200 chars: {}",
                    path.display(),
                    snippet(&text, 200)
                ),
                0,
            ));
        }
        return Ok(Outcome::pass(format!("contains {hay:?}"), 0));
    }
    if let Some(hay) = &c.not_contains {
        let text = read_utf8_lossy(&path)?;
        if text.contains(hay) {
            return Ok(Outcome::fail(
                format!("{}: must NOT contain {hay:?}", path.display()),
                0,
            ));
        }
        return Ok(Outcome::pass(format!("does not contain {hay:?}"), 0));
    }
    if let Some(re) = &c.regex {
        let text = read_utf8_lossy(&path)?;
        let rx = regex::Regex::new(re).map_err(|e| format!("regex {re:?}: {e}"))?;
        if rx.is_match(&text) {
            return Ok(Outcome::pass(format!("matches {re:?}"), 0));
        }
        return Ok(Outcome::fail(
            format!(
                "{}: no match for {re:?}; first 200 chars: {}",
                path.display(),
                snippet(&text, 200)
            ),
            0,
        ));
    }
    Ok(Outcome::pass(
        if expect_exists {
            "file exists"
        } else {
            "file absent"
        },
        0,
    ))
}

fn read_utf8_lossy(path: &Path) -> Result<String, String> {
    std::fs::read(path)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .map_err(|e| format!("read {}: {e}", path.display()))
}

fn snippet(s: &str, n: usize) -> String {
    let t: String = s.chars().take(n).collect();
    if s.chars().count() > n {
        format!("{t}…")
    } else {
        t
    }
}

// ---------------------------------------------------------------- cmd

/// Spawn via the platform shell, read pipes concurrently (cap + keep tail),
/// poll with a deadline **and an optional silence deadline**, kill the direct
/// child when either fires. Whole-tree kill is P1 (unirun delegation); P0 kills
/// the direct child.
///
/// 两个期限的语义（刻意分开，见 `CmdCheck::idle_secs`）：
/// - `timeout_secs` 先判（总预算优先），触发 ⇒ `timed out`；
/// - `idle_secs > 0` 后判（自 spawn 起算，每读到一段输出就重置），触发 ⇒ `stalled`。
///   manifest 校验已强制 `idle_secs < timeout_secs`，所以正常情况下静默先触发。
fn run_cmd(c: &CmdCheck, cwd: &Path) -> Result<Outcome, String> {
    let (shell, flag) = if cfg!(windows) {
        ("cmd", "/C")
    } else {
        ("sh", "-c")
    };
    let mut child = Command::new(shell)
        .arg(flag)
        .arg(&c.cmd)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {shell} -c {:?}: {e}", c.cmd))?;

    let stdout = child.stdout.take().ok_or("no stdout pipe")?;
    let stderr = child.stderr.take().ok_or("no stderr pipe")?;
    let out_buf = Arc::new(Mutex::new(Vec::new()));
    let err_buf = Arc::new(Mutex::new(Vec::new()));
    // 最后一次"有输出"的时刻（相对 start 的毫秒）。读线程写，主循环读；
    // 只用于判定"沉默多久"，不参与内容判定。
    let start = Instant::now();
    let last_output_ms = Arc::new(AtomicU64::new(0));
    spawn_reader(
        stdout,
        Arc::clone(&out_buf),
        Arc::clone(&last_output_ms),
        start,
    );
    spawn_reader(
        stderr,
        Arc::clone(&err_buf),
        Arc::clone(&last_output_ms),
        start,
    );

    let deadline = Duration::from_secs(c.timeout_secs);
    let idle_ms = c.idle_secs * 1000;
    let mut timed_out = false;
    let mut stalled = false;
    let mut silent_for_ms = 0u64;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let _ = status;
                break;
            }
            Ok(None) => {
                if start.elapsed() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break;
                }
                if idle_ms > 0 {
                    let now_ms = start.elapsed().as_millis() as u64;
                    let since = now_ms.saturating_sub(last_output_ms.load(Ordering::Relaxed));
                    if since >= idle_ms {
                        let _ = child.kill();
                        let _ = child.wait();
                        silent_for_ms = since;
                        stalled = true;
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(format!("wait on {:?}: {e}", c.cmd)),
        }
    }
    let out = out_buf.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let err = err_buf.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let stdout_s = String::from_utf8_lossy(&out).into_owned();
    let stderr_s = String::from_utf8_lossy(&err).into_owned();

    // 沉默超时：内容断言没有意义（进程被打断，输出是残的），直接给出该结论。
    if stalled {
        return Ok(Outcome::stalled(
            format!(
                "stalled: no output for {silent_for_ms}ms (idle_secs={}, timeout_secs={}); \
                 stdout bytes={}; stderr bytes={}; stdout tail: {}; stderr tail: {}",
                c.idle_secs,
                c.timeout_secs,
                out.len(),
                err.len(),
                snippet(&stdout_s, 160),
                snippet(&stderr_s, 160),
            ),
            0,
        ));
    }

    let exit_code = if timed_out {
        None
    } else {
        // try_wait already reported the status; re-wait for a fresh status.
        child.wait().ok().and_then(|s| s.code())
    };

    let expected = c.exit.unwrap_or(0);
    let mut problems: Vec<String> = Vec::new();
    if timed_out {
        problems.push(format!("timed out after {}s", c.timeout_secs));
    } else if exit_code != Some(expected) {
        problems.push(format!(
            "exit {} != expected {expected}",
            exit_code.map_or("?".into(), |c| c.to_string())
        ));
    }
    if let Some(hay) = &c.stdout_contains {
        if !stdout_s.contains(hay) {
            problems.push(format!("stdout lacks {hay:?}"));
        }
    }
    if let Some(hay) = &c.stderr_contains {
        if !stderr_s.contains(hay) {
            problems.push(format!("stderr lacks {hay:?}"));
        }
    }
    if let Some(re) = &c.stdout_regex {
        let rx = regex::Regex::new(re).map_err(|e| format!("regex {re:?}: {e}"))?;
        if !rx.is_match(&stdout_s) {
            problems.push(format!("stdout lacks match for {re:?}"));
        }
    }
    if let Some(re) = &c.stderr_regex {
        let rx = regex::Regex::new(re).map_err(|e| format!("regex {re:?}: {e}"))?;
        if !rx.is_match(&stderr_s) {
            problems.push(format!("stderr lacks match for {re:?}"));
        }
    }

    if problems.is_empty() {
        Ok(Outcome::pass(
            format!("exit {expected}; stdout tail: {}", snippet(&stdout_s, 200)),
            0,
        ))
    } else {
        Ok(Outcome::fail(
            format!(
                "{}; exit {}; stdout tail: {}; stderr tail: {}",
                problems.join("; "),
                exit_code.map_or("killed".into(), |c| c.to_string()),
                snippet(&stdout_s, 200),
                snippet(&stderr_s, 200)
            ),
            0,
        ))
    }
}

fn spawn_reader(
    mut pipe: impl Read + Send + 'static,
    buf: Arc<Mutex<Vec<u8>>>,
    last_output_ms: Arc<AtomicU64>,
    start: Instant,
) {
    std::thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    // 先记"有输出"再落盘：让静默计时器立刻重置，不因加锁顺序
                    // 把一次输出误算成沉默（反之则会漏判，代价更小但没必要）。
                    last_output_ms.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
                    let mut b = buf.lock().unwrap_or_else(|p| p.into_inner());
                    b.extend_from_slice(&chunk[..n]);
                    if b.len() > OUTPUT_CAP {
                        let drop = b.len() - OUTPUT_CAP;
                        b.drain(0..drop);
                    }
                }
            }
        }
    });
}

// ---------------------------------------------------------------- http

fn run_http(c: &HttpCheck) -> Result<Outcome, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(c.timeout_secs))
        .build();
    let (status, body) = match agent.get(&c.url).call() {
        Ok(resp) => {
            let status = resp.status();
            let body = resp
                .into_string()
                .map_err(|e| format!("read body from {}: {e}", c.url))?;
            (status, body)
        }
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            (code, body)
        }
        Err(e) => {
            return Ok(Outcome::fail(
                format!("request to {} failed: {e}", c.url),
                0,
            ))
        }
    };
    let expected = c.status.unwrap_or(200);
    let mut problems: Vec<String> = Vec::new();
    if status != expected {
        problems.push(format!("status {status} != expected {expected}"));
    }
    if let Some(hay) = &c.body_contains {
        if !body.contains(hay) {
            problems.push(format!("body lacks {hay:?}"));
        }
    }
    if problems.is_empty() {
        Ok(Outcome::pass(format!("GET {} -> {status}", c.url), 0))
    } else {
        Ok(Outcome::fail(
            format!(
                "{}; body tail: {}",
                problems.join("; "),
                snippet(&body, 200)
            ),
            0,
        ))
    }
}

// ---------------------------------------------------------------- git

fn run_git(c: &GitCheck, cwd: &Path) -> Result<Outcome, String> {
    let expect = c.expect.as_deref().unwrap_or("clean");
    match expect {
        "clean" => {
            let out = git(cwd, &["status", "--porcelain"])?;
            if out.trim().is_empty() {
                Ok(Outcome::pass("worktree clean", 0))
            } else {
                Ok(Outcome::fail(
                    format!("worktree dirty:\n{}", snippet(&out, 400)),
                    0,
                ))
            }
        }
        "branch" => {
            let branch = c.branch.as_deref().unwrap_or("");
            let cur = git(cwd, &["rev-parse", "--abbrev-ref", "HEAD"])?;
            let cur = cur.trim();
            if cur == branch {
                Ok(Outcome::pass(format!("on branch {branch}"), 0))
            } else {
                Ok(Outcome::fail(
                    format!("on branch {cur} != expected {branch}"),
                    0,
                ))
            }
        }
        other => Err(format!("unknown git expect {other:?}")),
    }
}

fn git(cwd: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .map_err(|e| format!("git {args:?}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

// ---------------------------------------------------------------- json

fn run_json(c: &JsonCheck, cwd: &Path) -> Result<Outcome, String> {
    let path = cwd.join(&c.path);
    let text = read_utf8_lossy(&path)?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("invalid JSON in {}: {e}", path.display()))?;
    let found = navigate(&value, &c.field)?;
    if let Some(expected) = &c.equals {
        if found == expected {
            Ok(Outcome::pass(
                format!("{} equals {}", c.field, compact(expected)),
                0,
            ))
        } else {
            Ok(Outcome::fail(
                format!(
                    "{} = {} != expected {}",
                    c.field,
                    compact(found),
                    compact(expected)
                ),
                0,
            ))
        }
    } else if c.exists == Some(true) {
        Ok(Outcome::pass(format!("field {} exists", c.field), 0))
    } else {
        Err("json check needs equals or exists=true".into())
    }
}

fn compact(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => format!("{s:?}"),
        other => other.to_string(),
    }
}

/// Navigate a dotted path with array indices: a.b[0].c
fn navigate<'a>(value: &'a serde_json::Value, path: &str) -> Result<&'a serde_json::Value, String> {
    let mut cur = value;
    for tok in tokenize(path)? {
        cur = match tok {
            Tok::Key(k) => cur
                .get(&k)
                .ok_or_else(|| format!("field {path}: missing key {k:?}"))?,
            Tok::Idx(i) => cur
                .get(i)
                .ok_or_else(|| format!("field {path}: index {i} out of range"))?,
        };
    }
    Ok(cur)
}

enum Tok {
    Key(String),
    Idx(usize),
}

fn tokenize(path: &str) -> Result<Vec<Tok>, String> {
    let mut toks = Vec::new();
    let mut rest = path;
    while !rest.is_empty() {
        rest = rest.trim_start_matches('.');
        if rest.is_empty() {
            break;
        }
        if let Some(open) = rest.find('[') {
            let key = &rest[..open];
            for part in key.split('.').filter(|p| !p.is_empty()) {
                toks.push(Tok::Key(part.to_string()));
            }
            let close = rest[open..]
                .find(']')
                .ok_or_else(|| format!("field {path}: unbalanced '['"))?;
            let idx: usize = rest[open + 1..open + close]
                .parse()
                .map_err(|_| format!("field {path}: bad index in {rest:?}"))?;
            toks.push(Tok::Idx(idx));
            rest = &rest[open + close + 1..];
        } else {
            for part in rest.split('.').filter(|p| !p.is_empty()) {
                toks.push(Tok::Key(part.to_string()));
            }
            rest = "";
        }
    }
    Ok(toks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn navigate_dotted_with_index() {
        let v = json!({ "a": { "b": [ { "c": 42 } ] } });
        assert_eq!(navigate(&v, "a.b[0].c").unwrap(), &json!(42));
        assert!(navigate(&v, "a.b[1]").is_err());
        assert!(navigate(&v, "a.x").is_err());
    }

    #[test]
    fn keep_tail_cap() {
        let buf = Arc::new(Mutex::new(Vec::new()));
        {
            let mut b = buf.lock().unwrap();
            for i in 0..10_000u32 {
                b.extend_from_slice(format!("{i} ").as_bytes());
            }
            if b.len() > OUTPUT_CAP {
                let drop = b.len() - OUTPUT_CAP;
                b.drain(0..drop);
            }
        }
        let b = buf.lock().unwrap();
        assert!(b.len() <= OUTPUT_CAP);
        // tail survives: last tokens present
        let s = String::from_utf8_lossy(&b);
        assert!(s.trim_end().ends_with("9999"));
    }

    #[test]
    fn outcome_hash_stable() {
        let a = Outcome::fail("secret output xyz", 1);
        let b = Outcome::fail("secret output xyz", 1);
        assert_eq!(a.evidence_hash(), b.evidence_hash());
        assert_ne!(a.evidence_hash(), Outcome::fail("other", 1).evidence_hash());
    }
}
