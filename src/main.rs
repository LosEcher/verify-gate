//! verify-gate — declarative verification manifest executor for AI agents.
//!
//! Given a TOML manifest of typed checks (file / cmd / http / git / json),
//! run each assertion against reality, aggregate a pass/fail report, and
//! return a strict exit code: 0 all pass · 1 any fail · 2 tool error (usage,
//! manifest parse, engine failure). The event-sourced ledger
//! (`.verify-gate/runs.jsonl` by default) makes replay/audit structurally
//! free, with dangling runs repaired as `interrupted` (DSH repair semantics).

mod check;
mod events;
mod ledger;
mod manifest;
mod policy;
mod report;
mod silence;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::check::Res;
use crate::events::Event;
use crate::manifest::Manifest;
use crate::policy::{PolicyManifest, RunContext};

const USAGE: &str = "\
verify-gate — declarative verification manifest executor (+ policy-gate).

Runs every assertion in a TOML manifest (file / cmd / http / git / json)
against reality, aggregates a pass/fail/inconclusive report, and exits
0 (all pass), 1 (any fail), or 2 (inconclusive OR tool error: usage,
manifest parse, engine bug).

NOTE: na (disabled check, or policy rule whose scope does not match) counts as
neither pass nor fail. If EVERY check is na, the verdict is inconclusive and the
exit code is 2 -- an all-na gate proves nothing and must never be read as a pass
(2026-10-08: previously reported pass + exit 0).
Event-sourced ledger: .verify-gate/runs.jsonl.

USAGE:
  verify-gate [OPTIONS] <manifest.toml>
  verify-gate policy --manifest <policy.toml> --context <ctx.json|->
                     [--emit json|pretty] [--log <path>] [--no-log]

OPTIONS:
  --emit json|pretty     output format (default pretty)
  --log <path>           event ledger path (default .verify-gate/runs.jsonl)
  --no-log               disable the event ledger
  --cwd <dir>            assertion base directory (default: manifest dir)
  --version              print version
  --help                 print this help

SUBCOMMANDS:
  policy                 evaluate a policy manifest (guardrails) against a
                         run context (JSON on stdin when --context -):
                         structured rule kinds (tool-denylist / tool-allowlist
                         / output-regex-deny / tool-call-limit / retry-limit /
                         cmd-deny), scoped rules evaluate to na when the
                         scope does not match; exit 0 pass · 1 violation ·
                         2 error OR inconclusive (every rule na)
  status [--log <path>] [--limit N]
                        list runs; dangling runs (start without finish) are
                        shown as interrupted
  log <runId> [--log <path>]
                        full event chain of one run + rebuilt summary

EXIT CODES: 0 pass · 1 fail · 2 inconclusive-or-tool-error.
              (2 = could-not-judge, never passed)

MANIFEST (TOML): a list of [[check]] entries. See README for the full
reference. Every check needs: name, type (file|cmd|http|git|json) and the
type-specific assertions. enabled = false marks a check as na.

POLICY MANIFEST (TOML): a list of [[rule]] entries. See README for the full
reference. Every rule needs: id, type (tool-denylist | tool-allowlist |
output-regex-deny | tool-call-limit | retry-limit | cmd-deny) and the
type-specific fields. scope = { profile = \"x\" } or { workspace = \"sub\" }
marks a rule na when it does not match the context.
";

#[derive(Debug)]
struct Config {
    emit: String,
    log: Option<PathBuf>,
    cwd: Option<PathBuf>,
    manifest: PathBuf,
}

#[derive(Debug)]
struct PolicyConfig {
    emit: String,
    log: Option<PathBuf>,
    manifest: PathBuf,
    /// "-" means read the run context from stdin.
    context: PathBuf,
}

enum Cli {
    Run(Config),
    Policy(PolicyConfig),
    Status { log: PathBuf, limit: usize },
    Log { run_id: String, log: PathBuf },
    Help,
    Version,
}

fn parse_args(argv: &[String]) -> Result<Cli, String> {
    if argv.is_empty() {
        return Ok(Cli::Help);
    }
    let mut emit = "pretty".to_string();
    let mut log: Option<PathBuf> = None;
    let mut cwd: Option<PathBuf> = None;
    let mut no_log = false;
    let mut manifest: Option<PathBuf> = None;
    let mut limit = 20usize;

    if argv[0] == "policy" {
        let mut emit = "pretty".to_string();
        let mut log: Option<PathBuf> = None;
        let mut no_log = false;
        let mut manifest: Option<PathBuf> = None;
        let mut context: Option<PathBuf> = None;
        let mut i = 1;
        while i < argv.len() {
            match argv[i].as_str() {
                "--emit" => {
                    emit = argv.get(i + 1).ok_or("--emit needs json|pretty")?.clone();
                    if emit != "json" && emit != "pretty" {
                        return Err(format!("--emit must be json|pretty, got {emit:?}"));
                    }
                    i += 1;
                }
                "--log" => {
                    log = Some(PathBuf::from(argv.get(i + 1).ok_or("--log needs a path")?));
                    i += 1;
                }
                "--no-log" => no_log = true,
                "--manifest" => {
                    manifest = Some(PathBuf::from(
                        argv.get(i + 1).ok_or("--manifest needs a path")?,
                    ));
                    i += 1;
                }
                "--context" => {
                    context = Some(PathBuf::from(
                        argv.get(i + 1).ok_or("--context needs a path")?,
                    ));
                    i += 1;
                }
                "--help" | "-h" => return Ok(Cli::Help),
                other => return Err(format!("policy: unknown arg {other:?}")),
            }
            i += 1;
        }
        let manifest = manifest.ok_or("policy: missing --manifest <policy.toml>")?;
        let context = context.ok_or("policy: missing --context <ctx.json|->")?;
        let log = if no_log {
            None
        } else {
            Some(log.unwrap_or_else(|| PathBuf::from(".verify-gate/runs.jsonl")))
        };
        return Ok(Cli::Policy(PolicyConfig {
            emit,
            log,
            manifest,
            context,
        }));
    }
    if argv[0] == "status" {
        let mut logp = PathBuf::from(".verify-gate/runs.jsonl");
        let mut i = 1;
        while i < argv.len() {
            match argv[i].as_str() {
                "--log" => {
                    logp = PathBuf::from(argv.get(i + 1).ok_or("--log needs a path")?);
                    i += 1;
                }
                "--limit" => {
                    limit = argv
                        .get(i + 1)
                        .ok_or("--limit needs a number")?
                        .parse()
                        .map_err(|_| "bad --limit".to_string())?;
                    i += 1;
                }
                other => return Err(format!("status: unknown arg {other:?}")),
            }
            i += 1;
        }
        return Ok(Cli::Status { log: logp, limit });
    }
    if argv[0] == "log" {
        let run_id = argv.get(1).ok_or("log needs a run id")?.clone();
        let mut logp = PathBuf::from(".verify-gate/runs.jsonl");
        let mut i = 2;
        while i < argv.len() {
            match argv[i].as_str() {
                "--log" => {
                    logp = PathBuf::from(argv.get(i + 1).ok_or("--log needs a path")?);
                    i += 1;
                }
                other => return Err(format!("log: unknown arg {other:?}")),
            }
            i += 1;
        }
        return Ok(Cli::Log { run_id, log: logp });
    }

    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--emit" => {
                emit = argv.get(i + 1).ok_or("--emit needs json|pretty")?.clone();
                if emit != "json" && emit != "pretty" {
                    return Err(format!("--emit must be json|pretty, got {emit:?}"));
                }
                i += 1;
            }
            "--log" => {
                log = Some(PathBuf::from(argv.get(i + 1).ok_or("--log needs a path")?));
                i += 1;
            }
            "--no-log" => no_log = true,
            "--cwd" => {
                cwd = Some(PathBuf::from(argv.get(i + 1).ok_or("--cwd needs a dir")?));
                i += 1;
            }
            "--version" => return Ok(Cli::Version),
            "--help" | "-h" => return Ok(Cli::Help),
            a if a.starts_with('-') => return Err(format!("unknown option {a:?}")),
            a => {
                if manifest.is_some() {
                    return Err("only one manifest allowed".into());
                }
                manifest = Some(PathBuf::from(a));
            }
        }
        i += 1;
    }
    let manifest = manifest.ok_or("missing <manifest.toml>")?;
    let log = if no_log {
        None
    } else {
        Some(log.unwrap_or_else(|| PathBuf::from(".verify-gate/runs.jsonl")))
    };
    Ok(Cli::Run(Config {
        emit,
        log,
        cwd,
        manifest,
    }))
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&argv) {
        Ok(Cli::Help) => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Cli::Version) => {
            println!("verify-gate {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Cli::Policy(cfg)) => match cmd_policy(cfg) {
            Ok(code) => ExitCode::from(code),
            Err(e) => {
                eprintln!("verify-gate: {e}");
                ExitCode::from(2)
            }
        },
        Ok(Cli::Status { log, limit }) => match cmd_status(&log, limit) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("verify-gate: {e}");
                ExitCode::from(2)
            }
        },
        Ok(Cli::Log { run_id, log }) => match cmd_log(&log, &run_id) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("verify-gate: {e}");
                ExitCode::from(2)
            }
        },
        Ok(Cli::Run(cfg)) => match cmd_run(cfg) {
            Ok(code) => ExitCode::from(code),
            Err(e) => {
                eprintln!("verify-gate: {e}");
                ExitCode::from(2)
            }
        },
        Err(e) => {
            eprintln!("verify-gate: {e}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn cmd_run(cfg: Config) -> Result<u8, String> {
    let text = std::fs::read_to_string(&cfg.manifest)
        .map_err(|e| format!("read manifest {}: {e}", cfg.manifest.display()))?;
    let manifest: Manifest =
        manifest::parse(&text).map_err(|e| format!("manifest {}: {e}", cfg.manifest.display()))?;

    let cwd = match &cfg.cwd {
        Some(d) => d.clone(),
        None => {
            let p = cfg
                .manifest
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_default();
            if p.as_os_str().is_empty() {
                PathBuf::from(".")
            } else {
                p
            }
        }
    };
    if !cwd.is_dir() {
        return Err(format!("cwd is not a directory: {}", cwd.display()));
    }

    let started_at = events::now_ms();
    let run_id = events::new_run_id();
    let version = env!("CARGO_PKG_VERSION");
    let cwd_s = cwd.to_string_lossy().into_owned();
    let manifest_s = cfg.manifest.to_string_lossy().into_owned();
    let log = cfg.log.as_deref();

    events::append(
        log,
        &Event::RunStart {
            run_id: run_id.clone(),
            version,
            ts: started_at,
            cwd: &cwd_s,
            manifest: &manifest_s,
            check_count: manifest.check.len(),
        },
    )
    .map_err(|e| format!("ledger write: {e}"))?;

    let mut results: Vec<(usize, String, String, check::Outcome)> = Vec::new();
    let mut failed = 0usize;
    let mut na = 0usize;
    let mut tool_error: Option<String> = None;
    // Checks that are `na` *because this manifest disables them* (the only `na`
    // source in verify mode). Kept separately from the count so the silence
    // ratchet knows which names stopped being judged.
    let mut disabled_now: Vec<String> = Vec::new();
    let silence_ok: Vec<String> = manifest
        .meta
        .as_ref()
        .map(|m| m.silence_ok.clone())
        .unwrap_or_default();

    for (index, check_item) in manifest.check.iter().enumerate() {
        let name = check_item.name().to_string();
        let kind = check_item.kind().to_string();
        events::append(
            log,
            &Event::CheckStart {
                run_id: &run_id,
                index,
                name: &name,
                r#type: &kind,
            },
        )
        .map_err(|e| format!("ledger write: {e}"))?;

        let outcome = if !check_item.enabled() {
            disabled_now.push(name.clone());
            check::Outcome::na("disabled", 0)
        } else {
            let guarded = std::panic::catch_unwind(|| check::run(check_item, &cwd));
            match guarded {
                Ok(Ok(o)) => o,
                Ok(Err(e)) => {
                    // tool-side error → G0: exit 2, not a verification failure
                    tool_error = Some(e);
                    check::Outcome::fail("tool error (see exit 2)", 0)
                }
                Err(_) => {
                    tool_error = Some(format!("check \"{name}\" panicked (engine bug)"));
                    check::Outcome::fail("engine panic (see exit 2)", 0)
                }
            }
        };
        match outcome.result {
            Res::Pass => {}
            Res::Fail => failed += 1,
            Res::Na => na += 1,
        }
        events::append(
            log,
            &Event::CheckFinish {
                run_id: &run_id,
                index,
                name: &name,
                result: outcome.result.as_str(),
                duration_ms: outcome.duration_ms,
                evidence_hash: &outcome.evidence_hash(),
            },
        )
        .map_err(|e| format!("ledger write: {e}"))?;
        results.push((index, name, kind, outcome));
    }

    let duration_ms = events::now_ms().saturating_sub(started_at);
    // 三态收紧（2026-10-08）：**全部 na 不等于通过**。
    //
    // 背景：`na` 由两处产生 —— `disabled`（规则被关）与 `scope mismatch`
    // （规则作用域不匹配，见 policy.rs:342-350）。二者都计入 report.checks，
    // 因此 manifest.rs:182 的 "defines no checks（empty gate = false confidence）"
    // 守卫**不会**触发。原先 `verdict = if failed == 0 { "pass" }` 会把
    // "所有规则都 disabled / 都作用域不匹配" 报成 pass + exit 0 ⇒ **静默绿灯**，
    // 与 2026-10-08 那次门禁假红（环境故障被当真实漂移）属同一类：状态被压平。
    //
    // 新判据：failed == 0 且 pass == 0 且 total > 0 ⇒ inconclusive（退出码 2）。
    let total = results.len();
    let pass = total.saturating_sub(failed + na);
    let all_inconclusive = total > 0 && failed == 0 && pass == 0;

    // 静音棘轮（2026-10-09）：`enabled = false` 能让一条**上次还在判**的检查
    // 从绿灯里消失，而运行仍然 exit 0。判据：上一条同 manifest 的**已完成**运行里
    // 该检查判过（pass/fail），这次是 na，且未在 `[meta] silence-ok` 里声明
    // ⇒ inconclusive（exit 2）。"不再判"既不是通过，也不是真实漂移。
    let silenced = match log {
        Some(p) => match ledger::load(p) {
            Ok(lines) => {
                silence::newly_silenced(&lines, &run_id, &manifest_s, &disabled_now, &silence_ok)
            }
            // 台账读不动不是判定结论：宁可退回"没有基线可比"，也不误报静音。
            Err(_) => Vec::new(),
        },
        None => Vec::new(),
    };

    let verdict = if failed > 0 {
        "fail"
    } else if all_inconclusive || !silenced.is_empty() {
        "inconclusive"
    } else {
        "pass"
    };
    if !silenced.is_empty() {
        eprintln!(
            "verify-gate: {} 条检查本次被静音（上次运行里还判过，这次 enabled = false）：{} —— \
             不再判定不等于通过（inconclusive）。若是有意为之，请把名字写进 manifest 的 \
             [meta] silence-ok。",
            silenced.len(),
            silenced.join(", ")
        );
    }
    if all_inconclusive {
        eprintln!(
            "verify-gate: 全部 {total} 条检查都是 na（disabled 或 scope 不匹配）—— \
             没有任何规则真正生效，不构成通过（inconclusive）"
        );
    }
    events::append(
        log,
        &Event::RunFinish {
            run_id: &run_id,
            verdict,
            failed,
            na,
            duration_ms,
        },
    )
    .map_err(|e| format!("ledger write: {e}"))?;

    let mut rep = report::build(
        &manifest_s,
        manifest.meta.as_ref().and_then(|m| m.name.as_deref()),
        started_at,
        duration_ms,
        verdict,
        pass,
        results,
    );
    // 静音清单进 JSON 契约：下游消费的是 JSON，"不再判"必须在契约里可见，
    // 而不是只出现在 stderr。
    rep.silenced = silenced;
    if cfg.emit == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(&rep).map_err(|e| format!("report serialize: {e}"))?
        );
    } else {
        print!("{}", report::render_pretty(&rep));
    }

    if let Some(e) = tool_error {
        eprintln!("verify-gate: tool error: {e}");
        return Ok(2);
    }
    // inconclusive（全 na / 有新静音）与 tool error 同用退出码 2：含义都是"判不了，不是通过"。
    Ok(if failed > 0 {
        1
    } else if all_inconclusive || !rep.silenced.is_empty() {
        2
    } else {
        0
    })
}

fn cmd_policy(cfg: PolicyConfig) -> Result<u8, String> {
    let text = std::fs::read_to_string(&cfg.manifest)
        .map_err(|e| format!("read policy manifest {}: {e}", cfg.manifest.display()))?;
    let manifest: PolicyManifest = policy::parse(&text)
        .map_err(|e| format!("policy manifest {}: {e}", cfg.manifest.display()))?;

    let ctx_json = if cfg.context.as_os_str() == "-" {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("read run context from stdin: {e}"))?;
        s
    } else {
        std::fs::read_to_string(&cfg.context)
            .map_err(|e| format!("read run context {}: {e}", cfg.context.display()))?
    };
    let ctx: RunContext = serde_json::from_str(&ctx_json)
        .map_err(|e| format!("run context {}: {e}", cfg.context.display()))?;

    let started_at = events::now_ms();
    let run_id = events::new_run_id();
    let version = env!("CARGO_PKG_VERSION");
    let cwd_s = ctx.workspace.clone().unwrap_or_else(|| ".".to_string());
    let manifest_s = cfg.manifest.to_string_lossy().into_owned();
    let log = cfg.log.as_deref();

    events::append(
        log,
        &Event::RunStart {
            run_id: run_id.clone(),
            version,
            ts: started_at,
            cwd: &cwd_s,
            manifest: &manifest_s,
            check_count: manifest.rule.len(),
        },
    )
    .map_err(|e| format!("ledger write: {e}"))?;

    let results = policy::evaluate(&manifest, &ctx).map_err(|e| format!("policy evaluate: {e}"))?;

    let mut failed = 0usize;
    let mut na = 0usize;
    for (index, name, kind, outcome) in &results {
        match outcome.result {
            Res::Pass => {}
            Res::Fail => failed += 1,
            Res::Na => na += 1,
        }
        events::append(
            log,
            &Event::CheckStart {
                run_id: &run_id,
                index: *index,
                name,
                r#type: kind,
            },
        )
        .map_err(|e| format!("ledger write: {e}"))?;
        events::append(
            log,
            &Event::CheckFinish {
                run_id: &run_id,
                index: *index,
                name,
                result: outcome.result.as_str(),
                duration_ms: outcome.duration_ms,
                evidence_hash: &outcome.evidence_hash(),
            },
        )
        .map_err(|e| format!("ledger write: {e}"))?;
    }

    let duration_ms = events::now_ms().saturating_sub(started_at);
    // 与 cmd_run 同一判据（见 cmd_run 处的长注释）：全部 na ≠ 通过。
    let total = results.len();
    let pass = total.saturating_sub(failed + na);
    let all_inconclusive = total > 0 && failed == 0 && pass == 0;
    let verdict = if failed > 0 {
        "fail"
    } else if all_inconclusive {
        "inconclusive"
    } else {
        "pass"
    };
    if all_inconclusive {
        eprintln!(
            "verify-gate: 全部 {total} 条检查都是 na（disabled 或 scope 不匹配）—— \
             没有任何规则真正生效，不构成通过（inconclusive）"
        );
    }
    events::append(
        log,
        &Event::RunFinish {
            run_id: &run_id,
            verdict,
            failed,
            na,
            duration_ms,
        },
    )
    .map_err(|e| format!("ledger write: {e}"))?;

    let rep = report::build(
        &manifest_s,
        manifest.meta.as_ref().and_then(|m| m.name.as_deref()),
        started_at,
        duration_ms,
        verdict,
        pass,
        results,
    );
    if cfg.emit == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(&rep).map_err(|e| format!("report serialize: {e}"))?
        );
    } else {
        print!("{}", report::render_pretty(&rep));
    }

    // inconclusive 与 tool error 同用退出码 2：含义都是"判不了，不是通过"。
    Ok(if failed > 0 {
        1
    } else if all_inconclusive {
        2
    } else {
        0
    })
}

fn cmd_status(log: &Path, limit: usize) -> Result<(), String> {
    if !log.exists() {
        println!("no ledger at {}", log.display());
        return Ok(());
    }
    let lines = ledger::load(log)?;
    let runs = ledger::fold(&lines);
    if runs.is_empty() {
        println!("ledger empty");
        return Ok(());
    }
    println!(
        "{:<22} {:<8} {:<9} {:<5} {:<6} duration_ms",
        "run_id", "verdict", "checks", "fail", "na"
    );
    for r in runs.iter().take(limit) {
        let verdict = if r.interrupted {
            "interrupted".to_string()
        } else {
            r.verdict.clone().unwrap_or_else(|| "?".into())
        };
        println!(
            "{:<22} {:<8} {:<9} {:<5} {:<6} {}",
            r.run_id,
            verdict,
            r.check_count
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".into()),
            r.failed
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".into()),
            r.na.map(|c| c.to_string()).unwrap_or_else(|| "?".into()),
            r.finished_ts
                .map(|t| t.saturating_sub(r.started_ts.unwrap_or(t)).to_string())
                .unwrap_or_else(|| "?".into()),
        );
    }
    if runs.len() > limit {
        println!("… {} more", runs.len() - limit);
    }
    Ok(())
}

fn cmd_log(log: &Path, run_id: &str) -> Result<(), String> {
    if !log.exists() {
        return Err(format!("no ledger at {}", log.display()));
    }
    let lines = ledger::load(log)?;
    let runs = ledger::fold(&lines);
    let run = runs
        .iter()
        .find(|r| r.run_id == run_id)
        .ok_or_else(|| format!("run {run_id:?} not found"))?;
    println!(
        "run {run_id} — verdict: {}",
        run.verdict.clone().unwrap_or_else(|| "interrupted".into())
    );
    for c in &run.checks {
        println!(
            "  [{}] {} {} — {} ({}ms)",
            c.kind,
            c.index,
            c.name,
            c.result.clone().unwrap_or_else(|| "started-only".into()),
            c.duration_ms.unwrap_or(0)
        );
    }
    if run.interrupted {
        println!("  ⚠ run has no finish event — repaired as interrupted (crash?)");
    }
    Ok(())
}
