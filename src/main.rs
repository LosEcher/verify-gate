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
mod report;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::check::Res;
use crate::events::Event;
use crate::manifest::Manifest;

const USAGE: &str = "\
verify-gate — declarative verification manifest executor.

Runs every assertion in a TOML manifest (file / cmd / http / git / json)
against reality, aggregates a pass/fail report, and exits 0 (all pass),
1 (any fail), or 2 (tool error: usage, manifest parse, engine bug).
Event-sourced ledger: .verify-gate/runs.jsonl.

USAGE:
  verify-gate [OPTIONS] <manifest.toml>

OPTIONS:
  --emit json|pretty     output format (default pretty)
  --log <path>           event ledger path (default .verify-gate/runs.jsonl)
  --no-log               disable the event ledger
  --cwd <dir>            assertion base directory (default: manifest dir)
  --version              print version
  --help                 print this help

SUBCOMMANDS:
  status [--log <path>] [--limit N]
                        list runs; dangling runs (start without finish) are
                        shown as interrupted
  log <runId> [--log <path>]
                        full event chain of one run + rebuilt summary

EXIT CODES: 0 pass · 1 fail · 2 tool error.

MANIFEST (TOML): a list of [[check]] entries. See README for the full
reference. Every check needs: name, type (file|cmd|http|git|json) and the
type-specific assertions. enabled = false marks a check as na.
";

#[derive(Debug)]
struct Config {
    emit: String,
    log: Option<PathBuf>,
    cwd: Option<PathBuf>,
    manifest: PathBuf,
}

enum Cli {
    Run(Config),
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
    let verdict = if failed == 0 { "pass" } else { "fail" };
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

    if let Some(e) = tool_error {
        eprintln!("verify-gate: tool error: {e}");
        return Ok(2);
    }
    Ok(if failed == 0 { 0 } else { 1 })
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
