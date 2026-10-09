//! The silence ratchet: a check that used to be judged must not stop being
//! judged without a deliberate act.
//!
//! In `verify` mode `na` has exactly one source — `enabled = false` in the
//! manifest — so `na` is already an author declaration rather than a silent
//! degradation. But it is also the one way to make a failing check disappear
//! from a green run: the run still exits 0, with only a count in the report.
//!
//! This module compares the current run with the newest *completed* run of the
//! **same manifest** in the ledger and reports the checks that went from judged
//! (`pass`/`fail`) to `na`. A non-empty result makes the run `inconclusive`
//! (exit 2): "we no longer judge this" is not "this passes".
//!
//! The escape hatch is `[meta] silence-ok = ["name", ...]`, so silencing is an
//! enumerated, reviewable edit next to the check instead of an invisible count.
//! `policy` mode is deliberately out of scope: there `na` also comes from a
//! scope mismatch, which is a property of the run context, not of the manifest.

use crate::ledger::{self, Line};

/// Names that were judged in the newest completed run of `manifest` but are
/// `na` now, minus the ones `silence_ok` declares.
///
/// No history (or no log at all) means no verdict to compare against, so the
/// ratchet stays quiet on a first run: it can only fire when it has evidence
/// that the check used to be judged.
pub fn newly_silenced(
    lines: &[Line],
    current_run: &str,
    manifest: &str,
    na_now: &[String],
    silence_ok: &[String],
) -> Vec<String> {
    if na_now.is_empty() {
        return Vec::new();
    }
    // `fold` returns newest first, so the first match is the newest completed
    // run of this manifest that is not the run in progress.
    let previous = ledger::fold(lines).into_iter().find(|r| {
        r.run_id != current_run
            && !r.interrupted
            && r.verdict.is_some()
            && r.manifest.as_deref() == Some(manifest)
    });
    let Some(previous) = previous else {
        return Vec::new();
    };

    let mut out: Vec<String> = Vec::new();
    for c in &previous.checks {
        let judged_before = matches!(c.result.as_deref(), Some("pass") | Some("fail"));
        if judged_before
            && na_now.contains(&c.name)
            && !silence_ok.contains(&c.name)
            && !out.contains(&c.name)
        {
            out.push(c.name.clone());
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start(run: &str, manifest: &str, ts: u64) -> String {
        format!(
            r#"{{"t":"run.start","run_id":"{run}","version":"0","ts":{ts},"cwd":"/w","manifest":"{manifest}","check_count":1}}"#
        )
    }
    /// `fold` attaches a check's name from `check.start`; `check.finish` only
    /// carries the index. A fixture without this line therefore has no names,
    /// which is what made these tests fail the first time they ran.
    fn check_start(run: &str) -> String {
        format!(r#"{{"t":"check.start","run_id":"{run}","index":0,"name":"lint","type":"cmd"}}"#)
    }
    fn finish(run: &str, result: &str) -> String {
        format!(
            r#"{{"t":"check.finish","run_id":"{run}","index":0,"name":"lint","result":"{result}","duration_ms":1,"evidence_hash":"h"}}"#
        )
    }
    fn done(run: &str, verdict: &str, ts: u64) -> String {
        format!(
            r#"{{"t":"run.finish","run_id":"{run}","verdict":"{verdict}","failed":0,"na":0,"ts":{ts}}}"#
        )
    }
    fn parse(rows: &[String]) -> Vec<Line> {
        rows.iter().map(|r| ledger::parse_line(r)).collect()
    }

    #[test]
    fn a_check_that_went_from_pass_to_na_is_silenced() {
        let lines = parse(&[
            start("r1", "verify.toml", 1),
            check_start("r1"),
            finish("r1", "pass"),
            done("r1", "pass", 2),
        ]);
        let got = newly_silenced(&lines, "r2", "verify.toml", &["lint".into()], &[]);
        assert_eq!(got, vec!["lint".to_string()]);
    }

    #[test]
    fn a_declared_silence_is_allowed_and_a_stable_na_is_not_a_regression() {
        // The check is already na in the previous run: nothing was lost.
        let lines = parse(&[
            start("r1", "verify.toml", 1),
            check_start("r1"),
            finish("r1", "na"),
            done("r1", "inconclusive", 2),
        ]);
        assert!(newly_silenced(&lines, "r2", "verify.toml", &["lint".into()], &[]).is_empty());

        // pass -> na, but declared in `silence-ok`.
        let lines = parse(&[
            start("r1", "verify.toml", 1),
            check_start("r1"),
            finish("r1", "pass"),
            done("r1", "pass", 2),
        ]);
        assert!(newly_silenced(
            &lines,
            "r2",
            "verify.toml",
            &["lint".into()],
            &["lint".into()]
        )
        .is_empty());
    }

    #[test]
    fn history_from_another_manifest_or_an_unfinished_run_does_not_count() {
        // Another manifest sharing the same log must not be used as a baseline.
        let other = parse(&[
            start("r1", "policy.toml", 1),
            check_start("r1"),
            finish("r1", "pass"),
            done("r1", "pass", 2),
        ]);
        assert!(newly_silenced(&other, "r2", "verify.toml", &["lint".into()], &[]).is_empty());

        // A run with no run.finish is repaired as interrupted: no baseline.
        let dangling = parse(&[
            start("r1", "verify.toml", 1),
            check_start("r1"),
            finish("r1", "pass"),
        ]);
        assert!(newly_silenced(&dangling, "r2", "verify.toml", &["lint".into()], &[]).is_empty());

        // First run ever: nothing to compare against.
        assert!(newly_silenced(&[], "r1", "verify.toml", &["lint".into()], &[]).is_empty());
    }

    #[test]
    fn the_run_in_progress_is_never_its_own_baseline() {
        // The current run's check.finish lines are already in the file by the
        // time the ratchet looks; they must not become the baseline.
        let lines = parse(&[
            start("r2", "verify.toml", 10),
            check_start("r2"),
            finish("r2", "pass"),
            start("r1", "verify.toml", 1),
            check_start("r1"),
            finish("r1", "pass"),
            done("r1", "pass", 2),
        ]);
        let got = newly_silenced(&lines, "r2", "verify.toml", &["lint".into()], &[]);
        assert_eq!(got, vec!["lint".to_string()], "must use r1, not r2");
    }
}
