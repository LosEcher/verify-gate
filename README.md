# verify-gate

**Declarative verification manifest executor for AI agents.** Point it at a
TOML checklist of typed assertions (file / cmd / http / git / json), it runs
each one against reality, aggregates a pass/fail report, and returns a strict
exit code:

- `0` — every check passed
- `1` — at least one check failed
- `2` — tool error (usage, unparseable manifest, engine bug)

```
verify-gate verify.toml
```

For AI agents this turns "make sure it's right" from prose into a mechanical
gate: a manifest is declarative ("what counts as correct"), the executor is
deterministic, and the event-sourced ledger (`.verify-gate/runs.jsonl`) makes
replay and audit structurally free — dangling runs are repaired as
`interrupted`, mirroring event-sourced session repair semantics.

## Why

1. **Verification is prose, not a gate** — agents and humans describe "should
   work" in natural language; there is no mechanical, machine-checkable
   contract of what "done" means.
2. **Exit codes lie by omission** — a command that exits `0` can still be
   wrong (wrong file content, wrong endpoint, wrong branch).
3. **No audit trail** — nothing records *what was checked, when, with which
   evidence*, so a later failure is a mystery instead of a diff.

`verify-gate` fixes the contract: the manifest is the spec, the exit code is
the verdict, the ledger is the evidence trail.

## Manifest

A TOML file with a list of `[[check]]` entries. Each check needs `name` and
`type`; the remaining fields are type-specific assertions.

```toml
[meta]
name = "my-project-verify"   # optional, for readable ledgers

# --- file -------------------------------------------------------------
[[check]]
name = "entry exists"
type = "file"
path = "src/main.rs"
expect = "exists"            # exists | not_exists (default exists)

[[check]]
name = "readme mentions usage"
type = "file"
path = "README.md"
contains = "verify-gate"

[[check]]
name = "no leftover todo markers"
type = "file"
path = "src/"
not_contains = "FIXME"

[[check]]
name = "version format"
type = "file"
path = "Cargo.toml"
regex = '(?m)^version[ \t]*=[ \t]*"0\.[0-9]+\.[0-9]+"$'

# --- cmd --------------------------------------------------------------
[[check]]
name = "tests pass"
type = "cmd"
cmd = "cargo test"
exit = 0                      # default 0
stdout_contains = "test result: ok"
timeout_secs = 180            # default 60; a timeout is a FAILURE, not a tool error

# --- http -------------------------------------------------------------
[[check]]
name = "gateway healthy"
type = "http"
url = "http://127.0.0.1:8080/healthz"
status = 200                  # default 200
body_contains = "ok"
timeout_secs = 10             # default 10

# --- git --------------------------------------------------------------
[[check]]
name = "worktree clean"
type = "git"
expect = "clean"              # clean | branch

[[check]]
name = "on main"
type = "git"
expect = "branch"
branch = "main"

# --- json -------------------------------------------------------------
[[check]]
name = "package name"
type = "json"
path = "package.json"
field = "name"                # dotted path, array index: deps.serde.features[0]
equals = "verify-gate"

# --- disable without deleting ------------------------------------------
[[check]]
name = "skipped in this env"
type = "cmd"
cmd = "exit 1"
enabled = false               # → reported as na (not counted as failure)
```

Check semantics:

- `file` — `path` (required); `expect` (`exists`/`not_exists`); at most one of
  `contains` / `not_contains` / `regex`.
- `cmd` — `cmd` (required, run through the platform shell: `sh -c` on unix,
  `cmd /C` on Windows); `exit` (default `0`); optional `stdout_contains` /
  `stderr_contains` / `stdout_regex` / `stderr_regex`; `timeout_secs`
  (default `60`, output capped at 64 KiB keep-tail).
- `http` — `url` (required); `status` (default `200`); optional
  `body_contains`; network errors count as failures.
- `git` — `expect` `clean` (worktree has no uncommitted changes) or `branch`
  (current branch equals `branch`).
- `json` — `path` + `field` (dotted, with `[n]` array indexes); either
  `equals <json literal>` or `exists = true`.

## CLI

```
verify-gate [OPTIONS] <manifest.toml>

  --emit json|pretty    output format (default pretty)
  --log <path>          event ledger (default .verify-gate/runs.jsonl)
  --no-log              disable the ledger
  --cwd <dir>           assertion base dir (default: manifest dir)

verify-gate status [--log <path>] [--limit N]
verify-gate log <runId> [--log <path>]
```

`status` lists runs newest-first; runs without a finish event are shown as
`interrupted`. `log <runId>` prints one run's full event chain. Ledger events
carry only evidence hashes — never plaintext check output — so secrets in
command output stay out of the audit trail.

## Exit codes

| code | meaning |
|---|---|
| 0 | all checks passed (na checks do not count) |
| 1 | at least one check failed |
| 2 | tool error: usage, unparseable manifest, engine bug |

Use the exit code as the gate — not the output text.

## Companion tools

- [`sandbox-run`](https://github.com/LosEcher/sandbox-run) — run verification
  in an isolated git worktree / jj workspace (answers "where to run").
- [`fmtguard`](https://github.com/LosEcher/fmtguard) — scoped, gated rustfmt
  for incremental changes (answers "is the diff formatted").
- `verify-gate` answers "did the result actually pass the spec".

Combined: `sandbox-run -- <verify cmd>` (isolate) → `verify-gate verify.toml`
(assert) → ship only when the exit code is 0.

## Build & test

```
cargo build --release
cargo test                 # unit tests
bash test/gates.sh         # mechanical acceptance gates (exit-non-zero)
./target/debug/verify-gate verify.toml   # self-bootstrap
```

## License

MIT
