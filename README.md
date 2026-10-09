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

## Policy mode (policy-gate)

`verify-gate policy` evaluates a **policy manifest** (guardrails) against a
**run context** (JSON: what a run actually did) and returns the same strict
exit code: `0` no violations · `1` at least one violation · `2` tool error **or inconclusive (every rule `na`)**.
This is the Policy pillar of the agent kernel: mechanical, declarative
guardrails instead of prose conventions. The shape is modeled on InstantDB's
CEL permission system (parse-time validation, explicit allow/deny, scoped
rules) but P0 uses structured rule kinds — no free-form expression DSL.

```
verify-gate policy --manifest policy.toml --context ctx.json [--emit json|pretty]
                   [--log <path>] [--no-log]        # --context - reads stdin
```

**Run context** (`--context`, JSON; `-` reads stdin):

```json
{
  "profile": "headless",
  "workspace": "/Users/echerlos/syncthing/project/dsfolder",
  "retries": { "llm_request": 2 },
  "tool_calls": [ { "name": "bash", "args": "ls" } ],
  "outputs": [ { "tool": "bash", "text": "..." } ],
  "cmd_lines": ["bash tools/los.sh restart"]
}
```

Missing fields are treated as empty (never an error). The caller (DSH plugin /
CI) collects the context after a run and evaluates.

**Policy manifest** (TOML): a list of `[[rule]]` entries. Every rule needs
`id` and `type`; the remaining fields are type-specific. Rules may carry a
`scope = { profile = "x" }` or `{ workspace = "substring" }`; a rule whose
scope does not match the context evaluates to `na` (not a failure).

```toml
[meta]
name = "dsh-default-policy"

[[rule]]
id = "headless-no-channel"
type = "tool-denylist"
scope = { profile = "headless" }
deny = ["de_channel_send", "de_notify"]

[[rule]]
id = "no-secret-in-output"
type = "output-regex-deny"
regex = 'sk-[A-Za-z0-9]{20,}'

[[rule]]
id = "per-turn-call-cap"
type = "tool-call-limit"
scope = { profile = "headless" }
max = 60

[[rule]]
id = "retry-cap"
type = "retry-limit"
field = "llm_request"
max = 5

[[rule]]
id = "no-prod-restart"
type = "cmd-deny"
regex = 'los\.sh\s+restart|restart\s+/governance'
```

Rule kinds:

| type | fields | violation when |
|---|---|---|
| `tool-denylist` | `deny: [tool...]` | any called tool is in the list |
| `tool-allowlist` | `allow: [tool...]` | any called tool is not in the list |
| `output-regex-deny` | `regex` | any output matches (detail never echoes the matched text — it may itself be a secret) |
| `tool-call-limit` | `max` | tool calls exceed `max` |
| `retry-limit` | `field, max` | `retries[field]` exceeds `max` (missing = 0) |
| `cmd-deny` | `regex` | any command line matches |

Parse-time validation (mirroring CEL parse checks): unknown kind, missing
required fields, empty lists, or an invalid regex → exit `2` (author bug, not
a policy violation).

## CLI

```
verify-gate [OPTIONS] <manifest.toml>

  --emit json|pretty    output format (default pretty)
  --log <path>          event ledger (default .verify-gate/runs.jsonl)
  --no-log              disable the ledger
  --cwd <dir>           assertion base dir (default: manifest dir)

verify-gate policy --manifest <policy.toml> --context <ctx.json|->
                   [--emit json|pretty] [--log <path>] [--no-log]
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
| 0 | at least one check **passed**, none failed, and no check was newly silenced (na checks do not count either way) |
| 1 | at least one check failed |
| 2 | **inconclusive** (every check is `na`, or a check was newly silenced) **or** tool error: usage, unparseable manifest, engine bug |

### `na` is not a pass

A check is `na` when it is `enabled = false`, or (for policy rules) when its
`scope` does not match the context. `na` counts as neither pass nor fail.

**But a gate where *everything* is `na` proves nothing.** Since 2026-10-08 that
case reports `verdict: "inconclusive"` and exits **2** (same code as a tool
error, because both mean "could not judge"). Before that fix it reported
`verdict: "pass"` and exited `0`, so a fully-disabled manifest — or one whose
rules all failed their scope check — read as a green gate.

The JSON report carries `passed` (count of real passes) alongside `checks[]`,
so `passed: 0` with `verdict: "inconclusive"` is distinguishable from a real
pass at the machine level. This mirrors the fail-closed guard for a manifest
that defines *no* checks (`empty gate = false confidence`), which exits 2.

### Silence ratchet: what was judged must not stop being judged (2026-10-09)

`enabled = false` is the one way to make a check disappear from a green run:
`pass → na` leaves the verdict `pass` and the exit code `0`, with only a count
in the report. A single check going quiet is not covered by the all-`na` rule
above.

So when a ledger exists, each run compares itself with the newest **completed**
run of the **same manifest** and reports the checks that went from judged
(`pass`/`fail`) to `na` in `silenced[]`. A non-empty `silenced[]` reports
`verdict: "inconclusive"` and exits **2** — "no longer judged" is neither a pass
nor a verified failure.

Silencing a check on purpose is declared next to the check, not discovered later:

```toml
[meta]
silence-ok = ["check name that is intentionally off"]
```

That list is the escape hatch, and it is a bounded, reviewable edit: without it,
a deliberate silencing keeps exiting 2 and the stderr message names the checks.
A first run (no history) never fires the ratchet, and policy rules are out of
scope because there `na` can also come from a scope mismatch about the *context*
rather than a decision in the manifest.

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
