#!/usr/bin/env bash
# verify-gate mechanical acceptance gates (P0).
#
# Every gate is exit-non-zero: prose is not a guard, this script is.
# Run from the repo root:  bash test/gates.sh
#
# Fixtures are created in a temp dir; nothing outside it is touched.
# The http gate needs python3 (spawns a throwaway http.server).

set -u

if [ -d "$HOME/.cargo/bin" ]; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi
if [ -d "/opt/homebrew/bin" ]; then
  export PATH="/opt/homebrew/bin:$PATH"
fi

VG=${VG:-"$PWD/target/debug/verify-gate"}
FIX="$PWD/test/fixtures"
FAILS=0

note() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILS=$((FAILS + 1)); }
expect_exit() { # desc expected actual
  if [ "$2" -eq "$3" ]; then pass "$1"; else fail "$1 (expected exit $2, got $3)"; fi
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

if [ ! -x "$VG" ]; then
  echo "binary not found: $VG (run: cargo build)"
  exit 2
fi

# ---------------------------------------------------------------- G1 pass
note "G1: pass manifest exits 0"
"$VG" --no-log "$FIX/pass.toml" >/dev/null 2>&1
expect_exit "pass.toml exits 0" 0 $?

# ---------------------------------------------------------------- G2 fail
note "G2: fail manifest exits 1"
"$VG" --no-log "$FIX/fail.toml" >/dev/null 2>&1
expect_exit "fail.toml exits 1" 1 $?

# ---------------------------------------------------------------- G3 broken
note "G3: broken manifest exits 2"
"$VG" --no-log "$FIX/broken.toml" >/dev/null 2>&1
expect_exit "broken.toml exits 2" 2 $?

# ---------------------------------------------------------------- G4 ledger
note "G4: ledger written + status + interrupted repair"
LEDGER="$WORK/ledger.jsonl"
"$VG" --log "$LEDGER" "$FIX/pass.toml" >/dev/null 2>&1
if [ -s "$LEDGER" ]; then pass "ledger written"; else fail "ledger missing"; fi
"$VG" status --log "$LEDGER" 2>/dev/null | grep -q 'pass' && pass "status shows pass" || fail "status missing pass"
# dangling run.start → repaired as interrupted
echo '{"t":"run.start","run_id":"run-dangling-1","version":"x","ts":1,"cwd":"/tmp","manifest":"x","check_count":1}' >>"$LEDGER"
"$VG" status --log "$LEDGER" 2>/dev/null | grep -q 'interrupted' && pass "dangling repaired as interrupted" || fail "no interrupted repair"

# ---------------------------------------------------------------- G5 file matrix
note "G5: file check matrix"
"$VG" --no-log "$FIX/pass.toml" >/dev/null 2>&1
expect_exit "not_exists passes" 0 $?
cat >"$WORK/file-fail.toml" <<'EOF'
[[check]]
name = "must be absent"
type = "file"
path = "sample.json"
expect = "not_exists"
EOF
(cd "$FIX" && "$VG" --no-log --cwd "$FIX" "$WORK/file-fail.toml" >/dev/null 2>&1)
expect_exit "not_exists on existing file fails (exit 1)" 1 $?
cat >"$WORK/regex.toml" <<'EOF'
[[check]]
name = "regex match"
type = "file"
path = "sample.json"
regex = '"name"[ \t]*:[ \t]*"verify-gate"'
EOF
(cd "$FIX" && "$VG" --no-log --cwd "$FIX" "$WORK/regex.toml" >/dev/null 2>&1)
expect_exit "regex passes" 0 $?

# ---------------------------------------------------------------- G6 cmd matrix
note "G6: cmd check matrix"
cat >"$WORK/cmd-pass.toml" <<'EOF'
[[check]]
name = "exit + stdout"
type = "cmd"
cmd = "echo hello && exit 0"
stdout_contains = "hello"
EOF
(cd "$WORK" && "$VG" --no-log "$WORK/cmd-pass.toml" >/dev/null 2>&1)
expect_exit "cmd pass" 0 $?
cat >"$WORK/cmd-fail.toml" <<'EOF'
[[check]]
name = "wrong exit"
type = "cmd"
cmd = "exit 7"
exit = 0
EOF
(cd "$WORK" && "$VG" --no-log "$WORK/cmd-fail.toml" >/dev/null 2>&1)
expect_exit "cmd wrong exit fails (1)" 1 $?
cat >"$WORK/cmd-timeout.toml" <<'EOF'
[[check]]
name = "timeout is a failure"
type = "cmd"
cmd = "sleep 5"
timeout_secs = 1
EOF
(cd "$WORK" && "$VG" --no-log "$WORK/cmd-timeout.toml" >/dev/null 2>&1)
expect_exit "cmd timeout fails fast (1)" 1 $?

# ---------------------------------------------------------------- G7 git matrix
note "G7: git check matrix"
GITFIX="$WORK/gitfix"
mkdir -p "$GITFIX"
( cd "$GITFIX" \
  && git init -q \
  && git config user.email t@v-g.local \
  && git config user.name "vg test" \
  && echo x > a.txt \
  && git add -A \
  && git commit -qm init )
cat >"$WORK/git-clean.toml" <<'EOF'
[[check]]
name = "clean"
type = "git"
expect = "clean"
EOF
( cd "$GITFIX" && "$VG" --no-log --cwd "$GITFIX" "$WORK/git-clean.toml" >/dev/null 2>&1 )
expect_exit "clean worktree passes" 0 $?
echo dirty >>"$GITFIX/a.txt"
( cd "$GITFIX" && "$VG" --no-log --cwd "$GITFIX" "$WORK/git-clean.toml" >/dev/null 2>&1 )
expect_exit "dirty worktree fails (1)" 1 $?
cat >"$WORK/git-branch.toml" <<'EOF'
[[check]]
name = "branch"
type = "git"
expect = "branch"
branch = "main"
EOF
( cd "$GITFIX" && git checkout -qb main 2>/dev/null; "$VG" --no-log --cwd "$GITFIX" "$WORK/git-branch.toml" >/dev/null 2>&1 )
expect_exit "branch check passes" 0 $?

# ---------------------------------------------------------------- G8 json matrix
note "G8: json check matrix"
cat >"$WORK/json-fail.toml" <<'EOF'
[[check]]
name = "wrong value"
type = "json"
path = "sample.json"
field = "version"
equals = "9.9.9"
EOF
( cd "$FIX" && "$VG" --no-log --cwd "$FIX" "$WORK/json-fail.toml" >/dev/null 2>&1 )
expect_exit "json mismatch fails (1)" 1 $?

# ---------------------------------------------------------------- G9 http matrix
note "G9: http check matrix"
if ! command -v python3 >/dev/null 2>&1; then
  fail "G9 needs python3 (not found)"
else
  PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
  HTTPDIR="$WORK/httpdir"
  mkdir -p "$HTTPDIR"
  echo "verify-gate-http-ok" >"$HTTPDIR/hello.txt"
  python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$HTTPDIR" >/dev/null 2>&1 &
  HTTP_PID=$!
  # wait until the server actually answers (up to 10s)
  READY=0
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if curl -s -o /dev/null "http://127.0.0.1:$PORT/hello.txt"; then READY=1; break; fi
    sleep 0.5
  done
  if [ "$READY" -eq 1 ]; then pass "http server ready"; else fail "http server never ready (port $PORT)"; fi
  cat >"$WORK/http.toml" <<EOF
[[check]]
name = "endpoint 200 + body"
type = "http"
url = "http://127.0.0.1:$PORT/hello.txt"
status = 200
body_contains = "http-ok"
EOF
  if ! "$VG" --emit json --no-log "$WORK/http.toml" >"$WORK/http-report.json" 2>&1; then
    cat "$WORK/http-report.json"
  fi
  expect_exit "http 200 + body passes" 0 $?
cat >"$WORK/http-404.toml" <<EOF
[[check]]
name = "missing path"
type = "http"
url = "http://127.0.0.1:$PORT/missing.txt"
status = 200
EOF
"$VG" --no-log "$WORK/http-404.toml" >/dev/null 2>&1
  expect_exit "http 404 fails (1)" 1 $?
  kill "$HTTP_PID" 2>/dev/null
  wait "$HTTP_PID" 2>/dev/null
fi

# ---------------------------------------------------------------- G10 na
note "G10: disabled checks are na, not failures"
"$VG" --no-log "$FIX/na.toml" >/dev/null 2>&1
expect_exit "na manifest exits 0" 0 $?

# ---------------------------------------------------------------- G11 self-bootstrap
note "G11: self-bootstrap (verify.toml on this repo)"
"$VG" --no-log "$PWD/verify.toml" >/dev/null 2>&1
expect_exit "verify.toml exits 0" 0 $?

# ---------------------------------------------------------------- G12 emit json
note "G12: --emit json is machine-consumable"
"$VG" --emit json --no-log "$FIX/pass.toml" 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["verdict"] == "pass", d
assert len(d["checks"]) >= 1
print("  json report ok")
'
expect_exit "json emit parses" 0 $?

# ---------------------------------------------------------------- summary
note "SUMMARY"
if [ "$FAILS" -eq 0 ]; then
  echo "all gates passed"
  exit 0
else
  echo "$FAILS gate(s) failed"
  exit 1
fi
