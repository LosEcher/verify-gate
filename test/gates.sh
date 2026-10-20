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

# G10b 全部 na **不等于通过**（2026-10-08 修复的静默绿灯）。
# 起因：verdict 原为 `if failed == 0 { "pass" }`，而 na 不计入 failed ⇒
# "所有 check 都 disabled / 都作用域不匹配"会报 pass + exit 0。
# 修法：failed == 0 且 pass == 0 且 total > 0 ⇒ verdict "inconclusive" + exit 2。
"$VG" --no-log "$FIX/all-na.toml" >/dev/null 2>&1
expect_exit "all-na manifest exits 2 (inconclusive, NOT pass)" 2 $?
"$VG" --no-log --emit json "$FIX/all-na.toml" 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert d["verdict"] == "inconclusive", d["verdict"]
assert d["passed"] == 0, d["passed"]
assert all(c["result"] == "na" for c in d["checks"]), d["checks"]
print("  all-na verdict/exit ok")
'
# 负向控制：混合清单（有真 pass）必须仍然是 pass + exit 0，不得因新判据误报。
"$VG" --no-log "$FIX/na.toml" >/dev/null 2>&1
expect_exit "mixed pass+na still exits 0 (no false inconclusive)" 0 $?

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

# ---------------------------------------------------------------- G13 policy pass
note "G13: policy manifest + clean context exits 0"
"$VG" policy --manifest "$FIX/policy.toml" --context "$FIX/ctx-clean.json" --no-log >/dev/null 2>&1
expect_exit "policy clean exits 0" 0 $?

# ---------------------------------------------------------------- G14 policy violation
note "G14: policy manifest + violating context exits 1"
"$VG" policy --manifest "$FIX/policy.toml" --context "$FIX/ctx-violation.json" --no-log >/dev/null 2>&1
expect_exit "policy violation exits 1" 1 $?
# and the report names the offending rules without echoing the secret
"$VG" policy --emit json --manifest "$FIX/policy.toml" --context "$FIX/ctx-violation.json" --no-log 2>/dev/null \
  | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["verdict"] == "fail", d
fails = [c for c in d["checks"] if c["result"] == "fail"]
ids = [c["name"] for c in fails]
assert "headless-no-channel" in ids, ids
assert "no-secret-in-output" in ids, ids
assert "no-prod-restart" in ids, ids
for c in fails:
    assert "sk-" not in c["detail"], c["detail"]
print("  policy report ok (offenses listed, secret not echoed)")
'
expect_exit "policy json report parses" 0 $?

# ---------------------------------------------------------------- G15 policy bad manifest
note "G15: bad policy manifest exits 2"
"$VG" policy --manifest "$FIX/bad-policy.toml" --context "$FIX/ctx-clean.json" --no-log >/dev/null 2>&1
expect_exit "bad policy manifest exits 2" 2 $?

# ---------------------------------------------------------------- G16 policy scope na
note "G16: scope mismatch is na, not a failure"
WEBCTX="$WORK/web-ctx.json"
echo '{"profile":"web","tool_calls":[{"name":"de_channel_send"}]}' >"$WEBCTX"
"$VG" policy --emit json --manifest "$FIX/policy.toml" --context "$WEBCTX" --no-log 2>/dev/null \
  | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["verdict"] == "pass", d
na = [c for c in d["checks"] if c["result"] == "na"]
assert any(c["name"] == "headless-no-channel" for c in na), [c["name"] for c in d["checks"]]
print("  scope na ok")
'
expect_exit "policy scope na passes" 0 $?

# ---------------------------------------------------------------- G17 policy ledger
note "G17: policy run writes the ledger + status + stdin context"
LEDGER2="$WORK/policy-ledger.jsonl"
"$VG" policy --manifest "$FIX/policy.toml" --context "$FIX/ctx-violation.json" --log "$LEDGER2" >/dev/null 2>&1
expect_exit "policy violation exits 1 (ledger mode)" 1 $?
if [ -s "$LEDGER2" ]; then pass "policy ledger written"; else fail "policy ledger missing"; fi
"$VG" status --log "$LEDGER2" 2>/dev/null | grep -q 'fail' && pass "policy status shows fail" || fail "policy status missing fail"
echo '{"profile":"headless","tool_calls":[]}' | "$VG" policy --manifest "$FIX/policy.toml" --context - --no-log >/dev/null 2>&1
expect_exit "policy context from stdin works" 0 $?

# ---------------------------------------------------------------- G18 silence ratchet
note "G18: 静音棘轮 — 上次判过、这次 enabled=false ⇒ inconclusive（exit 2）"
D="$WORK/g18"
mkdir -p "$D"
RLOG="$D/runs.jsonl"

# 基线：两条都真判过
cat > "$D/m.toml" <<'EOF'
[meta]
name = "g18 ratchet"

[[check]]
name = "judged then silenced"
type = "cmd"
cmd = "true"

[[check]]
name = "always judged"
type = "cmd"
cmd = "true"
EOF
( cd "$D" && "$VG" m.toml --log "$RLOG" >/dev/null 2>&1 )
expect_exit "G18 baseline: both checks judged" 0 $?

# arm 1：静音其一且未声明 ⇒ exit 2，且 JSON 点名
cat > "$D/m.toml" <<'EOF'
[meta]
name = "g18 ratchet"

[[check]]
name = "judged then silenced"
type = "cmd"
cmd = "true"
enabled = false

[[check]]
name = "always judged"
type = "cmd"
cmd = "true"
EOF
( cd "$D" && "$VG" m.toml --log "$RLOG" --emit json >"$D/a.json" 2>"$D/a.err" ); RC=$?
expect_exit "G18 arm1: undeclared silence exits 2" 2 "$RC"
python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
assert d["verdict"] == "inconclusive", d["verdict"]
assert d["silenced"] == ["judged then silenced"], d["silenced"]
assert d["passed"] == 1, d["passed"]
print("  silenced check named in JSON + verdict inconclusive")
' "$D/a.json" || fail "G18 arm1: JSON does not name the silenced check"
grep -q 'judged then silenced' "$D/a.err" && pass "G18 arm1: stderr names the silenced check" || fail "G18 arm1: stderr does not name it"

# arm 2：同一状态但写进 [meta] silence-ok ⇒ 回到 pass + exit 0
cat > "$D/m.toml" <<'EOF'
[meta]
name = "g18 ratchet"
silence-ok = ["judged then silenced"]

[[check]]
name = "judged then silenced"
type = "cmd"
cmd = "true"
enabled = false

[[check]]
name = "always judged"
type = "cmd"
cmd = "true"
EOF
( cd "$D" && "$VG" m.toml --log "$RLOG" --emit json >"$D/b.json" 2>/dev/null ); RC=$?
expect_exit "G18 arm2: declared silence exits 0" 0 "$RC"
python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
assert d["verdict"] == "pass", d["verdict"]
assert d["silenced"] == [], d["silenced"]
print("  declared silence accepted (escape hatch works)")
' "$D/b.json" || fail "G18 arm2: declared silence must not be reported"

# arm 3（负向控制）：没有历史 ⇒ 不得误报（首跑无基线可判）
cat > "$D/fresh.toml" <<'EOF'
[meta]
name = "g18 fresh"

[[check]]
name = "never judged before"
type = "cmd"
cmd = "true"
enabled = false

[[check]]
name = "real pass"
type = "cmd"
cmd = "true"
EOF
( cd "$D" && "$VG" fresh.toml --log "$D/fresh.jsonl" >/dev/null 2>&1 )
expect_exit "G18 arm3: no history ⇒ no false silence (negative control)" 0 $?

# ---------------------------------------------------------------- G19 idle (silence) deadline
# 沉默超时：`idle_secs` = 相邻两段输出之间的最大间隔，缺省关闭（0）。
# 触发 ⇒ result = "stalled"，**计入失败（exit 1）**，与 timed out 同码不同标签。
note "G19: idle_secs (silence deadline) — 卡死与慢必须分开判"
cat >"$WORK/idle-stall.toml" <<'EOF'
[[check]]
name = "never prints"
type = "cmd"
cmd = "sleep 5"
timeout_secs = 10
idle_secs = 1
EOF
out=$("$VG" --no-log "$WORK/idle-stall.toml" 2>/dev/null); rc=$?
expect_exit "G19 arm1: silent command ⇒ stalled (1)" 1 "$rc"
case "$out" in
  *stalled*) pass "G19 arm1: report labels it stalled (not timed out)" ;;
  *) fail "G19 arm1: report does not label stalled: $out" ;;
esac
case "$out" in
  *"timed out"*) fail "G19 arm1: stalled must not be reported as timed out" ;;
  *) pass "G19 arm1: not mislabelled as timed out" ;;
esac

# 负向控制：慢但出声 ⇒ 必须 pass。这是"常报警=没报警"的那道闸门：
# 若 idle 判据按总沉默（而不是按相邻间隔）算，慢命令会被误判成卡死。
cat >"$WORK/idle-slow.toml" <<'EOF'
[[check]]
name = "slow but audible"
type = "cmd"
cmd = "sleep 1; echo a; sleep 1; echo b"
timeout_secs = 10
idle_secs = 3
EOF
( cd "$WORK" && "$VG" --no-log "$WORK/idle-slow.toml" >/dev/null 2>&1 )
expect_exit "G19 arm2: slow-but-audible passes (negative control)" 0 $?

# 负向控制：缺省关闭。2 秒不出声但没声明 idle_secs ⇒ 不得判卡死。
cat >"$WORK/idle-off.toml" <<'EOF'
[[check]]
name = "quiet then ok, no idle declared"
type = "cmd"
cmd = "sleep 2; echo ok"
timeout_secs = 10
EOF
( cd "$WORK" && "$VG" --no-log "$WORK/idle-off.toml" >/dev/null 2>&1 )
expect_exit "G19 arm3: idle_secs absent ⇒ off by default (negative control)" 0 $?

# 声明错误：idle_secs >= timeout_secs 永远够不到 ⇒ fail-closed 报 manifest bug（exit 2）。
cat >"$WORK/idle-bad.toml" <<'EOF'
[[check]]
name = "idle never fires"
type = "cmd"
cmd = "true"
timeout_secs = 2
idle_secs = 2
EOF
( cd "$WORK" && "$VG" --no-log "$WORK/idle-bad.toml" >/dev/null 2>&1 )
expect_exit "G19 arm4: idle_secs >= timeout_secs is a manifest error (2)" 2 $?

# JSON 契约：stalled 必须是可数的独立标签，且计入 verdict=fail。
cat >"$WORK/idle-json.toml" <<'EOF'
[[check]]
name = "never prints"
type = "cmd"
cmd = "sleep 5"
timeout_secs = 10
idle_secs = 1
EOF
"$VG" --no-log --emit json "$WORK/idle-json.toml" >"$WORK/idle.json" 2>/dev/null
if grep -q '"result": "stalled"' "$WORK/idle.json" && grep -q '"stalled": 1' "$WORK/idle.json"; then
  pass "G19 arm5: JSON carries result=stalled and stalled count"
else
  fail "G19 arm5: JSON missing stalled label/count: $(head -c 300 "$WORK/idle.json")"
fi
grep -q '"verdict": "fail"' "$WORK/idle.json" \
  && pass "G19 arm5: stalled counts as failure (verdict=fail)" \
  || fail "G19 arm5: verdict should be fail"

# ---------------------------------------------------------------- summary
note "SUMMARY"
if [ "$FAILS" -eq 0 ]; then
  echo "all gates passed"
  exit 0
else
  echo "$FAILS gate(s) failed"
  exit 1
fi
