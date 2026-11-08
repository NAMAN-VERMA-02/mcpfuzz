#!/usr/bin/env bash
# Proves mcpfuzz can tell a vulnerable MCP server from a fixed one, in both
# protocol eras, with each server isolated in Docker. If it could not, none of
# its other verdicts would mean anything. CI runs this; it also runs locally.
set -u
export MSYS_NO_PATHCONV=1 # Git Bash on Windows would rewrite /work into a Windows path
cd "$(dirname "$0")/.."
go build -o bin/ ./cmd/mcpfuzz ./testservers/fixed || exit 3
docker build -q --load -t mcpfuzz-testservers -f testservers/Dockerfile . >/dev/null || exit 3
mkdir -p reports
bin=bin/mcpfuzz; [ -x bin/mcpfuzz.exe ] && bin=bin/mcpfuzz.exe
fixed=bin/fixed; [ -x bin/fixed.exe ] && fixed=bin/fixed.exe
fail=0

expect() { # expect <exit code> <label> <command...>
  local want=$1 label=$2; shift 2
  echo "::group::$label (want exit $want)"
  "$@"; local got=$?
  echo "::endgroup::"
  if [ "$got" -ne "$want" ]; then echo "FAIL $label: exit $got, want $want"; fail=1; else echo "ok   $label: exit $got"; fi
}

for era in legacy modern; do
  for pair in vulnerable:1 fixed:0; do
    srv=${pair%%:*} want=${pair##*:}
    expect "$want" "$srv/$era" "$bin" scan --image mcpfuzz-testservers --active \
      --allow-tools read_file,ping_host,add_note,echo --allowed-root /work --i-own-this-target \
      --json "reports/$srv-$era.json" -- "/usr/local/bin/$srv" -era "$era" -root /work
  done
  # Exit 1 alone could come from a passive finding; the canaries must have fired too.
  for id in active.path-traversal active.shell-injection; do
    tr -d '\n ' < "reports/vulnerable-$era.json" | grep -q "\"id\":\"$id\",\"status\":\"FINDING\"" ||
      { echo "FAIL vulnerable/$era: no confirmed $id"; fail=1; }
  done
done

# Active mode on a target that is not isolated must never pass.
expect 2 "fixed/unisolated-active" "$bin" scan --active --allow-tools echo --allowed-root /work \
  --i-own-this-target -- "$fixed" -era modern -root .

[ "$fail" -eq 0 ] && echo "e2e: all expectations met"
exit "$fail"
