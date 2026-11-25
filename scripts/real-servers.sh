#!/usr/bin/env bash
# Passive scans of real, published MCP servers, run locally from a sandbox folder.
# Usage: scripts/real-servers.sh <sandbox dir>   (caches and installs stay inside it)
# Nothing here calls a tool or touches a remote endpoint; the servers run as local
# child processes, and the ones that read files get a throwaway folder.
set -u
cd "$(dirname "$0")/.."
S=$(cd "${1:?usage: real-servers.sh <sandbox dir>}" && pwd)
export npm_config_cache="$S/npm-cache" UV_CACHE_DIR="$S/uv-cache" UV_TOOL_DIR="$S/uv-tools" UV_TOOL_BIN_DIR="$S/uv-bin"
out=results/real-servers-2026-11; mkdir -p "$out" "$S/work/repo"

# Pinned versions: the latest releases of the day the scans were run.
(cd "$S" && mkdir -p node && cd node && [ -f package.json ] || npm init -y >/dev/null
 npm install --no-audit --no-fund @modelcontextprotocol/server-filesystem@2.4.0 \
   @modelcontextprotocol/server-memory@2.2.1 @modelcontextprotocol/server-everything@2.3.1 >/dev/null) || exit 3
uv tool install mcp-server-fetch==2026.11.18 >/dev/null && uv tool install mcp-server-git==2026.11.18 >/dev/null || exit 3
[ -d "$S/work/repo/.git" ] || (cd "$S/work/repo" && git init -q && git -c user.name=t -c user.email=t@t commit -q --allow-empty -m init)

go build -o bin/ ./cmd/mcpfuzz || exit 3
bin=bin/mcpfuzz; [ -x bin/mcpfuzz.exe ] && bin=bin/mcpfuzz.exe
nb="$S/node/node_modules/.bin"; ex=""; [ -x "$nb/mcp-server-memory.cmd" ] && ex=.cmd
declare -A cmd=(
  [filesystem]="$nb/mcp-server-filesystem$ex $S/work"
  [memory]="$nb/mcp-server-memory$ex"
  [everything]="$nb/mcp-server-everything$ex stdio"
  [fetch]="$S/uv-bin/mcp-server-fetch"
  [git]="$S/uv-bin/mcp-server-git --repository $S/work/repo"
)
[ -x "$S/uv-bin/mcp-server-fetch.exe" ] && cmd[fetch]="$S/uv-bin/mcp-server-fetch.exe" && cmd[git]="$S/uv-bin/mcp-server-git.exe --repository $S/work/repo"

for name in filesystem memory everything fetch git; do
  # 60 s per call: the Python servers need about 15 s to start on a cold cache.
  MEMORY_FILE_PATH="$S/work/memory.jsonl" $bin scan --timeout 60s --json "$out/$name.json" -- ${cmd[$name]} > "$out/$name.txt"
  echo "$name: exit $?"
done

# mcpfuzz sends its meta-less probes first, and the 2.x TypeScript servers then stay
# in legacy mode for that connection. Replay the probes that matter on fresh processes.
V='"io.modelcontextprotocol/protocolVersion"'; C='"io.modelcontextprotocol/clientCapabilities":{}'
fresh() { printf '%s\n' "$1" | MEMORY_FILE_PATH="$S/work/memory.jsonl" timeout 30 ${cmd[$2]} 2>/dev/null | head -n1; }
for name in filesystem memory everything; do
  bad=$(fresh "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{\"_meta\":{$V:\"1900-01-01\",$C}}}" $name)
  ok=$(fresh "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{\"_meta\":{$V:\"2026-07-28\",$C}}}" $name)
  none=$(fresh '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' $name)
  {
    echo "bad-version: $(echo "$bad" | cut -c1-160)"
    echo "valid-meta has resultType/ttlMs/cacheScope: $(echo "$ok" | grep -c '"resultType":"complete","ttlMs":[0-9]*,"cacheScope":"[a-z]*"')"
    echo "no-meta accepted: $(echo "$none" | grep -c '"result"')"
  } > "$out/$name.fresh.txt"
done
