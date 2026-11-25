# mcpfuzz against five real MCP servers (November 2026)

Until now mcpfuzz had only been run against the two test servers in this repo. This
page records the first run against published servers: what ran, how to repeat it, and
what the results do and don't show. Raw reports are in
[real-servers-2026-11/](real-servers-2026-11/).

**Short version: passive scans only, because Docker wasn't available. Two servers
passed. Three got `FINDINGS`, and on inspection most of those are mcpfuzz's own
mistakes. No server bug was confirmed.**

## What was scanned

| Server | Version | Runs as | Tools | mcpfuzz verdict | Checks passed |
|---|---|---|---|---|---|
| `@modelcontextprotocol/server-filesystem` | 2.4.0 | Node, local | 16 | FINDINGS (exit 1) | 18 |
| `@modelcontextprotocol/server-memory` | 2.2.1 | Node, local | 9 | FINDINGS (exit 1) | 11 |
| `@modelcontextprotocol/server-everything` | 2.3.1 | Node, local | 16 | FINDINGS (exit 1) | 18 |
| `mcp-server-fetch` | 2026.11.18 | Python, local | 1 | PASS (exit 0) | 8 |
| `mcp-server-git` | 2026.11.18 | Python, local | 14 | PASS (exit 0) | 21 |

These are the official reference servers from `modelcontextprotocol/servers`, at the
latest release on the day of the run. All five answered `server/discover` and were
detected as the modern era (2026-07-28). The three Node servers are built on
`@modelcontextprotocol/server` 2.4.0; the two Python ones on `mcp` 2.3.0.

Tool versions: mcpfuzz 0.1.0 at commit `3689bbd` (Go 1.27.3), Node 24.13.0,
uv 0.13.4, Windows 11. Every server ran as a local child process with no network
target. The servers that read files got an empty throwaway folder, `git` got an
empty one-commit repository, and `memory` was pointed at a file inside the sandbox (no tool was called, so it wrote nothing).

## How to repeat it

```bash
bash scripts/real-servers.sh /path/to/empty/sandbox
```

The script installs the pinned versions inside the sandbox (npm and uv caches
included), scans each server with `mcpfuzz scan --timeout 60s`, and writes
`<name>.txt` (the summary), `<name>.json` (the full report) and `<name>.fresh.txt`
(the replay described below) to `results/real-servers-2026-11/`. The 60 s timeout is
there because the Python servers take about 15 s to start on a cold cache, which
is longer than the default 10 s. With the default, `fetch` and `git` came back
`INCONCLUSIVE` because no era answered in time. That is mcpfuzz behaving as
designed, but it is a startup cost, not a server problem.

## What the three FINDINGS actually are

Each Node server reported the same five findings, so they are one result, not
fifteen.

| mcpfuzz finding | Verdict after checking by hand |
|---|---|
| `modern.unsupported-version`: unknown version accepted | **mcpfuzz artifact.** On a fresh process the server answers `-32022` with `data.supported`. See below. |
| `tools.list`: no `resultType`, `ttlMs` or `cacheScope` | **mcpfuzz artifact.** On a fresh process a valid request gets all three. |
| `modern.missing-meta` (three probes): `tools/list` without `_meta`, or without `protocolVersion` or `clientCapabilities`, is answered instead of rejected with `-32602` | **Real behaviour, unclear whether it is a bug.** The server serves these as a legacy-style request. |

**Why two of them are artifacts.** The servers track which era a connection is in.
The first `tools/list` that arrives without `_meta` switches that connection to
legacy handling, and every later request on it is treated as legacy: `_meta` is
ignored, so a bad version is accepted and the result has no `resultType`. mcpfuzz
sends its meta-less probes first and reuses the same process, so it poisons its own
later checks. Replaying each probe on a fresh process (`<name>.fresh.txt`) gives, for
all three servers: bad version rejected with `-32022`; a valid request returns
`resultType`, `ttlMs` and `cacheScope`; a request without `_meta` is accepted.

**Why the third is open.** 2026-07-28 says modern requests carry `_meta`. A server
that also wants to serve older clients on the same stdio stream has to do something
with a request that has none, and answering it as legacy is a defensible choice.
What looks more questionable is that the choice then sticks to the connection, so a
later request that carries a bad version is no longer checked. I haven't confirmed
that the spec forbids either behaviour, so this is not filed anywhere. See
[Open question](#open-question) below.

## What this says about mcpfuzz

Two changes the real servers show are needed:

1. Run the destructive-state probes (`modern.missing-meta`) on their own process,
   or last, so one probe cannot change what the next one measures.
2. Tell "does not support the modern era" from "supports both eras". A server that
   serves both will always look wrong to a check that assumes modern-only.

Neither change is in this commit. Until then, `FINDINGS` on a dual-era server should
be read with the `.fresh.txt` replay next to it.

## What this does not cover

- **No active scans.** Active mode needs the server inside Docker, and Docker wasn't
  running on this machine. So nothing here says anything about path traversal or shell
  injection in `filesystem`, `git` or `fetch`. That is the more interesting half of
  mcpfuzz and it is still unrun on real servers.
- **No tools were called.** Passive mode only lists tools and reads their schemas
  and descriptions.
- **Dual-era handling was checked only on the three Node servers**, and only by the
  three replayed requests above.
- **One run each**, on one machine, on one day. Nothing was repeated to check for
  flakiness.
- **stdio only, and only the reference servers.** Streamable HTTP and third-party
  servers were not tested.

Smaller notes: `server-everything` got one `SUSPICIOUS` (`trigger-resource-update`
claims `readOnlyHint` while its name contains "update"). It triggers a notification,
and a read-only hint is plausible, so this is mcpfuzz's name heuristic being cautious.
It never changes a verdict. The `hint` lines (`path`, `repo_path`, `url`, `query`
parameters with no constraint) are the starting point for choosing `--allow-tools` in
an active scan.

## Open question

Does 2026-07-28 allow a server to answer a request without `_meta` as a legacy
request, and to keep the connection in legacy mode afterwards? If it doesn't, the
three Node servers share one small bug in the SDK they are built on. If it does,
mcpfuzz's `modern.missing-meta` check is too strict for dual-era servers. Either way
it should be settled against the spec text before anything is reported upstream.
