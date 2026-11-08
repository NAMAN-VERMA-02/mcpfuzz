# mcpfuzz

Does your MCP server follow the spec, and can its tools be turned against the
machine they run on?

mcpfuzz starts an MCP server over stdio, works out which protocol era it speaks,
and checks it. It trusts nothing the server says about itself. A path traversal
counts only when a random canary from outside the allowed root comes back in a
tool's output. A shell injection counts only when an injected command creates a
marker file. Everything else is observed directly: wrong error codes, bad ids,
crashes, hangs.

## Try it in one minute

You need Go. Passive scans need nothing else.

```bash
go build -o bin/ ./cmd/mcpfuzz ./testservers/vulnerable ./testservers/fixed
bin/mcpfuzz scan -- bin/vulnerable -era modern   # FINDINGS: it accepts requests without the required _meta
bin/mcpfuzz scan -- bin/fixed -era legacy        # PASS
```

Active scans send attack payloads, so the server must run isolated in Docker:

```bash
docker build --load -t mcpfuzz-testservers -f testservers/Dockerfile .
bin/mcpfuzz scan --image mcpfuzz-testservers --active \
  --allow-tools read_file,ping_host,add_note,echo --allowed-root /work --i-own-this-target \
  --json report.json -- /usr/local/bin/vulnerable -root /work           # FINDINGS
```

Swap `vulnerable` for `fixed` and the same scan gives PASS. The two servers share
their code and differ only at each deliberate bug, so you can read exactly what
each finding catches in [testservers/internal/server](testservers/internal/server/server.go).
[scripts/e2e.sh](scripts/e2e.sh) runs both servers in both eras and checks every
exit code. CI runs it on every push, because if mcpfuzz could not tell these two
servers apart, none of its other verdicts would mean anything.

## Verdicts

| Verdict | Meaning | Exit code |
|---|---|---|
| `PASS` | Every check ran and the server behaved correctly | 0 |
| `FINDINGS` | At least one problem was observed directly or confirmed by a canary | 1 |
| `INCONCLUSIVE` | Something could not be checked, for example no era answered, the server offers no tools, active mode was asked for on a target that isn't isolated, or a probe got no usable response | 2 |
| could not run | The flags are wrong, the server command won't start, or `--image` was given and Docker isn't available | 3 |

`INCONCLUSIVE` is there so a broken setup never reads as a pass. A confirmed finding
outranks it, because a confirmed problem stays real even when other probes could not run.

`SUSPICIOUS` items, such as prompt-injection wording or annotations that contradict
a tool's name, are listed in the report but never change the verdict. Suspicious
wording is not a confirmed vulnerability. A check only reports `PASS` for behaviour
mcpfuzz actually observed, so the absence of `SUSPICIOUS` items is not a pass either.

## Protocol eras

| | Legacy (2025-11-25 and earlier) | Modern (2026-07-28) |
|---|---|---|
| Opening | `initialize`, then `notifications/initialized` | none; `server/discover` is optional |
| Per request | nothing | `_meta` with `io.modelcontextprotocol/protocolVersion` and `clientCapabilities` |
| `ping` | required | removed |

Detection follows the 2026-07-28 stdio rules. mcpfuzz sends `server/discover`
first. A `DiscoverResult` or an `UnsupportedProtocolVersion` error (-32022) means
the server is modern. Any other error, or silence until the timeout, means it falls
back to `initialize`. If neither answers, the scan is `INCONCLUSIVE`.

## What it checks

**Passive** (the default) calls no tools.

| Check | Era | Passes when |
|---|---|---|
| `modern.discover` | modern | `server/discover` returns `resultType: "complete"`, `supportedVersions` and `capabilities` |
| `modern.missing-meta` | modern | a request missing `_meta`, its `protocolVersion` or its `clientCapabilities` is rejected with -32602 |
| `modern.unsupported-version` | modern | an unknown version gets -32022 with `data.supported` |
| `legacy.initialize`, `legacy.ping` | legacy | the handshake returns version, capabilities and `serverInfo`; `ping` returns `{}` |
| `unknown-method` | both | an unknown method gets -32601 |
| `tools.list` | both | every page is followed and each is well formed; in the modern era each page has `resultType`, `ttlMs` and `cacheScope`; cursors never loop |
| `tools.schema` | both | each `inputSchema` is an object schema |
| `stdio.output` | both | stdout carries only JSON-RPC messages |
| `prompt-injection` | both | (`SUSPICIOUS` only) wording that talks to the model, secret-file paths, or invisible characters in any tool string or server instructions |
| `annotations` | both | (`SUSPICIOUS` only) a tool claims `readOnlyHint` while its name says it changes state |

If the server doesn't advertise the tools capability, the tool checks are
`INCONCLUSIVE`, never `PASS`. String parameters that look like paths or commands and
have no `enum` or `pattern` are listed as hints for `--allow-tools`.

**Active** (`--active`) also calls the tools you allow, and only those.

| Check | Payloads | Confirmed when |
|---|---|---|
| `active.path-traversal` | relative, URL-encoded, absolute and deep `../` paths to the canary | the canary's random contents appear anywhere in the response |
| `active.shell-injection` | `;`, `\|`, `&&`, `$( )`, backticks and a newline, each running `touch <marker>` | the marker file exists afterwards |
| `active.oversized` | a 512 KiB string in each string parameter | (a crash or hang is a finding) |
| `active.wrong-type` | the wrong JSON type for each typed parameter | (a crash or hang is a finding) |
| `active.unknown-tool` | a call to a tool the server didn't list | success here is a finding |
| `active.invalid-jsonrpc` | truncated JSON, a non-string method, an empty batch | a crash, a result instead of an error, or no longer answering valid requests is a finding |

Tool annotations play no part. A tool that claims to be read-only is probed like any
other once it is on the allowlist, and a tool not on the allowlist is never called.

## Active mode needs isolation

`--i-own-this-target` says you may test the server. It doesn't stop a vulnerable
tool from deleting your files when a payload works. Authorization is not isolation,
so active probes run only when mcpfuzz starts the server itself with `--image`:

- `--network none`, `--read-only` root filesystem, `--cap-drop ALL`, `no-new-privileges`, user 65534
- a 128-process limit, 512 MB of memory and a 16 MB `/tmp`
- a fresh work directory mounted at `--allowed-root`
- the canary mounted read-only outside it, and a marker directory for injected commands

`--pull never` is set, so build or pull the image first. A server that can't be
isolated this way still gets a passive scan, and an active scan of it is
`INCONCLUSIVE`. Active mode refuses to start at all without `--allow-tools`,
`--allowed-root` and `--i-own-this-target`.

Each call has a deadline (`--timeout`, 10 s by default). Messages are capped at
1 MiB going out and 4 MiB coming in. A server that crashes or hangs is restarted
for the next probe, and its whole process tree, or its container, is removed at the end.

## What these results can't tell you

- **PASS means these probes found nothing.** It does not mean the server is secure.
  The active probes cover path traversal and shell injection through string
  parameters only. SSRF, SQL injection, logic bugs and nested parameters are not tested.
- **The wording rules are a short list.** Text that gets past them can still be malicious.
- **stdio only.** Streamable HTTP and the `Mcp-Method`/`Mcp-Name` headers are not tested yet.
- **One modern version.** A modern server that does not support 2026-07-28 is `INCONCLUSIVE`.
- **Only the test servers in this repo have been scanned.**

## Status

v0.1. Scan only servers you own or are authorised to test. Results about other
people's servers stay private until the maintainers have had a chance to respond.
See [THREAT_MODEL.md](THREAT_MODEL.md) for the threat model and
[TESTING.md](TESTING.md) for what each test proves.
