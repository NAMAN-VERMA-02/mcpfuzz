# Testing

```bash
go test ./...                     # everything, about half a minute
go test -race -count=1 ./...      # what CI runs on Linux
bash scripts/e2e.sh               # needs Docker: both test servers, both eras, isolated
```

## What proves what
| Area | Files | Proves |
|---|---|---|
| The scanner can tell good from bad | `scripts/e2e.sh`, CI job `e2e` | In Docker, with the real isolation flags: the vulnerable server gets FINDINGS (exit 1) with a confirmed path traversal and shell injection, and the fixed server gets PASS (exit 0), in the legacy and the modern era. An active scan of a target that isn't isolated gets INCONCLUSIVE (exit 2). If this fails, no other verdict is trustworthy. |
| The same, without Docker | `internal/scan/scan_test.go` `TestSuiteTellsControlsApart` | The probe and canary logic gives the same split on the host, using a stand-in sandbox in a temp directory. The shell-injection assertion is skipped where there is no `sh`. |
| Era rules | `TestModernOnlyServerRejectsMissingMeta` | modern servers must reject a request missing `_meta` with -32602 and an unknown version with -32022 |
| Never PASS on what didn't run | `TestNeitherEraIsInconclusive`, `TestActiveRefusedWithoutIsolation`, `TestVerdict` | a silent server and an unisolated active scan are INCONCLUSIVE; no probe touches an unisolated target; an empty run is not a pass; SUSPICIOUS never changes the verdict |
| Observed conformance problems | `TestHangIsAFinding`, `TestWrongIDIsAFinding`, `TestNonJSONStdoutIsAFinding` | hangs, mismatched ids and junk on stdout are findings |
| Hostile server output | `TestCleanEscapesControlCharacters`, `internal/rpc/client_test.go` | escape codes and bidi characters are neutralised; oversized responses are refused; oversized requests are never sent; a server that stops reading stdin can't block the scanner |
| Isolation settings | `TestDockerArgsIsolate`, `TestValidRoot` | the container gets no network, a read-only root, no capabilities and a read-only canary; `--allowed-root` can't overlap the canary |
| Active mode needs consent | `cmd/mcpfuzz/main_test.go` | `--active` without `--allow-tools`, `--allowed-root` or `--i-own-this-target` exits 3 |
| Wording heuristics | `TestInjectionWording` | known tool-poisoning phrasings are flagged; ordinary descriptions are not |

CI (`.github/workflows/ci.yml`): gofmt, `go vet`, `go test -race` on Linux, plain
`go test` on Windows, govulncheck, and the Docker e2e job. Actions are pinned by SHA.

## Gaps
- Nothing has been scanned except the two test servers in this repo.
- No fuzz tests of the scanner's own response parsing.
- The prompt-injection rules are tested against a handful of phrasings, not a corpus.
- Process-tree cleanup is exercised on every run but not asserted by a test.
