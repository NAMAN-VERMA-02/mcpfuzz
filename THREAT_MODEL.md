# Threat model

mcpfuzz runs servers it does not trust, so the server under test is treated as the
attacker. A server must not be able to:

| Attack | Defence |
|---|---|
| Pass by crashing, hanging or staying silent | Crashes and hangs are findings; a probe with no usable answer is INCONCLUSIVE, never PASS |
| Fake a traversal result, or hide one | The canary holds 32 random hex characters per run, is never sent to the server, and sits read-only outside the allowed root; only its contents count, not its path |
| Fake a shell-injection marker | Markers have random names and live in a directory outside the allowed root; only the exact path counts |
| Talk its way past the scanner | Annotations, `serverInfo` and descriptions are recorded but never used for decisions; wording is only ever SUSPICIOUS |
| Damage the host during active probes | Active probes run only in a container with no network, a read-only root, no capabilities, no privilege escalation, user 65534 and pid and memory limits |
| Exhaust the scanner | 4 MiB per message, 8 KiB of stderr kept, a deadline on every call and every write |
| Forge output or plant escape codes in a terminal | Control and invisible format characters in server text are shown as `\u{...}` escapes |
| Make the scanner do things for it | Server-to-client requests are refused with -32601 |
| Outlive the scan | The process group (Unix) or tree (`taskkill /T`, Windows) is killed, and containers are removed with `docker rm -f`, after the scan, after a hang and on Ctrl-C |

## Limits

- **A passive scan without `--image` runs the server on your machine** with your
  privileges. Passive means mcpfuzz calls no tools. It does not make an untrusted
  server safe to start. Use `--image` for anything you don't trust.
- **Docker is not a VM.** The container shares the host kernel. A kernel exploit
  escapes it.
- **The work directory is writable and has no quota.** A hostile server can fill it.
  It is a fresh temporary directory, deleted after the scan.
- **Probes go only to allow-listed tools**, but the server decides what a tool
  does. A tool can do damage inside the container with harmless-looking input.
- **A report is self-reported.** Nothing signs it. Trust a result only after
  rerunning it.
