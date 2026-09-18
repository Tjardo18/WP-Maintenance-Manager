# Performance report

This report records the measurements made for the background-scan refactor. The
numbers below come from a Windows development build on 10 September 2026. They
are regression indicators, not promises about a hosting provider: real SSH,
filesystem and HTTP latency depends on the remote server.

## Before and after

| Measurement | Before | After |
| --- | ---: | ---: |
| Click **Website controleren** until IPC returns | Entire scan duration; the synchronous command stayed open during SSH, HTTP and SQLite work | 0.223 ms in the job-manager unit harness |
| Full SSH handshakes/authentications per normal scan | Approximately 16 (17 when the checksum fallback ran) | 1 |
| UI-blocking scan work | Full request lifecycle | None; the scan runs on a named blocking worker and reports events |
| Synthetic full scan | Not retained for the old implementation | 2.07 s; 2.062 s was the deliberately failing local HTTP check and mocked SSH/parser steps were 0 ms |
| Persist and read 5,000 findings | No isolated baseline retained | 198 ms write, 18 ms read, using one transaction and prepared statements |
| Match 100 installed plugins against the local Wordfence index | Not applicable | Below 2 seconds in the deterministic Rust regression test; no network or SSH request |

The old implementation was inspected before refactoring. It authenticated once
for the initial scan and then opened a new authenticated SSH session for each
remote command, including a separate update pass. More importantly, the
frontend awaited that complete synchronous Tauri command. Consequently its
blocking duration equalled the variable remote scan duration. The new start
command only validates input and creates a job; remote work is no longer part of
the UI request lifecycle.

The synthetic tests intentionally avoid production credentials and therefore do
not claim a live-server speedup in seconds. They demonstrate the architectural
changes deterministically: immediate job creation, one authentication per scan,
bounded global concurrency, cancellation, batched persistence and continued UI
interaction while a mocked long-running job is active. Development builds also
record real per-step timings and IPC response sizes, so a live scan can expose a
slow hosting step without logging command output, paths or credentials.

## Current budgets and limits

- Cached Dashboard and site-detail rendering target: below 300 ms on a normal
  development machine.
- Local scan-job acknowledgement target: below 200 ms. The measured unit-harness
  result is 0.223 ms, excluding OS scheduling and frontend IPC overhead.
- Global active site scans: configurable from 1 through 5, default 4.
- Remote concurrency inside one scan: 1. Commands use sequential channels on one
  authenticated libssh2 session to preserve correctness and server headroom.
- IPC warning threshold in development: 1 MiB.
- Security-result page sizes: 25, 50 or 100 rows; normal PHP inventory entries are
  summarized rather than sent to Vue.
- Text and decompressed SVGZ previews are capped at 256 KiB. Supported raster
  images are capped at 10 MiB; binary inspection bounds readable text, suspicious
  matches and hex ranges so long files do not create an unbounded DOM.
- Wordfence Production Feed refresh: at most once automatically per 24 hours and
  never from a normal site scan. The response streams to disk and is parsed with
  `BufReader`; only compact job progress crosses IPC.
- Vulnerability matching: indexed by provider, software type and exact slug.
  Dashboard counts are precomputed on `sites`; a successful feed refresh
  re-evaluates cached inventories locally without SSH and does not rewrite old
  scan history.

## Remaining measurement limitations

No production SSH credentials or repeatable remote fixture are part of the
repository, so before/after wall-clock timings for the same live WordPress host
cannot be reproduced automatically. Server-side `find`, checksum, WP-CLI and
HTTP work can still be slow, but the UI now exposes that step and remains usable.
Cancellation is cooperative between commands: an already running read-only SSH
command is allowed to finish before the next step is suppressed.
