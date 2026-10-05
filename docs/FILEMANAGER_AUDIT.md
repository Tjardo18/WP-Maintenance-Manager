# Filemanager phase 10 — audit and acceptance evidence

Audit date: 2026-10-05. Scope: phases 1–9 on `feature/filemanager`.
Phase branch: `feature/filemanager-phase-10-hardening`. No release, deployment,
version bump, dependency upgrade or merge to a production branch is part of this work.

## Result and verification boundaries

The implementation has been reviewed across frontend, IPC, authorization,
SFTP paths/transport, mutations, downloads, shared preview and terminal reuse.
The feature is ready for **human review**, not an unconditional production-readiness claim.

**PASS (automated)** below means the named component/service/transport-boundary
tests passed. Test transports model SFTP; they do not authenticate to a real host.
**PASS (review)** means source inspection, not a runtime guarantee.
**NOT VERIFIED** identifies checks requiring the real desktop, an isolated SSH
server, server configuration or a human visual review. No customer files were
read, changed or deleted for this audit.

### Findings fixed

| ID | Severity | Finding and correction | Evidence |
| --- | --- | --- | --- |
| F1 | High | Ongoing operations previously checked access mainly at start/end. Revocation or expiry could leave later SFTP work running. A shared live guard now checks the app session and fixed site-bound access at SFTP work boundaries, including stream chunks and pre-replacement checks. | All ten filesystem service methods reject another site and expired access before transport; in-flight guard tests cover revocation/app lock/fixed expiry. |
| F2 | Medium | Reusing the browser after A → B → A could let an old mutation response change current dialogs, busy state or feedback. Context-generation guards now cover mutations, downloads, refreshes, navigation waits and unmount; context changes clear dialogs/state. | Two browser tests first reproduced the stale dialog/late create failure, then passed. |
| F3 | Medium | A backend expiry event discarded an unsaved editor although timer expiry preserved it. Both paths now revoke access and preserve the in-memory draft until explicit discard. | Parameterized access test covers timer and backend events. App lock still clears protected content. |
| F4 | Medium | ZIP entry validation accepted Windows aliases such as `.. `, trailing dots/spaces and device names. These are now rejected before adding archive entries; reserved suggested download names are replaced. | `.. /outside.php` failed the new regression test before the fix. Helper and actual archive-builder tests cover unsafe descendants. |
| F5 | Medium | The archive entry cap counted processed items, allowing substantially more pending descendants than its 10,000-entry budget. Queued descendants now consume the same budget. | Actual archive builder rejects a wide/deep tree before the first file copy. |
| F6 | Medium | Concurrent direct download calls could open multiple native save dialogs before acquiring the transport lock. One manager-wide reservation now includes dialog and transfer. | Exclusive reservation/release test plus existing duplicate-request UI test. |
| F7 | Low | Filemanager create/permission/confirmation dialogs lacked reliable initial focus and Tab containment. A small shared directive adds focus restoration, Tab wrapping and Escape cancellation without swallowing unrelated keys. | Mounted confirmation test checks focus, Escape/busy handling and unblocked MediaPlayPause. |

Totals: **Critical 0, High 1, Medium 5, Low 1**. No new product features.

An already-sent remote mutation cannot be undone by revocation. The next checked
work boundary stops further work; an uncertain operation is not reported as
successful. This is not a distributed transaction or instantaneous network cancellation.

## Evidence map

Paths below are repository-relative.

- **A — authorization:** `src-tauri/src/commands.rs` guard/endpoint tests and
  `src-tauri/src/filemanager.rs` tests; `FilemanagerAccess.test.ts`,
  `FilemanagerView.test.ts`, `src/services/tauri.test.ts`.
- **P — paths/listing:** `filemanager_paths.rs`, `filemanager_directory.rs`
  tests and their real `ssh.rs` adapter.
- **R — reading/rendering:** `filemanager_file.rs`, resolver/read tests,
  `ChecksumFilePreview.test.ts`, `fileSyntax.test.ts`,
  `markdownPreview.test.ts`, `svgPreview.test.ts`, image/binary tests.
- **E — editing:** `filemanager_edit.rs`, `sftp_replace.rs`,
  `FileEditing.test.ts`, `fileEditing.test.ts`.
- **M — mutations:** `filemanager_mutation.rs` tests, corresponding guarded
  service methods and SFTP adapter.
- **D — downloads:** `filemanager_download.rs` tests and actual
  `download_filemanager_items` → `save_local` → download service path.
  Tests inspect ZIP entries/bytes and real temporary local directories.
- **U — browser:** `FilemanagerBrowser.test.ts`, access/view tests,
  `ConfirmDialog.test.ts`; source/CSS in browser, breadcrumbs and shared preview.
- **T — regression:** `SshTerminal.test.ts`, Rust terminal/auth/SSH tests,
  shared preview tests and complete application test suites.

## Audit areas 1–45

| # | Area | Outcome and qualification |
| --- | --- | --- |
| 1 | Website isolation | PASS automated A/U: all filesystem service entry points reject cross-site tokens, including single/bulk/archive download through their shared service. |
| 2 | Authentication | PASS automated A: password sequence, guards, missing/expired access, changed site configuration and session; live password/host-key exchange NOT VERIFIED. |
| 3 | Credentials | PASS review: no filemanager password/token browser storage, query strings or content logging; input fields clear after submission, Rust passwords zeroize. IPC/JS memory cannot guarantee secure erasure. |
| 4 | Traversal | PASS automated P/M/E/D: root-underflow and malformed paths fail; every operation uses the central resolver. |
| 5 | Absolute paths | PASS automated P: leading slash is a virtual root-relative path, not a physical server override. |
| 6 | Prefix boundary | PASS automated P: canonical containment requires exact root or slash boundary, not a naive prefix. |
| 7 | Symlinks | PASS automated P/M/D: navigation/read/write/chmod/download reject links; deletion unlinks the leaf only. Hostile filesystem races remain a server-confinement limitation. |
| 8 | Symlink loops | PASS automated/review P/D: links are never recursively traversed. |
| 9 | Shell injection | PASS automated/review P/M/E/D: shell punctuation remains literal; filemanager uses SFTP, never shell interpolation. |
| 10 | Preview XSS | PASS automated R: escaped raw source, Markdown HTML disabled, SVG sanitized. Real WebView engine behavior NOT VERIFIED. |
| 11 | File reads | PASS automated P/R/U: empty/Unicode/binary/truncated content, missing/type changes and safe errors; live SSH failure timing NOT VERIFIED. |
| 12 | Safe writes | PASS automated E: exclusive temp, verified bytes/metadata, explicit atomic-replace extension, cleanup; real server extension/fsync support NOT VERIFIED. |
| 13 | Atomicity | PASS modeled E: write/quota/permission/replace failures keep original bytes; actual disk-full/disconnect timing NOT VERIFIED. |
| 14 | Stale editing | PASS automated E: second editor, same-size/mtime external edits, deletion and conflict retention. No atomic server-side compare-and-swap guarantee. |
| 15 | Save permissions | PASS modeled E: 644/755/640 and UID/GID retained; actual hosting ownership/ACL behavior NOT VERIFIED. |
| 16 | Encoding | PASS automated E/R: UTF-8, BOM, accents, euro, Chinese, emoji, LF/CRLF and unchanged buffer roundtrip. |
| 17 | Create | PASS automated/review M/U: exclusive creation, valid names, collisions, path validation and immediate preview. Real concurrent server create NOT VERIFIED; SFTP uses EXCL. |
| 18 | Delete | PASS modeled M/U: explicit confirmation, correct type, root guard, leaf symlink unlink and non-empty directory refusal. |
| 19 | Chmod | PASS modeled M: three octal digits, 000–777, invalid modes rejected, no implicit recursion or link following. |
| 20 | Selection | PASS automated U: path identities, count/select-all/indeterminate, navigation/refresh/site reset. |
| 21 | Bulk delete | PASS modeled M/U: validate whole structural request before work, confirmation/count and itemized operational failures. |
| 22 | Bulk chmod | PASS modeled M/U: strict common mode, files/directories, partial failure and non-recursion. |
| 23 | File download | PASS modeled D/U plus real local output bytes; native dialog and actual SSH stream NOT VERIFIED. |
| 24 | Streaming | PASS review/modeled D: 64 KiB blocking read/write with backpressure, limits and scoped handles. No HTTP client stream. Real peak-memory/load measurement NOT VERIFIED. |
| 25 | Archives | PASS automated D: actual ZIP opened and entries/content inspected; only selected relative descendants. |
| 26 | Zip Slip | PASS automated D: traversal, drive/absolute/backslash paths and Windows aliases rejected by builder-used validator. |
| 27 | Archive injection | PASS automated/review D: Rust ZIP writer, literal punctuation, no remote archive command. |
| 28 | Tempfiles | PASS local filesystem D: exclusive random staging and failure/collision/revocation cleanup. Remote HTTP secrecy and arbitrary destination ACLs NOT VERIFIED; see rollout gates. |
| 29 | Archive failures | PASS modeled/local D: read/write errors never publish final output. Actual full-volume/server disconnect NOT VERIFIED. |
| 30 | Navigation | PASS automated U: root, Up, Back, breadcrumbs, empty and error states. |
| 31 | Navigation races | PASS automated U: stale listing/preview and late create after A → B → A; generation guard also applied to delete/chmod/download. |
| 32 | Unsaved changes | PASS automated E/U: save/cancel/close/Escape/router guards and draft retention on error/expiry. Forced process termination cannot guarantee preservation. |
| 33 | Website changes | PASS automated U/A: old token/state/dialogs cleared and old responses discarded; new site requires both passwords. |
| 34 | Mid-action expiry | PASS automated A/E: service guard rechecked during work and before publication; cannot roll back a request already sent. |
| 35 | SSH disconnect | PASS modeled P/E/D and error mapping; actual cable/process interruption across each action NOT VERIFIED. |
| 36 | Errors | PASS review/automated: typed safe user messages, numeric SFTP diagnostic codes, no raw server output/file contents. |
| 37 | API semantics | PASS review/A: protected async Tauri IPC, not HTTP GET/download endpoints; app/site/token guard and payload limits. |
| 38 | Resource limits | PASS automated/review: 256 KiB text edit, 10 MiB image read, 100 bulk selections, 5,000 listing items, 10,000 queued ZIP entries, 64 archive levels, 4 GiB source data, deadlines and serialized save/download. |
| 39 | Accessibility | PASS automated/review U: buttons/labels/checkboxes/busy states and dialog focus. Screen-reader/native keyboard walkthrough NOT VERIFIED. |
| 40 | Responsive UI | Source reviewed: wrapping toolbars, horizontal table/breadcrumb scrolling, bounded preview. Visual small-viewport check NOT VERIFIED; reserved for human review. |
| 41 | SSH Terminal | PASS automated T: independent access/session, authentication/EOF/input/cleanup regression tests. Real terminal command execution NOT VERIFIED. |
| 42 | Existing preview | PASS automated R/T outside filemanager: highlighting, line numbers, Raw/Preview, fullscreen/Escape and scan preview controls. |
| 43 | Test quality | Added service-level access matrix, actual local staging and ZIP-builder tests rather than only unused helper assertions. Existing source-string guard test is a structural check, not an E2E security proof. |
| 44 | Complete practical flow | NOT VERIFIED: no disposable live SSH environment or desktop interaction used. Model-level paths are tested, not one full native 30-step flow. |
| 45 | Original acceptance | Each criterion is addressed below with its evidence scope; outstanding human/server checks are explicit. |

## Original acceptance checklist

Every PASS in this list is **automated/model-level** unless marked review.
It does not supersede the NOT VERIFIED live checks above.

### Website and SSH

- PASS A — each website has its own route/filemanager.
- PASS A — stored website SSH configuration is used (live connection NOT VERIFIED).
- PASS A — website A credentials/token cannot authorize website B.

### Authentication

- PASS A — app password first.
- PASS A — website-specific SSH password second.
- PASS A — no access without both checks.
- PASS A — backend entry points protected (service/command boundary tests and registration review).

### Navigation

- PASS U — open directories.
- PASS U — previous directory/history.
- PASS U — one level up.
- PASS U — current directory displayed.
- PASS U — breadcrumbs displayed.
- PASS U — ancestor breadcrumbs clickable.
- PASS P — root cannot be escaped by client paths.

### Listing

- PASS U/P — filename shown.
- PASS U/P — type shown.
- PASS U/P — file size shown or explicitly unavailable.
- PASS U/P — permissions shown or explicitly unavailable.
- PASS U/P — modification date shown when available.

### Preview

- PASS U — open files.
- PASS P/R — bounded read.
- PASS R/U — existing shared preview reused.
- PASS R — syntax highlighting.
- PASS R — line numbers.
- PASS R — Raw/Preview for supported types.
- PASS R — fullscreen.
- PASS R — binary/unsupported content safely classified and displayed.

### Editing

- PASS E — supported text/code extensions editable.
- PASS E — save to the same resolved location.
- PASS E/U — explicit save only.
- PASS E — safe staged write.
- PASS E — original preserved on modeled pre-replacement failure.
- PASS E — conflict/stale version detection.
- PASS E — mode/UID/GID retained in modeled saves; actual server NOT VERIFIED.

### Delete

- PASS M/U — individual file removal.
- PASS U — confirmation required by UI.
- PASS U — item name shown in confirmation.
- PASS M — root target rejected.
- PASS M — non-empty directory never recursively deleted.

### Permissions

- PASS M/U — individual mode visible.
- PASS M/U — individual chmod.
- PASS M — octal validation/interpretation.
- PASS M — files and directories supported, symlink chmod refused.

### Bulk

- PASS U — multi-selection.
- PASS U — selected count visible.
- PASS U — select all in current listing.
- PASS M/U — bulk delete.
- PASS U — bulk delete confirmation.
- PASS U — confirmation includes count.
- PASS M/U — bulk chmod.
- PASS M — no implicit recursive chmod.
- PASS M/U — partial operational failures returned/displayed per item.

### Create

- PASS M/U — new file in current directory.
- PASS M — existing names are not overwritten; EXCL in real adapter (review).
- PASS U — new file immediately opens in shared preview.
- PASS M — new directory.
- PASS M — server-side name validation.

### Download

- PASS D/U — individual download path.
- PASS D/U — directory ZIP path.
- PASS D/U — bulk download path.
- PASS D — files and directories combined.
- PASS D — safe relative archive entries.
- PASS D — no absolute server root in archive.
- PASS D/E (partial) — random exclusive tempfiles; server HTTP/private ACL validation NOT VERIFIED.
- PASS D/E (partial) — local cleanup proven; remote cleanup modeled, unavailable SSH cleanup cannot be guaranteed.

### Security

- PASS P/M/E/D — central path validation.
- PASS P — traversal above root rejected.
- PASS P — physical absolute path override prevented.
- PASS P — prefix boundary.
- PASS P — stable symlink escape prevented; adversarial path races require server confinement.
- PASS P/M/E/D — no shell interpolation.
- PASS R — preview XSS test payloads inert.
- PASS A — cross-site access rejected.
- PASS A (review + password-clearing tests) — credentials not persisted/exposed by feature; forensic memory erasure NOT VERIFIED.

### Errors

- PASS P/R/U — unreadable file failure propagated.
- PASS P/E/M — permission denial handled.
- PASS E — deleted file not recreated during editing.
- PASS E — externally changed file conflicts.
- PASS E/U — save failure retains draft and is not success.
- PASS D/U — failed download not published/reported successful.
- PASS P/E/D — modeled disconnect/error mapping; live disconnect NOT VERIFIED.
- PASS P/U — missing directory error.
- PASS A/U — expired access denied and authentication recovery available.
- PASS U/E/D — success requires backend confirmation; uncertain committed writes explicitly require inspection.

## Tests and checks

Executed locally on Windows:

- `npm run check` — PASS: typecheck, ESLint (zero warnings), **240 frontend tests
  across 36 files**, production Vite build; zero failed/skipped tests.
- `cargo test --manifest-path src-tauri/Cargo.toml --all-targets --all-features`
  — PASS: **288 backend tests**, zero failed/ignored; binary target has zero tests.
- `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --all-features -- -D warnings`
  — PASS.
- `cargo fmt --manifest-path src-tauri/Cargo.toml --check` — PASS (formatting also applied).
- `cargo build --manifest-path src-tauri/Cargo.toml` — PASS, native debug application build.
- `cargo test --manifest-path src-tauri/Cargo.toml filemanager_download --lib`
  — PASS: 9 download/archive tests, 279 unrelated tests filtered out.
- Earlier targeted filemanager/ZIP tests reproduced and verified fixes. Remote CI
  outcome and merge commit are recorded in the PR and final hand-off.
- `git diff --check` — PASS at checkpoints.

The existing Vite main-chunk warning (>500 kB) remains non-blocking. No new
dependency was added or upgraded: `zip` is used by the streaming archive builder,
`tempfile` by local staging, and the shared preview still uses its existing
libraries. `package-lock.json` was explicitly staged/checked; its content is
already identical to the feature branch, so there is no artificial lockfile diff.

No live SSH, native save-dialog, real full-volume/quota test, WebView execution
test, screen-reader run or human visual viewport check is claimed. Local test
directories are RAII temporary directories and are removed by their tests.

## Remaining gates and limitations

### Blockers for production rollout (not for isolated feature-branch review)

1. Run the complete 30-step desktop flow from the phase-10 request on a disposable
   site, including a second site, wrong passwords/host key, expiry, terminal
   regression, native dialogs, archive extraction and narrow-screen/fullscreen checks.
2. Verify server support for fsync and `posix-rename@openssh.com`, ownership/mode
   retention, quota/disconnect failure handling and cleanup.
3. Verify HTTP denial for `.wpmm-save-*.tmp` in each relevant hosting layout.
   Same-directory staging briefly uses the original mode and is not proven private
   from the web server solely by a random dotfile name. Do not treat this audit as
   approval to edit sensitive files on an unverified hosting configuration.
4. If other filesystem writers are untrusted, enforce server-side confinement.
   SFTP v3 revalidation is not atomic rooted traversal or compare-and-swap rename.

### Non-blocking limitations

- Lost SSH, revoked access or forced process termination can prevent remote temp
  cleanup; the failure warns about residue. A hard local crash can leave a partial
  download; normal local failures/revocation remove it.
- Chosen local destination-folder ACLs govern Windows staging confidentiality;
  do not choose a publicly shared directory for sensitive downloads.
- SFTP replacement cannot preserve unsupported ACLs/xattrs/hardlink identity.
  A disconnect after rename can leave a completed but unconfirmed save.
- No HTTP header-injection surface exists for downloads: they use native IPC and
  a filesystem save dialog. Cancellation/window close is not an HTTP disconnect.
- UI/model tests do not replace visual/manual/native server testing.

No future feature or phase 11 has been started.
