# Filemanager — foundation and website-specific authentication

This feature is developed on `feature/filemanager`, with phase 1 on
`feature/filemanager-phase-1-foundation` and phase 2 on
`feature/filemanager-phase-2-auth`. It must not be merged into `main`
without a later explicit instruction. The application version is unchanged.

## Existing architecture and reuse

- Vue 3 views use hash routes in `src/router.ts`, Pinia site/auth stores and the
  authenticated `call()` wrapper in `src/services/tauri.ts`. `App.vue` mounts
  protected routes only while authenticated and clears site state on lock.
- Sites have UUID identities. `Database::get_site` loads the stored site and its
  credential reference. SSH host, port, username, root and pinned host key come
  from SQLite; managed secrets come from the OS credential vault. A route ID is
  a selector, never proof of authorization or a source of SSH configuration.
- `SshTerminal.vue` owns ephemeral password fields, xterm.js, FitAddon and event
  subscriptions. Commands in `commands.rs` authorize every IPC request.
  `TerminalManager` owns a worker and persistent PTY per connection, streams
  bytes and validates session/site/terminal authorization on subsequent calls.
  Closing, EOF, route departure and application lock release terminal state.
- `begin_terminal_reauthentication` verifies the app password with Argon2id;
  failure revokes the app session. `TerminalAccessManager` issues a single-use,
  60-second challenge bound to the site and app session. `open_terminal` consumes
  it and uses `verified_terminal_password_session` in `ssh.rs` for pinned-host,
  explicit SSH password authentication. Passwords are zeroized in Rust and are
  not persisted. This flow does not fall back to managed credentials.
- `SshExecutor`/`Ssh2Executor` and `SshConnection` already implement managed SSH
  commands and bounded SFTP reads, deletes and fingerprints. Managed scans reuse
  a session; the terminal owns its separate interactive session. The terminal
  intentionally executes unrestricted shell input with the remote user's rights;
  managed commands instead use `command_catalog.rs`. SSH failures become
  `AppError`, with redacted reporting through the existing error infrastructure.
- `ChecksumFilePreview.vue` already supports syntax highlighting, line numbers,
  Raw/Preview, fullscreen, Escape and images. Its helpers are `fileSyntax`,
  `markdownPreview`, `svgPreview`, `imagePreview` and `binaryInspector`.
  It is read-only, not an editor. `checksum_files.rs` loads it using the newest
  authorized finding and SFTP. Its `FilePreview` contract and delete button are
  currently coupled to findings; reuse must separate presentation from those
  permissions in the later preview phase, without fabricating a finding.
- Styles use shared cards/buttons/empty states in `styles.css`. Vitest and Vue
  Test Utils cover views; Rust tests cover auth, terminal, SSH and database.
  `npm run check` and Cargo fmt/test/clippy are the established checks.

## Phase 1 design

`/websites/:id/filemanager` opens `FilemanagerView.vue` from a website's detail
page. The view loads a small typed `FilemanagerContext` through the existing
`appApi` boundary and discards stale responses when the route changes or unmounts.
It displays the stored site name and URL, a loading/error state and an honest
unavailable placeholder. No credentials or paths are accepted from the UI.

`get_filemanager_context` checks the existing app session and UUID, then delegates
to `filemanager.rs`. That module resolves context from the existing database and
returns only identity/display metadata. It does not access the credential vault,
open SSH, grant a file session or perform any remote operation. This is the
application-service location for later filemanager orchestration, not a second
SSH stack. No speculative file-operation stubs or generic command endpoint exist.

## Phase 2 authentication

The metadata endpoint remains display-only. `FilemanagerAccess.vue` gates the
placeholder workspace through two password forms and a backend authorization
check. Its parent keys it by website ID: navigation unmounts the previous gate,
closes its access and starts again. There is no global authenticated flag or
browser-demo authentication bypass. Password fields clear immediately after IPC
submission; neither credentials nor access tokens go into browser storage.

`begin_filemanager_reauthentication` requires a live app session and uses the
same `verify_feature_password` helper as the terminal (Argon2id). A wrong app
password revokes the entire app session, terminal sessions and filemanager
access. The helper audits the feature name, not the password or token.
`TerminalAccessManager` is reused in a **separate instance**, preserving its
random hashed, single-use, 60-second challenges and escalating SSH-attempt delay.
Terminal challenges cannot be exchanged for filemanager access, or vice versa.

`open_filemanager` consumes the challenge and resolves the website from SQLite.
It calls the existing `verified_terminal_password_session`: pinned host key
verification before explicit password authentication with the stored host, port
and username. No managed-key/vault fallback, command, directory read or PTY is
used. Connection attempts use the existing bounded SSH timeouts/retry mechanism;
timeout, host-key, unsupported password authentication and connection failures
produce safe login messages without raw server responses. Rust wraps passwords
in `Zeroizing<String>`; the SSH password is dropped immediately after the attempt.
JavaScript/IPC/OS memory cannot provide a guaranteed secure wipe.

`FilemanagerAccessManager` holds only in-memory token/session hashes, site ID,
a configuration fingerprint, an expiry and the authenticated SSH session. The
configuration fingerprint covers host, port, username, WordPress root and pinned
host key. The same server/account used by another site is a different boundary.
Active access has a fixed **15-minute maximum**, does not auto-renew, and also
requires the current app session. Pending access cannot pass the workspace guard.
Access is checked before and after SSH login: closing, canceling, replacing an
attempt or revoking access while login runs prevents late activation. Cleanup
uses the exact token so an old response cannot close a newer attempt.

Route departure, closing access, UI expiry, lock, password change, replacement
login and website deletion revoke access. The guard rejects expiration regardless
of frontend timers; expired entries/connections are discarded on access/status
checks and the normal UI close callback. App-session invalidation remains
authoritative even if a frontend cleanup call cannot run. The manager is capped
at 128 entries; nothing is restored after restarting the app.

Future endpoints must call `require_filemanager_auth` in `commands.rs` with the
app session, website ID and authorization token. This central boundary validates
the app session, loads the current stored website and invokes the filemanager
guard. `get_filemanager_authorization` already exercises this boundary before the
UI shows the placeholder. Do not treat `get_filemanager_context` or a successful
terminal login as file authorization.

## Next phases (not implemented)

Future file operations belong in `filemanager.rs`, with the established `ssh.rs`
transport providing SFTP, and backend-owned site context and centralized path
validation. Do not use the current metadata endpoint as file authorization or
silently substitute stored credentials for the planned two-password gate.
Phase 3 must add centralized path validation before any file operation, including
root confinement and symlink handling. Extend the guarded service to use its
authenticated connection; never reintroduce a stored-credential fallback after
connection loss. Reconnection requires both checks again. Directory navigation,
preview integration, editing, mutations, permissions, downloads, archives and
bulk operations have not been implemented here.

## Verification

Route tests cover site changes, delayed responses, missing sites and unmounts.
Existing terminal/auth tests remain the regression baseline. Opening the route
loads only metadata; only the explicit two-password flow establishes SSH.

Phase 1 checks completed: `npm run check` (typecheck, lint, 191 tests and Vite
build), `cargo test --manifest-path src-tauri/Cargo.toml --all-targets
--all-features` (229 tests), Cargo fmt and Clippy with warnings denied, and
`git diff --check`. The existing Vite warning about a main chunk above 500 kB
remains; the filemanager view is loaded as a separate route chunk. These are
automated checks, not a live-server or manual desktop test.

Phase 2 tests cover app-session/password requirements, missing websites/config,
pending versus active authorization, cross-site/session/purpose isolation,
configuration changes, failed/unreachable/timed-out SSH, rate limiting, expiry,
canceling in-flight login, stale responses, password changes and site deletion.
Transport is injected in unit tests; no test credentials or production bypass
are added. UI tests cover password clearing, duplicate submission, server guard
failure, both expiry states and navigation from an authorized site to another.
The IPC tests verify dedicated site-bound endpoints and app-session revocation.

Phase 2 checks completed: `npm run check` (typecheck, lint, 203 tests across
33 files and production build), `cargo test --manifest-path src-tauri/Cargo.toml
--all-targets --all-features` (238 tests), Cargo fmt, Clippy with warnings denied,
and `git diff --check`. The existing Vite main-chunk warning above 500 kB remains.

Added: `src/components/FilemanagerAccess.vue` and its `.test.ts`.
Updated: `src/views/FilemanagerView.vue` and its test, `src/services/tauri.ts`
and its test, `src/types/filemanager.ts`, `src-tauri/src/filemanager.rs`,
`commands.rs`, `state.rs`, `lib.rs`, this document and `ARCHITECTURE.md`.

Before use against real servers, manually verify both password steps, refusal of
an incorrect/changed host key, lock during login, route changes during a slow
connection, and existing terminal behavior. Automated transport-boundary tests
do not replace those real desktop/server checks.
