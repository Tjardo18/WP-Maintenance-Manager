# Filemanager — phase 1 foundation

This feature is developed on `feature/filemanager`, with phase 1 on
`feature/filemanager-phase-1-foundation`. It must not be merged into `main`
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

## Next phases (not implemented)

Phase 2 can reuse app-password verification, host verification, SSH password
authentication, rate limiting and ephemeral authorization patterns. Challenges
and file sessions must be purpose-bound so terminal authorization cannot grant
filemanager access. Extend shared helpers only when that phase requires it;
preserve terminal behavior and lock/site-removal cleanup.

Future file operations belong in `filemanager.rs`, with the established `ssh.rs`
transport providing SFTP, and backend-owned site context and centralized path
validation. Do not use the current metadata endpoint as file authorization or
silently substitute stored credentials for the planned two-password gate.
Directory navigation, path security, preview integration, editing, mutations,
permissions, downloads, archives and bulk operations are all outside phase 1.

## Verification

Route tests cover site changes, delayed responses, missing sites and unmounts.
Existing terminal/auth tests remain the regression baseline. Opening this page
requires only local metadata and never establishes a remote session.

Phase 1 checks completed: `npm run check` (typecheck, lint, 191 tests and Vite
build), `cargo test --manifest-path src-tauri/Cargo.toml --all-targets
--all-features` (229 tests), Cargo fmt and Clippy with warnings denied, and
`git diff --check`. The existing Vite warning about a main chunk above 500 kB
remains; the filemanager view is loaded as a separate route chunk. These are
automated checks, not a live-server or manual desktop test.
