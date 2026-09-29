# Filemanager — authentication, safe paths, browser and previews

This feature is developed on `feature/filemanager`, with phase 1 on
`feature/filemanager-phase-1-foundation` and phase 2 on
`feature/filemanager-phase-2-auth`, followed by phase 3 on
`feature/filemanager-phase-3-directory-backend`, followed by phase 4 on
`feature/filemanager-phase-4-directory-browser` and phase 5 on
`feature/filemanager-phase-5-file-preview`. It must not be merged into `main`
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
  authorized finding and SFTP. Phase 5 separates its generic
  `FileContentPreview` presentation contract from the optional finding/delete
  permission, without fabricating a finding for filemanager files.
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

## Phase 3: safe paths and directory backend

`list_filemanager_directory` is an authenticated Tauri command, not an HTTP
endpoint. Its arguments are `sessionToken`, `siteId`, `authorizationToken` and
`requestedPath`. `appApi.listFilemanagerDirectory()` and TypeScript response
types are available for phase 4, but no directory-browser UI calls them yet.
The client cannot supply a root, host, port, username or credentials.

The command calls the phase-2 `require_filemanager_auth` guard before invoking
transport, loads `Site.wordpress_path` from the database, and uses the existing
password-authenticated SSH session. It checks the app session and authorization
again before returning successful results. Modified website configuration,
another site ID, missing/expired access, deleted websites and canceled sessions
cannot authorize a directory response. There is no vault/key fallback.
Network I/O uses a per-connection mutex, outside the global authorization mutex:
concurrent calls for that access return `filemanager_busy`; locking or revoking
access can proceed while a read is in flight. Revoked results are discarded.

### One path convention and resolver

`filemanager_paths.rs` owns `VirtualPath` and `ResolvedDirectory`. Client paths
are **virtual, website-root-relative POSIX paths**, optionally starting with `/`.
`/` and the empty string identify the website root. `/wp-content` identifies a
child of that root, not the server's `/wp-content`. Even an input that resembles
a full server path remains virtual and cannot override the configured root.
The response never includes the server's physical root.

The resolver removes duplicate separators and `.` components, handles `..` with
a component stack, and rejects an attempt to pop above the website root. Percent
encoding is **not decoded**: `%2e%2e` is a literal filename, not `..`. Phase 4 must
pass the returned path unchanged through IPC, without a second decoding layer.
Backslashes, control characters (including NUL/newlines), replacement characters,
paths above 4096 bytes and more than 128 components are rejected. Spaces, dots,
hyphens, underscores, Unicode, quotes and shell punctuation remain literal names.
The configured root must be absolute and must not normalize to server root `/`.

The remote resolver uses SFTP `lstat` on every component and `realpath` for the
root and requested directory. Containment accepts only an exact root match or
a descendant separated by `/`: `public_html_backup` is not within `public_html`.
Missing/ambiguous directory types fail closed. A `ResolvedDirectory` cannot be
constructed by the transport or client, only by this shared resolver.

### Symlink policy and remote-race limitation

The phase-3 policy deliberately **does not follow any symlink in a directory
path**, including the configured root and its ancestors. Internal, external,
broken and looping symlinks are equally non-navigable. A symlink may appear in
the listing as `kind: "symlink"`, without its target or followed metadata.
Hosting layouts that use a symlink for the root or an ancestor are therefore
blocked; configure the actual physical WordPress root if appropriate. Do not
relax this rule in frontend code.

Paths are validated before opening the directory, immediately after opening,
and again after reading. Results are discarded if an observed change creates a
symlink or changes the resolved target. **SFTP v3 does not provide atomic
`openat2`/`RESOLVE_BENEATH`/`O_NOFOLLOW` directory traversal or a portable inode
identity check.** A malicious process that replaces and restores paths between
these separate operations can evade revalidation. This is defense against path
input and ordinary/stable symlink escapes, not a filesystem sandbox against a
hostile server or concurrent attacker with filesystem write access. A stronger
guarantee requires server-side confinement (for example an SFTP chroot) or an
appropriately sandboxed server helper. Future write/delete operations require a
separate design review; they must not assume these read-only checks are atomic.

### Listing transport, metadata and limits

`filemanager_directory.rs` orchestrates resolution and typed listing. Its narrow
`DirectoryTransport` test seam is implemented in the existing `ssh.rs` using
`Session::sftp`, `opendir` and handle-based `readdir`. No `ls`, shell construction,
remote script, recursive walk, file-content read or MIME scan is involved.

Responses contain `currentPath`, `isRoot`, nullable `parentPath`, `items` and
`truncated`. At `/`, `parentPath` is always null. Every item contains:

- `name`, virtual `path`, and `kind` (`directory`, `file`, `symlink`, `other`);
- nullable `extension`, regular-file `size` in bytes, octal `permissions`
  (including special permission bits) and UTC RFC3339 `modifiedAt`;
- null for missing/unreliable metadata and directory/symlink sizes, never a
  fabricated recursive directory size.

Dotfiles are included; only literal `.` and `..` entries are skipped. Sorting is
directories, files, symlinks, other, then Unicode lowercase name and original
name as a deterministic tie-breaker. The listing is limited to 5000 items and
5003 `readdir` calls, with a 20-second work budget and a maximum 5-second timeout
per blocking SFTP call. Handle/channel cleanup may add bounded transport time.
`truncated` explicitly marks an incomplete subset; there is no pagination yet.

Malformed names, duplicate entries and undecodable UTF-8 fail the entire
listing rather than silently returning a different or unsafe identifier. This
includes containing the existing ssh2 Windows filename-decoder panic. No server
message or absolute path is put in the error response: SFTP diagnostics contain
numeric error codes only. Typed errors distinguish invalid paths, escaped roots,
blocked symlinks, non-directories, missing directories, permissions, timeout,
disconnect and invalid responses. Transport failure/timeout/decoding failure
revokes filemanager access; ordinary missing-directory/permission errors do not.

## Phase 4: directory browser and navigation

`FilemanagerAccess.vue` still owns the two-password flow and its one
authorization token. Only after its server-side guard succeeds does it mount
`FilemanagerBrowser.vue`; the browser receives the current website context and
that ephemeral token as props. An authorization error from a directory request
emits `expired` back to the access component, which immediately unmounts the
browser, clears its state, revokes access through the existing cleanup flow and
returns to the app-password step. No directory content remains visible.

The browser makes exactly one `appApi.listFilemanagerDirectory(siteId, token,
virtualPath)` request for each successful navigation. It does not derive a server
root, construct physical paths, run SSH, request per-file metadata, or validate
path traversal itself. It displays the phase-3 response unchanged in security
terms: virtual root-relative paths only. The backend remains authoritative for
authorization, website isolation, root enforcement, normalization and symlinks.

`FilemanagerBreadcrumbs.vue` derives display segments only from the backend's
safe `currentPath`: **Hoofdmap** followed by virtual directory segments. Each
ancestor returns the exact virtual path to the same directory API; the active
segment is disabled. No physical server path is invented, exposed or stored in
the route. Directory state is intentionally internal rather than query state:
a deep link first authenticates and then safely starts at `/`.

The browser maintains a per-mounted-component history stack. A successful normal
navigation records the preceding directory; back navigation loads and removes
only the prior successful path. Failed requests never affect history. One-level
up uses the backend's nullable `parentPath`, not frontend string slicing; at root
the Up control is disabled. A new website context keys and unmounts the complete
access/browser tree, so token, current listing, history, breadcrumbs and pending
responses from website A cannot appear for website B.

While a listing is loading, directory, back, up, breadcrumb and refresh controls
are disabled. A monotonically increasing request ID also discards an older result
when a newer request exists, including during unmount. The interface shows a
spinner, a distinct empty-folder state, a bounded-list warning and existing safe
error banner. It formats backend byte values locally (without recursively sizing
directories), uses the existing Dutch date formatter, and renders permissions
read-only. Directories are buttons with keyboard focus and labels; files are not
interactive in phase 4. The table is horizontally scrollable on narrow screens,
long file names truncate visually but retain a full-name tooltip, and breadcrumbs
scroll horizontally.

## Phase 5: secure file reads and shared preview

Regular files in `FilemanagerBrowser.vue` are keyboard-accessible buttons.
Selecting one calls `appApi.readFilemanagerFile(siteId, authorizationToken,
virtualPath)` and shows an accessible loading state. Directories retain their
phase-4 navigation behavior. A successful response opens the existing
`ChecksumFilePreview.vue`; closing it, pressing Escape or choosing **Terug naar
map** reveals the still-mounted directory listing and preserves its history.
Separate request IDs discard a late response when another file was selected or
the website/component was unmounted. The response path must exactly equal the
requested virtual path before it is rendered.

`read_filemanager_file` repeats the app-session and phase-2 filemanager guard
before transport, loads the current site from SQLite, normalizes the client path
as a phase-3 `VirtualPath`, and rechecks both guards before returning success.
The token remains bound to the app session, site UUID and current SSH/root/host
configuration; a token for website A cannot invoke transport for website B.
The client cannot submit an SSH host, credentials or physical server root.

`ResolvedFile` extends the phase-3 resolver rather than introducing another path
scheme. It resolves the target's parent with `ResolvedDirectory`, validates the
final name, uses SFTP `lstat`/`realpath`, requires a regular file, rejects a final
symlink and enforces exact root containment. Metadata is compared before opening,
on the opened handle and after reading. A changed target is discarded. SFTP paths
are passed as paths, never interpolated into a shell command, so spaces, Unicode,
quotes and shell punctuation remain literal. The same documented SFTP-v3 remote
race limitation still applies; server-side confinement is required against a
hostile process that can replace and restore paths between checks.

The read is bounded centrally in `filemanager_file.rs`: text/unknown formats use
256 KiB and existing supported image/SVGZ formats use 10 MiB. At most limit + 1
bytes are read to determine truncation; oversized content is returned as an
explicitly truncated preview, never loaded without a limit. Invalid UTF-8 or NUL
content is binary and is not presented as source. Supported binary images reuse
the existing allowlisted MIME/data-URL path and byte inspector; unsupported
binaries show the existing no-readable-source state. Missing files, a directory
at the former file path, permission denial, transport timeout/disconnect and a
file changed during reading produce typed safe errors without credentials or
physical paths.

The shared preview provides existing highlighting for PHP templates (including
embedded HTML/CSS/JavaScript/JSON), JavaScript, CSS/SCSS, HTML/XML/SVG, JSON,
Markdown, Twig, `.htaccess`/Apache and logs. Plain text, dotfiles and extensionless
files remain safely visible without artificial highlighting when no grammar is
known. It provides the same line numbers, fullscreen/Escape behavior and saved
fullscreen/Markdown defaults as finding previews. Markdown rendering keeps raw
HTML disabled and only delegates HTTP(S) links to the validated external opener;
SVG is sanitized before a data URL is created. HTML/XML/JavaScript source is not
executed. The preview remains strictly read-only.

## Next phases (not implemented)

Future write operations belong in `filemanager.rs`, with the established
`ssh.rs` transport, backend-owned site context and centralized path validation.
Do not use metadata or UI state as authorization and do not substitute stored
credentials for the two-password gate. Phase 6 may add editing only after a
separate write, conflict, atomicity and authorization review. Mutations,
permissions, downloads, archives and bulk operations have not been implemented.

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

Phase 4 tests cover initial root load, metadata rendering, ordinary directory
opening, Up, Back, virtual breadcrumbs, root-disabled navigation, empty folders,
safe server errors, authorization expiry, website A/B isolation and late A
responses after unmount. The access/view tests ensure the browser is mounted only
after both passwords and uses the existing cleanup on context changes. Tests use
mocked API responses and do not create an alternate browser/demo directory API.

Phase 4 added `src/components/FilemanagerBrowser.vue`,
`FilemanagerBreadcrumbs.vue` and `FilemanagerBrowser.test.ts`. It updated
`FilemanagerAccess.vue` and existing filemanager access/view tests. There are no
backend, database, dependency, version, route query or file-operation changes.

Phase 4 checks completed: `npm run check` (typecheck, lint, 209 frontend tests
across 34 files and production build), Cargo fmt, `cargo test --manifest-path
src-tauri/Cargo.toml --all-targets --all-features` (256 tests), Clippy with warnings
denied, and `git diff --check`. The existing Vite main-chunk warning remains. No
live SSH server or manual desktop session was used for this phase.

Phase 5 tests cover secure file resolution, traversal underflow, canonical and
symlink escape, directory-versus-file rejection, file changes around the read,
central size limits, UTF-8/Unicode, binary classification, authorization before
transport, website A/B isolation and post-operation authorization. Frontend tests
cover code/dotfile/space/Unicode opening, escaped active content, line numbers,
directory-context preservation, safe permission errors, expired/disconnected
access, binary unsupported state, overlapping file requests and reuse of saved
Markdown/fullscreen behavior. Existing checksum preview tests remain the
regression baseline for syntax, Raw/Preview, SVG/Markdown sanitization, images,
fullscreen, scroll position and Escape.

Phase 5 added `src-tauri/src/filemanager_file.rs`. It updated the shared preview
contracts, checksum preview builder, phase-3 path resolver, authenticated
filemanager service/command and SFTP adapter, TypeScript API/types,
`FilemanagerBrowser.vue` and its tests. There are no dependencies, migrations,
version changes, routes, writes, deletes, downloads or phase-6 editor controls.

Phase 5 checks completed: `npm run check` (typecheck, lint, 213 frontend tests
across 34 files and production build), Cargo fmt, `cargo test --all-targets
--all-features` (262 tests), Clippy with warnings denied and `git diff --check`.
The existing Vite main-chunk warning above 500 kB remains. Verification used the
mocked SFTP/API boundaries; no live SSH server or manual desktop session was used.

Phase 3 checks completed: `npm run check` (typecheck, lint, 204 tests across
33 files and production build), Cargo fmt, `cargo test --manifest-path
src-tauri/Cargo.toml --all-targets --all-features` (256 tests), Clippy with warnings
denied, and `git diff --check`. The existing Vite main-chunk warning remains.
No real SSH server or manual desktop session was used for verification.

The phase-3 tests explicitly cover normal and dotted paths, traversal underflow,
duplicate separators, virtual absolute paths, literal encoded input, prefix
collisions, symlink components/ancestors, canonical escapes, revalidation after
open/read, shell punctuation, Unicode/space/dotfile names, malformed/duplicate
entries, metadata/null handling, stable sorting, root/parent navigation and
bounded large listings. Authorization tests verify no transport invocation for
missing auth, another website, an unknown website or traversal, and rejection of
results after lock/revocation. Additional tests verify per-connection concurrency,
transport-failure revocation, safe SFTP error mapping and decoder-panic handling.
Existing terminal tests remain green. Remote filesystem behavior is modeled at
the SFTP boundary; this does not claim to test a real malicious race or hosting
server. A live smoke test should verify the host's SFTP/realpath support, the
strict symlink policy, permissions, empty/large directories and reconnect flow.

Phase 3 added `src-tauri/src/filemanager_paths.rs` and
`src-tauri/src/filemanager_directory.rs`. Updated `src-tauri/src/filemanager.rs`,
`commands.rs`, `ssh.rs`, `lib.rs`, `src/services/tauri.ts` and its tests,
`src/types/filemanager.ts`, `ARCHITECTURE.md` and this document. There are no
database migrations, new dependencies, version changes or phase-4 UI changes.
