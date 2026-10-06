# Filemanager phase 6 — existing text files

This phase targets `feature/filemanager`, never `main`/`master`. No dependencies,
database migrations or application-version changes are required. Creating/deleting
files, permissions and downloads were added in phases 7–9; this document describes
the phase-6 editing design. See [FILEMANAGER_AUDIT.md](FILEMANAGER_AUDIT.md) for
the phase-10 verification scope and rollout gates.

## User flow

Open a file through the authenticated filemanager and choose **Bewerken**.
The existing preview owns the edit state and reuses the confirmation dialog.
`FileTextEditor.vue` provides a bounded plain-text textarea with aligned line
numbers, horizontal/vertical scrolling and fullscreen support. There was no
existing editable code-editor component. Syntax highlighting remains available
in the read-only preview; text editing does not execute HTML, PHP or JavaScript.

**Opslaan** is explicit, disabled without changes, and protected against repeat
submissions. **Annuleren**, close, Escape, file/directory navigation and router
navigation ask before discarding dirty content. Close/navigation is blocked
during a save. A browser unload receives the standard unsaved-change signal;
native forced termination cannot guarantee a dialog. No autosave/draft persistence
is introduced. App lock still clears protected content. Expiring filemanager
access revokes the connection but retains a dirty editor in memory so the user
can copy it before confirming discard/re-authentication.

Success replaces the preview, version token and directory size/mtime from the
backend result. Raw and rendered views derive from this new source. On failure
the draft remains and **Herlaad bestand** offers a guarded reload. Conflicts are
never automatically retried or force-overwritten.

## Editable content

Valid UTF-8 text up to 256 KiB, including `.php`, `.js`, `.css`, `.html`, `.json`,
`.md`, `.htaccess`, `.xml`, `.twig`, `.scss`, `.txt`, `.svg`, logs and extensionless
text. The backend rejects control/binary bytes, known binary extensions, invalid
UTF-8 and oversized input/originals. Truncated previews never receive an edit
version. This is text classification, not malware detection.

UTF-8 Unicode and an existing BOM are retained. Textareas use LF internally;
the adapter restores original newline sequences by index, falling back to the
dominant CRLF/LF style for additional lines. An unchanged buffer reproduces the
original exactly. Mixed-ending files retain their sequence by line index, not
by tracking moved lines. Neither the transport nor backend normalizes content.

## Backend and integrity

`save_filemanager_file` uses the authenticated IPC wrapper, the shared file
operation authorization boundary, the phase-2 session/site/configuration-bound
access manager, and the phase-3 virtual-path resolver. Client input contains
only a relative virtual path, UTF-8 content and expected version, never SSH
credentials or server root. The access manager serializes saves within the app
process, also across independently authorized editors. Network work runs outside
the global authorization lock.

1. Authorize and resolve an existing regular, non-symlink file inside the stored
   root. Recheck root/ancestor canonical paths and metadata around I/O.
2. Read bounded bytes and compare SHA-256 of physical path, size, mtime, mode,
   UID/GID and content with the expected version issued during preview loading.
3. Probe actual write permission by opening WRITE without CREATE or TRUNCATE.
4. Exclusively create `.wpmm-save-<random-UUID>.tmp` in the same directory with
   mode 0600. Never overwrite a pre-existing temporary filename.
5. Write bounded chunks, restore original UID/GID where necessary, restore mode,
   verify metadata, fsync, read back the temporary bytes and close the handle.
   Failure to preserve ownership/mode aborts replacement. No old mtime is set.
6. Re-resolve/recheck the original, reread its content and compare again; recheck
   authorization immediately before replacement.
7. Use the server's `posix-rename@openssh.com` SFTP extension for atomic replacement.
   Read the resulting file and verify content/metadata before returning success.

The ssh2 wrapper's ordinary rename only supplies protocol flags that v3 servers
can ignore. `sftp_replace.rs` therefore implements the small bounded v3 handshake
and posix-rename exchange on a dedicated SFTP subsystem channel of the **same**
authenticated SSH session. No shell runs; paths and source bytes are length-framed
protocol values. The server must advertise this extension and support fsync.
Unsupported servers fail safely instead of falling back to truncate or delete.

Missing files are not recreated. Directories and symlinks cannot be replaced.
An external edit, including changed content with identical size and mtime, causes
a conflict. A successful first editor invalidates a second editor's old token.
Write/quota/permission/replace failures attempt removal of only the operation's
own temporary file. A collision is never cleaned up. After a lost connection,
cleanup may be impossible; the error warns of a possible `.wpmm-save-*.tmp` residue.
On later interactive directory opening, bounded best-effort recovery can remove
strictly recognized regular save temps older than one hour. It does not change
the safe-write sequence. See [FILEMANAGER_SAVE_RECOVERY.md](FILEMANAGER_SAVE_RECOVERY.md)
for the exact UUID pattern, age/concurrency checks, failure behavior and limits.
No content, passwords or server-provided error text is logged; diagnostics use
numeric SFTP/OS codes. An unconfirmed save never returns success.

## Important limits and live verification

SFTP does **not** provide rooted descriptor operations or compare-and-swap rename.
The last validation and replacement are separate requests. An external process
can still race that final window, remove/recreate the target, or replace a parent
directory; repeated checks are not a hostile-filesystem sandbox. Use server-side
chroot/SSH isolation when other writers are untrusted. Process-local serialization
does not coordinate another app process or external editor.

Atomic replacement creates a new inode. Mode, UID and GID are verified, but v3
does not expose ACLs, extended attributes or hardlink identity for preservation.
Do not use this editor for files depending on those special attributes. Temporary
files reside inside the site's directory and briefly receive the original mode;
the hosting configuration should deny HTTP access to dotfiles. fsync confirms the
file content, not a durable fsync of the parent directory. A disconnect after
rename may mean the save happened but its success cannot be confirmed: reconnect
and inspect before retrying.

Automated tests model transport failures, conflicts and authorization boundaries;
they are not a live-server atomicity test. Before production rollout, verify on a
disposable site: OpenSSH extension/fsync support, mode/ownership retention, same
directory permissions, CRLF/BOM, two editors, external deletion/change, quota,
disconnect cleanup and the existing SSH terminal. No production files should be
used as test targets. Phase 7 must keep the resolver/auth boundary and explicitly
review create/delete races rather than assuming SFTP checks are atomic.

## Implementation map and automated coverage

Added `src-tauri/src/filemanager_edit.rs` (central save flow and transport tests),
`sftp_replace.rs` (bounded extension exchange/tests), `src/components/FileTextEditor.vue`,
`FileEditing.test.ts`, `src/services/fileEditing.ts` and `fileEditing.test.ts`.
Updated the shared preview/model, filemanager access/browser, authenticated IPC
command/API, SFTP adapter, app command registration and related tests/docs.

Backend cases include successful exact-byte saves with mode 644/755/640 and UID/GID,
Unicode/shell punctuation, same-size/same-mtime external edits, second-editor
conflicts, auth revocation, cross-site writes, simultaneous saves, missing or
non-regular targets, traversal, binary/oversized content, temp collisions,
permission/quota/write/replace failures and disconnect cleanup warnings. Protocol
tests cover extension negotiation, status failures, framing and incomplete input.
Frontend cases cover explicit save, disabled unchanged/in-flight saves, draft
retention on errors, discard confirmation, Escape, router cancellation, site-bound
IPC, refreshed preview/version, expired access, raw XSS strings and BOM/newlines.
Existing preview, scan and SSH terminal tests remain part of the regression suite.
