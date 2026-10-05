# Filemanager downloads — phase 9

Downloads use one authenticated Tauri command (`download_filemanager_items`). The
desktop application has no HTTP download endpoint, so HTTP-specific
Content-Disposition, Content-Type, Content-Length, cache and CSRF headers do not
apply. No download URL or credential is exposed to a browser or shared cache.
The native save dialog chooses the local destination. Existing files are never
overwritten, including if another process creates the chosen name after the
dialog closes.

The command checks the app session, site identity and site-bound filemanager
authorization before the dialog and again after it. The access manager checks
authorization again around the SSH operation and at SFTP work boundaries, including
each streamed chunk. A manager-wide reservation allows only one native download
dialog/transfer at a time, even when IPC is invoked directly.
A request for another site's ID
cannot reuse this site's filemanager token. The backend loads SSH configuration
and WordPress root from the stored site; the UI supplies only virtual paths and
item types. Bulk requests are limited to direct children of the current
directory and the existing maximum of 100 selections. Each file and directory
is resolved through the phase-3 secure path resolver. Symlinks, including
descendants within a selected directory, abort the entire download. They are
never followed or stored as links. This also prevents symlink loops.

One selected file is copied byte-for-byte from SFTP to a local file in 64 KiB
chunks; it is not loaded into memory as one buffer. One directory or multiple
selected items produce a ZIP on the local computer using the ZIP library's
streaming writer, with Stored entries (no compression). The archive starts at
the selected names relative to the current listing and includes only those
items plus descendants of selected directories. No server-side archive or shell
command is run. A central entry-name validator rejects traversal, absolute and
Windows drive paths, trailing-dot/space components and reserved Windows device
names before adding them to ZIP. ZIP names cannot contain the
absolute WordPress root. Changes or read errors while fetching a file abort the
operation rather than reporting a successful incomplete download. An open
editor's unsaved buffer is never used: downloads read the saved server version.

Limits: 4 GiB of source file data per download, 10,000 ZIP entries (files and
directories), 64 nested directory levels, 100 selected top-level items, 5,000
items per directory listing, and a 10-minute operation deadline. The entry limit
counts queued descendants, not just entries already written. One SSH session
is locked per filemanager access while downloading, so concurrent operations
using that access are rejected. The local disk must also have sufficient space.

The temporary output is a random-name file (`.wpmm-download-*`) created by
`tempfile` in the **user-chosen local destination directory**, never in the
public website root or on the remote host. `tempfile` uses restrictive file
creation permissions; Windows ACL inheritance remains governed by the chosen
folder's permissions. On success it is synced and atomically persisted without
overwriting another file. On errors, timeout, SSH disconnect or failed
authorization, its RAII handle removes it. The SSH/SFTP handles are released
after the operation. A hard process crash can leave this hidden partial file;
remove it manually if found. Cancelling the native save dialog writes nothing.
Tauri does not provide an HTTP-response disconnect for this command. Closing
the window after the operation starts may allow the worker to run until its
deadline; revocation is checked at subsequent SFTP work boundaries and before the
final file is published. An already-issued remote request cannot be rolled back.
The command uses the same `save_local` implementation exercised by real local
filesystem tests for partial transfer, revocation, collision and no-clobber publication.

The browser shows an in-progress state, success with the saved path, and safe
failure text. The current selection is kept after a successful download.
No upload, extraction, rename, copy, move or persistent backup was added.
