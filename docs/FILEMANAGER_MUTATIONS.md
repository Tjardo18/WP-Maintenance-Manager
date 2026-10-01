# Filemanager phase 7 — create and individual delete

Phase 7 adds only three server-side mutations: create an empty file in the
current virtual directory, create one directory there, and delete one existing
file, symlink or empty directory. It does not add rename, move, upload, download,
permissions controls, recursive removal or bulk actions.

All requests pass the existing app-session, site-bound filemanager authorization,
SSH session and root-relative POSIX resolver. The client supplies a current
directory plus a **name** for creation, not an arbitrary destination path. The
backend rejects empty names, `.`, `..`, separators, backslashes, control bytes,
replacement characters and traversal before joining it to a revalidated current
directory. Dotfiles are valid. SFTP receives paths and bytes as data; no shell is
used.

File creation uses SFTP `CREATE|EXCLUSIVE` and therefore never truncates an
existing item, including if another writer wins the race. The requested modes are
`0666` for files and `0777` for directories, so the server's umask determines the
safe actual defaults; no world-writable mode is forced. After successful creation
the browser refreshes the directory from the server; a new file is then opened in
the existing preview/editor.

Deletion reparses the virtual target, rejects `/`, resolves and revalidates its
parent, lstat-checks the final item and compares its current kind to the listing
kind supplied by the UI. Regular files and symlinks use `unlink`; a symlink is
never followed. Directories are checked for entries other than `.`/`..` and then
removed with `rmdir`. No recursive operation exists. A concurrently filled
directory safely fails `rmdir`; a missing or changed item returns a safe error.
As with the earlier SFTP resolver, separate remote requests cannot fully defeat a
hostile filesystem writer; server-side confinement remains the stronger boundary.

The UI exposes keyboard-accessible **Nieuw bestand** and **Nieuwe map** dialogs,
per-item destructive actions and explicit delete confirmation. It disables
duplicate mutation controls while an operation runs. Deleting an open dirty file
first uses the phase-6 discard guard; after a successful delete the preview closes
and the fresh directory listing replaces stale state.

Tests cover exclusive create, hidden/special Unicode names, invalid names and
traversal, matching file/directory collisions, empty/non-empty directory delete,
root delete rejection, symlink unlink semantics, frontend confirmation/cancel,
refresh/open-after-create, authentication expiry behavior and site-bound IPC.
No live SSH mutation test is claimed; first deployment should use a disposable
site to check its SFTP permissions, umask and non-empty-directory response.
