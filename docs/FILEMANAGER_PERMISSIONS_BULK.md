# Filemanager phase 8 — permissions and bulk actions

The directory listing shows numeric Unix permissions for files and folders.
The permissions action accepts exactly three octal digits (`000` through `777`).
The backend parses the value in base eight and sends an SFTP `setstat` request;
no shell command or automatic permission escalation is used. Permissions can be
changed for one regular file or directory, never a symlink or the filemanager
root. Directory permissions apply only to the directory inode, not its children.

Selection uses virtual paths scoped to the current site and directory. The
checkbox in the table header selects every selectable item in the loaded
listing; it does not traverse subdirectories. Selection clears when navigating,
changing sites, or refreshing the listing. Up to 100 items can be changed in a
single bulk request. The UI disables bulk actions above that limit, and the
backend enforces it independently.

The bulk backend validates the whole request before any mutation: authentication,
site, mode, count, duplicate paths, canonical virtual paths, parent directory,
root protection, and symlink rules. It then runs the existing per-item delete or
permission primitive over the same SFTP connection. Deletion still uses `unlink`
for files/symlinks and `rmdir` only for empty directories. Both bulk operations
report requested, successful and failed counts with a safe error per failed
virtual path. Operational failures are not rolled back; no recursive operation is
performed. Bulk deletion always requires explicit confirmation.

SFTP mutations are path based. The backend revalidates parents and checks item
types immediately before each operation, but SFTP does not provide an atomic
`openat`-style containment guarantee against an adversary changing the remote
filesystem between requests. Deployments requiring that level of guarantee need
server-side filesystem isolation of the SSH account.
