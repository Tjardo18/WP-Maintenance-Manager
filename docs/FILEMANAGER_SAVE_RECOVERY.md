# Interrupted save recovery — stale internal tempfiles

Implemented on `feature/filemanager-stale-save-temp-cleanup`, targeting only
`feature/filemanager`. No version/dependency changes, background service,
recursive scan or production-branch merge.

## Existing save behavior is retained

The save path resolves the existing regular file, checks the expected content/
metadata version and write access, then exclusively creates a same-directory
temporary file with mode 0600. It writes and verifies the bytes, preserves original
mode/UID/GID, fsyncs, rechecks the original and authorization, and atomically
replaces it via the OpenSSH SFTP rename extension. It never truncates the original.

Success consumes the temp name through rename. Failure still immediately attempts
to unlink only the temp created by that operation. A disconnected connection can
prevent that attempt. The reported live test retained `atomic-test.txt` containing
`versie 3`, mode 0644 and its owner/group, with an empty 0600 temp left behind.
The new regression models this failure and subsequent recovery; it is not a new
live-server test.

## Exact identity and age

`filemanager_save_temp::new_name` and `is_save_temp` share this convention:

```text
.wpmm-save-<canonical lowercase hyphenated RFC4122 UUID v4>.tmp
```

Non-v4 IDs, nonstandard variants, uppercase/compact UUID encodings, suffixes,
ordinary `.tmp` files and similar-looking names do not match. There is no wildcard
delete, shell command, content scan or broad `.wpmm-*` rule.

`STALE_SAVE_TEMP_AGE` is **one hour**. A candidate must be **strictly older**
than 3,600 seconds: exactly on/below the boundary is kept. Missing/unparseable
mtime, a future timestamp and missing/non-regular type metadata fail closed.
Age compares remote mtime with UTC on the computer, so clocks must be reasonably
synchronized. Age is a conservative recovery heuristic, not proof of provenance.

The one-hour threshold is far longer than the existing bounded 30-second save.
The access manager additionally uses its existing process-wide save mutex:
listing with cleanup cannot overlap an app save. If a save is already active,
listing skips cleanup rather than waiting for that mutex (the same SSH connection
can still be busy as before). This does not lock other processes or external tools.

## Trigger and bounds

Only the authenticated **interactive filemanager directory listing** invokes the
recovery wrapper. Returning to a directory or refreshing it can therefore remove
old residues after reconnecting. Merely authenticating does not recursively search
the website. The existing archive traversal still uses the read-only listing.

Candidates are selected from metadata already obtained by the normal listing.
Non-candidates incur no additional SSH lookups. Cleanup considers at most
`MAX_CLEANUP_CANDIDATES = 8` old candidates per request, with
`CLEANUP_BUDGET = 2 seconds` for additional blocking SFTP work, also bounded by
the listing's existing deadline. Transport teardown can add its existing bounded
time. More residues can require later refreshes; permission failures are not
promised to disappear.

## Security and failure behavior

For each candidate, the ordinary backend-owned website root and secure file
resolver are reused. Cleanup checks a regular file, canonical containment,
non-symlink ancestors and leaf, unchanged listing mtime/size, and repeats full
metadata/path validation immediately before unlink. The SFTP adapter checks live
authorization again at work boundaries. No new IPC endpoint, physical client path,
alternate credential source or cross-site access bypass exists.

Directories, symlinks, sockets/devices and other types are never automatic targets.
Symlink targets are not followed. Only individual regular files are unlinked.

Operational errors (permissions, missing/changed item, removal failure, timeout or
disconnect) are best-effort. Failed/uncertain removals remain in the returned
listing; no cleanup success is invented. Disconnect/timeout stops further cleanup
work. Authorization failures and unsafe paths fail closed instead of returning a
potentially unsafe listing. Logging contains counts only, no server path, content
or credentials.

The save warning still tells the user to check server content after reconnecting.
It now says that the app **tries** to clean its own save files older than an hour
when the directory is opened later. It deliberately does not guarantee removal.

SFTP v3 still cannot atomically combine validation and unlink. An external writer
that maliciously swaps paths between requests is outside this guarantee; use
server-side confinement for untrusted writers. Other tools must not reuse the
internal filename namespace or falsify timestamps. Clock skew, a hard crash,
unavailable SSH, missing permission or a directory that is never revisited can
leave residues. Recovery does not replace HTTP protection of temporary dotfiles.

## Automated verification

New cleanup tests exercise the real wrapper used by interactive SFTP listing:

- exact generated UUID convention and malformed/lookalike names;
- multiple old files, recent files, exact/under threshold, missing/future mtime;
- regular-file-only filtering, directories, symlinks, sockets and devices;
- no extra lookup for non-candidates and skipping during an active-save reservation;
- current-directory scope, nested/other-root preservation and traversal refusal;
- metadata/type replacement between listing and deletion;
- permission/removal failures, disconnect/timeout, fail-closed auth/path errors;
- bounded candidate count;
- external symlink target and prefix/canonical escape protection.

An additional integration-model test runs the existing save service into a
connection/cleanup failure, verifies original bytes/mode/UID/GID and empty 0600
residue, reconnects without deleting the recent residue, advances time, then
uses the recovery listing and verifies only the old internal temp disappears.
The existing all-service cross-site/expiry tests and safe-write/rename/conflict/
permission tests remain part of the complete suite.

Full check results and Git merge information are recorded in the PR and hand-off.
No production file was modified to test this fix.

