# Redaction

Cockpit builds a redaction table for each session before model requests,
exports, sync, and client-display boundaries. The table is populated from the
session environment, dotenv-style files, stored Cockpit secrets, private SSH key
material, and explicit `redact.denylist` values.

`redact.min_secret_length` applies only to prunable candidates from automatic
scans, but the table enforces a hard four-byte floor for every entry. Values
shorter than the applicable threshold are skipped, including forced sources
that fall below the hard floor.

`redact.allowlist` is an environment-variable name allowlist. It prevents values
from matching names such as `PATH` or a user-specified variable name from being
registered automatically. It is not a value allowlist.

File-derived dotenv values and private SSH key material are re-derived when a session resumes and are never stored in `cockpit.db`'s redaction snapshot. If a legacy file-derived entry cannot be re-derived, Cockpit emits a warning without logging its value. Stored named secrets, provider API keys, and OAuth tokens are redacted and may remain in the private session snapshot.

Filesystem paths are protected structurally. Cockpit never automatically
registers the session cwd/project root, git worktree root, `HOME`, `TMPDIR`, or
any ancestor of those paths. Existing absolute filesystem paths are also not
registered by automatic scanning. This guard still applies when
`redact.min_secret_length` is very low and when an older persisted redaction
table is merged into the current session table.

Forced entries are intentionally different:

- `redact.denylist` values at least four bytes long redact even if they equal a filesystem path.
- Stored named secrets and the FlyCockpit instance token at least four bytes long redact.
- Private SSH key material at least four bytes long redacts.

Use `redact.denylist` only for literal values at least four bytes long that must be scrubbed everywhere.

`redact.secret_path_patterns` adds gitignore-style path patterns to the built-in secret-bearing path floor (`.env*`, PEM/key files, common credential files, Terraform vars, npm/netrc files, and `.ssh`, `.aws`, `.gnupg` directories). The matcher itself never reads files; an authorized read registers only parsed values, never the whole file body.
Use `redact.allowlist` only for environment variable names that should be
excluded from automatic scanning.
