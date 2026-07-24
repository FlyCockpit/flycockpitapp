# Redaction

Cockpit builds a redaction table for each session before model requests,
exports, sync, and client-display boundaries. The table is populated from the
session environment, dotenv-style files, stored Cockpit secrets, private SSH key
material, and explicit `redact.denylist` values.

`redact.min_secret_length` applies only to prunable candidates from automatic
scans. Values shorter than the threshold are skipped unless they come from a
credential-shaped variable name or a forced source.

`redact.allowlist` is an environment-variable name allowlist. It prevents values
from matching names such as `PATH` or a user-specified variable name from being
registered automatically. It is not a value allowlist.

Filesystem paths are protected structurally. Cockpit never automatically
registers the session cwd/project root, git worktree root, `HOME`, `TMPDIR`, or
any ancestor of those paths. Existing absolute filesystem paths are also not
registered by automatic scanning. This guard still applies when
`redact.min_secret_length` is very low and when an older persisted redaction
table is merged into the current session table.

Forced entries are intentionally different:

- `redact.denylist` values always redact, even if they equal a filesystem path.
- Stored named secrets and the FlyCockpit instance token always redact.
- Private SSH key material always redacts.

Use `redact.denylist` only for literal values that must be scrubbed everywhere.
Use `redact.allowlist` only for environment variable names that should be
excluded from automatic scanning.
