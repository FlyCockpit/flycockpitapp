---
title: Dependency health snapshots
description: Read-only CLI and Settings dependency diagnostics.
---

`cockpit doctor --dependencies-json` prints dependency health schema version 1.
The command runs in-process and does not require or start the Cockpit daemon.
It waits at most two seconds; unfinished applicable checks are reported as
`timed_out`. Configured harness, LSP, and MCP commands are checked for
resolution and spawnability but are never executed.

Rows include a stable dependency ID, state, importance, execution target,
required and discovered versions when known, typed safe cause/remedy data, and
the same bounded `reason` displayed by Settings and text doctor output. The
document never includes raw probe output, environment variables, credentials,
or configured command arguments.
