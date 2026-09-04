#!/usr/bin/env bash
set -euo pipefail

# Tenant-authority acceptance-manifest ratchet.
#
# 1. Source scan: every `#[test] fn tenant_authority_*` in this package must
#    live only in `tests/tenant_authority_service_acceptance.rs` (feature-
#    independent; closes prefixed tests gated on a future non-remote feature).
# 2. Nextest list: within `cargo nextest list -p tenant-authority --features
#    remote --message-format json`, every `tenant_authority_*` name must come
#    from binary `tenant_authority_service_acceptance`, the complete
#    lexicographically sorted manifest must match exactly the nine names in
#    `verify_tenant_authority_acceptance_manifest.mjs`, and none may have
#    `ignored=true`.
#
# This script must itself run as an unconditional `run:` step of a blocking
# pull_request/push job. A comment in the verifier or acceptance suite
# documenting a manual command is not that binding.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

MANIFEST_CMD="bash scripts/check-tenant-authority-acceptance-manifest.sh"
WORKFLOW=".github/workflows/cli-ci.yml"

python3 - <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

MANIFEST_CMD = "bash scripts/check-tenant-authority-acceptance-manifest.sh"
WORKFLOW = Path(".github/workflows/cli-ci.yml")


def die(msg: str) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(1)


def workflow_triggers(text: str) -> set[str]:
    events: set[str] = set()
    on_list = re.search(r"(?m)^on:\s*\[([^\]]+)\]", text)
    if on_list:
        for part in on_list.group(1).split(","):
            events.add(part.strip().strip("'\""))
        return events
    on_map = re.search(r"(?m)^(?:\"on\"|on):\s*\n((?:  .*\n)+)", text)
    if on_map:
        for line in on_map.group(1).splitlines():
            key = line.strip()
            if key.endswith(":"):
                key = key[:-1].strip()
            key = key.strip("'\"")
            if key and not key.startswith("#"):
                events.add(key)
    return events


def split_jobs(text: str) -> dict[str, str]:
    jobs_at = text.find("\njobs:\n")
    if jobs_at < 0:
        return {}
    body = text[jobs_at + len("\njobs:\n") :]
    header = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$", re.M)
    matches = list(header.finditer(body))
    jobs = {}
    for idx, match in enumerate(matches):
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(body)
        jobs[match.group(1)] = body[start:end]
    return jobs


def job_continue_on_error(job: str) -> bool:
    return bool(re.search(r"(?m)^    continue-on-error:\s*true\s*$", job))


def job_if(job: str) -> str:
    match = re.search(r"(?m)^    if:\s*(.+)$", job)
    return match.group(1).strip() if match else ""


def is_blocking_job(triggers: set[str], job_if_expr: str, continue_on_error: bool) -> bool:
    if continue_on_error:
        return False
    if "pull_request" not in triggers and "push" not in triggers:
        return False
    if "workflow_dispatch" in job_if_expr and "inputs." in job_if_expr:
        return False
    if re.search(r"github\.event_name\s*==\s*'workflow_dispatch'", job_if_expr):
        return False
    return True


def parse_job_steps(job: str) -> list[tuple[str, str, str, bool]]:
    """Return (name, if_expr, script, continue_on_error) for each step."""
    lines = job.splitlines()
    i = 0
    while i < len(lines):
        if re.match(r"^    steps:\s*$", lines[i]):
            i += 1
            break
        i += 1
    else:
        return []

    steps: list[tuple[str, str, str, bool]] = []
    current: dict | None = None

    def flush() -> None:
        nonlocal current
        if current is None:
            return
        steps.append(
            (
                current["name"],
                current["if"],
                current["script"] or "",
                current["continue_on_error"],
            )
        )
        current = None

    while i < len(lines):
        line = lines[i]
        if line.strip() and not line.startswith("      "):
            break
        if re.match(r"^      - ", line):
            flush()
            current = {
                "name": "",
                "if": "",
                "script": None,
                "continue_on_error": False,
            }
            rest = line[len("      - ") :]
            if rest.startswith("name:"):
                current["name"] = rest[len("name:") :].strip().strip("'\"")
            elif rest.startswith("run:"):
                current["script"] = rest[len("run:") :].strip()
            i += 1
            continue
        if current is None:
            i += 1
            continue
        stripped = line.strip()
        if stripped.startswith("name:"):
            current["name"] = stripped[len("name:") :].strip().strip("'\"")
        elif stripped.startswith("if:"):
            current["if"] = stripped[len("if:") :].strip()
        elif stripped.startswith("continue-on-error:"):
            current["continue_on_error"] = stripped.endswith("true")
        elif stripped.startswith("run:"):
            current["script"] = stripped[len("run:") :].strip()
        i += 1
    flush()
    return steps


def assert_manifest_ratchet_is_blocking() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    triggers = workflow_triggers(text)
    jobs = split_jobs(text)
    job = jobs.get("remote-lockstep")
    if job is None:
        die("remote-lockstep job missing from cli-ci.yml")
    blocking = is_blocking_job(triggers, job_if(job), job_continue_on_error(job))
    if not blocking:
        die("remote-lockstep is not a blocking pull_request/push job")
    hits: list[str] = []
    for name, if_expr, script, cont in parse_job_steps(job):
        if MANIFEST_CMD not in script:
            continue
        loc = f"remote-lockstep step `{name or '(unnamed)'}`"
        if if_expr or cont:
            die(f"{loc}: manifest ratchet step is conditional or continue-on-error")
        hits.append(loc)
    if not hits:
        die(
            "tenant-authority acceptance-manifest ratchet is not bound to "
            f"remote-lockstep as an unconditional `run: {MANIFEST_CMD}` step"
        )


def assert_prefix_reserved_in_acceptance_only() -> None:
    pkg = Path("apps/tenant-authority")
    acceptance = pkg / "tests" / "tenant_authority_service_acceptance.rs"
    pattern = re.compile(
        r"(?m)^\s*#\[test\]\s*\n\s*fn\s+(tenant_authority_[A-Za-z0-9_]+)\s*\("
    )
    violations: list[str] = []
    for path in sorted(pkg.rglob("*.rs")):
        if path == acceptance:
            continue
        text = path.read_text(encoding="utf-8")
        for match in pattern.finditer(text):
            violations.append(f"{path}:{match.group(1)}")
    if violations:
        die(
            "tenant_authority_* test-name prefix is reserved for the nine "
            "acceptance suites in tests/tenant_authority_service_acceptance.rs; "
            f"found elsewhere: {', '.join(violations)}"
        )


assert_manifest_ratchet_is_blocking()
assert_prefix_reserved_in_acceptance_only()
PY

cargo nextest list --locked \
  -p tenant-authority \
  --features remote \
  --message-format json \
  | node apps/tenant-authority/tests/verify_tenant_authority_acceptance_manifest.mjs
