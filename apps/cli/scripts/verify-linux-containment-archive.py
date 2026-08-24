#!/usr/bin/env python3
"""Validate one target-specific, checksummed Linux containment bundle."""

import hashlib
import sys
import tarfile
from pathlib import Path

if len(sys.argv) != 4:
    raise SystemExit("usage: verify-linux-containment-archive.py OUTPUT_DIR TARGET RELEASE_TAG")
root, target, release_tag = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
if target not in {"x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"}:
    raise SystemExit(f"not a supported Linux target: {target}")
archive = root / f"flycockpit-containment-{release_tag}-{target}.tar.gz"
checksum = Path(f"{archive}.sha256")
if not archive.is_file() or not checksum.is_file():
    raise SystemExit(f"missing containment bundle or checksum for {target}")
expected = checksum.read_text().split()
if len(expected) != 2 or expected[1] != archive.name:
    raise SystemExit("containment checksum sidecar does not name the exact bundle")
actual = hashlib.sha256(archive.read_bytes()).hexdigest()
if expected[0] != actual:
    raise SystemExit("containment bundle checksum mismatch")
required = {
    "cockpit", "cockpit-containment-broker", "install-linux-containment-broker.sh",
    "infra/systemd/cockpit-containment-broker@.service",
    "infra/systemd/cockpit-daemon@.service",
    "infra/tmpfiles.d/flycockpit-containment.conf", "TARGET", "RELEASE",
}
with tarfile.open(archive) as bundle:
    members = bundle.getmembers()
    if any(not member.isfile() and not member.isdir() for member in members):
        raise SystemExit("containment bundle contains a non-file payload member")
    files = [member for member in members if member.isfile()]
    relative = {str(Path(*Path(member.name).parts[1:])) for member in files}
    if relative != required:
        raise SystemExit(
            f"containment bundle payload mismatch: missing={sorted(required-relative)}, "
            f"extra={sorted(relative-required)}"
        )
    by_relative = {str(Path(*Path(member.name).parts[1:])): member for member in files}
    for executable in ["cockpit", "cockpit-containment-broker", "install-linux-containment-broker.sh"]:
        if by_relative[executable].mode != 0o755:
            raise SystemExit(f"{executable} does not have mode 0755")
    executables = {
        "cockpit",
        "cockpit-containment-broker",
        "install-linux-containment-broker.sh",
    }
    for data_file in required - executables:
        if by_relative[data_file].mode != 0o644:
            raise SystemExit(f"{data_file} does not have mode 0644")
    target_value = bundle.extractfile(by_relative["TARGET"]).read().decode().strip()
    release_value = bundle.extractfile(by_relative["RELEASE"]).read().decode().strip()
    expected_machine = {"x86_64-unknown-linux-gnu": 62, "aarch64-unknown-linux-gnu": 183}[target]
    for executable in ["cockpit", "cockpit-containment-broker"]:
        header = bundle.extractfile(by_relative[executable]).read(20)
        if (
            len(header) < 20
            or header[:4] != b"\x7fELF"
            or header[4:6] != b"\x02\x01"
            or int.from_bytes(header[18:20], "little") != expected_machine
        ):
            raise SystemExit(f"{executable} is not an ELF executable for {target}")
if target_value != target or release_value != release_tag:
    raise SystemExit("containment bundle metadata does not match target/release")
