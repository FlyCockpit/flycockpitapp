#!/usr/bin/env python3
"""Validate one target-specific, checksummed Linux containment bundle."""

import hashlib
import io
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
def digest_stream(stream: io.BufferedReader) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()

with archive.open("rb") as archive_stream:
    actual = digest_stream(archive_stream)
if expected[0] != actual:
    raise SystemExit("containment bundle checksum mismatch")
required = {
    "cockpit", "cockpit-containment-broker", "install-linux-containment-broker.sh",
    "infra/systemd/cockpit-containment-broker@.service",
    "infra/systemd/cockpit-daemon@.service",
    "infra/tmpfiles.d/flycockpit-containment.conf", "TARGET", "RELEASE",
    "MANIFEST.sha256",
}
with tarfile.open(archive) as bundle:
    members = bundle.getmembers()
    if not members or len(members) > 32:
        raise SystemExit("containment bundle member count is invalid")
    if any(not member.isfile() and not member.isdir() for member in members):
        raise SystemExit("containment bundle contains a non-file payload member")
    files = [member for member in members if member.isfile()]
    if any(member.size < 0 or member.size > 256 * 1024 * 1024 for member in files):
        raise SystemExit("containment bundle member size is invalid")
    roots = {Path(member.name).parts[0] for member in members if Path(member.name).parts}
    expected_root = f"flycockpit-containment-{release_tag}-{target}"
    if roots != {expected_root}:
        raise SystemExit("containment bundle root does not match target/release identity")
    relative = {str(Path(*Path(member.name).parts[1:])) for member in files}
    if len(relative) != len(files):
        raise SystemExit("containment bundle contains duplicate payload paths")
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
    manifest_text = bundle.extractfile(by_relative["MANIFEST.sha256"]).read().decode("ascii")
    manifest = {}
    for line in manifest_text.splitlines():
        fields = line.split(None, 1)
        if len(fields) != 2 or len(fields[0]) != 64 or fields[1].startswith(("/", "*")):
            raise SystemExit("containment member manifest is malformed")
        name = fields[1]
        if name in manifest:
            raise SystemExit("containment member manifest contains duplicate paths")
        try:
            bytes.fromhex(fields[0])
        except ValueError as error:
            raise SystemExit("containment member manifest has a non-hex digest") from error
        manifest[name] = fields[0]
    manifested = required - {"MANIFEST.sha256"}
    if set(manifest) != manifested:
        raise SystemExit("containment member manifest does not cover the exact payload")
    for name in manifested:
        stream = bundle.extractfile(by_relative[name])
        if stream is None or digest_stream(stream) != manifest[name]:
            raise SystemExit(f"containment member hash mismatch: {name}")
    expected_machine = {"x86_64-unknown-linux-gnu": 62, "aarch64-unknown-linux-gnu": 183}[target]
    for executable in ["cockpit", "cockpit-containment-broker"]:
        header = bundle.extractfile(by_relative[executable]).read(24)
        if (
            len(header) < 24
            or header[:4] != b"\x7fELF"
            or header[4:6] != b"\x02\x01"
            or header[6] != 1
            or int.from_bytes(header[16:18], "little") not in {2, 3}
            or int.from_bytes(header[18:20], "little") != expected_machine
            or int.from_bytes(header[20:24], "little") != 1
        ):
            raise SystemExit(f"{executable} is not an ELF executable for {target}")
if target_value != target or release_value != release_tag:
    raise SystemExit("containment bundle metadata does not match target/release")
