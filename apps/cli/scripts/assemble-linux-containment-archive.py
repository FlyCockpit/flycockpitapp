#!/usr/bin/env python3
"""Co-assemble privileged Linux containment payloads after cargo-dist.

cargo-dist models binaries as independently publishable artifacts. FlyCockpit's
Linux installation contract does not: the unprivileged CLI, privileged broker,
installer, units, and tmpfiles policy are one atomic payload. This script
rebuilds the CLI archive with the broker payload when dist emitted split
archives, then refreshes adjacent SHA-256 files. Non-Linux targets are rejected
instead of accidentally receiving a root service binary.
"""

from __future__ import annotations

import hashlib
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

REQUIRED = {
    "cockpit",
    "cockpit-containment-broker",
    "install-linux-containment-broker.sh",
    "cockpit-containment-broker@.service",
    "cockpit-daemon@.service",
    "flycockpit-containment.conf",
}


def members(path: Path) -> dict[str, str]:
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            return {Path(name).name: name for name in archive.namelist() if not name.endswith("/")}
    if tarfile.is_tarfile(path):
        with tarfile.open(path) as archive:
            return {Path(item.name).name: item.name for item in archive.getmembers() if item.isfile()}
    return {}


def extract(path: Path, destination: Path) -> None:
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            if any(Path(name).is_absolute() or ".." in Path(name).parts for name in archive.namelist()):
                raise SystemExit(f"unsafe archive member in {path.name}")
            archive.extractall(destination)
        return
    with tarfile.open(path) as archive:
        for item in archive.getmembers():
            member = Path(item.name)
            if member.is_absolute() or ".." in member.parts or item.issym() or item.islnk():
                raise SystemExit(f"unsafe archive member in {path.name}: {item.name}")
        archive.extractall(destination)


def rebuild(path: Path, source: Path) -> None:
    staged = path.with_name(f".{path.name}.assembled")
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(staged, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for item in sorted(source.rglob("*")):
                if item.is_file():
                    archive.write(item, item.relative_to(source))
    else:
        suffixes = "".join(path.suffixes)
        mode = "w:xz" if suffixes.endswith(".tar.xz") else "w:gz" if suffixes.endswith(".tar.gz") else "w"
        if mode == "w" and not suffixes.endswith(".tar"):
            raise SystemExit(f"unsupported Linux archive format for deterministic assembly: {path.name}")
        with tarfile.open(staged, mode) as archive:
            for item in sorted(source.iterdir()):
                archive.add(item, arcname=item.name, recursive=True)
    staged.replace(path)


def refresh_checksums(path: Path) -> None:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    for checksum in (path.with_name(path.name + ".sha256"), path.with_suffix(path.suffix + ".sha256")):
        if checksum.exists():
            checksum.write_text(f"{digest}  {path.name}\n")


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "target/distrib")
    target = sys.argv[2] if len(sys.argv) > 2 else ""
    archives = [path for path in root.iterdir() if path.is_file() and target in path.name and members(path)]
    if not target:
        raise SystemExit("containment archive assembly requires an explicit target")
    if "linux" not in target:
        forbidden = REQUIRED - {"cockpit"}
        for archive in archives:
            if not (forbidden & members(archive).keys()):
                continue
            with tempfile.TemporaryDirectory(prefix="flycockpit-nonlinux-assembly-") as temporary:
                payload = Path(temporary) / "payload"
                payload.mkdir()
                extract(archive, payload)
                for item in list(payload.rglob("*")):
                    if item.is_file() and item.name in forbidden:
                        item.unlink()
                rebuild(archive, payload)
            refresh_checksums(archive)
        if any(forbidden & members(archive).keys() for archive in archives):
            raise SystemExit(f"privileged Linux payload leaked into non-Linux target {target}")
        return 0
    cli = next((path for path in archives if "cockpit" in members(path)), None)
    broker = next((path for path in archives if "cockpit-containment-broker" in members(path)), None)
    raw_broker = root / "linux-brokers" / target / "cockpit-containment-broker"
    if cli is None or (broker is None and not raw_broker.is_file()):
        raise SystemExit(f"missing CLI or broker archive for {target}")
    with tempfile.TemporaryDirectory(prefix="flycockpit-linux-assembly-") as temporary:
        assembled = Path(temporary) / "payload"
        assembled.mkdir()
        extract(cli, assembled)
        if broker is None:
            cli_root = next((path.parent for path in assembled.rglob("cockpit") if path.is_file()), assembled)
            shutil.copy2(raw_broker, cli_root / "cockpit-containment-broker")
        elif broker != cli:
            broker_tree = Path(temporary) / "broker"
            broker_tree.mkdir()
            extract(broker, broker_tree)
            broker_member = members(broker)["cockpit-containment-broker"]
            broker_source = broker_tree / broker_member
            cli_root = next((path.parent for path in assembled.rglob("cockpit") if path.is_file()), assembled)
            shutil.copy2(broker_source, cli_root / "cockpit-containment-broker")
        present = {path.name for path in assembled.rglob("*") if path.is_file()}
        missing = REQUIRED - present
        if missing:
            raise SystemExit(f"assembled Linux archive is incomplete: {sorted(missing)}")
        rebuild(cli, assembled)
    refresh_checksums(cli)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
