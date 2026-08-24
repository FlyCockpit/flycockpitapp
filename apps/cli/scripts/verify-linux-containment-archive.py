#!/usr/bin/env python3
"""Fail release assembly unless one Linux archive contains both executables."""

from pathlib import Path
import sys
import tarfile
import zipfile


def member_names(path: Path) -> set[str]:
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            return {Path(name).name for name in archive.namelist()}
    if tarfile.is_tarfile(path):
        with tarfile.open(path) as archive:
            return {Path(member.name).name for member in archive.getmembers()}
    return set()


root = Path(sys.argv[1] if len(sys.argv) > 1 else "target/distrib")
required = {"cockpit", "cockpit-containment-broker", "install-linux-containment-broker.sh"}
archives = [path for path in root.iterdir() if path.is_file()]
if not any(required <= member_names(path) for path in archives):
    raise SystemExit(
        "no Linux release archive contains cockpit, cockpit-containment-broker, "
        "and the privileged installer as sibling payloads"
    )
