"""Content seal for a separately constructed native release. No runtime repair."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat


def _inventory(root: Path) -> dict:
    root = root.resolve(strict=True)
    entries = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if relative == "release-inventory.json":
                continue
            metadata = path.lstat()
            if path.is_symlink():
                if not path.resolve(strict=True).is_relative_to(root):
                    raise ValueError("release link escapes candidate: " + relative)
                entries[relative] = {"link": os.readlink(path)}
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1:
                    raise ValueError("release file has a shared writable hardlink: " + relative)
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                entries[relative] = {"sha256": digest.hexdigest(), "mode": stat.S_IMODE(metadata.st_mode)}
            elif not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("unsupported release entry: " + relative)
    return entries


def seal_inventory(root: Path, commit: str) -> dict:
    path = root / "release-inventory.json"
    if path.exists():
        raise ValueError("release is already sealed")
    value = {"schema": 1, "commit": commit, "entries": _inventory(root)}
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    return value


def verify_inventory(root: Path) -> dict:
    path = root / "release-inventory.json"
    if path.is_symlink():
        raise ValueError("release inventory is symlinked")
    value = json.loads(path.read_text())
    if value["schema"] != 1 or value["entries"] != _inventory(root):
        raise ValueError("release contents changed; candidate is not admitted")
    return value
