#!/usr/bin/env python3
"""Stable, release-independent Gateway selector launcher.

Trusted Owner / non-hostile same-UID operational boundary only. It does not claim
hostile same-UID isolation and never automatically rebaselines admitted metadata.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

# The immutable six-file selector library must never grow __pycache__ at runtime.
sys.dont_write_bytecode = True

SCHEMA = 1
LAYOUT = "gateway-selector-foundation-v1"
RUNTIME_REL = Path("runtime/python-3.14.7+20260901-darwin-arm64")
PYTHON_REL = RUNTIME_REL / "bin/python3"
LAUNCHER_REL = Path("bin/hermes-gateway-selector")
INVENTORY_REL = Path("admission/foundation-inventory.json")
ADMISSION_REL = Path("admission/foundation.json")
JOURNAL_REL = Path("state/selection.jsonl")
LIBS = ("__init__.py", "gateway_release_selector.py", "gateway_release.py", "gateway_release_errors.py", "gateway_release_metadata.py", "release_inventory.py")
TRUSTED_OWNER_LIMIT = "trusted Owner / trusted non-hostile same UID operational environment; no hostile same-UID isolation; no automatic rebaseline"
ADMISSION_FIELDS = {"schema", "foundation_root", "foundation_inventory", "python_path", "launcher_path", "lib_root", "journal_path", "releases_root", "journal_security", "security_baselines"}
SECURITY_FIELDS = {"uid", "gid", "mode", "flags", "acl", "xattrs"}


def sha_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): digest.update(block)
    return digest.hexdigest()


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value: raise RuntimeError("duplicate JSON key")
        value[key] = item
    return value


def strict_json(raw: bytes):
    try: return json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except Exception as exc: raise RuntimeError("invalid strict JSON") from exc


def read_regular_nofollow(path: Path, limit: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit: raise RuntimeError("invalid regular file")
        chunks = []; total = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
            if not block: break
            chunks.append(block); total += len(block)
            if total > limit: raise RuntimeError("file exceeds admitted size bound")
        return b"".join(chunks)
    finally: os.close(descriptor)


def security_metadata(path: Path) -> dict:
    info = Path(path).stat()
    value = {"uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode), "flags": getattr(info, "st_flags", 0), "acl": "", "xattrs": {}}
    if sys.platform == "darwin":
        names = subprocess.check_output(["/usr/bin/xattr", str(path)], timeout=5, text=True).splitlines()
        for name in sorted(names):
            raw = subprocess.check_output(["/usr/bin/xattr", "-px", name, str(path)], timeout=5)
            value["xattrs"][name] = sha_bytes(raw)
        lines = subprocess.check_output(["/bin/ls", "-ldeO", str(path)], timeout=5, text=True).splitlines()
        value["acl"] = "\n".join(lines[1:])
    else:
        for name in sorted(os.listxattr(path)): value["xattrs"][name] = sha_bytes(os.getxattr(path, name))
    return value


def _entry(path: Path, root: Path) -> dict:
    meta = path.lstat(); rel = path.relative_to(root).as_posix(); mode = stat.S_IMODE(meta.st_mode)
    if path.is_symlink(): return {"path": rel, "type": "symlink", "mode": mode, "target": os.readlink(path)}
    if stat.S_ISDIR(meta.st_mode): return {"path": rel, "type": "directory", "mode": mode}
    if stat.S_ISREG(meta.st_mode): return {"path": rel, "type": "file", "mode": mode, "sha256": sha_file(path)}
    raise RuntimeError("unsupported foundation filesystem entry")


def actual_inventory_entries(root: Path) -> list[dict]:
    paths = [root / LAUNCHER_REL]
    for subtree in (root / RUNTIME_REL, root / "lib/hermes_cli"):
        for directory, dirs, files in os.walk(subtree, followlinks=False):
            dirs.sort(); files.sort()
            for name in dirs + files: paths.append(Path(directory) / name)
    return sorted((_entry(path, root) for path in paths), key=lambda item: item["path"])


def _canonical_exact(path_text: str, expected: Path, *, directory=False, allow_symlink=False) -> Path:
    if type(path_text) is not str: raise RuntimeError("admitted path must be string")
    path = Path(path_text)
    if path != expected or not path.is_absolute(): raise RuntimeError("admitted canonical path mismatch")
    resolved = path.resolve(strict=True)
    if not allow_symlink and path != resolved: raise RuntimeError("admitted canonical path mismatch")
    if directory and not path.is_dir(): raise RuntimeError("admitted directory missing")
    return path


def load_and_validate_admission(root: Path, supplied_hash: str) -> dict:
    if len(supplied_hash) != 64 or any(ch not in "0123456789abcdef" for ch in supplied_hash): raise RuntimeError("invalid admission SHA256")
    admission_path = root / ADMISSION_REL
    raw = read_regular_nofollow(admission_path, 4 * 1024 * 1024)
    if sha_bytes(raw) != supplied_hash: raise RuntimeError("foundation admission SHA256 mismatch")
    value = strict_json(raw)
    if not isinstance(value, dict) or set(value) != ADMISSION_FIELDS or type(value.get("schema")) is not int or value["schema"] != SCHEMA: raise RuntimeError("foundation admission schema/fields invalid")
    _canonical_exact(value["foundation_root"], root, directory=True)
    inventory = value.get("foundation_inventory")
    if not isinstance(inventory, dict) or set(inventory) != {"path", "sha256"}: raise RuntimeError("foundation inventory admission invalid")
    inv_path = _canonical_exact(inventory["path"], root / INVENTORY_REL)
    if type(inventory["sha256"]) is not str or sha_file(inv_path) != inventory["sha256"]: raise RuntimeError("foundation inventory hash drift")
    _canonical_exact(value["python_path"], root / PYTHON_REL, allow_symlink=True)
    _canonical_exact(value["launcher_path"], root / LAUNCHER_REL)
    lib_root = _canonical_exact(value["lib_root"], root / "lib", directory=True)
    journal = _canonical_exact(value["journal_path"], root / JOURNAL_REL)
    releases_root = Path(value["releases_root"])
    if not releases_root.is_absolute() or releases_root != releases_root.resolve(strict=True) or not releases_root.is_dir(): raise RuntimeError("releases root is not canonical")
    if Path(sys.executable).absolute() != root / PYTHON_REL or Path(sys.executable).resolve(strict=True) != (root / PYTHON_REL).resolve(strict=True): raise RuntimeError("foundation Python executable mismatch")

    inv_raw = read_regular_nofollow(inv_path, 64 * 1024 * 1024); inv = strict_json(inv_raw)
    if not isinstance(inv, dict) or set(inv) != {"schema", "layout", "entries"} or inv.get("schema") != SCHEMA or inv.get("layout") != LAYOUT or not isinstance(inv.get("entries"), list): raise RuntimeError("foundation inventory document invalid")
    if inv["entries"] != actual_inventory_entries(root): raise RuntimeError("immutable foundation inventory drift")

    baselines = value["security_baselines"]
    if not isinstance(baselines, dict) or not isinstance(value["journal_security"], dict): raise RuntimeError("foundation security baseline invalid")
    critical = [root, root / "bin", root / "runtime", lib_root, root / "admission", root / "state", root / LAUNCHER_REL, root / PYTHON_REL, inv_path]
    critical += [root / "lib/hermes_cli" / name for name in LIBS]; critical.append(journal)
    expected_keys = {str(path) for path in critical}
    if set(baselines) != expected_keys: raise RuntimeError("foundation critical security baseline set is not exact")
    for path in critical:
        expected = baselines[str(path)]
        if not isinstance(expected, dict) or set(expected) != SECURITY_FIELDS or not isinstance(expected.get("xattrs"), dict): raise RuntimeError("foundation security baseline fields invalid")
        if security_metadata(path) != expected: raise RuntimeError("foundation security metadata drift: " + str(path))
    if value["journal_security"] != baselines[str(journal)]: raise RuntimeError("journal security baseline binding mismatch")
    value["_lib_root"] = str(lib_root); value["_journal"] = str(journal); value["_releases_root"] = str(releases_root)
    return value


def import_selector_modules(admission: dict):
    lib_root = Path(admission["_lib_root"]); releases_root = Path(admission["_releases_root"])
    if any(name == "hermes_cli" or name.startswith("hermes_cli.") for name in sys.modules): raise RuntimeError("selector modules imported before foundation admission")
    sys.path.insert(0, str(lib_root))
    import hermes_cli
    from hermes_cli import gateway_release, gateway_release_selector, gateway_release_errors, gateway_release_metadata, release_inventory
    modules = (hermes_cli, gateway_release, gateway_release_selector, gateway_release_errors, gateway_release_metadata, release_inventory)
    for module in modules:
        origin = Path(module.__file__).resolve(strict=True)
        if not origin.is_relative_to(lib_root) or origin.is_relative_to(releases_root): raise RuntimeError("selector import origin escaped foundation lib")
    return gateway_release_selector


def exec_handoff(target: dict):
    selected_launcher = target["launcher"]
    argv = [selected_launcher, "--run-module", "hermes_cli.stderr_timestamp", "--error-log", "/Users/yura/.hermes/logs/gateway.error.log", "--", selected_launcher, "gateway", "run", "--external-supervisor"]
    os.execv(selected_launcher, argv)
    raise RuntimeError("exec handoff unexpectedly returned")


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False); parser.add_argument("--admission-sha256", required=True); args = parser.parse_args(argv)
    launcher = Path(__file__).absolute()
    if launcher != launcher.resolve(strict=True): raise RuntimeError("foundation launcher must be canonical and not symlinked")
    root = launcher.parent.parent.resolve(strict=True)
    admission = load_and_validate_admission(root, args.admission_sha256)
    selector = import_selector_modules(admission)
    selector.validate_security_baseline(Path(admission["_journal"]), admission["journal_security"])
    selector.startup_target(Path(admission["_journal"]), Path(admission["_releases_root"]), admission["journal_security"], handoff=exec_handoff)
    raise RuntimeError("selector startup unexpectedly returned")


if __name__ == "__main__":
    try: raise SystemExit(main())
    except Exception as exc:
        print("foundation selector refused startup: " + str(exc), file=sys.stderr); raise SystemExit(1)
