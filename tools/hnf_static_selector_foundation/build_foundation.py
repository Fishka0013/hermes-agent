#!/usr/bin/env python3
"""Deterministic isolated builder/admission helper for static Gateway selector foundation."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess

SCHEMA = 1
LAYOUT = "gateway-selector-foundation-v1"
RUNTIME_REL = Path("tools/python-3.14.7+20260901-darwin-arm64")
FOUNDATION_RUNTIME_REL = Path("runtime/python-3.14.7+20260901-darwin-arm64")
PYTHON_REL = FOUNDATION_RUNTIME_REL / "bin/python3"
LAUNCHER_REL = Path("bin/hermes-gateway-selector")
INVENTORY_REL = Path("admission/foundation-inventory.json")
JOURNAL_REL = Path("state/selection.jsonl")
ADMISSION_REL = Path("admission/foundation.json")
LIBS = ("__init__.py", "gateway_release_selector.py", "gateway_release.py", "gateway_release_errors.py", "gateway_release_metadata.py", "release_inventory.py")


def sha_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_existing(path: Path) -> Path:
    path = Path(path)
    if not path.is_absolute() or path != path.resolve(strict=True):
        raise ValueError("path must be absolute and canonical: " + str(path))
    return path


def canonical_new(path: Path) -> Path:
    path = Path(path)
    if not path.is_absolute() or path.exists() or path.parent != path.parent.resolve(strict=True):
        raise ValueError("output path must be absent with canonical parent: " + str(path))
    return path


def _entry(path: Path, root: Path) -> dict:
    meta = path.lstat(); rel = path.relative_to(root).as_posix(); mode = stat.S_IMODE(meta.st_mode)
    if path.is_symlink(): return {"path": rel, "type": "symlink", "mode": mode, "target": os.readlink(path)}
    if stat.S_ISDIR(meta.st_mode): return {"path": rel, "type": "directory", "mode": mode}
    if stat.S_ISREG(meta.st_mode): return {"path": rel, "type": "file", "mode": mode, "sha256": sha_file(path)}
    raise ValueError("unsupported filesystem entry: " + rel)


def tree_entries(root: Path) -> list[dict]:
    root = canonical_existing(root); entries = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs.sort(); files.sort()
        for name in dirs + files: entries.append(_entry(Path(directory) / name, root))
    entries.sort(key=lambda item: item["path"]); return entries


def tree_identity(root: Path) -> dict:
    entries = tree_entries(root); raw = canonical_json({"schema": SCHEMA, "entries": entries}) + b"\n"
    return {"sha256": sha_bytes(raw), "entry_count": len(entries), "entries": entries}


def foundation_entries(root: Path) -> list[dict]:
    root = canonical_existing(root); paths = []
    launcher = root / LAUNCHER_REL
    if not launcher.is_file(): raise ValueError("foundation launcher missing")
    paths.append(launcher)
    for subtree in (root / FOUNDATION_RUNTIME_REL, root / "lib/hermes_cli"):
        canonical_existing(subtree)
        for directory, dirs, files in os.walk(subtree, followlinks=False):
            dirs.sort(); files.sort()
            for name in dirs + files: paths.append(Path(directory) / name)
    return sorted((_entry(path, root) for path in paths), key=lambda item: item["path"])


def foundation_inventory_identity(root: Path) -> dict:
    value = {"schema": SCHEMA, "layout": LAYOUT, "entries": foundation_entries(root)}
    raw = canonical_json(value) + b"\n"
    return {"sha256": sha_bytes(raw), "entry_count": len(value["entries"]), "raw": raw, "value": value}


def security_metadata(path: Path) -> dict:
    path = Path(path); info = path.stat()
    value = {"uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode), "flags": getattr(info, "st_flags", 0), "acl": "", "xattrs": {}}
    if os.uname().sysname == "Darwin":
        names = subprocess.check_output(["/usr/bin/xattr", str(path)], timeout=5, text=True).splitlines()
        for name in sorted(names):
            raw = subprocess.check_output(["/usr/bin/xattr", "-px", name, str(path)], timeout=5)
            value["xattrs"][name] = sha_bytes(raw)
        lines = subprocess.check_output(["/bin/ls", "-ldeO", str(path)], timeout=5, text=True).splitlines()
        value["acl"] = "\n".join(lines[1:])
    else:
        for name in sorted(os.listxattr(path)): value["xattrs"][name] = sha_bytes(os.getxattr(path, name))
    return value


def hnf_candidate_identity(candidate: Path) -> dict:
    candidate = canonical_existing(candidate); entries = []
    for path in sorted(candidate.rglob("*"), key=lambda item: item.relative_to(candidate).as_posix()):
        rel = path.relative_to(candidate).as_posix(); meta = path.lstat(); mode = oct(stat.S_IMODE(meta.st_mode))
        if path.is_symlink(): entry = {"link": os.readlink(path), "mode": mode, "path": rel, "type": "symlink"}
        elif path.is_dir(): entry = {"mode": mode, "path": rel, "type": "dir"}
        elif path.is_file(): entry = {"mode": mode, "path": rel, "sha256": sha_file(path), "size": meta.st_size, "type": "file"}
        else: raise ValueError("unsupported candidate filesystem entry: " + rel)
        entries.append(entry)
    raw = json.dumps({"entries": entries, "schema": "hnf-candidate-release-inventory-v1"}, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    return {"sha256": sha_bytes(raw), "entry_count": len(entries)}


def candidate_inputs(candidate: Path, launcher_source: Path) -> dict:
    candidate = canonical_existing(candidate); launcher_source = canonical_existing(launcher_source)
    candidate_id = hnf_candidate_identity(candidate)
    runtime_id = tree_identity(canonical_existing(candidate / RUNTIME_REL))
    libs = {name: sha_file(candidate / "hermes-agent/hermes_cli" / name) for name in LIBS}
    version = subprocess.check_output([str(candidate / RUNTIME_REL / "bin/python3"), "--version"], text=True).strip()
    return {"candidate_inventory_sha256": candidate_id["sha256"], "candidate_inventory_entry_count": candidate_id["entry_count"], "library_sha256": libs, "launcher_sha256": sha_file(launcher_source), "python_runtime_sha256": runtime_id["sha256"], "python_runtime_entry_count": runtime_id["entry_count"], "python_version": version}


def selector_command(root: Path, admission_sha256: str) -> list[str]:
    if len(admission_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in admission_sha256): raise ValueError("admission SHA256 must be lowercase hex")
    root = Path(root)
    return [str(root / PYTHON_REL), "-I", "-S", str(root / LAUNCHER_REL), "--admission-sha256", admission_sha256]


def build_payload(candidate: Path, output: Path, frozen: dict, launcher_source: Path, expected: dict | None = None) -> dict:
    candidate = canonical_existing(candidate); output = canonical_new(output); launcher_source = canonical_existing(launcher_source)
    observed = candidate_inputs(candidate, launcher_source)
    for key in ("candidate_inventory_sha256", "candidate_inventory_entry_count", "library_sha256", "launcher_sha256", "python_runtime_sha256", "python_runtime_entry_count", "python_version"):
        if observed[key] != frozen[key]: raise ValueError("frozen foundation input drift: " + key)
    if frozen.get("layout") != LAYOUT or frozen.get("schema") != SCHEMA: raise ValueError("unsupported foundation frozen-input schema/layout")
    output.mkdir(mode=0o755)
    for rel in ("bin", "runtime", "lib", "lib/hermes_cli", "admission", "state"): (output / rel).mkdir(mode=0o755, exist_ok=True)
    shutil.copytree(candidate / RUNTIME_REL, output / FOUNDATION_RUNTIME_REL, symlinks=True, copy_function=shutil.copy2)
    shutil.copyfile(launcher_source, output / LAUNCHER_REL); (output / LAUNCHER_REL).chmod(0o755)
    for name in LIBS:
        target = output / "lib/hermes_cli" / name; shutil.copyfile(candidate / "hermes-agent/hermes_cli" / name, target); target.chmod(0o644)
    identity = foundation_inventory_identity(output); (output / INVENTORY_REL).write_bytes(identity["raw"]); (output / INVENTORY_REL).chmod(0o644)
    verify = foundation_inventory_identity(output)
    if verify["sha256"] != identity["sha256"] or verify["raw"] != identity["raw"]: raise ValueError("foundation inventory read-back mismatch")
    runtime_id = tree_identity(output / FOUNDATION_RUNTIME_REL)
    result = {"schema": SCHEMA, "layout": LAYOUT, "foundation_inventory_sha256": identity["sha256"], "foundation_inventory_entry_count": identity["entry_count"], "launcher_sha256": sha_file(output / LAUNCHER_REL), "python_runtime_sha256": runtime_id["sha256"], "python_runtime_entry_count": runtime_id["entry_count"], "python_executable_sha256": sha_file((output / PYTHON_REL).resolve(strict=True)), "library_sha256": {name: sha_file(output / "lib/hermes_cli" / name) for name in LIBS}}
    if expected is not None:
        for key in ("schema", "layout", "foundation_inventory_sha256", "foundation_inventory_entry_count", "launcher_sha256", "python_runtime_sha256", "python_runtime_entry_count", "python_executable_sha256", "library_sha256"):
            if result[key] != expected[key]: raise ValueError("foundation expected-output mismatch: " + key)
    return result


def generate_admission(root: Path, journal: Path, releases_root: Path, output: Path | None = None) -> tuple[dict, bytes]:
    root = canonical_existing(root); journal = canonical_existing(journal); releases_root = canonical_existing(releases_root)
    inventory = canonical_existing(root / INVENTORY_REL); launcher = canonical_existing(root / LAUNCHER_REL); python = root / PYTHON_REL; lib_root = canonical_existing(root / "lib")
    if not python.exists(): raise ValueError("foundation Python missing")
    critical = [root, root / "bin", root / "runtime", lib_root, root / "admission", root / "state", launcher, python, inventory]
    critical += [root / "lib/hermes_cli" / name for name in LIBS]; critical.append(journal)
    baselines = {str(path): security_metadata(path) for path in critical}; journal_security = baselines[str(journal)]
    value = {"schema": SCHEMA, "foundation_root": str(root), "foundation_inventory": {"path": str(inventory), "sha256": sha_file(inventory)}, "python_path": str(python), "launcher_path": str(launcher), "lib_root": str(lib_root), "journal_path": str(journal), "releases_root": str(releases_root), "journal_security": journal_security, "security_baselines": baselines}
    raw = canonical_json(value) + b"\n"
    if output is not None:
        output = canonical_new(output)
        if output != root / ADMISSION_REL: raise ValueError("admission output must be foundation admission/foundation.json")
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "wb") as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    return value, raw


def _load(path: Path) -> dict:
    value = json.loads(Path(path).read_text())
    if not isinstance(value, dict): raise ValueError("JSON input must be object")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False); sub = parser.add_subparsers(dest="action", required=True)
    inspect = sub.add_parser("inspect", allow_abbrev=False); inspect.add_argument("--candidate", type=Path, required=True); inspect.add_argument("--launcher-source", type=Path, required=True)
    build = sub.add_parser("build", allow_abbrev=False); build.add_argument("--candidate", type=Path, required=True); build.add_argument("--dest", type=Path, required=True)
    admission = sub.add_parser("admission", allow_abbrev=False); admission.add_argument("--root", type=Path, required=True); admission.add_argument("--journal", type=Path, required=True); admission.add_argument("--releases-root", type=Path, required=True); admission.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv); here = Path(__file__).resolve().parent; launcher_source = here / "hermes_gateway_selector.py"
    if args.action == "inspect": result = candidate_inputs(args.candidate, args.launcher_source)
    elif args.action == "build": result = build_payload(args.candidate, args.dest, _load(here / "frozen-input.json"), launcher_source, _load(here / "expected-output.json"))
    else:
        value, raw = generate_admission(args.root, args.journal, args.releases_root, args.output); result = {"schema": value["schema"], "admission_sha256": sha_bytes(raw), "bytes": len(raw)}
    print(json.dumps(result, sort_keys=True, separators=(",", ":"))); return 0


if __name__ == "__main__": raise SystemExit(main())
