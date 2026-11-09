#!/usr/bin/env python3
"""Read-only pull-request change guard for the Owner's Hermes GitHub fork.

Syntax/secret/path hygiene is a smoke check, not a full security audit.
This script never creates credentials, writes to GitHub, or executes changed code.
"""
from __future__ import annotations

import argparse
import ast
from pathlib import Path
import re
import subprocess

MAX_FILES = 120
MAX_BYTES = 1_000_000
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{25,}"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9_]{30,}"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{24,}"),
)
BLOCKED_EXTENSIONS = {".pem", ".key", ".p12", ".pfx", ".sqlite", ".db"}
BLOCKED_PARTS = {".git", ".ssh", ".aws", "secrets", "credentials"}


class GuardFailure(ValueError):
    pass


def checked_path(worktree: Path, rel: str) -> Path:
    path = Path(rel)
    parts = [part.lower() for part in path.parts]
    if (
        not rel
        or path.is_absolute()
        or ".." in path.parts
        or any(part in BLOCKED_PARTS for part in parts)
        or any(part == ".env" or part.startswith(".env.") for part in parts)
        or path.suffix.lower() in BLOCKED_EXTENSIONS
    ):
        raise GuardFailure("Blocked file path: " + rel)
    candidate = worktree / path
    if candidate.is_symlink() or not candidate.is_file():
        raise GuardFailure("Non-regular or missing changed file: " + rel)
    if not candidate.resolve().is_relative_to(worktree.resolve()):
        raise GuardFailure("Path leaves worktree: " + rel)
    return candidate


def check_content(rel: str, contents: bytes) -> None:
    if len(contents) > MAX_BYTES:
        raise GuardFailure("Changed file is too large: " + rel)
    if b"\0" in contents:
        raise GuardFailure("Binary content requires separate review: " + rel)
    if any(p.search(contents) for p in SECRET_PATTERNS):
        raise GuardFailure("Potential secret in changed file: " + rel)
    if rel.lower().endswith(".py"):
        try:
            ast.parse(contents.decode("utf-8"), filename=rel)
        except (SyntaxError, UnicodeError) as exc:
            raise GuardFailure("Python syntax problem: " + rel) from exc


def scan(worktree: Path, changed: list[str]) -> int:
    if len(changed) > MAX_FILES:
        raise GuardFailure("Too many changed files")
    for name in changed:
        path = checked_path(worktree, name)
        check_content(name, path.read_bytes())
    return len(changed)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    out = subprocess.run(
        ["git", "-C", str(root), "diff", "--name-only", "-z",
         "--diff-filter=ACMR", args.base, args.head],
        stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=30,
    ).stdout
    paths = [s.decode("utf-8") for s in out.split(b"\0") if s]
    count = scan(root, paths)
    print(f"FORK_CI_GUARD_PASS: {count} added/modified files checked; no execution")


if __name__ == "__main__":
    main()
