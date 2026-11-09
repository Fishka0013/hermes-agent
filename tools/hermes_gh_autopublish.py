#!/usr/bin/env python3
"""Bounded Hermes code delivery: isolated worktree -> checked commit -> one push -> PR.

Never updates main, releases, tags, production, auth, or GitHub permissions.
An ambiguous push is terminal until independent remote reconciliation.
"""
from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone, UTC
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import uuid

REPO = "Fishka0013/hermes-agent"
ORIGIN = "https://github.com/Fishka0013/hermes-agent.git"
BRANCH_PREFIX = "hermes/auto/"
SECRET_RE = re.compile(
    rb"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    rb"\bgh[pousr]_[A-Za-z0-9_]{30,}|"
    rb"\bgithub_pat_[A-Za-z0-9_]{30,}|"
    rb"\bsk-[A-Za-z0-9_-]{24,}"
)
TASK_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,55}$")


class Stop(RuntimeError):
    pass


def cmd(argv, *, cwd=None, timeout=25, check=True):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="never")
    try:
        p = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, capture_output=True, encoding="utf-8",
                           errors="replace", timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise Stop("TIMEOUT_UNKNOWN_NO_AUTOMATIC_RETRY") from exc
    if check and p.returncode:
        # No stderr/stdout: Git/CLI sometimes echo remote credentials.
        raise Stop("COMMAND_FAILED_" + str(p.returncode) + "_" + str(Path(argv[0]).name))
    return p.stdout.strip()


def git(w, *args, **kwargs):
    return cmd(["git", "-C", str(w), *args], **kwargs)


def check_task(task):
    if not TASK_RE.fullmatch(task):
        raise Stop("INVALID_TASK_SLUG")


def expected_workspace(root, task, *, require=True):
    check_task(task)
    root = root.expanduser().resolve()
    p = root / task
    if require:
        if p.is_symlink() or not p.is_dir() or p.resolve() != p:
            raise Stop("WORKSPACE_NOT_SAFE")
    return p


def check_repo(w, branch):
    if git(w, "remote", "get-url", "origin") != ORIGIN:
        raise Stop("ORIGIN_MISMATCH")
    if git(w, "rev-parse", "--show-toplevel") != str(w):
        raise Stop("WORKTREE_TOPLEVEL_MISMATCH")
    if git(w, "symbolic-ref", "--quiet", "--short", "HEAD") != branch:
        raise Stop("BRANCH_MISMATCH")
    if git(w, "rev-parse", "--is-shallow-repository") != "false":
        raise Stop("SHALLOW_REPO_STOP")


def remote_main(w):
    out = git(w, "ls-remote", "--exit-code", "origin", "refs/heads/main")
    if len(out.split()) != 2 or out.split()[1] != "refs/heads/main":
        raise Stop("REMOTE_MAIN_UNREADABLE")
    sha = out.split()[0]
    if not re.fullmatch(r"[a-f0-9]{40}", sha):
        raise Stop("REMOTE_MAIN_SHA")
    return sha


def changed_paths(w):
    names = set()
    for args in [("ls-files", "-m", "-o", "--exclude-standard", "-z"),
                 ("ls-files", "--deleted", "-z")]:
        raw = subprocess.run(["git", "-C", str(w), *args], check=True,
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, timeout=25).stdout
        names.update(os.fsdecode(n) for n in raw.split(b"\0") if n)
    return sorted(names)


def validate_files(w, paths):
    if len(paths) > 100:
        raise Stop("TOO_MANY_FILES")
    for name in paths:
        rel = Path(name)
        parts = rel.parts
        low = name.lower().replace("\\", "/")
        if (rel.is_absolute() or ".." in parts or any(p in
                {".git", ".ssh", ".aws", ".config", "secrets", "credentials", "data"}
                for p in parts) or
                any(p == ".env" or p.startswith(".env.") for p in parts) or
                low.endswith((".pem", ".key", ".p12", ".pfx", ".sqlite", ".db",
                              ".bak", ".zip", ".tar", ".gz"))):
            raise Stop("BLOCKED_PATH_" + name[:100])
        p = w / rel
        if not p.exists() and not p.is_symlink():
            continue  # tracked deletion
        if p.is_symlink() or not p.is_file():
            raise Stop("BLOCKED_TYPE_" + name[:100])
        if p.stat().st_size > 1_000_000:
            raise Stop("FILE_TOO_LARGE_" + name[:100])
        data = p.read_bytes()
        if b"\0" in data or SECRET_RE.search(data):
            raise Stop("BINARY_OR_SECRET_PATTERN_" + name[:100])
        if p.suffix == ".py":
            try:
                ast.parse(data.decode("utf-8"), filename=name)
            except (SyntaxError, UnicodeError) as exc:
                raise Stop("PYTHON_SYNTAX_" + name[:100]) from exc


def save_once(path, record):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        raise Stop("ALREADY_CLAIMED_NO_RETRY")
    data = (json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def prepare(source, root, task):
    check_task(task)
    w = expected_workspace(root, task, require=False)
    if w.exists() or w.is_symlink():
        raise Stop("TASK_WORKSPACE_ALREADY_EXISTS")
    if git(source, "remote", "get-url", "origin") != ORIGIN:
        raise Stop("ORIGIN_MISMATCH")
    base = remote_main(source)
    if git(source, "cat-file", "-t", base) != "commit":
        raise Stop("REMOTE_MAIN_COMMIT_NOT_LOCAL_FETCH_REQUIRED")
    branch = BRANCH_PREFIX + task
    if cmd(["git", "-C", str(source), "show-ref", "--verify",
            "refs/heads/" + branch], check=False):
        raise Stop("LOCAL_BRANCH_EXISTS")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    cmd(["git", "-C", str(source), "worktree", "add",
         "-b", branch, str(w), base], timeout=60)
    print(json.dumps({"status": "PREPARED", "worktree": str(w),
                      "branch": branch, "base": base}, ensure_ascii=False))


def publish(root, task, title, test_command):
    w = expected_workspace(root, task)
    branch = BRANCH_PREFIX + task
    check_repo(w, branch)
    receipt = root.expanduser().resolve() / ".receipts" / (task + ".intent.json")
    if receipt.exists():
        raise Stop("ALREADY_CLAIMED_NO_RETRY_READ_REMOTE")
    base = remote_main(w)
    if subprocess.run(["git", "-C", str(w), "merge-base", "--is-ancestor", base, "HEAD"],
                      stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=25).returncode:
        raise Stop("REMOTE_MAIN_ADVANCED_REBASE_REQUIRED")
    if git(w, "ls-remote", "origin", "refs/heads/" + branch):
        raise Stop("REMOTE_BRANCH_EXISTS_NO_OVERWRITE")
    paths = changed_paths(w)
    validate_files(w, paths)
    if paths:
        git(w, "add", "-A")
    git(w, "diff", "--cached", "--check")
    if test_command:
        words = shlex.split(test_command)
        if not words or not (re.fullmatch(r"python(?:3(?:\.\d+)?)?", Path(words[0]).name) or Path(words[0]).name in ("pytest", "uv")):
            raise Stop("TEST_COMMAND_NOT_ALLOWED")
        cmd(words, cwd=w, timeout=180)
    if subprocess.run(["git", "-C", str(w), "diff", "--cached", "--quiet"],
                      stdin=subprocess.DEVNULL, check=False, timeout=25).returncode:
        git(w, "commit", "-m", "chore(hermes): " + title[:68], timeout=60)
    commit = git(w, "rev-parse", "HEAD")
    if commit == base:
        raise Stop("NO_NEW_COMMITS_TO_PUBLISH")
    changed_committed = git(w, "diff", "--name-only", base + "..HEAD").splitlines()
    validate_files(w, changed_committed)
    if git(w, "status", "--porcelain"):
        raise Stop("DIRTY_WORKTREE_AFTER_COMMIT")
    claim = {
        "schema": "hermes-gh-autopublish-v1", "task": task,
        "branch": branch, "commit": commit, "remote_main": base,
        "action": "ONE_CREATE_ONLY_BRANCH_PUSH_AND_PR",
        "created_utc": datetime.now(UTC).isoformat(),
        "title": title, "test_command": test_command or "SYNTAX_AND_GIT_CHECK_ONLY",
        "note": "No main/release/tag/production/credentials modifications",
    }
    save_once(receipt, claim)
    print("INTENT_RECORDED_NO_RETRY", commit, flush=True)
    try:
        git(w, "push", "origin", "HEAD:refs/heads/" + branch, timeout=90)
    except Stop:
        print("PUSH_OUTCOME_UNKNOWN_OR_FAILED_NO_RETRY", flush=True)
        raise
    observed = git(w, "ls-remote", "--exit-code", "origin", "refs/heads/" + branch)
    if observed.split()[0] != commit:
        raise Stop("REMOTE_POST_MISMATCH_NO_RETRY")
    body = ("Automated Hermes code-delivery pilot.\n\n"
            "Source: isolated worktree. No main/tag/production mutation.\n"
            "Local check: " + (test_command or "syntax + git diff --check") + "\n"
            "Task: " + task)
    try:
        url = cmd(["gh", "pr", "create", "-R", REPO, "-B", "main",
                   "-H", branch, "-t", title, "-b", body], cwd=w, timeout=60)
    except Stop:
        raise Stop("BRANCH_PUBLISHED_PR_NEEDS_RECONCILIATION_NO_REPUSH")
    print(json.dumps({"status": "PUBLISHED_PR", "branch": branch,
                      "commit": commit, "pr_url": url}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("prepare", "publish", "status"))
    parser.add_argument("--task", required=True)
    git_workspace = Path.home() / ".hermes"  # health: allow HX001 -- account-wide checkout and worktrees
    parser.add_argument("--source", type=Path, default=git_workspace / "hermes-agent")
    parser.add_argument("--root", type=Path, default=git_workspace / "github-worktrees")
    parser.add_argument("--title")
    parser.add_argument("--test-command")
    a = parser.parse_args()
    try:
        root = a.root.expanduser().resolve()
        if a.action == "prepare":
            prepare(a.source.expanduser().resolve(), root, a.task)
        elif a.action == "publish":
            if not a.title or len(a.title) > 120:
                raise Stop("VALID_PR_TITLE_REQUIRED")
            publish(root, a.task, a.title, a.test_command)
        else:
            claim = root / ".receipts" / (a.task + ".intent.json")
            print(json.dumps({"task": a.task,
                              "local_intent": claim.exists(),
                              "remote_branch": cmd(["git", "-C", str(a.source),
                                  "ls-remote", "origin", "refs/heads/" +
                                  BRANCH_PREFIX + a.task]),
                              "pr": cmd(["gh", "pr", "list", "-R", REPO,
                                  "--head", BRANCH_PREFIX + a.task,
                                  "--json", "number,url,state"])}, ensure_ascii=False))
    except Stop as exc:
        print("STOP:", str(exc), file=sys.stderr)
        sys.exit(44)


if __name__ == "__main__":
    main()
