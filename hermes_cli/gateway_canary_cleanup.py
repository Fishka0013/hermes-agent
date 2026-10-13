"""Fixed, owned Stage 5 artifact cleanup after an interrupted live canary.

No arbitrary path input, no recursive removal, no config/service/DB mutations.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import re


def _cleanup(directory: Path) -> bool:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    # macOS /tmp is the trusted system alias for /private/tmp. Do not resolve
    # a workspace .tmp symlink: that must still fail closed.
    parent_path = directory.parent.resolve(strict=True) if directory.parent == Path("/tmp") else directory.parent
    parent = os.open(parent_path, flags)
    try:
        try:
            fd = os.open(directory.name, flags, dir_fd=parent)
        except FileNotFoundError:
            return True
        try:
            owner_fd = os.open(".hermes-owner.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            with os.fdopen(owner_fd, "r") as stream:
                marker = json.loads(stream.read(1024))
            if (marker.get("schema") != 1 or marker.get("producer") != "hermes-stage5-fixed-canary"
                    or not re.fullmatch(r"[a-f0-9]{32}", marker.get("nonce", ""))):
                raise RuntimeError("Stage 5 cleanup ownership not established")
            allowed = {"canary.txt", "escape", "written.txt", "fail-closed-marker", ".hermes-owner.json"}
            names = set(os.listdir(fd))
            if names - allowed:
                raise RuntimeError("unexpected Stage 5 artifact; refuse broad cleanup")
            for name in names - {".hermes-owner.json"}:
                os.unlink(name, dir_fd=fd)
            os.unlink(".hermes-owner.json", dir_fd=fd)
            os.rmdir(directory.name, dir_fd=parent)
        finally:
            os.close(fd)
    finally:
        os.close(parent)
    return True


def cleanup_stage5() -> dict:
    from agent.model_file_policy import get_model_workspace_root
    inside = get_model_workspace_root() / ".tmp/hermes-access-stage5"
    outside = Path("/tmp/hermes-access-stage5")
    results = []
    for path in (inside, outside):
        if not path.parent.exists():
            results.append(True)
        else:
            results.append(_cleanup(path))
    return {"cleaned": all(results), "inside_absent": not inside.exists(), "outside_absent": not outside.exists()}


if __name__ == "__main__":
    print(json.dumps(cleanup_stage5(), sort_keys=True))
