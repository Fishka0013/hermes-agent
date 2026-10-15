"""MEDIA tags pointing into a remote terminal sandbox are fetched for delivery (#466).

The host cannot see files an agent writes inside an ssh/modal/daytona sandbox, so
``filter_media_delivery_paths`` used to drop them silently. With a remote backend active the path is
pulled through the environment's ``fetch_file`` into the document cache — after the SAME denylist
the host applies, so a sandbox path (or a symlink) at ``~/.ssh/...`` never crosses.
"""

from pathlib import Path
import json

import pytest

from gateway import media_fetch
from gateway.platforms.base import BasePlatformAdapter
from tools.environments.base import BaseEnvironment, FileFetchError


class _FakeRemoteEnv:
    """Stands in for a live SSHEnvironment: a tiny remote filesystem + symlink table."""

    def __init__(self, root):
        self._remote_home = str(root)
        self.files = {str(root / "out/report.txt"): b"hello from sandbox",
                      str(root / ".ssh/id_rsa"): b"SECRET"}
        self.links = {str(root / "out/innocent.txt"): str(root / ".ssh/id_rsa")}
        self.fetched: list = []
        self.resolved: list = []

    def fetch_realpath(self, remote_path):
        self.resolved.append(remote_path)
        return self.links.get(remote_path, remote_path)

    def fetch_file(self, remote_path, local_dest, *, max_bytes):
        self.fetched.append(remote_path)
        if remote_path not in self.files:
            raise FileFetchError("missing")
        Path(local_dest).write_bytes(self.files[remote_path])


@pytest.fixture
def remote_env(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "workspace"
    root.mkdir()
    (home / "config.yaml").write_text(json.dumps({"security": {"model_workspace_root": str(root)}}))
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    env = _FakeRemoteEnv(root)
    monkeypatch.setattr(media_fetch, "_active_remote_env", lambda: env)
    monkeypatch.setattr("gateway.platforms.base.DOCUMENT_CACHE_DIR", tmp_path / "cache" / "documents")
    monkeypatch.setattr("gateway.platforms.base.MEDIA_DELIVERY_SAFE_ROOTS", (root,))
    return env


def test_sandbox_artifact_is_fetched_but_credentials_and_symlinks_to_them_are_not(remote_env):
    home = remote_env._remote_home
    media = [(home + "/out/report.txt", False), (home + "/out/innocent.txt", False),
             (home + "/.ssh/id_rsa", False), ("~/out/report.txt", False)]
    delivered = BasePlatformAdapter.filter_media_delivery_paths(media)

    assert [Path(p).read_bytes() for p, _ in delivered] == [b"hello from sandbox", b"hello from sandbox"]
    # The credential file and the symlink that resolves to it were refused BEFORE any bytes moved.
    assert remote_env.fetched == [home + "/out/report.txt", home + "/out/report.txt"]
    for path, _ in delivered:
        assert Path(path).is_relative_to(Path(home) / ".tmp" / "model-artifacts" / "remote-media")
        assert Path(path + ".receipt.json").is_file()


def test_local_backend_and_strict_mode_do_not_fetch(monkeypatch, tmp_path, remote_env):
    """Strict mode keeps its recency gate: a fetched copy would land in an allowlisted root and skip it."""
    monkeypatch.setenv("HERMES_MEDIA_DELIVERY_STRICT", "1")
    assert BasePlatformAdapter.filter_media_delivery_paths([(remote_env._remote_home + "/out/report.txt", False)]) == []
    monkeypatch.delenv("HERMES_MEDIA_DELIVERY_STRICT")
    monkeypatch.setattr(media_fetch, "_active_remote_env", lambda: None)
    assert BasePlatformAdapter.filter_media_delivery_paths([(str(tmp_path / "nope.txt"), False)]) == []
    assert remote_env.fetched == []


def test_outside_workspace_is_blocked_before_remote_resolution(remote_env, tmp_path):
    source = str(tmp_path / "outside.txt")
    remote_env.files[source] = b"outside sentinel"
    assert media_fetch.fetch_remote_media(source) is None
    assert remote_env.resolved == [] and remote_env.fetched == []


def test_remote_symlink_escape_cannot_fetch_source(remote_env, tmp_path):
    candidate = remote_env._remote_home + "/out/escape.txt"
    outside = str(tmp_path / "outside.txt")
    remote_env.files[outside] = b"outside sentinel"
    remote_env.links[candidate] = outside
    assert media_fetch.fetch_remote_media(candidate) is None
    assert remote_env.resolved == [candidate] and remote_env.fetched == []


class _ScriptedEnv(BaseEnvironment):
    """Runs the fetch command through a real shell so the transport (marker fencing, in-sandbox
    size bound, base64 round-trip) is exercised end to end."""

    def __init__(self):
        pass

    def cleanup(self):
        pass

    def execute(self, command, cwd="", **kwargs):
        import subprocess
        proc = subprocess.run(["bash", "-c", command], capture_output=True, text=True, check=False)
        return {"output": "echo login-noise\n" + proc.stdout + proc.stderr, "returncode": proc.returncode}


def test_fetch_file_round_trips_bytes_and_enforces_the_in_sandbox_size_cap(tmp_path):
    src = tmp_path / "artifact.bin"
    src.write_bytes(bytes(range(256)) * 40)
    dest = tmp_path / "copy.bin"
    env = _ScriptedEnv()

    env.fetch_file(str(src), dest, max_bytes=len(src.read_bytes()))
    assert dest.read_bytes() == src.read_bytes()

    with pytest.raises(FileFetchError, match="exceeds"):
        env.fetch_file(str(src), dest, max_bytes=100)
    with pytest.raises(FileFetchError, match="could not read"):
        env.fetch_file(str(tmp_path), dest, max_bytes=100)  # a directory is not a regular file
