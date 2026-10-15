"""Kernel-enforced workspace authority for model-triggered Mac terminals.

The host keeps its runtime authority. Only child shells enter Seatbelt; fork,
exec, interpreters and detached descendants retain that policy. No profile or
launcher is loaded from the model-writable workspace.
"""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

from agent.model_file_policy import get_model_workspace_root, validate_resolution_base
from hermes_platform.resolver import locate_command


class TerminalConfinementError(PermissionError):
    """Confinement is unavailable; never retry through an unrestricted shell."""


# These are policy grants, not a PATH-based executable discovery fallback.
_SYSTEM_COMMANDS = (
    "/bin/bash", "/bin/cat", "/bin/mv", "/bin/rm", "/bin/ln",
    "/bin/mkdir", "/bin/chmod", "/bin/ls", "/bin/realpath",
    "/usr/bin/awk", "/usr/bin/grep", "/usr/bin/mktemp", "/usr/bin/env",
    "/usr/bin/true", "/usr/bin/head", "/usr/bin/base64", "/usr/bin/sed",
    "/usr/bin/cut", "/usr/bin/wc", "/usr/bin/tail", "/usr/bin/stat",
    "/usr/bin/readlink", "/usr/bin/dirname", "/usr/bin/od",
)
_SYSTEM_LIBRARIES = (
    "/usr/lib", "/System/Library",
    "/System/Volumes/Preboot/Cryptexes/OS",
    "/System/Volumes/Preboot/Cryptexes/App/System",
    "/System/Cryptexes/OS", "/System/Cryptexes/App",
)
_SETUP_TIMEOUT = 3


def _selector(kind: str, path: Path | str) -> str:
    return f"({kind} {json.dumps(str(path), ensure_ascii=True)})"


def _required_command(path: str) -> str:
    command = locate_command(path).command
    if not command:
        raise TerminalConfinementError(f"Required Mac sandbox executable unavailable: {path}")
    return str(Path(command[0]).resolve(strict=True))


class MacOSTerminalConfinement:
    """One trusted workspace binding and a workspace-local child HOME/scratch."""

    def __init__(self):
        self._directory_fds: list[int] = []
        self._scratch_fd: int | None = None
        self._tmp_fd: int | None = None
        try:
            self.root = get_model_workspace_root()
            self.launcher = _required_command("/usr/bin/sandbox-exec")
            self.shell = _required_command("/bin/bash")
            self.probe = _required_command("/usr/bin/true")
            self.python = Path(sys._base_executable).resolve(strict=True)
            self.python_libraries = (Path(sys.base_prefix) / "lib").resolve(strict=True)
            # Model writes must never alter the interpreter or Hermes host code.
            host_code = Path(__file__).resolve().parents[2]
            for component in (self.python, self.python_libraries, host_code):
                if component.is_relative_to(self.root):
                    raise TerminalConfinementError("Model workspace overlaps trusted Hermes runtime")
            self.profile = self._profile()
            self.scratch = self.root / ".tmp" / "hermes-terminal" / uuid.uuid4().hex
            self._open_scratch()
            self.verify_kernel()
        except Exception as exc:
            self.cleanup()
            if isinstance(exc, TerminalConfinementError):
                raise
            raise TerminalConfinementError(f"Mac terminal confinement initialization failed: {exc}") from exc

    def _profile(self) -> str:
        files = [Path(p).resolve() for p in _SYSTEM_COMMANDS]
        files.append(self.python)
        read_dirs = [*_SYSTEM_LIBRARIES, str(self.python_libraries), str(self.root)]
        reads = " ".join([*(_selector("literal", p) for p in files),
                          *(_selector("subpath", p) for p in read_dirs)])
        executables = " ".join([*(_selector("literal", p) for p in files),
                                _selector("subpath", self.root)])
        ancestors = {str(p) for root in (self.root, self.python, self.python_libraries)
                     for p in root.parents}
        metadata = " ".join(_selector("literal", p) for p in sorted(ancestors))
        return f"""(version 1)
(deny default)
(allow syscall*)
(allow mach-bootstrap)
(allow sysctl-read)
(allow system-fcntl)
(allow system-mac-syscall (require-all (mac-policy-name "Sandbox") (mac-syscall-number 2)))
(allow process-fork)
(allow process-exec {executables})
(allow signal (target same-sandbox))
(allow file-read* (literal "/"))
(allow file-read* file-map-executable {reads})
(allow file-write* {_selector("subpath", self.root)})
(allow file-read-metadata {metadata})
(allow file-read* file-write-data (literal "/dev/null"))
(allow file-read* (literal "/dev/random") (literal "/dev/urandom"))
"""

    def _open_scratch(self) -> None:
        # Directory FDs and O_NOFOLLOW prevent a workspace symlink/race from
        # turning host-side scratch creation or cleanup into an outside write.
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        parent = os.open(self.root, flags)
        self._directory_fds.append(parent)
        for name in (".tmp", "hermes-terminal", self.scratch.name):
            with contextlib.suppress(FileExistsError):
                os.mkdir(name, mode=0o700, dir_fd=parent)
            child = os.open(name, flags, dir_fd=parent)
            self._directory_fds.append(child)
            parent = child
        self._scratch_fd = parent
        for name in ("home", "tmp"):
            os.mkdir(name, mode=0o700, dir_fd=parent)
            if name == "tmp":
                self._tmp_fd = os.open(name, flags, dir_fd=parent)
                self._directory_fds.append(self._tmp_fd)

    def child_env(self) -> dict[str, str]:
        from tools.environments.local import build_subprocess_env

        # An allowlist avoids exporting host credentials, agent control markers,
        # shell-init hooks, credential-agent sockets or unclassified secrets.
        return build_subprocess_env(
            {}, scrub_secrets=False, inherit_profile_home=False,
            extra={"PATH": f"/bin:/usr/bin:{self.python.parent}", "LANG": "C",
                   "PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1",
                   "HOME": str(self.scratch / "home"),
                   "TMPDIR": str(self.scratch / "tmp"),
                   "TMP": str(self.scratch / "tmp"), "TEMP": str(self.scratch / "tmp"),
                   "GIT_PAGER": "cat", "PAGER": "cat"},
        )

    def resolve_cwd(self, cwd: str | None) -> str:
        try:
            if get_model_workspace_root() != self.root:
                raise TerminalConfinementError("Model workspace binding changed; recreate terminal environment")
            return str(validate_resolution_base(cwd or self.root, root=self.root))
        except TerminalConfinementError:
            raise
        except Exception as exc:
            raise TerminalConfinementError(f"Confined terminal cwd rejected: {exc}") from exc

    def verify_kernel(self) -> None:
        try:
            result = subprocess.run(
                [self.launcher, "-p", self.profile, self.probe], cwd=self.root,
                env=self.child_env(), stdin=subprocess.DEVNULL, capture_output=True,
                text=True, close_fds=True, timeout=_SETUP_TIMEOUT,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise TerminalConfinementError("Mac kernel sandbox setup failed") from exc
        if result.returncode:
            raise TerminalConfinementError(
                f"Mac kernel sandbox setup failed (exit {result.returncode}): {result.stderr.strip()[:200]}")

    def launch(self, command: str, cwd: str | None) -> tuple[list[str], dict[str, str], str]:
        cwd = self.resolve_cwd(cwd)
        # Check before background/PTY reports a started process. The command's
        # own launch ALSO applies Seatbelt; a later failure cannot run it bare.
        self.verify_kernel()
        argv = [self.launcher, "-p", self.profile, self.shell,
                "--noprofile", "--norc", "-c", command]
        return argv, self.child_env(), cwd

    def cleanup(self) -> None:
        fd = self._scratch_fd
        if fd is not None:
            with contextlib.suppress(OSError):
                if self._tmp_fd is not None:
                    for name in os.listdir(self._tmp_fd):
                        if name.startswith(("hermes-snap-", "hermes-cwd-")):
                            with contextlib.suppress(OSError):
                                os.unlink(name, dir_fd=self._tmp_fd)
                for name in ("home", "tmp"):
                    with contextlib.suppress(OSError):
                        os.rmdir(name, dir_fd=fd)
                with contextlib.suppress(OSError):
                    os.rmdir(self.scratch.name, dir_fd=self._directory_fds[2])
        for fd in reversed(self._directory_fds):
            with contextlib.suppress(OSError):
                os.close(fd)
        self._directory_fds.clear()
        self._scratch_fd = None
        self._tmp_fd = None
