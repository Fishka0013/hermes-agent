"""Local fixed canaries through the real registered model terminal, without turns/DB.

Only case IDs cross the socket. Commands, paths, backend and sandbox policy are
trusted code. State/results stay in memory; the only files are owned canaries.
"""
from __future__ import annotations

import contextlib
import contextvars
import errno
import hashlib
import json
import os
from pathlib import Path
import shlex
import socket
import sys
import threading
import time
import uuid

CASES = (
    "INSIDE_WORKSPACE", "OUTSIDE_ROOT_DENY", "TRAVERSAL_DENY",
    "SYMLINK_ESCAPE_DENY", "PYTHON_CHILD_DENY", "NESTED_SHELL_DENY",
    "DETACHED_DESCENDANT_DENY", "BASIC_SYSTEM_COMMAND_ALLOWED",
    "PRIVATE_HOME_TMP_VERIFY", "LOOPBACK_NETWORK_DENY", "SANDBOX_INIT_FAIL_CLOSED",
)
_CATALOG_VERSION = 1
_COMMAND_TIMEOUT = 8


class _Artifacts:
    """Exclusive directories and FD-relative cleanup, never recursive deletion."""
    def __init__(self, root: Path, outside: Path):
        self.inside = root / ".tmp" / "hermes-access-stage5"
        self.outside = outside
        self.nonce = uuid.uuid4().hex
        self._dirs: list[tuple[int, int, str, Path]] = []
        self._parents: list[int] = []

    def __enter__(self):
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            root = os.open(self.inside.parent.parent, flags)
            self._parents.append(root)
            with contextlib.suppress(FileExistsError):
                os.mkdir(".tmp", mode=0o700, dir_fd=root)
            parent = os.open(".tmp", flags, dir_fd=root)
            self._parents.append(parent)
            outside_parent = os.open(self.outside.parent.resolve(strict=True), flags)
            self._parents.append(outside_parent)
            for fd, path in ((parent, self.inside), (outside_parent, self.outside)):
                os.mkdir(path.name, mode=0o700, dir_fd=fd)  # Existing artifact => refuse, never inspect it.
                child = os.open(path.name, flags, dir_fd=fd)
                self._dirs.append((fd, child, path.name, path))
                self.write(path, ".hermes-owner.json", json.dumps({"schema": 1, "producer": "hermes-stage5-fixed-canary", "nonce": self.nonce}))
                self.write(path, "canary.txt", self.nonce)
            os.symlink(str(self.outside / "canary.txt"), "escape", dir_fd=self._dirs[0][1])
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def write(self, directory: Path, name: str, text: str):
        fd = next(fd for _, fd, _, path in self._dirs if path == directory)
        handle = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(handle, "w") as stream:
            stream.write(text)

    def __exit__(self, *unused):
        failure = None
        for parent, fd, name, path in reversed(self._dirs):
            try:
                # Fixed filenames only. Unexpected content is a cleanup failure.
                for entry in ("canary.txt", "escape", "written.txt", "fail-closed-marker", ".hermes-owner.json"):
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(entry, dir_fd=fd)
                os.rmdir(name, dir_fd=parent)
            except OSError as exc:
                failure = exc
            finally:
                os.close(fd)
        self._dirs.clear()
        for fd in reversed(self._parents):
            os.close(fd)
        self._parents.clear()
        if failure is not None:
            raise RuntimeError("diagnostic artifacts could not be completely cleaned") from failure


def _python(code: str) -> str:
    return shlex.quote(str(Path(sys._base_executable).resolve())) + " -I -S -B -c " + shlex.quote(code)


def _denial_code(path: str, *, write=False) -> str:
    operation = f"open({path!r}, 'w').write('HERMES_GENERATED_WRITE')" if write else f"open({path!r}).read()"
    return ("import json,errno\ntry:\n " + operation + "\n print(json.dumps({'denied':False}))\n"
            "except OSError as e:\n print(json.dumps({'denied':e.errno in (errno.EPERM,errno.EACCES),'errno':e.errno}))\n")


def _commands(case: str, artifacts: _Artifacts, root: Path, port: int | None) -> list[str]:
    inside, outside = artifacts.inside / "canary.txt", artifacts.outside / "canary.txt"
    if case == "INSIDE_WORKSPACE":
        return [_python(f"import json,pathlib; p=pathlib.Path({str(inside)!r}); "
                        f"ok=p.read_text()=={artifacts.nonce!r}; "
                        f"pathlib.Path({str(artifacts.inside / 'written.txt')!r}).write_text({artifacts.nonce!r}); "
                        "print(json.dumps({'allowed':ok,'written':True}))")]
    if case == "OUTSIDE_ROOT_DENY":
        return [_python(_denial_code(str(outside))), _python(_denial_code(str(outside), write=True))]
    if case in {"TRAVERSAL_DENY", "SYMLINK_ESCAPE_DENY"}:
        path = os.path.relpath(outside, root) if case == "TRAVERSAL_DENY" else str(artifacts.inside / "escape")
        return [_python(_denial_code(path))]
    if case in {"PYTHON_CHILD_DENY", "DETACHED_DESCENDANT_DENY"}:
        child = _denial_code(str(outside))
        detached = case == "DETACHED_DESCENDANT_DENY"
        return [_python("import subprocess,json\np=subprocess.Popen(" + repr([str(Path(sys._base_executable).resolve()),
                        "-I", "-S", "-B", "-c", child]) +
                        f",start_new_session={detached!r},stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)\n"
                        "try:\n out,err=p.communicate(timeout=2)\n print(json.dumps({'denied':p.returncode==0 and json.loads(out).get('denied') is True}))\n"
                        "finally:\n if p.poll() is None:\n  p.terminate()\n  p.wait(timeout=2)\n")]
    if case == "NESTED_SHELL_DENY":
        command = "/bin/cat " + shlex.quote(str(outside))
        return [_python("import subprocess,json; p=subprocess.run(" + repr(["/bin/bash", "--noprofile", "--norc", "-c", command]) +
                        ",capture_output=True,text=True,timeout=2); "
                        "print(json.dumps({'denied':p.returncode!=0 and 'Operation not permitted' in p.stderr}))")]
    if case == "BASIC_SYSTEM_COMMAND_ALLOWED":
        return ["/usr/bin/true && printf '%s' '{\"allowed\":true}'"]
    if case == "PRIVATE_HOME_TMP_VERIFY":
        allowed = {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "PYTHONIOENCODING", "PYTHONDONTWRITEBYTECODE", "PYTHONUTF8",
                   "HOME", "TMPDIR", "TMP", "TEMP", "GIT_PAGER", "PAGER", "PWD", "OLDPWD", "SHLVL", "_",
                   "AI_AGENT", "HERMES_AGENT"}  # Fixed shell markers added by Hermes, not inherited credentials.
        return [_python("import json,os,pathlib; "
                        f"r=pathlib.Path({str(root)!r}).resolve(); h=pathlib.Path(os.environ['HOME']).resolve(); "
                        "t=pathlib.Path(os.environ['TMPDIR']).resolve(); p=t/'generated-tmp-probe'; p.write_text('GENERATED'); p.unlink(); "
                        f"print(json.dumps({{'private':h.is_relative_to(r) and t.is_relative_to(r) and h!=r and t!=r and h!=t,"
                        f"'unexpected_environment_keys':sorted(set(os.environ)-{allowed!r}),"
                        f"'secret_inheritance':bool(set(os.environ)-{allowed!r}),'credential_agent_inheritance':"
                        "any(k in os.environ for k in ('SSH_AUTH_SOCK','GPG_AGENT_INFO','AWS_CONTAINER_CREDENTIALS_RELATIVE_URI'))}))")]
    if case == "LOOPBACK_NETWORK_DENY":
        return [_python("import socket,errno,json\ns=socket.socket()\ns.settimeout(1)\ntry:\n "
                        f"s.connect(('127.0.0.1',{port}))\n print(json.dumps({{'denied':False}}))\n"
                        "except OSError as e:\n print(json.dumps({'denied':e.errno in (errno.EPERM,errno.EACCES),'errno':e.errno}))\n"
                        "finally:\n s.close()")]
    if case == "SANDBOX_INIT_FAIL_CLOSED":
        return [_python(f"import pathlib; pathlib.Path({str(artifacts.inside / 'fail-closed-marker')!r}).write_text('GENERATED')")]
    raise ValueError("unknown fixed diagnostic case")


class TerminalDiagnostics:
    def __init__(self, home: Path, *, _isolated_outside: Path | None = None):
        self.home = home.resolve()
        self.outside = _isolated_outside or Path("/tmp/hermes-access-stage5")
        self.context = contextvars.copy_context()
        self.lock = threading.Lock()
        self.job: dict | None = None

    def start(self, params: dict) -> dict:
        if set(params) != {"case"} or params.get("case") not in CASES:
            raise ValueError("only a fixed diagnostic case ID is accepted")
        with self.lock:
            if self.job and not self.job.get("finished"):
                return {"accepted": False, "busy": True}
            job = {"id": uuid.uuid4().hex, "case": params["case"], "finished": False, "started": time.monotonic()}
            self.job = job
            thread = threading.Thread(target=lambda: self.context.copy().run(self._run, job),
                                      name="hermes-fixed-terminal-diagnostic", daemon=True)
            thread.start()
            return {"accepted": True, "job": job["id"], "case": job["case"], "pid": os.getpid()}

    def result(self, params: dict) -> dict:
        if set(params) != {"job"} or not isinstance(params["job"], str):
            raise ValueError("a returned diagnostic job ID is required")
        with self.lock:
            if not self.job or params["job"] != self.job["id"]:
                raise ValueError("unknown diagnostic job")
            return {k: v for k, v in self.job.items() if k != "started"}

    def _run(self, job: dict):
        from hermes_constants import set_hermes_home_override, reset_hermes_home_override
        from tools.terminal_scope import install_and_reset_profile_terminal_scope
        token = set_hermes_home_override(self.home)
        outcome = {"passed": False, "cleaned": False}
        try:
            with install_and_reset_profile_terminal_scope(self.home):
                outcome = self._execute(job["case"], job["id"])
        except Exception as exc:
            outcome["error_kind"] = type(exc).__name__  # Never return raw exception/command/secret text.
        finally:
            reset_hermes_home_override(token)
            with self.lock:
                job.update(outcome)
                job["finished"] = True

    def _execute(self, case: str, task: str) -> dict:
        from agent.model_file_policy import get_model_workspace_root
        from tools.registry import registry
        from tools import terminal_tool as terminal
        from tools.terminal_diagnostic_scope import fixed_diagnostic
        from tools.terminal_scope import terminal_env
        if sys.platform != "darwin" or terminal_env("TERMINAL_ENV", "local") != "local":
            raise RuntimeError("fixed diagnostic requires the configured Mac local model terminal")
        entry = registry.get_entry("terminal", scope=registry.current_scope_key())
        if entry is None or entry.handler is not terminal._handle_terminal:
            raise RuntimeError("registered model terminal handler identity mismatch")
        root = get_model_workspace_root().resolve(strict=True)
        evidence = {"catalog": _CATALOG_VERSION, "pid": os.getpid(), "handler": str(Path(terminal.__file__).resolve()),
                    "handler_sha256": hashlib.sha256(Path(terminal.__file__).read_bytes()).hexdigest(), "passed": False}
        listener = None
        try:
            with _Artifacts(root, self.outside) as artifacts:
                if case == "LOOPBACK_NETWORK_DENY":
                    listener = socket.socket()
                    listener.bind(("127.0.0.1", 0))
                    listener.listen(1)
                    listener.settimeout(.1)
                    # Positive control against this private generated listener,
                    # never a production service or an external endpoint.
                    with socket.create_connection(listener.getsockname(), timeout=1) as host_control:
                        accepted, address = listener.accept()
                        accepted.close()
                        if address[0] != "127.0.0.1":
                            raise RuntimeError("loopback positive control identity mismatch")
                port = listener.getsockname()[1] if listener else None
                results = []
                commands = _commands(case, artifacts, root, port)
                fingerprints = frozenset(hashlib.sha256(command.encode()).hexdigest() for command in commands)
                with fixed_diagnostic(fail_preflight=case == "SANDBOX_INIT_FAIL_CLOSED", approved_command_hashes=fingerprints) as probe:
                    for command in commands:
                        value = registry.dispatch("terminal", {"command": command, "timeout": _COMMAND_TIMEOUT,
                                                  "background": False, "workdir": str(root)},
                                                  scope=registry.current_scope_key(), task_id="fixed-diagnostic-" + task,
                                                  expected_handler=terminal._handle_terminal)
                        value = json.loads(value) if isinstance(value, str) else value
                        if not isinstance(value, dict) or value.get("session_id"):
                            raise RuntimeError("diagnostic attempted asynchronous terminal authority")
                        results.append(value)
                    if case == "SANDBOX_INIT_FAIL_CLOSED":
                        evidence["passed"] = (probe.injected_failures == 1 and probe.command_launches == 0 and
                                              bool(results[0].get("error")) and
                                              not (artifacts.inside / "fail-closed-marker").exists())
                    else:
                        parsed = [json.loads(result["output"]) if result.get("exit_code") == 0 and not result.get("error")
                                  else {} for result in results]
                        if case == "INSIDE_WORKSPACE":
                            evidence["passed"] = (parsed[0].get("allowed") is True and parsed[0].get("written") is True and
                                                  (artifacts.inside / "written.txt").read_text() == artifacts.nonce)
                        elif case == "BASIC_SYSTEM_COMMAND_ALLOWED":
                            evidence["passed"] = parsed[0].get("allowed") is True
                        elif case == "PRIVATE_HOME_TMP_VERIFY":
                            evidence.update(parsed[0])
                            evidence["passed"] = (parsed[0].get("private") is True and parsed[0].get("secret_inheritance") is False
                                                  and parsed[0].get("credential_agent_inheritance") is False)
                        else:
                            evidence["passed"] = all(p.get("denied") is True for p in parsed)
                        if case == "OUTSIDE_ROOT_DENY":
                            evidence["passed"] &= (artifacts.outside / "canary.txt").read_text() == artifacts.nonce
                    evidence["command_launches"] = probe.command_launches
                    evidence["injected_failures"] = probe.injected_failures
                    evidence["dispatches"] = len(results)
                    evidence["tirith_scans"] = probe.tirith_scans
                    evidence["guard_findings"] = probe.guard_findings
                    if case != "SANDBOX_INIT_FAIL_CLOSED":
                        evidence["passed"] &= probe.tirith_scans >= len(results)
                    evidence["exit_codes"] = [r.get("exit_code") for r in results]
                if listener:
                    try:
                        connection, _ = listener.accept()
                        connection.close()
                        evidence["passed"] = False
                    except socket.timeout:
                        pass
                terminal._evict_environment_for_task("fixed-diagnostic-" + task)
                terminal.clear_session_cwd("fixed-diagnostic-" + task)
            evidence["cleaned"] = not artifacts.inside.exists() and not artifacts.outside.exists()
            evidence["passed"] &= evidence["cleaned"]
            return evidence
        finally:
            if listener:
                listener.close()
            terminal._evict_environment_for_task("fixed-diagnostic-" + task)
            terminal.clear_session_cwd("fixed-diagnostic-" + task)


def diagnostic_handlers(home: Path | None = None) -> dict:
    if home is None:
        from hermes_constants import get_process_hermes_home
        home = get_process_hermes_home()
    service = TerminalDiagnostics(Path(home))
    return {"terminal-canary-start": service.start, "terminal-canary-result": service.result}
