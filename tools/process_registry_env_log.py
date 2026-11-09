"""Background launch and log capture through the terminal environment."""

import os
from pathlib import Path
import re
import shlex
from typing import TYPE_CHECKING, Any

from tools.process_registry_output_log import open_output_log, record_exit_command, worker_output_log

if TYPE_CHECKING:
    from tools.process_registry import ProcessSession


def _sandbox_launch(command: str, directory: str, paths: tuple[str, str, str]) -> str:
    log_path, pid_path, exit_path = map(shlex.quote, paths)
    driver = f"bash -lc {shlex.quote(command)}; rc=$?; printf '%s\\n' \"$rc\" > {exit_path}"
    directory = shlex.quote(directory)
    # Brace the launch so A&&B& does not background setup and lose the exit receipt.
    return (
        f"{{ [ -d {directory} ] || mkdir -p {directory}; }} && {{ "
        f"nohup bash -c {shlex.quote(driver)} > {log_path} 2>&1 < /dev/null & "
        f"echo $! > {pid_path} && cat {pid_path}; }}"
    )


def _worker_launch(command: str, log: Path, marker: str) -> str:
    os.close(open_output_log(log))
    # The wrapper reports its own Linux PID and kernel start ticks before running
    # model code. The private descriptor closes before that code starts, so a
    # command's output and login-shell banners cannot become a host PID.
    driver = (
        'IFS= read -r stat < "/proc/$$/stat" || exit 1; '
        'set -- ${stat##*) }; '
        f'printf "{marker}:%s:%s\\n" "$$" "${{20}}" >&3; exec 3>&-; '
        + record_exit_command(log, f"bash -lc {shlex.quote(command)}")
    )
    launch = f"nohup bash -c {shlex.quote(driver)} 3>&1 >> {shlex.quote(str(log))} 2>&1 < /dev/null &"
    # The receipt pipe must close before the transport returns, even on a busy runner.
    return f'receipt=$({launch}); printf "%s\\n" "$receipt"'


def _worker_identity(output: str, marker: str) -> tuple[int | None, int | None]:
    matches = re.findall(rf"(?m)^{marker}:([0-9]+):([0-9]+)$", output)
    if len(matches) == 1:
        pid, start = map(int, matches[0])
        if pid > 1 and start > 0:
            return pid, start
    return None, None


class ProcessEnvSpawnMixin:
    def spawn_via_env(
        self, env: Any, command: str, cwd: str | None = None, task_id: str = "", session_key: str = "",
        timeout: int = 10, owner_task_id: str = "", persist_on_release: bool = False,
    ) -> "ProcessSession":
        """Launch through env.execute and keep native worker logs available for the next turn."""
        from tools.environments.local import LocalEnvironment
        from tools.process_registry import _IS_LINUX

        session = self._new_session(command, task_id, owner_task_id, session_key, cwd, env_ref=env, pid_scope="sandbox",
                                    persist_on_release=persist_on_release)
        # Only this actual native backend can attest a PID in our Linux namespace.
        local = _IS_LINUX and type(env) is LocalEnvironment and env.confinement is None
        log = worker_output_log(session.id) if local else None
        paths = ()
        try:
            if log:
                launch = _worker_launch(command, log, session.id)
            else:
                directory = self._env_temp_dir(env)
                paths = tuple(f"{directory}/hermes_bg_{session.id}.{ext}" for ext in ("log", "pid", "exit"))
                launch = _sandbox_launch(command, directory, paths)
            result = env.execute(launch, timeout=timeout, rewrite_compound_background=False)
            output = result.get("output", "").strip()
            if log:
                session.pid, session.host_start_time = _worker_identity(output, session.id)
            else:
                session.pid = next((int(line) for line in map(str.strip, output.splitlines()) if line.isdigit()), None)
            if session.pid is None:
                session.mark_exited(int(result.get("returncode", -1)) or -1, "failed_start", "failed_start")
                session.output_buffer = output
        except Exception as exc:  # health: allow BLE001 -- backends have different launch errors
            session.mark_exited(-1, "failed_start", "failed_start")
            session.output_buffer = f"Failed to start: {exc}"

        if session.exited:
            with self._lock:
                self._prune_if_needed()
        elif log:
            session.pid_scope = "host"
            session.output_log = str(log)
            self._track_started(session, self._log_reader_loop, f"proc-log-reader-{session.id}")
        else:
            self._track_started(session, self._env_poller_loop, f"proc-poller-{session.id}", (env, *paths))
        return session


def log_delta_command(quoted_log_path: str, offset: int) -> str:
    """Shell command that reads only the log bytes written since ``offset``
    (``cat``-ing the whole file every poll re-sends all output over docker/SSH).

    Prints one header line ``"<size> <offset>"`` then the bytes in [offset, size).
    The size is read first and the tail cut at that same size, so a growing file
    never sends a byte twice; a file that shrank was rotated/truncated, so the
    offset drops to 0 and the reader starts over. The window end is pulled back
    to a UTF-8 character boundary (the backend decodes each ``execute()`` result
    on its own, so a straddling multibyte char would become U+FFFD and break watch
    patterns at the seam): up to 3 trailing continuation bytes are held for the
    next poll and the header reports the trimmed size."""
    return (
        f"O={offset}; "
        f"S=$({{ wc -c < {quoted_log_path}; }} 2>/dev/null | tr -dc '0-9'); "
        f"S=${{S:-0}}; "
        f'if [ "$S" -lt "$O" ]; then O=0; fi; '
        # Scan back up to 3 continuation bytes (octal 200-277) to the lead byte; if
        # the lead's declared length (3xx=2, 34x-35x=3, 36x-37x=4) exceeds the bytes
        # present, trim to before it. Complete sequences and ASCII tails untouched.
        f'N=0; P=$S; while [ "$P" -gt "$O" ] && [ "$N" -lt 3 ]; do '
        f"B=$(tail -c +$P {quoted_log_path} 2>/dev/null | head -c 1 | od -An -to1 | tr -dc '0-9'); "
        f'case "$B" in 2[0-7][0-7]) P=$((P-1)); N=$((N+1));; *) break;; esac; done; '
        f'if [ "$N" -gt 0 ] || [ "$P" -eq "$S" ]; then '
        f"B=$(tail -c +$P {quoted_log_path} 2>/dev/null | head -c 1 | od -An -to1 | tr -dc '0-9'); "
        f'case "$B" in 3[0-3][0-7]) L=2;; 3[4-5][0-7]) L=3;; 3[6-7][0-7]) L=4;; *) L=1;; esac; '
        f'if [ "$L" -gt $((N+1)) ]; then S=$((P-1)); fi; fi; '
        f'echo "$S $O"; '
        f'if [ "$S" -gt "$O" ]; then '
        f"tail -c +$((O+1)) {quoted_log_path} 2>/dev/null | head -c $((S-O)); fi"
    )
