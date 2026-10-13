"""Private fixed-job bookkeeping; never a model/tool argument or sandbox override."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field


@dataclass
class DiagnosticProbe:
    fail_next_preflight: bool = False
    injected_failures: int = 0
    command_launches: int = 0
    tirith_scans: int = 0
    guard_home: str | None = None
    guard_findings: list = field(default_factory=list)
    approved_command_hashes: frozenset = frozenset()


_probe: ContextVar[DiagnosticProbe | None] = ContextVar("terminal_fixed_diagnostic", default=None)


def current_probe() -> DiagnosticProbe | None:
    return _probe.get()


@contextmanager
def fixed_diagnostic(*, fail_preflight: bool = False, approved_command_hashes: frozenset = frozenset()):
    state = DiagnosticProbe(fail_next_preflight=fail_preflight, approved_command_hashes=approved_command_hashes)
    token = _probe.set(state)
    try:
        yield state
    finally:
        _probe.reset(token)
