"""Owner-only local client for the fixed Gateway terminal case catalog."""
from __future__ import annotations

import json
import os
from pathlib import Path
import time

from gateway.security_terminal_diagnostics import CASES


def run_canaries(home: Path, *, expected_pid: int, expected_handler: Path) -> dict:
    from gateway.control_socket import query_gateway_control
    results = []
    for case in CASES:
        # One start attempt only: a lost ACK is unknown execution, never retry.
        start = query_gateway_control(home, "terminal-canary-start", params={"case": case})
        if not start or start.get("accepted") is not True or start.get("pid") != expected_pid:
            raise RuntimeError("fixed canary start/identity failed; rollback required")
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            result = query_gateway_control(home, "terminal-canary-result", params={"job": start["job"]})
            if not result:
                raise RuntimeError("fixed canary result unavailable; rollback required")
            if result.get("finished"):
                if (result.get("pid") != expected_pid or result.get("handler") != str(expected_handler.resolve())
                        or result.get("case") != case or result.get("passed") is not True or not result.get("cleaned")):
                    raise RuntimeError("fixed canary failed; rollback required: " + case)
                results.append(result)
                break
            time.sleep(.1)
        else:
            raise RuntimeError("fixed canary deadline exceeded; rollback required")
    return {"passed": True, "pid": expected_pid, "cases": results, "cleaned": True}


def command(args):
    from hermes_constants import get_process_hermes_home
    result = run_canaries(get_process_hermes_home(), expected_pid=args.expected_pid,
                         expected_handler=Path(args.expected_handler))
    print(json.dumps(result, sort_keys=True))
