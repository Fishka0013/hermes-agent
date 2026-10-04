#!/usr/bin/env python3
"""Read the in-app browser / preview pane in the Hermes desktop GUI.

The preview's content lives in the renderer (a sandboxed ``<webview>``), so this
round-trips through the gateway's blocking-prompt bridge like ``read_terminal``
(``preview.read.request`` -> ``preview.read.respond``). Registered as action=read of
`desktop_preview`; the agent dispatches here with the injected callback.
"""

import json
from typing import Callable, Optional
from urllib.parse import unquote, urlparse

from tools.read_terminal_tool import read_pane
from tools.registry import tool_error


def _confined_preview_response(raw: str) -> str:
    """A renderer-owned local tab never grants model filesystem authority."""
    try:
        payload = json.loads(raw)
        if isinstance(payload, dict) and payload.get("error"):
            return tool_error(str(payload["error"]))
        if not isinstance(payload, dict) or payload.get("kind") != "url" or payload.get("path"):
            raise ValueError("not a web preview")
        target = payload.get("url")
        if not isinstance(target, str):
            raise ValueError("missing preview URL")
        parsed = urlparse(unquote(target.strip()))
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("not an HTTP(S) page")
    except (TypeError, ValueError):
        return tool_error("Local or unverified preview access is disabled for ordinary model tools. Use an HTTP(S) page.")
    return raw


def read_preview_tool(
    start: Optional[int] = None, count: Optional[int] = None, callback: Optional[Callable] = None
) -> str:
    """Return the active preview tab's contents (+ metadata) as a JSON string."""
    return _confined_preview_response(read_pane(callback, (("start", start, 0), ("count", count, 1)), (
        "read_preview is only available in the Hermes desktop app.",
        "start and count must be integers.",
        "Failed to read the preview pane: ",
        "No preview tab answered: no page is loaded (call open_preview first), "
        "or the bridge timed out. If the pane IS open, the desktop app may be older "
        "than this backend — update it and retry.")))
