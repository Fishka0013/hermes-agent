#!/usr/bin/env python3
"""Open an HTTP(S) URL or authorized dev server in the desktop preview pane.

Registration lives in the `desktop_preview` tool (``tools.preview_tool``); this module keeps
the normalizer + open action. Emits ``preview.open`` via ``desktop_ui``: the renderer opens
the pane for the window that asked and never steals focus for a background session.
"""

import re
from urllib.parse import unquote, urlparse

from tools import desktop_ui
from tools.registry import tool_error


def _normalize_target(raw: str) -> str:
    """Coax a bare host/domain into a fetchable URL; leave paths + schemes alone.

    ``www.cnn.com`` -> ``https://www.cnn.com``; ``localhost:3000`` -> ``http://localhost:3000``.
    Preserve explicit schemes for the fail-closed target check.
    """
    v = raw.strip().strip("`").strip()
    if not v or "://" in v or v.startswith(("/", "./", "../", "~", "file:")):
        return v
    if re.match(r"^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(:\d+)?(/|$)", v, re.IGNORECASE):
        return "http://" + v
    if re.match(r"^[^/\\]+\.(?:html?|md|txt|pdf|csv|json|ya?ml|toml|xml|js|ts|css|docx?|xlsx?|pptx?)$", v, re.I):
        return v
    if re.match(r"^[\w.-]+\.[a-z]{2,}(:\d+)?(/.*)?$", v, re.I):
        return "https://" + v
    return v


def open_preview_tool(url: str, label: str = "") -> str:
    """Ask the desktop GUI to show an HTTP(S) target beside the chat."""
    target = _normalize_target(url or "")
    if not target:
        return tool_error("url is required — use an HTTP(S) target or an authorized dev server.")
    try:
        scheme = (urlparse(unquote(target)).scheme or "").lower()
    except (ValueError, TypeError):
        scheme = ""
    if scheme not in {"http", "https"}:
        return tool_error(
            "Local file/path preview is disabled for ordinary model tools. "
            "Use an HTTP(S) target; localhost access requires task authorization."
        )

    label = (label or "").strip()
    return desktop_ui.emit_or_error(
        "preview.open",
        {"url": target, "label": label},
        "Failed to open the preview pane: ",
        "The preview pane is only available in the Hermes desktop app.",
        {"success": True, "url": target, "label": label})
