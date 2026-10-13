"""Minimal Policy contract for Core V1 Package A.

This interface does not replace or call the active Hermes approval engine.
"""

from __future__ import annotations

from typing import Protocol

from agent.core.contracts import PolicyDecision, TargetBinding, Task


class Policy(Protocol):
    def authorize(self, task: Task, binding: TargetBinding) -> PolicyDecision:
        """Return the decision for this exact normalized binding."""
        ...
