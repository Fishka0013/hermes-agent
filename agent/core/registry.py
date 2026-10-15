"""Deterministic in-code target resolution for Core V1 Package A."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Iterable

from agent.core.contracts import TargetBinding, Task


class TargetResolutionError(ValueError):
    pass


class UnknownTarget(TargetResolutionError):
    pass


class UnsupportedCapability(TargetResolutionError):
    pass


class IdentityNotAllowed(TargetResolutionError):
    pass


class TrustPathNotAllowed(TargetResolutionError):
    pass


@dataclass(frozen=True, slots=True)
class TargetDefinition:
    target_id: str
    adapter_id: str
    supported_capabilities: frozenset[str]
    allowed_identity_refs: frozenset[str] = frozenset()
    allowed_trust_path_refs: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(self, "supported_capabilities", frozenset(self.supported_capabilities))
        object.__setattr__(self, "allowed_identity_refs", frozenset(self.allowed_identity_refs))
        object.__setattr__(self, "allowed_trust_path_refs", frozenset(self.allowed_trust_path_refs))


class DeterministicTargetRegistry:
    """Small immutable code/test registry; never a governance or ownership authority."""

    def __init__(self, definitions: Iterable[TargetDefinition]) -> None:
        items = list(definitions)
        by_id = {definition.target_id: definition for definition in items}
        if len(by_id) != len(items):
            raise ValueError("Duplicate target_id in Core target definitions")
        self._targets = MappingProxyType(by_id)

    def resolve(
        self,
        task: Task,
        *,
        identity_ref: str,
        trust_path_ref: str,
        resource_ref: str = "",
    ) -> TargetBinding:
        definition = self._targets.get(task.requested_target)
        if definition is None:
            raise UnknownTarget(task.requested_target)
        if task.requested_capability not in definition.supported_capabilities:
            raise UnsupportedCapability(
                f"{task.requested_target}:{task.requested_capability}"
            )
        if definition.allowed_identity_refs and identity_ref not in definition.allowed_identity_refs:
            raise IdentityNotAllowed(identity_ref)
        if definition.allowed_trust_path_refs and trust_path_ref not in definition.allowed_trust_path_refs:
            raise TrustPathNotAllowed(trust_path_ref)
        return TargetBinding(
            target_id=definition.target_id,
            capability=task.requested_capability,
            adapter_id=definition.adapter_id,
            identity_ref=identity_ref,
            trust_path_ref=trust_path_ref,
            resource_ref=resource_ref,
        )
