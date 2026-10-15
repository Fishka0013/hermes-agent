"""Immutable data contracts for the isolated Core V1 semantic skeleton."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any


_JSON_SCALARS = (str, int, float, bool, type(None))


def freeze_json(value: Any) -> Any:
    """Recursively freeze JSON-like values without inventing a new identity model."""
    if isinstance(value, Mapping):
        frozen = {str(key): freeze_json(item) for key, item in sorted(value.items(), key=lambda item: str(item[0]))}
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(freeze_json(item) for item in value)
    if isinstance(value, _JSON_SCALARS):
        return value
    raise TypeError(f"Core parameters must be JSON-like, got {type(value).__name__}")


def thaw_json(value: Any) -> Any:
    """Return a canonical JSON-serializable representation of a frozen value."""
    if isinstance(value, Mapping):
        return {key: thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw_json(item) for item in value]
    return value


class PermissionLevel(str, Enum):
    A = "A"
    B = "B"
    C = "C"


class AuthorizationScope(str, Enum):
    ONE_SHOT = "ONE_SHOT"
    SESSION = "SESSION"
    NEVER_PERSIST = "NEVER_PERSIST"


class PolicyVerdict(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class AdapterStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    TIMEOUT = "TIMEOUT"


class CoreOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    DENIED = "DENIED"
    TIMEOUT_NO_DISPATCH = "TIMEOUT_NO_DISPATCH"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
    DUPLICATE_REQUEST = "DUPLICATE_REQUEST"


class HealthState(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True, slots=True)
class Task:
    request_id: str
    intent: str
    requested_target: str
    requested_capability: str
    parameters: Mapping[str, Any]
    provenance_ref: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "parameters", freeze_json(self.parameters))


@dataclass(frozen=True, slots=True)
class TargetBinding:
    target_id: str
    capability: str
    adapter_id: str
    identity_ref: str
    trust_path_ref: str
    resource_ref: str = ""


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    verdict: PolicyVerdict
    permission_level: PermissionLevel
    scope: AuthorizationScope
    authorization_ref: str = ""
    binding_digest: str = ""
    reason: str = ""

    def __post_init__(self) -> None:
        if self.verdict is PolicyVerdict.ALLOW and not self.authorization_ref:
            raise ValueError("Allowed policy decision requires authorization_ref")
        if self.permission_level is PermissionLevel.C and self.verdict is PolicyVerdict.ALLOW:
            if self.scope is AuthorizationScope.SESSION:
                raise ValueError("Level C authorization cannot be reusable within a session")


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    execution_id: str
    request_id: str
    binding: TargetBinding
    parameters: Mapping[str, Any]
    authorization_ref: str
    binding_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "parameters", freeze_json(self.parameters))


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    kind: str
    reference: str


_HEALTH_FINDING_MAX = 280


@dataclass(frozen=True, slots=True)
class HealthObservation:
    """A target observation; a nonempty finding denotes an adverse/blocking fact."""

    state: HealthState
    evidence_refs: tuple[EvidenceRef, ...] = ()
    finding: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "state", HealthState(self.state))
        refs = tuple(self.evidence_refs)
        if any(
            not isinstance(ref, EvidenceRef)
            or not isinstance(ref.kind, str)
            or not isinstance(ref.reference, str)
            for ref in refs
        ):
            raise TypeError("Health evidence must contain EvidenceRef strings")
        object.__setattr__(self, "evidence_refs", refs)
        if not isinstance(self.finding, str):
            raise TypeError("Health finding must be a string")
        finding = self.finding.strip()
        if len(finding) > _HEALTH_FINDING_MAX:
            finding = finding[: _HEALTH_FINDING_MAX - 1] + "…"
        object.__setattr__(self, "finding", finding)


@dataclass(frozen=True, slots=True)
class AdapterResult:
    status: AdapterStatus
    dispatch_started: bool
    outcome_known: bool
    summary: str = ""
    evidence: tuple[EvidenceRef, ...] = ()
    health_observation: HealthObservation | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", tuple(self.evidence))


_RECEIPT_SUMMARY_MAX = 280


@dataclass(frozen=True, slots=True)
class Receipt:
    request_id: str
    execution_id: str
    outcome: CoreOutcome
    binding_digest: str
    evidence_refs: tuple[EvidenceRef, ...] = ()
    summary: str = ""

    def __post_init__(self) -> None:
        if len(self.summary) > _RECEIPT_SUMMARY_MAX:
            object.__setattr__(self, "summary", self.summary[: _RECEIPT_SUMMARY_MAX - 1] + "…")
        object.__setattr__(self, "evidence_refs", tuple(self.evidence_refs))


@dataclass(frozen=True, slots=True)
class CoreExecutionResult:
    request_id: str
    execution_id: str
    outcome: CoreOutcome
    adapter_result: AdapterResult | None
    evidence: tuple[EvidenceRef, ...]
    receipt: Receipt
    health_observation: HealthObservation | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", tuple(self.evidence))


def compute_binding_digest(binding: TargetBinding, parameters: Mapping[str, Any]) -> str:
    """Digest exactly what Policy authorized and Adapter will receive."""
    payload = {
        "target_id": binding.target_id,
        "capability": binding.capability,
        "adapter_id": binding.adapter_id,
        "identity_ref": binding.identity_ref,
        "trust_path_ref": binding.trust_path_ref,
        "resource_ref": binding.resource_ref,
        "parameters": thaw_json(freeze_json(parameters)),
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
