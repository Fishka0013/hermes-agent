"""Fail-isolated Core V1 production binding for the local Hermes Gateway.

The binding is intentionally narrow: target=mac, capability=status, Level A,
using a direct in-process Gateway status provider. It never opens Hermes'
existing state.db and never uses the Gateway control socket as a target
transport.
"""

from __future__ import annotations

import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Callable

from agent.core.contracts import (
    AdapterResult,
    AdapterStatus,
    AuthorizationScope,
    EvidenceRef,
    HealthObservation,
    HealthState,
    PermissionLevel,
    PolicyDecision,
    PolicyVerdict,
    Task,
    TargetBinding,
    compute_binding_digest,
)
from agent.core.dispatcher import CoreDispatcher, ReconciliationRequired
from agent.core.registry import DeterministicTargetRegistry, TargetDefinition
from agent.core.storage import (
    CoreStateStore,
    RecoveryDecision,
    create_core_state_schema,
    validate_core_state_schema,
)

CORE_DB_FILENAME = "core-state-v1.db"
CORE_STATUS_CONTROL_VERB = "core-status"
MAC_TARGET_ID = "mac"
MAC_STATUS_CAPABILITY = "status"
MAC_STATUS_ADAPTER_ID = "mac-status-inproc-v1"
MAC_LOCAL_IDENTITY_REF = "mac-local-owner"
MAC_INPROC_STATUS_TRUST_PATH_REF = "gateway-inproc-status-v1"

StatusProvider = Callable[[], dict | None]


def core_database_path(home: Path) -> Path:
    """Dedicated Core DB; deliberately separate from Hermes state.db."""
    return Path(home) / CORE_DB_FILENAME


def open_core_database(home: Path) -> sqlite3.Connection:
    """Open/create the dedicated Core DB and fail closed on incompatible state."""
    home = Path(home)
    if not home.is_dir():
        raise RuntimeError(f"Hermes home does not exist: {home}")
    path = core_database_path(home)
    existed = path.exists()
    if existed and (path.is_symlink() or not path.is_file()):
        raise RuntimeError("Core DB path is not a regular non-symlink file")

    connection = sqlite3.connect(str(path), timeout=5.0, check_same_thread=False)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        if existed:
            validate_core_state_schema(connection)
        else:
            create_core_state_schema(connection)
            validate_core_state_schema(connection)
        return connection
    except BaseException:
        connection.close()
        raise


class GatewayMacStatusLevelAPolicy:
    """Authorize only the exact in-process Mac status binding."""

    def authorize(self, task: Task, binding: TargetBinding) -> PolicyDecision:
        exact = (
            task.requested_target == MAC_TARGET_ID
            and task.requested_capability == MAC_STATUS_CAPABILITY
            and binding.target_id == MAC_TARGET_ID
            and binding.capability == MAC_STATUS_CAPABILITY
            and binding.adapter_id == MAC_STATUS_ADAPTER_ID
            and binding.identity_ref == MAC_LOCAL_IDENTITY_REF
            and binding.trust_path_ref == MAC_INPROC_STATUS_TRUST_PATH_REF
        )
        if not exact:
            return PolicyDecision(
                verdict=PolicyVerdict.DENY,
                permission_level=PermissionLevel.A,
                scope=AuthorizationScope.ONE_SHOT,
                reason="Only mac/status over the in-process Gateway status provider is allowed",
            )
        return PolicyDecision(
            verdict=PolicyVerdict.ALLOW,
            permission_level=PermissionLevel.A,
            scope=AuthorizationScope.ONE_SHOT,
            authorization_ref="level-a:mac:status:gateway-inproc-status-v1",
            binding_digest=compute_binding_digest(binding, task.parameters),
        )


class GatewayInProcessMacStatusAdapter:
    """Read Gateway status directly in-process; never recurse through gateway.sock."""

    adapter_id = MAC_STATUS_ADAPTER_ID

    def __init__(self, status_provider: StatusProvider) -> None:
        self._status_provider = status_provider

    def execute(self, request) -> AdapterResult:
        binding = request.binding
        if (
            binding.target_id != MAC_TARGET_ID
            or binding.capability != MAC_STATUS_CAPABILITY
            or binding.adapter_id != self.adapter_id
            or binding.identity_ref != MAC_LOCAL_IDENTITY_REF
            or binding.trust_path_ref != MAC_INPROC_STATUS_TRUST_PATH_REF
        ):
            raise PermissionError("Gateway status adapter received an out-of-scope binding")

        try:
            payload = self._status_provider()
        except Exception as exc:
            return AdapterResult(
                status=AdapterStatus.FAILURE,
                dispatch_started=True,
                outcome_known=True,
                summary=f"Gateway in-process status provider failed: {type(exc).__name__}",
                health_observation=HealthObservation(
                    HealthState.INDETERMINATE,
                    finding="Gateway in-process status provider raised",
                ),
            )

        if not isinstance(payload, dict):
            return AdapterResult(
                status=AdapterStatus.FAILURE,
                dispatch_started=True,
                outcome_known=True,
                summary="Gateway in-process status provider returned no factual payload",
                health_observation=HealthObservation(
                    HealthState.INDETERMINATE,
                    finding="Gateway in-process status unavailable",
                ),
            )

        state = str(payload.get("gateway_state") or "unknown")
        pid = payload.get("answering_pid") or payload.get("pid") or "unknown"
        code_sha = str(payload.get("code_sha") or "unknown")
        evidence = EvidenceRef(
            kind="gateway_inproc_status",
            reference=f"state={state};pid={pid};code_sha={code_sha}",
        )
        if state == "running":
            health = HealthObservation(HealthState.HEALTHY, (evidence,))
        else:
            health = HealthObservation(
                HealthState.DEGRADED,
                (evidence,),
                f"Gateway reported state={state}",
            )
        return AdapterResult(
            status=AdapterStatus.SUCCESS,
            dispatch_started=True,
            outcome_known=True,
            summary=f"Gateway status: state={state}, pid={pid}, code_sha={code_sha}",
            evidence=(evidence,),
            health_observation=health,
        )


def gateway_mac_status_registry() -> DeterministicTargetRegistry:
    return DeterministicTargetRegistry([
        TargetDefinition(
            target_id=MAC_TARGET_ID,
            adapter_id=MAC_STATUS_ADAPTER_ID,
            supported_capabilities=frozenset({MAC_STATUS_CAPABILITY}),
            allowed_identity_refs=frozenset({MAC_LOCAL_IDENTITY_REF}),
            allowed_trust_path_refs=frozenset({MAC_INPROC_STATUS_TRUST_PATH_REF}),
        )
    ])


class CoreGatewayRuntime:
    """Single-process serialized Core owner attached to one Gateway lifetime."""

    def __init__(
        self,
        *,
        connection: sqlite3.Connection,
        dispatcher: CoreDispatcher,
        database_path: Path,
        recovery_decisions: tuple[RecoveryDecision, ...],
    ) -> None:
        self._connection = connection
        self._dispatcher = dispatcher
        self.database_path = Path(database_path)
        self.recovery_decisions = recovery_decisions
        self._lock = threading.Lock()
        self._closed = False

    @classmethod
    def bootstrap(cls, *, home: Path, status_provider: StatusProvider) -> "CoreGatewayRuntime":
        connection = open_core_database(Path(home))
        try:
            adapter = GatewayInProcessMacStatusAdapter(status_provider)
            dispatcher = CoreDispatcher(
                registry=gateway_mac_status_registry(),
                policy=GatewayMacStatusLevelAPolicy(),
                adapters={adapter.adapter_id: adapter},
                store=CoreStateStore(connection),
            )
            recovery = dispatcher.recover()
            return cls(
                connection=connection,
                dispatcher=dispatcher,
                database_path=core_database_path(Path(home)),
                recovery_decisions=recovery,
            )
        except BaseException:
            connection.close()
            raise

    def control_status(self) -> dict:
        """Execute one fresh Level-A mac/status task for the local control verb."""
        with self._lock:
            if self._closed:
                raise RuntimeError("Core Gateway runtime is closed")
            request_id = "core-status-" + uuid.uuid4().hex
            task = Task(
                request_id=request_id,
                intent="status",
                requested_target=MAC_TARGET_ID,
                requested_capability=MAC_STATUS_CAPABILITY,
                parameters={},
                provenance_ref="gateway-control:core-status-v1",
            )
            try:
                result = self._dispatcher.dispatch(
                    task,
                    identity_ref=MAC_LOCAL_IDENTITY_REF,
                    trust_path_ref=MAC_INPROC_STATUS_TRUST_PATH_REF,
                )
            except ReconciliationRequired:
                return {
                    "core_ready": False,
                    "request_id": request_id,
                    "blocked": "RECONCILE_BEFORE_NEW_ACTION",
                    "database": str(self.database_path),
                }

            health = result.health_observation
            return {
                "core_ready": True,
                "request_id": result.request_id,
                "execution_id": result.execution_id,
                "outcome": result.outcome.value,
                "health": None if health is None else health.state.value,
                "summary": result.receipt.summary,
                "evidence": [
                    {"kind": item.kind, "reference": item.reference}
                    for item in result.evidence
                ],
                "target": MAC_TARGET_ID,
                "capability": MAC_STATUS_CAPABILITY,
                "permission_level": PermissionLevel.A.value,
                "adapter_id": MAC_STATUS_ADAPTER_ID,
                "identity_ref": MAC_LOCAL_IDENTITY_REF,
                "trust_path_ref": MAC_INPROC_STATUS_TRUST_PATH_REF,
            }

    def close(self) -> None:
        """Idempotently close the caller-owned SQLite connection."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._connection.close()
