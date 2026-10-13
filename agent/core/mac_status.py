"""Minimal real-Mac Level-A status slice for isolated Core V1 validation.

This module binds only target=mac, capability=status to the existing local
Gateway control socket.  It does not activate Core in the production Gateway
and never opens Hermes' live state.db.
"""

from __future__ import annotations

import sqlite3
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
from agent.core.dispatcher import CoreDispatcher
from agent.core.registry import DeterministicTargetRegistry, TargetDefinition
from agent.core.storage import CoreStateStore
from gateway.control_socket import query_gateway_control

MAC_TARGET_ID = "mac"
MAC_STATUS_CAPABILITY = "status"
MAC_STATUS_ADAPTER_ID = "mac-status"
MAC_LOCAL_IDENTITY_REF = "mac-local-owner"
MAC_GATEWAY_TRUST_PATH_REF = "gateway-control-socket-v1"

StatusQuery = Callable[[Path, str], dict | None]


class MacStatusLevelAPolicy:
    """Allow exactly the read-only Mac status binding and deny everything else."""

    def authorize(self, task: Task, binding: TargetBinding) -> PolicyDecision:
        exact = (
            task.requested_target == MAC_TARGET_ID
            and task.requested_capability == MAC_STATUS_CAPABILITY
            and binding.target_id == MAC_TARGET_ID
            and binding.capability == MAC_STATUS_CAPABILITY
            and binding.adapter_id == MAC_STATUS_ADAPTER_ID
            and binding.identity_ref == MAC_LOCAL_IDENTITY_REF
            and binding.trust_path_ref == MAC_GATEWAY_TRUST_PATH_REF
        )
        if not exact:
            return PolicyDecision(
                verdict=PolicyVerdict.DENY,
                permission_level=PermissionLevel.A,
                scope=AuthorizationScope.ONE_SHOT,
                reason="Only mac/status over the local Gateway control socket is Level-A bound here",
            )
        return PolicyDecision(
            verdict=PolicyVerdict.ALLOW,
            permission_level=PermissionLevel.A,
            scope=AuthorizationScope.ONE_SHOT,
            authorization_ref="level-a:mac:status:gateway-control-socket-v1",
            binding_digest=compute_binding_digest(binding, task.parameters),
        )


class MacStatusAdapter:
    """Read current Hermes-on-Mac status through the existing local control socket."""

    adapter_id = MAC_STATUS_ADAPTER_ID

    def __init__(
        self,
        home: Path,
        *,
        query: Callable[..., dict | None] = query_gateway_control,
        timeout: float = 2.0,
    ) -> None:
        self._home = Path(home)
        self._query = query
        self._timeout = timeout

    def execute(self, request) -> AdapterResult:
        binding = request.binding
        if (
            binding.target_id != MAC_TARGET_ID
            or binding.capability != MAC_STATUS_CAPABILITY
            or binding.adapter_id != self.adapter_id
            or binding.identity_ref != MAC_LOCAL_IDENTITY_REF
            or binding.trust_path_ref != MAC_GATEWAY_TRUST_PATH_REF
        ):
            raise PermissionError("MacStatusAdapter received an out-of-scope execution binding")

        payload = self._query(self._home, "status", timeout=self._timeout)
        if not isinstance(payload, dict):
            return AdapterResult(
                status=AdapterStatus.FAILURE,
                dispatch_started=True,
                outcome_known=True,
                summary="Gateway status control read returned no factual payload",
                health_observation=HealthObservation(
                    HealthState.INDETERMINATE,
                    finding="Gateway status control read unavailable",
                ),
            )

        state = str(payload.get("gateway_state") or "unknown")
        pid = payload.get("answering_pid") or payload.get("pid") or "unknown"
        code_sha = str(payload.get("code_sha") or "unknown")
        evidence = EvidenceRef(
            kind="gateway_control_status",
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


def mac_status_registry() -> DeterministicTargetRegistry:
    """Return the one-target registry for the first real Mac/status slice."""
    return DeterministicTargetRegistry([
        TargetDefinition(
            target_id=MAC_TARGET_ID,
            adapter_id=MAC_STATUS_ADAPTER_ID,
            supported_capabilities=frozenset({MAC_STATUS_CAPABILITY}),
            allowed_identity_refs=frozenset({MAC_LOCAL_IDENTITY_REF}),
            allowed_trust_path_refs=frozenset({MAC_GATEWAY_TRUST_PATH_REF}),
        )
    ])


def build_mac_status_dispatcher(
    connection: sqlite3.Connection,
    *,
    home: Path,
    query: Callable[..., dict | None] = query_gateway_control,
) -> CoreDispatcher:
    """Compose the isolated Core path; caller owns DB/schema and lifecycle."""
    adapter = MacStatusAdapter(home, query=query)
    return CoreDispatcher(
        registry=mac_status_registry(),
        policy=MacStatusLevelAPolicy(),
        adapters={adapter.adapter_id: adapter},
        store=CoreStateStore(connection),
    )


def run_mac_status(
    connection: sqlite3.Connection,
    *,
    home: Path,
    request_id: str,
    query: Callable[..., dict | None] = query_gateway_control,
):
    """Local/manual composition entrypoint for an already-initialized isolated DB."""
    dispatcher = build_mac_status_dispatcher(connection, home=home, query=query)
    dispatcher.recover()
    task = Task(
        request_id=request_id,
        intent="status",
        requested_target=MAC_TARGET_ID,
        requested_capability=MAC_STATUS_CAPABILITY,
        parameters={},
        provenance_ref="local-manual",
    )
    return dispatcher.dispatch(
        task,
        identity_ref=MAC_LOCAL_IDENTITY_REF,
        trust_path_ref=MAC_GATEWAY_TRUST_PATH_REF,
    )
