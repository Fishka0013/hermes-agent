"""Isolated Core V1 dispatcher with durable Package B attempt state."""

from __future__ import annotations

import time
import uuid
from dataclasses import replace
from typing import Mapping, Protocol

from agent.core.contracts import (
    AdapterResult,
    AdapterStatus,
    CoreExecutionResult,
    CoreOutcome,
    ExecutionRequest,
    HealthObservation,
    PolicyVerdict,
    Receipt,
    Task,
    compute_binding_digest,
)
from agent.core.health import map_status_health
from agent.core.policy import Policy
from agent.core.registry import DeterministicTargetRegistry
from agent.core.storage import CoreStateStore, DuplicateRequestError, RecoveryDecision


class AuthorizationBindingMismatch(PermissionError):
    pass


class AdapterUnavailable(LookupError):
    pass


class ReconciliationRequired(RuntimeError):
    def __init__(self, decisions: tuple[RecoveryDecision, ...]) -> None:
        self.decisions = decisions
        super().__init__("RECONCILE_BEFORE_NEW_ACTION: unresolved execution outcome")


class Adapter(Protocol):
    adapter_id: str

    def execute(self, request: ExecutionRequest) -> AdapterResult:
        ...


class CoreDispatcher:
    """Serialized dispatch over a caller-owned store; recover at quiescent startup."""

    def __init__(
        self,
        *,
        registry: DeterministicTargetRegistry,
        policy: Policy,
        adapters: Mapping[str, Adapter],
        store: CoreStateStore,
    ) -> None:
        self._registry = registry
        self._policy = policy
        self._adapters = dict(adapters)
        self._store = store
        self._recovery_complete = False

    def recover(self) -> tuple[RecoveryDecision, ...]:
        """Run once before dispatch; classify old attempts without executing them."""
        if self._recovery_complete:
            raise RuntimeError("startup recovery is already complete")
        decisions = self._store.recover_incomplete(recovered_at=time.time())
        self._recovery_complete = True
        return decisions

    def _check_reconciliation(self) -> None:
        decisions = self._store.get_unresolved_attempts()
        if decisions:
            raise ReconciliationRequired(decisions)

    @staticmethod
    def _receipt(
        *,
        task: Task,
        execution_id: str,
        outcome: CoreOutcome,
        digest: str,
        adapter_result: AdapterResult | None,
    ) -> Receipt:
        evidence = () if adapter_result is None else adapter_result.evidence
        summary = "" if adapter_result is None else adapter_result.summary
        return Receipt(
            request_id=task.request_id,
            execution_id=execution_id,
            outcome=outcome,
            binding_digest=digest,
            evidence_refs=evidence,
            summary=summary,
        )

    def _result(
        self,
        *,
        task: Task,
        execution_id: str,
        outcome: CoreOutcome,
        digest: str,
        adapter_result: AdapterResult | None,
        health_observation: HealthObservation | None = None,
    ) -> CoreExecutionResult:
        evidence = () if adapter_result is None else adapter_result.evidence
        return CoreExecutionResult(
            request_id=task.request_id,
            execution_id=execution_id,
            outcome=outcome,
            adapter_result=adapter_result,
            evidence=evidence,
            health_observation=health_observation,
            receipt=self._receipt(
                task=task,
                execution_id=execution_id,
                outcome=outcome,
                digest=digest,
                adapter_result=adapter_result,
            ),
        )

    @staticmethod
    def _normalize_outcome(adapter_result: AdapterResult) -> CoreOutcome:
        if adapter_result.outcome_known is not True:
            return CoreOutcome.OUTCOME_UNKNOWN
        if adapter_result.status is AdapterStatus.TIMEOUT:
            if adapter_result.dispatch_started is False:
                return CoreOutcome.TIMEOUT_NO_DISPATCH
            return CoreOutcome.OUTCOME_UNKNOWN
        if adapter_result.status is AdapterStatus.SUCCESS:
            return CoreOutcome.SUCCESS
        return CoreOutcome.FAILED

    def dispatch(
        self,
        task: Task,
        *,
        identity_ref: str,
        trust_path_ref: str,
        resource_ref: str = "",
    ) -> CoreExecutionResult:
        if not self._recovery_complete:
            raise RuntimeError("quiescent startup recovery is required before dispatch")
        self._check_reconciliation()
        if self._store.get_attempt(task.request_id) is not None:
            return self._result(
                task=task,
                execution_id="",
                outcome=CoreOutcome.DUPLICATE_REQUEST,
                digest="",
                adapter_result=None,
            )

        binding = self._registry.resolve(
            task,
            identity_ref=identity_ref,
            trust_path_ref=trust_path_ref,
            resource_ref=resource_ref,
        )
        expected_digest = compute_binding_digest(binding, task.parameters)
        decision = self._policy.authorize(task, binding)
        if decision.verdict is PolicyVerdict.DENY:
            return self._result(
                task=task,
                execution_id="",
                outcome=CoreOutcome.DENIED,
                digest=expected_digest,
                adapter_result=None,
            )
        if decision.binding_digest != expected_digest:
            raise AuthorizationBindingMismatch("Policy decision does not match resolved execution binding")

        execution_id = uuid.uuid4().hex
        request = ExecutionRequest(
            execution_id=execution_id,
            request_id=task.request_id,
            binding=binding,
            parameters=task.parameters,
            authorization_ref=decision.authorization_ref,
            binding_digest=expected_digest,
        )
        adapter = self._adapters.get(binding.adapter_id)
        if adapter is None or adapter.adapter_id != binding.adapter_id:
            raise AdapterUnavailable(binding.adapter_id)

        try:
            self._store.persist_prepared(task=task, request=request, created_at=time.time())
        except DuplicateRequestError:
            self._check_reconciliation()
            return self._result(
                task=task,
                execution_id="",
                outcome=CoreOutcome.DUPLICATE_REQUEST,
                digest="",
                adapter_result=None,
            )
        self._store.mark_dispatch_started(execution_id=execution_id, started_at=time.time())
        try:
            adapter_result = adapter.execute(request)
        except Exception:
            # The adapter exception contract cannot prove whether the action started.
            adapter_result = None
            outcome = CoreOutcome.OUTCOME_UNKNOWN
        else:
            outcome = self._normalize_outcome(adapter_result)
        health_observation = None
        if binding.capability == "status":
            health_observation = map_status_health(adapter_result, outcome=outcome)
            if adapter_result is not None and adapter_result.health_observation is not None:
                # Returned adapter observations must not contradict Core's validated output.
                adapter_result = replace(adapter_result, health_observation=health_observation)
        result = self._result(
            task=task,
            execution_id=execution_id,
            outcome=outcome,
            digest=expected_digest,
            adapter_result=adapter_result,
            health_observation=health_observation,
        )
        self._store.complete(result=result, completed_at=time.time())
        return result
