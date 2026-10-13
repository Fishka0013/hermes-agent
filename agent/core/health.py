"""Core mapping for one status result, without cached health or background work."""

from __future__ import annotations

from agent.core.contracts import (
    AdapterResult,
    AdapterStatus,
    CoreOutcome,
    HealthObservation,
    HealthState,
)


def map_status_health(
    adapter_result: AdapterResult | None,
    *,
    outcome: CoreOutcome,
) -> HealthObservation:
    """Require an explicit observation backed by this execution's evidence.

    The minimal contract treats at least one nonblank, linked evidence reference
    as support for an explicit HEALTHY observation. Execution/receipt evidence
    alone never implies target health, and findings prevent HEALTHY.
    """
    if (
        outcome is not CoreOutcome.SUCCESS
        or adapter_result is None
        or adapter_result.status is not AdapterStatus.SUCCESS
        or adapter_result.dispatch_started is not True
        or adapter_result.outcome_known is not True
    ):
        return HealthObservation(
            HealthState.INDETERMINATE,
            finding="Status execution did not establish target health",
        )

    observation = adapter_result.health_observation
    if not isinstance(observation, HealthObservation):
        return HealthObservation(
            HealthState.INDETERMINATE,
            finding="No valid structured health observation was provided",
        )

    refs = observation.evidence_refs
    if any(
        not ref.kind.strip()
        or not ref.reference.strip()
        or ref not in adapter_result.evidence
        for ref in refs
    ):
        return HealthObservation(
            HealthState.INDETERMINATE,
            finding="Health evidence is blank or absent from execution evidence",
        )

    if observation.state is HealthState.HEALTHY:
        if not refs:
            return HealthObservation(
                HealthState.INDETERMINATE,
                finding="HEALTHY requires explicit health evidence",
            )
        if observation.finding:
            return HealthObservation(HealthState.DEGRADED, refs, observation.finding)

    if observation.state is HealthState.DEGRADED and not (refs or observation.finding):
        return HealthObservation(
            HealthState.INDETERMINATE,
            finding="DEGRADED requires a finding or health evidence",
        )
    return observation
