"""Package B isolated durable-execution persistence.

This module owns only Core persistence semantics. It never locates or opens
Hermes state.db; callers must supply an explicit SQLite connection.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from agent.core.contracts import (
    AdapterStatus,
    CoreExecutionResult,
    CoreOutcome,
    ExecutionRequest,
    Task,
    compute_binding_digest,
    thaw_json,
)


CORE_STATE_SCHEMA_VERSION = 1


CORE_STATE_SCHEMA_SQL = """
CREATE TABLE core_tasks (
    request_id TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    task_json TEXT NOT NULL
);
CREATE TABLE core_execution_attempts (
    execution_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE
        REFERENCES core_tasks(request_id) ON DELETE CASCADE,
    authorization_ref TEXT NOT NULL,
    execution_request_json TEXT NOT NULL,
    binding_digest TEXT NOT NULL,
    state TEXT NOT NULL
        CHECK (state IN ('PREPARED', 'DISPATCH_STARTED', 'COMPLETED')),
    dispatch_started_at REAL,
    outcome TEXT
        CHECK (
            outcome IS NULL OR outcome IN (
                'SUCCESS',
                'FAILED',
                'DENIED',
                'TIMEOUT_NO_DISPATCH',
                'OUTCOME_UNKNOWN',
                'DUPLICATE_REQUEST'
            )
        ),
    result_json TEXT,
    evidence_refs_json TEXT,
    receipt_json TEXT,
    created_at REAL NOT NULL,
    completed_at REAL
);

CREATE INDEX idx_core_execution_attempts_state
    ON core_execution_attempts(state);
"""


def create_core_state_schema(connection: sqlite3.Connection) -> None:
    """Create Package-B tables and stamp the exact Core schema version."""
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(CORE_STATE_SCHEMA_SQL)
    connection.execute(f"PRAGMA user_version = {CORE_STATE_SCHEMA_VERSION}")
    connection.commit()


def _core_schema_objects(connection: sqlite3.Connection) -> tuple[tuple[str, str, str, str], ...]:
    rows = connection.execute(
        """
        SELECT type, name, tbl_name, COALESCE(sql, '')
        FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%'
        ORDER BY type, name
        """
    ).fetchall()
    return tuple((str(t), str(n), str(tbl), str(sql)) for t, n, tbl, sql in rows)


def validate_core_state_schema(connection: sqlite3.Connection) -> None:
    """Fail closed unless an existing dedicated Core DB matches schema v1 exactly."""
    row = connection.execute("PRAGMA user_version").fetchone()
    version = int(row[0]) if row else -1
    if version != CORE_STATE_SCHEMA_VERSION:
        raise RuntimeError(
            f"incompatible Core schema version: {version}; expected {CORE_STATE_SCHEMA_VERSION}"
        )

    expected = sqlite3.connect(":memory:")
    try:
        create_core_state_schema(expected)
        expected_objects = _core_schema_objects(expected)
    finally:
        expected.close()

    actual_objects = _core_schema_objects(connection)
    if actual_objects != expected_objects:
        raise RuntimeError("Core schema objects do not match the accepted v1 schema")
    connection.execute("PRAGMA foreign_keys = ON")


class InvalidCoreStateTransition(RuntimeError):
    pass


class DuplicateRequestError(RuntimeError):
    def __init__(
        self,
        request_id: str,
        execution_id: str,
        state: str,
        outcome: str | None,
    ) -> None:
        self.request_id = request_id
        self.execution_id = execution_id
        self.state = state
        self.outcome = outcome
        super().__init__(
            f"request {request_id!r} already has execution {execution_id!r} "
            f"in state {state!r}"
        )


@dataclass(frozen=True, slots=True)
class RecoveryDecision:
    request_id: str
    execution_id: str
    disposition: str
    outcome: CoreOutcome | None


def _canonical_json(value) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _task_payload(task: Task) -> dict:
    return {
        "request_id": task.request_id,
        "intent": task.intent,
        "requested_target": task.requested_target,
        "requested_capability": task.requested_capability,
        "parameters": thaw_json(task.parameters),
        "provenance_ref": task.provenance_ref,
    }


def _execution_request_payload(request: ExecutionRequest) -> dict:
    return {
        "execution_id": request.execution_id,
        "request_id": request.request_id,
        "binding": {
            "target_id": request.binding.target_id,
            "capability": request.binding.capability,
            "adapter_id": request.binding.adapter_id,
            "identity_ref": request.binding.identity_ref,
            "trust_path_ref": request.binding.trust_path_ref,
            "resource_ref": request.binding.resource_ref,
        },
        "parameters": thaw_json(request.parameters),
        "authorization_ref": request.authorization_ref,
        "binding_digest": request.binding_digest,
    }


def _result_payload(result: CoreExecutionResult) -> dict:
    adapter = result.adapter_result
    payload = {
        "request_id": result.request_id,
        "execution_id": result.execution_id,
        "outcome": result.outcome.value,
        "adapter_result": None if adapter is None else {
            "status": adapter.status.value,
            "dispatch_started": adapter.dispatch_started,
            "outcome_known": adapter.outcome_known,
            "summary": adapter.summary,
        },
    }
    health = result.health_observation
    if health is not None:
        payload["health_observation"] = {
            "state": health.state.value,
            "evidence_refs": [
                {"kind": ref.kind, "reference": ref.reference}
                for ref in health.evidence_refs
            ],
            "finding": health.finding,
        }
    return payload


def _evidence_payload(result: CoreExecutionResult) -> list[dict]:
    return [
        {"kind": item.kind, "reference": item.reference}
        for item in result.evidence
    ]


def _receipt_payload(result: CoreExecutionResult) -> dict:
    receipt = result.receipt
    return {
        "request_id": receipt.request_id,
        "execution_id": receipt.execution_id,
        "outcome": receipt.outcome.value,
        "binding_digest": receipt.binding_digest,
        "evidence_refs": [
            {"kind": item.kind, "reference": item.reference}
            for item in receipt.evidence_refs
        ],
        "summary": receipt.summary,
    }


class CoreStateStore:
    """Durable Core state over an explicitly supplied SQLite connection."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def get_attempt(
        self,
        request_id: str,
    ) -> tuple[str, str, str | None] | None:
        return self._connection.execute(
            """
            SELECT execution_id, state, outcome
            FROM core_execution_attempts
            WHERE request_id = ?
            """,
            (request_id,),
        ).fetchone()

    def get_unresolved_attempts(self) -> tuple[RecoveryDecision, ...]:
        """Read durable uncertainty, including a dispatch whose completion failed.

        COMPLETED/OUTCOME_UNKNOWN remains a gate on every later restart; this
        query never clears it or runs reconciliation. Dispatch is serialized.
        """
        rows = self._connection.execute(
            """
            SELECT request_id, execution_id
            FROM core_execution_attempts
            WHERE outcome = 'OUTCOME_UNKNOWN' OR state = 'DISPATCH_STARTED'
            ORDER BY created_at, execution_id
            """
        ).fetchall()
        return tuple(
            RecoveryDecision(request_id, execution_id, "RECONCILE_BEFORE_NEW_ACTION", CoreOutcome.OUTCOME_UNKNOWN)
            for request_id, execution_id in rows
        )

    @staticmethod
    def _raise_duplicate(
        request_id: str,
        row: tuple[str, str, str | None],
    ) -> None:
        raise DuplicateRequestError(request_id, row[0], row[1], row[2])

    def persist_prepared(
        self,
        *,
        task: Task,
        request: ExecutionRequest,
        created_at: float,
    ) -> None:
        """Atomically persist Task + exact authorized request as PREPARED."""
        if request.request_id != task.request_id:
            raise ValueError("Task and ExecutionRequest request_id must match")
        if not request.authorization_ref:
            raise ValueError("ExecutionRequest requires authorization_ref")
        expected_digest = compute_binding_digest(request.binding, request.parameters)
        if request.binding_digest != expected_digest:
            raise ValueError("ExecutionRequest binding_digest does not match its binding")

        existing = self.get_attempt(task.request_id)
        if existing is not None:
            self._raise_duplicate(task.request_id, existing)

        task_json = _canonical_json(_task_payload(task))
        request_json = _canonical_json(_execution_request_payload(request))
        try:
            with self._connection:
                self._connection.execute(
                    """
                    INSERT INTO core_tasks(request_id, created_at, task_json)
                    VALUES (?, ?, ?)
                    """,
                    (task.request_id, created_at, task_json),
                )
                self._connection.execute(
                    """
                    INSERT INTO core_execution_attempts(
                        execution_id,
                        request_id,
                        authorization_ref,
                        execution_request_json,
                        binding_digest,
                        state,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, 'PREPARED', ?)
                    """,
                    (
                        request.execution_id,
                        request.request_id,
                        request.authorization_ref,
                        request_json,
                        request.binding_digest,
                        created_at,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            existing = self.get_attempt(task.request_id)
            if existing is not None:
                raise DuplicateRequestError(
                    task.request_id, existing[0], existing[1], existing[2]
                ) from exc
            raise

    def mark_dispatch_started(
        self,
        *,
        execution_id: str,
        started_at: float,
    ) -> None:
        """Commit the 'real action may now start' marker before adapter dispatch."""
        with self._connection:
            cursor = self._connection.execute(
                """
                UPDATE core_execution_attempts
                SET state = 'DISPATCH_STARTED', dispatch_started_at = ?
                WHERE execution_id = ?
                  AND state = 'PREPARED'
                  AND dispatch_started_at IS NULL
                  AND outcome IS NULL
                """,
                (started_at, execution_id),
            )
        if cursor.rowcount == 1:
            return
        row = self._connection.execute(
            "SELECT state FROM core_execution_attempts WHERE execution_id = ?",
            (execution_id,),
        ).fetchone()
        if row is None:
            raise KeyError(execution_id)
        raise InvalidCoreStateTransition(
            f"cannot mark dispatch from state {row[0]!r}"
        )

    def complete(
        self,
        *,
        result: CoreExecutionResult,
        completed_at: float,
    ) -> None:
        """Persist a terminal Core result with state-transition checks."""
        row = self._connection.execute(
            """
            SELECT request_id, state
            FROM core_execution_attempts
            WHERE execution_id = ?
            """,
            (result.execution_id,),
        ).fetchone()
        if row is None:
            raise KeyError(result.execution_id)
        if row[0] != result.request_id:
            raise ValueError("Stored request_id does not match result")
        state = row[1]
        if result.outcome is CoreOutcome.TIMEOUT_NO_DISPATCH:
            adapter = result.adapter_result
            if (
                adapter is None
                or adapter.status is not AdapterStatus.TIMEOUT
                or adapter.dispatch_started is not False
                or adapter.outcome_known is not True
            ):
                raise InvalidCoreStateTransition("TIMEOUT_NO_DISPATCH requires confirmed no dispatch")
        pre_dispatch = {
            CoreOutcome.DENIED,
            CoreOutcome.TIMEOUT_NO_DISPATCH,
        }
        post_dispatch = {
            CoreOutcome.SUCCESS,
            CoreOutcome.FAILED,
            CoreOutcome.OUTCOME_UNKNOWN,
            CoreOutcome.TIMEOUT_NO_DISPATCH,
        }
        if state == "PREPARED" and result.outcome not in pre_dispatch:
            raise InvalidCoreStateTransition(
                f"{result.outcome.value} requires DISPATCH_STARTED"
            )
        if state == "DISPATCH_STARTED" and result.outcome not in post_dispatch:
            raise InvalidCoreStateTransition(
                f"{result.outcome.value} is incompatible with DISPATCH_STARTED"
            )
        if state == "COMPLETED":
            raise InvalidCoreStateTransition("attempt is already completed")

        with self._connection:
            cursor = self._connection.execute(
                """
                UPDATE core_execution_attempts
                SET state = 'COMPLETED',
                    outcome = ?,
                    result_json = ?,
                    evidence_refs_json = ?,
                    receipt_json = ?,
                    completed_at = ?
                WHERE execution_id = ? AND request_id = ? AND state = ?
                  AND outcome IS NULL
                """,
                (
                    result.outcome.value,
                    _canonical_json(_result_payload(result)),
                    _canonical_json(_evidence_payload(result)),
                    _canonical_json(_receipt_payload(result)),
                    completed_at,
                    result.execution_id,
                    result.request_id,
                    state,
                ),
            )
            if cursor.rowcount != 1:
                raise InvalidCoreStateTransition("completion did not update exactly one expected attempt")

    def recover_incomplete(
        self,
        *,
        recovered_at: float,
    ) -> tuple[RecoveryDecision, ...]:
        """Classify incomplete attempts after restart; never redispatch here."""
        rows = self._connection.execute(
            """
            SELECT request_id, execution_id, state
            FROM core_execution_attempts
            WHERE state IN ('PREPARED', 'DISPATCH_STARTED')
            ORDER BY created_at, execution_id
            """
        ).fetchall()
        decisions: list[RecoveryDecision] = []
        for request_id, execution_id, state in rows:
            if state == "PREPARED":
                decisions.append(
                    RecoveryDecision(
                        request_id=request_id,
                        execution_id=execution_id,
                        disposition="NOT_DISPATCHED",
                        outcome=None,
                    )
                )
                continue

            with self._connection:
                self._connection.execute(
                    """
                    UPDATE core_execution_attempts
                    SET state = 'COMPLETED',
                        outcome = 'OUTCOME_UNKNOWN',
                        result_json = ?,
                        completed_at = ?
                    WHERE execution_id = ?
                      AND state = 'DISPATCH_STARTED'
                      AND outcome IS NULL
                    """,
                    (
                        _canonical_json({
                            "recovered_after_restart": True,
                            "outcome": CoreOutcome.OUTCOME_UNKNOWN.value,
                        }),
                        recovered_at,
                        execution_id,
                    ),
                )
            decisions.append(
                RecoveryDecision(
                    request_id=request_id,
                    execution_id=execution_id,
                    disposition="RECONCILE_BEFORE_NEW_ACTION",
                    outcome=CoreOutcome.OUTCOME_UNKNOWN,
                )
            )
        return tuple(decisions)
