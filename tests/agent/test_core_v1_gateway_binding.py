from __future__ import annotations

import json
import sqlite3

import pytest

from agent.core.contracts import ExecutionRequest, PermissionLevel, PolicyVerdict, Task, compute_binding_digest
from agent.core.gateway_runtime import (
    CORE_DB_FILENAME,
    CORE_STATUS_CONTROL_VERB,
    MAC_INPROC_STATUS_TRUST_PATH_REF,
    MAC_LOCAL_IDENTITY_REF,
    MAC_STATUS_ADAPTER_ID,
    MAC_STATUS_CAPABILITY,
    MAC_TARGET_ID,
    CoreGatewayRuntime,
    GatewayMacStatusLevelAPolicy,
    core_database_path,
    gateway_mac_status_registry,
    open_core_database,
)
from agent.core.registry import TrustPathNotAllowed, UnsupportedCapability
from agent.core.storage import CoreStateStore, CORE_STATE_SCHEMA_VERSION


def _payload(state="running"):
    return {
        "gateway_state": state,
        "answering_pid": 4321,
        "code_sha": "candidate-sha",
        "session_store": {"status": "ok"},
    }


def _prepared_request(connection, *, request_id="old-request", execution_id="old-execution", started=False):
    task = Task(request_id, "status", MAC_TARGET_ID, MAC_STATUS_CAPABILITY, {})
    binding = gateway_mac_status_registry().resolve(
        task,
        identity_ref=MAC_LOCAL_IDENTITY_REF,
        trust_path_ref=MAC_INPROC_STATUS_TRUST_PATH_REF,
    )
    decision = GatewayMacStatusLevelAPolicy().authorize(task, binding)
    request = ExecutionRequest(
        execution_id=execution_id,
        request_id=request_id,
        binding=binding,
        parameters=task.parameters,
        authorization_ref=decision.authorization_ref,
        binding_digest=compute_binding_digest(binding, task.parameters),
    )
    store = CoreStateStore(connection)
    store.persist_prepared(task=task, request=request, created_at=1.0)
    if started:
        store.mark_dispatch_started(execution_id=execution_id, started_at=2.0)
    return task, request


def test_new_database_is_created_once_with_schema_v1(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    path = home / CORE_DB_FILENAME
    assert not path.exists()
    connection = open_core_database(home)
    try:
        assert path.is_file()
        assert connection.execute("PRAGMA user_version").fetchone() == (CORE_STATE_SCHEMA_VERSION,)
    finally:
        connection.close()


def test_existing_database_reopens_and_validates(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    first = open_core_database(home)
    first.close()
    second = open_core_database(home)
    try:
        assert second.execute("SELECT COUNT(*) FROM core_tasks").fetchone() == (0,)
    finally:
        second.close()


def test_incompatible_schema_fails_closed_without_repair(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    path = core_database_path(home)
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA user_version = 999")
    connection.execute("CREATE TABLE foreign_schema(x INTEGER)")
    connection.commit()
    connection.close()

    with pytest.raises(RuntimeError, match="incompatible Core schema version"):
        open_core_database(home)

    observer = sqlite3.connect(path)
    try:
        assert observer.execute("PRAGMA user_version").fetchone() == (999,)
        assert observer.execute("SELECT name FROM sqlite_master WHERE name='foreign_schema'").fetchone() == ("foreign_schema",)
    finally:
        observer.close()


def test_prepared_recovery_never_redispatches_old_attempt(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    connection = open_core_database(home)
    _prepared_request(connection, started=False)
    connection.close()

    calls = []
    runtime = CoreGatewayRuntime.bootstrap(home=home, status_provider=lambda: calls.append("new") or _payload())
    try:
        assert [(d.disposition, d.outcome) for d in runtime.recovery_decisions] == [("NOT_DISPATCHED", None)]
        result = runtime.control_status()
        assert result["core_ready"] is True
        assert calls == ["new"]
    finally:
        runtime.close()


def test_dispatched_recovery_becomes_unknown_and_blocks_new_action(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    connection = open_core_database(home)
    _prepared_request(connection, started=True)
    connection.close()

    calls = []
    runtime = CoreGatewayRuntime.bootstrap(home=home, status_provider=lambda: calls.append("unexpected") or _payload())
    try:
        assert runtime.recovery_decisions[0].disposition == "RECONCILE_BEFORE_NEW_ACTION"
        result = runtime.control_status()
        assert result["core_ready"] is False
        assert result["blocked"] == "RECONCILE_BEFORE_NEW_ACTION"
        assert calls == []
    finally:
        runtime.close()


def test_production_policy_is_only_level_a_mac_status():
    registry = gateway_mac_status_registry()
    task = Task("r1", "status", MAC_TARGET_ID, MAC_STATUS_CAPABILITY, {})
    binding = registry.resolve(
        task,
        identity_ref=MAC_LOCAL_IDENTITY_REF,
        trust_path_ref=MAC_INPROC_STATUS_TRUST_PATH_REF,
    )
    decision = GatewayMacStatusLevelAPolicy().authorize(task, binding)
    assert decision.verdict is PolicyVerdict.ALLOW
    assert decision.permission_level is PermissionLevel.A
    assert binding.adapter_id == MAC_STATUS_ADAPTER_ID

    with pytest.raises(UnsupportedCapability):
        registry.resolve(
            Task("r2", "restart", MAC_TARGET_ID, "restart", {}),
            identity_ref=MAC_LOCAL_IDENTITY_REF,
            trust_path_ref=MAC_INPROC_STATUS_TRUST_PATH_REF,
        )
    with pytest.raises(TrustPathNotAllowed):
        registry.resolve(
            task,
            identity_ref=MAC_LOCAL_IDENTITY_REF,
            trust_path_ref="gateway-control-socket-v1",
        )


def test_direct_provider_has_no_self_socket_recursion(tmp_path, monkeypatch):
    import gateway.control_socket as control_socket

    monkeypatch.setattr(
        control_socket,
        "query_gateway_control",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("self socket recursion")),
    )
    home = tmp_path / "home"
    home.mkdir()
    calls = []
    runtime = CoreGatewayRuntime.bootstrap(home=home, status_provider=lambda: calls.append("direct") or _payload())
    try:
        result = runtime.control_status()
        assert result["outcome"] == "SUCCESS"
        assert result["health"] == "HEALTHY"
        assert result["trust_path_ref"] == MAC_INPROC_STATUS_TRUST_PATH_REF
        assert result["evidence"][0]["kind"] == "gateway_inproc_status"
        assert calls == ["direct"]
    finally:
        runtime.close()


def test_existing_gateway_status_handler_is_not_replaced(monkeypatch):
    import gateway.control_socket as control_socket

    monkeypatch.setattr(control_socket, "build_status_payload", lambda: {"gateway_state": "legacy-status-sentinel"})
    server = control_socket.GatewayControlServer(
        verb_handlers={CORE_STATUS_CONTROL_VERB: lambda: {"core_ready": True}}
    )
    legacy = json.loads(server.handle_request_line(b'{"id":1,"verb":"status"}\n'))
    core = json.loads(server.handle_request_line(b'{"id":2,"verb":"core-status"}\n'))
    assert legacy["ok"] is True
    assert legacy["result"] == {"gateway_state": "legacy-status-sentinel"}
    assert core["result"] == {"core_ready": True}


def test_restart_reopen_recovery_and_close(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    runtime = CoreGatewayRuntime.bootstrap(home=home, status_provider=_payload)
    first = runtime.control_status()
    runtime.close()
    runtime.close()
    with pytest.raises(RuntimeError, match="closed"):
        runtime.control_status()

    restarted = CoreGatewayRuntime.bootstrap(home=home, status_provider=_payload)
    try:
        assert restarted.recovery_decisions == ()
        second = restarted.control_status()
        assert first["request_id"] != second["request_id"]
        observer = sqlite3.connect(core_database_path(home))
        try:
            assert observer.execute("SELECT COUNT(*) FROM core_execution_attempts").fetchone() == (2,)
        finally:
            observer.close()
    finally:
        restarted.close()


def test_gateway_core_bootstrap_failure_is_nonfatal(tmp_path, monkeypatch):
    import agent.core.gateway_runtime as core_runtime
    import gateway.run_bootstrap as gateway_bootstrap

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    def fail_bootstrap(*args, **kwargs):
        raise RuntimeError("injected core failure")

    monkeypatch.setattr(core_runtime.CoreGatewayRuntime, "bootstrap", fail_bootstrap)
    assert gateway_bootstrap._start_gateway_start_core_runtime() is None
