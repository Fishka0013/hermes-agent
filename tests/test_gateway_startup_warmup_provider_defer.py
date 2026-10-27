import json
import socket
from types import SimpleNamespace


def _forbidden(counters, key):
    def blocked(*args, **kwargs):
        counters[key] += 1
        raise AssertionError(f"forbidden startup path entered: {key}")
    return blocked


def _install_startup_fences(monkeypatch, counters):
    import agent.model_metadata as model_metadata
    import gateway.run as gateway_run
    import hermes_cli.auth as auth
    import hermes_cli.auth_codex as auth_codex
    import hermes_cli.runtime_provider as runtime_provider
    import model_tools

    monkeypatch.setattr(model_tools, "_resolve_active_context_length", _forbidden(counters, "tool_search_ctx"))
    monkeypatch.setattr(gateway_run, "_resolve_gateway_model_context", _forbidden(counters, "resolve_gateway_model_context"))
    monkeypatch.setattr(model_metadata, "get_model_context_length", _forbidden(counters, "model_context"))
    monkeypatch.setattr(auth, "read_credential_pool", _forbidden(counters, "pool_load"))
    monkeypatch.setattr(auth_codex, "resolve_codex_runtime_credentials", _forbidden(counters, "oauth_rung"))
    monkeypatch.setattr(runtime_provider, "resolve_runtime_provider", _forbidden(counters, "oauth_rung"))
    monkeypatch.setattr(runtime_provider, "resolve_runtime_with_fallback", _forbidden(counters, "oauth_rung"))
    for name in ("refresh_codex_oauth_pure", "_refresh_codex_auth_tokens"):
        if hasattr(auth_codex, name):
            monkeypatch.setattr(auth_codex, name, _forbidden(counters, "oauth_refresh"))
    for module, names in (
        (auth_codex, ("_read_codex_tokens", "_pool_codex_credential")),
        (auth, ("_load_auth_store", "_load_global_auth_store")),
    ):
        for name in names:
            if hasattr(module, name):
                monkeypatch.setattr(module, name, _forbidden(counters, "credential_read_export"))
    for module, names in (
        (auth_codex, ("_save_codex_tokens",)),
        (auth, ("_save_auth_store", "_save_private_json", "write_credential_pool",
                "_save_provider_state", "_persist_provider_state_to_store", "_save_provider_state_to_source")),
    ):
        for name in names:
            if hasattr(module, name):
                monkeypatch.setattr(module, name, _forbidden(counters, "credential_auth_write"))
    for name in ("_auth_store_lock", "_file_lock"):
        if hasattr(auth, name):
            monkeypatch.setattr(auth, name, _forbidden(counters, "auth_lock"))

    original_connect = socket.socket.connect
    original_getaddrinfo = socket.getaddrinfo
    def guarded_connect(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            counters["provider_network"] += 1
            raise AssertionError("forbidden provider/network connect during startup")
        return original_connect(sock, address)
    def guarded_getaddrinfo(host, port, *args, **kwargs):
        host_s = str(host)
        if host_s not in ("localhost", "127.0.0.1", "::1") and not host_s.endswith(".local"):
            counters["provider_network"] += 1
            raise AssertionError("forbidden provider/network DNS during startup")
        return original_getaddrinfo(host, port, *args, **kwargs)
    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)


def _zero_tool_warmup(monkeypatch):
    import gateway.run as gateway_run
    import hermes_cli.config as config
    import model_tools
    import tools.env_probe as env_probe

    counters = {key: 0 for key in (
        "tool_search_ctx", "resolve_gateway_model_context", "model_context", "pool_load",
        "oauth_rung", "provider_network", "oauth_refresh", "credential_read_export",
        "credential_auth_write", "auth_lock",
    )}
    _install_startup_fences(monkeypatch, counters)
    model_tools._clear_tool_defs_cache()
    monkeypatch.setattr(model_tools, "_select_tool_names", lambda *args, **kwargs: set())
    monkeypatch.setattr(config, "load_config_readonly", lambda: {"agent": {"environment_probe": True}})
    monkeypatch.setattr(env_probe, "get_environment_probe_line", lambda: "")
    assert gateway_run._warm_turn_machinery_sync() == 0
    assert counters == {key: 0 for key in counters}
    return counters


def test_zero_tool_actual_gateway_warmup_defers_provider_resolution(monkeypatch):
    counters = _zero_tool_warmup(monkeypatch)
    print("R2_COUNTERS=" + json.dumps(counters, sort_keys=True))


def test_first_real_turn_retains_provider_and_model_resolution(monkeypatch):
    import gateway.run as gateway_run
    real_context_resolver = gateway_run._resolve_gateway_model_context
    assert all(value == 0 for value in _zero_tool_warmup(monkeypatch).values())
    # R2 deliberately fences this symbol; restore the unchanged product resolver for the R3 positive proof.
    monkeypatch.setattr(gateway_run, "_resolve_gateway_model_context", real_context_resolver)

    import agent.model_metadata as model_metadata
    from gateway.run_turn import GatewayTurnMixin
    import hermes_cli.runtime_provider as runtime_provider

    evidence = {"gateway_model": 0, "runtime_provider": 0, "model_context": 0, "provider_network": 0}
    def fake_gateway_model(user_config=None):
        evidence["gateway_model"] += 1
        return "d145-sentinel-model"
    def fake_model_cfg():
        return {"default": "d145-sentinel-model", "provider": "d145-sentinel-provider"}
    def fake_runtime_with_fallback(config):
        evidence["runtime_provider"] += 1
        return ({
            "provider": "d145-sentinel-provider", "requested_provider": "d145-sentinel-provider",
            "api_key": None, "base_url": "https://d145.invalid/v1", "api_mode": "chat_completions",
            "command": None, "args": [], "credential_pool": None, "request_overrides": {}, "capabilities": {},
        }, None)
    def fake_context_length(model, **kwargs):
        evidence["model_context"] += 1
        assert model == "d145-sentinel-model"
        assert kwargs.get("provider") == "d145-sentinel-provider"
        return 131072

    monkeypatch.setattr(gateway_run, "_resolve_gateway_model", fake_gateway_model)
    monkeypatch.setattr(gateway_run, "_load_gateway_config", lambda: {
        "model": {"default": "d145-sentinel-model", "provider": "d145-sentinel-provider"}
    })
    monkeypatch.setattr(runtime_provider, "_get_model_config", fake_model_cfg)
    monkeypatch.setattr(runtime_provider, "resolve_runtime_with_fallback", fake_runtime_with_fallback)
    monkeypatch.setattr(model_metadata, "get_model_context_length", fake_context_length)

    class Harness(GatewayTurnMixin):
        def __init__(self):
            self.config = None
            self._state = SimpleNamespace(conversation=SimpleNamespace(model_override=None, last_resolved_model=""))
        def _resolve_session_key_or_none(self, source, session_key):
            return None
        def _peek_session_state(self, key):
            return self._state
        def _session_state(self, key):
            return self._state
        def _rehydrate_session_model_override(self, key):
            raise AssertionError("unexpected session rehydrate")

    model, runtime = Harness()._resolve_session_agent_runtime(source=None, session_key=None, user_config={})
    assert model == "d145-sentinel-model"
    assert runtime["provider"] == "d145-sentinel-provider"
    assert runtime["api_key"] is None
    assert evidence["gateway_model"] == 1
    assert evidence["runtime_provider"] == 1

    ctx = gateway_run._resolve_gateway_model_context(
        model="d145-sentinel-model",
        route={"provider": "d145-sentinel-provider", "base_url": "https://d145.invalid/v1", "api_key": None},
    )
    assert ctx.context_length == 131072
    assert evidence["model_context"] == 1
    assert evidence["provider_network"] == 0
    print("R3_EVIDENCE=" + json.dumps(evidence, sort_keys=True))
