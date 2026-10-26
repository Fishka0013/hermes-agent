from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from tools import website_policy as wp

URL = "https://blocked.example/path"


def _clear_cache() -> None:
    with wp._cache_lock:
        wp._cached_policy = None
        wp._cached_policy_path = None
        wp._cached_policy_time = 0.0


def _write(home: Path, body: str) -> Path:
    home.mkdir(parents=True, exist_ok=True)
    path = home / "config.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def _disabled(home: Path) -> Path:
    return _write(home, "security:\n  website_blocklist:\n    enabled: false\n    domains: []\n")


def _blocked(home: Path) -> Path:
    return _write(home, "security:\n  website_blocklist:\n    enabled: true\n    domains:\n      - blocked.example\n")


@pytest.fixture(autouse=True)
def _isolate_cache():
    _clear_cache()
    yield
    _clear_cache()


def test_disabled_cache_is_scoped_to_current_profile_path(monkeypatch, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    _disabled(a)
    _blocked(b)
    monkeypatch.setenv("HERMES_HOME", str(a))
    assert wp.check_website_access(URL) is None
    monkeypatch.setenv("HERMES_HOME", str(b))
    blocked = wp.check_website_access(URL)
    assert blocked and blocked["rule"] == "blocked.example"


def test_reverse_profile_switch_does_not_inherit_other_policy(monkeypatch, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    _disabled(a)
    _blocked(b)
    monkeypatch.setenv("HERMES_HOME", str(b))
    assert wp.check_website_access(URL)
    monkeypatch.setenv("HERMES_HOME", str(a))
    assert wp.check_website_access(URL) is None
    monkeypatch.setenv("HERMES_HOME", str(b))
    assert wp.check_website_access(URL)


def test_same_profile_disabled_cache_keeps_ttl_behavior(monkeypatch, tmp_path):
    home = tmp_path / "same"
    config = _disabled(home)
    monkeypatch.setenv("HERMES_HOME", str(home))
    assert wp.check_website_access(URL) is None
    config.write_text("security:\n  website_blocklist:\n    enabled: true\n    domains:\n      - blocked.example\n", encoding="utf-8")
    assert wp.check_website_access(URL) is None


def test_ttl_expiry_rereads_same_profile(monkeypatch, tmp_path):
    home = tmp_path / "same"
    config = _disabled(home)
    monkeypatch.setenv("HERMES_HOME", str(home))
    assert wp.check_website_access(URL) is None
    config.write_text("security:\n  website_blocklist:\n    enabled: true\n    domains:\n      - blocked.example\n", encoding="utf-8")
    with wp._cache_lock:
        wp._cached_policy_time -= wp._CACHE_TTL_SECONDS + 1.0
    blocked = wp.check_website_access(URL)
    assert blocked and blocked["rule"] == "blocked.example"


@pytest.mark.parametrize(
    "body",
    [
        "security: [broken\n",
        'security:\n  website_blocklist:\n    enabled: "not-a-bool"\n    domains: []\n',
    ],
)
def test_default_path_policy_validation_errors_fail_closed(monkeypatch, tmp_path, body):
    home = tmp_path / "bad"
    _write(home, body)
    monkeypatch.setenv("HERMES_HOME", str(home))
    blocked = wp.check_website_access(URL)
    assert blocked
    assert blocked["rule"] == "policy-evaluation-error"
    assert blocked["source"] == "website-policy"
    assert "Invalid config YAML" not in blocked["message"]
    assert "must be a boolean" not in blocked["message"]


def test_unexpected_default_policy_load_error_fails_closed_without_detail(monkeypatch, tmp_path):
    home = tmp_path / "unexpected"
    _disabled(home)
    monkeypatch.setenv("HERMES_HOME", str(home))

    def boom(_path):
        raise RuntimeError("INTERNAL-SENTINEL-DO-NOT-EXPOSE")

    monkeypatch.setattr(wp, "_load_policy_config", boom)
    blocked = wp.check_website_access(URL)
    assert blocked and blocked["rule"] == "policy-evaluation-error"
    assert "INTERNAL-SENTINEL" not in blocked["message"]


def test_explicit_config_path_keeps_validation_exception_contract(tmp_path):
    path = _write(tmp_path / "explicit", "security: [broken\n")
    with pytest.raises(wp.WebsitePolicyError):
        wp.check_website_access(URL, config_path=path)


def test_explicit_config_path_keeps_prior_unexpected_error_behavior(monkeypatch, tmp_path):
    path = _disabled(tmp_path / "explicit")

    def boom(_path):
        raise RuntimeError("synthetic")

    monkeypatch.setattr(wp, "_load_policy_config", boom)
    assert wp.check_website_access(URL, config_path=path) is None


def test_policy_error_stops_url_download_before_network_invocation(monkeypatch, tmp_path):
    from tools import url_safety
    from tools import vision_tools

    home = tmp_path / "unexpected"
    _disabled(home)
    monkeypatch.setenv("HERMES_HOME", str(home))

    def boom(_path):
        raise RuntimeError("synthetic loader failure")

    network_calls = 0

    def forbidden_network(*args, **kwargs):
        nonlocal network_calls
        network_calls += 1
        raise AssertionError("network client must not be created")

    monkeypatch.setattr(wp, "_load_policy_config", boom)
    monkeypatch.setattr(url_safety, "create_ssrf_safe_async_client", forbidden_network)
    with pytest.raises(PermissionError):
        asyncio.run(vision_tools._download_image(URL, tmp_path / "never-written.img", max_retries=1))
    assert network_calls == 0
