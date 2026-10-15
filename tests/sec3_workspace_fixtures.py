"""Explicit on-disk authority for positive local-consumer regression fixtures."""
import json
from pathlib import Path


def configure_model_workspace(monkeypatch, tmp_path, *, root=None, home=None):
    root = (root or tmp_path).resolve()
    home = home or tmp_path / "sec3-profile"
    root.mkdir(parents=True, exist_ok=True)
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.yaml").write_text(json.dumps({
        "security": {"model_workspace_root": str(root)},
    }), encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(home))
    user_home = tmp_path / "os-user"
    user_home.mkdir(exist_ok=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: user_home))
    return root
