"""Explicit on-disk authority for positive local-consumer regression fixtures."""
import json
from pathlib import Path


def write_model_workspace_config(home: Path, root: Path) -> None:
    import hermes_yaml

    home.mkdir(parents=True, exist_ok=True)
    path = home / "config.yaml"
    config = (hermes_yaml.safe_load(path.read_text(encoding="utf-8-sig")) or {}) if path.exists() else {}
    config.setdefault("security", {})["model_workspace_root"] = str(root.resolve())
    path.write_text(json.dumps(config), encoding="utf-8")


def configure_model_workspace(monkeypatch, tmp_path, *, root=None, home=None):
    root = (root or tmp_path).resolve()
    home = home or tmp_path / "sec3-profile"
    root.mkdir(parents=True, exist_ok=True)
    write_model_workspace_config(home, root)
    monkeypatch.setenv("HERMES_HOME", str(home))
    user_home = tmp_path / "os-user"
    user_home.mkdir(exist_ok=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: user_home))
    return root
