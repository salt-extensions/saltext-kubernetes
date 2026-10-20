import os
import stat

import pytest
import yaml
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.modules import kubeconfig


def test_merge_creates_restrictive_kubeconfig_without_returning_credentials(tmp_path):
    path = tmp_path / "config"
    result = kubeconfig.merge(
        str(path),
        clusters=[{"name": "dev", "cluster": {"server": "https://example.test"}}],
        users=[{"name": "bot", "user": {"token": "secret-token"}}],
        contexts=[{"name": "dev-bot", "context": {"cluster": "dev", "user": "bot"}}],
        current_context="dev-bot",
    )
    assert result["changed"] is True
    assert "secret-token" not in repr(result)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    config = yaml.safe_load(path.read_text())
    assert config["users"][0]["user"]["token"] == "secret-token"
    assert config["current-context"] == "dev-bot"


def test_merge_is_idempotent_and_supports_keep_replace_remove(tmp_path):
    path = tmp_path / "config"
    initial = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{"name": "dev", "cluster": {"server": "one", "proxy-url": "proxy"}}],
        "users": [],
        "contexts": [],
        "preferences": {},
        "current-context": "",
    }
    path.write_text(yaml.safe_dump(initial))
    path.chmod(0o600)
    no_change = kubeconfig.merge(
        str(path), clusters=[{"name": "dev", "cluster": {"server": "one"}}]
    )
    assert no_change["changed"] is False
    replaced = kubeconfig.merge(
        str(path), clusters=[{"name": "dev", "behavior": "replace", "cluster": {"server": "two"}}]
    )
    assert replaced["changed"] is True
    assert yaml.safe_load(path.read_text())["clusters"][0]["cluster"] == {"server": "two"}
    removed = kubeconfig.merge(str(path), clusters=[{"name": "dev", "behavior": "remove"}])
    assert removed["changes"] == {"clusters": ["dev"]}


def test_merge_test_mode_does_not_create_or_write_file(tmp_path):
    path = tmp_path / "new-config"
    result = kubeconfig.merge(
        str(path), users=[{"name": "bot", "user": {"token": "secret"}}], test=True
    )
    assert result["changed"] is True
    assert not path.exists()
    assert "secret" not in repr(result)


def test_merge_rejects_invalid_entry_behavior(tmp_path):
    with pytest.raises(CommandExecutionError, match="invalid behavior"):
        kubeconfig.merge(str(tmp_path / "config"), clusters=[{"name": "dev", "behavior": "append"}])


def test_merge_repairs_existing_file_permissions(tmp_path):
    path = tmp_path / "config"
    path.write_text(yaml.safe_dump({"kind": "Config", "clusters": [], "users": [], "contexts": []}))
    path.chmod(0o644)
    result = kubeconfig.merge(str(path))
    assert result["changes"] == {"permissions": ["updated"]}
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
