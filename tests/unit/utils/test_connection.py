"""
Unit tests for ``saltext.kubernetes.utils._connection``.

These tests exercise the connection helpers in isolation — without any
Salt loader / minion fixtures — to demonstrate the testable seam created
when the helpers were extracted from ``kubernetesmod``. Behavioural tests
that require the Salt context still live in
``tests/unit/modules/test_kubernetesmod.py``.
"""

import base64
import os
from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.utils import _connection


@pytest.fixture
def fake_config():
    """A minimal stand-in for ``__salt__["config.option"]``."""
    store = {}

    def _get(key, default=""):
        return store.get(key, default)

    _get.store = store
    return _get


def test_setup_conn_kubeconfig_path_from_kwargs(fake_config, tmp_path):
    """Explicit kwargs win over config; legacy contract preserved."""
    kc = tmp_path / "user.kubeconfig"
    kc.write_text("apiVersion: v1\nkind: Config\n")
    with patch.object(_connection, "kubernetes") as mock_k8s:
        cfg = _connection._setup_conn(fake_config, kubeconfig=str(kc), context="user-ctx")
    assert cfg == {"kubeconfig": str(kc), "context": "user-ctx"}
    mock_k8s.config.load_kube_config.assert_called_once_with(
        config_file=str(kc), context="user-ctx"
    )


def test_setup_conn_kubeconfig_from_config(fake_config, tmp_path):
    """Falls back to ``config.option`` when kwargs are absent."""
    kc = tmp_path / "from-config.kubeconfig"
    kc.write_text("apiVersion: v1\nkind: Config\n")
    fake_config.store["kubernetes.kubeconfig"] = str(kc)
    fake_config.store["kubernetes.context"] = "config-ctx"
    with patch.object(_connection, "kubernetes"):
        cfg = _connection._setup_conn(fake_config)
    assert cfg == {"kubeconfig": str(kc), "context": "config-ctx"}


def test_setup_conn_kubeconfig_data_writes_temp_file(fake_config):
    """Inline base64 data is decoded and written to a salt-prefixed tmpfile."""
    payload = b"apiVersion: v1\nkind: Config\n"
    fake_config.store["kubernetes.kubeconfig-data"] = base64.b64encode(payload).decode()
    fake_config.store["kubernetes.context"] = "ctx"
    with patch.object(_connection, "kubernetes"):
        cfg = _connection._setup_conn(fake_config)
    try:
        assert os.path.basename(cfg["kubeconfig"]).startswith("salt-kubeconfig-")
        with open(cfg["kubeconfig"], "rb") as f:
            assert f.read() == payload
    finally:
        # Use the helper itself to clean up — confirms _cleanup recognises the prefix.
        _connection._cleanup(**cfg)
        assert not os.path.exists(cfg["kubeconfig"])


def test_setup_conn_missing_required_raises(fake_config):
    """Without kubeconfig + context, the legacy CommandExecutionError fires."""
    with pytest.raises(CommandExecutionError):
        _connection._setup_conn(fake_config)


def test_cleanup_leaves_user_supplied_paths_alone(tmp_path):
    """Files that don't match the ``salt-kubeconfig-`` prefix are not touched."""
    kc = tmp_path / "user.kubeconfig"
    kc.write_text("apiVersion: v1\n")
    _connection._cleanup(kubeconfig=str(kc))
    assert kc.exists()


def test_cleanup_handles_missing_file_quietly(tmp_path):
    """ENOENT is swallowed; other OSErrors are logged at error level."""
    missing = tmp_path / "salt-kubeconfig-vanished"
    # Should not raise even though the file never existed.
    _connection._cleanup(kubeconfig=str(missing))
