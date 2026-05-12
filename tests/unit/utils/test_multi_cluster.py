"""
Unit tests for the multi-cluster routing layer added to
``saltext.kubernetes.utils._connection``.

These tests exercise the alias-resolution logic in isolation, without
touching any real Kubernetes API client. Behaviour we verify:

* ``cluster=None`` and ``cluster="default"`` keep the legacy single-cluster
  path, byte-identical for pre-existing callers.
* ``cluster="prod"`` consults ``kubernetes.clusters.prod`` and routes
  alias-local kwargs through the auth resolver.
* Unknown aliases raise ``CommandExecutionError`` with a clear message.
* The alias shim falls back to the parent ``get_config_option`` when the
  alias block does not define a key.
"""

from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.utils import _connection


@pytest.fixture
def fake_config():
    """A minimal stand-in for ``__salt__["config.option"]`` with a setable store."""
    store = {}

    def _get(key, default=""):
        return store.get(key, default)

    _get.store = store
    return _get


def test_list_configured_clusters_includes_default(fake_config):
    fake_config.store["kubernetes.clusters"] = {"prod": {}, "staging": {}}
    assert _connection.list_configured_clusters(fake_config) == ["default", "prod", "staging"]


def test_list_configured_clusters_no_aliases_just_default(fake_config):
    assert _connection.list_configured_clusters(fake_config) == ["default"]


def test_list_configured_clusters_explicit_default_not_duplicated(fake_config):
    fake_config.store["kubernetes.clusters"] = {"default": {}, "prod": {}}
    assert _connection.list_configured_clusters(fake_config) == ["default", "prod"]


def test_setup_conn_cluster_none_uses_legacy_path(fake_config, tmp_path):
    kc = tmp_path / "user.kubeconfig"
    kc.write_text("apiVersion: v1\nkind: Config\n")
    fake_config.store["kubernetes.kubeconfig"] = str(kc)
    fake_config.store["kubernetes.context"] = "ctx"
    with patch.object(_connection, "kubernetes"):
        cfg = _connection._setup_conn(fake_config, env={}, cluster=None)
    assert cfg == {"kubeconfig": str(kc), "context": "ctx"}


def test_setup_conn_cluster_default_uses_legacy_path(fake_config, tmp_path):
    kc = tmp_path / "user.kubeconfig"
    kc.write_text("apiVersion: v1\nkind: Config\n")
    fake_config.store["kubernetes.kubeconfig"] = str(kc)
    fake_config.store["kubernetes.context"] = "ctx"
    with patch.object(_connection, "kubernetes"):
        cfg = _connection._setup_conn(fake_config, env={}, cluster="default")
    assert cfg == {"kubeconfig": str(kc), "context": "ctx"}


def test_setup_conn_unknown_cluster_raises(fake_config):
    fake_config.store["kubernetes.clusters"] = {"prod": {}}
    with pytest.raises(CommandExecutionError, match="Unknown kubernetes cluster alias"):
        _connection._setup_conn(fake_config, env={}, cluster="staging")


def test_setup_conn_alias_kubeconfig_overrides_top_level(fake_config, tmp_path):
    """An alias's ``kubeconfig`` entry is used in preference to the global."""
    global_kc = tmp_path / "global.kubeconfig"
    global_kc.write_text("apiVersion: v1\nkind: Config\n")
    prod_kc = tmp_path / "prod.kubeconfig"
    prod_kc.write_text("apiVersion: v1\nkind: Config\n")

    fake_config.store["kubernetes.kubeconfig"] = str(global_kc)
    fake_config.store["kubernetes.context"] = "global-ctx"
    fake_config.store["kubernetes.clusters"] = {
        "prod": {"kubeconfig": str(prod_kc), "context": "prod-ctx"},
    }

    with patch.object(_connection, "kubernetes"):
        cfg = _connection._setup_conn(fake_config, env={}, cluster="prod")
    assert cfg == {"kubeconfig": str(prod_kc), "context": "prod-ctx"}


def test_setup_conn_alias_falls_back_to_global_for_missing_keys(fake_config, tmp_path):
    """When the alias omits a key, the global setting is used."""
    kc = tmp_path / "shared.kubeconfig"
    kc.write_text("apiVersion: v1\nkind: Config\n")
    fake_config.store["kubernetes.kubeconfig"] = str(kc)
    # Alias only overrides the context; kubeconfig falls through to global
    fake_config.store["kubernetes.clusters"] = {"prod": {"context": "prod-ctx"}}

    with patch.object(_connection, "kubernetes"):
        cfg = _connection._setup_conn(fake_config, env={}, cluster="prod")
    assert cfg == {"kubeconfig": str(kc), "context": "prod-ctx"}


def test_alias_shim_accepts_bare_keys(fake_config):
    """The shim recognises both ``kubernetes.context`` and bare ``context``."""
    alias_cfg = {"context": "alias-ctx"}
    shim = _connection._alias_config_shim(alias_cfg, fake_config)
    assert shim("kubernetes.context") == "alias-ctx"


def test_alias_shim_full_prefixed_keys(fake_config):
    """The shim also accepts the full ``kubernetes.foo`` form in the alias dict."""
    alias_cfg = {"kubernetes.context": "alias-ctx"}
    shim = _connection._alias_config_shim(alias_cfg, fake_config)
    assert shim("kubernetes.context") == "alias-ctx"


def test_alias_shim_default_passes_through(fake_config):
    """Default values flow through to the parent config when the alias has no entry."""
    shim = _connection._alias_config_shim({}, fake_config)
    assert shim("kubernetes.context", "fallback") == "fallback"


def test_setup_conn_alias_with_host_and_api_key(fake_config):
    fake_config.store["kubernetes.clusters"] = {
        "eks": {"host": "https://api.eks.example.com", "api_key": "abc123"}
    }
    with patch.object(_connection, "kubernetes") as mock_k8s:
        cfg = _connection._setup_conn(fake_config, env={}, cluster="eks")
        config_obj = mock_k8s.client.Configuration.return_value
    assert cfg == {"host": "https://api.eks.example.com"}
    assert config_obj.host == "https://api.eks.example.com"
    assert config_obj.api_key == {"authorization": "abc123"}
