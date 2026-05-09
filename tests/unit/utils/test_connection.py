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
    """Explicit kwargs win over config; legacy return shape preserved."""
    kc = tmp_path / "user.kubeconfig"
    kc.write_text("apiVersion: v1\nkind: Config\n")
    with patch.object(_connection, "kubernetes") as mock_k8s:
        cfg = _connection._setup_conn(fake_config, env={}, kubeconfig=str(kc), context="user-ctx")
    assert cfg == {"kubeconfig": str(kc), "context": "user-ctx"}
    # load_kube_config is invoked with the kubeconfig path, the requested
    # context, and a Configuration object the resolver later installs as
    # the client default. The presence of ``client_configuration`` is
    # what allows multiple auth modes to coexist.
    mock_k8s.config.load_kube_config.assert_called_once()
    call = mock_k8s.config.load_kube_config.call_args
    assert call.kwargs["config_file"] == str(kc)
    assert call.kwargs["context"] == "user-ctx"
    assert "client_configuration" in call.kwargs
    mock_k8s.client.Configuration.set_default.assert_called_once()


def test_setup_conn_kubeconfig_from_config(fake_config, tmp_path):
    """Falls back to ``config.option`` when kwargs are absent."""
    kc = tmp_path / "from-config.kubeconfig"
    kc.write_text("apiVersion: v1\nkind: Config\n")
    fake_config.store["kubernetes.kubeconfig"] = str(kc)
    fake_config.store["kubernetes.context"] = "config-ctx"
    with patch.object(_connection, "kubernetes"):
        cfg = _connection._setup_conn(fake_config, env={})
    assert cfg == {"kubeconfig": str(kc), "context": "config-ctx"}


def test_setup_conn_kubeconfig_data_writes_temp_file(fake_config):
    """Inline base64 data is decoded and written to a salt-prefixed tmpfile."""
    payload = b"apiVersion: v1\nkind: Config\n"
    fake_config.store["kubernetes.kubeconfig-data"] = base64.b64encode(payload).decode()
    fake_config.store["kubernetes.context"] = "ctx"
    with patch.object(_connection, "kubernetes"):
        cfg = _connection._setup_conn(fake_config, env={})
    try:
        assert os.path.basename(cfg["kubeconfig"]).startswith("salt-kubeconfig-")
        with open(cfg["kubeconfig"], "rb") as f:
            assert f.read() == payload
    finally:
        # Use the helper itself to clean up — confirms _cleanup recognises the prefix.
        _connection._cleanup(**cfg)
        assert not os.path.exists(cfg["kubeconfig"])


def test_setup_conn_missing_required_raises(fake_config):
    """No source supplies kubeconfig/host/in-cluster: CommandExecutionError fires."""
    with pytest.raises(CommandExecutionError):
        _connection._setup_conn(fake_config, env={})


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


# ---------------------------------------------------------------------------
# PR3 — rich auth: in-cluster, bearer, basic, certs, proxy, env-var precedence
# ---------------------------------------------------------------------------


def test_in_cluster_auto_detected_from_env(fake_config):
    """KUBERNETES_SERVICE_HOST + PORT in env triggers in-cluster auth."""
    env = {
        "KUBERNETES_SERVICE_HOST": "10.0.0.1",
        "KUBERNETES_SERVICE_PORT": "443",
    }
    with patch.object(_connection, "kubernetes") as mock_k8s:
        cfg = _connection._setup_conn(fake_config, env=env)
    assert cfg == {"in_cluster": True}
    mock_k8s.config.load_incluster_config.assert_called_once()
    mock_k8s.config.load_kube_config.assert_not_called()


def test_in_cluster_explicit_true_overrides_env(fake_config):
    """``in_cluster: true`` works even when running outside a pod."""
    fake_config.store["kubernetes.in_cluster"] = True
    with patch.object(_connection, "kubernetes") as mock_k8s:
        cfg = _connection._setup_conn(fake_config, env={})
    assert cfg == {"in_cluster": True}
    mock_k8s.config.load_incluster_config.assert_called_once()


def test_in_cluster_explicit_false_blocks_autodetect(fake_config):
    """``in_cluster: false`` overrides the autodetect heuristic."""
    fake_config.store["kubernetes.in_cluster"] = False
    env = {
        "KUBERNETES_SERVICE_HOST": "10.0.0.1",
        "KUBERNETES_SERVICE_PORT": "443",
    }
    with pytest.raises(CommandExecutionError):
        with patch.object(_connection, "kubernetes"):
            _connection._setup_conn(fake_config, env=env)


def test_explicit_bearer_token(fake_config):
    """host + api_key produces a Bearer-token Configuration."""
    fake_config.store["kubernetes.host"] = "https://api.example.com"
    fake_config.store["kubernetes.api_key"] = "abc123"
    with patch.object(_connection, "kubernetes") as mock_k8s:
        cfg = _connection._setup_conn(fake_config, env={})
        config_obj = mock_k8s.client.Configuration.return_value
    assert cfg == {"host": "https://api.example.com"}
    assert config_obj.host == "https://api.example.com"
    assert config_obj.api_key == {"authorization": "abc123"}
    assert config_obj.api_key_prefix == {"authorization": "Bearer"}
    mock_k8s.client.Configuration.set_default.assert_called_once_with(config_obj)


def test_explicit_bearer_token_custom_prefix(fake_config):
    """``api_key_prefix`` overrides the default Bearer prefix."""
    fake_config.store["kubernetes.host"] = "https://api.example.com"
    fake_config.store["kubernetes.api_key"] = "abc123"
    fake_config.store["kubernetes.api_key_prefix"] = "Token"
    with patch.object(_connection, "kubernetes") as mock_k8s:
        _connection._setup_conn(fake_config, env={})
        config_obj = mock_k8s.client.Configuration.return_value
    assert config_obj.api_key_prefix == {"authorization": "Token"}


def test_explicit_basic_auth(fake_config):
    """host + username/password produces a basic-auth Configuration."""
    fake_config.store["kubernetes.host"] = "https://api.example.com"
    fake_config.store["kubernetes.username"] = "alice"
    fake_config.store["kubernetes.password"] = "s3cret"
    with patch.object(_connection, "kubernetes") as mock_k8s:
        _connection._setup_conn(fake_config, env={})
        config_obj = mock_k8s.client.Configuration.return_value
    assert config_obj.username == "alice"
    assert config_obj.password == "s3cret"


def test_explicit_client_cert(fake_config, tmp_path):
    """host + client_cert/key sets cert_file / key_file."""
    cert = tmp_path / "client.crt"
    key = tmp_path / "client.key"
    cert.write_text("-----BEGIN CERT-----\n")
    key.write_text("-----BEGIN KEY-----\n")
    fake_config.store["kubernetes.host"] = "https://api.example.com"
    fake_config.store["kubernetes.client_cert"] = str(cert)
    fake_config.store["kubernetes.client_key"] = str(key)
    with patch.object(_connection, "kubernetes") as mock_k8s:
        _connection._setup_conn(fake_config, env={})
        config_obj = mock_k8s.client.Configuration.return_value
    assert config_obj.cert_file == str(cert)
    assert config_obj.key_file == str(key)


def test_explicit_with_ca_cert_and_verify_ssl_false(fake_config, tmp_path):
    """ca_cert is wired to ssl_ca_cert; verify_ssl=False is respected."""
    ca = tmp_path / "ca.crt"
    ca.write_text("-----BEGIN CERT-----\n")
    fake_config.store["kubernetes.host"] = "https://api.example.com"
    fake_config.store["kubernetes.api_key"] = "abc"
    fake_config.store["kubernetes.ca_cert"] = str(ca)
    fake_config.store["kubernetes.verify_ssl"] = "false"
    with patch.object(_connection, "kubernetes") as mock_k8s:
        _connection._setup_conn(fake_config, env={})
        config_obj = mock_k8s.client.Configuration.return_value
    assert config_obj.ssl_ca_cert == str(ca)
    assert config_obj.verify_ssl is False


def test_proxy_no_proxy_proxy_headers_applied(fake_config):
    """Proxy-related fields propagate through any auth mode."""
    fake_config.store["kubernetes.host"] = "https://api.example.com"
    fake_config.store["kubernetes.api_key"] = "abc"
    fake_config.store["kubernetes.proxy"] = "http://proxy:3128"
    fake_config.store["kubernetes.no_proxy"] = "*.cluster.local"
    fake_config.store["kubernetes.proxy_headers"] = {"X-Test": "y"}
    with patch.object(_connection, "kubernetes") as mock_k8s:
        _connection._setup_conn(fake_config, env={})
        config_obj = mock_k8s.client.Configuration.return_value
    assert config_obj.proxy == "http://proxy:3128"
    assert config_obj.no_proxy == "*.cluster.local"
    assert config_obj.proxy_headers == {"X-Test": "y"}


def test_env_var_precedence_over_pillar(fake_config, tmp_path):
    """Env vars override pillar values (matches kubernetes.core convention)."""
    pillar_kc = tmp_path / "pillar.kubeconfig"
    env_kc = tmp_path / "env.kubeconfig"
    pillar_kc.write_text("apiVersion: v1\n")
    env_kc.write_text("apiVersion: v1\n")
    fake_config.store["kubernetes.kubeconfig"] = str(pillar_kc)
    fake_config.store["kubernetes.context"] = "ctx-from-pillar"
    env = {"K8S_AUTH_KUBECONFIG": str(env_kc), "K8S_AUTH_CONTEXT": "ctx-from-env"}
    with patch.object(_connection, "kubernetes"):
        cfg = _connection._setup_conn(fake_config, env=env)
    assert cfg == {"kubeconfig": str(env_kc), "context": "ctx-from-env"}


def test_kwarg_precedence_over_env_and_pillar(fake_config, tmp_path):
    """Explicit kwargs win over both env vars and pillar values."""
    kw_kc = tmp_path / "kwarg.kubeconfig"
    pillar_kc = tmp_path / "pillar.kubeconfig"
    env_kc = tmp_path / "env.kubeconfig"
    for p in (kw_kc, pillar_kc, env_kc):
        p.write_text("apiVersion: v1\n")
    fake_config.store["kubernetes.kubeconfig"] = str(pillar_kc)
    fake_config.store["kubernetes.context"] = "ctx-from-pillar"
    env = {"K8S_AUTH_KUBECONFIG": str(env_kc), "K8S_AUTH_CONTEXT": "ctx-from-env"}
    with patch.object(_connection, "kubernetes"):
        cfg = _connection._setup_conn(
            fake_config, env=env, kubeconfig=str(kw_kc), context="ctx-from-kwarg"
        )
    assert cfg == {"kubeconfig": str(kw_kc), "context": "ctx-from-kwarg"}


def test_kube_config_path_env_var_native(fake_config, tmp_path):
    """The native ``KUBE_CONFIG_PATH`` env var is honoured."""
    kc = tmp_path / "via-native-env.kubeconfig"
    kc.write_text("apiVersion: v1\n")
    fake_config.store["kubernetes.context"] = "from-pillar"
    with patch.object(_connection, "kubernetes"):
        cfg = _connection._setup_conn(fake_config, env={"KUBE_CONFIG_PATH": str(kc)})
    assert cfg == {"kubeconfig": str(kc), "context": "from-pillar"}


def test_in_cluster_below_explicit_credentials(fake_config):
    """When ``host`` is configured, in-cluster autodetect is skipped."""
    fake_config.store["kubernetes.host"] = "https://api.example.com"
    fake_config.store["kubernetes.api_key"] = "abc"
    env = {
        "KUBERNETES_SERVICE_HOST": "10.0.0.1",
        "KUBERNETES_SERVICE_PORT": "443",
    }
    with patch.object(_connection, "kubernetes") as mock_k8s:
        cfg = _connection._setup_conn(fake_config, env=env)
    assert cfg == {"host": "https://api.example.com"}
    mock_k8s.config.load_incluster_config.assert_not_called()


def test_coerce_bool_handles_strings():
    """``_coerce_bool`` handles env-var truthy/falsy strings."""
    for v in ("true", "TRUE", "1", "yes", "on"):
        assert _connection._coerce_bool(v) is True
    for v in ("false", "0", "no", "off", "FALSE"):
        assert _connection._coerce_bool(v) is False
    for v in (None, "", "maybe"):
        assert _connection._coerce_bool(v) is None
    assert _connection._coerce_bool(True) is True
    assert _connection._coerce_bool(False) is False
