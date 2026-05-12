"""
Unit tests for the exec-plugin auth path in
``saltext.kubernetes.utils._connection._apply_exec_auth``.

These tests do not invoke any real exec plugin; they verify input
validation, PATH resolution, and the wiring on the kubernetes-client
Configuration object.
"""

import stat
import sys
from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.utils import _connection


@pytest.fixture
def config():
    """A bare ``kubernetes.client.Configuration``-like object."""

    class _Cfg:
        host = ""
        api_key = None
        api_key_prefix = None
        refresh_api_key_hook = None

    return _Cfg()


def test_exec_auth_requires_mapping(config):
    with pytest.raises(CommandExecutionError, match="must be a mapping"):
        _connection._apply_exec_auth(config, "not-a-dict")


def test_exec_auth_requires_command(config):
    with pytest.raises(CommandExecutionError, match="command is required"):
        _connection._apply_exec_auth(config, {})


def test_exec_auth_rejects_unresolvable_command(config):
    with pytest.raises(CommandExecutionError, match="not found on PATH"):
        _connection._apply_exec_auth(
            config,
            {"command": "definitely-not-on-path-aaaaa", "install_hint": "Try apt install x."},
        )


def test_exec_auth_install_hint_in_error(config):
    with pytest.raises(CommandExecutionError, match="Try apt install x."):
        _connection._apply_exec_auth(
            config,
            {"command": "definitely-not-on-path-aaaaa", "install_hint": "Try apt install x."},
        )


def test_exec_auth_absolute_path_no_path_lookup(config, tmp_path):
    """Absolute paths are taken at face value (no shutil.which lookup)."""
    fake = tmp_path / "my-auth-plugin"
    fake.write_text('#!/bin/sh\necho \'{"status":{"token":"tok"}}\'\n')
    fake.chmod(0o755)
    with patch("kubernetes.config.kube_config.ExecProvider") as mock_provider_cls:
        mock_provider_cls.return_value.run.return_value = {"token": "tok"}
        _connection._apply_exec_auth(config, {"command": str(fake)})
    # Should not raise. Verify the provider was constructed with our absolute path.
    args = mock_provider_cls.call_args[0]
    assert args[0]["command"] == str(fake)


@pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="POSIX-only — /usr/bin/sh resolution. Windows ships no `sh` on PATH.",
)
def test_exec_auth_resolves_command_via_path(config):
    """Bare names are resolved via shutil.which."""
    with patch("kubernetes.config.kube_config.ExecProvider") as mock_provider_cls:
        mock_provider_cls.return_value.run.return_value = {"token": "tok"}
        # ``sh`` is virtually always on PATH on test runners
        _connection._apply_exec_auth(config, {"command": "sh", "args": ["-c", "echo"]})
    args = mock_provider_cls.call_args[0]
    # Resolved to an absolute path
    assert args[0]["command"].startswith("/")
    assert args[0]["command"].endswith("/sh")


def test_exec_auth_default_api_version(config):
    with patch("kubernetes.config.kube_config.ExecProvider") as mock_provider_cls:
        mock_provider_cls.return_value.run.return_value = {"token": "tok"}
        _connection._apply_exec_auth(config, {"command": "sh"})
    assert mock_provider_cls.call_args[0][0]["apiVersion"] == "client.authentication.k8s.io/v1beta1"


def test_exec_auth_env_is_list_of_name_value_dicts(config):
    """The kubeconfig schema requires ``env`` as a list of {name, value} dicts."""
    with patch("kubernetes.config.kube_config.ExecProvider") as mock_provider_cls:
        mock_provider_cls.return_value.run.return_value = {"token": "tok"}
        _connection._apply_exec_auth(
            config,
            {"command": "sh", "env": {"AWS_PROFILE": "prod", "AWS_REGION": "us-east-1"}},
        )
    env_block = mock_provider_cls.call_args[0][0]["env"]
    # Order-insensitive comparison since dict iteration order may vary
    assert {"name": "AWS_PROFILE", "value": "prod"} in env_block
    assert {"name": "AWS_REGION", "value": "us-east-1"} in env_block


def test_exec_auth_wires_refresh_hook(config):
    """The Configuration object ends up with a refresh_api_key_hook callable."""
    with patch("kubernetes.config.kube_config.ExecProvider") as mock_provider_cls:
        mock_provider_cls.return_value.run.return_value = {"token": "tok-123"}
        _connection._apply_exec_auth(config, {"command": "sh"})
    assert callable(config.refresh_api_key_hook)
    # Invoking the hook should produce a Bearer-formatted authorization value
    config.refresh_api_key_hook(config)
    assert config.api_key["authorization"] == "Bearer tok-123"


def test_exec_auth_setup_via_setup_conn(tmp_path):
    """End-to-end: ``_setup_conn`` with a ``kubernetes.exec`` block wires correctly."""
    plugin = tmp_path / "fake-auth"
    plugin.write_text("#!/bin/sh\nexit 0\n")
    plugin.chmod(plugin.stat().st_mode | stat.S_IEXEC)

    store = {
        "kubernetes.host": "https://api.example.com",
        "kubernetes.exec": {"command": str(plugin)},
    }

    def get_opt(key, default=""):
        return store.get(key, default)

    with (
        patch("kubernetes.config.kube_config.ExecProvider") as mock_provider_cls,
        patch.object(_connection, "kubernetes") as mock_k8s,
    ):
        mock_provider_cls.return_value.run.return_value = {"token": "abc"}
        cfg = _connection._setup_conn(get_opt, env={})
        config_obj = mock_k8s.client.Configuration.return_value
    assert cfg == {"host": "https://api.example.com"}
    # Refresh hook should be wired
    assert config_obj.refresh_api_key_hook is not None
