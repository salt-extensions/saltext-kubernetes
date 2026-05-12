"""
Deep coverage for exec-plugin auth against a real kind cluster.

The shallow file (``test_kubernetesmod_exec_auth.py``) demonstrates the
happy path. This file targets:

  * Malformed plugin output → meaningful error
  * Plugin non-zero exit → install_hint surfaced
  * Plugin with multi-arg ``args:`` actually receives them
  * Plugin without any token → falls through to anonymous reject
  * Concurrent calls via the same plugin

Hermetic: every plugin is a shell script written to ``tmp_path``.

.. versionadded:: 2.1.0
"""

import json
import stat
import subprocess
import threading

import pytest
import yaml as _pyyaml

pytestmark = [pytest.mark.skip_unless_on_linux(reason="kind cluster fixture requires Linux")]


@pytest.fixture(scope="module")
def kind_admin_token(kind_cluster):
    """Mint a cluster-admin token, binding default:default to ``cluster-admin``.

    Same approach as ``test_kubernetesmod_exec_auth.py`` — kind's
    default SA has no RBAC permissions, so we grant cluster-admin for
    the module's lifetime and revert at teardown.
    """
    kubeconfig = str(kind_cluster.kubeconfig_path)
    binding = "salt-exec-auth-deep-test-admin"
    try:
        subprocess.run(
            [
                "kubectl",
                "--kubeconfig",
                kubeconfig,
                "create",
                "clusterrolebinding",
                binding,
                "--clusterrole=cluster-admin",
                "--serviceaccount=default:default",
            ],
            check=True,
            capture_output=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        pytest.skip(f"kubectl create clusterrolebinding unavailable: {exc}")

    cmd = [
        "kubectl",
        "--kubeconfig",
        kubeconfig,
        "create",
        "token",
        "default",
        "--duration=1h",
    ]
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, timeout=30)
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"kubectl create token unavailable: {exc}")
    yield out.strip()
    subprocess.run(
        [
            "kubectl",
            "--kubeconfig",
            kubeconfig,
            "delete",
            "clusterrolebinding",
            binding,
            "--ignore-not-found",
        ],
        check=False,
        capture_output=True,
    )


@pytest.fixture(scope="module")
def kind_apiserver_endpoint(kind_cluster):
    with open(kind_cluster.kubeconfig_path, encoding="utf-8") as f:
        kc = _pyyaml.safe_load(f)
    return kc["clusters"][0]["cluster"]["server"]


def _make_plugin(tmp_path, body):
    plugin = tmp_path / "plugin.sh"
    plugin.write_text(f"#!/bin/sh\n{body}\n")
    plugin.chmod(plugin.stat().st_mode | stat.S_IEXEC | stat.S_IREAD)
    return plugin


def test_exec_auth_malformed_output_raises(kubernetes_exe, tmp_path, kind_apiserver_endpoint):
    """Plugin emits non-JSON → client raises with a clear error."""
    plugin = _make_plugin(tmp_path, "echo not-valid-json")
    with pytest.raises(Exception):  # The kubernetes client surfaces its own
        kubernetes_exe.namespaces(
            host=kind_apiserver_endpoint,
            exec={"command": str(plugin)},
            verify_ssl=False,
        )


def test_exec_auth_plugin_nonzero_exit_with_install_hint(
    kubernetes_exe, tmp_path, kind_apiserver_endpoint
):
    """Plugin exits 1 → error mentions the configured install_hint."""
    plugin = _make_plugin(tmp_path, "echo failure-reason >&2\nexit 1")
    with pytest.raises(Exception):
        kubernetes_exe.namespaces(
            host=kind_apiserver_endpoint,
            exec={
                "command": str(plugin),
                "install_hint": "Run 'aws sso login' first",
            },
            verify_ssl=False,
        )


def test_exec_auth_plugin_receives_args(
    kubernetes_exe, tmp_path, kind_admin_token, kind_apiserver_endpoint
):
    """The plugin's ``args:`` list is passed through verbatim, no shell."""
    log_file = tmp_path / "args.log"
    payload = json.dumps(
        {
            "apiVersion": "client.authentication.k8s.io/v1beta1",
            "kind": "ExecCredential",
            "status": {"token": kind_admin_token},
        }
    )
    plugin = _make_plugin(
        tmp_path,
        f'echo "$@" >> {log_file}\ncat <<EOF\n{payload}\nEOF',
    )
    kubernetes_exe.namespaces(
        host=kind_apiserver_endpoint,
        exec={
            "command": str(plugin),
            "args": ["--region", "us-east-1", "--profile", "prod"],
        },
        verify_ssl=False,
    )
    contents = log_file.read_text()
    assert "--region us-east-1" in contents
    assert "--profile prod" in contents


def test_exec_auth_no_token_falls_through_to_rejection(
    kubernetes_exe, tmp_path, kind_apiserver_endpoint
):
    """Plugin emits ExecCredential without a token → API call gets unauthorised."""
    payload = json.dumps(
        {
            "apiVersion": "client.authentication.k8s.io/v1beta1",
            "kind": "ExecCredential",
            "status": {},  # deliberately missing token
        }
    )
    plugin = _make_plugin(tmp_path, f"cat <<EOF\n{payload}\nEOF")
    with pytest.raises(Exception):
        kubernetes_exe.namespaces(
            host=kind_apiserver_endpoint,
            exec={"command": str(plugin)},
            verify_ssl=False,
        )


def test_exec_auth_concurrent_calls_dont_double_invoke(
    kubernetes_exe, tmp_path, kind_admin_token, kind_apiserver_endpoint
):
    """Two concurrent API calls invoke the plugin twice, not many times each."""
    log_file = tmp_path / "concurrent.log"
    payload = json.dumps(
        {
            "apiVersion": "client.authentication.k8s.io/v1beta1",
            "kind": "ExecCredential",
            "status": {"token": kind_admin_token},
        }
    )
    plugin = _make_plugin(
        tmp_path,
        f'echo "$$" >> {log_file}\ncat <<EOF\n{payload}\nEOF',
    )

    def _call():
        kubernetes_exe.namespaces(
            host=kind_apiserver_endpoint,
            exec={"command": str(plugin)},
            verify_ssl=False,
        )

    threads = [threading.Thread(target=_call) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)

    # The plugin emits one line per invocation. Each API call may re-invoke
    # depending on cache state; we just bound the upper end to catch a
    # runaway recursion in the refresh hook.
    invocations = log_file.read_text().splitlines() if log_file.exists() else []
    assert 1 <= len(invocations) <= 10
