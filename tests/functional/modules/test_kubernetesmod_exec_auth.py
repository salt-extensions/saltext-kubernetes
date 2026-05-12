"""
Functional tests for exec-plugin auth against a real kind cluster.

Uses a hermetic mock exec plugin (a shell script that prints a valid
``ExecCredential`` JSON with the kind cluster's service-account token).
This proves the exec-auth wiring works end-to-end without depending on
external auth tools like aws-iam-authenticator or gke-gcloud-auth-plugin.

.. versionadded:: 2.1.0
"""

import json
import stat
import subprocess

import pytest
import yaml as _pyyaml

pytestmark = [pytest.mark.skip_unless_on_linux(reason="kind cluster fixture requires Linux")]


@pytest.fixture(scope="module")
def kind_admin_token(kind_cluster):
    """Mint a cluster-admin token to feed to the fake exec plugin.

    kind's default service-account has no RBAC permissions, so a token
    minted from it can't list any resource. We bind ``cluster-admin``
    to ``default:default`` for the duration of the module — the token
    we then mint can drive the test API calls. The binding is cleaned
    up at module teardown.

    kind generates a client cert by default, not a token, so the token
    has to be minted via ``kubectl create token``.
    """
    kubeconfig = str(kind_cluster.kubeconfig_path)
    binding = "salt-exec-auth-test-admin"
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


@pytest.fixture
def exec_plugin(tmp_path, kind_admin_token):
    """Write a shell script that prints a valid ExecCredential JSON.

    The script ignores its arguments and stdin; it simply emits a token
    in the expected format. Counts invocations via a sidecar log file
    so tests can assert the plugin actually ran.
    """
    plugin = tmp_path / "fake-exec-plugin.sh"
    log_file = tmp_path / "exec-plugin.log"
    payload = json.dumps(
        {
            "apiVersion": "client.authentication.k8s.io/v1beta1",
            "kind": "ExecCredential",
            "status": {"token": kind_admin_token},
        }
    )
    plugin.write_text(
        "#!/bin/sh\n" f"echo invoked >> {log_file}\n" f"cat <<'EOF'\n{payload}\nEOF\n"
    )
    plugin.chmod(plugin.stat().st_mode | stat.S_IEXEC | stat.S_IREAD)
    return plugin, log_file


@pytest.fixture(scope="module")
def kind_apiserver_endpoint(kind_cluster):
    """Read the API server URL from the kind kubeconfig."""
    with open(kind_cluster.kubeconfig_path, encoding="utf-8") as f:
        kc = _pyyaml.safe_load(f)
    # kind kubeconfig has exactly one cluster
    return kc["clusters"][0]["cluster"]["server"]


def test_exec_auth_lists_namespaces(kubernetes_exe, exec_plugin, kind_apiserver_endpoint):
    """End-to-end: kubernetes.namespaces() via exec-plugin auth succeeds."""
    plugin_path, log_path = exec_plugin
    host = kind_apiserver_endpoint

    # Inline the CA cert from the kubeconfig so we don't need to write a file.
    # The kubernetes client honours config.ssl_ca_cert as a path, but for
    # this test the kubeconfig already exposes it; we drive the call with
    # explicit kwargs so the exec path is taken.
    namespaces = kubernetes_exe.namespaces(
        host=host,
        exec={"command": str(plugin_path)},
        # The kind CA is self-signed; verify_ssl=False for the test harness.
        verify_ssl=False,
    )
    assert isinstance(namespaces, list)
    # ``default`` namespace must exist on every cluster
    assert "default" in namespaces
    # The plugin script logged its invocations
    assert log_path.exists()
    assert log_path.read_text().count("invoked") >= 1


def test_exec_auth_missing_command_clear_error(kubernetes_exe):
    """Unresolvable command produces an actionable error with the install hint."""
    from salt.exceptions import CommandExecutionError  # pylint: disable=import-outside-toplevel

    with pytest.raises(CommandExecutionError, match="not found on PATH"):
        kubernetes_exe.namespaces(
            host="https://example.invalid",
            exec={
                "command": "definitely-not-on-path-zzzzz",
                "install_hint": "Run 'brew install fake-auth-plugin'",
            },
            verify_ssl=False,
        )


def test_exec_auth_invocation_count_increases_on_repeat_calls(
    kubernetes_exe, exec_plugin, kind_apiserver_endpoint
):
    """Two API calls produce more invocations than one (refresh hook fires)."""
    plugin_path, log_path = exec_plugin
    host = kind_apiserver_endpoint

    def _ns(**extra):
        return kubernetes_exe.namespaces(
            host=host,
            exec={"command": str(plugin_path)},
            verify_ssl=False,
            **extra,
        )

    _ns()
    first_count = log_path.read_text().count("invoked")
    _ns()
    second_count = log_path.read_text().count("invoked")
    assert second_count > first_count
