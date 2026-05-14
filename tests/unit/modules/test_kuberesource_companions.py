"""
Unit tests for the ``kuberesource_*`` companion modules.

Each test injects ``__resource__`` and a stub ``__salt__`` to exercise
the identity-routing logic without bringing up a cluster. The
underlying ``kubernetes.*`` execution-module functions have their own
end-to-end tests; what we're proving here is that:

  * ``__virtual__`` returns the dormant sentinel on stock Salt.
  * Each public function pulls (kind, namespace, name) from
    ``__resource__["id"]`` and forwards them as the right kwargs to
    the underlying ``kubernetes.*`` function.
  * Pod-only / Node-only / workload-only constraints fire on the wrong
    kind via :py:func:`_kuberesource.require_kind`.
"""

from unittest.mock import MagicMock

import pytest
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.modules import kuberesource_cmd
from saltext.kubernetes.modules import kuberesource_cp
from saltext.kubernetes.modules import kuberesource_logs
from saltext.kubernetes.modules import kuberesource_node
from saltext.kubernetes.modules import kuberesource_state
from saltext.kubernetes.modules import kuberesource_workload

# ---------------------------------------------------------------------------
# Shared __virtual__ behaviour
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mod",
    [
        kuberesource_cmd,
        kuberesource_logs,
        kuberesource_cp,
        kuberesource_node,
        kuberesource_workload,
        kuberesource_state,
    ],
)
def test_companion_modules_dormant_on_stock_salt(mod):
    """Every companion module reports the dormant sentinel."""
    result = mod.__virtual__()
    assert isinstance(result, tuple)
    assert result[0] is False


# ---------------------------------------------------------------------------
# Test fixture: inject __resource__ + __salt__ into a target module
# ---------------------------------------------------------------------------


@pytest.fixture
def pod_resource(monkeypatch):
    """Set up a Pod resource context on every companion module."""
    salt_stub = {
        "kubernetes.exec": MagicMock(return_value={"stdout": "ok", "stderr": "", "retcode": 0}),
        "kubernetes.logs": MagicMock(return_value="log lines"),
        "kubernetes.cp_to": MagicMock(return_value={"retcode": 0}),
        "kubernetes.cp_from": MagicMock(return_value={"retcode": 0}),
        "kubernetes.cordon": MagicMock(return_value={}),
        "kubernetes.uncordon": MagicMock(return_value={}),
        "kubernetes.drain": MagicMock(
            return_value={"node": "x", "evicted": [], "skipped": [], "errors": []}
        ),
        "kubernetes.taint": MagicMock(return_value={}),
        "kubernetes.untaint": MagicMock(return_value={}),
        "kubernetes.scale": MagicMock(return_value={}),
        "kubernetes.restart": MagicMock(return_value={}),
        "kubernetes.rollback": MagicMock(return_value={}),
        "kubernetes.apply": MagicMock(return_value={}),
    }
    rid = {"id": "pod:default/nginx-abc"}
    for mod in (
        kuberesource_cmd,
        kuberesource_logs,
        kuberesource_cp,
        kuberesource_node,
        kuberesource_workload,
        kuberesource_state,
    ):
        monkeypatch.setattr(mod, "__resource__", rid, raising=False)
        monkeypatch.setattr(mod, "__salt__", salt_stub, raising=False)
    return salt_stub


@pytest.fixture
def node_resource(monkeypatch):
    salt_stub = {
        "kubernetes.cordon": MagicMock(return_value={}),
        "kubernetes.uncordon": MagicMock(return_value={}),
        "kubernetes.drain": MagicMock(
            return_value={"node": "x", "evicted": [], "skipped": [], "errors": []}
        ),
        "kubernetes.taint": MagicMock(return_value={}),
        "kubernetes.untaint": MagicMock(return_value={}),
        "kubernetes.exec": MagicMock(),
    }
    rid = {"id": "node:gke-prod-pool-1"}
    for mod in (kuberesource_node, kuberesource_cmd):
        monkeypatch.setattr(mod, "__resource__", rid, raising=False)
        monkeypatch.setattr(mod, "__salt__", salt_stub, raising=False)
    return salt_stub


@pytest.fixture
def deployment_resource(monkeypatch):
    salt_stub = {
        "kubernetes.scale": MagicMock(return_value={}),
        "kubernetes.restart": MagicMock(return_value={}),
        "kubernetes.rollback": MagicMock(return_value={}),
        "kubernetes.exec": MagicMock(),
    }
    rid = {"id": "deployment:production/api"}
    for mod in (kuberesource_workload, kuberesource_cmd):
        monkeypatch.setattr(mod, "__resource__", rid, raising=False)
        monkeypatch.setattr(mod, "__salt__", salt_stub, raising=False)
    return salt_stub


# ---------------------------------------------------------------------------
# kuberesource_cmd
# ---------------------------------------------------------------------------


def test_cmd_run_forwards_pod_identity(pod_resource):
    kuberesource_cmd.run("echo hi")
    pod_resource["kubernetes.exec"].assert_called_once()
    call = pod_resource["kubernetes.exec"].call_args
    assert call.kwargs["name"] == "nginx-abc"
    assert call.kwargs["namespace"] == "default"
    assert call.kwargs["command"] == "echo hi"


def test_cmd_run_rejects_node_kind(node_resource):
    """Exec doesn't make sense against a Node resource."""
    with pytest.raises(CommandExecutionError, match="not valid for resource kind 'node'"):
        kuberesource_cmd.run("echo hi")


def test_cmd_run_stdout_returns_only_stdout(pod_resource):
    pod_resource["kubernetes.exec"].return_value = {"stdout": "OUT", "stderr": "", "retcode": 0}
    assert kuberesource_cmd.run_stdout("x") == "OUT"


# ---------------------------------------------------------------------------
# kuberesource_logs
# ---------------------------------------------------------------------------


def test_logs_fetch_forwards_pod_identity(pod_resource):
    kuberesource_logs.fetch(tail_lines=10)
    call = pod_resource["kubernetes.logs"].call_args
    assert call.kwargs["name"] == "nginx-abc"
    assert call.kwargs["namespace"] == "default"
    assert call.kwargs["tail_lines"] == 10


def test_logs_tail_convenience(pod_resource):
    kuberesource_logs.tail(lines=25)
    call = pod_resource["kubernetes.logs"].call_args
    assert call.kwargs["tail_lines"] == 25


# ---------------------------------------------------------------------------
# kuberesource_cp
# ---------------------------------------------------------------------------


def test_cp_to_pod(pod_resource, tmp_path):
    src = tmp_path / "x.txt"
    src.write_text("hi")
    kuberesource_cp.to_pod(str(src), "/tmp")
    call = pod_resource["kubernetes.cp_to"].call_args
    assert call.kwargs["name"] == "nginx-abc"
    assert call.kwargs["src_path"] == str(src)
    assert call.kwargs["dst_path"] == "/tmp"


def test_cp_from_pod(pod_resource, tmp_path):
    kuberesource_cp.from_pod("/etc/hostname", str(tmp_path))
    call = pod_resource["kubernetes.cp_from"].call_args
    assert call.kwargs["src_path"] == "/etc/hostname"
    assert call.kwargs["dst_path"] == str(tmp_path)


# ---------------------------------------------------------------------------
# kuberesource_node
# ---------------------------------------------------------------------------


def test_node_cordon_forwards_node_name(node_resource):
    kuberesource_node.cordon()
    node_resource["kubernetes.cordon"].assert_called_once_with(name="gke-prod-pool-1")


def test_node_drain_forwards_kwargs(node_resource):
    kuberesource_node.drain(ignore_daemonsets=False, force=True, timeout=120)
    call = node_resource["kubernetes.drain"].call_args
    assert call.kwargs["name"] == "gke-prod-pool-1"
    assert call.kwargs["ignore_daemonsets"] is False
    assert call.kwargs["force"] is True
    assert call.kwargs["timeout"] == 120


def test_node_cordon_rejects_pod_resource(pod_resource):
    """Cordon doesn't make sense against a Pod resource."""
    with pytest.raises(CommandExecutionError, match="not valid for resource kind 'pod'"):
        kuberesource_node.cordon()


def test_node_taint_forwards(node_resource):
    kuberesource_node.taint(key="gpu", effect="NoSchedule", value="true")
    call = node_resource["kubernetes.taint"].call_args
    assert call.kwargs == {
        "name": "gke-prod-pool-1",
        "key": "gpu",
        "effect": "NoSchedule",
        "value": "true",
    }


# ---------------------------------------------------------------------------
# kuberesource_workload
# ---------------------------------------------------------------------------


def test_workload_scale_forwards_deployment_identity(deployment_resource):
    kuberesource_workload.scale(replicas=5)
    call = deployment_resource["kubernetes.scale"].call_args
    assert call.kwargs == {
        "kind": "deployment",
        "name": "api",
        "replicas": 5,
        "namespace": "production",
    }


def test_workload_restart_forwards(deployment_resource):
    kuberesource_workload.restart()
    call = deployment_resource["kubernetes.restart"].call_args
    assert call.kwargs == {
        "kind": "deployment",
        "name": "api",
        "namespace": "production",
    }


def test_workload_rollback_only_for_deployments(deployment_resource):
    kuberesource_workload.rollback(to_revision=3)
    call = deployment_resource["kubernetes.rollback"].call_args
    assert call.kwargs == {"name": "api", "namespace": "production", "to_revision": 3}


def test_workload_rollback_rejects_pod(pod_resource):
    with pytest.raises(CommandExecutionError, match="not valid for resource kind 'pod'"):
        kuberesource_workload.rollback()


# ---------------------------------------------------------------------------
# kuberesource_state
# ---------------------------------------------------------------------------


def test_state_apply_injects_resource_into_template_context(pod_resource):
    kuberesource_state.apply_(
        manifest={"apiVersion": "v1", "kind": "ConfigMap"},
        template_context={"existing": "value"},
    )
    call = pod_resource["kubernetes.apply"].call_args
    ctx = call.kwargs["template_context"]
    assert ctx["existing"] == "value"
    assert ctx["resource"] == {"kind": "pod", "namespace": "default", "name": "nginx-abc"}


def test_state_apply_resource_namespace_falls_back_to_resource(pod_resource):
    """When namespace= is not given, falls back to the resource's namespace."""
    kuberesource_state.apply_(
        manifest={"apiVersion": "v1", "kind": "ConfigMap"},
    )
    call = pod_resource["kubernetes.apply"].call_args
    assert call.kwargs["namespace"] == "default"
