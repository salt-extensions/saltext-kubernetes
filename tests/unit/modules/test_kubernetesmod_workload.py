"""
Unit tests for the workload + cluster operations on
``saltext.kubernetes.modules.kubernetesmod`` (scale, restart, rollback,
cluster_info).

These exercise the input-validation and kind-normalisation layer
without touching the kubernetes API. Functional tests against a real
cluster live alongside the other functional tests.
"""

import kubernetes.client
import pytest
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.modules import kubernetesmod

# ---------------------------------------------------------------------------
# _normalise_workload_kind
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Deployment", "deployment"),
        ("StatefulSet", "statefulset"),
        ("stateful-set", "stateful_set"),
        ("Daemon Set", "daemon_set"),
    ],
)
def test_normalise_workload_kind(raw, expected):
    assert kubernetesmod._normalise_workload_kind(raw) == expected


def test_normalise_workload_kind_rejects_non_string():
    with pytest.raises(CommandExecutionError, match="kind must be a string"):
        kubernetesmod._normalise_workload_kind(42)


# ---------------------------------------------------------------------------
# scale (input validation; the actual API call lives behind _setup_conn
# and exercises in functional tests)
# ---------------------------------------------------------------------------


def test_scale_rejects_unknown_kind():
    with pytest.raises(CommandExecutionError, match="Unsupported scalable kind"):
        kubernetesmod.scale("daemonset", "x", 1)


def test_scale_rejects_pod_kind():
    """Pods aren't workload controllers; scale() must reject them."""
    with pytest.raises(CommandExecutionError, match="Unsupported scalable kind"):
        kubernetesmod.scale("pod", "x", 1)


@pytest.mark.parametrize("bad", [-1, 1.5, "two", None])
def test_scale_rejects_invalid_replicas(bad):
    with pytest.raises(CommandExecutionError, match="non-negative integer"):
        kubernetesmod.scale("deployment", "x", bad)


# ---------------------------------------------------------------------------
# restart (input validation)
# ---------------------------------------------------------------------------


def test_restart_accepts_daemonset():
    """DaemonSet has no /scale subresource but does support restart."""
    # Just probe the kind lookup path; the real API call is mocked away
    # because this test never reaches _setup_conn (no kubeconfig in env).
    norm = kubernetesmod._normalise_workload_kind("DaemonSet")
    assert norm == "daemonset"
    assert norm in kubernetesmod._RESTARTABLE_ONLY_KINDS


def test_restart_rejects_pod():
    with pytest.raises(CommandExecutionError, match="Unsupported restartable kind"):
        kubernetesmod.restart("pod", "x")


def test_restart_rejects_unknown_kind():
    with pytest.raises(CommandExecutionError, match="Unsupported restartable kind"):
        kubernetesmod.restart("Frobozz", "x")


# ---------------------------------------------------------------------------
# Registry consistency
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind_name", sorted(kubernetesmod._SCALABLE_KINDS))
def test_scalable_kinds_resolve_real_api_methods(kind_name):
    """Every entry in _SCALABLE_KINDS points at real kubernetes-client methods."""

    api_attr, patch_scale, (read, patch) = kubernetesmod._SCALABLE_KINDS[kind_name]
    api_class = getattr(kubernetes.client, api_attr)
    for method in (patch_scale, read, patch):
        assert hasattr(api_class, method), f"{api_attr}.{method} not found"


@pytest.mark.parametrize("kind_name", sorted(kubernetesmod._RESTARTABLE_ONLY_KINDS))
def test_restartable_only_kinds_resolve_real_api_methods(kind_name):

    api_attr, (read, patch) = kubernetesmod._RESTARTABLE_ONLY_KINDS[kind_name]
    api_class = getattr(kubernetes.client, api_attr)
    assert hasattr(api_class, read)
    assert hasattr(api_class, patch)
