"""
Unit tests for ``saltext.kubernetes.utils._kinds``.

Verifies:
- The registry includes every kind currently supported by ``kubernetesmod``.
- Each entry's ``api_class_attr`` resolves to a real class on
  ``kubernetes.client``.
- Each entry's ``list_method`` and ``read_method`` are real methods on
  the resolved API class.
- Ready predicates produce the same boolean for the same input as the
  pre-refactor in-line logic in ``_wait_for_resource_status`` (regression
  guard against silent timing drift).
- ``get_kind`` raises the legacy ``CommandExecutionError`` shape on
  unknown kinds.
"""

from types import SimpleNamespace

import kubernetes.client
import pytest
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.utils import _kinds

# Kinds whose CRUD functions exist today on ``kubernetesmod``.
EXPECTED_KINDS = {
    "deployment",
    "statefulset",
    "replicaset",
    "daemonset",
    "pod",
    "service",
    "secret",
    "configmap",
    "namespace",
    "storageclass",
    "role",
    "role_binding",
    "cluster_role",
    "cluster_role_binding",
    "service_account",
    "job",
    "cron_job",
    "ingress",
    "horizontal_pod_autoscaler",
    "pod_disruption_budget",
}


def test_registry_covers_every_supported_kind():
    """Every kind we ship typed CRUD for has a registry entry."""
    assert set(_kinds._KIND_REGISTRY) == EXPECTED_KINDS


@pytest.mark.parametrize("kind_name", sorted(EXPECTED_KINDS))
def test_api_methods_exist(kind_name):
    """``api_class_attr`` resolves; ``list_method`` and ``read_method`` exist on it."""
    kind = _kinds.get_kind(kind_name)
    api_class = getattr(kubernetes.client, kind.api_class_attr)
    assert hasattr(
        api_class, kind.list_method
    ), f"{kind.api_class_attr}.{kind.list_method} not found"
    assert hasattr(
        api_class, kind.read_method
    ), f"{kind.api_class_attr}.{kind.read_method} not found"


def test_get_kind_unknown_raises_command_execution_error():
    """Unknown kinds raise the legacy CommandExecutionError shape."""
    with pytest.raises(CommandExecutionError, match="Unsupported resource type"):
        _kinds.get_kind("frobozz")


# ---------------------------------------------------------------------------
# Ready predicates — sample objects modelled after the kubernetes.client
# response shapes the pre-refactor code accessed directly.
# ---------------------------------------------------------------------------


def _make_deployment(available, replicas):
    return SimpleNamespace(
        status=SimpleNamespace(available_replicas=available),
        spec=SimpleNamespace(replicas=replicas),
    )


def _make_pod(phase, container_readiness):
    statuses = (
        [SimpleNamespace(ready=r, name=f"c{i}") for i, r in enumerate(container_readiness)]
        if container_readiness is not None
        else None
    )
    return SimpleNamespace(status=SimpleNamespace(phase=phase, container_statuses=statuses))


def _make_service(cluster_ip):
    return SimpleNamespace(spec=SimpleNamespace(cluster_ip=cluster_ip))


def test_deployment_ready_when_available_matches_replicas():
    assert _kinds._deployment_ready(_make_deployment(3, 3)) is True


def test_deployment_not_ready_when_partial():
    assert _kinds._deployment_ready(_make_deployment(2, 3)) is False


def test_deployment_not_ready_when_no_available_yet():
    assert _kinds._deployment_ready(_make_deployment(None, 3)) is False
    assert _kinds._deployment_ready(_make_deployment(0, 3)) is False


def test_pod_ready_when_running_and_all_containers_ready():
    assert _kinds._pod_ready(_make_pod("Running", [True, True])) is True


def test_pod_not_ready_when_any_container_not_ready():
    assert _kinds._pod_ready(_make_pod("Running", [True, False])) is False


def test_pod_not_ready_when_container_statuses_absent():
    assert _kinds._pod_ready(_make_pod("Running", None)) is False


def test_pod_not_ready_when_phase_pending():
    assert _kinds._pod_ready(_make_pod("Pending", [True])) is False


def test_service_ready_when_cluster_ip_assigned():
    assert _kinds._service_ready(_make_service("10.0.0.1")) is True


def test_service_not_ready_without_cluster_ip():
    assert _kinds._service_ready(_make_service(None)) is False
    assert _kinds._service_ready(_make_service("")) is False


@pytest.mark.parametrize(
    "kind_name",
    ["statefulset", "replicaset", "daemonset", "secret", "configmap", "namespace", "storageclass"],
)
def test_default_predicate_is_always_ready(kind_name):
    """Kinds without specific readiness checks accept any object."""
    kind = _kinds.get_kind(kind_name)
    assert kind.ready_predicate(SimpleNamespace()) is True


@pytest.mark.parametrize(
    "kind_name,expected_namespaced",
    [
        ("deployment", True),
        ("pod", True),
        ("service", True),
        ("namespace", False),
        ("storageclass", False),
    ],
)
def test_namespaced_flag(kind_name, expected_namespaced):
    """Cluster-scoped kinds are correctly flagged."""
    assert _kinds.get_kind(kind_name).namespaced is expected_namespaced
