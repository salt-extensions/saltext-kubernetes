import logging

import pytest
from pytest_kind import KindCluster

log = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def kind_cluster():
    """Create Kind cluster for testing"""
    cluster = KindCluster(name="salt-test")
    try:
        cluster.create()
        yield cluster
    finally:
        cluster.delete()


@pytest.fixture(scope="module")
def master_config_overrides(kind_cluster):
    """
    Kubernetes specific configuration for Salt master
    """
    return {
        "kubernetes.kubeconfig": str(kind_cluster.kubeconfig_path),
        "kubernetes.context": "kind-salt-test",
    }


@pytest.fixture(scope="module")
def minion_config_overrides(kind_cluster):
    """
    Kubernetes specific configuration for Salt minion
    """
    return {
        "file_client": "local",
        "kubernetes.kubeconfig": str(kind_cluster.kubeconfig_path),
        "kubernetes.context": "kind-salt-test",
    }


@pytest.fixture
def kubernetes(modules, minion_config_overrides):
    """
    Configure and return the kubernetes execution module
    """
    # Configure kubernetes module options
    modules.opts.update(
        {
            "kubernetes.kubeconfig": minion_config_overrides["kubernetes.kubeconfig"],
            "kubernetes.context": minion_config_overrides["kubernetes.context"],
        }
    )
    return modules.kubernetes


def test_kubernetes_ping(kubernetes, caplog):
    """
    Test kubernetes.ping returns True when connection is successful
    """
    caplog.set_level(logging.INFO)
    result = kubernetes.ping()
    assert result is True


def test_kubernetes_nodes(kubernetes, caplog):
    """
    Test kubernetes.nodes returns list of nodes
    """
    caplog.set_level(logging.INFO)
    result = kubernetes.nodes()
    assert isinstance(result, list)
    assert len(result) > 0
    assert any("salt-test-control-plane" in node for node in result)


def test_kubernetes_namespaces(kubernetes, caplog):
    """
    Test kubernetes.namespaces returns list of namespaces
    """
    caplog.set_level(logging.INFO)
    result = kubernetes.namespaces()
    assert isinstance(result, list)
    assert "default" in result, "Default namespace not found"
    assert "kube-system" in result, "kube-system namespace not found"


def test_kubernetes_pods(kubernetes, caplog):
    """
    Test kubernetes.pods returns list of pods in kube-system namespace
    """
    caplog.set_level(logging.INFO)
    result = kubernetes.pods(namespace="kube-system")
    assert isinstance(result, list)
    assert len(result) > 0


def test_create_namespace(kubernetes, caplog):
    """
    Test creating a new namespace and then verify it exists
    """
    caplog.set_level(logging.INFO)
    test_ns = "salt-test-ns"

    # First make sure namespace doesn't exist
    result = kubernetes.show_namespace(test_ns)
    assert result is None, f"Namespace {test_ns} already exists"

    # Create the namespace
    result = kubernetes.create_namespace(test_ns)
    assert isinstance(result, dict)
    assert result["metadata"]["name"] == test_ns

    # Verify namespace exists
    result = kubernetes.namespaces()
    assert test_ns in result

    # Clean up - delete the namespace
    result = kubernetes.delete_namespace(test_ns)
