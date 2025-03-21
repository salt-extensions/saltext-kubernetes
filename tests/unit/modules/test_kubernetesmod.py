"""
    :codeauthor: Jochen Breuer <jbreuer@suse.de>
"""

import logging

# pylint: disable=no-value-for-parameter
from unittest.mock import MagicMock
from unittest.mock import Mock
from unittest.mock import patch

import pytest
from kubernetes.client import V1Container
from kubernetes.client import V1DeploymentSpec
from kubernetes.client import V1PodSpec
from kubernetes.client import V1PodTemplateSpec
from salt.exceptions import CommandExecutionError
from salt.modules import config

from saltext.kubernetes.modules import kubernetesmod as kubernetes

# Configure logging
log = logging.getLogger(__name__)


@pytest.fixture()
def configure_loader_modules():
    """
    Configure loader modules for tests.
    """
    return {
        config: {
            "__opts__": {
                "kubernetes.kubeconfig": "/home/testuser/.minikube/kubeconfig.cfg",
                "kubernetes.context": "minikube",
                "extension_modules": "",
                "file_client": "local",
            }
        },
        kubernetes: {
            "__salt__": {
                "config.option": config.option,
                "cp.cache_file": MagicMock(return_value="/tmp/mock_file"),
            },
            "__grains__": {},
            "__pillar__": {},
            "__opts__": {
                "extension_modules": "",
                "file_client": "local",
            },
        },
    }


@pytest.fixture
def mock_kubernetes_lib():
    """
    After fixing the bug in 1c821c0e77de58892c77d8e55386fac25e518c31,
    it caused kubernetes._cleanup() to get called for virtually every
    test, which blows up. This prevents that specific blow-up once
    """
    with patch("saltext.kubernetes.modules.kubernetesmod.kubernetes") as mock_kubernetes_lib:
        yield mock_kubernetes_lib


def test_nodes(mock_kubernetes_lib):
    """
    Test node listing.
    :return:
    """
    mock_kubernetes_lib.client.CoreV1Api.return_value = Mock(
        **{
            "list_node.return_value.to_dict.return_value": {
                "items": [{"metadata": {"name": "mock_node_name"}}]
            }
        }
    )
    assert kubernetes.nodes() == ["mock_node_name"]
    assert kubernetes.kubernetes.client.CoreV1Api().list_node().to_dict.called


def test_deployments(mock_kubernetes_lib):
    """
    Tests deployment listing.
    :return:
    """
    mock_kubernetes_lib.client.AppsV1Api.return_value = Mock(
        **{
            "list_namespaced_deployment.return_value.to_dict.return_value": {
                "items": [{"metadata": {"name": "mock_deployment_name"}}]
            }
        }
    )
    assert kubernetes.deployments() == ["mock_deployment_name"]
    assert kubernetes.kubernetes.client.AppsV1Api().list_namespaced_deployment().to_dict.called


def test_services(mock_kubernetes_lib):
    """
    Tests services listing.
    :return:
    """
    mock_kubernetes_lib.client.CoreV1Api.return_value = Mock(
        **{
            "list_namespaced_service.return_value.to_dict.return_value": {
                "items": [{"metadata": {"name": "mock_service_name"}}]
            }
        }
    )
    assert kubernetes.services() == ["mock_service_name"]
    assert kubernetes.kubernetes.client.CoreV1Api().list_namespaced_service().to_dict.called


def test_pods(mock_kubernetes_lib):
    """
    Tests pods listing.
    :return:
    """
    mock_kubernetes_lib.client.CoreV1Api.return_value = Mock(
        **{
            "list_namespaced_pod.return_value.to_dict.return_value": {
                "items": [{"metadata": {"name": "mock_pod_name"}}]
            }
        }
    )
    assert kubernetes.pods() == ["mock_pod_name"]
    assert kubernetes.kubernetes.client.CoreV1Api().list_namespaced_pod().to_dict.called


def test_delete_deployments(mock_kubernetes_lib):
    """
    Tests deployment deletion
    :return:
    """
    with patch("saltext.kubernetes.modules.kubernetesmod.show_deployment", Mock(return_value=None)):
        mock_kubernetes_lib.client.V1DeleteOptions = Mock(return_value="")
        mock_kubernetes_lib.client.AppsV1Api.return_value = Mock(
            **{"delete_namespaced_deployment.return_value.to_dict.return_value": {"code": 200}}
        )
        assert kubernetes.delete_deployment("test") == {"code": 200}
        assert (
            kubernetes.kubernetes.client.AppsV1Api().delete_namespaced_deployment().to_dict.called
        )


def test_create_deployments(mock_kubernetes_lib):
    """
    Tests deployment creation.
    :return:
    """
    mock_kubernetes_lib.client.V1DeploymentSpec = V1DeploymentSpec
    mock_kubernetes_lib.client.V1PodTemplateSpec = V1PodTemplateSpec
    mock_kubernetes_lib.client.V1PodSpec = V1PodSpec
    mock_kubernetes_lib.client.V1Container = V1Container
    mock_kubernetes_lib.client.AppsV1Api.return_value = Mock(
        **{"create_namespaced_deployment.return_value.to_dict.return_value": {}}
    )
    spec = {
        "template": {
            "metadata": {"labels": {"app": "test"}},
            "spec": {"containers": [{"name": "test-container", "image": "nginx"}]},
        },
        "selector": {"matchLabels": {"app": "test"}},
    }
    assert kubernetes.create_deployment("test", "default", {}, spec, None, None, None) == {}
    assert kubernetes.kubernetes.client.AppsV1Api().create_namespaced_deployment().to_dict.called


def test_setup_kubeconfig_file(mock_kubernetes_lib):
    """
    Test that the `kubernetes.kubeconfig` configuration isn't overwritten
    :return:
    """
    mock_kubernetes_lib.config.load_kube_config = Mock()
    cfg = kubernetes._setup_conn()
    assert config.option("kubernetes.kubeconfig") == cfg["kubeconfig"]


def test_node_labels():
    """
    Test kubernetes.node_labels
    :return:
    """
    with patch("saltext.kubernetes.modules.kubernetesmod.node") as mock_node:
        mock_node.return_value = {
            "metadata": {
                "labels": {
                    "kubernetes.io/hostname": "minikube",
                    "kubernetes.io/os": "linux",
                }
            }
        }
        assert kubernetes.node_labels("minikube") == {
            "kubernetes.io/hostname": "minikube",
            "kubernetes.io/os": "linux",
        }


def test_adding_change_cause_annotation():
    """
    Tests adding a `kubernetes.io/change-cause` annotation just like
    kubectl [apply|create|replace] --record does
    :return:
    """
    with patch(
        "saltext.kubernetes.modules.kubernetesmod.sys.argv", ["/usr/bin/salt-call", "state.apply"]
    ):
        func = getattr(kubernetes, "__dict_to_object_meta")
        data = func(name="test-pod", namespace="test", metadata={})

        assert data.name == "test-pod"
        assert data.namespace == "test"
        assert data.annotations == {"kubernetes.io/change-cause": "/usr/bin/salt-call state.apply"}

        # Ensure any specified annotations aren't overwritten
        test_metadata = {"annotations": {"kubernetes.io/change-cause": "NOPE"}}
        data = func(name="test-pod", namespace="test", metadata=test_metadata)

        assert data.annotations == {"kubernetes.io/change-cause": "NOPE"}


def test_enforce_only_strings_dict():
    """
    Test conversion of dictionary values to strings.
    """
    func = getattr(kubernetes, "__enforce_only_strings_dict")
    data = {
        "unicode": 1,
        2: 2,
    }
    assert func(data) == {"unicode": "1", "2": "2"}


@pytest.mark.parametrize(
    "invalid_spec,expected_error",
    [
        # Missing ports list
        ({"selector": {"app": "nginx"}, "type": "ClusterIP"}, "ports"),
        # Invalid port value type
        (
            {
                "ports": [{"name": "http", "port": "invalid", "targetPort": 80}],
                "selector": {"app": "nginx"},
            },
            "invalid",
        ),
        # Invalid service type
        (
            {
                "ports": [{"name": "http", "port": 80}],
                "selector": {"app": "nginx"},
                "type": "InvalidType",
            },
            "type",
        ),
        # Invalid NodePort value
        (
            {
                "ports": [{"name": "http", "port": 80, "nodePort": 12345}],
                "selector": {"app": "nginx"},
                "type": "NodePort",
            },
            "between 30000-32767",
        ),
        # Invalid ports structure
        ({"ports": "invalid", "selector": {"app": "nginx"}}, "must be a list"),
        # Missing port name in multi-port service
        (
            {"ports": [{"port": 80}, {"port": 443}], "selector": {"app": "nginx"}},
            "must specify 'name'",
        ),
    ],
)
def test_service_validation(mock_kubernetes_lib, invalid_spec, expected_error):
    """Test service validation for different configurations"""
    mock_kubernetes_lib.client.CoreV1Api.return_value = Mock(
        **{"create_namespaced_service.return_value.to_dict.return_value": {}}
    )

    with pytest.raises(CommandExecutionError, match=expected_error):
        kubernetes.create_service(
            name="test-service",
            namespace="default",
            metadata={},
            spec=invalid_spec,
            source=None,
            template=None,
            saltenv="base",
        )


@pytest.mark.parametrize(
    "invalid_spec,expected_error",
    [
        # Missing template
        ({"selector": {"matchLabels": {"app": "nginx"}}}, "template"),
        # Invalid replicas type
        (
            {
                "replicas": "invalid",
                "selector": {"matchLabels": {"app": "nginx"}},
                "template": {
                    "metadata": {"labels": {"app": "nginx"}},
                    "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
                },
            },
            "invalid",
        ),
        # Invalid template spec (missing container image)
        (
            {
                "selector": {"matchLabels": {"app": "nginx"}},
                "template": {
                    "metadata": {"labels": {"app": "nginx"}},
                    "spec": {"containers": [{"name": "nginx"}]},
                },
            },
            "image",
        ),
    ],
)
def test_deployment_invalid_spec(mock_kubernetes_lib, invalid_spec, expected_error):
    """Test creating a deployment with invalid spec raises appropriate error"""
    mock_kubernetes_lib.client.AppsV1Api.return_value = Mock(
        **{"create_namespaced_deployment.return_value.to_dict.return_value": {}}
    )

    with patch(
        "saltext.kubernetes.modules.kubernetesmod.__dict_to_deployment_spec"
    ) as mock_spec_creator:
        mock_spec_creator.side_effect = CommandExecutionError(
            f"Invalid Deployment spec: {expected_error}"
        )

        with pytest.raises(CommandExecutionError, match=expected_error):
            kubernetes.create_deployment(
                name="test-deployment",
                namespace="default",
                metadata={},
                spec=invalid_spec,
                source=None,
                template=None,
                saltenv="base",
            )


@pytest.mark.parametrize(
    "invalid_spec,expected_error",
    [
        # Missing containers list
        ({}, "containers"),
        # Empty containers list
        ({"containers": []}, "containers"),
        # Missing required container name
        ({"containers": [{"image": "nginx:latest"}]}, "name"),
        # Missing required container image
        ({"containers": [{"name": "nginx"}]}, "image"),
        # Invalid container port type
        (
            {
                "containers": [
                    {
                        "name": "nginx",
                        "image": "nginx:latest",
                        "ports": [{"containerPort": "invalid"}],
                    }
                ]
            },
            "invalid",
        ),
        # Invalid port structure
        ({"containers": [{"name": "nginx", "image": "nginx:latest", "ports": "invalid"}]}, "ports"),
    ],
)
def test_pod_with_invalid_spec(mock_kubernetes_lib, invalid_spec, expected_error):
    """Test creating a pod with invalid spec raises appropriate error"""
    mock_kubernetes_lib.client.CoreV1Api.return_value = Mock(
        **{"create_namespaced_pod.return_value.to_dict.return_value": {}}
    )

    with patch("saltext.kubernetes.modules.kubernetesmod.__dict_to_pod_spec") as mock_spec_creator:
        mock_spec_creator.side_effect = CommandExecutionError(f"Invalid Pod spec: {expected_error}")

        with pytest.raises(CommandExecutionError, match=expected_error):
            kubernetes.create_pod(
                name="test-pod",
                namespace="default",
                metadata={},
                spec=invalid_spec,
                source=None,
                template=None,
                saltenv="base",
                wait=True,
            )
