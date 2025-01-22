"""
    :codeauthor: Jochen Breuer <jbreuer@suse.de>
"""

import logging
import logging.handlers

# pylint: disable=no-value-for-parameter
from contextlib import contextmanager
from unittest.mock import MagicMock
from unittest.mock import Mock
from unittest.mock import mock_open
from unittest.mock import patch

import pytest
from kubernetes.client import V1Container
from kubernetes.client import V1DeploymentSpec
from kubernetes.client import V1PodSpec
from kubernetes.client import V1PodTemplateSpec
from salt.modules import config

from saltext.kubernetes.modules import kubernetesmod as kubernetes

# Configure logging
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# Disable logging for tests
logging.disable(logging.CRITICAL)


@pytest.fixture(autouse=True)
def setup_test_environment():
    """Configure test environment setup and cleanup"""
    # Store existing handlers
    root_logger = logging.getLogger()
    existing_handlers = root_logger.handlers[:]

    # Remove all handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add a null handler during tests
    null_handler = logging.NullHandler()
    root_logger.addHandler(null_handler)

    yield

    # Cleanup
    root_logger.removeHandler(null_handler)

    # Restore original handlers
    for handler in existing_handlers:
        root_logger.addHandler(handler)


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
                "cachedir": "/tmp/salt-test-cache",
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
                "cachedir": "/tmp/salt-test-cache",
                "extension_modules": "",
                "file_client": "local",
            },
            "__context__": {},
        },
    }


@contextmanager
def mock_kubernetes_library():
    """
    After fixing the bug in 1c821c0e77de58892c77d8e55386fac25e518c31,
    it caused kubernetes._cleanup() to get called for virtually every
    test, which blows up. This prevents that specific blow-up once
    """
    with patch("saltext.kubernetes.modules.kubernetesmod.kubernetes") as mock_kubernetes_lib:
        yield mock_kubernetes_lib


def test_nodes():
    """
    Test node listing.
    :return:
    """
    with mock_kubernetes_library() as mock_kubernetes_lib:
        mock_kubernetes_lib.client.CoreV1Api.return_value = Mock(
            **{
                "list_node.return_value.to_dict.return_value": {
                    "items": [{"metadata": {"name": "mock_node_name"}}]
                }
            }
        )
        assert kubernetes.nodes() == ["mock_node_name"]
        assert kubernetes.kubernetes.client.CoreV1Api().list_node().to_dict.called


def test_deployments():
    """
    Tests deployment listing.
    :return:
    """
    with mock_kubernetes_library() as mock_kubernetes_lib:
        mock_kubernetes_lib.client.AppsV1Api.return_value = Mock(
            **{
                "list_namespaced_deployment.return_value.to_dict.return_value": {
                    "items": [{"metadata": {"name": "mock_deployment_name"}}]
                }
            }
        )
        assert kubernetes.deployments() == ["mock_deployment_name"]
        # py#int: disable=E1120
        assert kubernetes.kubernetes.client.AppsV1Api().list_namespaced_deployment().to_dict.called


def test_services():
    """
    Tests services listing.
    :return:
    """
    with mock_kubernetes_library() as mock_kubernetes_lib:
        mock_kubernetes_lib.client.CoreV1Api.return_value = Mock(
            **{
                "list_namespaced_service.return_value.to_dict.return_value": {
                    "items": [{"metadata": {"name": "mock_service_name"}}]
                }
            }
        )
        assert kubernetes.services() == ["mock_service_name"]
        assert kubernetes.kubernetes.client.CoreV1Api().list_namespaced_service().to_dict.called


def test_pods():
    """
    Tests pods listing.
    :return:
    """
    with mock_kubernetes_library() as mock_kubernetes_lib:
        mock_kubernetes_lib.client.CoreV1Api.return_value = Mock(
            **{
                "list_namespaced_pod.return_value.to_dict.return_value": {
                    "items": [{"metadata": {"name": "mock_pod_name"}}]
                }
            }
        )
        assert kubernetes.pods() == ["mock_pod_name"]
        assert kubernetes.kubernetes.client.CoreV1Api().list_namespaced_pod().to_dict.called


def test_delete_deployments():
    """
    Tests deployment deletion
    :return:
    """
    with mock_kubernetes_library() as mock_kubernetes_lib:
        with patch(
            "saltext.kubernetes.modules.kubernetesmod.show_deployment", Mock(return_value=None)
        ):
            mock_kubernetes_lib.client.V1DeleteOptions = Mock(return_value="")
            mock_kubernetes_lib.client.AppsV1Api.return_value = Mock(
                **{"delete_namespaced_deployment.return_value.to_dict.return_value": {"code": ""}}
            )
            assert kubernetes.delete_deployment("test") == {"code": 200}
            assert (
                kubernetes.kubernetes.client.AppsV1Api()
                .delete_namespaced_deployment()
                .to_dict.called
            )


def test_create_deployments():
    """
    Tests deployment creation.
    :return:
    """
    with mock_kubernetes_library() as mock_kubernetes_lib:
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
        assert (
            kubernetes.kubernetes.client.AppsV1Api().create_namespaced_deployment().to_dict.called
        )


def test_setup_kubeconfig_file():
    """
    Test that the `kubernetes.kubeconfig` configuration isn't overwritten
    :return:
    """
    with mock_kubernetes_library() as mock_kubernetes_lib:
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


def test_create_deployment_with_context():
    """
    Test deployment creation with template context using actual YAML file
    """
    mock_template_data = {
        "result": True,
        "data": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deploy
spec:
  replicas: 3
  selector:
    matchLabels:
      app: test-deploy
  template:
    metadata:
      labels:
        app: test-deploy
    spec:
      containers:
      - name: test-deploy
        image: nginx:latest""",
    }

    mock_file_contents = MagicMock(return_value=mock_template_data["data"])

    with mock_kubernetes_library() as mock_kubernetes_lib:
        mock_kubernetes_lib.client.V1DeploymentSpec = V1DeploymentSpec
        mock_kubernetes_lib.client.V1PodTemplateSpec = V1PodTemplateSpec
        mock_kubernetes_lib.client.V1PodSpec = V1PodSpec
        mock_kubernetes_lib.client.V1Container = V1Container
        with (
            patch("salt.utils.files.fopen", mock_open(read_data=mock_file_contents())),
            patch(
                "salt.utils.templates.TEMPLATE_REGISTRY",
                {"jinja": MagicMock(return_value=mock_template_data)},
            ),
        ):
            context = {"name": "test-deploy", "replicas": 3, "image": "nginx:latest", "port": 80}
            mock_kubernetes_lib.client.AppsV1Api.return_value = Mock(
                **{"create_namespaced_deployment.return_value.to_dict.return_value": {}}
            )
            ret = kubernetes.create_deployment(
                "test-deploy",
                "default",
                {},
                {},
                "/mock/deployment.yaml",
                "jinja",
                "base",
                context=context,
            )
            assert ret == {}


def test_create_service_with_context():
    """
    Test service creation with template context using actual YAML file
    """
    template_content = """
apiVersion: v1
kind: Service
metadata:
  name: {{ context.name }}
spec:
  ports:
  - port: {{ context.port }}
    targetPort: {{ context.target_port }}
  type: {{ context.type }}
"""
    rendered_content = """
apiVersion: v1
kind: Service
metadata:
  name: test-svc
spec:
  ports:
  - port: 80
    targetPort: 8080
  type: LoadBalancer
"""
    mock_template_data = {"result": True, "data": rendered_content}

    mock_jinja = MagicMock(return_value=mock_template_data)
    template_registry = {"jinja": mock_jinja}

    with mock_kubernetes_library() as mock_kubernetes_lib:
        with (
            patch("salt.utils.files.fopen", mock_open(read_data=template_content)),
            patch("salt.utils.templates.TEMPLATE_REGISTRY", template_registry),
            patch(
                "salt.utils.yaml.safe_load",
                return_value={
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": {"name": "test-svc"},
                    "spec": {"ports": [{"port": 80, "targetPort": 8080}], "type": "LoadBalancer"},
                },
            ),
        ):

            context = {"name": "test-svc", "port": 80, "target_port": 8080, "type": "LoadBalancer"}
            mock_kubernetes_lib.client.CoreV1Api.return_value = Mock(
                **{"create_namespaced_service.return_value.to_dict.return_value": {}}
            )
            ret = kubernetes.create_service(
                "test-svc",
                "default",
                {},
                {},
                "/mock/service.yaml",
                "jinja",
                "base",
                context=context,
            )
            assert ret == {}

            mock_jinja.assert_called_once()
            call_kwargs = mock_jinja.call_args[1]
            assert call_kwargs.get("context") == context

            assert "port: 80" in rendered_content
            assert "targetPort: 8080" in rendered_content
            assert "type: LoadBalancer" in rendered_content
