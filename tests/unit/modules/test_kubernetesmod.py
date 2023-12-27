"""
    :codeauthor: Jochen Breuer <jbreuer@suse.de>
"""
# pylint: disable=no-value-for-parameter
import os
from contextlib import contextmanager
from unittest.mock import Mock
from unittest.mock import patch

import pytest
import salt.utils.files
import salt.utils.platform
from salt.modules import config
from salt.modules import kubernetesmod as kubernetes


pytestmark = [
    pytest.mark.skipif(
        not kubernetes.HAS_LIBS,
        reason="Kubernetes client lib is not installed. Skipping test_kubernetes.py",
    ),
]


@pytest.fixture()
def configure_loader_modules():
    return {
        config: {
            "__opts__": {
                "kubernetes.kubeconfig": "/home/testuser/.minikube/kubeconfig.cfg",
                "kubernetes.context": "minikube",
            }
        },
        kubernetes: {
            "__salt__": {
                "config.option": config.option,
            }
        },
    }


@contextmanager
def mock_kubernetes_library():
    """
    After fixing the bug in 1c821c0e77de58892c77d8e55386fac25e518c31,
    it caused kubernetes._cleanup() to get called for virtually every
    test, which blows up. This prevents that specific blow-up once
    """
    with patch("salt.modules.kubernetesmod.kubernetes") as mock_kubernetes_lib:
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
        mock_kubernetes_lib.client.ExtensionsV1beta1Api.return_value = Mock(
            **{
                "list_namespaced_deployment.return_value.to_dict.return_value": {
                    "items": [{"metadata": {"name": "mock_deployment_name"}}]
                }
            }
        )
        assert kubernetes.deployments() == ["mock_deployment_name"]
        # py#int: disable=E1120
        assert (
            kubernetes.kubernetes.client.ExtensionsV1beta1Api()
            .list_namespaced_deployment()
            .to_dict.called
        )


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
        with patch("salt.modules.kubernetesmod.show_deployment", Mock(return_value=None)):
            mock_kubernetes_lib.client.V1DeleteOptions = Mock(return_value="")
            mock_kubernetes_lib.client.ExtensionsV1beta1Api.return_value = Mock(
                **{"delete_namespaced_deployment.return_value.to_dict.return_value": {"code": ""}}
            )
            assert kubernetes.delete_deployment("test") == {"code": 200}
            assert (
                kubernetes.kubernetes.client.ExtensionsV1beta1Api()
                .delete_namespaced_deployment()
                .to_dict.called
            )


def test_create_deployments():
    """
    Tests deployment creation.
    :return:
    """
    with mock_kubernetes_library() as mock_kubernetes_lib:
        mock_kubernetes_lib.client.ExtensionsV1beta1Api.return_value = Mock(
            **{"create_namespaced_deployment.return_value.to_dict.return_value": {}}
        )
        assert kubernetes.create_deployment("test", "default", {}, {}, None, None, None) == {}
        assert (
            kubernetes.kubernetes.client.ExtensionsV1beta1Api()
            .create_namespaced_deployment()
            .to_dict.called
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


def test_setup_kubeconfig_data_overwrite():
    """
    Test that provided `kubernetes.kubeconfig` configuration is overwritten
    by provided kubeconfig_data in the command
    :return:
    """
    with mock_kubernetes_library() as mock_kubernetes_lib:
        mock_kubernetes_lib.config.load_kube_config = Mock()
        cfg = kubernetes._setup_conn(kubeconfig_data="MTIzNDU2Nzg5MAo=", context="newcontext")
        check_path = os.path.join("/tmp", "salt-kubeconfig-")
        if salt.utils.platform.is_windows():
            check_path = os.path.join(os.environ.get("TMP"), "salt-kubeconfig-")
        elif salt.utils.platform.is_darwin():
            check_path = os.path.join(os.environ.get("TMPDIR", "/tmp"), "salt-kubeconfig-")
        assert cfg["kubeconfig"].lower().startswith(check_path.lower())
        assert os.path.exists(cfg["kubeconfig"])
        with salt.utils.files.fopen(cfg["kubeconfig"], "r") as kcfg:
            assert kcfg.read() == "1234567890\n"
        kubernetes._cleanup(**cfg)


def test_node_labels():
    """
    Test kubernetes.node_labels
    :return:
    """
    with patch("salt.modules.kubernetesmod.node") as mock_node:
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
        "salt.modules.kubernetesmod.sys.argv", ["/usr/bin/salt-call", "state.apply"]
    ) as mock_sys:
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
    func = getattr(kubernetes, "__enforce_only_strings_dict")
    data = {
        "unicode": 1,
        2: 2,
    }
    assert func(data) == {"unicode": "1", "2": "2"}
