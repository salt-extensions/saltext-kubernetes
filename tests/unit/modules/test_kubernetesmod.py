"""
:codeauthor: Jochen Breuer <jbreuer@suse.de>
"""

import base64
import logging
import os
import tempfile

# pylint: disable=no-value-for-parameter
from unittest.mock import MagicMock
from unittest.mock import Mock
from unittest.mock import patch

import pytest
from kubernetes.client.rest import ApiException
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


@pytest.fixture
def mock_api():
    """
    Mock kubernetes API connection for testing error handling paths.
    Patches _setup_conn, _cleanup, and the kubernetes client module.
    """
    with patch(
        "saltext.kubernetes.modules.kubernetesmod._setup_conn",
        autospec=True,
        return_value={},
    ):
        with patch("saltext.kubernetes.modules.kubernetesmod._cleanup", autospec=True):
            with patch("saltext.kubernetes.modules.kubernetesmod.kubernetes") as mock_k8s:
                yield mock_k8s


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
        **{"create_namespaced_service.return_value": Mock()}
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
            "integer",
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
        # Empty selector
        (
            {
                "selector": {},
                "template": {
                    "metadata": {"labels": {"app": "nginx"}},
                    "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
                },
            },
            "matchLabels",
        ),
        # Mismatched selector labels
        (
            {
                "selector": {"matchLabels": {"app": "different"}},
                "template": {
                    "metadata": {"labels": {"app": "nginx"}},
                    "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
                },
            },
            "must match template",
        ),
        # No template labels and no selector
        (
            {"template": {"spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]}}},
            "labels",
        ),
        # Not a dictionary
        ("not-a-dict", "must be a dictionary"),
    ],
)
def test_deployment_invalid_spec(invalid_spec, expected_error):
    """Test deployment spec validation raises appropriate errors"""
    func = getattr(kubernetes, "__dict_to_deployment_spec")
    with pytest.raises(CommandExecutionError, match=expected_error):
        func(invalid_spec)


@pytest.mark.parametrize(
    "invalid_spec,expected_error",
    [
        # Spec is None
        (None, "cannot be None"),
        # Not a dictionary
        ("not-a-dict", "must be a dictionary"),
        # Missing containers list
        ({}, "container"),
        # Empty containers list
        ({"containers": []}, "container"),
        # Missing required container name
        ({"containers": [{"image": "nginx:latest"}]}, "name"),
        # Missing required container image
        ({"containers": [{"name": "nginx"}]}, "image"),
        # Container not a dictionary
        ({"containers": ["not-a-dict"]}, "must be a dictionary"),
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
            "integer",
        ),
        # Invalid port structure
        (
            {"containers": [{"name": "nginx", "image": "nginx:latest", "ports": "invalid"}]},
            "must be a list",
        ),
        # imagePullSecrets not a list
        (
            {
                "containers": [{"name": "nginx", "image": "nginx:latest"}],
                "imagePullSecrets": "invalid",
            },
            "imagePullSecrets must be a list",
        ),
    ],
)
def test_pod_with_invalid_spec(invalid_spec, expected_error):
    """Test pod spec validation raises appropriate errors"""
    func = getattr(kubernetes, "__dict_to_pod_spec")
    with pytest.raises(CommandExecutionError, match=expected_error):
        func(invalid_spec)


def test_deployments_handles_api_exception(mock_api):
    """
    Test that deployments() handles ApiException properly
    """
    # Simulate API exception (e.g., network error, auth failure)
    mock_api.client.AppsV1Api().list_namespaced_deployment.side_effect = ApiException(
        status=500, reason="Internal Server Error"
    )

    with pytest.raises(CommandExecutionError):
        kubernetes.deployments()


def test_deployments_handles_404_gracefully(mock_api):
    """
    Test that deployments() returns empty list for 404 (namespace not found)
    """
    # Simulate 404 - namespace doesn't exist
    mock_api.client.AppsV1Api().list_namespaced_deployment.side_effect = ApiException(
        status=404, reason="Not Found"
    )

    result = kubernetes.deployments("nonexistent-namespace")
    assert result == []


def test_deployments_handles_empty_response(mock_api):
    """
    Test that deployments() handles response with no items gracefully
    """
    with patch("saltext.kubernetes.modules.kubernetesmod.ApiClient") as mock_api_client_class:
        mock_api_client_instance = Mock()
        mock_api_client_instance.sanitize_for_serialization.return_value = {}
        mock_api_client_class.return_value = mock_api_client_instance

        mock_api.client.AppsV1Api().list_namespaced_deployment.return_value = Mock()

        result = kubernetes.deployments()
        assert result == []


def test_statefulsets_handles_api_exception(mock_api):
    """
    Test that statefulsets() handles ApiException properly
    """
    mock_api.client.AppsV1Api().list_namespaced_stateful_set.side_effect = ApiException(
        status=500, reason="Internal Server Error"
    )

    with pytest.raises(CommandExecutionError):
        kubernetes.statefulsets()


def test_statefulsets_handles_404_gracefully(mock_api):
    """
    Test that statefulsets() returns empty list for 404 (namespace not found)
    """
    mock_api.client.AppsV1Api().list_namespaced_stateful_set.side_effect = ApiException(
        status=404, reason="Not Found"
    )

    result = kubernetes.statefulsets("nonexistent-namespace")
    assert result == []


def test_statefulsets_handles_empty_response(mock_api):
    """
    Test that statefulsets() handles response with no items gracefully
    """
    with patch("saltext.kubernetes.modules.kubernetesmod.ApiClient") as mock_api_client_class:
        mock_api_client_instance = Mock()
        mock_api_client_instance.sanitize_for_serialization.return_value = {}
        mock_api_client_class.return_value = mock_api_client_instance

        mock_api.client.AppsV1Api().list_namespaced_stateful_set.return_value = Mock()

        result = kubernetes.statefulsets()
        assert result == []


def test_replicasets_handles_api_exception(mock_api):
    """
    Test that replicasets() handles ApiException properly
    """
    mock_api.client.AppsV1Api().list_namespaced_replica_set.side_effect = ApiException(
        status=500, reason="Internal Server Error"
    )

    with pytest.raises(CommandExecutionError):
        kubernetes.replicasets()


def test_replicasets_handles_404_gracefully(mock_api):
    """
    Test that replicasets() returns empty list for 404 (namespace not found)
    """
    mock_api.client.AppsV1Api().list_namespaced_replica_set.side_effect = ApiException(
        status=404, reason="Not Found"
    )

    result = kubernetes.replicasets("nonexistent-namespace")
    assert result == []


def test_replicasets_handles_empty_response(mock_api):
    """
    Test that replicasets() handles response with no items gracefully
    """
    with patch("saltext.kubernetes.modules.kubernetesmod.ApiClient") as mock_api_client_class:
        mock_api_client_instance = Mock()
        mock_api_client_instance.sanitize_for_serialization.return_value = {}
        mock_api_client_class.return_value = mock_api_client_instance

        mock_api.client.AppsV1Api().list_namespaced_replica_set.return_value = Mock()

        result = kubernetes.replicasets()
        assert result == []


def test_daemonsets_handles_api_exception(mock_api):
    """
    Test that daemonsets() handles ApiException properly
    """
    mock_api.client.AppsV1Api().list_namespaced_daemon_set.side_effect = ApiException(
        status=500, reason="Internal Server Error"
    )

    with pytest.raises(CommandExecutionError):
        kubernetes.daemonsets()


def test_daemonsets_handles_404_gracefully(mock_api):
    """
    Test that daemonsets() returns empty list for 404 (namespace not found)
    """
    mock_api.client.AppsV1Api().list_namespaced_daemon_set.side_effect = ApiException(
        status=404, reason="Not Found"
    )

    result = kubernetes.daemonsets("nonexistent-namespace")
    assert result == []


def test_daemonsets_handles_empty_response(mock_api):
    """
    Test that daemonsets() handles response with no items gracefully
    """
    with patch("saltext.kubernetes.modules.kubernetesmod.ApiClient") as mock_api_client_class:
        mock_api_client_instance = Mock()
        mock_api_client_instance.sanitize_for_serialization.return_value = {}
        mock_api_client_class.return_value = mock_api_client_instance

        mock_api.client.AppsV1Api().list_namespaced_daemon_set.return_value = Mock()

        result = kubernetes.daemonsets()
        assert result == []


def test_storageclasses_handles_api_exception(mock_api):
    """
    Test that storageclasses() handles ApiException properly
    """
    mock_api.client.StorageV1Api().list_storage_class.side_effect = ApiException(
        status=500, reason="Internal Server Error"
    )

    with pytest.raises(CommandExecutionError):
        kubernetes.storageclasses()


def test_storageclasses_handles_404_gracefully(mock_api):
    """
    Test that storageclasses() returns empty list for 404
    """
    mock_api.client.StorageV1Api().list_storage_class.side_effect = ApiException(
        status=404, reason="Not Found"
    )

    result = kubernetes.storageclasses()
    assert result == []


def test_storageclasses_handles_empty_response(mock_api):
    """
    Test that storageclasses() handles response with no items gracefully
    """
    with patch("saltext.kubernetes.modules.kubernetesmod.ApiClient") as mock_api_client_class:
        mock_api_client_instance = Mock()
        mock_api_client_instance.sanitize_for_serialization.return_value = {}
        mock_api_client_class.return_value = mock_api_client_instance

        mock_api.client.StorageV1Api().list_storage_class.return_value = Mock()

        result = kubernetes.storageclasses()
        assert result == []


def test_patch_deployment_validates_patch_parameter():
    """
    Test patch_deployment raises error when patch is not a dictionary
    """
    with pytest.raises(CommandExecutionError, match="Patch must be a dictionary"):
        kubernetes.patch_deployment("test", "default", patch="not-a-dict")


def test_patch_statefulset_validates_patch_parameter():
    """
    Test patch_statefulset raises error when patch is not a dictionary
    """
    with pytest.raises(CommandExecutionError, match="Patch must be a dictionary"):
        kubernetes.patch_statefulset("test", "default", patch="not-a-dict")


def test_patch_replicaset_validates_patch_parameter():
    """
    Test patch_replicaset raises error when patch is not a dictionary
    """
    with pytest.raises(CommandExecutionError, match="Patch must be a dictionary"):
        kubernetes.patch_replicaset("test", "default", patch="not-a-dict")


def test_patch_daemonset_validates_patch_parameter():
    """
    Test patch_daemonset raises error when patch is not a dictionary
    """
    with pytest.raises(CommandExecutionError, match="Patch must be a dictionary"):
        kubernetes.patch_daemonset("test", "default", patch="not-a-dict")


def test_patch_storageclass_validates_patch_parameter():
    """
    Test patch_storageclass raises error when patch is not a dictionary
    """
    with pytest.raises(CommandExecutionError, match="Patch must be a dictionary"):
        kubernetes.patch_storageclass("test", patch="not-a-dict")


def test_patch_storageclass_accepts_spec_wrapped_patch(mock_api):
    """
    Test patch_storageclass supports patches with fields nested under `spec`.
    """
    with patch("saltext.kubernetes.modules.kubernetesmod.ApiClient") as mock_api_client_class:
        mock_api_client_instance = Mock()
        mock_api_client_instance.sanitize_for_serialization.return_value = {
            "metadata": {"name": "test"},
            "reclaimPolicy": "Retain",
        }
        mock_api_client_class.return_value = mock_api_client_instance

        mock_api.client.StorageV1Api().patch_storage_class.return_value = Mock()

        res = kubernetes.patch_storageclass("test", patch={"spec": {"reclaimPolicy": "Retain"}})
        mock_api.client.StorageV1Api().patch_storage_class.assert_called_once_with(
            "test", {"reclaimPolicy": "Retain"}, dry_run=None
        )
        assert res["reclaimPolicy"] == "Retain"


def test_patch_storageclass_source_flattens_storageclass_object(mock_api):
    """
    Test patch_storageclass source rendering strips object envelope fields.
    """
    with patch("saltext.kubernetes.modules.kubernetesmod.ApiClient") as mock_api_client_class:
        mock_api_client_instance = Mock()
        mock_api_client_instance.sanitize_for_serialization.return_value = {
            "metadata": {"name": "test"},
            "reclaimPolicy": "Retain",
        }
        mock_api_client_class.return_value = mock_api_client_instance

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write("""
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: test
  labels:
    app: storage
provisioner: kubernetes.io/no-provisioner
reclaimPolicy: Retain
""")
            tmpfile = f.name

        try:
            with patch.dict(
                kubernetes.__salt__,
                {"cp.cache_file": MagicMock(return_value=tmpfile)},
            ):
                with patch.dict(kubernetes.__opts__, {"saltenv": "base"}):
                    mock_api.client.StorageV1Api().patch_storage_class.return_value = Mock()

                    kubernetes.patch_storageclass("test", source="salt://storageclass.yml")
        finally:
            os.unlink(tmpfile)

    mock_api.client.StorageV1Api().patch_storage_class.assert_called_once_with(
        "test",
        {
            "metadata": {"labels": {"app": "storage"}},
            "provisioner": "kubernetes.io/no-provisioner",
            "reclaimPolicy": "Retain",
        },
        dry_run=None,
    )


def test_replace_storageclass_includes_resource_version(mock_api):
    """
    Test replace_storageclass includes the current resourceVersion on update.
    """
    with patch("saltext.kubernetes.modules.kubernetesmod.ApiClient") as mock_api_client_class:
        mock_api_client_instance = Mock()
        mock_api_client_instance.sanitize_for_serialization.return_value = {
            "metadata": {"name": "test"}
        }
        mock_api_client_class.return_value = mock_api_client_instance

        current = Mock()
        current.metadata.resource_version = "12345"
        mock_api.client.StorageV1Api().read_storage_class.return_value = current
        mock_api.client.StorageV1Api().replace_storage_class.return_value = Mock()

        kubernetes.replace_storageclass(
            name="test",
            metadata={},
            spec={"provisioner": "kubernetes.io/no-provisioner"},
        )

    replace_call = mock_api.client.StorageV1Api().replace_storage_class.call_args
    assert replace_call.args[0] == "test"
    assert replace_call.args[1].metadata.resource_version == "12345"


def test_patch_deployment_handles_missing_deployment(mock_api):
    """
    Test patch_deployment handles case where deployment doesn't exist
    """
    # Simulate deployment not found
    mock_api.client.AppsV1Api().patch_namespaced_deployment.side_effect = ApiException(
        status=404, reason="Not Found"
    )

    with pytest.raises(CommandExecutionError):
        kubernetes.patch_deployment("nonexistent", "default", patch={"spec": {"replicas": 3}})


def test_patch_statefulset_handles_missing_statefulset(mock_api):
    """
    Test patch_statefulset handles case where statefulset doesn't exist
    """
    mock_api.client.AppsV1Api().patch_namespaced_stateful_set.side_effect = ApiException(
        status=404, reason="Not Found"
    )

    with pytest.raises(CommandExecutionError):
        kubernetes.patch_statefulset("nonexistent", "default", patch={"spec": {"replicas": 3}})


def test_patch_replicaset_handles_missing_replicaset(mock_api):
    """
    Test patch_replicaset handles case where replicaset doesn't exist
    """
    mock_api.client.AppsV1Api().patch_namespaced_replica_set.side_effect = ApiException(
        status=404, reason="Not Found"
    )

    with pytest.raises(CommandExecutionError):
        kubernetes.patch_replicaset("nonexistent", "default", patch={"spec": {"replicas": 3}})


def test_patch_daemonset_handles_missing_daemonset(mock_api):
    """
    Test patch_daemonset handles case where daemonset doesn't exist
    """
    mock_api.client.AppsV1Api().patch_namespaced_daemon_set.side_effect = ApiException(
        status=404, reason="Not Found"
    )

    with pytest.raises(CommandExecutionError):
        kubernetes.patch_daemonset("nonexistent", "default", patch={"spec": {"template": {}}})


def test_patch_storageclass_handles_missing_storageclass(mock_api):
    """
    Test patch_storageclass handles case where storageclass doesn't exist
    """
    mock_api.client.StorageV1Api().patch_storage_class.side_effect = ApiException(
        status=404, reason="Not Found"
    )

    with pytest.raises(CommandExecutionError):
        kubernetes.patch_storageclass("nonexistent", patch={"reclaimPolicy": "Retain"})


def test_delete_deployment_handles_already_deleted(mock_api):
    """
    Test delete_deployment returns None when deployment is already deleted (404)
    """
    mock_api.client.V1DeleteOptions.return_value = MagicMock()
    mock_api.client.AppsV1Api.return_value.delete_namespaced_deployment.side_effect = ApiException(
        status=404, reason="Not Found"
    )
    result = kubernetes.delete_deployment("already-deleted", "default")
    assert result is None


def test_delete_statefulset_handles_already_deleted(mock_api):
    """
    Test delete_statefulset returns None when statefulset is already deleted (404)
    """
    mock_api.client.V1DeleteOptions.return_value = MagicMock()
    mock_api.client.AppsV1Api.return_value.delete_namespaced_stateful_set.side_effect = (
        ApiException(status=404, reason="Not Found")
    )
    result = kubernetes.delete_statefulset("already-deleted", "default")
    assert result is None


def test_delete_replicaset_handles_already_deleted(mock_api):
    """
    Test delete_replicaset returns None when replicaset is already deleted (404)
    """
    mock_api.client.V1DeleteOptions.return_value = MagicMock()
    mock_api.client.AppsV1Api.return_value.delete_namespaced_replica_set.side_effect = ApiException(
        status=404, reason="Not Found"
    )
    result = kubernetes.delete_replicaset("already-deleted", "default")
    assert result is None


def test_delete_daemonset_handles_already_deleted(mock_api):
    """
    Test delete_daemonset returns None when daemonset is already deleted (404)
    """
    mock_api.client.V1DeleteOptions.return_value = MagicMock()
    mock_api.client.AppsV1Api.return_value.delete_namespaced_daemon_set.side_effect = ApiException(
        status=404, reason="Not Found"
    )
    result = kubernetes.delete_daemonset("already-deleted", "default")
    assert result is None


def test_delete_storageclass_handles_already_deleted(mock_api):
    """
    Test delete_storageclass returns None when storageclass is already deleted (404)
    """
    mock_api.client.V1DeleteOptions.return_value = MagicMock()
    mock_api.client.StorageV1Api.return_value.delete_storage_class.side_effect = ApiException(
        status=404, reason="Not Found"
    )
    result = kubernetes.delete_storageclass("already-deleted")
    assert result is None


def test_patch_deployment_handles_source_rendering_error():
    """
    Test patch_deployment handles template rendering errors gracefully
    """
    with patch.dict(
        kubernetes.__salt__,
        {
            "cp.cache_file": MagicMock(return_value=None),
        },
    ):
        with patch.dict(kubernetes.__opts__, {"saltenv": "base"}):
            with pytest.raises(CommandExecutionError, match="Source file.*not found"):
                kubernetes.patch_deployment(
                    "test", "default", patch=None, source="salt://bad-template.yml"
                )


def test_patch_deployment_handles_invalid_yaml():
    """
    Test patch_deployment raises error when source file does not render to a dictionary
    """

    # Create a file with valid YAML that is not a dictionary (a list)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write("- item1\n- item2\n")
        tmpfile = f.name

    try:
        with patch.dict(
            kubernetes.__salt__,
            {
                "cp.cache_file": MagicMock(return_value=tmpfile),
            },
        ):
            with patch.dict(kubernetes.__opts__, {"saltenv": "base"}):
                with pytest.raises(CommandExecutionError, match="did not render to a dictionary"):
                    kubernetes.patch_deployment(
                        "test", "default", patch=None, source="salt://invalid.yml"
                    )
    finally:
        os.unlink(tmpfile)


def test_patch_statefulset_handles_source_rendering_error():
    """
    Test patch_statefulset handles template rendering errors gracefully
    """
    with patch.dict(
        kubernetes.__salt__,
        {
            "cp.cache_file": MagicMock(return_value=None),
        },
    ):
        with patch.dict(kubernetes.__opts__, {"saltenv": "base"}):
            with pytest.raises(CommandExecutionError, match="Source file.*not found"):
                kubernetes.patch_statefulset(
                    "test", "default", patch=None, source="salt://bad-template.yml"
                )


def test_patch_statefulset_handles_invalid_yaml():
    """
    Test patch_statefulset raises error when source file does not render to a dictionary
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write("- item1\n- item2\n")
        tmpfile = f.name

    try:
        with patch.dict(
            kubernetes.__salt__,
            {
                "cp.cache_file": MagicMock(return_value=tmpfile),
            },
        ):
            with patch.dict(kubernetes.__opts__, {"saltenv": "base"}):
                with pytest.raises(CommandExecutionError, match="did not render to a dictionary"):
                    kubernetes.patch_statefulset(
                        "test", "default", patch=None, source="salt://invalid.yml"
                    )
    finally:
        os.unlink(tmpfile)


def test_patch_replicaset_handles_source_rendering_error():
    """
    Test patch_replicaset handles template rendering errors gracefully
    """
    with patch.dict(
        kubernetes.__salt__,
        {
            "cp.cache_file": MagicMock(return_value=None),
        },
    ):
        with patch.dict(kubernetes.__opts__, {"saltenv": "base"}):
            with pytest.raises(CommandExecutionError, match="Source file.*not found"):
                kubernetes.patch_replicaset(
                    "test", "default", patch=None, source="salt://bad-template.yml"
                )


def test_patch_replicaset_handles_invalid_yaml():
    """
    Test patch_replicaset raises error when source file does not render to a dictionary
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write("- item1\n- item2\n")
        tmpfile = f.name

    try:
        with patch.dict(
            kubernetes.__salt__,
            {
                "cp.cache_file": MagicMock(return_value=tmpfile),
            },
        ):
            with patch.dict(kubernetes.__opts__, {"saltenv": "base"}):
                with pytest.raises(CommandExecutionError, match="did not render to a dictionary"):
                    kubernetes.patch_replicaset(
                        "test", "default", patch=None, source="salt://invalid.yml"
                    )
    finally:
        os.unlink(tmpfile)


def test_patch_daemonset_handles_source_rendering_error():
    """
    Test patch_daemonset handles template rendering errors gracefully
    """
    with patch.dict(
        kubernetes.__salt__,
        {
            "cp.cache_file": MagicMock(return_value=None),
        },
    ):
        with patch.dict(kubernetes.__opts__, {"saltenv": "base"}):
            with pytest.raises(CommandExecutionError, match="Source file.*not found"):
                kubernetes.patch_daemonset(
                    "test", "default", patch=None, source="salt://bad-template.yml"
                )


def test_patch_storageclass_handles_source_rendering_error():
    """
    Test patch_storageclass handles template rendering errors gracefully
    """
    with patch.dict(
        kubernetes.__salt__,
        {
            "cp.cache_file": MagicMock(return_value=None),
        },
    ):
        with patch.dict(kubernetes.__opts__, {"saltenv": "base"}):
            with pytest.raises(CommandExecutionError, match="Source file.*not found"):
                kubernetes.patch_storageclass("test", patch=None, source="salt://bad-template.yml")


def test_patch_daemonset_handles_invalid_yaml():
    """
    Test patch_daemonset raises error when source file does not render to a dictionary
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write("- item1\n- item2\n")
        tmpfile = f.name

    try:
        with patch.dict(
            kubernetes.__salt__,
            {
                "cp.cache_file": MagicMock(return_value=tmpfile),
            },
        ):
            with patch.dict(kubernetes.__opts__, {"saltenv": "base"}):
                with pytest.raises(CommandExecutionError, match="did not render to a dictionary"):
                    kubernetes.patch_daemonset(
                        "test", "default", patch=None, source="salt://invalid.yml"
                    )
    finally:
        os.unlink(tmpfile)


def test_patch_storageclass_handles_invalid_yaml():
    """
    Test patch_storageclass raises error when source file does not render to a dictionary
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write("- item1\n- item2\n")
        tmpfile = f.name

    try:
        with patch.dict(
            kubernetes.__salt__,
            {
                "cp.cache_file": MagicMock(return_value=tmpfile),
            },
        ):
            with patch.dict(kubernetes.__opts__, {"saltenv": "base"}):
                with pytest.raises(CommandExecutionError, match="did not render to a dictionary"):
                    kubernetes.patch_storageclass("test", patch=None, source="salt://invalid.yml")
    finally:
        os.unlink(tmpfile)


def test_patch_service_validates_patch_parameter():
    """
    Test patch_service raises error when patch is not a dictionary
    """
    with pytest.raises(CommandExecutionError, match="Patch must be a dictionary"):
        kubernetes.patch_service("test", "default", patch="not-a-dict")


def test_patch_service_handles_missing_service(mock_api):
    """
    Test patch_service handles case where service doesn't exist
    """
    mock_api.client.CoreV1Api().patch_namespaced_service.side_effect = ApiException(
        status=404, reason="Not Found"
    )
    with pytest.raises(CommandExecutionError):
        kubernetes.patch_service("nonexistent", "default", patch={"spec": {"type": "ClusterIP"}})


def test_patch_secret_validates_patch_parameter():
    """
    Test patch_secret raises error when patch is not a dictionary
    """
    with pytest.raises(CommandExecutionError, match="Patch must be a dictionary"):
        kubernetes.patch_secret("test", "default", patch="not-a-dict")


def test_patch_secret_handles_missing_secret(mock_api):
    """
    Test patch_secret handles case where secret doesn't exist
    """
    mock_api.client.CoreV1Api().patch_namespaced_secret.side_effect = ApiException(
        status=404, reason="Not Found"
    )
    with pytest.raises(CommandExecutionError):
        kubernetes.patch_secret("nonexistent", "default", patch={"data": {"key": "val"}})


def test_patch_configmap_validates_patch_parameter():
    """
    Test patch_configmap raises error when patch is not a dictionary
    """
    with pytest.raises(CommandExecutionError, match="Patch must be a dictionary"):
        kubernetes.patch_configmap("test", "default", patch="not-a-dict")


def test_patch_configmap_handles_missing_configmap(mock_api):
    """
    Test patch_configmap handles case where configmap doesn't exist
    """
    mock_api.client.CoreV1Api().patch_namespaced_config_map.side_effect = ApiException(
        status=404, reason="Not Found"
    )
    with pytest.raises(CommandExecutionError):
        kubernetes.patch_configmap("nonexistent", "default", patch={"data": {"key": "val"}})


def test_setup_conn_missing_config():
    """
    Test _setup_conn raises when kubeconfig and context are missing
    """
    with patch.dict(
        kubernetes.__salt__,
        {"config.option": MagicMock(return_value=None)},
    ):
        with pytest.raises(CommandExecutionError, match="Invalid kubernetes configuration"):
            kubernetes._setup_conn()


def test_create_namespace_handles_conflict(mock_api):
    """
    Test create_namespace raises for 409 conflict (already exists)
    """
    mock_api.client.CoreV1Api().create_namespace.side_effect = ApiException(
        status=409, reason="AlreadyExists"
    )
    with pytest.raises(CommandExecutionError, match="already exists"):
        kubernetes.create_namespace("test")


def test_create_namespace_handles_invalid_name(mock_api):
    """
    Test create_namespace raises for 422 (invalid name)
    """
    mock_api.client.CoreV1Api().create_namespace.side_effect = ApiException(
        status=422, reason="Unprocessable Entity"
    )
    with pytest.raises(CommandExecutionError, match="Invalid namespace name"):
        kubernetes.create_namespace("INVALID!")


def test_delete_namespace_handles_forbidden(mock_api):
    """
    Test delete_namespace raises for 403 (RBAC forbidden)
    """
    mock_api.client.CoreV1Api().delete_namespace.side_effect = ApiException(
        status=403, reason="Forbidden"
    )
    with pytest.raises(CommandExecutionError, match="Cannot delete namespace"):
        kubernetes.delete_namespace("kube-system")


def test_delete_namespace_already_deleted(mock_api):
    """
    Test delete_namespace returns None for 404 (already deleted)
    """
    mock_api.client.CoreV1Api().delete_namespace.side_effect = ApiException(
        status=404, reason="Not Found"
    )
    result = kubernetes.delete_namespace("already-gone")
    assert result is None


def test_create_deployment_handles_conflict(mock_api):
    """
    Test create_deployment raises for 409 conflict (already exists)
    """
    with patch(
        "saltext.kubernetes.modules.kubernetesmod.__create_object_body", return_value=MagicMock()
    ):
        mock_api.client.AppsV1Api().create_namespaced_deployment.side_effect = ApiException(
            status=409, reason="AlreadyExists"
        )
        with pytest.raises(CommandExecutionError, match="already exists"):
            kubernetes.create_deployment("test", "default", {}, {}, None, None, None)


def test_create_service_handles_conflict(mock_api):
    """
    Test create_service raises for 409 conflict (already exists)
    """
    with patch(
        "saltext.kubernetes.modules.kubernetesmod.__create_object_body", return_value=MagicMock()
    ):
        mock_api.client.CoreV1Api().create_namespaced_service.side_effect = ApiException(
            status=409, reason="AlreadyExists"
        )
        with pytest.raises(CommandExecutionError, match="already exists"):
            kubernetes.create_service("test", "default", {}, {}, None, None, None)


def test_create_statefulset_handles_conflict(mock_api):
    """
    Test create_statefulset raises for 409 conflict (already exists)
    """
    with patch(
        "saltext.kubernetes.modules.kubernetesmod.__create_object_body", return_value=MagicMock()
    ):
        mock_api.client.AppsV1Api().create_namespaced_stateful_set.side_effect = ApiException(
            status=409, reason="AlreadyExists"
        )
        with pytest.raises(CommandExecutionError, match="already exists"):
            kubernetes.create_statefulset("test", "default", {}, {}, None, None, None)


def test_create_replicaset_handles_conflict(mock_api):
    """
    Test create_replicaset raises for 409 conflict (already exists)
    """
    with patch(
        "saltext.kubernetes.modules.kubernetesmod.__create_object_body", return_value=MagicMock()
    ):
        mock_api.client.AppsV1Api().create_namespaced_replica_set.side_effect = ApiException(
            status=409, reason="AlreadyExists"
        )
        with pytest.raises(CommandExecutionError, match="already exists"):
            kubernetes.create_replicaset("test", "default", {}, {}, None, None, None)


def test_create_daemonset_handles_conflict(mock_api):
    """
    Test create_daemonset raises for 409 conflict (already exists)
    """
    with patch(
        "saltext.kubernetes.modules.kubernetesmod.__create_object_body", return_value=MagicMock()
    ):
        mock_api.client.AppsV1Api().create_namespaced_daemon_set.side_effect = ApiException(
            status=409, reason="AlreadyExists"
        )
        with pytest.raises(CommandExecutionError, match="already exists"):
            kubernetes.create_daemonset("test", "default", {}, {}, None, None, None)


def test_create_storageclass_handles_conflict(mock_api):
    """
    Test create_storageclass raises for 409 conflict (already exists)
    """
    mock_api.client.StorageV1Api().create_storage_class.side_effect = ApiException(
        status=409, reason="AlreadyExists"
    )
    with pytest.raises(CommandExecutionError, match="already exists"):
        kubernetes.create_storageclass(
            "test", metadata={}, spec={"provisioner": "kubernetes.io/no-provisioner"}
        )


def test_patch_deployment_handles_conflict(mock_api):
    """
    Test patch_deployment raises for 409 conflict (concurrent modification)
    """
    mock_api.client.AppsV1Api().patch_namespaced_deployment.side_effect = ApiException(
        status=409, reason="Conflict"
    )
    with pytest.raises(CommandExecutionError, match="Conflict when patching"):
        kubernetes.patch_deployment("test", "default", patch={"spec": {"replicas": 3}})


def test_patch_configmap_handles_conflict(mock_api):
    """
    Test patch_configmap raises for 409 conflict (concurrent modification)
    """
    mock_api.client.CoreV1Api().patch_namespaced_config_map.side_effect = ApiException(
        status=409, reason="Conflict"
    )
    with pytest.raises(CommandExecutionError, match="Conflict when patching"):
        kubernetes.patch_configmap("test", "default", patch={"data": {"key": "val"}})


def test_patch_statefulset_handles_conflict(mock_api):
    """
    Test patch_statefulset raises for 409 conflict (concurrent modification)
    """
    mock_api.client.AppsV1Api().patch_namespaced_stateful_set.side_effect = ApiException(
        status=409, reason="Conflict"
    )
    with pytest.raises(CommandExecutionError, match="Conflict when patching"):
        kubernetes.patch_statefulset("test", "default", patch={"spec": {"replicas": 3}})


def test_patch_replicaset_handles_conflict(mock_api):
    """
    Test patch_replicaset raises for 409 conflict (concurrent modification)
    """
    mock_api.client.AppsV1Api().patch_namespaced_replica_set.side_effect = ApiException(
        status=409, reason="Conflict"
    )
    with pytest.raises(CommandExecutionError, match="Conflict when patching"):
        kubernetes.patch_replicaset("test", "default", patch={"spec": {"replicas": 3}})


def test_patch_daemonset_handles_conflict(mock_api):
    """
    Test patch_daemonset raises for 409 conflict (concurrent modification)
    """
    mock_api.client.AppsV1Api().patch_namespaced_daemon_set.side_effect = ApiException(
        status=409, reason="Conflict"
    )
    with pytest.raises(CommandExecutionError, match="Conflict when patching"):
        kubernetes.patch_daemonset("test", "default", patch={"spec": {"template": {}}})


def test_patch_storageclass_handles_conflict(mock_api):
    """
    Test patch_storageclass raises for 409 conflict (concurrent modification)
    """
    mock_api.client.StorageV1Api().patch_storage_class.side_effect = ApiException(
        status=409, reason="Conflict"
    )
    with pytest.raises(CommandExecutionError, match="Conflict when patching"):
        kubernetes.patch_storageclass("test", patch={"reclaimPolicy": "Retain"})


@pytest.mark.parametrize(
    "invalid_spec,expected_error",
    [
        ({"template": {}}, "serviceName"),
        ({"serviceName": "svc"}, "template"),
        ({"serviceName": "svc", "template": "not-a-dict"}, "Template must be a dictionary"),
        (
            {
                "serviceName": "svc",
                "template": {
                    "metadata": {"labels": {"app": "nginx"}},
                    "spec": {"containers": [{"name": "nginx"}]},
                },
            },
            "Invalid pod spec in statefulset template",
        ),
        (
            {
                "serviceName": "svc",
                "replicas": "invalid",
                "selector": {"matchLabels": {"app": "nginx"}},
                "template": {
                    "metadata": {"labels": {"app": "nginx"}},
                    "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
                },
            },
            "replicas must be an integer",
        ),
        (
            {
                "serviceName": "svc",
                "selector": "invalid",
                "template": {
                    "metadata": {"labels": {"app": "nginx"}},
                    "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
                },
            },
            "Selector must be a dictionary",
        ),
        ("not-a-dict", "must be a dictionary"),
    ],
)
def test_statefulset_invalid_spec(invalid_spec, expected_error):
    """Test statefulset spec validation raises appropriate errors"""
    func = getattr(kubernetes, "__dict_to_statefulset_spec")
    with pytest.raises(CommandExecutionError, match=expected_error):
        func(invalid_spec)


@pytest.mark.parametrize(
    "invalid_spec,expected_error",
    [
        ({"selector": {"matchLabels": {"app": "nginx"}}}, "template"),
        (
            {
                "replicas": "invalid",
                "selector": {"matchLabels": {"app": "nginx"}},
                "template": {
                    "metadata": {"labels": {"app": "nginx"}},
                    "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
                },
            },
            "replicas must be an integer",
        ),
        (
            {
                "selector": {"matchLabels": {"app": "different"}},
                "template": {
                    "metadata": {"labels": {"app": "nginx"}},
                    "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
                },
            },
            "must match template",
        ),
        (
            {"template": {"spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]}}},
            "Template must include labels",
        ),
        ("not-a-dict", "must be a dictionary"),
    ],
)
def test_replicaset_invalid_spec(invalid_spec, expected_error):
    """Test replicaset spec validation raises appropriate errors"""
    func = getattr(kubernetes, "__dict_to_replicaset_spec")
    with pytest.raises(CommandExecutionError, match=expected_error):
        func(invalid_spec)


@pytest.mark.parametrize(
    "invalid_spec,expected_error",
    [
        ({"selector": {"matchLabels": {"app": "nginx"}}}, "template"),
        (
            {
                "selector": {"matchLabels": {"app": "different"}},
                "template": {
                    "metadata": {"labels": {"app": "nginx"}},
                    "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
                },
            },
            "must match template",
        ),
        (
            {"template": {"spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]}}},
            "Template must include labels",
        ),
        ("not-a-dict", "must be a dictionary"),
    ],
)
def test_daemonset_invalid_spec(invalid_spec, expected_error):
    """Test daemonset spec validation raises appropriate errors"""
    func = getattr(kubernetes, "__dict_to_daemonset_spec")
    with pytest.raises(CommandExecutionError, match=expected_error):
        func(invalid_spec)


@pytest.mark.parametrize(
    "invalid_spec,expected_error",
    [
        ({}, "must include provisioner"),
        ({"provisioner": "", "parameters": {}}, "must include provisioner"),
        (
            {"provisioner": "kubernetes.io/no-provisioner", "parameters": "invalid"},
            "parameters must be a dictionary",
        ),
        (
            {"provisioner": "kubernetes.io/no-provisioner", "mountOptions": "invalid"},
            "mountOptions must be a list",
        ),
        (
            {
                "provisioner": "kubernetes.io/no-provisioner",
                "allowedTopologies": "invalid",
            },
            "allowedTopologies must be a list",
        ),
        ("not-a-dict", "must be a dictionary"),
    ],
)
def test_storageclass_invalid_spec(invalid_spec, expected_error):
    """Test storageclass spec validation raises appropriate errors"""
    func = getattr(kubernetes, "__dict_to_storageclass_spec")
    with pytest.raises(CommandExecutionError, match=expected_error):
        func(invalid_spec)


def test_patch_service_handles_source_not_found():
    """
    Test patch_service raises when source file is not found
    """
    with patch.dict(
        kubernetes.__salt__,
        {"cp.cache_file": MagicMock(return_value=None)},
    ):
        with patch.dict(kubernetes.__opts__, {"saltenv": "base"}):
            with pytest.raises(CommandExecutionError, match="Source file.*not found"):
                kubernetes.patch_service("test", "default", patch=None, source="salt://missing.yml")


def test_create_configmap_invalid_data_type():
    """
    Test create_configmap raises when data is not a dictionary
    """
    with pytest.raises(CommandExecutionError, match="Data must be a dictionary"):
        kubernetes.create_configmap("test", "default", data="not-a-dict")


def test_create_configmap_source_missing_data_key():
    """
    Test create_configmap raises when source YAML is missing 'data' key
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write("kind: ConfigMap\nmetadata:\n  name: test\n")
        tmpfile = f.name

    try:
        with patch.dict(
            kubernetes.__salt__,
            {"cp.cache_file": MagicMock(return_value=tmpfile)},
        ):
            with patch.dict(kubernetes.__opts__, {"saltenv": "base"}):
                with pytest.raises(CommandExecutionError, match="data"):
                    kubernetes.create_configmap(
                        "test", "default", data=None, source="salt://test.yml"
                    )
    finally:
        os.unlink(tmpfile)


def test_show_secret_binary_data(mock_api):
    """
    Test show_secret handles binary (non-UTF-8) data in secret values
    """

    binary_value = base64.b64encode(b"\x80\x81\x82\xff").decode("ascii")
    mock_api.client.CoreV1Api().read_namespaced_secret.return_value = Mock()

    with patch("saltext.kubernetes.modules.kubernetesmod.ApiClient") as mock_api_client_class:
        mock_api_client_instance = Mock()
        mock_api_client_instance.sanitize_for_serialization.return_value = {
            "data": {"binary_key": binary_value},
            "metadata": {"name": "test"},
        }
        mock_api_client_class.return_value = mock_api_client_instance

        result = kubernetes.show_secret("test", "default", decode=True)
        assert result is not None
        # The binary data should be returned as raw bytes (not decoded as UTF-8)
        assert result["data"]["binary_key"] == base64.b64decode(binary_value)


def test_source_file_wrong_kind():
    """
    Test __create_object_body raises when source defines wrong kind
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write("kind: Service\nmetadata:\n  name: test\nspec:\n  ports:\n  - port: 80\n")
        tmpfile = f.name

    try:
        with patch.dict(
            kubernetes.__salt__,
            {"cp.cache_file": MagicMock(return_value=tmpfile)},
        ):
            with patch.dict(kubernetes.__opts__, {"saltenv": "base"}):
                func = getattr(kubernetes, "__create_object_body")
                with pytest.raises(CommandExecutionError, match="should define only a"):
                    func(
                        kind="Deployment",
                        obj_class=MagicMock(),
                        spec_creator=MagicMock(),
                        name="test",
                        namespace="default",
                        metadata=None,
                        spec=None,
                        source="salt://wrong-kind.yml",
                        template=None,
                        saltenv="base",
                    )
    finally:
        os.unlink(tmpfile)


def test_read_and_render_yaml_unknown_template():
    """
    Test __read_and_render_yaml_file raises for unknown template type
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write("key: value\n")
        tmpfile = f.name

    try:
        with patch.dict(
            kubernetes.__salt__,
            {"cp.cache_file": MagicMock(return_value=tmpfile)},
        ):
            with patch.dict(kubernetes.__opts__, {"saltenv": "base"}):
                func = getattr(kubernetes, "__read_and_render_yaml_file")
                with pytest.raises(CommandExecutionError, match="Unknown template"):
                    func(
                        source="salt://test.yml",
                        template="nonexistent_engine",
                        saltenv="base",
                    )
    finally:
        os.unlink(tmpfile)
