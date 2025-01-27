import logging
import sys
import time

import pytest
from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Only run on Linux platforms")


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
def kubernetes(modules):
    """
    Return the kubernetes execution module
    """
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


def test_namespace_lifecycle(kubernetes, caplog):
    """Test the complete lifecycle of a namespace"""
    caplog.set_level(logging.INFO)
    test_ns = "salt-test-namespace-lifecycle"

    # Ensure namespace doesn't exist
    result = kubernetes.show_namespace(test_ns)
    assert result is None, f"Namespace {test_ns} already exists"

    # Create namespace
    result = kubernetes.create_namespace(test_ns)
    assert isinstance(result, dict)
    assert result["metadata"]["name"] == test_ns

    # Show namespace details
    result = kubernetes.show_namespace(test_ns)
    assert isinstance(result, dict)
    assert result["metadata"]["name"] == test_ns
    assert result["status"]["phase"] == "Active"

    # List namespaces and verify ours exists
    result = kubernetes.namespaces()
    assert isinstance(result, list)
    assert test_ns in result

    # Delete namespace - just verify it's accepted
    result = kubernetes.delete_namespace(test_ns)
    assert isinstance(result, dict)
    assert "kind" in result
    assert result["kind"] == "Namespace"  # Verify it's a namespace response

    # Verify namespace is gone with retry
    for _ in range(5):
        result = kubernetes.show_namespace(test_ns)
        if result is None:
            break
        time.sleep(2)
    assert result is None, f"Namespace {test_ns} still exists after deletion"


def test_show_nonexistent_namespace(kubernetes, caplog):
    """
    Test showing a namespace that doesn't exist returns None
    """
    caplog.set_level(logging.INFO)
    test_ns = "salt-test-nonexistent-ns"

    result = kubernetes.show_namespace(test_ns)
    assert result is None


def test_create_namespace_twice(kubernetes, caplog):
    """
    Test creating a namespace that already exists raises the appropriate error
    """
    caplog.set_level(logging.INFO)
    test_ns = "salt-test-duplicate-ns"

    # Create namespace first time
    result = kubernetes.create_namespace(test_ns)
    assert isinstance(result, dict)
    assert result["metadata"]["name"] == test_ns

    # Attempt to create same namespace again
    with pytest.raises(CommandExecutionError) as exc:
        kubernetes.create_namespace(test_ns)
    assert "already exists" in str(exc.value)

    # Cleanup
    kubernetes.delete_namespace(test_ns)


def test_delete_nonexistent_namespace(kubernetes, caplog):
    """
    Test deleting a namespace that doesn't exist returns None
    """
    caplog.set_level(logging.INFO)
    test_ns = "salt-test-nonexistent-ns"

    result = kubernetes.delete_namespace(test_ns)
    assert result is None


def test_create_namespace_with_invalid_name(kubernetes, caplog):
    """
    Test creating a namespace with an invalid name raises appropriate error
    Names must be lowercase RFC 1123 labels (no underscores or uppercase)
    """
    caplog.set_level(logging.INFO)
    invalid_names = [
        "UPPERCASE",
        "under_score",
        "special@char",
        "-startwithdash",
        "endwithdash-",
        "a" * 254,  # Too long
    ]

    for name in invalid_names:
        with pytest.raises(CommandExecutionError) as exc:
            kubernetes.create_namespace(name)
        assert "Invalid" in str(exc.value)


def test_namespace_without_required_fields(kubernetes, caplog):
    """
    Test delete/show namespace without providing name parameter raises error
    """
    caplog.set_level(logging.INFO)

    with pytest.raises(TypeError):
        kubernetes.delete_namespace()

    with pytest.raises(TypeError):
        kubernetes.show_namespace()


def test_delete_system_namespace(kubernetes, caplog):
    """
    Test attempting to delete protected system namespaces raises error
    """
    caplog.set_level(logging.INFO)
    protected_namespaces = ["default", "kube-system", "kube-public"]

    for namespace in protected_namespaces:
        with pytest.raises(CommandExecutionError) as exc:
            kubernetes.delete_namespace(namespace)
        assert "forbidden" in str(exc.value).lower()


def test_list_namespaces_filtering(kubernetes, caplog):
    """
    Test listing namespaces shows newly created ones
    and doesn't show deleted ones after deletion
    """
    caplog.set_level(logging.INFO)
    test_ns = "salt-test-filtering"

    # Create namespace and verify it appears in list
    kubernetes.create_namespace(test_ns)
    time.sleep(2)  # Longer wait for creation

    # Multiple retries for namespace to appear
    for _ in range(5):
        updated_namespaces = set(kubernetes.namespaces())
        if test_ns in updated_namespaces:
            break
        time.sleep(2)
    else:
        pytest.fail("Namespace never appeared in listing")

    # Delete namespace and wait for removal
    kubernetes.delete_namespace(test_ns)
    time.sleep(2)  # Longer wait for deletion

    # Multiple retries for namespace to disappear
    for _ in range(5):
        final_namespaces = set(kubernetes.namespaces())
        if test_ns not in final_namespaces:
            break
        time.sleep(2)
    else:
        pytest.fail("Namespace never disappeared from listing")


def test_secret_lifecycle(kubernetes, caplog):
    """Test the complete lifecycle of a secret with both plain text and pre-encoded values"""
    caplog.set_level(logging.INFO)
    test_secret = "salt-test-secret-lifecycle"
    namespace = "default"

    # Clean up any existing secret first
    kubernetes.delete_secret(test_secret, namespace)
    # Wait for deletion to complete
    for _ in range(5):
        if not kubernetes.show_secret(test_secret, namespace):
            break
        time.sleep(1)

    # Test data - plain text
    plain_text_data = {"username": "admin", "password": "secret123"}

    # Test data - pre-encoded
    encoded_data = {"token": "bGV0bWVpbg=="}  # "letmein" base64 encoded

    # Create secret with plain text values
    result = kubernetes.create_secret(test_secret, namespace=namespace, data=plain_text_data)
    assert isinstance(result, dict)
    assert result["metadata"]["name"] == test_secret

    # Wait for secret to be accessible
    for _ in range(5):
        if kubernetes.show_secret(test_secret, namespace):
            break
        time.sleep(1)
    else:
        pytest.fail("Secret was not created")

    # Verify values are properly encoded/decoded
    result = kubernetes.show_secret(test_secret, namespace, decode=True)
    assert result["data"]["username"] == "admin"
    assert result["data"]["password"] == "secret123"

    # Replace with pre-encoded values
    result = kubernetes.replace_secret(test_secret, namespace=namespace, data=encoded_data)
    assert isinstance(result, dict)

    # Verify pre-encoded values
    result = kubernetes.show_secret(test_secret, namespace, decode=True)
    assert result["data"]["token"] == "letmein"

    # Delete secret
    result = kubernetes.delete_secret(test_secret, namespace)
    assert isinstance(result, dict)

    # Verify secret is gone with retry
    for _ in range(5):
        if not kubernetes.show_secret(test_secret, namespace):
            break
        time.sleep(1)
    else:
        pytest.fail("Secret was not deleted")


def test_create_secret_inputs(kubernetes, caplog):
    """Test creating secrets with different input formats"""
    caplog.set_level(logging.INFO)
    namespace = "default"

    test_cases = [
        {
            "name": "salt-test-plaintext",
            "data": {"key": "value"},  # Plain text
            "expected": "value",
        },
        {
            "name": "salt-test-preencoded",
            "data": {"key": "dmFsdWU="},  # "value" pre-encoded
            "expected": "value",
        },
    ]

    for case in test_cases:
        # Clean up any existing secret first
        kubernetes.delete_secret(case["name"], namespace)
        # Wait for deletion to complete
        for _ in range(5):
            if not kubernetes.show_secret(case["name"], namespace):
                break
            time.sleep(1)

        # Create secret
        result = kubernetes.create_secret(case["name"], namespace=namespace, data=case["data"])
        assert isinstance(result, dict)
        assert result["metadata"]["name"] == case["name"]

        # Wait for secret to be accessible
        for _ in range(5):
            if kubernetes.show_secret(case["name"], namespace):
                break
            time.sleep(1)
        else:
            pytest.fail(f"Secret {case['name']} was not created")

        # Verify decoded value
        result = kubernetes.show_secret(case["name"], namespace, decode=True)
        assert result["data"]["key"] == case["expected"]

        # Cleanup
        kubernetes.delete_secret(case["name"], namespace)


def test_create_secret_twice(kubernetes, caplog):
    """Test creating a secret that already exists raises appropriate error"""
    caplog.set_level(logging.INFO)
    test_secret = "salt-test-duplicate-secret"
    data = {"key": "value"}

    # Create secret first time
    result = kubernetes.create_secret(test_secret, data=data)
    assert isinstance(result, dict)
    assert result["metadata"]["name"] == test_secret

    # Attempt to create same secret again
    with pytest.raises(CommandExecutionError) as exc:
        kubernetes.create_secret(test_secret, data=data)
    assert "already exists" in str(exc.value)

    # Cleanup
    kubernetes.delete_secret(test_secret)


def test_delete_nonexistent_secret(kubernetes, caplog):
    """Test deleting a secret that doesn't exist returns None"""
    caplog.set_level(logging.INFO)
    result = kubernetes.delete_secret("salt-test-nonexistent-secret")
    assert result is None


def test_secret_type_preservation(kubernetes, caplog):
    """Test that secret types are preserved during replace operations"""
    caplog.set_level(logging.INFO)
    test_secret = "salt-test-typed-secret"

    # Create secret with Opaque type (default)
    kubernetes.create_secret(test_secret, data={"key": "value"})
    result = kubernetes.show_secret(test_secret)
    assert result["type"] == "Opaque"

    # Replace secret and verify type remains
    kubernetes.replace_secret(test_secret, data={"newkey": "newvalue"})
    result = kubernetes.show_secret(test_secret)
    assert result["type"] == "Opaque"

    # Cleanup
    kubernetes.delete_secret(test_secret)


def test_secret_types(kubernetes, caplog):
    """Test creating and replacing secrets with different types"""
    caplog.set_level(logging.INFO)
    test_cases = [
        {
            "name": "salt-test-opaque-secret",
            "type": "Opaque",
            "data": {"key": "value"},
            "replace_data": {"newkey": "newvalue"},
        },
        {
            "name": "salt-test-dockerconfig",
            "type": "kubernetes.io/dockerconfigjson",
            "data": {
                ".dockerconfigjson": '{"auths":{"registry.example.com":{"username":"user","password":"pass"}}}'
            },
            "replace_data": {
                ".dockerconfigjson": '{"auths":{"registry.example.com":{"username":"newuser","password":"newpass"}}}'
            },
        },
        {
            "name": "salt-test-basic-auth",
            "type": "kubernetes.io/basic-auth",
            "data": {"username": "admin", "password": "secret"},
            "replace_data": {"username": "newadmin", "password": "newsecret"},
        },
        {
            "name": "salt-test-tls",
            "type": "kubernetes.io/tls",
            "data": {
                "tls.crt": "-----BEGIN CERTIFICATE-----\nMIICwjCCAaqgAwIBAgIBADANBgkqhkiG9w0BAQsFADAS\n-----END CERTIFICATE-----",
                "tls.key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEA\n-----END PRIVATE KEY-----",
            },
            "replace_data": {
                "tls.crt": "-----BEGIN CERTIFICATE-----\nNew Certificate\n-----END CERTIFICATE-----",
                "tls.key": "-----BEGIN PRIVATE KEY-----\nNew Key\n-----END PRIVATE KEY-----",
            },
        },
    ]

    namespace = "default"

    for case in test_cases:
        # Clean up any existing secret
        kubernetes.delete_secret(case["name"], namespace)
        for _ in range(5):
            if not kubernetes.show_secret(case["name"], namespace):
                break
            time.sleep(1)

        try:
            # Create secret directly first
            result = kubernetes.create_secret(
                case["name"], namespace=namespace, data=case["data"], type=case["type"]
            )
            assert isinstance(result, dict)
            assert result["metadata"]["name"] == case["name"]

            # Verify secret was created with correct type
            secret = kubernetes.show_secret(case["name"], namespace)
            assert secret is not None, f"Secret {case['name']} was not created"
            assert secret["type"] == case["type"]

            # Verify data
            result = kubernetes.show_secret(case["name"], namespace, decode=True)
            assert result is not None
            for key, value in case["data"].items():
                assert result["data"][key] == value

            # Replace secret with new data
            result = kubernetes.replace_secret(
                case["name"], namespace=namespace, data=case["replace_data"], type=case["type"]
            )

            # Verify type was preserved
            secret = kubernetes.show_secret(case["name"], namespace)
            assert secret is not None
            assert secret["type"] == case["type"]

        finally:
            kubernetes.delete_secret(case["name"], namespace)


def test_secret_validation(kubernetes, caplog):
    """Test secret validation for different types"""
    caplog.set_level(logging.INFO)
    namespace = "default"

    # Test docker registry secret without required key
    with pytest.raises(CommandExecutionError) as exc:
        kubernetes.create_secret(
            "invalid-docker-secret",
            namespace=namespace,
            data={"wrong-key": "value"},
            type="kubernetes.io/dockerconfigjson",
        )
    assert ".dockerconfigjson" in str(exc.value)

    # Test TLS secret with missing required keys
    with pytest.raises(CommandExecutionError) as exc:
        kubernetes.create_secret(
            "invalid-tls-secret",
            namespace=namespace,
            data={"missing": "keys"},
            type="kubernetes.io/tls",
        )
    assert "tls.crt" in str(exc.value) or "tls.key" in str(exc.value)


def test_pod_lifecycle(kubernetes, caplog):
    """Test the complete lifecycle of a pod"""
    caplog.set_level(logging.INFO)
    test_pod = "salt-test-pod-lifecycle"
    namespace = "default"

    # Pod spec for nginx
    pod_spec = {
        "containers": [
            {
                "name": "nginx",
                "image": "nginx:latest",
                "ports": [{"containerPort": 80}],  # Port is already an integer
            }
        ]
    }

    # Create pod
    result = kubernetes.create_pod(
        name=test_pod,
        namespace=namespace,
        metadata={},
        spec=pod_spec,
        source=None,
        template=None,
        saltenv="base",
    )
    assert isinstance(result, dict)
    assert result["metadata"]["name"] == test_pod

    # Wait for pod to be accessible
    for _ in range(5):
        if kubernetes.show_pod(test_pod, namespace):
            break
        time.sleep(2)
    else:
        pytest.fail("Pod was not created")

    # Show pod details
    result = kubernetes.show_pod(test_pod, namespace)
    assert isinstance(result, dict)
    assert result["metadata"]["name"] == test_pod
    assert result["spec"]["containers"][0]["name"] == "nginx"

    # List pods and verify ours exists
    result = kubernetes.pods(namespace=namespace)
    assert isinstance(result, list)
    assert test_pod in result

    # Delete pod
    result = kubernetes.delete_pod(test_pod, namespace)
    assert isinstance(result, dict)

    # Verify pod is gone with retry
    for _ in range(5):
        if not kubernetes.show_pod(test_pod, namespace):
            break
        time.sleep(5)
    else:
        pytest.fail("Pod still exists after deletion")


def test_show_nonexistent_pod(kubernetes, caplog):
    """Test showing a pod that doesn't exist returns None"""
    caplog.set_level(logging.INFO)
    test_pod = "salt-test-nonexistent-pod"

    result = kubernetes.show_pod(test_pod)
    assert result is None


def test_delete_nonexistent_pod(kubernetes, caplog):
    """Test deleting a pod that doesn't exist returns None"""
    caplog.set_level(logging.INFO)
    test_pod = "salt-test-nonexistent-pod"

    result = kubernetes.delete_pod(test_pod)
    assert result is None


def test_pod_with_invalid_spec(kubernetes, caplog):
    """Test creating a pod with invalid spec raises appropriate error"""
    caplog.set_level(logging.INFO)
    test_pod = "salt-test-invalid-pod"
    namespace = "default"

    invalid_specs = [
        # Missing containers list
        {},
        # Empty containers list
        {"containers": []},
        # Missing required container name
        {"containers": [{"image": "nginx:latest"}]},
        # Missing required container image
        {"containers": [{"name": "nginx"}]},
        # Invalid container port type
        {
            "containers": [
                {"name": "nginx", "image": "nginx:latest", "ports": [{"containerPort": "invalid"}]}
            ]
        },
        # Invalid port structure
        {"containers": [{"name": "nginx", "image": "nginx:latest", "ports": "invalid"}]},
    ]

    for spec in invalid_specs:
        with pytest.raises((CommandExecutionError, ValueError)) as exc:
            kubernetes.create_pod(
                name=test_pod,
                namespace=namespace,
                metadata={},
                spec=spec,
                source=None,
                template=None,
                saltenv="base",
            )
        # Error message should mention validation failure
        assert any(
            x in str(exc.value).lower() for x in ["invalid", "required", "validation", "must"]
        )


def test_list_pods_in_nonexistent_namespace(kubernetes, caplog):
    """Test listing pods in a namespace that doesn't exist returns empty list"""
    caplog.set_level(logging.INFO)
    result = kubernetes.pods(namespace="nonexistent-namespace")
    assert result == []


def test_pod_namespace_required(kubernetes, caplog):
    """Test create/show/delete pod operations require namespace"""
    caplog.set_level(logging.INFO)
    test_pod = "salt-test-pod-namespace"
    pod_spec = {"containers": [{"name": "nginx", "image": "nginx:latest"}]}

    # Create without namespace
    with pytest.raises(TypeError):
        kubernetes.create_pod(
            name=test_pod, metadata={}, spec=pod_spec, source=None, template=None, saltenv="base"
        )

    # Show without namespace
    result = kubernetes.show_pod(test_pod)  # Should use default namespace
    assert result is None

    # Delete without namespace
    result = kubernetes.delete_pod(test_pod)  # Should use default namespace
    assert result is None


def test_deployment_lifecycle(kubernetes, caplog):
    """Test the complete lifecycle of a deployment"""
    caplog.set_level(logging.INFO)
    test_deployment = "salt-test-deployment"
    namespace = "default"

    # Deployment spec for nginx with proper selector and labels
    deployment_spec = {
        "replicas": 2,
        "selector": {"matchLabels": {"app": "nginx"}},
        "template": {
            "metadata": {"labels": {"app": "nginx"}},  # Must match selector.matchLabels
            "spec": {
                "containers": [
                    {"name": "nginx", "image": "nginx:latest", "ports": [{"containerPort": 80}]}
                ],
                "imagePullSecrets": [{"name": "myregistrykey"}],
            },
        },
    }

    # Create deployment
    result = kubernetes.create_deployment(
        name=test_deployment,
        namespace=namespace,
        metadata={},
        spec=deployment_spec,
        source=None,
        template=None,
        saltenv="base",
    )
    assert isinstance(result, dict)
    assert result["metadata"]["name"] == test_deployment

    # Wait for deployment to be accessible
    for _ in range(5):
        if kubernetes.show_deployment(test_deployment, namespace):
            break
        time.sleep(2)
    else:
        pytest.fail("Deployment was not created")

    # Show deployment details
    result = kubernetes.show_deployment(test_deployment, namespace)
    assert isinstance(result, dict)
    assert result["metadata"]["name"] == test_deployment
    assert result["spec"]["replicas"] == 2
    assert result["spec"]["template"]["spec"]["containers"][0]["name"] == "nginx"
    # Verify imagePullSecrets
    assert result["spec"]["template"]["spec"]["image_pull_secrets"][0]["name"] == "myregistrykey"

    # List deployments and verify ours exists
    result = kubernetes.deployments(namespace=namespace)
    assert isinstance(result, list)
    assert test_deployment in result

    # Update deployment
    deployment_spec["replicas"] = 3
    deployment_spec["template"]["spec"]["imagePullSecrets"].append({"name": "additional-key"})
    result = kubernetes.replace_deployment(
        name=test_deployment,
        namespace=namespace,
        metadata={},
        spec=deployment_spec,
        source=None,
        template=None,
        saltenv="base",
    )
    assert isinstance(result, dict)
    assert result["spec"]["replicas"] == 3
    assert len(result["spec"]["template"]["spec"]["image_pull_secrets"]) == 2

    # Delete deployment
    result = kubernetes.delete_deployment(test_deployment, namespace)
    assert isinstance(result, dict)

    # Verify deployment is gone with retry
    for _ in range(5):
        if not kubernetes.show_deployment(test_deployment, namespace):
            break
        time.sleep(2)
    else:
        pytest.fail("Deployment still exists after deletion")


def test_show_nonexistent_deployment(kubernetes, caplog):
    """Test showing a deployment that doesn't exist returns None"""
    caplog.set_level(logging.INFO)
    test_deployment = "salt-test-nonexistent-deployment"

    result = kubernetes.show_deployment(test_deployment)
    assert result is None


def test_delete_nonexistent_deployment(kubernetes, caplog):
    """Test deleting a deployment that doesn't exist returns None"""
    caplog.set_level(logging.INFO)
    test_deployment = "salt-test-nonexistent-deployment"

    result = kubernetes.delete_deployment(test_deployment)
    assert result is None


def test_deployment_invalid_spec(kubernetes, caplog):
    """Test creating a deployment with invalid spec raises appropriate error"""
    caplog.set_level(logging.INFO)
    test_deployment = "salt-test-invalid-deployment"
    namespace = "default"

    invalid_specs = [
        # Missing template
        {"selector": {"matchLabels": {"app": "nginx"}}},
        # Invalid replicas type
        {
            "replicas": "invalid",
            "selector": {"matchLabels": {"app": "nginx"}},
            "template": {
                "metadata": {"labels": {"app": "nginx"}},
                "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
            },
        },
        # Mismatched labels
        {
            "selector": {"matchLabels": {"app": "nginx"}},
            "template": {
                "metadata": {"labels": {"app": "different"}},
                "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
            },
        },
        # Invalid template spec
        {
            "selector": {"matchLabels": {"app": "nginx"}},
            "template": {
                "metadata": {"labels": {"app": "nginx"}},
                "spec": {"containers": [{"name": "nginx"}]},
            },
        },
    ]

    for spec in invalid_specs:
        with pytest.raises((CommandExecutionError, ValueError)) as exc:
            kubernetes.create_deployment(
                name=test_deployment,
                namespace=namespace,
                metadata={},
                spec=spec,
                source=None,
                template=None,
                saltenv="base",
            )
        assert any(x in str(exc.value).lower() for x in ["invalid", "required", "must"])


def test_deployment_namespace_required(kubernetes, caplog):
    """Test create/show/delete deployment operations require namespace"""
    caplog.set_level(logging.INFO)
    test_deployment = "salt-test-deployment-namespace"
    deployment_spec = {
        "selector": {"matchLabels": {"app": "nginx"}},
        "template": {
            "metadata": {"labels": {"app": "nginx"}},
            "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
        },
    }

    # Create without namespace should raise TypeError
    with pytest.raises(TypeError):
        kubernetes.create_deployment(
            name=test_deployment,
            metadata={},
            spec=deployment_spec,
            source=None,
            template=None,
            saltenv="base",
        )

    # Show without namespace should use default namespace
    result = kubernetes.show_deployment(test_deployment)
    assert result is None

    # Delete without namespace should use default namespace
    result = kubernetes.delete_deployment(test_deployment)
    assert result is None


def test_deployment_replace_validation(kubernetes, caplog):
    """Test replacing deployment validates the new spec"""
    caplog.set_level(logging.INFO)
    test_deployment = "salt-test-replace-deployment"
    namespace = "default"

    # Create initial deployment
    initial_spec = {
        "replicas": 1,
        "selector": {"matchLabels": {"app": "nginx"}},
        "template": {
            "metadata": {"labels": {"app": "nginx"}},
            "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
        },
    }

    result = kubernetes.create_deployment(
        name=test_deployment,
        namespace=namespace,
        metadata={},
        spec=initial_spec,
        source=None,
        template=None,
        saltenv="base",
    )
    assert isinstance(result, dict)

    # Try to replace with invalid spec
    invalid_spec = {
        "replicas": "invalid",  # Should be int
        "selector": {"matchLabels": {"app": "nginx"}},
        "template": {
            "metadata": {"labels": {"app": "nginx"}},
            "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
        },
    }

    with pytest.raises((CommandExecutionError, ValueError)) as exc:
        kubernetes.replace_deployment(
            name=test_deployment,
            namespace=namespace,
            metadata={},
            spec=invalid_spec,
            source=None,
            template=None,
            saltenv="base",
        )
    assert any(x in str(exc.value).lower() for x in ["invalid", "type"])

    # Cleanup
    kubernetes.delete_deployment(test_deployment, namespace)


def test_deployment_selector_validation(kubernetes, caplog):
    """Test that deployment selector validation works correctly"""
    caplog.set_level(logging.INFO)
    test_deployment = "salt-test-selector-validation"
    namespace = "default"

    test_cases = [
        # Valid case - selector matches labels
        {
            "spec": {
                "selector": {"matchLabels": {"app": "nginx"}},
                "template": {
                    "metadata": {"labels": {"app": "nginx"}},
                    "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
                },
            },
            "should_succeed": True,
        },
        # Valid case - missing selector but has template labels
        {
            "spec": {
                "template": {
                    "metadata": {"labels": {"app": "nginx"}},
                    "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
                }
            },
            "should_succeed": True,
        },
        # Invalid case - missing selector and template labels
        {
            "spec": {
                "template": {
                    "metadata": {},
                    "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
                }
            },
            "should_succeed": False,
        },
        # Invalid case - selector doesn't match labels
        {
            "spec": {
                "selector": {"matchLabels": {"app": "nginx"}},
                "template": {
                    "metadata": {"labels": {"app": "different"}},
                    "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
                },
            },
            "should_succeed": False,
        },
        # Invalid case - empty selector
        {
            "spec": {
                "selector": {},
                "template": {
                    "metadata": {"labels": {"app": "nginx"}},
                    "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
                },
            },
            "should_succeed": False,
        },
    ]

    for i, test_case in enumerate(test_cases, 1):
        if test_case["should_succeed"]:
            try:
                result = kubernetes.create_deployment(
                    name=f"{test_deployment}-{i}",
                    namespace=namespace,
                    metadata={},
                    spec=test_case["spec"],
                    source=None,
                    template=None,
                    saltenv="base",
                )
                assert isinstance(result, dict)
                # Clean up
                kubernetes.delete_deployment(f"{test_deployment}-{i}", namespace)
            except CommandExecutionError as exc:
                pytest.fail(f"Case {i} should have succeeded but failed: {exc}")
        else:
            with pytest.raises(CommandExecutionError) as exc:
                kubernetes.create_deployment(
                    name=f"{test_deployment}-{i}",
                    namespace=namespace,
                    metadata={},
                    spec=test_case["spec"],
                    source=None,
                    template=None,
                    saltenv="base",
                )
            assert any(x in str(exc.value).lower() for x in ["selector", "labels"])


def test_node_lifecycle(kubernetes, caplog):
    """Test the complete lifecycle of node labels and operations"""
    caplog.set_level(logging.INFO)

    # Get control plane node name
    nodes = kubernetes.nodes()
    assert nodes, "No nodes found in cluster"
    node_name = next(node for node in nodes if "control-plane" in node)

    # Test initial node info
    result = kubernetes.node(node_name)
    assert isinstance(result, dict)
    assert result["metadata"]["name"] == node_name

    # Test node labels
    initial_labels = kubernetes.node_labels(node_name)
    assert isinstance(initial_labels, dict)
    assert "kubernetes.io/hostname" in initial_labels

    # Add a new label
    label_key = "test.salt.label"
    label_value = "value"
    kubernetes.node_add_label(node_name, label_key, label_value)

    # Verify label was added
    updated_labels = kubernetes.node_labels(node_name)
    assert label_key in updated_labels
    assert updated_labels[label_key] == label_value

    # Remove the label
    kubernetes.node_remove_label(node_name, label_key)

    # Verify label was removed
    final_labels = kubernetes.node_labels(node_name)
    assert label_key not in final_labels


def test_node_invalid_operations(kubernetes, caplog):
    """Test invalid node operations"""
    caplog.set_level(logging.INFO)

    # Test nonexistent node
    result = kubernetes.node("nonexistent-node")
    assert result is None

    # Test invalid operations on nonexistent node
    with pytest.raises(CommandExecutionError) as exc:
        kubernetes.node_add_label("nonexistent-node", "test.label", "value")
    assert "not found" in str(exc.value).lower() or "404" in str(exc.value)

    with pytest.raises(CommandExecutionError) as exc:
        kubernetes.node_add_label("nonexistent-node", "invalid label", "value")
    assert any(x in str(exc.value).lower() for x in ["invalid", "not found", "404"])

    # Test node labels on nonexistent node should return empty dict
    result = kubernetes.node_labels("nonexistent-node")
    assert result == {}


def test_node_multi_label_operations(kubernetes, caplog):
    """Test multiple label operations on nodes"""
    caplog.set_level(logging.INFO)

    # Get control plane node name
    nodes = kubernetes.nodes()
    node_name = next(node for node in nodes if "control-plane" in node)

    test_labels = {
        "salt.test/label1": "value1",
        "salt.test/label2": "value2",
        "salt.test/label3": "value3",
    }

    try:
        # Add multiple labels
        for label, value in test_labels.items():
            kubernetes.node_add_label(node_name, label, value)

        # Verify all labels were added
        current_labels = kubernetes.node_labels(node_name)
        for label, value in test_labels.items():
            assert current_labels[label] == value

    finally:
        # Cleanup - remove test labels
        for label in test_labels:
            kubernetes.node_remove_label(node_name, label)


def test_service_lifecycle(kubernetes, caplog):
    """Test the complete lifecycle of a service"""
    caplog.set_level(logging.INFO)
    test_service = "salt-test-service-lifecycle"
    namespace = "default"

    # Service spec with named ports
    service_spec = {
        "ports": [
            {"name": "http", "port": 80, "targetPort": 80},
            {"name": "https", "port": 443, "targetPort": 443},
        ],
        "selector": {"app": "nginx"},
        "type": "ClusterIP",
    }

    # Create service
    result = kubernetes.create_service(
        name=test_service,
        namespace=namespace,
        metadata={},
        spec=service_spec,
        source=None,
        template=None,
        saltenv="base",
    )
    assert isinstance(result, dict)
    assert result["metadata"]["name"] == test_service

    # Wait for service to be accessible
    for _ in range(5):
        if kubernetes.show_service(test_service, namespace):
            break
        time.sleep(1)
    else:
        pytest.fail("Service was not created")

    # Show service details
    result = kubernetes.show_service(test_service, namespace)
    assert isinstance(result, dict)
    assert result["metadata"]["name"] == test_service
    assert len(result["spec"]["ports"]) == 2
    assert result["spec"]["ports"][0]["name"] == "http"
    assert result["spec"]["ports"][0]["port"] == 80
    assert result["spec"]["type"] == "ClusterIP"

    # List services and verify ours exists
    result = kubernetes.services(namespace=namespace)
    assert isinstance(result, list)
    assert test_service in result

    # Delete service
    result = kubernetes.delete_service(test_service, namespace)
    assert isinstance(result, dict)

    # Verify service is gone with retry
    for _ in range(5):
        if not kubernetes.show_service(test_service, namespace):
            break
        time.sleep(1)
    else:
        pytest.fail("Service still exists after deletion")


def test_show_nonexistent_service(kubernetes, caplog):
    """Test showing a service that doesn't exist returns None"""
    caplog.set_level(logging.INFO)
    test_service = "salt-test-nonexistent-service"

    result = kubernetes.show_service(test_service)
    assert result is None


def test_delete_nonexistent_service(kubernetes, caplog):
    """Test deleting a service that doesn't exist returns None"""
    caplog.set_level(logging.INFO)
    test_service = "salt-test-nonexistent-service"

    result = kubernetes.delete_service(test_service)
    assert result is None


def test_service_validation(kubernetes, caplog):
    """Test service validation for different configurations"""
    caplog.set_level(logging.INFO)
    test_service = "salt-test-validation-service"
    namespace = "default"

    invalid_specs = [
        # Missing ports
        {"selector": {"app": "nginx"}, "type": "ClusterIP"},
        # Invalid port type (string instead of int)
        {
            "ports": [{"name": "http", "port": "invalid", "targetPort": 80}],
            "selector": {"app": "nginx"},
        },
        # Invalid service type
        {
            "ports": [{"name": "http", "port": 80}],
            "selector": {"app": "nginx"},
            "type": "InvalidType",
        },
        # Invalid nodePort range
        {
            "ports": [{"name": "http", "port": 80, "nodePort": 12345}],
            "selector": {"app": "nginx"},
            "type": "NodePort",
        },
        # Invalid port structure
        {"ports": "invalid", "selector": {"app": "nginx"}},
        # Missing port name in multi-port service
        {"ports": [{"port": 80}, {"port": 443}], "selector": {"app": "nginx"}},
    ]

    for spec in invalid_specs:
        with pytest.raises(CommandExecutionError) as exc:
            kubernetes.create_service(
                name=test_service,
                namespace=namespace,
                metadata={},
                spec=spec,
                source=None,
                template=None,
                saltenv="base",
            )
        assert any(x in str(exc.value).lower() for x in ["invalid", "required", "must"])


def test_service_different_types(kubernetes, caplog):
    """Test creating services with different types"""
    caplog.set_level(logging.INFO)
    namespace = "default"

    test_cases = [
        {
            "name": "salt-test-clusterip",
            "spec": {"ports": [{"port": 80}], "selector": {"app": "nginx"}, "type": "ClusterIP"},
        },
        {
            "name": "salt-test-nodeport",
            "spec": {
                "ports": [{"port": 80, "nodePort": 30080}],
                "selector": {"app": "nginx"},
                "type": "NodePort",
            },
        },
    ]

    for case in test_cases:
        try:
            # Create service
            result = kubernetes.create_service(
                name=case["name"],
                namespace=namespace,
                metadata={},
                spec=case["spec"],
                source=None,
                template=None,
                saltenv="base",
            )
            assert isinstance(result, dict)
            assert result["metadata"]["name"] == case["name"]
            assert result["spec"]["type"] == case["spec"]["type"]

            # Verify service exists
            service = kubernetes.show_service(case["name"], namespace)
            assert service is not None
            assert service["spec"]["type"] == case["spec"]["type"]

        finally:
            # Cleanup
            kubernetes.delete_service(case["name"], namespace)


def test_configmap_lifecycle(kubernetes, caplog):
    """Test the complete lifecycle of a configmap"""
    caplog.set_level(logging.INFO)
    test_configmap = "salt-test-configmap-lifecycle"
    namespace = "default"

    # Test data
    config_data = {
        "game.properties": "enemies=aliens\nlives=3\nenemies.cheat=true\nenemies.cheat.level=noGoodRotten",
        "user-interface.properties": "color.good=purple\ncolor.bad=yellow\nallow.textmode=true",
    }

    # Create configmap
    result = kubernetes.create_configmap(test_configmap, namespace=namespace, data=config_data)
    assert isinstance(result, dict)
    assert result["metadata"]["name"] == test_configmap

    # Wait for configmap to be accessible
    for _ in range(5):
        if kubernetes.show_configmap(test_configmap, namespace):
            break
        time.sleep(1)
    else:
        pytest.fail("ConfigMap was not created")

    # Verify data
    result = kubernetes.show_configmap(test_configmap, namespace)
    assert isinstance(result, dict)
    assert result["data"] == config_data

    # Update configmap
    updated_data = {
        "game.properties": "enemies=aliens\nlives=5\nenemies.cheat=false",
        "ui.properties": "color.good=blue\ncolor.bad=red",
    }

    result = kubernetes.replace_configmap(test_configmap, namespace=namespace, data=updated_data)
    assert isinstance(result, dict)
    assert result["data"] == updated_data

    # Delete configmap
    result = kubernetes.delete_configmap(test_configmap, namespace)
    assert isinstance(result, dict)

    # Verify configmap is gone with retry
    for _ in range(5):
        if not kubernetes.show_configmap(test_configmap, namespace):
            break
        time.sleep(1)
    else:
        pytest.fail("ConfigMap still exists after deletion")


def test_configmap_validation(kubernetes, caplog):
    """Test configmap validation for different inputs"""
    caplog.set_level(logging.INFO)
    test_configmap = "salt-test-validation-configmap"
    namespace = "default"

    # Test non-string values get converted correctly
    data = {"number": 42, "boolean": True, "list": [1, 2, 3], "dict": {"key": "value"}}
    result = kubernetes.create_configmap(test_configmap, namespace=namespace, data=data)
    assert isinstance(result, dict)
    # Verify all values were converted to strings
    assert isinstance(result["data"], dict)
    for key, value in result["data"].items():
        assert isinstance(key, str)
        assert isinstance(value, str)
    kubernetes.delete_configmap(test_configmap, namespace)

    # Test completely invalid data type
    with pytest.raises(CommandExecutionError):
        kubernetes.create_configmap(test_configmap, namespace=namespace, data="invalid")


def test_configmap_special_data(kubernetes, caplog):
    """Test configmap with special data types and characters"""
    caplog.set_level(logging.INFO)
    test_configmap = "salt-test-special-data"
    namespace = "default"

    # Test with binary-like and special character data
    config_data = {
        "config.yaml": "foo: bar\nkey: value",
        "special.data": "!@#$%^&*()\n\t\r\n",
        "unicode.txt": "Hello 世界",
    }

    # Create configmap
    result = kubernetes.create_configmap(test_configmap, namespace=namespace, data=config_data)
    assert isinstance(result, dict)
    assert result["data"]["config.yaml"] == config_data["config.yaml"]
    assert result["data"]["special.data"] == config_data["special.data"]
    assert result["data"]["unicode.txt"] == config_data["unicode.txt"]

    # Cleanup
    kubernetes.delete_configmap(test_configmap, namespace)


def test_configmap_large_data(kubernetes, caplog):
    """Test configmap with data approaching size limits"""
    caplog.set_level(logging.INFO)
    test_configmap = "salt-test-large-configmap"
    namespace = "default"

    # Create large data (approaching but not exceeding 1MB limit)
    large_data = {"large-file.txt": "x" * 900000}  # 900KB of data

    # Create configmap
    result = kubernetes.create_configmap(test_configmap, namespace=namespace, data=large_data)
    assert isinstance(result, dict)
    assert len(result["data"]["large-file.txt"]) == 900000

    # Cleanup
    kubernetes.delete_configmap(test_configmap, namespace)


def test_configmap_with_special_characters(kubernetes, caplog):
    """Test configmap with special characters in data"""
    caplog.set_level(logging.INFO)
    test_configmap = "salt-test-special-chars"
    namespace = "default"

    special_data = {
        "special.conf": "key=value\n#comment\n$VAR=${OTHER_VAR}\nspecial_chars=!@#$%^&*()",
        "unicode.txt": "Hello 世界",
    }

    # Create configmap
    result = kubernetes.create_configmap(test_configmap, namespace=namespace, data=special_data)
    assert isinstance(result, dict)
    assert result["data"] == special_data

    # Cleanup
    kubernetes.delete_configmap(test_configmap, namespace)
