import logging

import pytest

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms"),
]


def test_deployments(salt_call_cli, kind_cluster):
    """Test creating and deleting a deployment"""
    deployment = {
        "metadata": {
            "name": "test-nginx",
            "namespace": "default",
            "labels": {"app": "test-nginx"},
        },
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "test-nginx"}},
            "template": {
                "metadata": {"labels": {"app": "test-nginx"}},
                "spec": {
                    "containers": [
                        {
                            "name": "nginx",
                            "image": "nginx:latest",
                            "ports": [{"containerPort": 80}],
                        }
                    ]
                },
            },
        },
    }

    # Create deployment
    ret = salt_call_cli.run(
        "kubernetes.create_deployment",
        name=deployment["metadata"]["name"],
        namespace=deployment["metadata"]["namespace"],
        metadata=deployment["metadata"],
        spec=deployment["spec"],
        source="",
        template="",
        saltenv="base",
        wait=True,
    )
    assert ret.returncode == 0
    assert ret.data

    # Verify deployment exists
    ret = salt_call_cli.run(
        "kubernetes.show_deployment",
        name=deployment["metadata"]["name"],
        namespace=deployment["metadata"]["namespace"],
        wait=True,
    )
    assert ret.returncode == 0
    assert ret.data["metadata"]["name"] == deployment["metadata"]["name"]

    # Delete deployment
    ret = salt_call_cli.run(
        "kubernetes.delete_deployment",
        name=deployment["metadata"]["name"],
        namespace=deployment["metadata"]["namespace"],
        wait=True,
    )
    assert ret.returncode == 0
    assert ret.data

    # Verify deployment is gone
    ret = salt_call_cli.run(
        "kubernetes.show_deployment",
        name=deployment["metadata"]["name"],
        namespace=deployment["metadata"]["namespace"],
    )
    assert ret.data is None


def test_namespaces(salt_call_cli, kind_cluster):
    """Test namespace operations"""
    test_ns = "test-namespace"

    try:
        # List namespaces
        ret = salt_call_cli.run("kubernetes.namespaces")
        assert ret.returncode == 0
        assert isinstance(ret.data, list)
        assert "default" in ret.data

        # Create namespace
        ret = salt_call_cli.run("kubernetes.create_namespace", name=test_ns, wait=True)
        assert ret.returncode == 0
        # Verify namespace creation response
        assert isinstance(ret.data, dict)
        assert ret.data.get("metadata", {}).get("name") == test_ns
        assert ret.data.get("kind") == "Namespace"

        # Show namespace
        ret = salt_call_cli.run("kubernetes.show_namespace", name=test_ns)
        assert ret.returncode == 0
        # Verify namespace details
        assert isinstance(ret.data, dict)
        assert ret.data.get("metadata", {}).get("name") == test_ns
        assert ret.data.get("kind") == "Namespace"
        assert ret.data.get("status", {}).get("phase") == "Active"

    finally:
        # Cleanup - delete namespace
        ret = salt_call_cli.run("kubernetes.delete_namespace", name=test_ns, wait=True)
        assert ret.returncode == 0
        assert ret.data

        # Verify namespace is gone
        ret = salt_call_cli.run("kubernetes.show_namespace", name=test_ns)
        assert ret.data is None


def test_pods(salt_call_cli, kind_cluster):
    """Test pod operations"""
    pod = {
        "metadata": {"name": "test-pod", "namespace": "default", "labels": {"app": "test"}},
        "spec": {
            "containers": [
                {"name": "nginx", "image": "nginx:latest", "ports": [{"containerPort": 80}]}
            ]
        },
    }

    # List pods
    ret = salt_call_cli.run("kubernetes.pods")
    assert ret.returncode == 0
    assert isinstance(ret.data, list)

    # Create pod
    ret = salt_call_cli.run(
        "kubernetes.create_pod",
        name=pod["metadata"]["name"],
        namespace=pod["metadata"]["namespace"],
        metadata=pod["metadata"],
        spec=pod["spec"],
        source="",
        template="",
        saltenv="base",
        wait=True,
    )
    assert ret.returncode == 0
    assert ret.data["metadata"]["name"] == pod["metadata"]["name"]

    # Show pod
    ret = salt_call_cli.run(
        "kubernetes.show_pod",
        name=pod["metadata"]["name"],
        namespace=pod["metadata"]["namespace"],
    )
    assert ret.returncode == 0
    assert ret.data["metadata"]["name"] == pod["metadata"]["name"]

    # Delete pod
    ret = salt_call_cli.run(
        "kubernetes.delete_pod",
        name=pod["metadata"]["name"],
        namespace=pod["metadata"]["namespace"],
        wait=True,
    )
    assert ret.returncode == 0

    # # Verify pod is gone
    ret = salt_call_cli.run(
        "kubernetes.show_pod",
        name=pod["metadata"]["name"],
        namespace=pod["metadata"]["namespace"],
    )
    assert ret.data is None


def test_services(salt_call_cli, kind_cluster):
    """Test service operations"""
    service = {
        "metadata": {"name": "test-service", "namespace": "default", "labels": {"app": "test"}},
        "spec": {
            "ports": [{"port": 80, "targetPort": 80, "name": "http"}],
            "selector": {"app": "test"},
            "type": "ClusterIP",
        },
    }

    # List services
    ret = salt_call_cli.run("kubernetes.services")
    assert ret.returncode == 0
    assert isinstance(ret.data, list)

    # Create service
    ret = salt_call_cli.run(
        "kubernetes.create_service",
        name=service["metadata"]["name"],
        namespace=service["metadata"]["namespace"],
        metadata=service["metadata"],
        spec=service["spec"],
        source="",
        template="",
        saltenv="base",
    )
    assert ret.returncode == 0
    assert ret.data["metadata"]["name"] == service["metadata"]["name"]

    # Show service
    ret = salt_call_cli.run(
        "kubernetes.show_service",
        name=service["metadata"]["name"],
        namespace=service["metadata"]["namespace"],
    )
    assert ret.returncode == 0
    assert ret.data["metadata"]["name"] == service["metadata"]["name"]

    # Delete service
    ret = salt_call_cli.run(
        "kubernetes.delete_service",
        name=service["metadata"]["name"],
        namespace=service["metadata"]["namespace"],
    )
    assert ret.returncode == 0
    assert ret.data

    # Verify service is gone
    ret = salt_call_cli.run(
        "kubernetes.show_service",
        name=service["metadata"]["name"],
        namespace=service["metadata"]["namespace"],
    )
    assert ret.data is None


def test_configmaps(salt_call_cli, kind_cluster):
    """Test configmap operations"""
    configmap_data = {
        "config.txt": "some configuration data",
        "other-file.txt": "other configuration data",
    }

    # List configmaps
    ret = salt_call_cli.run("kubernetes.configmaps")
    assert ret.returncode == 0
    assert isinstance(ret.data, list)

    # Create configmap
    ret = salt_call_cli.run(
        "kubernetes.create_configmap",
        name="test-config",
        namespace="default",
        data=configmap_data,
    )
    assert ret.returncode == 0
    assert ret.data["metadata"]["name"] == "test-config"

    # Show configmap
    ret = salt_call_cli.run("kubernetes.show_configmap", name="test-config", namespace="default")
    assert ret.returncode == 0
    assert ret.data["data"] == configmap_data

    # Delete configmap
    ret = salt_call_cli.run("kubernetes.delete_configmap", name="test-config", namespace="default")
    assert ret.returncode == 0
    assert ret.data

    # Verify configmap is gone
    ret = salt_call_cli.run("kubernetes.show_configmap", name="test-config", namespace="default")
    assert ret.data is None


def test_secrets(salt_call_cli, kind_cluster):
    """Test secret operations"""
    secret = {
        "metadata": {"name": "test-secret", "namespace": "default", "labels": {"app": "test"}},
        "type": "Opaque",
        "data": {"username": "admin", "password": "YWRtaW4xMjM="},  # base64 encoded "admin123"
    }

    # List secrets
    ret = salt_call_cli.run("kubernetes.secrets")
    assert ret.returncode == 0
    assert isinstance(ret.data, list)

    # Create secret
    ret = salt_call_cli.run(
        "kubernetes.create_secret",
        name=secret["metadata"]["name"],
        namespace=secret["metadata"]["namespace"],
        data=secret["data"],
        type=secret["type"],
    )
    assert ret.returncode == 0
    assert ret.data["metadata"]["name"] == secret["metadata"]["name"]

    # Show secret without decode
    ret = salt_call_cli.run(
        "kubernetes.show_secret",
        name=secret["metadata"]["name"],
        namespace=secret["metadata"]["namespace"],
        decode=False,
    )
    assert ret.returncode == 0
    assert ret.data["metadata"]["name"] == secret["metadata"]["name"]
    assert ret.data["data"]["password"] == secret["data"]["password"]

    # Show secret with decode
    ret = salt_call_cli.run(
        "kubernetes.show_secret",
        name=secret["metadata"]["name"],
        namespace=secret["metadata"]["namespace"],
        decode=True,
    )
    assert ret.returncode == 0
    assert ret.data["data"]["username"] == "admin"
    assert ret.data["data"]["password"] == "admin123"

    # Delete secret
    ret = salt_call_cli.run(
        "kubernetes.delete_secret",
        name=secret["metadata"]["name"],
        namespace=secret["metadata"]["namespace"],
    )
    assert ret.returncode == 0
    assert ret.data

    # Verify secret is gone
    ret = salt_call_cli.run(
        "kubernetes.show_secret",
        name=secret["metadata"]["name"],
        namespace=secret["metadata"]["namespace"],
    )
    assert ret.data is None
