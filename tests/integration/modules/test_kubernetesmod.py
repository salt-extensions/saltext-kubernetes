import logging

import pytest
from saltfactories.utils import random_string

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms"),
]


@pytest.fixture()
def deployment_spec():
    """
    Fixture providing a deployment specification for testing.
    """
    return {
        "metadata": {"labels": {"app": "test-nginx"}},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "test-nginx"}},
            "template": {
                "metadata": {"labels": {"app": "test-nginx"}},
                "spec": {
                    "containers": [
                        {"name": "nginx", "image": "nginx:latest", "ports": [{"containerPort": 80}]}
                    ]
                },
            },
        },
    }


@pytest.fixture(params=[True])
def deployment(salt_call_cli, kind_cluster, deployment_spec, request):
    """
    Create a deployment for testing purposes.
    """
    name = random_string("deployment-", uppercase=False)
    namespace = "default"

    if request.param:
        res = salt_call_cli.run(
            "kubernetes.create_deployment",
            name=name,
            namespace=namespace,
            metadata=deployment_spec["metadata"],
            spec=deployment_spec["spec"],
            source="",
            template="",
            saltenv="base",
            wait=True,
        )
        assert res.returncode == 0

    try:
        yield {"name": name, "namespace": namespace, "spec": deployment_spec}
    finally:
        # Cleanup - delete deployment
        res = salt_call_cli.run(
            "kubernetes.delete_deployment",
            name=name,
            namespace=namespace,
            wait=True,
        )
        assert res.returncode == 0


@pytest.mark.parametrize("deployment", [False], indirect=True)
def test_create_deployment(salt_call_cli, kind_cluster, deployment, deployment_spec):
    """
    Test creating a deployment using the provided fixture.
    """
    res = salt_call_cli.run(
        "kubernetes.create_deployment",
        name=deployment["name"],
        namespace=deployment["namespace"],
        metadata=deployment_spec["metadata"],
        spec=deployment_spec["spec"],
        source="",
        template="",
        saltenv="base",
        wait=True,
    )
    assert res.returncode == 0

    # Verify deployment exists
    res = salt_call_cli.run(
        "kubernetes.show_deployment",
        name=deployment["name"],
        namespace=deployment["namespace"],
    )
    assert res.returncode == 0
    assert res.data["metadata"]["name"] == deployment["name"]
    assert res.data["metadata"]["namespace"] == deployment["namespace"]
    assert res.data["spec"]["replicas"] == 1
    assert res.data["spec"]["selector"]["match_labels"]["app"] == "test-nginx"
    assert res.data["spec"]["template"]["metadata"]["labels"]["app"] == "test-nginx"
    assert res.data["spec"]["template"]["spec"]["containers"][0]["name"] == "nginx"
    assert res.data["spec"]["template"]["spec"]["containers"][0]["image"] == "nginx:latest"
    assert res.data["spec"]["template"]["spec"]["containers"][0]["ports"][0]["container_port"] == 80


def test_delete_deployment(salt_call_cli, kind_cluster, deployment):
    """
    Test deleting a deployment using the provided fixture.
    """
    res = salt_call_cli.run(
        "kubernetes.delete_deployment",
        name=deployment["name"],
        namespace=deployment["namespace"],
        wait=True,
    )
    assert res.returncode == 0

    # Verify deployment is deleted
    res = salt_call_cli.run(
        "kubernetes.show_deployment",
        name=deployment["name"],
        namespace=deployment["namespace"],
    )
    assert res.data is None


@pytest.fixture(params=[True])
def namespace(salt_call_cli, kind_cluster, request):
    """
    Create a namespace for testing purposes.
    """
    name = random_string("namespace-", uppercase=False)

    if request.param:
        res = salt_call_cli.run("kubernetes.create_namespace", name=name, wait=True)
        assert res.returncode == 0
        assert res.data["metadata"]["name"] == name
        assert res.data["kind"] == "Namespace"

    try:
        yield name
    finally:
        # Cleanup - delete namespace
        res = salt_call_cli.run("kubernetes.delete_namespace", name=name, wait=True)
        assert res.returncode == 0


@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_create_namespace(salt_call_cli, kind_cluster, namespace):
    """
    Test creating a namespace using the provided fixture.
    """
    res = salt_call_cli.run("kubernetes.create_namespace", name=namespace, wait=True)
    assert res.returncode == 0

    # Verify namespace exists
    res = salt_call_cli.run("kubernetes.show_namespace", name=namespace)
    assert res.returncode == 0
    assert res.data["metadata"]["name"] == namespace
    assert res.data["kind"] == "Namespace"
    assert res.data["status"]["phase"] == "Active"


def test_delete_namespace(salt_call_cli, kind_cluster, namespace):
    """
    Test deleting a namespace using the provided fixture.
    """
    # Delete namespace
    res = salt_call_cli.run("kubernetes.delete_namespace", name=namespace, wait=True)
    assert res.returncode == 0

    # Verify namespace is deleted
    res = salt_call_cli.run("kubernetes.show_namespace", name=namespace)
    assert res.data is None


@pytest.fixture()
def pod_spec():
    return {
        "metadata": {"labels": {"app": "test"}},
        "spec": {
            "containers": [
                {"name": "nginx", "image": "nginx:latest", "ports": [{"containerPort": 80}]}
            ]
        },
    }


@pytest.fixture(params=[True])
def pod(salt_call_cli, kind_cluster, pod_spec, request):
    """
    Create a pod for testing purposes.
    """
    name = random_string("pod-", uppercase=False)
    namespace = "default"

    if request.param:
        res = salt_call_cli.run(
            "kubernetes.create_pod",
            name=name,
            namespace=namespace,
            metadata=pod_spec["metadata"],
            spec=pod_spec["spec"],
            source="",
            template="",
            saltenv="base",
            wait=True,
        )
        assert res.returncode == 0

    try:
        yield {"name": name, "namespace": namespace, "spec": pod_spec}
    finally:
        # Cleanup - delete pod
        res = salt_call_cli.run(
            "kubernetes.delete_pod",
            name=name,
            namespace=namespace,
            wait=True,
        )
        assert res.returncode == 0


@pytest.mark.parametrize("pod", [False], indirect=True)
def test_create_pod(salt_call_cli, kind_cluster, pod, pod_spec):
    """
    Test creating a pod using the provided fixture.
    """
    res = salt_call_cli.run(
        "kubernetes.create_pod",
        name=pod["name"],
        namespace=pod["namespace"],
        metadata=pod_spec["metadata"],
        spec=pod_spec["spec"],
        source="",
        template="",
        saltenv="base",
        wait=True,
    )
    assert res.returncode == 0

    # Verify pod exists
    res = salt_call_cli.run(
        "kubernetes.show_pod",
        name=pod["name"],
        namespace=pod["namespace"],
    )
    assert res.returncode == 0
    assert res.data["metadata"]["name"] == pod["name"]
    assert res.data["metadata"]["namespace"] == pod["namespace"]
    assert res.data["spec"]["containers"][0]["name"] == "nginx"
    assert res.data["spec"]["containers"][0]["image"] == "nginx:latest"
    assert res.data["spec"]["containers"][0]["ports"][0]["container_port"] == 80


def test_delete_pod(salt_call_cli, kind_cluster, pod):
    """
    Test deleting a pod using the provided fixture.
    """

    res = salt_call_cli.run(
        "kubernetes.delete_pod", name=pod["name"], namespace=pod["namespace"], wait=True
    )
    assert res.returncode == 0

    res = salt_call_cli.run("kubernetes.show_pod", name=pod["name"], namespace=pod["namespace"])
    assert res.data is None


@pytest.fixture()
def service_spec():
    """
    Fixture providing a service specification for testing.
    """
    return {
        "metadata": {"labels": {"app": "test"}},
        "spec": {
            "ports": [{"port": 80, "targetPort": 80, "name": "http"}],
            "selector": {"app": "test"},
            "type": "ClusterIP",
        },
    }


@pytest.fixture(params=[True])
def service(salt_call_cli, kind_cluster, service_spec, request):
    """
    Create providing a service for testing purposes.
    """
    name = random_string("service-", uppercase=False)
    namespace = "default"

    if request.param:
        res = salt_call_cli.run(
            "kubernetes.create_service",
            name=name,
            namespace=namespace,
            metadata=service_spec["metadata"],
            spec=service_spec["spec"],
            source="",
            template="",
            saltenv="base",
        )
        assert res.returncode == 0

    try:
        yield {"name": name, "namespace": namespace}
    finally:

        res = salt_call_cli.run(
            "kubernetes.delete_service",
            name=name,
            namespace=namespace,
        )
        assert res.returncode == 0


@pytest.mark.parametrize("service", [False], indirect=True)
def test_create_service(salt_call_cli, kind_cluster, service, service_spec):
    """
    Test creating a service using the provided fixture.
    """
    res = salt_call_cli.run(
        "kubernetes.create_service",
        name=service["name"],
        namespace=service["namespace"],
        metadata=service_spec["metadata"],
        spec=service_spec["spec"],
        source="",
        template="",
        saltenv="base",
    )
    assert res.returncode == 0

    # Verify service exists
    res = salt_call_cli.run(
        "kubernetes.show_service",
        name=service["name"],
        namespace=service["namespace"],
    )
    assert res.returncode == 0
    assert res.data["metadata"]["name"] == service["name"]
    assert res.data["metadata"]["namespace"] == service["namespace"]
    assert res.data["spec"]["type"] == "ClusterIP"
    assert res.data["spec"]["selector"]["app"] == "test"


def test_delete_service(salt_call_cli, kind_cluster, service):
    """
    Test deleting a service using the provided fixture.
    """
    res = salt_call_cli.run(
        "kubernetes.delete_service",
        name=service["name"],
        namespace=service["namespace"],
        wait=True,
    )
    assert res.returncode == 0

    res = salt_call_cli.run(
        "kubernetes.show_service",
        name=service["name"],
        namespace=service["namespace"],
    )
    assert res.data is None


@pytest.fixture()
def configmap_data():
    """
    Fixture providing configmap data for testing.
    """
    return {
        "config.txt": "some configuration data",
        "other-file.txt": "other configuration data",
    }


@pytest.fixture(params=[True])
def configmap(salt_call_cli, kind_cluster, configmap_data, request):
    """
    Create a configmap for testing purposes.
    """
    name = random_string("configmap-", uppercase=False)
    namespace = "default"

    if request.param:
        res = salt_call_cli.run(
            "kubernetes.create_configmap",
            name=name,
            namespace=namespace,
            data=configmap_data,
            wait=True,
        )
        assert res.returncode == 0

    try:
        yield {"name": name, "namespace": namespace, "data": configmap_data}
    finally:
        # Cleanup - delete configmap
        res = salt_call_cli.run(
            "kubernetes.delete_configmap",
            name=name,
            namespace=namespace,
        )
        assert res.returncode == 0


@pytest.mark.parametrize("configmap", [False], indirect=True)
def test_create_configmap(salt_call_cli, kind_cluster, configmap, configmap_data):
    """
    Test creating a configmap using the provided fixture.
    """
    res = salt_call_cli.run(
        "kubernetes.create_configmap",
        name=configmap["name"],
        namespace=configmap["namespace"],
        data=configmap_data,
        wait=True,
    )
    assert res.returncode == 0

    # Verify configmap exists
    res = salt_call_cli.run(
        "kubernetes.show_configmap",
        name=configmap["name"],
        namespace=configmap["namespace"],
    )
    assert res.returncode == 0
    assert res.data["metadata"]["name"] == configmap["name"]
    assert res.data["metadata"]["namespace"] == configmap["namespace"]
    assert res.data["data"]["config.txt"] == configmap["data"]["config.txt"]
    assert res.data["data"]["other-file.txt"] == configmap["data"]["other-file.txt"]


def test_delete_configmap(salt_call_cli, kind_cluster, configmap):
    """
    Test deleting a configmap using the provided fixture.
    """
    res = salt_call_cli.run(
        "kubernetes.delete_configmap",
        name=configmap["name"],
        namespace=configmap["namespace"],
        wait=True,
    )
    assert res.returncode == 0

    # Verify configmap is deleted
    res = salt_call_cli.run(
        "kubernetes.show_configmap",
        name=configmap["name"],
        namespace=configmap["namespace"],
    )
    assert res.data is None


@pytest.fixture()
def secret_data():
    """
    Fixture providing secres data for testing.
    """
    return {
        "metadata": {"labels": {"app": "test"}},
        "type": "Opaque",
        "data": {"username": "admin", "password": "admin123"},
    }


@pytest.fixture(params=[True])
def secret(salt_call_cli, kind_cluster, secret_data, request):
    """
    Create a secres for testing purposes.
    """
    name = random_string("secret-", uppercase=False)
    namespace = "default"

    if request.param:
        res = salt_call_cli.run(
            "kubernetes.create_secret",
            name=name,
            namespace=namespace,
            data=secret_data["data"],
            type=secret_data["type"],
        )
        assert res.returncode == 0

    try:
        yield {"name": name, "namespace": namespace}
    finally:
        # Cleanup - delete secret
        res = salt_call_cli.run(
            "kubernetes.delete_secret",
            name=name,
            namespace=namespace,
        )
        assert res.returncode == 0


@pytest.mark.parametrize("secret", [False], indirect=True)
def test_create_secret(salt_call_cli, kind_cluster, secret, secret_data):
    """
    Test creating a secres using the provided fixture.
    """
    res = salt_call_cli.run(
        "kubernetes.create_secret",
        name=secret["name"],
        namespace=secret["namespace"],
        data=secret_data["data"],
        type=secret_data["type"],
        wait=True,
    )
    assert res.returncode == 0

    # Verify secres exists
    res = salt_call_cli.run(
        "kubernetes.show_secret",
        name=secret["name"],
        namespace=secret["namespace"],
        decode=True,
    )
    assert res.returncode == 0
    assert res.data["metadata"]["name"] == secret["name"]
    assert res.data["metadata"]["namespace"] == secret["namespace"]
    assert res.data["data"]["username"] == "admin"
    assert res.data["data"]["password"] == "admin123"


def test_delete_secret(salt_call_cli, kind_cluster, secret):
    """
    Test deleting a secres using the provided fixture.
    """
    res = salt_call_cli.run(
        "kubernetes.delete_secret",
        name=secret["name"],
        namespace=secret["namespace"],
        wait=True,
    )
    assert res.returncode == 0

    # Verify secres is deleted
    res = salt_call_cli.run(
        "kubernetes.show_secret",
        name=secret["name"],
        namespace=secret["namespace"],
    )
    assert res.data is None
