import logging

import pytest

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms"),
]


@pytest.mark.parametrize("deployment", [False], indirect=True)
def test_create_deployment(salt_call_cli, deployment):
    """
    Test creating a deployment.
    """
    res = salt_call_cli.run(
        "kubernetes.create_deployment",
        name=deployment["name"],
        namespace=deployment["namespace"],
        metadata=deployment["metadata"],
        spec=deployment["spec"],
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


def test_delete_deployment(salt_call_cli, deployment):
    """
    Test deleting a deployment.
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


@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_create_namespace(salt_call_cli, namespace):
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


def test_delete_namespace(salt_call_cli, namespace):
    """
    Test deleting a namespace using the provided fixture.
    """
    # Delete namespace
    res = salt_call_cli.run("kubernetes.delete_namespace", name=namespace, wait=True)
    assert res.returncode == 0

    # Verify namespace is deleted
    res = salt_call_cli.run("kubernetes.show_namespace", name=namespace)
    assert res.data is None


@pytest.mark.parametrize("pod", [False], indirect=True)
def test_create_pod(salt_call_cli, pod):
    """
    Test creating a pod.
    """
    res = salt_call_cli.run(
        "kubernetes.create_pod",
        name=pod["name"],
        namespace=pod["namespace"],
        metadata=pod["metadata"],
        spec=pod["spec"],
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


def test_delete_pod(salt_call_cli, pod):
    """
    Test deleting a pod.
    """

    res = salt_call_cli.run(
        "kubernetes.delete_pod", name=pod["name"], namespace=pod["namespace"], wait=True
    )
    assert res.returncode == 0

    res = salt_call_cli.run("kubernetes.show_pod", name=pod["name"], namespace=pod["namespace"])
    assert res.data is None


@pytest.mark.parametrize("service", [False], indirect=True)
def test_create_service(salt_call_cli, service):
    """
    Test creating a service.
    """
    res = salt_call_cli.run(
        "kubernetes.create_service",
        name=service["name"],
        namespace=service["namespace"],
        metadata=service["metadata"],
        spec=service["spec"],
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


def test_delete_service(salt_call_cli, service):
    """
    Test deleting a service.
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


@pytest.mark.parametrize("configmap", [False], indirect=True)
def test_create_configmap(salt_call_cli, configmap):
    """
    Test creating a configmap.
    """
    res = salt_call_cli.run(
        "kubernetes.create_configmap",
        name=configmap["name"],
        namespace=configmap["namespace"],
        data=configmap["data"],
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


def test_delete_configmap(salt_call_cli, configmap):
    """
    Test deleting a configmap.
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


@pytest.mark.parametrize("secret", [False], indirect=True)
def test_create_secret(salt_call_cli, secret):
    """
    Test creating a secret.
    """
    res = salt_call_cli.run(
        "kubernetes.create_secret",
        name=secret["name"],
        namespace=secret["namespace"],
        data=secret["data"],
        metadata=secret["metadata"],
        type=secret["type"],
        wait=True,
    )
    assert res.returncode == 0

    # Verify secret exists
    res = salt_call_cli.run(
        "kubernetes.show_secret",
        name=secret["name"],
        namespace=secret["namespace"],
        decode=True,
    )
    assert res.returncode == 0
    assert res.data["metadata"]["name"] == secret["name"]
    assert res.data["metadata"]["namespace"] == secret["namespace"]
    assert res.data["metadata"]["labels"]["app"] == secret["metadata"]["labels"]["app"]
    assert res.data["data"]["username"] == "admin"
    assert res.data["data"]["password"] == "admin123"


def test_delete_secret(salt_call_cli, secret):
    """
    Test deleting a secret using the provided fixture.
    """
    res = salt_call_cli.run(
        "kubernetes.delete_secret",
        name=secret["name"],
        namespace=secret["namespace"],
        wait=True,
    )
    assert res.returncode == 0

    # Verify secret is deleted
    res = salt_call_cli.run(
        "kubernetes.show_secret",
        name=secret["name"],
        namespace=secret["namespace"],
    )
    assert res.data is None
