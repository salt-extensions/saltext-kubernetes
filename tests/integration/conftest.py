import pytest
from saltfactories.utils import random_string


@pytest.fixture(scope="module")
def master(master):  # pragma: no cover
    with master.started():
        yield master


@pytest.fixture(scope="module")
def minion(minion):  # pragma: no cover
    with minion.started():
        yield minion


@pytest.fixture
def salt_run_cli(master):  # pragma: no cover
    return master.salt_run_cli()


@pytest.fixture
def salt_cli(master):  # pragma: no cover
    return master.salt_cli()


@pytest.fixture
def salt_call_cli(minion, kind_cluster):  # pylint: disable=unused-argument; # pragma: no cover
    return minion.salt_call_cli()


@pytest.fixture(params=[True])
def namespace(salt_call_cli, request):
    """
    Create/cleanup a namespace for testing purposes.
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


@pytest.fixture
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
def pod(salt_call_cli, pod_spec, request):
    """
    Create/cleanup a pod for testing purposes.
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
        yield {
            "name": name,
            "namespace": namespace,
            "metadata": pod_spec["metadata"],
            "spec": pod_spec["spec"],
        }
    finally:
        # Cleanup - delete pod
        res = salt_call_cli.run(
            "kubernetes.delete_pod",
            name=name,
            namespace=namespace,
            wait=True,
        )
        assert res.returncode == 0


@pytest.fixture
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
def deployment(salt_call_cli, deployment_spec, request):
    """
    Create/cleanup a deployment for testing purposes.
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
        yield {
            "name": name,
            "namespace": namespace,
            "metadata": deployment_spec["metadata"],
            "spec": deployment_spec["spec"],
        }
    finally:
        # Cleanup - delete deployment
        res = salt_call_cli.run(
            "kubernetes.delete_deployment",
            name=name,
            namespace=namespace,
            wait=True,
        )
        assert res.returncode == 0


@pytest.fixture
def secret_spec():
    """
    Fixture providing secret data for testing.
    """
    return {
        "metadata": {"labels": {"app": "test"}},
        "type": "Opaque",
        "data": {"username": "admin", "password": "admin123"},
    }


@pytest.fixture(params=[True])
def secret(salt_call_cli, secret_spec, request):
    """
    Create/cleanup a secret for testing purposes.
    """
    name = random_string("secret-", uppercase=False)
    namespace = "default"

    if request.param:
        res = salt_call_cli.run(
            "kubernetes.create_secret",
            name=name,
            namespace=namespace,
            data=secret_spec["data"],
            type=secret_spec["type"],
        )
        assert res.returncode == 0

    try:
        yield {
            "name": name,
            "namespace": namespace,
            "data": secret_spec["data"],
            "metadata": secret_spec["metadata"],
            "type": secret_spec["type"],
        }
    finally:
        # Cleanup - delete secret
        res = salt_call_cli.run(
            "kubernetes.delete_secret",
            name=name,
            namespace=namespace,
        )
        assert res.returncode == 0


@pytest.fixture
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
def service(salt_call_cli, service_spec, request):
    """
    Create/cleanup a service for testing purposes.
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
        yield {
            "name": name,
            "namespace": namespace,
            "metadata": service_spec["metadata"],
            "spec": service_spec["spec"],
        }
    finally:

        res = salt_call_cli.run(
            "kubernetes.delete_service",
            name=name,
            namespace=namespace,
        )
        assert res.returncode == 0


@pytest.fixture
def configmap_data():
    """
    Fixture providing configmap data for testing.
    """
    return {
        "config.txt": "some configuration data",
        "other-file.txt": "other configuration data",
    }


@pytest.fixture(params=[True])
def configmap(salt_call_cli, configmap_data, request):
    """
    Create/cleanup a configmap for testing purposes.
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
