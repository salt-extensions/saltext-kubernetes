import logging

import pytest
from salt.exceptions import CommandExecutionError
from saltfactories.utils import random_string

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms"),
]


@pytest.fixture
def kubernetes(modules):
    """
    Return the kubernetes execution module
    """
    return modules.kubernetes


@pytest.fixture
def namespace_name():
    """
    Fixture providing a namespace name for testing

    Kubernetes requires names to be lowercase RFC 1123 complient
    """
    return random_string("namespace-", uppercase=False)


@pytest.fixture(params=[True])
def namespace(kubernetes, namespace_name, request):
    """
    Fixture to create a test namespace.
    """
    name = namespace_name

    # Only create the namespace if requested
    if request.param:
        res = kubernetes.create_namespace(name)
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name
    try:
        yield name
    finally:
        kubernetes.delete_namespace(name, wait=True)


@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_create_namespace(kubernetes, namespace):
    """
    Test creating a namespace returns expected result
    """

    res = kubernetes.create_namespace(namespace)
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == namespace


@pytest.mark.parametrize("namespace", [True], indirect=True)
def test_create_existing_namespace(kubernetes, namespace):
    """
    Test creating a namespace that already exists raises appropriate error
    """
    with pytest.raises(CommandExecutionError, match=".*already exists.*"):
        kubernetes.create_namespace(namespace)


@pytest.mark.parametrize("namespace", [True], indirect=True)
def test_delete_existing_namespace(kubernetes, namespace):
    """
    Test deleting a namespace that exists returns expected result
    """
    res = kubernetes.delete_namespace(namespace, wait=True)
    assert isinstance(res, dict)

    # Verify namespace was actually deleted
    deleted_namespace = kubernetes.show_namespace(namespace)
    assert deleted_namespace is None


@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_delete_nonexistent_namespace(kubernetes, namespace):
    """
    Test deleting a namespace that doesn't exist returns None
    """
    res = kubernetes.delete_namespace(namespace)
    assert res is None


def test_namespace_invalid_name(kubernetes):
    """
    Test creating a namespace with an invalid name raises appropriate error
    """
    invalid_name = "invalid_name"
    with pytest.raises(CommandExecutionError, match="Invalid"):
        kubernetes.create_namespace(invalid_name)


def test_delete_system_namespace(kubernetes):
    """
    Test deleting a protected system namespace raises appropriate error
    """
    with pytest.raises(CommandExecutionError, match="Forbidden"):
        kubernetes.delete_namespace("kube-system")


@pytest.fixture
def pod_name():
    """
    Fixture providing a pod name for testing

    Kubernetes requires names to be lowercase RFC 1123 complient
    """
    return random_string("pod-", uppercase=False)


@pytest.fixture
def pod_spec():
    """
    Fixture providing a basic pod spec
    """
    return {"containers": [{"name": "nginx", "image": "nginx:latest"}]}


@pytest.fixture(params=[True])
def pod(kubernetes, pod_name, pod_spec, request):
    """
    Fixture to create a test pod.

    If request.param is True, pod is created before the test.
    If request.param is False, pod is not created.
    """
    name = pod_name
    namespace = "default"

    # Only create the pod if requested
    if request.param:
        res = kubernetes.create_pod(
            name=name,
            namespace=namespace,
            metadata={"labels": {"test": "true"}},
            spec=pod_spec,
            source=None,
            template=None,
            saltenv="base",
            wait=True,
        )
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name
    try:
        yield {"name": name, "namespace": namespace}
    finally:
        kubernetes.delete_pod(name, namespace, wait=True)


@pytest.mark.parametrize("pod", [False], indirect=True)
def test_create_pod(kubernetes, pod, pod_spec):
    """
    Test creating a pod returns expected result
    """
    res = kubernetes.create_pod(
        name=pod["name"],
        namespace=pod["namespace"],
        metadata={},
        spec=pod_spec,
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == pod["name"]
    assert res["metadata"]["namespace"] == pod["namespace"]


@pytest.mark.parametrize("pod", [True], indirect=True)
def test_create_existing_pod(kubernetes, pod, pod_spec):
    """
    Test creating a pod that already exists raises appropriate error
    """
    with pytest.raises(CommandExecutionError, match=".*already exists.*"):
        kubernetes.create_pod(
            name=pod["name"],
            namespace=pod["namespace"],
            metadata={},
            spec=pod_spec,
            source=None,
            template=None,
            saltenv="base",
            wait=True,
        )


@pytest.mark.parametrize("pod", [True], indirect=True)
def test_delete_existing_pod(kubernetes, pod):
    """
    Test deleting a pod that exists returns expected result
    """
    res = kubernetes.delete_pod(pod["name"], pod["namespace"], wait=True)
    assert isinstance(res, dict)

    # Verify pod was actually deleted
    deleted_pod = kubernetes.show_pod(pod["name"], pod["namespace"])
    assert deleted_pod is None


@pytest.mark.parametrize("pod", [False], indirect=True)
def test_delete_nonexistent_pod(kubernetes, pod):
    """
    Test deleting a pod that doesn't exist returns None
    """
    res = kubernetes.delete_pod(pod["name"], pod["namespace"])
    assert res is None


@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_list_pods_in_nonexistent_namespace(kubernetes, namespace):
    """
    Test listing pods in a namespace that doesn't exist returns empty list
    """
    res = kubernetes.pods(namespace)
    assert res == []


@pytest.fixture
def secret_name():
    """
    Fixture providing a secret name for testing

    Kubernetes requires names to be lowercase RFC 1123 complient
    """
    return random_string("secret-", uppercase=False)


@pytest.fixture
def secret_data():
    """
    Fixture providing a basic secret data
    """
    return {"key": "value"}


@pytest.fixture(params=[True])
def secret(kubernetes, secret_name, secret_data, request):
    """
    Fixture to create a test secret.

    If request.param is True, secret is created before the test.
    If
    request.param is False, secret is not created.
    """
    name = secret_name
    namespace = "default"

    # Only create the secret if requested
    if request.param:
        res = kubernetes.create_secret(name, namespace=namespace, data=secret_data, wait=True)
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name

    try:
        yield {"name": name, "namespace": namespace}
    finally:
        kubernetes.delete_secret(name, namespace, wait=True)


@pytest.mark.parametrize("secret", [False], indirect=True)
def test_create_secret(kubernetes, secret):
    """
    Test creating a secret returns expected result
    """
    res = kubernetes.create_secret(
        secret["name"],
        namespace=secret["namespace"],
        data={"key": "value"},
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == secret["name"]
    assert res["metadata"]["namespace"] == secret["namespace"]


@pytest.mark.parametrize("secret", [True], indirect=True)
def test_create_existing_secret(kubernetes, secret, secret_data):
    """
    Test creating a secret that already exists raises appropriate error
    """
    with pytest.raises(CommandExecutionError, match=".*already exists.*"):
        kubernetes.create_secret(secret["name"], secret["namespace"], data=secret_data, wait=True)


@pytest.mark.parametrize("secret", [True], indirect=True)
def test_delete_existing_secret(kubernetes, secret):
    """
    Test deleting a secret that exists returns expected result
    """
    res = kubernetes.delete_secret(secret["name"], secret["namespace"], wait=True)
    assert isinstance(res, dict)

    # Verify secret was actually deleted
    deleted_secret = kubernetes.show_secret(secret["name"], secret["namespace"])
    assert deleted_secret is None


@pytest.mark.parametrize("secret", [True], indirect=True)
def test_secret_type_preservation(kubernetes, secret, secret_data):
    """
    Test creating a secret with a specific type preserves the type
    """
    secret_type = kubernetes.show_secret(secret["name"], secret["namespace"])["type"]

    res = kubernetes.replace_secret(
        secret["name"],
        namespace=secret["namespace"],
        data=secret_data,
        secret_type=None,
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["type"] == secret_type


@pytest.mark.parametrize("secret", [False], indirect=True)
def test_delete_nonexistent_secret(kubernetes, secret):
    """
    Test deleting a secret that doesn't exist returns None
    """
    res = kubernetes.delete_secret(secret)
    assert res is None


@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_list_secrets_in_nonexistent_namespace(kubernetes, namespace):
    """
    Test listing secrets in a namespace that doesn't exist returns empty list
    """
    res = kubernetes.secrets(namespace)
    assert res == []


# I could not figure out how to test this using a fixture for
# parameterization of test cases so I used direct parametrization
@pytest.mark.parametrize(
    "name,data,expected",
    [
        (
            "salt-test-plaintext",
            {"key": "value"},
            "value",
        ),
        (
            "salt-test-preencoded",
            {"key": "dmFsdWU="},
            "value",
        ),
    ],
)
def test_create_secret_inputs(name, data, expected, kubernetes):
    """
    Test creating secrets with different input formats
    """
    try:
        namespace = "default"

        # Create secret
        res = kubernetes.create_secret(name, namespace=namespace, data=data, wait=True)
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name

        # Verify decoded value
        res = kubernetes.show_secret(name, namespace, decode=True)
        assert res["data"]["key"] == expected
    finally:
        kubernetes.delete_secret(name, namespace, wait=True)


# I could not figure out how to test this using a fixture for
# parameterization of test cases so I used direct parametrization
@pytest.mark.parametrize(
    "case",
    [
        {
            "name": "salt-test-opaque-secret",
            "secret_type": "Opaque",
            "data": {"key": "value"},
            "replace_data": {"newkey": "newvalue"},
        },
        {
            "name": "salt-test-dockerconfig",
            "secret_type": "kubernetes.io/dockerconfigjson",
            "data": {
                ".dockerconfigjson": '{"auths":{"registry.example.com":{"username":"user","password":"pass"}}}'
            },
            "replace_data": {
                ".dockerconfigjson": '{"auths":{"registry.example.com":{"username":"newuser","password":"newpass"}}}'
            },
        },
        {
            "name": "salt-test-basic-auth",
            "secret_type": "kubernetes.io/basic-auth",
            "data": {"username": "admin", "password": "secret"},
            "replace_data": {"username": "newadmin", "password": "newsecret"},
        },
        {
            "name": "salt-test-tls",
            "secret_type": "kubernetes.io/tls",
            "data": {
                "tls.crt": "-----BEGIN CERTIFICATE-----\nMIICwjCCAaqgAwIBAgIBADANBgkqhkiG9w0BAQsFADAS\n-----END CERTIFICATE-----",
                "tls.key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEA\n-----END PRIVATE KEY-----",
            },
            "replace_data": {
                "tls.crt": "-----BEGIN CERTIFICATE-----\nNew Certificate\n-----END CERTIFICATE-----",
                "tls.key": "-----BEGIN PRIVATE KEY-----\nNew Key\n-----END PRIVATE KEY-----",
            },
        },
        {
            "name": "salt-test-multiline-b64",
            "secret_type": "kubernetes.io/tls",
            "data": {
                "tls.crt": (
                    "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM5akNDQWQ2Z0F3SUJBZ0lSQVA4"
                    "Y3NuYmovVS9nWHJ4VDR5dXk5OUF3RFFZSktvWklodmNOQVFFTEJRQXcKRlRFVE1CRUdB"
                    "MVVFQXhNS2EzVmlaWEp1WlhSbGN6QWVGdzB5TkRBeE1UY3hOekEwTWpkYUZ3MHpOREF4"
                    "TVRReApOekEwTWpkYU1CVXhFekFSQmdOVkJBTVRDbXQxWW1WeWJtVjBaWE13Z2dFaU1B"
                    "MEdDU3FHU0liM0RRRUJBUVVBQ"
                ),
                "tls.key": (
                    "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2UUlCQURBTkJna3Foa2lHOXcw"
                    "QkFRRUZBQVNDQktjd2dnU2pBZ0VBQW9JQkFRQzFyZkdjdGhFaXk3K0YKLzdSOEd6TmFh"
                    "d29PdEVHVHZvWWFPMlF1b2JEcUd0NitTZFZ1Y2NTS2dDYWh3V09XN0dTTzhNRjJzaEtE"
                    "WHlsegp1VzZySjN2WlJOaVgyMy9TV1J3d0xXYzBHZUNVT3VXQVlVR2N1THQ5OVplUzRQ"
                    "eWQ5UmRnNTRZRlhMZ1FKV0"
                ),
            },
            "replace_data": {
                "tls.crt": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk5FVyBURVNUIENFUlQKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=",
                "tls.key": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk5FVyBURVNUIEtFWQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg==",
            },
        },
    ],
)
def test_secret_types(case, kubernetes):
    """
    Test creating and replacing secrets with different types
    """
    namespace = "default"

    try:
        # Create secret directly first
        res = kubernetes.create_secret(
            case["name"],
            namespace=namespace,
            data=case["data"],
            secret_type=case["secret_type"],
            wait=True,
        )
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == case["name"]

        # Verify secret was created with correct type
        secret = kubernetes.show_secret(case["name"], namespace)
        assert secret != [], f"Secret {case['name']} was not created"
        assert secret["type"] == case["secret_type"]

        # Verify data
        res = kubernetes.show_secret(case["name"], namespace, decode=True)
        assert res != []
        for key, value in case["data"].items():
            assert res["data"][key] == value

        # Replace secret with new data
        res = kubernetes.replace_secret(
            case["name"],
            namespace=namespace,
            data=case["replace_data"],
            secret_type=case["secret_type"],
            wait=True,
        )

        # Verify type was preserved
        secret = kubernetes.show_secret(case["name"], namespace)
        assert secret is not None
        assert secret["type"] == case["secret_type"]
    finally:
        kubernetes.delete_secret(case["name"], namespace, wait=True)


@pytest.fixture
def deployment_name():
    """
    Fixture providing a deployment name for testing

    # Kubernetes requires names to be lowercase RFC 1123 complient
    """
    return random_string("deployment-", uppercase=False)


@pytest.fixture
def deployment_spec():
    """
    Fixture providing a basic deployment spec
    """
    return {
        "replicas": 1,
        "selector": {"matchLabels": {"app": "nginx"}},
        "template": {
            "metadata": {"labels": {"app": "nginx"}},
            "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
        },
    }


@pytest.fixture(params=[True])
def deployment(kubernetes, deployment_name, deployment_spec, request):
    """
    Fixture to create a test deployment.

    If request.param is True, deployment is created before the test.
    If request.param is False, deployment is not created.
    """
    name = deployment_name
    namespace = "default"

    # Only create the deployment if requested
    if request.param:
        res = kubernetes.create_deployment(
            name=name,
            namespace=namespace,
            metadata={},
            spec=deployment_spec,
            source=None,
            template=None,
            saltenv="base",
            wait=True,
        )
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name

    try:
        yield {"name": name, "namespace": namespace}
    finally:
        kubernetes.delete_deployment(name, namespace, wait=True)


@pytest.mark.parametrize("deployment", [False], indirect=True)
def test_create_deployment(kubernetes, deployment, deployment_spec):
    """
    Test creating a deployment returns expected result
    """
    res = kubernetes.create_deployment(
        name=deployment["name"],
        namespace=deployment["namespace"],
        metadata={},
        spec=deployment_spec,
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == deployment["name"]
    assert res["metadata"]["namespace"] == deployment["namespace"]


@pytest.mark.parametrize("deployment", [True], indirect=True)
def test_create_existing_deployment(kubernetes, deployment, deployment_spec):
    """
    Test creating a deployment that already exists raises appropriate error
    """
    with pytest.raises(CommandExecutionError, match=".*already exists.*"):
        kubernetes.create_deployment(
            name=deployment["name"],
            namespace=deployment["namespace"],
            metadata={},
            spec=deployment_spec,
            source=None,
            template=None,
            saltenv="base",
            wait=True,
        )


@pytest.mark.parametrize("deployment", [True], indirect=True)
def test_delete_existing_deployment(kubernetes, deployment):
    """
    Test deleting a deployment that exists returns expected result
    """
    res = kubernetes.delete_deployment(deployment["name"], deployment["namespace"], wait=True)
    assert isinstance(res, dict)

    # Verify deployment was actually deleted
    deleted_deployment = kubernetes.show_deployment(deployment["name"], deployment["namespace"])
    assert deleted_deployment is None


@pytest.mark.parametrize("deployment", [False], indirect=True)
def test_delete_nonexistent_deployment(kubernetes, deployment):
    """
    Test deleting a deployment that doesn't exist returns None
    """
    res = kubernetes.delete_deployment(deployment["name"], deployment["namespace"])
    assert res is None


@pytest.mark.parametrize("deployment", [True], indirect=True)
def test_deployment_replacement(kubernetes, deployment):
    """
    Test replacing a deployment with new spec
    """
    new_spec = {
        "replicas": 2,
        "selector": {"matchLabels": {"app": "nginx"}},
        "template": {
            "metadata": {"labels": {"app": "nginx"}},
            "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
        },
    }

    res = kubernetes.replace_deployment(
        name=deployment["name"],
        namespace=deployment["namespace"],
        metadata={},
        spec=new_spec,
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["spec"]["replicas"] == 2


@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_list_deployments_in_nonexistent_namespace(kubernetes, namespace):
    """
    Test listing deployments in a namespace that doesn't exist returns empty list
    """
    res = kubernetes.deployments(namespace)
    assert res == []


@pytest.mark.parametrize(
    "spec",
    [
        # Valid case - selector matches labels
        {
            "selector": {"matchLabels": {"app": "nginx"}},
            "template": {
                "metadata": {"labels": {"app": "nginx"}},
                "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
            },
        },
        # Valid case - missing selector but has template labels
        {
            "template": {
                "metadata": {"labels": {"app": "nginx"}},
                "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
            }
        },
    ],
)
def test_deployment_selector(spec, kubernetes):
    """Test that deployment selector validation works correctly"""
    test_deployment = "salt-test-selector"
    namespace = "default"

    try:
        res = kubernetes.create_deployment(
            name=test_deployment,
            namespace=namespace,
            metadata={},
            spec=spec,
            source=None,
            template=None,
            saltenv="base",
            wait=True,
        )
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == test_deployment
    finally:
        kubernetes.delete_deployment(test_deployment, namespace, wait=True)


@pytest.fixture
def service_name():
    """
    Fixture providing a service name for testing

    Kubernetes requires names to be lowercase RFC 1123 complient
    """
    return random_string("service-", uppercase=False)


@pytest.fixture
def service_spec():
    """
    Fixture providing a basic service spec
    """
    return {
        "ports": [{"port": 80}],
        "selector": {"app": "nginx"},
        "type": "ClusterIP",
    }


@pytest.fixture(params=[True])
def service(kubernetes, service_name, service_spec, request):
    """
    Fixture to create a test service.

    If request.param is True, service is created before the test.
    If request.param is False, service is not created.
    """
    name = service_name
    namespace = "default"

    # Only create the service if requested
    if request.param:
        res = kubernetes.create_service(
            name=name,
            namespace=namespace,
            metadata={},
            spec=service_spec,
            source=None,
            template=None,
            saltenv="base",
            wait=True,
        )
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name

    try:
        yield {"name": name, "namespace": namespace}
    finally:
        kubernetes.delete_service(name, namespace, wait=True)


@pytest.mark.parametrize("service", [False], indirect=True)
def test_create_service(kubernetes, service, service_spec):
    """
    Test creating a service returns expected result
    """
    res = kubernetes.create_service(
        name=service["name"],
        namespace=service["namespace"],
        metadata={},
        spec=service_spec,
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == service["name"]
    assert res["metadata"]["namespace"] == service["namespace"]


@pytest.mark.parametrize("service", [True], indirect=True)
def test_create_existing_service(kubernetes, service, service_spec):
    """
    Test creating a service that already exists raises appropriate error
    """
    with pytest.raises(CommandExecutionError, match=".*already exists.*"):
        kubernetes.create_service(
            name=service["name"],
            namespace=service["namespace"],
            metadata={},
            spec=service_spec,
            source=None,
            template=None,
            saltenv="base",
            wait=True,
        )


@pytest.mark.parametrize("service", [True], indirect=True)
def test_delete_existing_service(kubernetes, service):
    """
    Test deleting a service that exists returns expected result
    """
    res = kubernetes.delete_service(service["name"], service["namespace"], wait=True)
    assert isinstance(res, dict)

    # Verify service was actually deleted
    deleted_service = kubernetes.show_service(service["name"], service["namespace"])
    assert deleted_service is None


@pytest.mark.parametrize("service", [False], indirect=True)
def test_delete_nonexistent_service(kubernetes, service):
    """
    Test deleting a service that doesn't exist returns None
    """
    res = kubernetes.delete_service(service["name"], service["namespace"])
    assert res is None


@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_list_services_in_nonexistent_namespace(kubernetes, namespace):
    """
    Test listing services in a namespace that doesn't exist returns empty list
    """
    res = kubernetes.services(namespace)
    assert res == []


# I could not figure out how to test this using a fixture for
# parameterization of test cases so I used direct parametrization
@pytest.mark.parametrize(
    "case",
    [
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
    ],
)
def test_service_different_types(case, kubernetes):
    """Test creating services with different types"""
    namespace = "default"

    try:
        # Create service
        res = kubernetes.create_service(
            name=case["name"],
            namespace=namespace,
            metadata={},
            spec=case["spec"],
            source=None,
            template=None,
            saltenv="base",
            wait=True,
        )
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == case["name"]
        assert res["spec"]["type"] == case["spec"]["type"]

        # Verify service exists
        service = kubernetes.show_service(case["name"], namespace)
        assert service is not None
        assert service["spec"]["type"] == case["spec"]["type"]
    finally:
        kubernetes.delete_service(case["name"], namespace, wait=True)


@pytest.fixture
def configmap_name():
    """
    Fixture providing a configmap name for testing

    Kubernetes requires names to be lowercase RFC 1123 complient
    """
    return random_string("configmap-", uppercase=False)


@pytest.fixture
def configmap_data():
    """
    Fixture providing a basic configmap data
    """
    return {"key": "value"}


@pytest.fixture(params=[True])
def configmap(kubernetes, configmap_name, configmap_data, request):
    """
    Fixture to create a test configmap.

    If request.param is True, configmap is created before the test.
    If
    request.param is False, configmap is not created.
    """
    name = configmap_name
    namespace = "default"

    # Only create the configmap if requested
    if request.param:
        res = kubernetes.create_configmap(name, namespace=namespace, data=configmap_data, wait=True)
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name

    try:
        yield {"name": name, "namespace": namespace}
    finally:
        kubernetes.delete_configmap(name, namespace, wait=True)


@pytest.mark.parametrize("configmap", [False], indirect=True)
def test_create_configmap(kubernetes, configmap):
    """
    Test creating a configmap returns expected result
    """
    res = kubernetes.create_configmap(
        name=configmap["name"],
        namespace=configmap["namespace"],
        data={"key": "value"},
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == configmap["name"]
    assert res["metadata"]["namespace"] == configmap["namespace"]


@pytest.mark.parametrize("configmap", [True], indirect=True)
def test_create_existing_configmap(kubernetes, configmap, configmap_data):
    """
    Test creating a configmap that already exists raises appropriate error
    """
    with pytest.raises(CommandExecutionError, match=".*already exists.*"):
        kubernetes.create_configmap(
            configmap["name"], configmap["namespace"], data=configmap_data, wait=True
        )


@pytest.mark.parametrize("configmap", [True], indirect=True)
def test_delete_existing_configmap(kubernetes, configmap):
    """
    Test deleting a configmap that exists returns expected result
    """
    res = kubernetes.delete_configmap(configmap["name"], configmap["namespace"], wait=True)
    assert isinstance(res, dict)

    # Verify configmap was actually deleted
    deleted_configmap = kubernetes.show_configmap(configmap["name"], configmap["namespace"])
    assert deleted_configmap is None


@pytest.mark.parametrize("configmap", [False], indirect=True)
def test_delete_nonexistent_configmap(kubernetes, configmap):
    """
    Test deleting a configmap that doesn't exist returns None
    """
    res = kubernetes.delete_configmap(configmap["name"], configmap["namespace"])
    assert res is None


@pytest.mark.parametrize("configmap", [True], indirect=True)
def test_configmap_special_data(kubernetes, configmap):
    """
    Test configmap with special data types and characters
    """
    special_data = {
        "config.yaml": "foo: bar\nkey: value",
        "special.data": "!@#$%^&*()\n\t\r\n",
        "unicode.txt": "Hello 世界",
    }

    # Create configmap
    res = kubernetes.replace_configmap(
        configmap["name"], namespace=configmap["namespace"], data=special_data, wait=True
    )
    assert isinstance(res, dict)
    assert res["data"] == special_data


@pytest.mark.parametrize("configmap", [True], indirect=True)
def test_configmap_large_data(kubernetes, configmap):
    """
    Test configmap with data approaching size limits
    """
    large_data = {"large-file.txt": "x" * 900000}  # 900KB of data

    # Create configmap
    res = kubernetes.replace_configmap(
        configmap["name"], namespace=configmap["namespace"], data=large_data, wait=True
    )
    assert isinstance(res, dict)
    assert res["data"] == large_data


@pytest.mark.parametrize("configmap", [True], indirect=True)
def test_configmap_with_special_characters(kubernetes, configmap):
    """
    Test configmap with special characters in data
    """
    special_data = {
        "special.conf": "key=value\n#comment\n$VAR=${OTHER_VAR}\nspecial_chars=!@#$%^&*()",
        "unicode.txt": "Hello 世界",
    }

    # Create configmap
    res = kubernetes.replace_configmap(
        configmap["name"], namespace=configmap["namespace"], data=special_data, wait=True
    )
    assert isinstance(res, dict)
    assert res["data"] == special_data


@pytest.fixture
def node_name(kubernetes):
    """
    Fixture providing a node name for testing
    """
    nodes = kubernetes.nodes()
    assert nodes, "No nodes found in cluster"
    node_name = next(node for node in nodes if "control-plane" in node)
    return node_name


@pytest.fixture(params=[True])
def node(kubernetes, request, node_name):
    """
    Fixture to create a test node.

    If request.param is True, node is created before the test.
    If
    request.param is False, node is not created.
    """

    label_key = "test.salt.label"
    label_value = "value"

    # Only create the node if requested
    if request.param:
        # check node labels
        initial_labels = kubernetes.node_labels(node_name)
        assert isinstance(initial_labels, dict)
        assert "kubernetes.io/hostname" in initial_labels

        # Add new label
        kubernetes.node_add_label(node_name, label_key, label_value)

        # Verify label was added
        updated_labels = kubernetes.node_labels(node_name)
        assert label_key in updated_labels
        assert updated_labels[label_key] == label_value
    try:
        yield node_name
    finally:
        # Cleanup - remove test label if it was created
        if request.param:
            kubernetes.node_remove_label(node_name, label_key)


@pytest.mark.parametrize("node", [True], indirect=True)
def test_node_add_label(kubernetes, node):
    """
    Test adding a label to a node returns expected result
    """
    res = kubernetes.node_labels(node)
    assert res["test.salt.label"] == "value"


@pytest.mark.parametrize("node", [True], indirect=True)
def test_node_remove_label(kubernetes, node):
    """
    Test removing a label from a node returns expected result
    """
    kubernetes.node_remove_label(node, "test.salt.label")
    # Verify the label was removed by checking the node's labels
    updated_labels = kubernetes.node_labels(node)
    assert "test.salt.label" not in updated_labels


@pytest.mark.parametrize("node", [False], indirect=True)
def test_node_multi_label_operations(kubernetes, node):
    """
    Test multiple label operations on nodes
    """
    test_labels = {
        "salt.test/label1": "value1",
        "salt.test/label2": "value2",
        "salt.test/label3": "value3",
    }

    try:
        # Add multiple labels
        for label, value in test_labels.items():
            kubernetes.node_add_label(node, label, value)

            # Verify all labels were added
            current_labels = kubernetes.node_labels(node)
            assert value in current_labels[label]
    finally:
        for label, value in test_labels.items():
            kubernetes.node_remove_label(node, label)
