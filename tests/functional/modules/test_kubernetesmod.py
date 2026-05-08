import logging

import pytest
from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms"),
]


@pytest.fixture(scope="module")
def kubernetes(modules):
    """
    Return the kubernetes execution module
    """
    return modules.kubernetes


def test_namespaces(kubernetes, namespace):
    """
    Test that the namespaces function returns a list of namespaces and includes the test namespace
    """
    res = kubernetes.namespaces()
    assert isinstance(res, list)
    assert namespace in res


@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_create_namespace(kubernetes, namespace):
    """
    Test creating a namespace returns expected result
    """

    res = kubernetes.create_namespace(namespace)
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == namespace


def test_create_existing_namespace(kubernetes, namespace):
    """
    Test creating a namespace that already exists raises appropriate error
    """
    with pytest.raises(CommandExecutionError, match=".*already exists.*"):
        kubernetes.create_namespace(namespace)


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
def pod_spec():
    """
    Fixture providing a basic pod spec
    """
    return {"containers": [{"name": "nginx", "image": "nginx:latest"}]}


def test_pods(kubernetes, pod):
    """
    Test that the pods function returns a list of pods in the specified namespace
    """
    res = kubernetes.pods(pod["namespace"])
    assert isinstance(res, list)
    assert pod["name"] in res


@pytest.mark.parametrize("pod", [False], indirect=True)
def test_create_pod(kubernetes, pod):
    """
    Test creating a pod returns expected result
    """
    res = kubernetes.create_pod(
        name=pod["name"],
        namespace=pod["namespace"],
        metadata={},
        spec=pod["spec"],
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == pod["name"]
    assert res["metadata"]["namespace"] == pod["namespace"]


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
def secret_data(request):
    """
    Fixture providing a basic secret data
    """
    typ = getattr(request, "param", "opaque")

    if typ == "opaque":
        return {"key": "value"}, "Opaque"
    if typ == "opaque_base64":
        return {"key": "dmFsdWU="}, "Opaque"
    if typ == "dockerconfigjson":
        return {
            ".dockerconfigjson": '{"auths":{"registry.example.com":{"username":"user","password":"pass"}}}'
        }, "kubernetes.io/dockerconfigjson"
    if typ == "basic_auth":
        return {"username": "user", "password": "pass"}, "kubernetes.io/basic-auth"
    if typ == "tls_pem":
        return {
            "tls.crt": "-----BEGIN CERTIFICATE-----\nMIICwjCCAaqgAwIBAgIBADANBgkqhkiG9w0BAQsFADAS\n-----END CERTIFICATE-----",
            "tls.key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEA\n-----END PRIVATE KEY-----",
        }, "kubernetes.io/tls"
    if typ == "tls_base64":
        return {
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
        }, "kubernetes.io/tls"
    raise ValueError(f"Unknown secret type: {typ}")


def test_secrets(kubernetes, secret):
    """
    Test that the secrets function returns a list of secrets in the specified namespace
    """
    res = kubernetes.secrets(secret["namespace"])
    assert isinstance(res, list)
    assert secret["name"] in res


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

    sec = kubernetes.show_secret(secret["name"], secret["namespace"], decode=True)
    assert sec["data"]["key"] == "value"


def test_create_existing_secret(kubernetes, secret, secret_data):
    """
    Test creating a secret that already exists raises appropriate error
    """
    with pytest.raises(CommandExecutionError, match=".*already exists.*"):
        kubernetes.create_secret(
            secret["name"], secret["namespace"], data=secret_data[0], wait=True
        )


def test_show_secret(kubernetes, secret, secret_data):
    """
    Test showing a secret returns expected result
    """
    res = kubernetes.show_secret(secret["name"], secret["namespace"], decode=True)
    assert isinstance(res, dict)
    assert res["data"]["key"] == secret_data[0]["key"]


@pytest.mark.parametrize("secret", [False], indirect=True)
def test_show_nonexistent_secret(kubernetes, secret):
    """
    Test showing a secret that doesn't exist returns None
    """
    res = kubernetes.show_secret(secret["name"], secret["namespace"])
    assert res is None


def test_replace_secret(kubernetes, secret, secret_data):
    """
    Test replacing a secret with new data
    """
    new_data = {"key": "new_value"}
    res = kubernetes.replace_secret(
        name=secret["name"],
        namespace=secret["namespace"],
        data=new_data,
        secret_type=secret_data[1],
        wait=True,
    )
    assert isinstance(res, dict)
    res = kubernetes.show_secret(secret["name"], secret["namespace"], decode=True)
    assert res["data"]["key"] == "new_value"


@pytest.mark.parametrize("secret", [False], indirect=True)
def test_replace_nonexistent_secret(kubernetes, secret, secret_data):
    """
    Test replacing a secret that doesn't exist raises appropriate error
    """
    new_data = {"key": "new_value"}
    with pytest.raises(CommandExecutionError, match=".*not found.*"):
        kubernetes.replace_secret(
            name=secret["name"],
            namespace=secret["namespace"],
            data=new_data,
            secret_type=secret_data[1],
            wait=True,
        )


def test_patch_secret(kubernetes, secret):
    """
    Test patching a secret to update data
    """
    patch = {"data": {"key": "patched_value"}}
    res = kubernetes.patch_secret(
        name=secret["name"],
        namespace=secret["namespace"],
        patch=patch,
        wait=True,
    )
    assert isinstance(res, dict)
    res = kubernetes.show_secret(secret["name"], secret["namespace"], decode=True)
    assert res["data"]["key"] == "patched_value"


@pytest.mark.parametrize("secret", [False], indirect=True)
def test_patch_nonexistent_secret(kubernetes, secret):
    """
    Test patching a secret that doesn't exist raises appropriate error
    """
    patch = {"data": {"key": "patched_value"}}
    with pytest.raises(CommandExecutionError, match=".*not found.*"):
        kubernetes.patch_secret(
            name=secret["name"],
            namespace=secret["namespace"],
            patch=patch,
            wait=True,
        )


def test_patch_preserves_keys_replace_removes_keys(kubernetes, secret, secret_data):
    """
    Test that patch preserves unspecified keys while replace removes them.
    """
    # Add an extra key via patch
    kubernetes.patch_secret(
        name=secret["name"],
        namespace=secret["namespace"],
        patch={"data": {"extra": "data"}},
        wait=True,
    )
    res = kubernetes.show_secret(secret["name"], secret["namespace"], decode=True)
    # Patch should preserve original key and add extra
    assert "key" in res["data"]
    assert res["data"]["extra"] == "data"

    # Replace with only the extra key
    kubernetes.replace_secret(
        name=secret["name"],
        namespace=secret["namespace"],
        data={"extra": "data"},
        secret_type=secret_data[1],
        wait=True,
    )
    res = kubernetes.show_secret(secret["name"], secret["namespace"], decode=True)
    # Replace should have removed the original key
    assert "key" not in res["data"]
    assert res["data"]["extra"] == "data"


def test_delete_existing_secret(kubernetes, secret):
    """
    Test deleting a secret that exists returns expected result
    """
    res = kubernetes.delete_secret(secret["name"], secret["namespace"], wait=True)
    assert isinstance(res, dict)

    # Verify secret was actually deleted
    deleted_secret = kubernetes.show_secret(secret["name"], secret["namespace"])
    assert deleted_secret is None


def test_secret_type_preservation(kubernetes, secret):
    """
    Test creating a secret with a specific type preserves the type
    """
    secret_type = kubernetes.show_secret(secret["name"], secret["namespace"])["type"]

    res = kubernetes.replace_secret(
        secret["name"],
        namespace=secret["namespace"],
        data=secret["data"],
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


@pytest.mark.usefixtures("secret_data")
@pytest.mark.parametrize(
    "secret_data,expected",
    [
        (
            "opaque",
            "value",
        ),
        (
            "opaque_base64",
            "value",
        ),
    ],
    indirect=["secret_data"],
)
def test_create_secret_inputs(secret, expected, kubernetes):
    """
    Test creating secrets with different input formats
    """

    # Verify decoded value
    res = kubernetes.show_secret(secret["name"], secret["namespace"], decode=True)
    assert res["data"]["key"] == expected


@pytest.mark.usefixtures("secret_data")
@pytest.mark.parametrize(
    "secret_data,replace,expected",
    [
        (
            "opaque",
            {"new_key": "new_value"},
            {"new_key": "new_value"},
        ),
        (
            "dockerconfigjson",
            {
                ".dockerconfigjson": '{"auths":{"registry.example.com":{"username":"new_user","password":"new_pass"}}}'
            },
            {
                ".dockerconfigjson": '{"auths":{"registry.example.com":{"username":"new_user","password":"new_pass"}}}'
            },
        ),
        (
            "basic_auth",
            {"username": "new_user", "password": "new_pass"},
            {"username": "new_user", "password": "new_pass"},
        ),
        (
            "tls_pem",
            {
                "tls.crt": "-----BEGIN CERTIFICATE-----\nNEW_CERTIFICATE\n-----END CERTIFICATE-----",
                "tls.key": "-----BEGIN PRIVATE KEY-----\nNEW_PRIVATE_KEY\n-----END PRIVATE KEY-----",
            },
            {
                "tls.crt": "-----BEGIN CERTIFICATE-----\nNEW_CERTIFICATE\n-----END CERTIFICATE-----",
                "tls.key": "-----BEGIN PRIVATE KEY-----\nNEW_PRIVATE_KEY\n-----END PRIVATE KEY-----",
            },
        ),
        (
            "tls_base64",
            {
                "tls.crt": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk5FVyBURVNUIENFUlQKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=",
                "tls.key": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk5FVyBURVNUIEtFWQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg==",
            },
            {
                "tls.crt": "-----BEGIN CERTIFICATE-----\nNEW TEST CERT\n-----END CERTIFICATE-----\n",
                "tls.key": "-----BEGIN PRIVATE KEY-----\nNEW TEST KEY\n-----END PRIVATE KEY-----\n",
            },
        ),
    ],
    indirect=["secret_data"],
)
def test_secret_types(kubernetes, secret, replace, expected):
    """
    Test creating and replacing secrets with different types
    """
    # Get initial secret state
    initial_secret = kubernetes.show_secret(secret["name"], secret["namespace"], decode=True)
    assert initial_secret is not None
    assert initial_secret["type"] == secret["type"]
    assert initial_secret["data"] == secret["data"]

    # Replace with new data
    kubernetes.replace_secret(
        name=secret["name"],
        namespace=secret["namespace"],
        data=replace,
        secret_type=secret["type"],
        wait=True,
    )

    # Verify type was preserved and data was updated
    updated_secret = kubernetes.show_secret(secret["name"], secret["namespace"], decode=True)
    assert updated_secret is not None
    assert updated_secret["type"] == secret["type"]
    assert updated_secret["data"] == expected


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


def test_deployments(kubernetes, deployment):
    """
    Test that the deployments function returns a list of deployments in the specified namespace
    """
    res = kubernetes.deployments(deployment["namespace"])
    assert isinstance(res, list)
    assert deployment["name"] in res


@pytest.mark.parametrize("deployment", [False], indirect=True)
def test_create_deployment(kubernetes, deployment):
    """
    Test creating a deployment returns expected result
    """
    res = kubernetes.create_deployment(
        name=deployment["name"],
        namespace=deployment["namespace"],
        metadata={},
        spec=deployment["spec"],
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == deployment["name"]
    assert res["metadata"]["namespace"] == deployment["namespace"]


def test_create_existing_deployment(kubernetes, deployment):
    """
    Test creating a deployment that already exists raises appropriate error
    """
    with pytest.raises(CommandExecutionError, match=".*already exists.*"):
        kubernetes.create_deployment(
            name=deployment["name"],
            namespace=deployment["namespace"],
            metadata={},
            spec=deployment["spec"],
            source=None,
            template=None,
            saltenv="base",
            wait=True,
        )


def test_show_deployment(kubernetes, deployment):
    """
    Test showing a deployment returns expected result
    """
    res = kubernetes.show_deployment(deployment["name"], deployment["namespace"])
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == deployment["name"]
    assert res["metadata"]["namespace"] == deployment["namespace"]
    assert res["spec"]["replicas"] == deployment["spec"]["replicas"]
    assert res["spec"]["selector"] == deployment["spec"]["selector"]


@pytest.mark.parametrize("deployment", [False], indirect=True)
def test_show_nonexistent_deployment(kubernetes, deployment):
    """
    Test showing a deployment that doesn't exist returns None
    """
    res = kubernetes.show_deployment(deployment["name"], deployment["namespace"])
    assert res is None


def test_replace_deployment(kubernetes, deployment):
    """
    Test replacing a deployment with new spec
    """
    new_spec = deployment["spec"].copy()
    new_spec["replicas"] = 2

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


@pytest.mark.parametrize("deployment", [False], indirect=True)
def test_replace_nonexistent_deployment(kubernetes, deployment):
    """
    Test replacing a deployment that doesn't exist raises appropriate error
    """
    new_spec = deployment["spec"].copy()
    new_spec["replicas"] = 2

    with pytest.raises(CommandExecutionError, match=".*not found.*"):
        kubernetes.replace_deployment(
            name=deployment["name"],
            namespace=deployment["namespace"],
            metadata={},
            spec=new_spec,
            source=None,
            template=None,
            saltenv="base",
            wait=True,
        )


def test_patch_deployment(kubernetes, deployment):
    """
    Test patching a deployment to change the number of replicas.
    """
    # Patch the deployment to change replicas from 1 to 2
    patch = {
        "spec": {
            "replicas": 2,
        }
    }
    res = kubernetes.patch_deployment(
        deployment["name"],
        deployment["namespace"],
        patch,
        wait=True,
        timeout=120,
    )
    assert isinstance(res, dict)
    assert res["spec"]["replicas"] == 2


@pytest.mark.parametrize("deployment", [False], indirect=True)
def test_patch_nonexistent_deployment(kubernetes, deployment):
    """
    Test patching a deployment that doesn't exist raises appropriate error
    """
    patch = {"spec": {"replicas": 2}}
    with pytest.raises(CommandExecutionError, match=".*not found.*"):
        kubernetes.patch_deployment(
            deployment["name"],
            deployment["namespace"],
            patch,
            wait=True,
            timeout=120,
        )


def test_patch_preserves_spec_replace_is_full_deployment(kubernetes, deployment):
    """
    Test that patch merges into spec while replace overwrites it entirely.
    """
    # Patch to add an annotation via spec.template.metadata
    kubernetes.patch_deployment(
        deployment["name"],
        deployment["namespace"],
        {"spec": {"template": {"metadata": {"annotations": {"note": "patched"}}}}},
        wait=True,
    )
    res = kubernetes.show_deployment(deployment["name"], deployment["namespace"])
    # Patch should have preserved replicas and added the annotation
    assert res["spec"]["replicas"] == 1
    assert res["spec"]["template"]["metadata"]["annotations"]["note"] == "patched"

    # Replace with original spec (no annotation) — should drop the annotation
    kubernetes.replace_deployment(
        name=deployment["name"],
        namespace=deployment["namespace"],
        metadata={},
        spec=deployment["spec"],
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )
    res = kubernetes.show_deployment(deployment["name"], deployment["namespace"])
    # Replace should have dropped the annotation
    assert not res["spec"]["template"]["metadata"].get("annotations", {})


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


def test_deployment_replacement(kubernetes, deployment):
    """
    Test replacing a deployment with new spec
    """
    deployment["spec"]["replicas"] = 2

    res = kubernetes.replace_deployment(
        name=deployment["name"],
        namespace=deployment["namespace"],
        metadata={},
        spec=deployment["spec"],
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["spec"]["replicas"] == 2


def test_deployment_present_with_patch(kubernetes, deployment):
    """
    Test patching a deployment with new spec
    """
    patch = {"spec": {"replicas": 3}}

    res = kubernetes.patch_deployment(
        name=deployment["name"],
        namespace=deployment["namespace"],
        patch=patch,
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["spec"]["replicas"] == 3


@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_list_deployments_in_nonexistent_namespace(kubernetes, namespace):
    """
    Test listing deployments in a namespace that doesn't exist returns empty list
    """
    res = kubernetes.deployments(namespace)
    assert res == []


def test_statefulsets(kubernetes, statefulset):
    """
    Test that the statefulsets function returns a list of statefulsets in the specified namespace
    """
    res = kubernetes.statefulsets(statefulset["namespace"])
    assert isinstance(res, list)
    assert statefulset["name"] in res


@pytest.mark.parametrize("statefulset", [False], indirect=True)
def test_create_statefulset(kubernetes, statefulset):
    """
    Test creating a statefulset returns expected result
    """
    res = kubernetes.create_statefulset(
        name=statefulset["name"],
        namespace=statefulset["namespace"],
        metadata={},
        spec=statefulset["spec"],
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == statefulset["name"]
    assert res["metadata"]["namespace"] == statefulset["namespace"]


def test_create_existing_statefulset(kubernetes, statefulset):
    """
    Test creating a statefulset that already exists raises appropriate error
    """
    with pytest.raises(CommandExecutionError, match=".*already exists.*"):
        kubernetes.create_statefulset(
            name=statefulset["name"],
            namespace=statefulset["namespace"],
            metadata={},
            spec=statefulset["spec"],
            source=None,
            template=None,
            saltenv="base",
            wait=True,
        )


def test_show_statefulset(kubernetes, statefulset):
    """
    Test showing a statefulset returns expected result
    """
    res = kubernetes.show_statefulset(statefulset["name"], statefulset["namespace"])
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == statefulset["name"]
    assert res["metadata"]["namespace"] == statefulset["namespace"]
    assert res["spec"]["replicas"] == statefulset["spec"]["replicas"]
    assert res["spec"]["selector"] == statefulset["spec"]["selector"]


@pytest.mark.parametrize("statefulset", [False], indirect=True)
def test_show_nonexistent_statefulset(kubernetes, statefulset):
    """
    Test showing a statefulset that doesn't exist returns None
    """
    res = kubernetes.show_statefulset(statefulset["name"], statefulset["namespace"])
    assert res is None


def test_replace_statefulset(kubernetes, statefulset):
    """
    Test replacing a statefulset with new spec
    """
    new_spec = statefulset["spec"].copy()
    new_spec["replicas"] = 2

    res = kubernetes.replace_statefulset(
        name=statefulset["name"],
        namespace=statefulset["namespace"],
        metadata={},
        spec=new_spec,
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["spec"]["replicas"] == 2


@pytest.mark.parametrize("statefulset", [False], indirect=True)
def test_replace_nonexistent_statefulset(kubernetes, statefulset):
    """
    Test replacing a statefulset that doesn't exist raises appropriate error
    """
    new_spec = statefulset["spec"].copy()
    new_spec["replicas"] = 2

    with pytest.raises(CommandExecutionError, match=".*not found.*"):
        kubernetes.replace_statefulset(
            name=statefulset["name"],
            namespace=statefulset["namespace"],
            metadata={},
            spec=new_spec,
            source=None,
            template=None,
            saltenv="base",
            wait=True,
        )


def test_patch_statefulset(kubernetes, statefulset):
    """
    Test patching a statefulset to change the number of replicas.
    """
    patch = {
        "spec": {
            "replicas": 2,
        }
    }
    res = kubernetes.patch_statefulset(
        statefulset["name"],
        statefulset["namespace"],
        patch,
        wait=True,
        timeout=120,
    )
    assert isinstance(res, dict)
    assert res["spec"]["replicas"] == 2


@pytest.mark.parametrize("statefulset", [False], indirect=True)
def test_patch_nonexistent_statefulset(kubernetes, statefulset):
    """
    Test patching a statefulset that doesn't exist raises appropriate error
    """
    patch = {"spec": {"replicas": 2}}
    with pytest.raises(CommandExecutionError, match=".*not found.*"):
        kubernetes.patch_statefulset(
            statefulset["name"],
            statefulset["namespace"],
            patch,
            wait=True,
            timeout=120,
        )


def test_patch_preserves_spec_replace_is_full_statefulset(kubernetes, statefulset):
    """
    Test that patch merges into spec while replace overwrites it entirely.
    """
    kubernetes.patch_statefulset(
        statefulset["name"],
        statefulset["namespace"],
        {"spec": {"template": {"metadata": {"annotations": {"note": "patched"}}}}},
        wait=True,
    )
    res = kubernetes.show_statefulset(statefulset["name"], statefulset["namespace"])
    assert res["spec"]["replicas"] == 1
    assert res["spec"]["template"]["metadata"]["annotations"]["note"] == "patched"

    kubernetes.replace_statefulset(
        name=statefulset["name"],
        namespace=statefulset["namespace"],
        metadata={},
        spec=statefulset["spec"],
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )
    res = kubernetes.show_statefulset(statefulset["name"], statefulset["namespace"])
    assert not res["spec"]["template"]["metadata"].get("annotations", {})


def test_delete_existing_statefulset(kubernetes, statefulset):
    """
    Test deleting a statefulset that exists returns expected result
    """
    res = kubernetes.delete_statefulset(statefulset["name"], statefulset["namespace"], wait=True)
    assert isinstance(res, dict)

    deleted_statefulset = kubernetes.show_statefulset(statefulset["name"], statefulset["namespace"])
    assert deleted_statefulset is None


@pytest.mark.parametrize("statefulset", [False], indirect=True)
def test_delete_nonexistent_statefulset(kubernetes, statefulset):
    """
    Test deleting a statefulset that doesn't exist returns None
    """
    res = kubernetes.delete_statefulset(statefulset["name"], statefulset["namespace"])
    assert res is None


@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_list_statefulsets_in_nonexistent_namespace(kubernetes, namespace):
    """
    Test listing statefulsets in a namespace that doesn't exist returns empty list
    """
    res = kubernetes.statefulsets(namespace)
    assert res == []


def test_replicasets(kubernetes, replicaset):
    """
    Test that the replicasets function returns a list of replicasets in the specified namespace
    """
    res = kubernetes.replicasets(replicaset["namespace"])
    assert isinstance(res, list)
    assert replicaset["name"] in res


@pytest.mark.parametrize("replicaset", [False], indirect=True)
def test_create_replicaset(kubernetes, replicaset):
    """
    Test creating a replicaset returns expected result
    """
    res = kubernetes.create_replicaset(
        name=replicaset["name"],
        namespace=replicaset["namespace"],
        metadata={},
        spec=replicaset["spec"],
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == replicaset["name"]
    assert res["metadata"]["namespace"] == replicaset["namespace"]


def test_create_existing_replicaset(kubernetes, replicaset):
    """
    Test creating a replicaset that already exists raises appropriate error
    """
    with pytest.raises(CommandExecutionError, match=".*already exists.*"):
        kubernetes.create_replicaset(
            name=replicaset["name"],
            namespace=replicaset["namespace"],
            metadata={},
            spec=replicaset["spec"],
            source=None,
            template=None,
            saltenv="base",
            wait=True,
        )


def test_show_replicaset(kubernetes, replicaset):
    """
    Test showing a replicaset returns expected result
    """
    res = kubernetes.show_replicaset(replicaset["name"], replicaset["namespace"])
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == replicaset["name"]
    assert res["metadata"]["namespace"] == replicaset["namespace"]
    assert res["spec"]["replicas"] == replicaset["spec"]["replicas"]
    assert res["spec"]["selector"] == replicaset["spec"]["selector"]


@pytest.mark.parametrize("replicaset", [False], indirect=True)
def test_show_nonexistent_replicaset(kubernetes, replicaset):
    """
    Test showing a replicaset that doesn't exist returns None
    """
    res = kubernetes.show_replicaset(replicaset["name"], replicaset["namespace"])
    assert res is None


def test_replace_replicaset(kubernetes, replicaset):
    """
    Test replacing a replicaset with new spec
    """
    new_spec = replicaset["spec"].copy()
    new_spec["replicas"] = 2

    res = kubernetes.replace_replicaset(
        name=replicaset["name"],
        namespace=replicaset["namespace"],
        metadata={},
        spec=new_spec,
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["spec"]["replicas"] == 2


@pytest.mark.parametrize("replicaset", [False], indirect=True)
def test_replace_nonexistent_replicaset(kubernetes, replicaset):
    """
    Test replacing a replicaset that doesn't exist raises appropriate error
    """
    new_spec = replicaset["spec"].copy()
    new_spec["replicas"] = 2

    with pytest.raises(CommandExecutionError, match=".*not found.*"):
        kubernetes.replace_replicaset(
            name=replicaset["name"],
            namespace=replicaset["namespace"],
            metadata={},
            spec=new_spec,
            source=None,
            template=None,
            saltenv="base",
            wait=True,
        )


def test_patch_replicaset(kubernetes, replicaset):
    """
    Test patching a replicaset to change the number of replicas.
    """
    patch = {
        "spec": {
            "replicas": 2,
        }
    }
    res = kubernetes.patch_replicaset(
        replicaset["name"],
        replicaset["namespace"],
        patch,
        wait=True,
        timeout=120,
    )
    assert isinstance(res, dict)
    assert res["spec"]["replicas"] == 2


@pytest.mark.parametrize("replicaset", [False], indirect=True)
def test_patch_nonexistent_replicaset(kubernetes, replicaset):
    """
    Test patching a replicaset that doesn't exist raises appropriate error
    """
    patch = {"spec": {"replicas": 2}}
    with pytest.raises(CommandExecutionError, match=".*not found.*"):
        kubernetes.patch_replicaset(
            replicaset["name"],
            replicaset["namespace"],
            patch,
            wait=True,
            timeout=120,
        )


def test_patch_preserves_spec_replace_is_full_replicaset(kubernetes, replicaset):
    """
    Test that patch merges into spec while replace overwrites it entirely.
    """
    kubernetes.patch_replicaset(
        replicaset["name"],
        replicaset["namespace"],
        {"spec": {"template": {"metadata": {"annotations": {"note": "patched"}}}}},
        wait=True,
    )
    res = kubernetes.show_replicaset(replicaset["name"], replicaset["namespace"])
    assert res["spec"]["replicas"] == 1
    assert res["spec"]["template"]["metadata"]["annotations"]["note"] == "patched"

    kubernetes.replace_replicaset(
        name=replicaset["name"],
        namespace=replicaset["namespace"],
        metadata={},
        spec=replicaset["spec"],
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )
    res = kubernetes.show_replicaset(replicaset["name"], replicaset["namespace"])
    assert not res["spec"]["template"]["metadata"].get("annotations", {})


def test_delete_existing_replicaset(kubernetes, replicaset):
    """
    Test deleting a replicaset that exists returns expected result
    """
    res = kubernetes.delete_replicaset(replicaset["name"], replicaset["namespace"], wait=True)
    assert isinstance(res, dict)

    deleted_replicaset = kubernetes.show_replicaset(replicaset["name"], replicaset["namespace"])
    assert deleted_replicaset is None


@pytest.mark.parametrize("replicaset", [False], indirect=True)
def test_delete_nonexistent_replicaset(kubernetes, replicaset):
    """
    Test deleting a replicaset that doesn't exist returns None
    """
    res = kubernetes.delete_replicaset(replicaset["name"], replicaset["namespace"])
    assert res is None


@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_list_replicasets_in_nonexistent_namespace(kubernetes, namespace):
    """
    Test listing replicasets in a namespace that doesn't exist returns empty list
    """
    res = kubernetes.replicasets(namespace)
    assert res == []


def test_daemonsets(kubernetes, daemonset):
    """
    Test that the daemonsets function returns a list of daemonsets in the specified namespace
    """
    res = kubernetes.daemonsets(daemonset["namespace"])
    assert isinstance(res, list)
    assert daemonset["name"] in res


@pytest.mark.parametrize("daemonset", [False], indirect=True)
def test_create_daemonset(kubernetes, daemonset):
    """
    Test creating a daemonset returns expected result
    """
    res = kubernetes.create_daemonset(
        name=daemonset["name"],
        namespace=daemonset["namespace"],
        metadata={},
        spec=daemonset["spec"],
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == daemonset["name"]
    assert res["metadata"]["namespace"] == daemonset["namespace"]


def test_create_existing_daemonset(kubernetes, daemonset):
    """
    Test creating a daemonset that already exists raises appropriate error
    """
    with pytest.raises(CommandExecutionError, match=".*already exists.*"):
        kubernetes.create_daemonset(
            name=daemonset["name"],
            namespace=daemonset["namespace"],
            metadata={},
            spec=daemonset["spec"],
            source=None,
            template=None,
            saltenv="base",
            wait=True,
        )


def test_show_daemonset(kubernetes, daemonset):
    """
    Test showing a daemonset returns expected result
    """
    res = kubernetes.show_daemonset(daemonset["name"], daemonset["namespace"])
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == daemonset["name"]
    assert res["metadata"]["namespace"] == daemonset["namespace"]


@pytest.mark.parametrize("daemonset", [False], indirect=True)
def test_show_nonexistent_daemonset(kubernetes, daemonset):
    """
    Test showing a daemonset that doesn't exist returns None
    """
    res = kubernetes.show_daemonset(daemonset["name"], daemonset["namespace"])
    assert res is None


def test_replace_daemonset(kubernetes, daemonset):
    """
    Test replacing a daemonset with new spec
    """
    new_spec = daemonset["spec"].copy()
    new_spec["template"] = {
        "metadata": {"labels": {"app": "nginx"}},
        "spec": {"containers": [{"name": "nginx", "image": "nginx:1.27"}]},
    }

    res = kubernetes.replace_daemonset(
        name=daemonset["name"],
        namespace=daemonset["namespace"],
        metadata={},
        spec=new_spec,
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["spec"]["template"]["spec"]["containers"][0]["image"] == "nginx:1.27"


@pytest.mark.parametrize("daemonset", [False], indirect=True)
def test_replace_nonexistent_daemonset(kubernetes, daemonset):
    """
    Test replacing a daemonset that doesn't exist raises appropriate error
    """
    with pytest.raises(CommandExecutionError, match=".*not found.*"):
        kubernetes.replace_daemonset(
            name=daemonset["name"],
            namespace=daemonset["namespace"],
            metadata={},
            spec=daemonset["spec"],
            source=None,
            template=None,
            saltenv="base",
            wait=True,
        )


def test_patch_daemonset(kubernetes, daemonset):
    """
    Test patching a daemonset to update pod template metadata.
    """
    patch = {
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "patched": "true",
                    }
                }
            }
        }
    }
    res = kubernetes.patch_daemonset(
        daemonset["name"],
        daemonset["namespace"],
        patch,
        wait=True,
        timeout=120,
    )
    assert isinstance(res, dict)
    assert res["spec"]["template"]["metadata"]["annotations"]["patched"] == "true"


@pytest.mark.parametrize("daemonset", [False], indirect=True)
def test_patch_nonexistent_daemonset(kubernetes, daemonset):
    """
    Test patching a daemonset that doesn't exist raises appropriate error
    """
    patch = {"spec": {"template": {"metadata": {"annotations": {"patched": "true"}}}}}
    with pytest.raises(CommandExecutionError, match=".*not found.*"):
        kubernetes.patch_daemonset(
            daemonset["name"],
            daemonset["namespace"],
            patch,
            wait=True,
            timeout=120,
        )


def test_patch_preserves_spec_replace_is_full_daemonset(kubernetes, daemonset):
    """
    Test that patch merges into spec while replace overwrites it entirely.
    """
    kubernetes.patch_daemonset(
        daemonset["name"],
        daemonset["namespace"],
        {"spec": {"template": {"metadata": {"annotations": {"note": "patched"}}}}},
        wait=True,
    )
    res = kubernetes.show_daemonset(daemonset["name"], daemonset["namespace"])
    assert res["spec"]["template"]["metadata"]["annotations"]["note"] == "patched"

    kubernetes.replace_daemonset(
        name=daemonset["name"],
        namespace=daemonset["namespace"],
        metadata={},
        spec=daemonset["spec"],
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )
    res = kubernetes.show_daemonset(daemonset["name"], daemonset["namespace"])
    assert not res["spec"]["template"]["metadata"].get("annotations", {})


def test_delete_existing_daemonset(kubernetes, daemonset):
    """
    Test deleting a daemonset that exists returns expected result
    """
    res = kubernetes.delete_daemonset(daemonset["name"], daemonset["namespace"], wait=True)
    assert isinstance(res, dict)

    deleted_daemonset = kubernetes.show_daemonset(daemonset["name"], daemonset["namespace"])
    assert deleted_daemonset is None


@pytest.mark.parametrize("daemonset", [False], indirect=True)
def test_delete_nonexistent_daemonset(kubernetes, daemonset):
    """
    Test deleting a daemonset that doesn't exist returns None
    """
    res = kubernetes.delete_daemonset(daemonset["name"], daemonset["namespace"])
    assert res is None


@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_list_daemonsets_in_nonexistent_namespace(kubernetes, namespace):
    """
    Test listing daemonsets in a namespace that doesn't exist returns empty list
    """
    res = kubernetes.daemonsets(namespace)
    assert res == []


@pytest.fixture
def service_spec(request):
    """
    Fixture providing service data based on type
    """
    typ = getattr(request, "param", "ClusterIP")

    if typ == "ClusterIP":
        return {"ports": [{"port": 80}], "selector": {"app": "nginx"}, "type": "ClusterIP"}
    if typ == "NodePort":
        return {
            "ports": [{"port": 80, "nodePort": 30080}],
            "selector": {"app": "nginx"},
            "type": "NodePort",
        }
    if typ == "LoadBalancer":
        return {"ports": [{"port": 80}], "selector": {"app": "nginx"}, "type": "LoadBalancer"}
    raise ValueError(f"Unknown service type: {typ}")


def test_services(kubernetes, service):
    """
    Test that the services function returns a list of services in the specified namespace
    """
    res = kubernetes.services(service["namespace"])
    assert isinstance(res, list)
    assert service["name"] in res


@pytest.mark.parametrize("service", [False], indirect=True)
def test_create_service(kubernetes, service):
    """
    Test creating a service returns expected result
    """
    res = kubernetes.create_service(
        name=service["name"],
        namespace=service["namespace"],
        metadata={},
        spec=service["spec"],
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == service["name"]
    assert res["metadata"]["namespace"] == service["namespace"]


def test_create_existing_service(kubernetes, service):
    """
    Test creating a service that already exists raises appropriate error
    """
    with pytest.raises(CommandExecutionError, match=".*already exists.*"):
        kubernetes.create_service(
            name=service["name"],
            namespace=service["namespace"],
            metadata={},
            spec=service["spec"],
            source=None,
            template=None,
            saltenv="base",
            wait=True,
        )


def test_show_service(kubernetes, service):
    """
    Test showing a service returns expected result
    """
    res = kubernetes.show_service(service["name"], service["namespace"])
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == service["name"]
    assert res["metadata"]["namespace"] == service["namespace"]
    assert res["spec"]["type"] == service["spec"]["type"]
    assert res["spec"]["selector"] == service["spec"]["selector"]
    # K8s adds default fields (protocol, targetPort) to ports
    for i, expected_port in enumerate(service["spec"]["ports"]):
        for key, val in expected_port.items():
            assert res["spec"]["ports"][i][key] == val


@pytest.mark.parametrize("service", [False], indirect=True)
def test_show_nonexistent_service(kubernetes, service):
    """
    Test showing a service that doesn't exist returns None
    """
    res = kubernetes.show_service(service["name"], service["namespace"])
    assert res is None


def test_replace_service(kubernetes, service):
    """
    Test replacing a service with new spec
    """
    old_service = kubernetes.show_service(service["name"], service["namespace"])
    new_spec = service["spec"].copy()
    new_spec["ports"] = [{"port": 8080}]

    res = kubernetes.replace_service(
        name=service["name"],
        namespace=service["namespace"],
        metadata={},
        spec=new_spec,
        old_service=old_service,
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["spec"]["ports"][0]["port"] == 8080


@pytest.mark.parametrize("service", [False], indirect=True)
def test_replace_nonexistent_service(kubernetes, service):
    """
    Test replacing a service that doesn't exist raises appropriate error
    """
    new_spec = service["spec"].copy()
    new_spec["ports"] = [{"port": 8080}]
    fake_old_service = {
        "metadata": {"resourceVersion": "1"},
        "spec": {"clusterIP": "None"},
    }

    with pytest.raises(CommandExecutionError):
        kubernetes.replace_service(
            name=service["name"],
            namespace="nonexistent-namespace",
            metadata={},
            spec=new_spec,
            old_service=fake_old_service,
            source=None,
            template=None,
            saltenv="base",
            wait=True,
        )


def test_patch_service(kubernetes, service):
    """
    Test patching a service to update selector
    """
    patch = {"spec": {"selector": {"app": "patched-nginx"}}}
    res = kubernetes.patch_service(
        name=service["name"],
        namespace=service["namespace"],
        patch=patch,
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["spec"]["selector"]["app"] == "patched-nginx"


@pytest.mark.parametrize("service", [False], indirect=True)
def test_patch_nonexistent_service(kubernetes, service):
    """
    Test patching a service that doesn't exist raises appropriate error
    """
    patch = {"spec": {"ports": [{"port": 8080}]}}
    with pytest.raises(CommandExecutionError, match=".*not found.*"):
        kubernetes.patch_service(
            name=service["name"],
            namespace=service["namespace"],
            patch=patch,
            wait=True,
        )


def test_patch_preserves_ports_replace_drops_them_service(kubernetes, service):
    """
    Test that patch merges into spec while replace overwrites it entirely.
    """
    # Patch to add a second port (original has port 80)
    kubernetes.patch_service(
        name=service["name"],
        namespace=service["namespace"],
        patch={"spec": {"ports": [{"name": "http", "port": 80}, {"name": "extra", "port": 9090}]}},
        wait=True,
    )
    res = kubernetes.show_service(service["name"], service["namespace"])
    ports = {p["port"] for p in res["spec"]["ports"]}
    assert 80 in ports
    assert 9090 in ports

    # Replace with spec that only has port 8080 — should drop both old ports
    old_service = kubernetes.show_service(service["name"], service["namespace"])
    new_spec = {"ports": [{"port": 8080}], "selector": {"app": "nginx"}, "type": "ClusterIP"}
    kubernetes.replace_service(
        name=service["name"],
        namespace=service["namespace"],
        metadata={},
        spec=new_spec,
        old_service=old_service,
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )
    res = kubernetes.show_service(service["name"], service["namespace"])
    ports = {p["port"] for p in res["spec"]["ports"]}
    # Replace should have only the new port
    assert ports == {8080}


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


@pytest.mark.usefixtures("service_spec")
@pytest.mark.parametrize(
    "service_spec,replace",
    [
        (
            "ClusterIP",
            {"ports": [{"port": 8080}]},
        ),
        (
            "NodePort",
            {"ports": [{"port": 8080, "nodePort": 30081}]},
        ),
        (
            "LoadBalancer",
            {"ports": [{"port": 8080}]},
        ),
    ],
    indirect=["service_spec"],
)
def test_service_different_types(kubernetes, service, replace):
    """
    Test creating and replacing services with different types
    """
    # Get initial service state
    old_service = kubernetes.show_service(service["name"], service["namespace"])
    assert old_service is not None
    assert old_service["spec"]["type"] == service["type"]

    service["spec"].update(replace)
    # Replace with new data
    kubernetes.replace_service(
        name=service["name"],
        namespace=service["namespace"],
        metadata={},
        spec=service["spec"],
        old_service=old_service,
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )

    updated_service = kubernetes.show_service(service["name"], service["namespace"])
    assert updated_service is not None
    assert updated_service["spec"]["type"] == service["type"]
    assert updated_service["spec"]["ports"][0]["port"] == replace["ports"][0]["port"]


@pytest.fixture
def configmap_data(request):
    """
    Fixture providing a basic configmap data
    """
    data = getattr(request, "param", "default")
    if data == "default":
        return {"key": "value"}
    if data == "config.yaml":
        return {"config.yaml": "foo: bar\nkey: value"}
    if data == "special.data":
        return {"special.data": "!@#$%^&*()\n\t\r\n"}
    if data == "unicode.txt":
        return {"unicode.txt": "Hello 世界"}
    if data == "large.data":
        return {"large.data": "x" * 900000}
    if data == "special.conf":
        return {"special.conf": "key=value\n#comment\n$VAR=${OTHER_VAR}\nspecial_chars=!@#$%^&*()"}
    raise ValueError(f"Unknown configmap data type: {data}")


def test_configmaps(kubernetes, configmap):
    """
    Test that the configmaps function returns a list of configmap names in the specified namespace
    """
    res = kubernetes.configmaps(configmap["namespace"])
    assert isinstance(res, list)
    assert configmap["name"] in res


@pytest.mark.usefixtures("configmap_data")
@pytest.mark.parametrize(
    "configmap_data,expected",
    [
        (
            "default",
            {"key": "value"},
        ),
        (
            "config.yaml",
            {"config.yaml": "foo: bar\nkey: value"},
        ),
        (
            "special.data",
            {"special.data": "!@#$%^&*()\n\t\r\n"},
        ),
        (
            "unicode.txt",
            {"unicode.txt": "Hello 世界"},
        ),
        (
            "large.data",
            {"large.data": "x" * 900000},
        ),
        (
            "special.conf",
            {"special.conf": "key=value\n#comment\n$VAR=${OTHER_VAR}\nspecial_chars=!@#$%^&*()"},
        ),
    ],
    indirect=["configmap_data"],
)
def test_create_configmap(kubernetes, configmap, expected):
    """
    Test creating a configmap returns expected result
    """
    res = kubernetes.show_configmap(configmap["name"], configmap["namespace"])
    assert isinstance(res, dict)
    assert res["data"] == expected


def test_create_existing_configmap(kubernetes, configmap):
    """
    Test creating a configmap that already exists raises appropriate error
    """
    with pytest.raises(CommandExecutionError, match=".*already exists.*"):
        kubernetes.create_configmap(
            configmap["name"], configmap["namespace"], data=configmap["data"], wait=True
        )


def test_show_configmap(kubernetes, configmap):
    """
    Test showing a configmap returns expected result
    """
    res = kubernetes.show_configmap(configmap["name"], configmap["namespace"])
    assert isinstance(res, dict)
    assert res["data"] == configmap["data"]


@pytest.mark.parametrize("configmap", [False], indirect=True)
def test_show_nonexistent_configmap(kubernetes, configmap):
    """
    Test showing a configmap that doesn't exist returns None
    """
    res = kubernetes.show_configmap(configmap["name"], configmap["namespace"])
    assert res is None


def test_replace_configmap(kubernetes, configmap):
    """
    Test replacing a configmap with new data
    """
    new_data = {"key": "new_value"}
    res = kubernetes.replace_configmap(
        name=configmap["name"],
        namespace=configmap["namespace"],
        data=new_data,
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["data"] == new_data


@pytest.mark.parametrize("configmap", [False], indirect=True)
def test_replace_nonexistent_configmap(kubernetes, configmap):
    """
    Test replacing a configmap that doesn't exist raises appropriate error
    """
    new_data = {"key": "new_value"}
    with pytest.raises(CommandExecutionError, match=".*not found.*"):
        kubernetes.replace_configmap(
            name=configmap["name"],
            namespace=configmap["namespace"],
            data=new_data,
            wait=True,
        )


def test_patch_configmap(kubernetes, configmap):
    """
    Test patching a configmap to update data
    """
    patch = {"data": {"key": "patched_value"}}
    res = kubernetes.patch_configmap(
        name=configmap["name"],
        namespace=configmap["namespace"],
        patch=patch,
        wait=True,
    )
    assert isinstance(res, dict)
    assert res["data"]["key"] == "patched_value"


@pytest.mark.parametrize("configmap", [False], indirect=True)
def test_patch_nonexistent_configmap(kubernetes, configmap):
    """
    Test patching a configmap that doesn't exist raises appropriate error
    """
    patch = {"data": {"key": "patched_value"}}
    with pytest.raises(CommandExecutionError, match=".*not found.*"):
        kubernetes.patch_configmap(
            name=configmap["name"],
            namespace=configmap["namespace"],
            patch=patch,
            wait=True,
        )


def test_patch_preserves_keys_replace_removes_keys_configmap(kubernetes, configmap):
    """
    Test that patch preserves unspecified keys while replace removes them.
    """
    # Add an extra key via patch
    kubernetes.patch_configmap(
        name=configmap["name"],
        namespace=configmap["namespace"],
        patch={"data": {"extra": "data"}},
        wait=True,
    )
    res = kubernetes.show_configmap(configmap["name"], configmap["namespace"])
    # Patch should preserve original key and add extra
    assert "key" in res["data"]
    assert res["data"]["extra"] == "data"

    # Replace with only the extra key
    kubernetes.replace_configmap(
        name=configmap["name"],
        namespace=configmap["namespace"],
        data={"extra": "data"},
        wait=True,
    )
    res = kubernetes.show_configmap(configmap["name"], configmap["namespace"])
    # Replace should have removed the original key
    assert "key" not in res["data"]
    assert res["data"]["extra"] == "data"


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


@pytest.mark.parametrize("labeled_node", [False], indirect=True)
def test_node_add_label(kubernetes, labeled_node):
    """
    Test adding a label to a node returns expected result
    """
    kubernetes.node_add_label(labeled_node["name"], "test.salt.label", "value")
    res = kubernetes.node_labels(labeled_node["name"])
    assert res["test.salt.label"] == "value"


def test_node_remove_label(kubernetes, labeled_node):
    """
    Test removing a label from a node returns expected result
    """
    label_to_delete = next(iter(labeled_node["labels"]))
    kubernetes.node_remove_label(labeled_node["name"], label_to_delete)
    # Verify the label was removed by checking the node's labels
    updated_labels = kubernetes.node_labels(labeled_node["name"])
    assert label_to_delete not in updated_labels


@pytest.mark.parametrize("labeled_node", [False], indirect=True)
def test_node_multi_label_operations(kubernetes, labeled_node):
    """
    Test multiple label operations on nodes
    """
    test_labels = {
        "salt.test/label1": "value1",
        "salt.test/label2": "value2",
        "salt.test/label3": "value3",
    }

    # Add multiple labels
    for label, value in test_labels.items():
        kubernetes.node_add_label(labeled_node["name"], label, value)

    # Verify all labels were added
    current_labels = kubernetes.node_labels(labeled_node["name"])
    for label, value in test_labels.items():
        assert label in current_labels
        assert current_labels[label] == value
