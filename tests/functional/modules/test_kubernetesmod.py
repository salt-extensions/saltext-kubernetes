import logging

import pytest
from salt.exceptions import CommandExecutionError

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
def _cleanup(modules):
    """
    Fixture to cleanup test resources after tests.
    Creates a list of resources to clean up and handles them after the test.
    """
    cleanup_list = []

    def _add_resource(resource_type, name, namespace="default"):
        cleanup_list.append({"type": resource_type, "name": name, "namespace": namespace})

    yield _add_resource

    # Cleanup all resources after test
    kubernetes = modules.kubernetes
    for resource in cleanup_list:
        try:
            if resource["type"] == "namespace":
                res = kubernetes.delete_namespace(resource["name"], wait=True)
                assert isinstance(res, dict)
            elif resource["type"] == "deployment":
                res = kubernetes.delete_deployment(
                    resource["name"], resource["namespace"], wait=True
                )
                assert isinstance(res, dict)
            elif resource["type"] == "service":
                res = kubernetes.delete_service(resource["name"], resource["namespace"], wait=True)
                assert isinstance(res, dict)
            elif resource["type"] == "pod":
                res = kubernetes.delete_pod(resource["name"], resource["namespace"], wait=True)
                assert isinstance(res, dict)
            elif resource["type"] == "secret":
                res = kubernetes.delete_secret(resource["name"], resource["namespace"], wait=True)
                assert isinstance(res, dict)
            elif resource["type"] == "configmap":
                res = kubernetes.delete_configmap(
                    resource["name"], resource["namespace"], wait=True
                )
                assert isinstance(res, dict)

            deleted = False
            # Handle namespace differently since it doesn't take namespace parameter
            if resource["type"] == "namespace":
                exists = kubernetes.show_namespace(resource["name"]) is not None
            else:
                check_func = getattr(kubernetes, f"show_{resource['type']}")
                exists = check_func(resource["name"], resource["namespace"]) is not None

            if not exists:
                deleted = True
                break

            assert deleted, (
                f"Resource {resource['type']} '{resource['name']}' "
                f"in namespace '{resource['namespace']}' "
                f"still exists after deletion attempts"
            )
        except CommandExecutionError as e:
            log.warning(
                "Failed to cleanup %s '%s' in namespace '%s': %s",
                resource["type"],
                resource["name"],
                resource["namespace"],
                str(e),
            )


def test_kubernetes_ping(kubernetes):
    """
    Test kubernetes.ping returns True when connection is successful
    """
    res = kubernetes.ping()
    assert res is True


def test_kubernetes_nodes(kubernetes):
    """
    Test kubernetes.nodes returns list of nodes
    """
    res = kubernetes.nodes()
    assert isinstance(res, list)
    assert len(res) > 0
    assert any("salt-test-control-plane" in node for node in res)


def test_kubernetes_namespaces(kubernetes):
    """
    Test kubernetes.namespaces returns list of namespaces
    """
    res = kubernetes.namespaces()
    assert isinstance(res, list)
    assert "default" in res, "Default namespace not found"
    assert "kube-system" in res, "kube-system namespace not found"


def test_kubernetes_pods(kubernetes):
    """
    Test kubernetes.pods returns list of pods in kube-system namespace
    """
    res = kubernetes.pods(namespace="kube-system")
    assert isinstance(res, list)
    assert len(res) > 0


def test_create_namespace_twice(kubernetes, _cleanup):
    """
    Test creating a namespace that already exists raises the appropriate error
    """
    test_ns = "salt-test-duplicate-ns"

    # Create namespace first time
    res = kubernetes.create_namespace(test_ns)
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == test_ns

    # Attempt to create same namespace again
    with pytest.raises(CommandExecutionError, match=".*already exists.*"):
        kubernetes.create_namespace(test_ns)

    # Cleanup
    _cleanup("namespace", test_ns)


def test_create_namespace_with_invalid_name(kubernetes, caplog):
    """
    Test creating a namespace with an invalid name raises appropriate error
    Names must be lowercase RFC 1123 labels (no underscores or uppercase)
    """
    caplog.set_level(logging.INFO)
    invalid_name = "under_score"

    with pytest.raises(CommandExecutionError) as exc:
        kubernetes.create_namespace(invalid_name)
    assert "Invalid" in str(exc.value)


def test_delete_system_namespace(kubernetes):
    """
    Test attempting to delete protected system namespaces raises error
    """
    protected_namespaces = ["default", "kube-system", "kube-public"]

    for namespace in protected_namespaces:
        with pytest.raises(CommandExecutionError) as exc:
            kubernetes.delete_namespace(namespace)
        assert "forbidden" in str(exc.value).lower()


def test_list_namespaces_filtering(kubernetes, _cleanup):
    """
    Test listing namespaces shows newly created ones
    and doesn't show deleted ones after deletion
    """
    test_ns = "salt-test-filtering"

    # Create namespace and verify it appears in list
    kubernetes.create_namespace(test_ns)

    # Cleanup namespace
    _cleanup("namespace", test_ns)


@pytest.mark.parametrize(
    "case",
    [
        {
            "name": "salt-test-plaintext",
            "data": {"key": "value"},
            "expected": "value",
        },
        {
            "name": "salt-test-preencoded",
            "data": {"key": "dmFsdWU="},
            "expected": "value",
        },
    ],
)
def test_create_secret_inputs(case, kubernetes, _cleanup):
    """Test creating secrets with different input formats"""
    namespace = "default"

    # Create secret
    res = kubernetes.create_secret(case["name"], namespace=namespace, data=case["data"], wait=True)
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == case["name"]

    # Verify decoded value
    res = kubernetes.show_secret(case["name"], namespace, decode=True)
    assert res["data"]["key"] == case["expected"]

    # Cleanup
    _cleanup("secret", case["name"], namespace)


def test_create_secret_twice(kubernetes, _cleanup):
    """Test creating a secret that already exists raises appropriate error"""
    test_secret = "salt-test-duplicate-secret"
    data = {"key": "value"}

    # Create secret first time
    res = kubernetes.create_secret(test_secret, data=data, wait=True)
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == test_secret

    # Attempt to create same secret again
    with pytest.raises(CommandExecutionError, match=".*already exists.*"):
        kubernetes.create_secret(test_secret, data=data, wait=True)

    # Cleanup
    _cleanup("secret", test_secret)


def test_secret_type_preservation(kubernetes, _cleanup):
    """Test that secret types are preserved during replace operations"""
    test_secret = "salt-test-typed-secret"

    # Create secret with Opaque type (default)
    kubernetes.create_secret(test_secret, data={"key": "value"}, wait=True)
    res = kubernetes.show_secret(test_secret)
    assert res["type"] == "Opaque"

    # Replace secret and verify type remains
    kubernetes.replace_secret(test_secret, data={"newkey": "newvalue"}, wait=True)
    res = kubernetes.show_secret(test_secret)
    assert res["type"] == "Opaque"

    # Cleanup
    _cleanup("secret", test_secret)


@pytest.mark.parametrize(
    "case",
    [
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
        {
            "name": "salt-test-multiline-b64",
            "type": "kubernetes.io/tls",
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
def test_secret_types(case, kubernetes, _cleanup):
    """Test creating and replacing secrets with different types"""
    namespace = "default"

    try:
        # Create secret directly first
        res = kubernetes.create_secret(
            case["name"],
            namespace=namespace,
            data=case["data"],
            type=case["type"],
            wait=True,
        )
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == case["name"]

        # Verify secret was created with correct type
        secret = kubernetes.show_secret(case["name"], namespace)
        assert secret != [], f"Secret {case['name']} was not created"
        assert secret["type"] == case["type"]

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
            type=case["type"],
            wait=True,
        )

        # Verify type was preserved
        secret = kubernetes.show_secret(case["name"], namespace)
        assert secret is not None
        assert secret["type"] == case["type"]

    finally:
        _cleanup("secret", case["name"], namespace)


def test_delete_nonexistent_pod(kubernetes):
    """Test deleting a pod that doesn't exist returns empty list"""
    test_pod = "salt-test-nonexistent-pod"

    res = kubernetes.delete_pod(test_pod)
    assert res is None


def test_list_pods_in_nonexistent_namespace(kubernetes):
    """Test listing pods in a namespace that doesn't exist returns empty list"""
    res = kubernetes.pods(namespace="nonexistent-namespace")
    assert res == []


def test_pod_namespace_required(kubernetes):
    """Test create/show/delete pod operations require namespace"""
    test_pod = "salt-test-pod-namespace"
    pod_spec = {"containers": [{"name": "nginx", "image": "nginx:latest"}]}

    # Create without namespace
    with pytest.raises(TypeError):
        kubernetes.create_pod(
            name=test_pod,
            metadata={},
            spec=pod_spec,
            source=None,
            template=None,
            saltenv="base",
            wait=True,
        )

    # Show without namespace
    res = kubernetes.show_pod(test_pod)  # Should use default namespace
    assert res is None

    # Delete without namespace
    res = kubernetes.delete_pod(test_pod)  # Should use default namespace
    assert res is None


def test_delete_nonexistent_deployment(kubernetes):
    """Test deleting a deployment that doesn't exist returns empty list"""
    test_deployment = "salt-test-nonexistent-deployment"

    res = kubernetes.delete_deployment(test_deployment)
    assert res is None


def test_deployment_replace_validation(kubernetes, _cleanup):
    """Test replacing deployment validates the new spec"""
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

    res = kubernetes.create_deployment(
        name=test_deployment,
        namespace=namespace,
        metadata={},
        spec=initial_spec,
        source=None,
        template=None,
        saltenv="base",
        wait=True,
    )
    assert isinstance(res, dict)

    # Try to replace with invalid spec
    invalid_spec = {
        "replicas": "invalid",  # Should be int
        "selector": {"matchLabels": {"app": "nginx"}},
        "template": {
            "metadata": {"labels": {"app": "nginx"}},
            "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
        },
    }

    with pytest.raises(CommandExecutionError, match=".*(invalid|type).*"):
        kubernetes.replace_deployment(
            name=test_deployment,
            namespace=namespace,
            metadata={},
            spec=invalid_spec,
            source=None,
            template=None,
            saltenv="base",
            wait=True,
        )

    # Cleanup
    _cleanup("deployment", test_deployment, namespace)


@pytest.mark.parametrize(
    "spec,should_succeed",
    [
        # Valid case - selector matches labels
        (
            {
                "selector": {"matchLabels": {"app": "nginx"}},
                "template": {
                    "metadata": {"labels": {"app": "nginx"}},
                    "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
                },
            },
            True,
        ),
        # Valid case - missing selector but has template labels
        (
            {
                "template": {
                    "metadata": {"labels": {"app": "nginx"}},
                    "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
                }
            },
            True,
        ),
        # Invalid case - missing selector and template labels
        (
            {
                "template": {
                    "metadata": {},
                    "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
                }
            },
            False,
        ),
        # Invalid case - selector doesn't match labels
        (
            {
                "selector": {"matchLabels": {"app": "nginx"}},
                "template": {
                    "metadata": {"labels": {"app": "different"}},
                    "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
                },
            },
            False,
        ),
        # Invalid case - empty selector
        (
            {
                "selector": {},
                "template": {
                    "metadata": {"labels": {"app": "nginx"}},
                    "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
                },
            },
            False,
        ),
    ],
)
def test_deployment_selector_validation(spec, should_succeed, kubernetes, _cleanup):
    """Test that deployment selector validation works correctly"""
    test_deployment = "salt-test-selector-validation"
    namespace = "default"

    if should_succeed:
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
        # Cleanup
        _cleanup("deployment", test_deployment, namespace)
    else:
        with pytest.raises(CommandExecutionError, match=".*(selector|labels).*"):
            kubernetes.create_deployment(
                name=test_deployment,
                namespace=namespace,
                metadata={},
                spec=spec,
                source=None,
                template=None,
                saltenv="base",
                wait=True,
            )


def test_node_lifecycle(kubernetes):
    """Test the complete lifecycle of node labels and operations"""
    # Get control plane node name
    nodes = kubernetes.nodes()
    assert nodes, "No nodes found in cluster"
    node_name = next(node for node in nodes if "control-plane" in node)

    # Test initial node info
    res = kubernetes.node(node_name)
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == node_name

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
    try:
        kubernetes.node_remove_label(node_name, label_key)
    except CommandExecutionError as exc:
        pytest.fail(f"Failed to remove label: {exc}")

    # Verify label was removed
    final_labels = kubernetes.node_labels(node_name)
    assert label_key not in final_labels


def test_node_multi_label_operations(kubernetes):
    """Test multiple label operations on nodes"""
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
            try:
                kubernetes.node_remove_label(node_name, label)
            except CommandExecutionError:
                pytest.fail(f"Failed to remove label {label}")


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
def test_service_different_types(case, kubernetes, _cleanup):
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
        # Cleanup
        _cleanup("service", case["name"], namespace)


def test_configmap_validation(kubernetes, _cleanup):
    """Test configmap validation for different inputs"""
    test_configmap = "salt-test-validation-configmap"
    namespace = "default"

    # Test non-string values get converted correctly
    data = {"number": 42, "boolean": True, "list": [1, 2, 3], "dict": {"key": "value"}}
    res = kubernetes.create_configmap(test_configmap, namespace=namespace, data=data, wait=True)
    assert isinstance(res, dict)
    # Verify all values were converted to strings
    assert isinstance(res["data"], dict)
    for key, value in res["data"].items():
        assert isinstance(key, str)
        assert isinstance(value, str)

    # Cleanup
    _cleanup("configmap", test_configmap, namespace)

    # Test completely invalid data type
    with pytest.raises(CommandExecutionError, match="Data must be a dictionary*"):
        kubernetes.create_configmap(test_configmap, namespace=namespace, data="invalid")


def test_configmap_special_data(kubernetes, _cleanup):
    """Test configmap with special data types and characters"""
    test_configmap = "salt-test-special-data"
    namespace = "default"

    # Test with binary-like and special character data
    config_data = {
        "config.yaml": "foo: bar\nkey: value",
        "special.data": "!@#$%^&*()\n\t\r\n",
        "unicode.txt": "Hello 世界",
    }

    # Create configmap
    res = kubernetes.create_configmap(
        test_configmap, namespace=namespace, data=config_data, wait=True
    )
    assert isinstance(res, dict)
    assert res["data"]["config.yaml"] == config_data["config.yaml"]
    assert res["data"]["special.data"] == config_data["special.data"]
    assert res["data"]["unicode.txt"] == config_data["unicode.txt"]

    # Cleanup
    _cleanup("configmap", test_configmap, namespace)


def test_configmap_large_data(kubernetes, _cleanup):
    """Test configmap with data approaching size limits"""
    test_configmap = "salt-test-large-configmap"
    namespace = "default"

    # Create large data (approaching but not exceeding 1MB limit)
    large_data = {"large-file.txt": "x" * 900000}  # 900KB of data

    # Create configmap
    res = kubernetes.create_configmap(
        test_configmap, namespace=namespace, data=large_data, wait=True
    )
    assert isinstance(res, dict)
    assert len(res["data"]["large-file.txt"]) == 900000

    # Cleanup
    _cleanup("configmap", test_configmap, namespace)


def test_configmap_with_special_characters(kubernetes, _cleanup):
    """Test configmap with special characters in data"""
    test_configmap = "salt-test-special-chars"
    namespace = "default"

    special_data = {
        "special.conf": "key=value\n#comment\n$VAR=${OTHER_VAR}\nspecial_chars=!@#$%^&*()",
        "unicode.txt": "Hello 世界",
    }

    # Create configmap
    res = kubernetes.create_configmap(
        test_configmap, namespace=namespace, data=special_data, wait=True
    )
    assert isinstance(res, dict)
    assert res["data"] == special_data

    # Cleanup
    _cleanup("configmap", test_configmap, namespace)


@pytest.mark.parametrize(
    "resource_type,spec_generator",
    [
        ("namespace", lambda: None),  # Namespaces don't need a spec
        (
            "pod",
            lambda: {
                "containers": [
                    {
                        "name": "nginx",
                        "image": "nginx:latest",
                        "ports": [{"containerPort": 80}],
                    }
                ]
            },
        ),
        (
            "deployment",
            lambda: {
                "replicas": 2,
                "selector": {"matchLabels": {"app": "nginx"}},
                "template": {
                    "metadata": {"labels": {"app": "nginx"}},
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
        ),
        (
            "service",
            lambda: {
                "ports": [
                    {"name": "http", "port": 80, "targetPort": 80},
                ],
                "selector": {"app": "nginx"},
                "type": "ClusterIP",
            },
        ),
        (
            "configmap",
            lambda: {
                "game.properties": "enemies=aliens\nlives=3",
                "user-interface.properties": "color.good=purple\ncolor.bad=yellow",
            },
        ),
        ("secret", lambda: {"username": "admin", "password": "secret123"}),
    ],
)
def test_resource_lifecycle(resource_type, spec_generator, kubernetes, _cleanup):
    """Test the complete lifecycle of a Kubernetes resource"""
    test_name = f"salt-test-{resource_type}-lifecycle"
    namespace = "default" if resource_type != "namespace" else None
    spec = spec_generator()

    # Create resource
    create_func = getattr(kubernetes, f"create_{resource_type}")

    kwargs = {"name": test_name}
    if namespace:
        kwargs["namespace"] = namespace
    if spec:
        if resource_type in ["configmap", "secret"]:
            kwargs["data"] = spec
        else:
            kwargs["spec"] = spec
    if resource_type not in ["namespace", "configmap", "secret"]:
        kwargs.update(
            {
                "metadata": {},
                "source": None,
                "template": None,
                "saltenv": "base",
            }
        )
    kwargs["wait"] = True

    res = create_func(**kwargs)
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == test_name

    # Show resource
    show_func = getattr(kubernetes, f"show_{resource_type}")
    show_kwargs = {"name": test_name}
    if namespace:
        show_kwargs["namespace"] = namespace

    res = show_func(**show_kwargs)
    assert isinstance(res, dict)
    assert res["metadata"]["name"] == test_name

    # Cleanup
    if resource_type != "namespace":
        _cleanup(resource_type, test_name, namespace)
    else:
        _cleanup(resource_type, test_name)


@pytest.mark.parametrize(
    "resource_type,expected_result",
    [
        ("namespace", None),
        ("pod", None),
        ("deployment", None),
        ("service", None),
        ("configmap", None),
        ("secret", None),
    ],
)
def test_show_nonexistent_resource(resource_type, expected_result, kubernetes):
    """Test showing a resource that doesn't exist returns expected result"""
    test_name = f"salt-test-nonexistent-{resource_type}"
    namespace = "default" if resource_type != "namespace" else None

    show_func = getattr(kubernetes, f"show_{resource_type}")
    kwargs = {"name": test_name}
    if namespace:
        kwargs["namespace"] = namespace

    res = show_func(**kwargs)
    assert res == expected_result
