import logging
from textwrap import dedent

import pytest

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms"),
]


@pytest.fixture
def kubernetes(states):
    """Return kubernetes state module"""
    return states.kubernetes


@pytest.fixture
def namespace_template(state_tree):
    sls = "k8s/namespace-template"
    contents = dedent(
        """
        apiVersion: v1
        kind: Namespace
        metadata:
          name: {{ name }}
          labels:
            {% for key, value in labels.items() %}
            {{ key }}: {{ value }}
            {% endfor %}
        """
    ).strip()

    with pytest.helpers.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        yield f"salt://{sls}.yml.jinja"


@pytest.fixture
def pod_template(state_tree):
    sls = "k8s/pod-template"
    contents = dedent(
        """
        apiVersion: v1
        kind: Pod
        metadata:
          name: {{ name }}
          namespace: {{ namespace }}
          labels:
            {% for key, value in labels.items() %}
            {{ key }}: {{ value }}
            {% endfor %}
        spec:
          containers:
          - name: {{ name }}
            image: {{ image }}
            ports:
            - containerPort: 80
        """
    ).strip()

    with pytest.helpers.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        yield f"salt://{sls}.yml.jinja"


@pytest.fixture
def deployment_template(state_tree):
    sls = "k8s/deployment-template"
    contents = dedent(
        """
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: {{ name }}
          namespace: {{ namespace }}
          labels:
            {% for key, value in labels.items() %}
            {{ key }}: {{ value }}
            {% endfor %}
        spec:
          replicas: {{ replicas }}
          selector:
            matchLabels:
              app: {{ app_label }}
          template:
            metadata:
              labels:
                app: {{ app_label }}
            spec:
              containers:
              - name: {{ name }}
                image: {{ image }}
                ports:
                - containerPort: 80
        """
    ).strip()

    with pytest.helpers.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        yield f"salt://{sls}.yml.jinja"


@pytest.fixture
def secret_template(state_tree):
    sls = "k8s/secret-template"
    contents = dedent(
        """
        apiVersion: v1
        kind: Secret
        metadata:
          name: {{ name }}
          namespace: {{ namespace }}
          labels:
            {% for key, value in labels.items() %}
            {{ key }}: {{ value }}
            {% endfor %}
        type: {{ type }}
        data:
          {% for key, value in secret_data.items() %}
          {{ key }}: {{ value }}
          {% endfor %}
        """
    ).strip()

    with pytest.helpers.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        yield f"salt://{sls}.yml.jinja"


@pytest.fixture
def service_template(state_tree):
    sls = "k8s/service-template"
    contents = dedent(
        """
        apiVersion: v1
        kind: Service
        metadata:
          name: {{ name }}
          namespace: {{ namespace }}
          labels:
            {% for key, value in labels.items() %}
            {{ key }}: {{ value }}
            {% endfor %}
        spec:
          type: {{ type }}
          ports:
            {% for port in ports %}
            - name: {{ port.name }}
              port: {{ port.port }}
              targetPort: {{ port.target_port }}
              {% if port.node_port is defined %}nodePort: {{ port.node_port }}{% endif %}
            {% endfor %}
          selector:
            {% for key, value in selector.items() %}
            {{ key }}: {{ value }}
            {% endfor %}
        """
    ).strip()

    with pytest.helpers.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        yield f"salt://{sls}.yml.jinja"


@pytest.fixture
def configmap_template(state_tree):
    sls = "k8s/configmap-template"
    contents = dedent(
        """
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: {{ name }}
          namespace: {{ namespace }}
          labels:
            {% for key, value in labels.items() %}
            {{ key }}: {{ value }}
            {% endfor %}
        data:
          {% for key, value in configmap_data.items() %}
          {{ key }}: |
            {{ value | indent(12) }}
          {% endfor %}
        """
    ).strip()

    with pytest.helpers.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        yield f"salt://{sls}.yml.jinja"


@pytest.fixture
def _pod_spec():
    return {
        "containers": [
            {
                "name": "nginx",
                "image": "nginx:latest",
                "ports": [{"containerPort": 80}],
            }
        ]
    }


@pytest.fixture
def _deployment_spec():
    return {
        "replicas": 2,
        "selector": {"matchLabels": {"app": "test"}},
        "template": {
            "metadata": {"labels": {"app": "test"}},
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
    }


@pytest.fixture
def _service_spec():
    return {
        "ports": [
            {"name": "http", "port": 80, "targetPort": 8080},
            {"name": "https", "port": 443, "targetPort": 8443},
        ],
        "selector": {"app": "test"},
        "type": "ClusterIP",
    }


@pytest.fixture
def _cleanup(kubernetes):
    """Cleanup fixture that handles all test resource cleanup"""
    cleanup_list = []

    def _add_resource(resource_type, name, namespace="default"):
        cleanup_list.append({"type": resource_type, "name": name, "namespace": namespace})

    yield _add_resource

    for resource in cleanup_list:
        try:
            if resource["type"] == "pod":
                ret = kubernetes.pod_absent(
                    name=resource["name"], namespace=resource["namespace"], wait=True
                )
                assert "Pod deleted" in ret.comment
            elif resource["type"] == "deployment":
                ret = kubernetes.deployment_absent(
                    name=resource["name"], namespace=resource["namespace"], wait=True
                )
                assert "None" in ret.comment
            elif resource["type"] == "service":
                ret = kubernetes.service_absent(
                    name=resource["name"], namespace=resource["namespace"], wait=True
                )
                assert "Service deleted" in ret.comment
            elif resource["type"] == "secret":
                ret = kubernetes.secret_absent(
                    name=resource["name"], namespace=resource["namespace"], wait=True
                )
                assert "Secret deleted" in ret.comment
            elif resource["type"] == "configmap":
                ret = kubernetes.configmap_absent(
                    name=resource["name"], namespace=resource["namespace"], wait=True
                )
                assert "ConfigMap deleted" in ret.comment
            elif resource["type"] == "namespace":
                if resource["namespace"] != "default":  # Don't delete default namespace
                    ret = kubernetes.namespace_absent(name=resource["name"])
                    assert ret.changes["kubernetes.namespace"]["new"] == "absent"
            elif resource["type"] == "node_label":
                ret = kubernetes.node_label_absent(
                    name=resource["name"], node=resource["namespace"]
                )
                assert "Label removed from node" in ret.comment

        except AssertionError as exc:
            # Log but don't fail tests on cleanup errors
            log.warning(
                "Failed to cleanup %s '%s' in namespace '%s': %s",
                resource["type"],
                resource["name"],
                resource["namespace"],
                str(exc),
            )


def test_namespace_present(kubernetes, _cleanup):
    """
    Test kubernetes.namespace_present ensures namespace is created
    """
    test_ns = "salt-test-namespace-present"

    # Test create namespace with test=true
    ret = kubernetes.namespace_present(name=test_ns, test=True)
    assert "The namespace is going to be created" in ret.comment
    assert ret.result is None

    # Create namespace
    ret = kubernetes.namespace_present(name=test_ns)
    assert ret.result is True
    assert ret.changes["namespace"]["new"]["metadata"]["name"] == test_ns

    # test namespace_present with test=true
    ret = kubernetes.namespace_present(name=test_ns, test=True)
    assert not ret.changes

    # Verify namespace_present again to verify idempotency
    ret = kubernetes.namespace_present(name=test_ns)
    assert ret.result is True
    assert "The namespace already exists" in ret.comment
    assert not ret.changes

    # Cleanup
    _cleanup("namespace", test_ns)


def test_namespace_absent(kubernetes):
    """
    Test kubernetes.namespace_absent ensures namespace is deleted
    """
    test_ns = "salt-test-namespace-absent"

    # Ensure namespace exists
    ret = kubernetes.namespace_present(name=test_ns, wait=True)
    assert ret.result is True
    assert ret.changes["namespace"]["new"]["metadata"]["name"] == test_ns

    # Test delete namespace with test=true
    ret = kubernetes.namespace_absent(name=test_ns, test=True)
    assert "The namespace is going to be deleted" in ret.comment
    assert ret.result is None

    # Delete namespace
    ret = kubernetes.namespace_absent(name=test_ns, wait=True)
    assert ret.result is True
    assert ret.changes["kubernetes.namespace"]["new"] == "absent"

    # test namespace_absent with test=true
    ret = kubernetes.namespace_absent(name=test_ns, test=True)
    assert not ret.changes

    # Verify namespace_absent again to verify idempotency
    ret = kubernetes.namespace_absent(name=test_ns)
    assert ret.result is True
    assert ret.comment in ["The namespace does not exist", "Terminating"]
    assert not ret.changes


def test_namespace_present_with_context(kubernetes, namespace_template, _cleanup):
    """
    Test kubernetes.namespace_present ensures namespace is created using context
    """
    test_ns = "salt-test-namespace-context"
    context = {
        "name": test_ns,
        "labels": {"app": "test"},
    }

    # Create namespace using context
    ret = kubernetes.namespace_present(
        name=test_ns,
        source=namespace_template,
        template="jinja",
        context=context,
        wait=True,
    )
    assert ret.result is True
    assert ret.changes["namespace"]["new"]["metadata"]["name"] == test_ns

    # Verify namespace_present again to verify idempotency
    ret = kubernetes.namespace_present(
        name=test_ns,
        source=namespace_template,
        template="jinja",
        context=context,
    )
    assert ret.result is True
    assert "The namespace already exists" in ret.comment
    assert not ret.changes

    # Cleanup
    _cleanup("namespace", test_ns)


def test_pod_present(kubernetes, _pod_spec, _cleanup):
    """
    Test kubernetes.pod_present ensures pod is created
    """
    test_pod = "salt-test-pod-present"
    namespace = "default"
    metadata = {"labels": {"app": "test"}}
    spec = _pod_spec

    # Test create pod with test=true
    ret = kubernetes.pod_present(name=test_pod, namespace=namespace, test=True)
    assert "The pod is going to be created" in ret.comment
    assert ret.result is None

    # Create pod
    ret = kubernetes.pod_present(
        name=test_pod,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        wait=True,
    )
    assert ret.result is True
    assert ret.changes["metadata"]["labels"] == metadata["labels"]

    # Test pod_present with test=true
    ret = kubernetes.pod_present(name=test_pod, namespace=namespace, test=True)
    assert not ret.changes

    # Comment out idempotent test for now
    # TODO: The state module needs fixed to handle proper present functionality
    # Run pod_present again to test idempotency
    # ret = kubernetes.pod_present(
    #     name=test_pod,
    #     namespace=namespace,
    #     metadata=metadata,
    #     spec=spec,
    # )
    # assert ret.result is False
    # assert (
    #     "salt is currently unable to replace a pod without deleting it. Please perform the removal of the pod requiring the 'pod_absent' state if this is the desired behaviour."
    #     in ret.comment
    # )

    # Cleanup
    _cleanup("pod", test_pod, namespace)


def test_pod_absent(kubernetes, _pod_spec):
    """
    Test kubernetes.pod_absent ensures pod is deleted
    """
    test_pod = "salt-test-pod-absent"
    namespace = "default"
    metadata = {"labels": {"app": "test"}}
    spec = _pod_spec

    # Ensure pod exists
    ret = kubernetes.pod_present(
        name=test_pod,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        wait=True,
    )
    assert ret.result is True
    assert ret.changes["metadata"]["labels"] == metadata["labels"]

    # Test delete pod with test=true
    ret = kubernetes.pod_absent(name=test_pod, namespace=namespace, test=True)
    assert "The pod is going to be deleted" in ret.comment
    assert ret.result is None

    # Delete pod
    ret = kubernetes.pod_absent(name=test_pod, namespace=namespace, wait=True)
    assert ret.result is True
    assert ret.changes["kubernetes.pod"]["new"] == "absent"

    # Test pod_absent with test=true
    ret = kubernetes.pod_absent(name=test_pod, namespace=namespace, test=True)
    assert not ret.changes

    # Verify pod_absent again to verify idempotency
    ret = kubernetes.pod_absent(name=test_pod, namespace=namespace)
    assert ret.result is True
    assert ret.comment in ["The pod does not exist", "In progress", "Pod deleted"]
    assert not ret.changes


def test_pod_present_with_context(kubernetes, pod_template, _cleanup):
    """
    Test kubernetes.pod_present ensures pod is created using context
    """
    test_pod = "salt-test-pod-present-context"
    namespace = "default"
    context = {
        "name": test_pod,
        "namespace": namespace,
        "image": "nginx:latest",
        "labels": {"app": "test"},
    }

    # Create pod using context
    ret = kubernetes.pod_present(
        name=test_pod,
        namespace=namespace,
        source=pod_template,
        template="jinja",
        context=context,
        wait=True,
    )

    # The first creation should work
    assert ret.result is True
    assert ret.changes

    # Comment out idempotent test for now
    # TODO: The state module needs fixed to handle proper present functionality
    # Run pod_present again to test idempotency
    # Run pod_present again to ensure it works if the pod already exists
    # ret = kubernetes.pod_present(
    #     name=test_pod,
    #     namespace=namespace,
    #     source=pod_template,
    #     template="jinja",
    #     context=context,
    # )
    # # This should return False with the expected message
    # assert ret.result is False
    # assert "salt is currently unable to replace a pod" in ret.comment

    # Cleanup
    _cleanup("pod", test_pod, namespace)


def test_deployment_present(kubernetes, _deployment_spec, _cleanup):
    """
    Test kubernetes.deployment_present ensures deployment is created
    """
    test_deployment = "salt-test-deployment-present"
    namespace = "default"
    metadata = {"labels": {"app": "test"}}
    spec = _deployment_spec

    # Test create deployment with test=true
    ret = kubernetes.deployment_present(name=test_deployment, namespace=namespace, test=True)
    assert "The deployment is going to be created" in ret.comment
    assert ret.result is None

    # Create deployment
    ret = kubernetes.deployment_present(
        name=test_deployment,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        wait=True,
    )
    assert ret.result is True
    assert ret.changes["metadata"]["labels"] == metadata["labels"]

    # Test deployment_present with test=true
    ret = kubernetes.deployment_present(name=test_deployment, namespace=namespace, test=True)
    assert not ret.changes

    # Comment out idempotent test for now
    # TODO: The state module needs fixed to handle proper present functionality
    # # Run deployment exists again to verify idempotency
    # ret = kubernetes.deployment_present(
    #     name=test_deployment,
    #     namespace=namespace,
    #     metadata=metadata,
    #     spec=spec,
    # )
    # assert ret.result is True
    # assert "The deployment is already present" in ret.comment
    # assert not ret.changes

    # Cleanup
    _cleanup("deployment", test_deployment, namespace)


def test_deployment_absent(kubernetes, _deployment_spec):
    """
    Test kubernetes.deployment_absent ensures deployment is deleted
    """
    test_deployment = "salt-test-deployment-absent"
    namespace = "default"
    metadata = {"labels": {"app": "test"}}
    spec = _deployment_spec

    # Ensure deployment exists
    ret = kubernetes.deployment_present(
        name=test_deployment,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        wait=True,
    )
    assert ret.result is True
    assert ret.changes

    # Test delete deployment with test=true
    ret = kubernetes.deployment_absent(name=test_deployment, namespace=namespace, test=True)
    assert "The deployment is going to be deleted" in ret.comment
    assert ret.result is None

    # Delete deployment
    ret = kubernetes.deployment_absent(name=test_deployment, namespace=namespace, wait=True)
    assert ret.result is True
    assert ret.changes["kubernetes.deployment"]["new"] == "absent"

    # Test deployment_absent with test=true
    ret = kubernetes.deployment_absent(name=test_deployment, namespace=namespace, test=True)
    assert not ret.changes

    # Run deployment_absent again to verify idempotency
    ret = kubernetes.deployment_absent(name=test_deployment, namespace=namespace)
    assert ret.result is True
    assert "The deployment does not exist" in ret.comment
    assert not ret.changes


def test_deployment_present_with_context(kubernetes, deployment_template, _cleanup):
    """
    Test kubernetes.deployment_present ensures deployment is created using context
    """
    test_deployment = "salt-test-deployment-present"
    namespace = "default"
    context = {
        "name": test_deployment,
        "namespace": namespace,
        "image": "nginx:latest",
        "labels": {"app": "test"},
        "replicas": 2,
        "app_label": "test",
    }

    # Create deployment using context
    ret = kubernetes.deployment_present(
        name=test_deployment,
        namespace=namespace,
        source=deployment_template,
        template="jinja",
        context=context,
        wait=True,
    )
    assert ret.result is True
    assert ret.changes

    # Comment out idempotent test for now
    # TODO: The state module needs fixed to handle proper present functionality
    # # Run deployment exists again to verify idempotency
    # ret = kubernetes.deployment_present(
    #     name=test_deployment,
    #     namespace=namespace,
    #     source=deployment_template,
    #     template="jinja",
    #     context=context,
    # )
    # assert ret.result is True
    # assert "The deployment already present" in ret.comment
    # assert not ret.changes

    # Cleanup
    _cleanup("deployment", test_deployment, namespace)


def test_secret_present(kubernetes, _cleanup):
    """
    Test kubernetes.secret_present ensures secret is created
    """
    test_secret = "salt-test-secret-present"
    namespace = "default"
    data = {
        "username": "admin",
        "password": "secretpassword",
    }

    # Test create secret with test=true
    ret = kubernetes.secret_present(name=test_secret, namespace=namespace, test=True)
    assert "The secret is going to be created" in ret.comment
    assert ret.result is None

    # Create secret
    ret = kubernetes.secret_present(
        name=test_secret,
        namespace=namespace,
        data=data,
        wait=True,
    )
    assert ret.result is True
    assert sorted(ret.changes["data"]) == sorted(data)

    # Test secret_present with test=true
    ret = kubernetes.secret_present(name=test_secret, namespace=namespace, test=True)
    assert not ret.changes

    # Comment out idempotent test for now
    # TODO: The state module needs fixed to handle proper present functionality
    # # Verify secret exists again to verify idempotency
    # ret = kubernetes.secret_present(
    #     name=test_secret,
    #     namespace=namespace,
    #     data={"username": "newadmin", "password": "newpassword"},
    # )
    # assert ret.result is True
    # assert sorted(ret.changes["data"]) == ["password", "username"]
    # assert "The secret already present" in ret.comment
    # assert not ret.changes

    # Cleanup
    _cleanup("secret", test_secret, namespace)


def test_secret_absent(kubernetes):
    """
    Test kubernetes.secret_absent ensures secret is deleted
    """
    test_secret = "salt-test-secret-absent"
    namespace = "default"
    data = {"key": "value"}

    # Ensure secret exists
    ret = kubernetes.secret_present(
        name=test_secret,
        namespace=namespace,
        data=data,
        wait=True,
    )
    assert ret.result is True
    assert sorted(ret.changes["data"]) == sorted(data)

    # Test delete secret with test=true
    ret = kubernetes.secret_absent(name=test_secret, namespace=namespace, test=True)
    assert "The secret is going to be deleted" in ret.comment
    assert ret.result is None

    # Delete secret
    ret = kubernetes.secret_absent(name=test_secret, namespace=namespace, wait=True)
    assert ret.result is True
    assert ret.changes["kubernetes.secret"]["new"] == "absent"

    # Test secret_absent with test=true
    ret = kubernetes.secret_absent(name=test_secret, namespace=namespace, test=True)
    assert not ret.changes

    # Run secret_absent again to verify idempotency
    ret = kubernetes.secret_absent(name=test_secret, namespace=namespace)
    assert ret.result is True
    assert "The secret does not exist" in ret.comment
    assert not ret.changes


def test_secret_present_with_context(kubernetes, secret_template, _cleanup):
    """
    Test kubernetes.secret_present ensures secret is created using context
    """
    test_secret = "salt-test-secret-present"
    namespace = "default"
    context = {
        "name": test_secret,
        "namespace": namespace,
        "labels": {"app": "test"},
        "type": "Opaque",
        "secret_data": {
            "username": "YWRtaW4=",  # base64 encoded "admin"
            "password": "c2VjcmV0",  # base64 encoded "secret"
        },
    }

    # Create secret using context
    ret = kubernetes.secret_present(
        name=test_secret,
        namespace=namespace,
        source=secret_template,
        template="jinja",
        context=context,
        wait=True,
    )
    assert ret.result is True
    assert sorted(ret.changes["data"]) == sorted(context["secret_data"])
    assert ret.changes

    # Verify secret exists and can be replaced
    new_context = context.copy()
    new_context["secret_data"] = {
        "username": "bmV3YWRtaW4=",  # base64 encoded "newadmin"
        "password": "bmV3c2VjcmV0",  # base64 encoded "newsecret"
    }
    ret = kubernetes.secret_present(
        name=test_secret,
        namespace=namespace,
        source=secret_template,
        template="jinja",
        context=new_context,
        wait=True,
    )
    assert ret.result is True
    assert sorted(ret.changes["data"]) == ["password", "username"]
    assert ret.changes

    # Cleanup
    _cleanup("secret", test_secret, namespace)


def test_service_present(kubernetes, _service_spec, _cleanup):
    """
    Test kubernetes.service_present ensures service is created
    """
    test_service = "salt-test-service-present"
    namespace = "default"
    metadata = {"labels": {"app": "test"}}
    spec = _service_spec

    # Test create service with test=true
    ret = kubernetes.service_present(name=test_service, namespace=namespace, test=True)
    assert "The service is going to be created" in ret.comment
    assert ret.result is None

    # Create service
    ret = kubernetes.service_present(
        name=test_service,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        wait=True,
    )
    assert ret.result is True
    assert ret.changes["metadata"]["labels"] == metadata["labels"]

    # Test service_present with test=true
    ret = kubernetes.service_present(name=test_service, namespace=namespace, test=True)
    assert not ret.changes

    # Comment out idempotent test for now
    # TODO: The state module needs fixed to handle proper present functionality
    # # Run service_present again to verify idempotency
    # ret = kubernetes.service_present(
    #     name=test_service,
    #     namespace=namespace,
    #     metadata=metadata,
    #     spec=spec,
    # )
    # assert ret.result is True
    # assert "The service already present" in ret.comment
    # assert not ret.changes

    # Cleanup
    _cleanup("service", test_service, namespace)


def test_service_absent(kubernetes, _service_spec):
    """
    Test kubernetes.service_absent ensures service is deleted
    """
    test_service = "salt-test-service-absent"
    namespace = "default"
    metadata = {"labels": {"app": "test"}}
    spec = _service_spec

    # Ensure service exists
    ret = kubernetes.service_present(
        name=test_service,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        wait=True,
    )
    assert ret.result is True
    assert ret.changes

    # Test delete service with test=true
    ret = kubernetes.service_absent(name=test_service, namespace=namespace, test=True)
    assert "The service is going to be deleted" in ret.comment
    assert ret.result is None

    # Delete service
    ret = kubernetes.service_absent(name=test_service, namespace=namespace, wait=True)
    assert ret.result is True
    assert ret.changes["kubernetes.service"]["new"] == "absent"

    # Test service_absent with test=true
    ret = kubernetes.service_absent(name=test_service, namespace=namespace, test=True)
    assert not ret.changes

    # Run service_absent again to verify idempotency
    ret = kubernetes.service_absent(name=test_service, namespace=namespace)
    assert ret.result is True
    assert "The service does not exist" in ret.comment
    assert not ret.changes


def test_service_present_with_context(kubernetes, service_template, _cleanup):
    """
    Test kubernetes.service_present ensures service is created using context
    """
    test_service = "salt-test-service-present"
    namespace = "default"
    context = {
        "name": test_service,
        "namespace": namespace,
        "labels": {"app": "test"},
        "type": "ClusterIP",
        "ports": [
            {"name": "http", "port": 80, "target_port": 8080},
            {"name": "https", "port": 443, "target_port": 8443},
        ],
        "selector": {"app": "test"},
    }

    # Create service using context
    ret = kubernetes.service_present(
        name=test_service,
        namespace=namespace,
        source=service_template,
        template="jinja",
        context=context,
        wait=True,
    )
    assert ret.result is True
    assert ret.changes

    # Comment out idempotent test for now
    # TODO: The state module needs fixed to handle proper present functionality
    # # Run service_present again to verify idempotency
    # ret = kubernetes.service_present(
    #     name=test_service,
    #     namespace=namespace,
    #     source=service_template,
    #     template="jinja",
    #     context=context,
    # )
    # assert ret.result is True
    # assert "The service already exists" in ret.comment
    # assert not ret.changes

    # Cleanup
    _cleanup("service", test_service, namespace)


def test_configmap_present(kubernetes, _cleanup):
    """
    Test kubernetes.configmap_present ensures configmap is created
    """
    test_configmap = "salt-test-configmap-present"
    namespace = "default"
    data = {
        "config.yaml": "foo: bar\nkey: value",
        "app.properties": "app.name=myapp\napp.port=8080",
    }

    # Test create configmap with test=true
    ret = kubernetes.configmap_present(name=test_configmap, namespace=namespace, test=True)
    assert "The configmap is going to be created" in ret.comment
    assert ret.result is None

    # Create configmap
    ret = kubernetes.configmap_present(
        name=test_configmap,
        namespace=namespace,
        data=data,
        wait=True,
    )
    assert ret.result is True
    assert ret.changes["data"] == data

    # Test configmap_present with test=true
    ret = kubernetes.configmap_present(name=test_configmap, namespace=namespace, test=True)
    assert not ret.changes

    # Verify configmap exists and can be replaced
    new_data = {
        "config.yaml": "foo: newbar\nkey: newvalue",
        "app.properties": "app.name=newapp\napp.port=9090",
    }
    ret = kubernetes.configmap_present(
        name=test_configmap,
        namespace=namespace,
        data=new_data,
        wait=True,
    )
    assert ret.result is True
    assert ret.changes["data"] == new_data

    # Cleanup
    _cleanup("configmap", test_configmap, namespace)


def test_configmap_absent(kubernetes):
    """
    Test kubernetes.configmap_absent ensures configmap is deleted
    """
    test_configmap = "salt-test-configmap-absent"
    namespace = "default"
    data = {"key": "value"}

    # Ensure configmap exists
    ret = kubernetes.configmap_present(
        name=test_configmap,
        namespace=namespace,
        data=data,
        wait=True,
    )
    assert ret.result is True
    assert ret.changes["data"] == data

    # Test delete configmap with test=true
    ret = kubernetes.configmap_absent(name=test_configmap, namespace=namespace, test=True)
    assert "The configmap is going to be deleted" in ret.comment
    assert ret.result is None

    # Delete configmap
    ret = kubernetes.configmap_absent(name=test_configmap, namespace=namespace, wait=True)
    assert ret.result is True
    assert ret.changes["kubernetes.configmap"]["new"] == "absent"

    # Test configmap_absent with test=true
    ret = kubernetes.configmap_absent(name=test_configmap, namespace=namespace, test=True)
    assert not ret.changes

    # Run configmap_absent again to verify idempotency
    ret = kubernetes.configmap_absent(name=test_configmap, namespace=namespace)
    assert ret.result is True
    assert "The configmap does not exist" in ret.comment
    assert not ret.changes


def test_configmap_present_with_context(kubernetes, configmap_template, _cleanup):
    """
    Test kubernetes.configmap_present ensures configmap is created using context
    """
    test_configmap = "salt-test-configmap-present"
    namespace = "default"
    context = {
        "name": test_configmap,
        "namespace": namespace,
        "labels": {"app": "test"},
        "configmap_data": {
            "config.yaml": "foo: bar\nkey: value",
            "app.properties": "app.name=myapp\napp.port=8080",
        },
    }

    # Create configmap using context
    ret = kubernetes.configmap_present(
        name=test_configmap,
        namespace=namespace,
        source=configmap_template,
        template="jinja",
        context=context,
        wait=True,
    )
    assert ret.result is True
    assert ret.changes

    # Verify configmap exists and can be replaced
    new_context = context.copy()
    new_context["configmap_data"] = {
        "config.yaml": "foo: newbar\nkey: newvalue",
        "app.properties": "app.name=newapp\napp.port=9090",
    }
    ret = kubernetes.configmap_present(
        name=test_configmap,
        namespace=namespace,
        source=configmap_template,
        template="jinja",
        context=new_context,
        wait=True,
    )
    assert ret.result is True
    assert ret.changes["data"]

    # Cleanup
    _cleanup("configmap", test_configmap, namespace)


def test_node_label_present(kubernetes, loaders, _cleanup):
    """
    Test kubernetes.node_label_present ensures label is created and updated
    """
    test_label = "salt-test.label/test"
    test_value = "value1"
    new_value = "value2"

    # Get a node to test with (use control-plane node)
    nodes = loaders.modules.kubernetes.nodes()
    node_name = next(node for node in nodes if "control-plane" in node)

    # Test create label with test=true
    ret = kubernetes.node_label_present(
        name=test_label,
        node=node_name,
        value=test_value,
        test=True,
    )
    assert "The label is going to be set" in ret.comment
    assert ret.result is None

    # Add label
    ret = kubernetes.node_label_present(
        name=test_label,
        node=node_name,
        value=test_value,
    )
    assert ret.result is True
    assert test_label in ret.changes[f"{node_name}.{test_label}"]["new"]

    # Test add label with test=true
    ret = kubernetes.node_label_present(
        name=test_label,
        node=node_name,
        value=test_value,
        test=True,
    )
    assert not ret.changes

    # Update label value
    ret = kubernetes.node_label_present(
        name=test_label,
        node=node_name,
        value=new_value,
    )
    assert ret.result is True
    assert ret.changes[f"{node_name}.{test_label}"]["new"][test_label] == new_value

    # Try to set same value (should be no-op)
    ret = kubernetes.node_label_present(
        name=test_label,
        node=node_name,
        value=new_value,
    )
    assert ret.result is True
    assert "The label is already set and has the specified value" in ret.comment
    assert not ret.changes

    # Cleanup
    _cleanup("node_label", test_label, node_name)


def test_node_label_absent(kubernetes, loaders):
    """
    Test kubernetes.node_label_absent ensures label is removed
    """
    test_label = "salt-test.label/remove"
    test_value = "value"

    # Get a node to test with (use control-plane node)
    nodes = loaders.modules.kubernetes.nodes()
    node_name = next(node for node in nodes if "control-plane" in node)

    # Ensure label exists first
    ret = kubernetes.node_label_present(
        name=test_label,
        node=node_name,
        value=test_value,
    )
    assert ret.result is True
    assert test_label in ret.changes[f"{node_name}.{test_label}"]["new"]
    assert ret.changes[f"{node_name}.{test_label}"]["new"][test_label] == test_value

    # Test remove label with test=true
    ret = kubernetes.node_label_absent(
        name=test_label,
        node=node_name,
        test=True,
    )
    assert "The label is going to be deleted" in ret.comment
    assert ret.result is None

    # Remove label
    ret = kubernetes.node_label_absent(
        name=test_label,
        node=node_name,
    )
    assert ret.result is True
    assert ret.changes["kubernetes.node_label"]["new"] == "absent"

    # Test remove label with test=true
    ret = kubernetes.node_label_absent(
        name=test_label,
        node=node_name,
        test=True,
    )
    assert not ret.changes

    # Try to remove again (should be no-op)
    ret = kubernetes.node_label_absent(
        name=test_label,
        node=node_name,
    )
    assert ret.result is True
    assert "The label does not exist" in ret.comment
    assert not ret.changes


def test_node_label_folder_absent(kubernetes, loaders):
    """
    Test kubernetes.node_label_folder_absent ensures all labels with prefix are removed
    """
    test_prefix = "example.com"
    test_labels = {
        f"{test_prefix}/label1": "value1",
        f"{test_prefix}/label2": "value2",
    }

    # Get a node to test with (use control-plane node)
    nodes = loaders.modules.kubernetes.nodes()
    node_name = next(node for node in nodes if "control-plane" in node)

    # Test create labels with test=true
    for label, value in test_labels.items():
        ret = kubernetes.node_label_present(
            name=label,
            node=node_name,
            value=value,
            test=True,
        )
        assert "The label is going to be set" in ret.comment
        assert ret.result is None

    # Add test labels
    for label, value in test_labels.items():
        ret = kubernetes.node_label_present(
            name=label,
            node=node_name,
            value=value,
        )
        assert ret.result is True
        assert label in ret.changes[f"{node_name}.{label}"]["new"]
        assert ret.changes[f"{node_name}.{label}"]["new"][label] == value

    # Remove label folder
    ret = kubernetes.node_label_folder_absent(
        name=test_prefix,
        node=node_name,
    )
    assert ret.result is True
    assert ret.changes

    # Try to remove again (should be no-op)
    ret = kubernetes.node_label_folder_absent(
        name=test_prefix,
        node=node_name,
    )
    assert ret.result is True
    assert "The label folder does not exist" in ret.comment
    assert not ret.changes


def test_service_account_token_secret_present(kubernetes, _cleanup):
    """Test creating a service account token secret via state"""
    secret_name = "test-svc-token"
    namespace = "default"

    # Test create secret with test=true
    ret = kubernetes.secret_present(name=secret_name, namespace=namespace, test=True)
    assert "The secret is going to be created" in ret.comment
    assert ret.result is None

    # Create token secret using state using default service account
    ret = kubernetes.secret_present(
        name=secret_name,
        namespace=namespace,
        data={},  # Empty data - kubernetes will populate
        type="kubernetes.io/service-account-token",
        metadata={"annotations": {"kubernetes.io/service-account.name": "default"}},
        wait=True,
    )

    assert ret.result is True
    assert isinstance(ret.changes["data"], list)

    # Test secret_present with test=true
    ret = kubernetes.secret_present(name=secret_name, namespace=namespace, test=True)
    assert not ret.changes

    # We don't test second run since token will always be different
    # Just clean up
    _cleanup("secret", secret_name, namespace)
