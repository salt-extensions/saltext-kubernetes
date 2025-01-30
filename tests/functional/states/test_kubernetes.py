import logging
import sys
import time
from pathlib import Path
from textwrap import dedent

import pytest

log = logging.getLogger(__name__)

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Only run on Linux platforms")


@pytest.fixture(scope="module")
def master_config_overrides(kind_cluster):
    """Kubernetes specific configuration for Salt master"""
    return {
        "kubernetes.kubeconfig": str(kind_cluster.kubeconfig_path),
        "kubernetes.context": "kind-salt-test",
        "cachedir": Path("/tmp/salt-test-cache"),
    }


@pytest.fixture(scope="module")
def minion_config_overrides(kind_cluster):
    """Kubernetes specific configuration for Salt minion"""
    return {
        "kubernetes.kubeconfig": str(kind_cluster.kubeconfig_path),
        "kubernetes.context": "kind-salt-test",
    }


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


def test_namespace_present(kubernetes, caplog):
    """
    Test kubernetes.namespace_present ensures namespace is created
    """
    caplog.set_level(logging.INFO)
    test_ns = "salt-test-namespace-present"

    # Create namespace
    result = kubernetes.namespace_present(name=test_ns)
    assert result["result"] is True
    assert result["changes"]["namespace"]["new"]["metadata"]["name"] == test_ns

    # Verify namespace_present again to verify idempotency
    result = kubernetes.namespace_present(name=test_ns)
    assert result["result"] is True
    assert result["comment"] == "The namespace already exists"

    # Cleanup
    kubernetes.namespace_absent(name=test_ns)


def test_namespace_absent(kubernetes, caplog):
    """
    Test kubernetes.namespace_absent ensures namespace is deleted
    """
    caplog.set_level(logging.INFO)
    test_ns = "salt-test-namespace-absent"

    # Ensure namespace exists
    result = kubernetes.namespace_present(name=test_ns)
    assert result["result"] is True

    # Delete namespace
    result = kubernetes.namespace_absent(name=test_ns)
    assert result["result"] is True
    assert result["changes"]["kubernetes.namespace"]["new"] == "absent"

    # Verify namespace_absent again to verify idempotency
    result = kubernetes.namespace_absent(name=test_ns)
    assert result["result"] is True
    assert result["comment"] in ["The namespace does not exist", "Terminating"]


def test_namespace_present_with_context(kubernetes, caplog, namespace_template):
    """
    Test kubernetes.namespace_present ensures namespace is created using context
    """
    caplog.set_level(logging.INFO)
    test_ns = "salt-test-namespace-context"
    context = {
        "name": test_ns,
        "labels": {"app": "test"},
    }

    # Ensure namespace doesn't exist
    kubernetes.namespace_absent(name=test_ns)

    # Create namespace using context
    result = kubernetes.namespace_present(
        name=test_ns,
        source=namespace_template,
        template="jinja",
        context=context,
    )
    assert result["result"] is True
    assert result["changes"]["namespace"]["new"]["metadata"]["name"] == test_ns

    # Verify namespace_present again to verify idempotency
    result = kubernetes.namespace_present(
        name=test_ns,
        source=namespace_template,
        template="jinja",
        context=context,
    )
    assert result["result"] is True
    assert result["comment"] == "The namespace already exists"

    # Cleanup
    kubernetes.namespace_absent(name=test_ns)


def test_pod_present(kubernetes, caplog):
    """
    Test kubernetes.pod_present ensures pod is created
    """
    caplog.set_level(logging.INFO)
    test_pod = "salt-test-pod-present"
    namespace = "default"
    metadata = {"labels": {"app": "test"}}
    spec = {
        "containers": [
            {
                "name": "nginx",
                "image": "nginx:latest",
                "ports": [{"containerPort": 80}],
            }
        ]
    }

    # Create pod
    result = kubernetes.pod_present(
        name=test_pod,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
    )
    assert result["result"] is True

    # TODO: This needs fixed to handle proper present functionality,
    # but for now we will just assert False and the comment until
    #  it is fixed in the state module.
    # Run pod_present again to ensure it works if the pod already exists
    result = kubernetes.pod_present(
        name=test_pod,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
    )
    assert result["result"] is False
    assert (
        result["comment"]
        == "salt is currently unable to replace a pod without deleting it. Please perform the removal of the pod requiring the 'pod_absent' state if this is the desired behaviour."
    )

    # Cleanup
    kubernetes.pod_absent(name=test_pod, namespace=namespace)


def test_pod_absent(kubernetes, caplog):
    """
    Test kubernetes.pod_absent ensures pod is deleted
    """
    caplog.set_level(logging.INFO)
    test_pod = "salt-test-pod-absent"
    namespace = "default"
    metadata = {"labels": {"app": "test"}}
    spec = {
        "containers": [
            {
                "name": "nginx",
                "image": "nginx:latest",
                "ports": [{"containerPort": 80}],
            }
        ]
    }

    # Ensure pod exists
    result = kubernetes.pod_present(
        name=test_pod,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
    )
    assert result["result"] is True

    # Delete pod
    result = kubernetes.pod_absent(name=test_pod, namespace=namespace)
    assert result["result"] is True
    assert result["changes"]["kubernetes.pod"]["new"] == "absent"

    # Add a delay before verifying pod is gone
    time.sleep(15)

    # Verify pod_absent again to verify idempotency
    result = kubernetes.pod_absent(name=test_pod, namespace=namespace)
    assert result["result"] is True
    assert result["comment"] in ["The pod does not exist", "In progress", "Pod deleted"]


def test_pod_present_with_context(kubernetes, caplog, pod_template):
    """
    Test kubernetes.pod_present ensures pod is created using context
    """
    caplog.set_level(logging.INFO)
    test_pod = "salt-test-pod-present-context"
    namespace = "default"
    context = {
        "name": test_pod,
        "namespace": namespace,
        "image": "nginx:latest",
        "labels": {"app": "test"},
    }

    try:
        # Create pod using context
        result = kubernetes.pod_present(
            name=test_pod,
            namespace=namespace,
            source=pod_template,
            template="jinja",
            context=context,
        )

        # The first creation should work
        assert result["result"] is True
        assert result["changes"], "Expected changes when creating pod"

        # TODO: This needs fixed to handle proper present functionality,
        # but for now we will just assert False and the comment until
        #  it is fixed in the state module.
        # Run pod_present again to ensure it works if the pod already exists
        result = kubernetes.pod_present(
            name=test_pod,
            namespace=namespace,
            source=pod_template,
            template="jinja",
            context=context,
        )
        # This should return False with the expected message
        assert result["result"] is False
        assert "salt is currently unable to replace a pod" in result["comment"]

    finally:
        # Cleanup
        kubernetes.pod_absent(name=test_pod, namespace=namespace)
        # Add delay to ensure cleanup completes
        time.sleep(5)


def test_deployment_present(kubernetes, caplog):
    """
    Test kubernetes.deployment_present ensures deployment is created
    """
    caplog.set_level(logging.INFO)
    test_deployment = "salt-test-deployment-present"
    namespace = "default"
    metadata = {"labels": {"app": "test"}}
    spec = {
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

    # Create deployment
    result = kubernetes.deployment_present(
        name=test_deployment,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
    )
    assert result["result"] is True
    assert result["changes"]["metadata"]["labels"] == metadata["labels"]

    # Run deployment exists and can be replaced
    result = kubernetes.deployment_present(
        name=test_deployment,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
    )
    assert result["result"] is True

    # Cleanup
    kubernetes.deployment_absent(name=test_deployment, namespace=namespace)


def test_deployment_absent(kubernetes, caplog):
    """
    Test kubernetes.deployment_absent ensures deployment is deleted
    """
    caplog.set_level(logging.INFO)
    test_deployment = "salt-test-deployment-absent"
    namespace = "default"
    metadata = {"labels": {"app": "test"}}
    spec = {
        "replicas": 1,
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

    # Ensure deployment exists
    result = kubernetes.deployment_present(
        name=test_deployment,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
    )
    assert result["result"] is True

    # Delete deployment
    result = kubernetes.deployment_absent(name=test_deployment, namespace=namespace)
    assert result["result"] is True
    assert result["changes"]["kubernetes.deployment"]["new"] == "absent"

    # Run deployment_absent again to verify idempotency
    result = kubernetes.deployment_absent(name=test_deployment, namespace=namespace)
    assert result["result"] is True
    assert result["comment"] == "The deployment does not exist"


def test_deployment_present_with_context(kubernetes, caplog, deployment_template):
    """
    Test kubernetes.deployment_present ensures deployment is created using context
    """
    caplog.set_level(logging.INFO)
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
    result = kubernetes.deployment_present(
        name=test_deployment,
        namespace=namespace,
        source=deployment_template,
        template="jinja",
        context=context,
    )
    assert result["result"] is True

    # Run deployment exists and can be replaced
    result = kubernetes.deployment_present(
        name=test_deployment,
        namespace=namespace,
        source=deployment_template,
        template="jinja",
        context=context,
    )
    assert result["result"] is True

    # Cleanup
    kubernetes.deployment_absent(name=test_deployment, namespace=namespace)


def test_secret_present(kubernetes, caplog):
    """
    Test kubernetes.secret_present ensures secret is created
    """
    caplog.set_level(logging.INFO)
    test_secret = "salt-test-secret-present"
    namespace = "default"
    data = {
        "username": "admin",
        "password": "secretpassword",
    }

    # Create secret
    result = kubernetes.secret_present(
        name=test_secret,
        namespace=namespace,
        data=data,
    )
    assert result["result"] is True
    assert sorted(result["changes"]["data"]) == sorted(data.keys())

    # Verify secret exists and can be replaced
    result = kubernetes.secret_present(
        name=test_secret,
        namespace=namespace,
        data={"username": "newadmin", "password": "newpassword"},
    )
    assert result["result"] is True
    assert sorted(result["changes"]["data"]) == ["password", "username"]

    # Cleanup
    kubernetes.secret_absent(name=test_secret, namespace=namespace)


def test_secret_absent(kubernetes, caplog):
    """
    Test kubernetes.secret_absent ensures secret is deleted
    """
    caplog.set_level(logging.INFO)
    test_secret = "salt-test-secret-absent"
    namespace = "default"
    data = {"key": "value"}

    # Ensure secret exists
    result = kubernetes.secret_present(
        name=test_secret,
        namespace=namespace,
        data=data,
    )
    assert result["result"] is True

    # Delete secret
    result = kubernetes.secret_absent(name=test_secret, namespace=namespace)
    assert result["result"] is True
    assert result["changes"]["kubernetes.secret"]["new"] == "absent"

    # Run secret_absent again to verify idempotency
    result = kubernetes.secret_absent(name=test_secret, namespace=namespace)
    assert result["result"] is True
    assert result["comment"] == "The secret does not exist"


def test_secret_present_with_context(kubernetes, caplog, secret_template):
    """
    Test kubernetes.secret_present ensures secret is created using context
    """
    caplog.set_level(logging.INFO)
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
    result = kubernetes.secret_present(
        name=test_secret,
        namespace=namespace,
        source=secret_template,
        template="jinja",
        context=context,
    )
    assert result["result"] is True

    # Verify secret exists and can be replaced
    new_context = context.copy()
    new_context["secret_data"] = {
        "username": "bmV3YWRtaW4=",  # base64 encoded "newadmin"
        "password": "bmV3c2VjcmV0",  # base64 encoded "newsecret"
    }
    result = kubernetes.secret_present(
        name=test_secret,
        namespace=namespace,
        source=secret_template,
        template="jinja",
        context=new_context,
    )
    assert result["result"] is True
    assert sorted(result["changes"]["data"]) == ["password", "username"]

    # Cleanup
    kubernetes.secret_absent(name=test_secret, namespace=namespace)


def test_service_present(kubernetes, caplog):
    """
    Test kubernetes.service_present ensures service is created
    """
    caplog.set_level(logging.INFO)
    test_service = "salt-test-service-present"
    namespace = "default"
    metadata = {"labels": {"app": "test"}}
    spec = {
        "ports": [
            {"name": "http", "port": 80, "targetPort": 8080},
            {"name": "https", "port": 443, "targetPort": 8443},
        ],
        "selector": {"app": "test"},
        "type": "ClusterIP",
    }

    # Create service
    result = kubernetes.service_present(
        name=test_service,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
    )
    assert result["result"] is True
    assert result["changes"]["metadata"]["labels"] == metadata["labels"]

    # Run service_present again to verify idempotency
    result = kubernetes.service_present(
        name=test_service,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
    )
    assert result["result"] is True

    # Cleanup
    kubernetes.service_absent(name=test_service, namespace=namespace)


def test_service_absent(kubernetes, caplog):
    """
    Test kubernetes.service_absent ensures service is deleted
    """
    caplog.set_level(logging.INFO)
    test_service = "salt-test-service-absent"
    namespace = "default"
    metadata = {"labels": {"app": "test"}}
    spec = {
        "ports": [{"name": "http", "port": 80, "targetPort": 8080}],
        "selector": {"app": "test"},
        "type": "ClusterIP",
    }

    # Ensure service exists
    result = kubernetes.service_present(
        name=test_service,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
    )
    assert result["result"] is True

    # Delete service
    result = kubernetes.service_absent(name=test_service, namespace=namespace)
    assert result["result"] is True
    assert result["changes"]["kubernetes.service"]["new"] == "absent"

    # Run service_absent again to verify idempotency
    result = kubernetes.service_absent(name=test_service, namespace=namespace)
    assert result["result"] is True
    assert result["comment"] == "The service does not exist"


def test_service_present_with_context(kubernetes, caplog, service_template):
    """
    Test kubernetes.service_present ensures service is created using context
    """
    caplog.set_level(logging.INFO)
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
    result = kubernetes.service_present(
        name=test_service,
        namespace=namespace,
        source=service_template,
        template="jinja",
        context=context,
    )
    assert result["result"] is True

    # Run service_present again to verify idempotency
    result = kubernetes.service_present(
        name=test_service,
        namespace=namespace,
        source=service_template,
        template="jinja",
        context=context,
    )
    assert result["result"] is True

    # Cleanup
    kubernetes.service_absent(name=test_service, namespace=namespace)


def test_configmap_present(kubernetes, caplog):
    """
    Test kubernetes.configmap_present ensures configmap is created
    """
    caplog.set_level(logging.INFO)
    test_configmap = "salt-test-configmap-present"
    namespace = "default"
    data = {
        "config.yaml": "foo: bar\nkey: value",
        "app.properties": "app.name=myapp\napp.port=8080",
    }

    # Create configmap
    result = kubernetes.configmap_present(
        name=test_configmap,
        namespace=namespace,
        data=data,
    )
    assert result["result"] is True
    assert result["changes"]["data"] == data

    # Verify configmap exists and can be replaced
    new_data = {
        "config.yaml": "foo: newbar\nkey: newvalue",
        "app.properties": "app.name=newapp\napp.port=9090",
    }
    result = kubernetes.configmap_present(
        name=test_configmap,
        namespace=namespace,
        data=new_data,
    )
    assert result["result"] is True
    assert result["changes"]["data"] == new_data

    # Cleanup
    kubernetes.configmap_absent(name=test_configmap, namespace=namespace)


def test_configmap_absent(kubernetes, caplog):
    """
    Test kubernetes.configmap_absent ensures configmap is deleted
    """
    caplog.set_level(logging.INFO)
    test_configmap = "salt-test-configmap-absent"
    namespace = "default"
    data = {"key": "value"}

    # Ensure configmap exists
    result = kubernetes.configmap_present(
        name=test_configmap,
        namespace=namespace,
        data=data,
    )
    assert result["result"] is True

    # Delete configmap
    result = kubernetes.configmap_absent(name=test_configmap, namespace=namespace)
    assert result["result"] is True
    assert result["changes"]["kubernetes.configmap"]["new"] == "absent"

    # Run configmap_absent again to verify idempotency
    result = kubernetes.configmap_absent(name=test_configmap, namespace=namespace)
    assert result["result"] is True
    assert result["comment"] == "The configmap does not exist"


def test_configmap_present_with_context(kubernetes, caplog, configmap_template):
    """
    Test kubernetes.configmap_present ensures configmap is created using context
    """
    caplog.set_level(logging.INFO)
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
    result = kubernetes.configmap_present(
        name=test_configmap,
        namespace=namespace,
        source=configmap_template,
        template="jinja",
        context=context,
    )
    assert result["result"] is True

    # Verify configmap exists and can be replaced
    new_context = context.copy()
    new_context["configmap_data"] = {
        "config.yaml": "foo: newbar\nkey: newvalue",
        "app.properties": "app.name=newapp\napp.port=9090",
    }
    result = kubernetes.configmap_present(
        name=test_configmap,
        namespace=namespace,
        source=configmap_template,
        template="jinja",
        context=new_context,
    )
    assert result["result"] is True

    # Cleanup
    kubernetes.configmap_absent(name=test_configmap, namespace=namespace)


def test_node_label_present(kubernetes, caplog, loaders):
    """
    Test kubernetes.node_label_present ensures label is created and updated
    """
    caplog.set_level(logging.INFO)
    test_label = "salt-test.label/test"
    test_value = "value1"
    new_value = "value2"

    # Get a node to test with (use control-plane node)
    nodes = loaders.modules.kubernetes.nodes()
    node_name = next(node for node in nodes if "control-plane" in node)

    # Add label
    result = kubernetes.node_label_present(
        name=test_label,
        node=node_name,
        value=test_value,
    )
    assert result["result"] is True
    assert test_label in result["changes"][f"{node_name}.{test_label}"]["new"]

    # Update label value
    result = kubernetes.node_label_present(
        name=test_label,
        node=node_name,
        value=new_value,
    )
    assert result["result"] is True
    assert result["changes"][f"{node_name}.{test_label}"]["new"][test_label] == new_value

    # Try to set same value (should be no-op)
    result = kubernetes.node_label_present(
        name=test_label,
        node=node_name,
        value=new_value,
    )
    assert result["result"] is True
    assert result["comment"] == "The label is already set and has the specified value"
    assert not result["changes"]

    # Cleanup
    kubernetes.node_label_absent(name=test_label, node=node_name)


def test_node_label_absent(kubernetes, caplog, loaders):
    """
    Test kubernetes.node_label_absent ensures label is removed
    """
    caplog.set_level(logging.INFO)
    test_label = "salt-test.label/remove"
    test_value = "value"

    # Get a node to test with (use control-plane node)
    nodes = loaders.modules.kubernetes.nodes()
    node_name = next(node for node in nodes if "control-plane" in node)

    # Ensure label exists first
    result = kubernetes.node_label_present(
        name=test_label,
        node=node_name,
        value=test_value,
    )
    assert result["result"] is True

    # Remove label
    result = kubernetes.node_label_absent(
        name=test_label,
        node=node_name,
    )
    assert result["result"] is True
    assert result["changes"]["kubernetes.node_label"]["new"] == "absent"

    # Try to remove again (should be no-op)
    result = kubernetes.node_label_absent(
        name=test_label,
        node=node_name,
    )
    assert result["result"] is True
    assert result["comment"] == "The label does not exist"
    assert not result["changes"]


def test_node_label_folder_absent(kubernetes, caplog, loaders):
    """
    Test kubernetes.node_label_folder_absent ensures all labels with prefix are removed
    """
    caplog.set_level(logging.INFO)
    test_prefix = "example.com"
    test_labels = {
        f"{test_prefix}/label1": "value1",
        f"{test_prefix}/label2": "value2",
    }

    # Get a node to test with (use control-plane node)
    nodes = loaders.modules.kubernetes.nodes()
    node_name = next(node for node in nodes if "control-plane" in node)

    # Add test labels
    for label, value in test_labels.items():
        result = kubernetes.node_label_present(
            name=label,
            node=node_name,
            value=value,
        )
        assert result["result"] is True

    # Give the cluster a moment to apply labels
    time.sleep(2)

    # Remove label folder
    result = kubernetes.node_label_folder_absent(
        name=test_prefix,
        node=node_name,
    )
    assert result["result"] is True
    # Check that we have changes in the result
    assert result["changes"], "Expected changes in result but got none"

    # Try to remove again (should be no-op)
    result = kubernetes.node_label_folder_absent(
        name=test_prefix,
        node=node_name,
    )
    assert result["result"] is True
    assert result["comment"] == "The label folder does not exist"
    assert not result["changes"]


def test_service_account_token_secret_present(kubernetes):
    """Test creating a service account token secret via state"""
    secret_name = "test-svc-token"
    namespace = "default"

    # Create token secret using state using default service account
    ret = kubernetes.secret_present(
        name=secret_name,
        namespace=namespace,
        data={},  # Empty data - kubernetes will populate
        type="kubernetes.io/service-account-token",
        metadata={"annotations": {"kubernetes.io/service-account.name": "default"}},
    )

    assert ret["result"] is True
    assert ret["changes"], "Expected changes when creating secret"
    assert isinstance(ret["changes"]["data"], list)  # Should return list of keys

    # We don't test second run since token will always be different
    # Just clean up
    kubernetes.secret_absent(name=secret_name, namespace=namespace)
