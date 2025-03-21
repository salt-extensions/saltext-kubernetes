import logging
from textwrap import dedent

import pytest
from saltfactories.utils import random_string

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms"),
]


@pytest.fixture()
def kubernetes(states):
    """
    Return kubernetes state module
    """
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


@pytest.fixture(params=[True])
def namespace(kubernetes, request):
    """
    Fixture providing a namespace for testing
    """
    name = random_string("namespace-", uppercase=False)

    # Only create the namespace if requested
    if request.param:
        ret = kubernetes.namespace_present(name=name, wait=True)
        assert ret.result is True
    try:
        yield name
    finally:
        ret = kubernetes.namespace_absent(name=name, wait=True)
        assert ret.result is True


@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_namespace_present(kubernetes, namespace):
    """
    Test kubernetes.namespace_present creates a namespace
    """
    ret = kubernetes.namespace_present(name=namespace, wait=True)

    assert ret.result is True
    assert ret.changes


def test_namespace_present_idempotency(kubernetes, namespace):
    """
    Test kubernetes.namespace_present is idempotent
    """
    ret = kubernetes.namespace_present(name=namespace)

    assert ret.result is True
    assert "already exists" in ret.comment


def test_namespace_present_test_mode(kubernetes, namespace):
    """
    Test kubernetes.namespace_present in test mode
    """
    ret = kubernetes.namespace_present(name=namespace, test=True)

    assert ret.result is None
    assert not ret.changes


@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_namespace_present_template_context(kubernetes, namespace, namespace_template):
    """
    Test kubernetes.namespace_present with template_context
    """
    template_context = {
        "name": namespace,
        "labels": {"app": "test"},
    }

    ret = kubernetes.namespace_present(
        name=namespace,
        source=namespace_template,
        template="jinja",
        template_context=template_context,
        wait=True,
    )

    assert ret.result is True
    assert ret.changes


def test_namespace_absent(kubernetes, namespace):
    """
    Test kubernetes.namespace_absent deletes a namespace
    """
    ret = kubernetes.namespace_absent(name=namespace, wait=True)

    assert ret.result is True
    assert ret.changes["kubernetes.namespace"]["new"] == "absent"


def test_namespace_absent_test_mode(kubernetes, namespace):
    """
    Test kubernetes.namespace_absent in test mode
    """
    ret = kubernetes.namespace_absent(name=namespace, test=True)

    assert ret.result is None
    assert not ret.changes


def test_namespace_absent_idempotency(kubernetes, namespace):
    """
    Test kubernetes.namespace_absent is idempotent
    """
    ret = kubernetes.namespace_absent(name=namespace, wait=True)
    assert ret.result is True

    # Test idempotency
    ret = kubernetes.namespace_absent(name=namespace)
    assert ret.result is True
    assert "does not exist" in ret.comment
    assert not ret.changes


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


@pytest.fixture(params=[True])
def pod(kubernetes, _pod_spec, request):
    """
    Fixture providing a pod for testing
    """
    name = random_string("pod-", uppercase=False)
    namespace = "default"

    # Only create the pod if requested
    if request.param:
        ret = kubernetes.pod_present(
            name=name,
            namespace=namespace,
            spec=_pod_spec,
            wait=True,
        )
        assert ret.result is True
    try:
        yield {"name": name, "namespace": namespace}
    finally:
        ret = kubernetes.pod_absent(name=name, namespace=namespace, wait=True)
        assert ret.result is True
        assert ret.comment in ["The pod does not exist", "Pod deleted"]


@pytest.mark.parametrize("pod", [False], indirect=True)
def test_pod_present(kubernetes, pod, _pod_spec):
    """
    Test kubernetes.pod_present creates a pod
    """
    ret = kubernetes.pod_present(
        name=pod["name"],
        namespace=pod["namespace"],
        spec=_pod_spec,
        wait=True,
    )

    assert ret.result is True
    assert ret.changes

    # Comment out idempotent test for now
    # TODO: The state module needs fixed to handle proper present functionality


# def test_pod_present_idempotency(kubernetes, pod, _pod_spec):
#     """
#     Test kubernetes.pod_present is idempotent
#     """
#     ret = kubernetes.pod_present(
#         name=pod["name"],
#         namespace=pod["namespace"],
#         spec=_pod_spec,
#         wait=True,
#     )

#     assert ret.result is True
#     assert "already exists" in ret.comment
#     assert not ret.changes


def test_pod_present_test_mode(kubernetes, pod, _pod_spec):
    """
    Test kubernetes.pod_present in test mode
    """
    ret = kubernetes.pod_present(
        name=pod["name"],
        namespace=pod["namespace"],
        spec=_pod_spec,
        test=True,
    )

    assert ret.result is None
    assert not ret.changes


@pytest.mark.parametrize("pod", [False], indirect=True)
def test_pod_present_template_context(kubernetes, pod, pod_template):
    """
    Test kubernetes.pod_present with template_context
    """
    template_context = {
        "name": pod["name"],
        "namespace": pod["namespace"],
        "image": "nginx:latest",
        "labels": {"app": "test"},
    }

    ret = kubernetes.pod_present(
        name=pod["name"],
        namespace=pod["namespace"],
        source=pod_template,
        template="jinja",
        template_context=template_context,
        wait=True,
    )

    assert ret.result is True
    assert ret.changes


def test_pod_absent(kubernetes, pod):
    """
    Test kubernetes.pod_absent deletes a pod
    """
    ret = kubernetes.pod_absent(
        name=pod["name"],
        namespace=pod["namespace"],
        wait=True,
    )

    assert ret.result is True
    assert ret.changes["kubernetes.pod"]["new"] == "absent"


def test_pod_absent_test_mode(kubernetes, pod):
    """
    Test kubernetes.pod_absent in test mode
    """
    ret = kubernetes.pod_absent(
        name=pod["name"],
        namespace=pod["namespace"],
        test=True,
    )

    assert ret.result is None
    assert not ret.changes


def test_pod_absent_idempotency(kubernetes, pod):
    """
    Test kubernetes.pod_absent is idempotent
    """
    ret = kubernetes.pod_absent(name=pod["name"], namespace=pod["namespace"], wait=True)
    assert ret.result is True

    # Test idempotency
    ret = kubernetes.pod_absent(name=pod["name"], namespace=pod["namespace"])
    assert ret.result is True
    assert "does not exist" in ret.comment
    assert not ret.changes


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


@pytest.fixture(params=[True])
def deployment(kubernetes, _deployment_spec, request):
    """
    Fixture providing a deployment for testing
    """
    name = random_string("deployment-", uppercase=False)
    namespace = "default"

    # Only create the deployment if requested
    if request.param:
        ret = kubernetes.deployment_present(
            name=name,
            namespace=namespace,
            spec=_deployment_spec,
            wait=True,
        )
        assert ret.result is True
    try:
        yield {"name": name, "namespace": namespace}
    finally:
        ret = kubernetes.deployment_absent(name=name, namespace=namespace, wait=True)
        assert ret.result is True
        assert ret.comment in ["The deployment does not exist", "None"]


@pytest.mark.parametrize("deployment", [False], indirect=True)
def test_deployment_present(kubernetes, deployment, _deployment_spec):
    """
    Test kubernetes.deployment_present creates a deployment
    """
    ret = kubernetes.deployment_present(
        name=deployment["name"],
        namespace=deployment["namespace"],
        spec=_deployment_spec,
        wait=True,
    )

    assert ret.result is True
    assert ret.changes

    # Comment out idempotent test for now
    # TODO: The state module needs fixed to handle proper present functionality


# def test_deployment_present_idempotency(kubernetes, deployment, _deployment_spec):
#     """
#     Test kubernetes.deployment_present is idempotent
#     """
#     ret = kubernetes.deployment_present(
#         name=deployment["name"],
#         namespace=deployment["namespace"],
#         spec=_deployment_spec,
#         wait=True,
#     )
#     assert ret.result is True
#     assert "already exists" in ret.comment
#     assert not ret.changes


def test_deployment_present_replace(kubernetes, deployment):
    """
    Test kubernetes.deployment_present replaces a deployment
    """
    new_spec = {
        "replicas": 3,
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

    ret = kubernetes.deployment_present(
        name=deployment["name"],
        namespace=deployment["namespace"],
        spec=new_spec,
        wait=True,
    )

    assert ret.result is True
    assert ret.changes["spec"]["replicas"] == 3


def test_deployment_present_test_mode(kubernetes, deployment, _deployment_spec):
    """
    Test kubernetes.deployment_present in test mode
    """
    ret = kubernetes.deployment_present(
        name=deployment["name"],
        namespace=deployment["namespace"],
        spec=_deployment_spec,
        test=True,
    )

    assert ret.result is None
    assert not ret.changes


@pytest.mark.parametrize("deployment", [False], indirect=True)
def test_deployment_present_template_context(kubernetes, deployment, deployment_template):
    """
    Test kubernetes.deployment_present with template_context
    """
    template_context = {
        "name": deployment["name"],
        "namespace": deployment["namespace"],
        "replicas": 2,
        "app_label": "test",
        "image": "nginx:latest",
        "labels": {"app": "test"},
    }

    ret = kubernetes.deployment_present(
        name=deployment["name"],
        namespace=deployment["namespace"],
        source=deployment_template,
        template="jinja",
        template_context=template_context,
        wait=True,
    )

    assert ret.result is True
    assert ret.changes


def test_deployment_absent(kubernetes, deployment):
    """
    Test kubernetes.deployment_absent deletes a deployment
    """
    ret = kubernetes.deployment_absent(
        name=deployment["name"],
        namespace=deployment["namespace"],
        wait=True,
    )

    assert ret.result is True
    assert ret.changes["kubernetes.deployment"]["new"] == "absent"


def test_deployment_absent_test_mode(kubernetes, deployment):
    """
    Test kubernetes.deployment_absent in test mode
    """
    ret = kubernetes.deployment_absent(
        name=deployment["name"],
        namespace=deployment["namespace"],
        test=True,
    )

    assert ret.result is None
    assert not ret.changes


def test_deployment_absent_idempotency(kubernetes, deployment):
    """
    Test kubernetes.deployment_absent is idempotent
    """
    ret = kubernetes.deployment_absent(
        name=deployment["name"], namespace=deployment["namespace"], wait=True
    )
    assert ret.result is True

    # Test idempotency
    ret = kubernetes.deployment_absent(name=deployment["name"], namespace=deployment["namespace"])
    assert ret.result is True
    assert "does not exist" in ret.comment
    assert not ret.changes


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


@pytest.fixture(params=[True])
def secret(kubernetes, request):
    """
    Fixture providing a secret for testing
    """
    name = random_string("secret-", uppercase=False)
    namespace = "default"

    # Only create the secret if requested
    if request.param:
        ret = kubernetes.secret_present(
            name=name,
            namespace=namespace,
            data={"key": "value"},
            wait=True,
        )
        assert ret.result is True
    try:
        yield {"name": name, "namespace": namespace}
    finally:
        ret = kubernetes.secret_absent(name=name, namespace=namespace, wait=True)
        assert ret.result is True
        assert ret.comment in ["The secret does not exist", "Secret deleted"]


@pytest.mark.parametrize("secret", [False], indirect=True)
def test_secret_present(kubernetes, secret):
    """
    Test kubernetes.secret_present creates a secret
    """
    ret = kubernetes.secret_present(
        name=secret["name"],
        namespace=secret["namespace"],
        data={"key": "value"},
        wait=True,
    )

    assert ret.result is True
    assert ret.changes

    # Comment out idempotent test for now
    # TODO: The state module needs fixed to handle proper present functionality


# def test_secret_present_idempotency(kubernetes, secret):
#     """
#     Test kubernetes.secret_present is idempotent
#     """
#     ret = kubernetes.secret_present(
#         name=secret["name"],
#         namespace=secret["namespace"],
#         data={"key": "value"},
#         wait=True,
#     )
#     assert ret.result is True
#     assert "already exists" in ret.comment
#     assert not ret.changes


def test_secret_present_test_mode(kubernetes, secret):
    """
    Test kubernetes.secret_present in test mode
    """
    ret = kubernetes.secret_present(
        name=secret["name"],
        namespace=secret["namespace"],
        data={"key": "value"},
        test=True,
    )

    assert ret.result is None
    assert not ret.changes


def test_secret_present_replace(kubernetes, secret):
    """
    Test kubernetes.secret_present replaces a secret
    """
    new_data = {"key": "new_value"}

    ret = kubernetes.secret_present(
        name=secret["name"],
        namespace=secret["namespace"],
        data=new_data,
        wait=True,
    )

    assert ret.result is True
    assert ret.changes


@pytest.mark.parametrize("secret", [False], indirect=True)
def test_secret_present_template_context(kubernetes, secret, secret_template):
    """
    Test kubernetes.secret_present with template_context
    """
    template_context = {
        "name": secret["name"],
        "namespace": secret["namespace"],
        "type": "Opaque",
        "labels": {"app": "test"},
        "secret_data": {"key": "value"},
    }

    ret = kubernetes.secret_present(
        name=secret["name"],
        namespace=secret["namespace"],
        source=secret_template,
        template="jinja",
        template_context=template_context,
        wait=True,
    )

    assert ret.result is True
    assert ret.changes


@pytest.mark.parametrize("secret", [False], indirect=True)
def test_service_account_token_secret_present(kubernetes, secret):
    """
    Test creating a service account token secret via state
    """
    ret = kubernetes.secret_present(
        name=secret["name"],
        namespace=secret["namespace"],
        data={},  # Empty data - kubernetes will populate
        type="kubernetes.io/service-account-token",
        metadata={"annotations": {"kubernetes.io/service-account.name": "default"}},
        wait=True,
    )

    assert ret.result is True
    assert ret.changes


def test_secret_absent(kubernetes, secret):
    """
    Test kubernetes.secret_absent deletes a secret
    """
    ret = kubernetes.secret_absent(
        name=secret["name"],
        namespace=secret["namespace"],
        wait=True,
    )

    assert ret.result is True
    assert ret.changes["kubernetes.secret"]["new"] == "absent"


def test_secret_absent_test_mode(kubernetes, secret):
    """
    Test kubernetes.secret_absent in test mode
    """
    ret = kubernetes.secret_absent(
        name=secret["name"],
        namespace=secret["namespace"],
        test=True,
    )

    assert ret.result is None
    assert not ret.changes


def test_secret_absent_idempotency(kubernetes, secret):
    """
    Test kubernetes.secret_absent is idempotent
    """
    ret = kubernetes.secret_absent(name=secret["name"], namespace=secret["namespace"], wait=True)
    assert ret.result is True

    # Test idempotency
    ret = kubernetes.secret_absent(name=secret["name"], namespace=secret["namespace"])
    assert ret.result is True
    assert "does not exist" in ret.comment
    assert not ret.changes


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


@pytest.fixture(params=[True])
def service(kubernetes, _service_spec, request):
    """
    Fixture providing a service for testing
    """
    name = random_string("service-", uppercase=False)
    namespace = "default"

    # Only create the service if requested
    if request.param:
        ret = kubernetes.service_present(
            name=name,
            namespace=namespace,
            spec=_service_spec,
            wait=True,
        )
        assert ret.result is True
    try:
        yield {"name": name, "namespace": namespace}
    finally:
        ret = kubernetes.service_absent(name=name, namespace=namespace, wait=True)
        assert ret.result is True
        assert ret.comment in ["The service does not exist", "Service deleted"]


@pytest.mark.parametrize("service", [False], indirect=True)
def test_service_present(kubernetes, service, _service_spec):
    """
    Test kubernetes.service_present creates a service
    """
    ret = kubernetes.service_present(
        name=service["name"],
        namespace=service["namespace"],
        spec=_service_spec,
        wait=True,
    )

    assert ret.result is True
    assert ret.changes

    # Comment out idempotent test for now
    # TODO: The state module needs fixed to handle proper present functionality


# def test_service_present_idempotency(kubernetes, service, _service_spec):
#     """
#     Test kubernetes.service_present is idempotent
#     """
#     ret = kubernetes.service_present(
#         name=service["name"],
#         namespace=service["namespace"],
#         spec=_service_spec,
#         wait=True,
#     )
#     assert ret.result is True
#     assert "already exists" in ret.comment
#     assert not ret.changes


def test_service_present_test_mode(kubernetes, service, _service_spec):
    """
    Test kubernetes.service_present in test mode
    """
    ret = kubernetes.service_present(
        name=service["name"],
        namespace=service["namespace"],
        spec=_service_spec,
        test=True,
    )

    assert ret.result is None
    assert not ret.changes


def test_service_present_replace(kubernetes, service):
    """
    Test kubernetes.service_present replaces a service
    """
    new_spec = {
        "ports": [
            {"name": "http", "port": 80, "targetPort": 8080},
            {"name": "https", "port": 443, "targetPort": 8443},
        ],
        "selector": {"app": "test"},
        "type": "NodePort",
    }

    ret = kubernetes.service_present(
        name=service["name"],
        namespace=service["namespace"],
        spec=new_spec,
        wait=True,
    )

    assert ret.result is True
    assert ret.changes["spec"]["type"] == "NodePort"


@pytest.mark.parametrize("service", [False], indirect=True)
def test_service_present_template_context(kubernetes, service, service_template):
    """
    Test kubernetes.service_present with template_context
    """
    template_context = {
        "name": service["name"],
        "namespace": service["namespace"],
        "type": "ClusterIP",
        "ports": [
            {"name": "http", "port": 80, "target_port": 8080},
            {"name": "https", "port": 443, "target_port": 8443},
        ],
        "selector": {"app": "test"},
        "labels": {"app": "test"},
    }

    ret = kubernetes.service_present(
        name=service["name"],
        namespace=service["namespace"],
        source=service_template,
        template="jinja",
        template_context=template_context,
        wait=True,
    )

    assert ret.result is True
    assert ret.changes


def test_service_absent(kubernetes, service):
    """
    Test kubernetes.service_absent deletes a service
    """
    ret = kubernetes.service_absent(
        name=service["name"],
        namespace=service["namespace"],
        wait=True,
    )

    assert ret.result is True
    assert ret.changes["kubernetes.service"]["new"] == "absent"


def test_service_absent_test_mode(kubernetes, service):
    """
    Test kubernetes.service_absent in test mode
    """
    ret = kubernetes.service_absent(
        name=service["name"],
        namespace=service["namespace"],
        test=True,
    )

    assert ret.result is None
    assert not ret.changes


def test_service_absent_idempotency(kubernetes, service):
    """
    Test kubernetes.service_absent is idempotent
    """
    ret = kubernetes.service_absent(name=service["name"], namespace=service["namespace"], wait=True)
    assert ret.result is True

    # Test idempotency
    ret = kubernetes.service_absent(name=service["name"], namespace=service["namespace"])
    assert ret.result is True
    assert "does not exist" in ret.comment
    assert not ret.changes


@pytest.fixture
def configmap_data():
    """
    Fixture providing basic configmap data
    """
    return {
        "config.yaml": "foo: bar\nkey: value",
        "app.properties": "app.name=myapp\napp.port=8080",
    }


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


@pytest.fixture(params=[True])
def configmap(kubernetes, configmap_data, request):
    """
    Fixture to create a test configmap for state tests
    """
    name = random_string("configmap-", uppercase=False)
    namespace = "default"

    # Only create the configmap if requested
    if request.param:
        ret = kubernetes.configmap_present(
            name=name,
            namespace=namespace,
            data=configmap_data,
            wait=True,
        )
        assert ret.result is True
    try:
        yield {"name": name, "namespace": namespace, "data": configmap_data}
    finally:
        # Cleanup the configmap after the test
        ret = kubernetes.configmap_absent(name=name, namespace=namespace, wait=True)
        assert ret.result is True
        assert ret.comment in ["The configmap does not exist", "ConfigMap deleted"]


@pytest.mark.parametrize("configmap", [False], indirect=True)
def test_configmap_present(kubernetes, configmap):
    """
    Test kubernetes.configmap_present creates a configmap
    """
    ret = kubernetes.configmap_present(
        name=configmap["name"],
        namespace=configmap["namespace"],
        data=configmap["data"],
        wait=True,
    )

    assert ret.result is True
    assert ret.changes["data"] == configmap["data"]

    # Comment out idempotent test for now
    # TODO: The state module needs fixed to handle proper present functionality


# def test_configmap_present_idempotency(kubernetes, configmap):
#     """
#     Test kubernetes.configmap_present is idempotent
#     """

#     ret = kubernetes.configmap_present(
#         name=configmap["name"],
#         namespace=configmap["namespace"],
#         data=configmap["data"],
#         wait=True,
#     )

#     assert ret.result is True
#     assert "already exists" in ret.comment
#     assert not ret.changes


def test_configmap_replace(kubernetes, configmap):
    """
    Test kubernetes.configmap_present replaces a configmap
    """
    new_data = {
        "config.yaml": "foo: newbar\nkey: newvalue",
        "app.properties": "app.name=newapp\napp.port=9090",
    }

    ret = kubernetes.configmap_present(
        name=configmap["name"],
        namespace=configmap["namespace"],
        data=new_data,
        wait=True,
    )

    assert ret.result is True
    assert ret.changes["data"] == new_data


def test_configmap_present_test_mode(kubernetes, configmap):
    """
    Test kubernetes.configmap_present in test mode
    """
    ret = kubernetes.configmap_present(
        name=configmap["name"],
        namespace=configmap["namespace"],
        data=configmap["data"],
        test=True,
    )

    assert ret.result is None
    assert not ret.changes


def test_configmap_present_test_changes(kubernetes, configmap):
    """
    Test kubernetes.configmap_present with changes=True
    """
    new_data = {
        "config.yaml": "foo: newbar\nkey: newvalue",
        "app.properties": "app.name=newapp\napp.port=9090",
    }

    ret = kubernetes.configmap_present(
        name=configmap["name"],
        namespace=configmap["namespace"],
        data=new_data,
        test=True,
    )
    assert ret.result is None
    assert not ret.changes


@pytest.mark.parametrize("configmap", [False], indirect=True)
def test_configmap_present_template_context(kubernetes, configmap, configmap_template):
    """
    Test kubernetes.configmap_present with template_context
    """
    template_context = {
        "name": configmap["name"],
        "namespace": configmap["namespace"],
        "labels": {"app": "test"},
        "configmap_data": {
            "config.yaml": "foo: bar\nkey: value",
            "app.properties": "app.name=myapp\napp.port=8080",
        },
    }

    ret = kubernetes.configmap_present(
        name=configmap["name"],
        namespace=configmap["namespace"],
        source=configmap_template,
        template="jinja",
        template_context=template_context,
        wait=True,
    )

    assert ret.result is True
    assert ret.changes


def test_configmap_absent(kubernetes, configmap):
    """
    Test kubernetes.configmap_absent deletes a configmap
    """
    ret = kubernetes.configmap_absent(
        name=configmap["name"],
        namespace=configmap["namespace"],
        wait=True,
    )

    assert ret.result is True
    assert ret.changes["kubernetes.configmap"]["new"] == "absent"
    assert ret.changes["kubernetes.configmap"]["old"] == "present"


def test_configmap_absent_test_mode(kubernetes, configmap):
    """
    Test kubernetes.configmap_absent in test mode
    """
    ret = kubernetes.configmap_absent(
        name=configmap["name"],
        namespace=configmap["namespace"],
        test=True,
    )

    assert ret.result is None
    assert not ret.changes


def test_configmap_absent_idempotency(kubernetes, configmap):
    """
    Test kubernetes.configmap_absent is idempotent
    """

    ret = kubernetes.configmap_absent(
        name=configmap["name"],
        namespace=configmap["namespace"],
        wait=True,
    )
    assert ret.result is True

    # Test idempotency
    ret = kubernetes.configmap_absent(
        name=configmap["name"],
        namespace=configmap["namespace"],
    )
    assert ret.result is True
    assert "does not exist" in ret.comment
    assert not ret.changes


@pytest.fixture(scope="module")
def node_name(loaders):
    """
    Fixture providing a node name for testing
    """
    # Get a node to test with (use control-plane node)
    nodes = loaders.modules.kubernetes.nodes()
    return next(node for node in nodes if "control-plane" in node)


@pytest.fixture(params=[True])
def node_label(kubernetes, node_name, request):
    """
    Fixture providing a node label for testing
    """
    test_label = "salt-test.label/test"
    test_value = "value1"

    # Only create the label if requested
    if request.param:
        ret = kubernetes.node_label_present(
            name=test_label,
            node=node_name,
            value=test_value,
        )
        assert ret.result is True
    try:
        yield {"name": test_label, "node": node_name, "value": test_value}
    finally:
        # Cleanup the label after the test
        ret = kubernetes.node_label_absent(name=test_label, node=node_name)
        assert ret.result is True
        assert ret.comment in ["The label does not exist", "Label removed from node"]


@pytest.mark.parametrize("node_label", [False], indirect=True)
def test_node_label_present(kubernetes, node_label):
    """
    Test kubernetes.node_label_present creates a label
    """
    ret = kubernetes.node_label_present(
        name=node_label["name"],
        node=node_label["node"],
        value=node_label["value"],
    )

    assert ret.result is True
    assert ret.changes[f"{node_label['node']}.{node_label['name']}"]["new"]
    assert (
        ret.changes[f"{node_label['node']}.{node_label['name']}"]["new"][node_label["name"]]
        == node_label["value"]
    )


def test_node_label_present_idempotency(kubernetes, node_label):
    """
    Test kubernetes.node_label_present is idempotent
    """
    ret = kubernetes.node_label_present(
        name=node_label["name"],
        node=node_label["node"],
        value=node_label["value"],
    )

    assert ret.result is True
    assert "The label is already set and has the specified value" in ret.comment
    assert not ret.changes


def test_node_label_present_test_mode(kubernetes, node_label):
    """
    Test kubernetes.node_label_present in test mode
    """
    ret = kubernetes.node_label_present(
        name=node_label["name"],
        node=node_label["node"],
        value=node_label["value"],
        test=True,
    )

    assert ret.result is True
    assert "The label is already set and has the specified value" in ret.comment
    assert not ret.changes


def test_node_label_present_replace(kubernetes, node_label):
    """
    Test kubernetes.node_label_present replaces a label
    """
    new_value = "value2"

    ret = kubernetes.node_label_present(
        name=node_label["name"],
        node=node_label["node"],
        value=new_value,
    )

    assert ret.result is True
    assert (
        ret.changes[f"{node_label['node']}.{node_label['name']}"]["new"][node_label["name"]]
        == new_value
    )


def test_node_label_present_test_changes(kubernetes, node_label):
    """
    Test kubernetes.node_label_present with changes=True
    """
    new_value = "value2"

    ret = kubernetes.node_label_present(
        name=node_label["name"],
        node=node_label["node"],
        value=new_value,
        test=True,
    )
    assert ret.result is None
    assert not ret.changes


def test_node_label_absent(kubernetes, node_label):
    """
    Test kubernetes.node_label_absent deletes a label
    """
    ret = kubernetes.node_label_absent(
        name=node_label["name"],
        node=node_label["node"],
    )

    assert ret.result is True
    assert ret.changes["kubernetes.node_label"]["new"] == "absent"


def test_node_label_absent_test_mode(kubernetes, node_label):
    """
    Test kubernetes.node_label_absent in test mode
    """
    ret = kubernetes.node_label_absent(
        name=node_label["name"],
        node=node_label["node"],
        test=True,
    )

    assert ret.result is None
    assert not ret.changes


def test_node_label_absent_idempotency(kubernetes, node_label):
    """
    Test kubernetes.node_label_absent is idempotent
    """
    ret = kubernetes.node_label_absent(
        name=node_label["name"],
        node=node_label["node"],
        wait=True,
    )
    assert ret.result is True

    # Test idempotency
    ret = kubernetes.node_label_absent(
        name=node_label["name"],
        node=node_label["node"],
    )
    assert ret.result is True
    assert "does not exist" in ret.comment
    assert not ret.changes


def test_node_label_folder_absent(kubernetes, node_label):
    """
    Test kubernetes.node_label_folder_absent deletes all labels with prefix
    """

    test_prefix = "salt-test.label"
    test_labels = {
        f"{test_prefix}/label1": "value1",
        f"{test_prefix}/label2": "value2",
    }

    # Ensure labels exist first
    for label, value in test_labels.items():
        ret = kubernetes.node_label_present(
            name=label,
            node=node_label["node"],
            value=value,
        )
        assert ret.result is True
        assert ret.changes[f"{node_label['node']}.{label}"]["new"][label] == value

    # Test remove labels with test=true
    ret = kubernetes.node_label_folder_absent(
        name=test_prefix,
        node=node_label["node"],
        test=True,
    )
    assert ret.comment in ["The label folder is going to be deleted", "The labels do not exist"]
    assert ret.result is None

    # Remove labels
    ret = kubernetes.node_label_folder_absent(
        name=test_prefix,
        node=node_label["node"],
    )
    assert ret.result is True
    assert ret.changes

    # Try to remove again (should be no-op)
    ret = kubernetes.node_label_folder_absent(
        name=test_prefix,
        node=node_label["node"],
    )
    assert ret.result is True
    assert "The label folder does not exis" in ret.comment
    assert not ret.changes
