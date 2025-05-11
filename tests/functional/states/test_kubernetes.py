import logging
from textwrap import dedent

import pytest

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms"),
]


@pytest.fixture
def kubernetes(states):
    """
    Return kubernetes state module
    """
    return states.kubernetes


@pytest.fixture(params=[False, True])
def testmode(request):
    return request.param


@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_namespace_present(kubernetes, namespace, testmode, kubernetes_exe):
    """
    Test kubernetes.namespace_present creates a namespace
    """
    ret = kubernetes.namespace_present(name=namespace, wait=True, test=testmode)

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    if not testmode:
        assert ret.changes["namespace"]["new"]["metadata"]["name"] == namespace
        # Verify namespace is created
        namespace_state = kubernetes_exe.show_namespace(name=namespace)
        assert namespace_state["metadata"]["name"] == namespace
        assert namespace_state["status"]["phase"] == "Active"
    else:
        # FIXME: Changes should be reported in test mode
        assert not ret.changes
        assert "The namespace is going to be created" in ret.comment

        # Verify namespace is not created in test mode
        namespace_state = kubernetes_exe.show_namespace(name=namespace)
        assert namespace_state is None


def test_namespace_present_idempotency(kubernetes, namespace):
    """
    Test kubernetes.namespace_present is idempotent
    """
    ret = kubernetes.namespace_present(name=namespace)

    assert ret.result is True
    assert not ret.changes
    assert "already exists" in ret.comment


@pytest.fixture
def namespace_template(state_tree):
    sls = "k8s/namespace-template"
    contents = dedent(
        """
        apiVersion: v1
        kind: Namespace
        metadata:
            name: {{ name }}
            labels: {{ labels | json }}
        """
    ).strip()

    with pytest.helpers.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        yield f"salt://{sls}.yml.jinja"


@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_namespace_present_template_context(
    kubernetes, namespace, namespace_template, kubernetes_exe
):
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
    assert ret.changes["namespace"]["new"]["metadata"]["name"] == namespace
    # Verify namespace is created
    namespace_state = kubernetes_exe.show_namespace(name=namespace)
    assert namespace_state["metadata"]["name"] == namespace


def test_namespace_absent(kubernetes, namespace, testmode, kubernetes_exe):
    """
    Test kubernetes.namespace_absent deletes a namespace
    """
    ret = kubernetes.namespace_absent(name=namespace, wait=True, test=testmode)

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    if not testmode:
        assert ret.changes["kubernetes.namespace"]["new"] == "absent"

        # Verify namespace is deleted
        namespace_state = kubernetes_exe.show_namespace(name=namespace)
        assert namespace_state is None
    else:
        # FIXME: Changes should be reported in test mode
        assert not ret.changes
        assert "The namespace is going to be deleted" in ret.comment

        # Verify namespace still exists in test mode
        namespace_state = kubernetes_exe.show_namespace(name=namespace)
        assert namespace_state is not None
        assert namespace_state["metadata"]["name"] == namespace


@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_namespace_absent_idempotency(kubernetes, namespace):
    """
    Test kubernetes.namespace_absent is idempotent
    """

    # Test deletion of non-existent namespace
    ret = kubernetes.namespace_absent(name=namespace)
    assert ret.result is True
    assert "does not exist" in ret.comment
    assert not ret.changes


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
          labels: {{ labels | json }}
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
def pod_spec():
    return {
        "containers": [
            {
                "name": "nginx",
                "image": "nginx:latest",
                "ports": [{"containerPort": 80}],
            }
        ]
    }


@pytest.mark.parametrize("pod", [False], indirect=True)
def test_pod_present(kubernetes, pod, testmode, kubernetes_exe):
    """
    Test kubernetes.pod_present creates a pod
    """
    ret = kubernetes.pod_present(
        name=pod["name"],
        namespace=pod["namespace"],
        spec=pod["spec"],
        wait=True,
        test=testmode,
    )
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    if not testmode:
        assert ret.changes["spec"]["containers"][0]["name"] == "nginx"
        # Verify pod is created
        pod_state = kubernetes_exe.show_pod(name=pod["name"], namespace=pod["namespace"])
        assert pod_state["metadata"]["name"] == pod["name"]
        assert pod_state["spec"]["containers"][0]["name"] == "nginx"
    else:
        # FIXME: Changes should be reported in test mode
        assert not ret.changes
        assert "The pod is going to be created" in ret.comment

        pod_state = kubernetes_exe.show_pod(name=pod["name"], namespace=pod["namespace"])
        assert pod_state is None

    # Comment out idempotent test for now
    # TODO: The state module needs fixed to handle proper present functionality


# def test_pod_present_idempotency(kubernetes, pod, pod_spec):
#     """
#     Test kubernetes.pod_present is idempotent
#     """
#     ret = kubernetes.pod_present(
#         name=pod["name"],
#         namespace=pod["namespace"],
#         spec=pod_spec,
#         wait=True,
#     )

#     assert ret.result is True
#     assert "already exists" in ret.comment
#     assert not ret.changes


@pytest.mark.parametrize("pod", [False], indirect=True)
def test_pod_present_template_context(kubernetes, kubernetes_exe, pod, pod_template):
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
    # Verify actual pod state matches what we expect
    pod_state = kubernetes_exe.show_pod(name=pod["name"], namespace=pod["namespace"])
    assert ret.result is True
    assert pod_state["metadata"]["name"] == pod["name"]
    assert pod_state["metadata"]["namespace"] == pod["namespace"]
    assert pod_state["metadata"]["labels"] == {"app": "test"}
    assert pod_state["spec"]["containers"][0]["image"] == "nginx:latest"
    assert pod_state["spec"]["containers"][0]["name"] == pod["name"]


def test_pod_absent(kubernetes, pod, testmode, kubernetes_exe):
    """
    Test kubernetes.pod_absent deletes a pod
    """
    ret = kubernetes.pod_absent(
        name=pod["name"],
        namespace=pod["namespace"],
        wait=True,
        test=testmode,
    )

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    if not testmode:
        assert ret.changes["kubernetes.pod"]["new"] == "absent"
        pod_state = kubernetes_exe.show_pod(name=pod["name"], namespace=pod["namespace"])
        assert pod_state is None
    else:
        # FIXME: Changes should be reported in test mode
        assert not ret.changes
        assert "The pod is going to be deleted" in ret.comment
        # Verify pod still exists in test mode
        pod_state = kubernetes_exe.show_pod(name=pod["name"], namespace=pod["namespace"])
        assert pod_state is not None
        assert pod_state["metadata"]["name"] == pod["name"]


@pytest.mark.parametrize("pod", [False], indirect=True)
def test_pod_absent_idempotency(kubernetes, pod):
    """
    Test kubernetes.pod_absent is idempotent
    """
    # Test deletion of non-existent pod
    ret = kubernetes.pod_absent(name=pod["name"], namespace=pod["namespace"])
    assert ret.result is True
    assert "does not exist" in ret.comment
    assert not ret.changes


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
          labels: {{ labels | json }}
        spec:
          replicas: {{ replicas }}
          selector:
            matchLabels:
              app: {{ app_label }}
          template:
            metadata:
              labels: {{ labels | json }}
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
def deployment_spec():
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


@pytest.mark.parametrize("deployment", [False], indirect=True)
def test_deployment_present(kubernetes, deployment, testmode, kubernetes_exe):
    """
    Test kubernetes.deployment_present creates a deployment
    """
    ret = kubernetes.deployment_present(
        name=deployment["name"],
        namespace=deployment["namespace"],
        spec=deployment["spec"],
        wait=True,
        test=testmode,
    )

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    if not testmode:
        assert ret.changes["spec"]["replicas"] == 2
        deployment_state = kubernetes_exe.show_deployment(
            name=deployment["name"], namespace=deployment["namespace"]
        )
        assert deployment_state["metadata"]["name"] == deployment["name"]
        assert deployment_state["spec"]["replicas"] == 2
    else:
        # FIXME: Changes should be reported in test mode
        assert not ret.changes
        deployment_state = kubernetes_exe.show_deployment(
            name=deployment["name"], namespace=deployment["namespace"]
        )
        assert deployment_state is None

    # Comment out idempotent test for now
    # TODO: The state module needs fixed to handle proper present functionality


# def test_deployment_present_idempotency(kubernetes, deployment):
#     """
#     Test kubernetes.deployment_present is idempotent
#     """
#     ret = kubernetes.deployment_present(
#         name=deployment["name"],
#         namespace=deployment["namespace"],
#         spec=deployment["spec"],
#         wait=True,
#     )
#     assert ret.result is True
#     assert "already exists" in ret.comment
#     assert not ret.changes


def test_deployment_present_replace(kubernetes, deployment, kubernetes_exe):
    """
    Test kubernetes.deployment_present replaces a deployment
    """
    deployment["spec"]["replicas"] = 3

    ret = kubernetes.deployment_present(
        name=deployment["name"],
        namespace=deployment["namespace"],
        spec=deployment["spec"],
        wait=True,
    )

    assert ret.result is True
    assert ret.changes["spec"]["replicas"] == 3

    # Verify actual deployment state matches what we expect
    deployment_state = kubernetes_exe.show_deployment(
        name=deployment["name"], namespace=deployment["namespace"]
    )
    assert deployment_state["metadata"]["name"] == deployment["name"]
    assert deployment_state["spec"]["replicas"] == 3


@pytest.mark.parametrize("deployment", [False], indirect=True)
def test_deployment_present_template_context(
    kubernetes, deployment, deployment_template, kubernetes_exe
):
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

    # Verify actual deployment state matches what we expect
    deployment_state = kubernetes_exe.show_deployment(
        name=deployment["name"], namespace=deployment["namespace"]
    )
    assert deployment_state["metadata"]["name"] == deployment["name"]
    assert deployment_state["spec"]["replicas"] == 2
    assert deployment_state["metadata"]["labels"]["app"] == "test"
    assert deployment_state["spec"]["selector"]["match_labels"]["app"] == "test"
    assert deployment_state["spec"]["template"]["spec"]["containers"][0]["image"] == "nginx:latest"


def test_deployment_absent(kubernetes, deployment, testmode, kubernetes_exe):
    """
    Test kubernetes.deployment_absent deletes a deployment
    """
    ret = kubernetes.deployment_absent(
        name=deployment["name"],
        namespace=deployment["namespace"],
        wait=True,
        test=testmode,
    )

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode

    if not testmode:
        assert ret.changes["kubernetes.deployment"]["new"] == "absent"
        deployment_state = kubernetes_exe.show_deployment(
            name=deployment["name"], namespace=deployment["namespace"]
        )
        assert deployment_state is None
    else:
        # FIXME: Changes should be reported in test mode
        assert not ret.changes
        assert "The deployment is going to be deleted" in ret.comment
        # Verify deployment still exists in test mode
        deployment_state = kubernetes_exe.show_deployment(
            name=deployment["name"], namespace=deployment["namespace"]
        )
        assert deployment_state is not None
        assert deployment_state["metadata"]["name"] == deployment["name"]


@pytest.mark.parametrize("deployment", [False], indirect=True)
def test_deployment_absent_idempotency(kubernetes, deployment):
    """
    Test kubernetes.deployment_absent is idempotent
    """

    # Test deletion of non-existent deployment
    ret = kubernetes.deployment_absent(name=deployment["name"], namespace=deployment["namespace"])
    assert ret.result is True
    assert "does not exist" in ret.comment
    assert not ret.changes


@pytest.fixture
def secret_data():
    return {"key": "value"}, "Opaque"


@pytest.mark.parametrize("secret", [False], indirect=True)
def test_secret_present(kubernetes, secret, testmode, kubernetes_exe):
    """
    Test kubernetes.secret_present creates a secret
    """
    ret = kubernetes.secret_present(
        name=secret["name"],
        namespace=secret["namespace"],
        data=secret["data"],
        wait=True,
        test=testmode,
    )

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    if not testmode:
        assert ret.result is True
        # Verify secret is created
        secret_state = kubernetes_exe.show_secret(
            name=secret["name"], namespace=secret["namespace"], decode=True
        )
        assert secret_state["metadata"]["name"] == secret["name"]
        assert secret_state["data"]["key"] == "value"
    else:
        # FIXME: Changes should be reported in test mode
        assert not ret.changes
        assert "The secret is going to be created" in ret.comment
        # Verify secret is not created in test mode
        secret_state = kubernetes_exe.show_secret(
            name=secret["name"], namespace=secret["namespace"], decoode=True
        )
        assert secret_state is None

    # Comment out idempotent test for now
    # TODO: The state module needs fixed to handle proper present functionality


# def test_secret_present_idempotency(kubernetes, secret):
#     """
#     Test kubernetes.secret_present is idempotent
#     """
#     ret = kubernetes.secret_present(
#         name=secret["name"],
#         namespace=secret["namespace"],
#         data=secret["data"],
#         wait=True,
#     )
#     assert ret.result is True
#     assert "already exists" in ret.comment
#     assert not ret.changes


def test_secret_present_replace(kubernetes, secret, kubernetes_exe):
    """
    Test kubernetes.secret_present replaces a secret
    """
    secret["data"]["key"] = "new_value"

    ret = kubernetes.secret_present(
        name=secret["name"],
        namespace=secret["namespace"],
        data=secret["data"],
        wait=True,
    )

    assert ret.result is True

    # Verify actual secret state matches what we expect
    secret_state = kubernetes_exe.show_secret(
        name=secret["name"], namespace=secret["namespace"], decode=True
    )
    assert secret_state["metadata"]["name"] == secret["name"]
    assert secret_state["data"]["key"] == "new_value"


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
          labels: {{ labels | json }}
        type: {{ secret_type }}
        data: {{ secret_data | json }}
        """
    ).strip()

    with pytest.helpers.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        yield f"salt://{sls}.yml.jinja"


@pytest.mark.parametrize("secret", [False], indirect=True)
def test_secret_present_template_context(kubernetes, secret, secret_template, kubernetes_exe):
    """
    Test kubernetes.secret_present with template_context
    """
    template_context = {
        "name": secret["name"],
        "namespace": secret["namespace"],
        "secret_type": "Opaque",
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

    # Verify actual secret state matches what we expect
    secret_state = kubernetes_exe.show_secret(
        name=secret["name"], namespace=secret["namespace"], decode=True
    )
    assert secret_state["metadata"]["name"] == secret["name"]
    assert secret_state["metadata"]["namespace"] == secret["namespace"]
    assert secret_state["type"] == "Opaque"
    assert secret_state["data"]["key"] == "value"


@pytest.mark.parametrize("secret", [False], indirect=True)
def test_service_account_token_secret_present(kubernetes, secret, kubernetes_exe):
    """
    Test creating a service account token secret via state
    """
    ret = kubernetes.secret_present(
        name=secret["name"],
        namespace=secret["namespace"],
        data={},  # Empty data - kubernetes will populate
        secret_type="kubernetes.io/service-account-token",
        metadata={"annotations": {"kubernetes.io/service-account.name": "default"}},
        wait=True,
    )

    assert ret.result is True

    # Verify actual secret state matches what we expect
    secret_state = kubernetes_exe.show_secret(
        name=secret["name"], namespace=secret["namespace"], decode=True
    )
    assert secret_state["metadata"]["name"] == secret["name"]
    # Passing data={} should cause kubernetes to generate and populate the secret
    assert secret_state["data"]["ca.crt"] is not None
    assert secret_state["type"] == "kubernetes.io/service-account-token"


def test_secret_absent(kubernetes, secret, testmode, kubernetes_exe):
    """
    Test kubernetes.secret_absent deletes a secret
    """
    ret = kubernetes.secret_absent(
        name=secret["name"],
        namespace=secret["namespace"],
        wait=True,
        test=testmode,
    )

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    if not testmode:
        assert ret.result is True
        assert ret.changes["kubernetes.secret"]["new"] == "absent"
        # Verify secret is deleted
        secret_state = kubernetes_exe.show_secret(
            name=secret["name"], namespace=secret["namespace"], decode=True
        )
        assert secret_state is None
    else:
        # FIXME: Changes should be reported in test mode
        assert not ret.changes
        assert "The secret is going to be deleted" in ret.comment
        # Verify secret still exists in test mode
        secret_state = kubernetes_exe.show_secret(
            name=secret["name"], namespace=secret["namespace"], decode=True
        )
        assert secret_state is not None
        assert secret_state["metadata"]["name"] == secret["name"]
        assert secret_state["data"]["key"] == "value"


@pytest.mark.parametrize("secret", [False], indirect=True)
def test_secret_absent_idempotency(kubernetes, secret):
    """
    Test kubernetes.secret_absent is idempotent
    """

    # Test deletion of non-existent secret
    ret = kubernetes.secret_absent(name=secret["name"], namespace=secret["namespace"])
    assert ret.result is True
    assert "does not exist" in ret.comment
    assert not ret.changes


@pytest.fixture
def service_spec():
    return {
        "ports": [
            {"name": "http", "port": 80, "target_port": 8080},
            {"name": "https", "port": 443, "target_port": 8443},
        ],
        "selector": {"app": "test"},
        "type": "ClusterIP",
    }


@pytest.mark.parametrize("service", [False], indirect=True)
def test_service_present(kubernetes, service, testmode, kubernetes_exe):
    """
    Test kubernetes.service_present creates a service
    """
    ret = kubernetes.service_present(
        name=service["name"],
        namespace=service["namespace"],
        spec=service["spec"],
        wait=True,
        test=testmode,
    )

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    if not testmode:
        assert ret.result is True
        # Verify service is created
        service_state = kubernetes_exe.show_service(
            name=service["name"], namespace=service["namespace"]
        )
        assert service_state["metadata"]["name"] == service["name"]
        assert service_state["spec"]["ports"][0]["name"] == "http"
        assert service_state["spec"]["ports"][0]["port"] == 80
        assert service_state["spec"]["ports"][0]["target_port"] == 8080
        assert service_state["spec"]["ports"][1]["name"] == "https"
        assert service_state["spec"]["ports"][1]["port"] == 443
        assert service_state["spec"]["ports"][1]["target_port"] == 8443
        assert service_state["spec"]["selector"]["app"] == "test"
        assert service_state["spec"]["type"] == "ClusterIP"
    else:
        # FIXME: Changes should be reported in test mode
        assert not ret.changes
        assert "The service is going to be created" in ret.comment

        # Verify service is not created in test mode
        service_state = kubernetes_exe.show_service(
            name=service["name"], namespace=service["namespace"]
        )
        assert service_state is None

    # Comment out idempotent test for now
    # TODO: The state module needs fixed to handle proper present functionality


# def test_service_present_idempotency(kubernetes, service):
#     """
#     Test kubernetes.service_present is idempotent
#     """
#     ret = kubernetes.service_present(
#         name=service["name"],
#         namespace=service["namespace"],
#         spec=service["spec"],
#         wait=True,
#     )
#     assert ret.result is True
#     assert "already exists" in ret.comment
#     assert not ret.changes


def test_service_present_replace(kubernetes, service, kubernetes_exe):
    """
    Test kubernetes.service_present replaces a service
    """
    service["spec"]["type"] = "NodePort"
    del service["spec"]["selector"]

    ret = kubernetes.service_present(
        name=service["name"],
        namespace=service["namespace"],
        spec=service["spec"],
        wait=True,
    )

    assert ret.result is True
    # Verify actual service state matches what we expect
    service_state = kubernetes_exe.show_service(
        name=service["name"], namespace=service["namespace"]
    )
    assert service_state["spec"]["ports"][0]["name"] == "http"
    assert service_state["spec"]["ports"][0]["port"] == 80
    assert service_state["spec"]["ports"][0]["target_port"] == 8080
    assert service_state["spec"]["ports"][1]["name"] == "https"
    assert service_state["spec"]["ports"][1]["port"] == 443
    assert service_state["spec"]["ports"][1]["target_port"] == 8443
    assert service_state["spec"]["type"] == "NodePort"


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
          labels: {{ labels | json }}
        spec:
          type: {{ type }}
          ports: {{ ports | json }}
          selector: {{ selector | json }}
        """
    ).strip()

    with pytest.helpers.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        yield f"salt://{sls}.yml.jinja"


@pytest.mark.parametrize("service", [False], indirect=True)
def test_service_present_template_context(kubernetes, service, service_template, kubernetes_exe):
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
    # Verify actual service state matches what we expect
    service_state = kubernetes_exe.show_service(
        name=service["name"], namespace=service["namespace"]
    )
    assert service_state["metadata"]["name"] == service["name"]
    assert service_state["metadata"]["namespace"] == service["namespace"]
    assert service_state["metadata"]["labels"]["app"] == "test"
    assert service_state["spec"]["ports"][0]["name"] == "http"
    assert service_state["spec"]["ports"][0]["port"] == 80
    assert service_state["spec"]["ports"][0]["target_port"] == 8080
    assert service_state["spec"]["ports"][1]["name"] == "https"
    assert service_state["spec"]["ports"][1]["port"] == 443
    assert service_state["spec"]["ports"][1]["target_port"] == 8443
    assert service_state["spec"]["selector"]["app"] == "test"
    assert service_state["spec"]["type"] == "ClusterIP"


def test_service_absent(kubernetes, service, testmode, kubernetes_exe):
    """
    Test kubernetes.service_absent deletes a service
    """
    ret = kubernetes.service_absent(
        name=service["name"],
        namespace=service["namespace"],
        wait=True,
        test=testmode,
    )

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    if not testmode:
        assert ret.result is True
        assert ret.changes["kubernetes.service"]["new"] == "absent"
        # Verify service is deleted
        service_state = kubernetes_exe.show_service(
            name=service["name"], namespace=service["namespace"]
        )
        assert service_state is None
    else:
        # FIXME: Changes should be reported in test mode
        assert not ret.changes
        assert "The service is going to be deleted" in ret.comment
        # Verify service still exists in test mode
        service_state = kubernetes_exe.show_service(
            name=service["name"], namespace=service["namespace"]
        )
        assert service_state is not None


@pytest.mark.parametrize("service", [False], indirect=True)
def test_service_absent_idempotency(kubernetes, service):
    """
    Test kubernetes.service_absent is idempotent
    """

    # Test deletion of non-existent service
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


@pytest.mark.parametrize("configmap", [False], indirect=True)
def test_configmap_present(kubernetes, configmap, testmode, kubernetes_exe):
    """
    Test kubernetes.configmap_present creates a configmap
    """
    ret = kubernetes.configmap_present(
        name=configmap["name"],
        namespace=configmap["namespace"],
        data=configmap["data"],
        wait=True,
        test=testmode,
    )

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    if not testmode:
        assert ret.result is True
        # Verify configmap is created
        configmap_state = kubernetes_exe.show_configmap(
            name=configmap["name"], namespace=configmap["namespace"]
        )
        assert configmap_state["metadata"]["name"] == configmap["name"]
        assert configmap_state["metadata"]["namespace"] == configmap["namespace"]
        assert configmap_state["data"]["config.yaml"] == "foo: bar\nkey: value"
        assert configmap_state["data"]["app.properties"] == "app.name=myapp\napp.port=8080"
    else:
        # FIXME: Changes should be reported in test mode
        assert not ret.changes
        assert "The configmap is going to be created" in ret.comment
        # Verify configmap is not created in test mode
        configmap_state = kubernetes_exe.show_configmap(
            name=configmap["name"], namespace=configmap["namespace"]
        )
        assert configmap_state is None

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


def test_configmap_replace(kubernetes, configmap, kubernetes_exe):
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
    # Verify actual configmap state matches what we expect
    configmap_state = kubernetes_exe.show_configmap(
        name=configmap["name"], namespace=configmap["namespace"]
    )
    assert configmap_state["metadata"]["name"] == configmap["name"]
    assert configmap_state["metadata"]["namespace"] == configmap["namespace"]
    assert configmap_state["data"]["config.yaml"] == "foo: newbar\nkey: newvalue"
    assert configmap_state["data"]["app.properties"] == "app.name=newapp\napp.port=9090"


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
          labels: {{ labels | json }}
        data: {{ data | json }}
        """
    ).strip()

    with pytest.helpers.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        yield f"salt://{sls}.yml.jinja"


@pytest.mark.parametrize("configmap", [False], indirect=True)
def test_configmap_present_template_context(
    kubernetes, configmap, configmap_template, kubernetes_exe
):
    """
    Test kubernetes.configmap_present with template_context
    """
    template_context = {
        "name": configmap["name"],
        "namespace": configmap["namespace"],
        "labels": {"app": "test"},
        "data": {
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
    # Verify actual configmap state matches what we expect
    configmap_state = kubernetes_exe.show_configmap(
        name=configmap["name"], namespace=configmap["namespace"]
    )
    assert configmap_state["metadata"]["name"] == configmap["name"]
    assert configmap_state["metadata"]["namespace"] == configmap["namespace"]
    assert (
        configmap_state["data"]["data"]
        == "{'app.properties': 'app.name=myapp\\napp.port=8080', 'config.yaml': 'foo: bar\\nkey: value'}"
    )


def test_configmap_absent(kubernetes, configmap, testmode, kubernetes_exe):
    """
    Test kubernetes.configmap_absent deletes a configmap
    """
    ret = kubernetes.configmap_absent(
        name=configmap["name"],
        namespace=configmap["namespace"],
        wait=True,
        test=testmode,
    )

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    if not testmode:
        assert ret.result is True
        assert ret.changes["kubernetes.configmap"]["new"] == "absent"

        # Verify configmap is deleted
        configmap_state = kubernetes_exe.show_configmap(
            name=configmap["name"], namespace=configmap["namespace"]
        )
        assert configmap_state is None
    else:
        # FIXME: Changes should be reported in test mode
        assert not ret.changes
        assert "The configmap is going to be deleted" in ret.comment

        # Verify configmap still exists in test mode
        configmap_state = kubernetes_exe.show_configmap(
            name=configmap["name"], namespace=configmap["namespace"]
        )
        assert configmap_state is not None


@pytest.mark.parametrize("configmap", [False], indirect=True)
def test_configmap_absent_idempotency(kubernetes, configmap):
    """
    Test kubernetes.configmap_absent is idempotent
    """

    # Test deletion of non-existent configmap
    ret = kubernetes.configmap_absent(
        name=configmap["name"],
        namespace=configmap["namespace"],
    )
    assert ret.result is True
    assert "does not exist" in ret.comment
    assert not ret.changes


@pytest.fixture(params=[True])
def node_label(kubernetes, node_name, kubernetes_exe, request):
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
        kubernetes_exe.node_remove_label(node_name, test_label)
        assert test_label not in kubernetes_exe.node_labels(node_name)


@pytest.mark.parametrize("labeled_node", [False], indirect=True)
def test_node_label_present(kubernetes, labeled_node, testmode, kubernetes_exe):
    """
    Test kubernetes.node_label_present creates a label
    """
    label_name = "salt-test.label/test"
    label_value = "value1"

    ret = kubernetes.node_label_present(
        name=label_name,
        node=labeled_node["name"],
        value=label_value,
        test=testmode,
    )

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    if not testmode:
        assert ret.result is True
        assert ret.changes[f"{labeled_node['name']}.{label_name}"]["new"]
        # Verify label is created
        node_label_state = kubernetes_exe.node_labels(labeled_node["name"])
        assert node_label_state[label_name] == label_value
    else:
        # FIXME: Changes should be reported in test mode
        assert not ret.changes
        assert "The label is going to be set" in ret.comment
        # Verify label is not created in test mode
        node_label_state = kubernetes_exe.node_labels(labeled_node["name"])
        assert label_name not in node_label_state


def test_node_label_present_idempotency(kubernetes, labeled_node):
    """
    Test kubernetes.node_label_present is idempotent
    """
    label_name = next(iter(labeled_node["labels"]))
    ret = kubernetes.node_label_present(
        name=label_name,
        node=labeled_node["name"],
        value=labeled_node["labels"][label_name],
    )

    assert ret.result is True
    assert "The label is already set and has the specified value" in ret.comment
    assert not ret.changes


def test_node_label_present_replace(kubernetes, labeled_node, testmode, kubernetes_exe):
    """
    Test kubernetes.node_label_present replaces a label
    """
    label_name = next(iter(labeled_node["labels"]))
    new_value = "value2"

    ret = kubernetes.node_label_present(
        name=label_name,
        node=labeled_node["name"],
        value=new_value,
        test=testmode,
    )
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    if not testmode:
        assert ret.result is True
        assert ret.changes[f"{labeled_node['name']}.{label_name}"]["new"][label_name] == new_value
        # Verify label is replaced
        node_label_state = kubernetes_exe.node_labels(labeled_node["name"])
        assert node_label_state[label_name] == new_value
    else:
        # FIXME: Changes should be reported in test mode
        assert not ret.changes
        assert "The label is going to be updated" in ret.comment
        # Verify label is not replaced in test mode
        node_label_state = kubernetes_exe.node_labels(labeled_node["name"])
        assert node_label_state[label_name] == labeled_node["labels"][label_name]


def test_node_label_absent(kubernetes, labeled_node, testmode, kubernetes_exe):
    """
    Test kubernetes.node_label_absent deletes a label
    """
    label_name = next(iter(labeled_node["labels"]))
    ret = kubernetes.node_label_absent(name=label_name, node=labeled_node["name"], test=testmode)
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    if not testmode:
        assert ret.result is True
        assert ret.changes["kubernetes.node_label"]["new"] == "absent"
        # Verify label is deleted
        node_label_state = kubernetes_exe.node_labels(labeled_node["name"])
        assert label_name not in node_label_state
        assert labeled_node["labels"][label_name] not in node_label_state
    else:
        # FIXME: Changes should be reported in test mode
        assert not ret.changes
        assert "The label is going to be deleted" in ret.comment
        # Verify label still exists in test mode
        node_label_state = kubernetes_exe.node_labels(labeled_node["name"])
        assert node_label_state[label_name] == labeled_node["labels"][label_name]


def test_node_label_absent_idempotency(kubernetes, node_name):
    """
    Test kubernetes.node_label_absent is idempotent
    """
    # Test removal of non-existent label
    ret = kubernetes.node_label_absent(
        name="test.fooo.label",
        node=node_name,
    )
    assert ret.result is True
    assert "does not exist" in ret.comment
    assert not ret.changes


@pytest.mark.parametrize(
    "labeled_node",
    [{"salt-test.label/label1": "value1", "salt-test.label/label2": "value2"}],
    indirect=True,
)
def test_node_label_folder_absent(kubernetes, labeled_node, kubernetes_exe):
    """
    Test kubernetes.node_label_folder_absent deletes all labels with prefix
    """
    test_prefix = next(iter(labeled_node["labels"])).split("/")[0]

    # Ensure the labels are present as expected
    node_labels_pre = kubernetes_exe.node_labels(labeled_node["name"])
    assert set(node_labels_pre).intersection(labeled_node["labels"]) == set(labeled_node["labels"])

    # Remove labels
    ret = kubernetes.node_label_folder_absent(
        name=test_prefix,
        node=labeled_node["name"],
    )
    assert ret.result is True
    assert ret.changes
    assert any(
        test_prefix in prev for prev in ret.changes["kubernetes.node_label_folder_absent"]["old"]
    )
    assert not any(
        test_prefix in post for post in ret.changes["kubernetes.node_label_folder_absent"]["new"]
    )

    # Verify all matching labels were removed
    node_label_state = kubernetes_exe.node_labels(labeled_node["name"])
    assert not set(node_label_state).intersection(labeled_node["labels"])

    # Try to remove again (should be no-op)
    ret = kubernetes.node_label_folder_absent(
        name=test_prefix,
        node=labeled_node["name"],
    )
    assert ret.result is True
    assert "The label folder does not exist" in ret.comment
    assert not ret.changes
