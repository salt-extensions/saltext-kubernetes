import logging
from textwrap import dedent

import pytest
from saltfactories.utils import random_string

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms"),
]


@pytest.fixture(scope="module")
def state_tree(master):
    return master.state_tree.base


@pytest.fixture()
def namespace_template(state_tree):
    """
    Create the template file to be used by the state
    """
    sls = "k8s/namespace-template"
    contents = dedent(
        """
        apiVersion: v1
        kind: Namespace
        metadata:
          name: {{ name }}
        """
    ).strip()

    with state_tree.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        yield f"salt://{sls}.yml.jinja"


@pytest.fixture()
def namespace_present_state(state_tree):
    """
    Create the .sls state file that uses the template
    """
    contents = dedent(
        """
        {%- set source = salt['pillar.get']('source') %}
        {%- set name = salt['pillar.get']('name') %}

        create_namespace:
          kubernetes.namespace_present:
            - source: {{ source }}
            - name: {{ name }}
            - template: jinja
            - template_context:
                name: {{ name }}
            - wait: True
        """
    ).strip()

    with state_tree.temp_file("namespace_present.sls", contents):
        yield "namespace_present"


@pytest.fixture()
def namespace_absent_state(state_tree):
    """
    Create the .sls state file that uses the template
    """
    contents = dedent(
        """
        {%- set name = salt['pillar.get']('name') %}

        delete_namespace:
          kubernetes.namespace_absent:
            - name: {{ name }}
            - wait: True
        """
    ).strip()

    with state_tree.temp_file("namespace_absent.sls", contents):
        yield "namespace_absent"


@pytest.fixture(params=[True])
def namespace(salt_call_cli, kind_cluster, namespace_template, namespace_present_state, request):
    """
    Fixture to create a namespace for testing
    """
    name = random_string("namespace-", uppercase=False)

    if request.param:
        ret = salt_call_cli.run(
            "state.apply",
            namespace_present_state,
            pillar={
                "name": name,
                "source": namespace_template,
            },
        )
        assert ret.returncode == 0
    try:
        yield {"name": name}
    finally:
        # Clean up
        ret = salt_call_cli.run(
            "kubernetes.delete_namespace",
            name=name,
            wait=True,
        )
        assert ret.returncode == 0


@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_namespace_present(
    kind_cluster, salt_call_cli, namespace, namespace_template, namespace_present_state
):
    """
    Test namespace creation via states
    """
    ret = salt_call_cli.run(
        "state.apply",
        namespace_present_state,
        pillar={
            "name": namespace["name"],
            "source": namespace_template,
        },
    )
    assert ret.returncode == 0

    # Verify namespace exists
    ret = salt_call_cli.run("kubernetes.show_namespace", name=namespace["name"])
    assert ret.returncode == 0
    assert ret.data["metadata"]["name"] == namespace["name"]
    assert ret.data["status"]["phase"] == "Active"


def test_namespace_absent(kind_cluster, salt_call_cli, namespace_absent_state, namespace):
    """
    Test namespace deletion via states
    """

    # Verify namespace exists
    ret = salt_call_cli.run("kubernetes.show_namespace", name=namespace["name"])
    assert ret.returncode == 0
    assert ret.data["metadata"]["name"] == namespace["name"]
    assert ret.data["status"]["phase"] == "Active"

    # Delete the namespace using the state
    ret = salt_call_cli.run(
        "state.apply", namespace_absent_state, pillar={"name": namespace["name"]}
    )
    assert ret.returncode == 0

    # Verify namespace is deleted
    ret = salt_call_cli.run("kubernetes.show_namespace", name=namespace["name"])
    assert ret.returncode == 0
    assert ret.data is None


@pytest.fixture()
def pod_template(state_tree):
    """
    Create the template file to be used by the state
    """
    sls = "k8s/pod-template"
    contents = dedent(
        """
        apiVersion: v1
        kind: Pod
        metadata:
          name: {{ name }}
          namespace: default
        spec:
          containers:
            - name: nginx
              image: nginx:latest
              ports:
                - containerPort: 80
        """
    ).strip()

    with state_tree.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        yield f"salt://{sls}.yml.jinja"


@pytest.fixture()
def pod_present_state(state_tree):
    """
    Create the .sls state file that uses the template
    """
    contents = dedent(
        """
        {%- set source = salt['pillar.get']('source') %}
        {%- set name = salt['pillar.get']('name') %}

        create_pod:
          kubernetes.pod_present:
            - source: {{ source }}
            - name: {{ name }}
            - namespace: default
            - template: jinja
            - template_context:
                name: {{ name }}
            - wait: True
        """
    ).strip()

    with state_tree.temp_file("pod_present.sls", contents):
        yield "pod_present"


@pytest.fixture()
def pod_absent_state(state_tree):
    """
    Create the .sls state file that uses the template
    """
    contents = dedent(
        """
        {%- set name = salt['pillar.get']('name') %}

        delete_pod:
          kubernetes.pod_absent:
            - name: {{ name }}
            - namespace: default
            - wait: True
        """
    ).strip()

    with state_tree.temp_file("pod_absent.sls", contents):
        yield "pod_absent"


@pytest.fixture(params=[True])
def pod(salt_call_cli, kind_cluster, pod_template, pod_present_state, request):
    """
    Fixture to create a pod for testing
    """
    name = random_string("pod-", uppercase=False)
    namespace = "default"
    if request.param:
        ret = salt_call_cli.run(
            "state.apply",
            pod_present_state,
            pillar={
                "name": name,
                "source": pod_template,
            },
        )
        assert ret.returncode == 0

    try:
        yield {
            "name": name,
            "namespace": namespace,
        }
    finally:
        # Clean up
        ret = salt_call_cli.run(
            "kubernetes.delete_pod",
            name=name,
            namespace=namespace,
            wait=True,
        )
        assert ret.returncode == 0


@pytest.mark.parametrize("pod", [False], indirect=True)
def test_pod_present(kind_cluster, salt_call_cli, pod, pod_template, pod_present_state):
    """
    Test pod creation via states
    """
    ret = salt_call_cli.run(
        "state.apply",
        pod_present_state,
        pillar={
            "name": pod["name"],
            "source": pod_template,
        },
    )
    assert ret.returncode == 0

    # Verify pod exists
    ret = salt_call_cli.run("kubernetes.show_pod", name=pod["name"], namespace=pod["namespace"])
    assert ret.returncode == 0
    assert ret.data["metadata"]["name"] == pod["name"]
    assert ret.data["status"]["phase"] == "Running"


def test_pod_absent(kind_cluster, salt_call_cli, pod_absent_state, pod):
    """
    Test pod deletion via states
    """
    # Verify pod exists
    ret = salt_call_cli.run("kubernetes.show_pod", name=pod["name"], namespace="default")
    assert ret.returncode == 0
    assert ret.data["metadata"]["name"] == pod["name"]
    assert ret.data["status"]["phase"] == "Running"

    # Delete the pod using the state
    ret = salt_call_cli.run("state.apply", pod_absent_state, pillar={"name": pod["name"]})
    assert ret.returncode == 0

    # Verify pod is deleted
    ret = salt_call_cli.run("kubernetes.show_pod", name=pod["name"], namespace="default")
    assert ret.returncode == 0
    assert ret.data is None


@pytest.fixture()
def deployment_template(state_tree):
    """
    Create the template file to be used by the state
    """
    sls = "k8s/deployment-template"
    contents = dedent(
        """
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: {{ name }}
          namespace: default
        spec:
          replicas: 2
          selector:
            matchLabels:
              app: test
          template:
            metadata:
              labels:
                app: test
            spec:
              containers:
                - name: nginx
                  image: nginx:latest
                  ports:
                    - containerPort: 80
        """
    ).strip()

    with state_tree.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        yield f"salt://{sls}.yml.jinja"


@pytest.fixture()
def deployment_present_state(state_tree):
    """
    Create the .sls state file that uses the template
    """
    contents = dedent(
        """
        {%- set source = salt['pillar.get']('source') %}
        {%- set name = salt['pillar.get']('name') %}

        create_deployment:
          kubernetes.deployment_present:
            - source: {{ source }}
            - name: {{ name }}
            - namespace: default
            - template: jinja
            - template_context:
                name: {{ name }}
            - wait: True
        """
    ).strip()

    with state_tree.temp_file("deployment_present.sls", contents):
        yield "deployment_present"


@pytest.fixture()
def deployment_absent_state(state_tree):
    """
    Create the .sls state file that uses the template
    """
    contents = dedent(
        """
        {%- set name = salt['pillar.get']('name') %}

        delete_deployment:
          kubernetes.deployment_absent:
            - name: {{ name }}
            - namespace: default
            - wait: True
        """
    ).strip()

    with state_tree.temp_file("deployment_absent.sls", contents):
        yield "deployment_absent"


@pytest.fixture(params=[True])
def deployment(salt_call_cli, kind_cluster, deployment_template, deployment_present_state, request):
    """
    Fixture to create a deployment for testing
    """
    name = random_string("deployment-", uppercase=False)
    namespace = "default"

    if request.param:
        ret = salt_call_cli.run(
            "state.apply",
            deployment_present_state,
            pillar={
                "name": name,
                "source": deployment_template,
            },
        )
        assert ret.returncode == 0

    try:
        yield {"name": name, "namespace": namespace}
    finally:
        # Clean up
        ret = salt_call_cli.run(
            "kubernetes.delete_deployment",
            name=name,
            namespace=namespace,
            wait=True,
        )
        assert ret.returncode == 0


@pytest.mark.parametrize("deployment", [False], indirect=True)
def test_deployment_present(
    kind_cluster, salt_call_cli, deployment, deployment_template, deployment_present_state
):
    """
    Test deployment creation via states
    """
    ret = salt_call_cli.run(
        "state.apply",
        deployment_present_state,
        pillar={
            "name": deployment["name"],
            "source": deployment_template,
        },
    )
    # Verify deployment exists
    ret = salt_call_cli.run(
        "kubernetes.show_deployment", name=deployment["name"], namespace=deployment["namespace"]
    )
    assert ret.returncode == 0
    assert ret.data["metadata"]["name"] == deployment["name"]
    assert ret.data["status"]["replicas"] == 2
    assert ret.data["spec"]["template"]["metadata"]["labels"]["app"] == "test"
    assert ret.data["spec"]["template"]["spec"]["containers"][0]["name"] == "nginx"


def test_deployment_absent(kind_cluster, salt_call_cli, deployment, deployment_absent_state):
    """
    Test deployment deletion via states
    """
    # Verify deployment exists
    ret = salt_call_cli.run(
        "kubernetes.show_deployment", name=deployment["name"], namespace=deployment["namespace"]
    )
    assert ret.returncode == 0
    assert ret.data["metadata"]["name"] == deployment["name"]
    assert ret.data["status"]["replicas"] == 2

    # Delete the deployment using the state
    ret = salt_call_cli.run(
        "state.apply", deployment_absent_state, pillar={"name": deployment["name"]}
    )
    assert ret.returncode == 0

    # Verify deployment is deleted
    ret = salt_call_cli.run(
        "kubernetes.show_deployment", name=deployment["name"], namespace=deployment["namespace"]
    )
    assert ret.returncode == 0
    assert ret.data is None


@pytest.fixture()
def secret_template(state_tree):
    """
    Create the template file to be used by the state
    """
    sls = "k8s/secret-template"
    contents = dedent(
        """
        apiVersion: v1
        kind: Secret
        metadata:
          name: {{ name }}
          namespace: default
        type: Opaque
        data:
          username: YWRtaW4=  # base64 encoded "admin"
          password: cGFzc3dvcmQ=  # base64 encoded "password"
        """
    ).strip()

    with state_tree.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        yield f"salt://{sls}.yml.jinja"


@pytest.fixture()
def secret_present_state(state_tree):
    """
    Create the actual .sls state file that uses the template
    """
    contents = dedent(
        """
        {%- set source = salt['pillar.get']('source') %}
        {%- set name = salt['pillar.get']('name') %}

        create_secret:
          kubernetes.secret_present:
            - source: {{ source }}
            - name: {{ name }}
            - namespace: default
            - template: jinja
            - template_context:
                name: {{ name }}
            - wait: True
        """
    ).strip()

    with state_tree.temp_file("secret_present.sls", contents):
        yield "secret_present"


@pytest.fixture()
def secret_absent_state(state_tree):
    """
    Create the .sls state file that uses the template
    """
    contents = dedent(
        """
        {%- set name = salt['pillar.get']('name') %}

        delete_secret:
          kubernetes.secret_absent:
            - name: {{ name }}
            - namespace: default
            - wait: True
        """
    ).strip()

    with state_tree.temp_file("secret_absent.sls", contents):
        yield "secret_absent"


@pytest.fixture(params=[True])
def secret(salt_call_cli, kind_cluster, secret_template, secret_present_state, request):
    """
    Fixture to create a secret for testing
    """
    name = random_string("secret-", uppercase=False)
    namespace = "default"
    if request.param:
        ret = salt_call_cli.run(
            "state.apply",
            secret_present_state,
            pillar={
                "name": name,
                "source": secret_template,
            },
        )

    try:
        yield {"name": name, "namespace": namespace}
    finally:
        # Clean up
        ret = salt_call_cli.run(
            "kubernetes.delete_secret",
            name=name,
            namespace=namespace,
            wait=True,
        )
        assert ret.returncode == 0


@pytest.mark.parametrize("secret", [False], indirect=True)
def test_secret_present(kind_cluster, salt_call_cli, secret, secret_template, secret_present_state):
    """
    Test secret creation via states
    """
    ret = salt_call_cli.run(
        "state.apply",
        secret_present_state,
        pillar={
            "name": secret["name"],
            "source": secret_template,
        },
    )
    assert ret.returncode == 0

    # Verify secret exists
    ret = salt_call_cli.run(
        "kubernetes.show_secret", name=secret["name"], namespace=secret["namespace"], decode=True
    )
    assert ret.returncode == 0
    assert ret.data["metadata"]["name"] == secret["name"]
    assert ret.data["data"]["username"] == "admin"
    assert ret.data["data"]["password"] == "password"


def test_secret_absent(kind_cluster, salt_call_cli, secret, secret_absent_state):
    """
    Test secret deletion via states
    """
    # Verify secret exists
    ret = salt_call_cli.run(
        "kubernetes.show_secret", name=secret["name"], namespace=secret["namespace"], decode=True
    )
    assert ret.returncode == 0
    assert ret.data["metadata"]["name"] == secret["name"]
    assert ret.data["data"]["username"] == "admin"
    assert ret.data["data"]["password"] == "password"

    # Delete the secret using the state
    ret = salt_call_cli.run("state.apply", secret_absent_state, pillar={"name": secret["name"]})
    assert ret.returncode == 0

    # Verify secret is deleted
    ret = salt_call_cli.run(
        "kubernetes.show_secret", name=secret["name"], namespace=secret["namespace"]
    )
    assert ret.returncode == 0
    assert ret.data is None


@pytest.fixture()
def service_template(state_tree):
    """
    Create the template file to be used by the state
    """
    sls = "k8s/service-template"
    contents = dedent(
        """
        apiVersion: v1
        kind: Service
        metadata:
          name: {{ name }}
          namespace: default
        spec:
          selector:
            app: test
          ports:
            - protocol: TCP
              port: 80
              targetPort: 8080
              name: http
            - protocol: TCP
              port: 443
              targetPort: 8443
              name: https
          type: ClusterIP
        """
    ).strip()

    with state_tree.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        yield f"salt://{sls}.yml.jinja"


@pytest.fixture()
def service_present_state(state_tree):
    """
    Create the .sls state file that uses the template
    """
    contents = dedent(
        """
        {%- set source = salt['pillar.get']('source') %}
        {%- set name = salt['pillar.get']('name') %}

        create_service:
          kubernetes.service_present:
            - source: {{ source }}
            - name: {{ name }}
            - namespace: default
            - template: jinja
            - template_context:
                name: {{ name }}
            - wait: True
        """
    ).strip()

    with state_tree.temp_file("service_present.sls", contents):
        yield "service_present"


@pytest.fixture()
def service_absent_state(state_tree):
    """
    Create the .sls state file that uses the template
    """
    contents = dedent(
        """
        {%- set name = salt['pillar.get']('name') %}

        delete_service:
          kubernetes.service_absent:
            - name: {{ name }}
            - namespace: default
            - wait: True
        """
    ).strip()

    with state_tree.temp_file("service_absent.sls", contents):
        yield "service_absent"


@pytest.fixture(params=[True])
def service(salt_call_cli, kind_cluster, service_template, service_present_state, request):
    """
    Fixture to create a service for testing
    """
    name = random_string("service-", uppercase=False)
    namespace = "default"

    if request.param:
        ret = salt_call_cli.run(
            "state.apply",
            service_present_state,
            pillar={
                "name": name,
                "source": service_template,
            },
        )
        assert ret.returncode == 0

    try:
        yield {"name": name, "namespace": namespace}
    finally:
        # Clean up
        ret = salt_call_cli.run(
            "kubernetes.delete_service",
            name=name,
            namespace=namespace,
            wait=True,
        )
        assert ret.returncode == 0


@pytest.mark.parametrize("service", [False], indirect=True)
def test_service_present(
    kind_cluster, salt_call_cli, service, service_template, service_present_state
):
    """
    Test service creation via states
    """
    ret = salt_call_cli.run(
        "state.apply",
        service_present_state,
        pillar={
            "name": service["name"],
            "source": service_template,
        },
    )
    assert ret.returncode == 0

    # Verify service exists
    ret = salt_call_cli.run(
        "kubernetes.show_service", name=service["name"], namespace=service["namespace"]
    )
    assert ret.returncode == 0
    assert ret.data["metadata"]["name"] == service["name"]
    assert len(ret.data["spec"]["ports"]) == 2
    assert ret.data["spec"]["type"] == "ClusterIP"
    assert ret.data["spec"]["selector"]["app"] == "test"


def test_service_absent(kind_cluster, salt_call_cli, service, service_absent_state):
    """
    Test service deletion via states
    """
    # Verify service exists
    ret = salt_call_cli.run(
        "kubernetes.show_service", name=service["name"], namespace=service["namespace"]
    )
    assert ret.returncode == 0
    assert ret.data["metadata"]["name"] == service["name"]
    assert len(ret.data["spec"]["ports"]) == 2
    assert ret.data["spec"]["type"] == "ClusterIP"

    # Delete the service using the state
    ret = salt_call_cli.run("state.apply", service_absent_state, pillar={"name": service["name"]})
    assert ret.returncode == 0

    # Verify service is deleted
    ret = salt_call_cli.run(
        "kubernetes.show_service", name=service["name"], namespace=service["namespace"]
    )
    assert ret.returncode == 0
    assert ret.data is None


@pytest.fixture()
def configmap_template(state_tree):
    """
    Create the .sls state file that uses the template
    """
    sls = "k8s/configmap-template"
    contents = dedent(
        """
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: {{ name }}
          namespace: default
        data:
          config.yaml: |
            foo: bar
            key: value
          app.properties: |
            app.name=myapp
            app.port=8080
        """
    ).strip()

    with state_tree.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        yield f"salt://{sls}.yml.jinja"


@pytest.fixture()
def configmap_present_state(state_tree):
    """
    Create the .sls state file that uses the template
    """
    contents = dedent(
        """
        {%- set source = salt['pillar.get']('source') %}
        {%- set name = salt['pillar.get']('name') %}

        create_configmap:
          kubernetes.configmap_present:
            - source: {{ source }}
            - name: {{ name }}
            - namespace: default
            - template: jinja
            - template_context:
                name: {{ name }}
            - wait: True
        """
    ).strip()

    with state_tree.temp_file("configmap_present.sls", contents):
        yield "configmap_present"


@pytest.fixture()
def configmap_absent_state(state_tree):
    """
    Create the .sls state file that uses the template
    """
    contents = dedent(
        """
        {%- set name = salt['pillar.get']('name') %}

        delete_configmap:
          kubernetes.configmap_absent:
            - name: {{ name }}
            - namespace: default
            - wait: True
        """
    ).strip()

    with state_tree.temp_file("configmap_absent.sls", contents):
        yield "configmap_absent"


@pytest.fixture(params=[True])
def configmap(salt_call_cli, kind_cluster, configmap_template, configmap_present_state, request):
    """
    Fixture to create a configmap for testing
    """
    name = random_string("configmap-", uppercase=False)
    namespace = "default"

    if request.param:
        ret = salt_call_cli.run(
            "state.apply",
            configmap_present_state,
            pillar={
                "name": name,
                "source": configmap_template,
            },
        )
        assert ret.returncode == 0

    try:
        yield {"name": name, "namespace": namespace}
    finally:
        # Clean up
        ret = salt_call_cli.run(
            "kubernetes.delete_configmap",
            name=name,
            namespace=namespace,
            wait=True,
        )
        assert ret.returncode == 0


@pytest.mark.parametrize("configmap", [False], indirect=True)
def test_configmap_present(
    kind_cluster, salt_call_cli, configmap, configmap_template, configmap_present_state
):
    """
    Test configmap creation via states
    """
    ret = salt_call_cli.run(
        "state.apply",
        configmap_present_state,
        pillar={
            "name": configmap["name"],
            "source": configmap_template,
        },
    )
    assert ret.returncode == 0

    # Verify configmap exists
    ret = salt_call_cli.run(
        "kubernetes.show_configmap", name=configmap["name"], namespace=configmap["namespace"]
    )
    assert ret.returncode == 0
    assert ret.data["metadata"]["name"] == configmap["name"]
    assert (
        ret.data["data"]["data"]
        == "{'config.yaml': 'foo: bar\\nkey: value\\n', 'app.properties': 'app.name=myapp\\napp.port=8080'}"
    )


def test_configmap_absent(kind_cluster, salt_call_cli, configmap, configmap_absent_state):
    """
    Test configmap deletion via states
    """
    # Verify configmap exists
    ret = salt_call_cli.run(
        "kubernetes.show_configmap", name=configmap["name"], namespace=configmap["namespace"]
    )
    assert ret.returncode == 0
    assert ret.data["metadata"]["name"] == configmap["name"]
    assert (
        ret.data["data"]["data"]
        == "{'config.yaml': 'foo: bar\\nkey: value\\n', 'app.properties': 'app.name=myapp\\napp.port=8080'}"
    )

    # Delete the configmap using the state
    ret = salt_call_cli.run(
        "state.apply", configmap_absent_state, pillar={"name": configmap["name"]}
    )
    assert ret.returncode == 0

    # Verify configmap is deleted
    ret = salt_call_cli.run(
        "kubernetes.show_configmap", name=configmap["name"], namespace=configmap["namespace"]
    )
    assert ret.returncode == 0
    assert ret.data is None
