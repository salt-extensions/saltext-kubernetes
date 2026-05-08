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
    assert ret.changes["new"]["metadata"]["name"] == namespace
    if not testmode:
        # Verify namespace is created
        namespace_state = kubernetes_exe.show_namespace(name=namespace)
        assert namespace_state["metadata"]["name"] == namespace
        assert namespace_state["status"]["phase"] == "Active"
    else:
        assert ret.changes == {"old": {}, "new": {"metadata": {"name": namespace}}}
        assert "The namespace is going to be created" in ret.comment

        # Verify namespace is not created in test mode
        namespace_state = kubernetes_exe.show_namespace(name=namespace)
        assert namespace_state is None


def test_namespace_present_idempotency(kubernetes, namespace, testmode):
    """
    Test kubernetes.namespace_present is idempotent
    """
    ret = kubernetes.namespace_present(name=namespace, test=testmode)

    assert ret.result is True
    assert not ret.changes
    assert "already exists" in ret.comment


@pytest.fixture
def namespace_template(state_tree):
    sls = "k8s/namespace-template"
    contents = dedent("""
        apiVersion: v1
        kind: Namespace
        metadata:
            name: {{ name }}
            labels: {{ labels | json }}
        """).strip()

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
    assert ret.changes["new"]["metadata"]["name"] == namespace
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
        assert ret.changes["new"] == "absent"

        # Verify namespace is deleted
        namespace_state = kubernetes_exe.show_namespace(name=namespace)
        assert namespace_state is None
    else:
        assert ret.changes == {"old": "present", "new": "absent"}
        assert "The namespace is going to be deleted" in ret.comment

        # Verify namespace still exists in test mode
        namespace_state = kubernetes_exe.show_namespace(name=namespace)
        assert namespace_state is not None
        assert namespace_state["metadata"]["name"] == namespace


@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_namespace_absent_idempotency(kubernetes, namespace, testmode):
    """
    Test kubernetes.namespace_absent is idempotent
    """

    # Test deletion of non-existent namespace
    ret = kubernetes.namespace_absent(name=namespace, test=testmode)
    assert ret.result is True
    assert "does not exist" in ret.comment
    assert not ret.changes


@pytest.fixture
def pod_template(state_tree):
    sls = "k8s/pod-template"
    contents = dedent("""
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
        """).strip()

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
        assert ret.changes["new"]["spec"]["containers"][0]["name"] == "nginx"
        # Verify pod is created
        pod_state = kubernetes_exe.show_pod(name=pod["name"], namespace=pod["namespace"])
        assert pod_state["metadata"]["name"] == pod["name"]
        assert pod_state["spec"]["containers"][0]["name"] == "nginx"
    else:
        assert "The pod is going to be created" in ret.comment

        pod_state = kubernetes_exe.show_pod(name=pod["name"], namespace=pod["namespace"])
        assert pod_state is None


def test_pod_present_idempotency(kubernetes, pod, testmode):
    """
    Test kubernetes.pod_present is idempotent (pods are immutable)
    """
    ret = kubernetes.pod_present(
        name=pod["name"],
        namespace=pod["namespace"],
        spec=pod["spec"],
        wait=True,
        test=testmode,
    )

    assert ret.result is True
    assert "already exists" in ret.comment
    assert not ret.changes


@pytest.mark.parametrize("pod", [False], indirect=True)
def test_pod_present_template_context(kubernetes, pod, pod_template, kubernetes_exe):
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
        assert ret.changes["new"] == "absent"
        pod_state = kubernetes_exe.show_pod(name=pod["name"], namespace=pod["namespace"])
        assert pod_state is None
    else:
        assert ret.changes == {"old": "present", "new": "absent"}
        assert "The pod is going to be deleted" in ret.comment
        # Verify pod still exists in test mode
        pod_state = kubernetes_exe.show_pod(name=pod["name"], namespace=pod["namespace"])
        assert pod_state is not None
        assert pod_state["metadata"]["name"] == pod["name"]


@pytest.mark.parametrize("pod", [False], indirect=True)
def test_pod_absent_idempotency(kubernetes, pod, testmode):
    """
    Test kubernetes.pod_absent is idempotent
    """
    # Test deletion of non-existent pod
    ret = kubernetes.pod_absent(
        name=pod["name"], namespace=pod["namespace"], wait=True, test=testmode
    )
    assert ret.result is True
    assert "does not exist" in ret.comment
    assert not ret.changes


@pytest.fixture
def deployment_template(state_tree):
    sls = "k8s/deployment-template"
    contents = dedent("""
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
        """).strip()

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
        assert ret.changes["new"]["spec"]["replicas"] == 2
        deployment_state = kubernetes_exe.show_deployment(
            name=deployment["name"], namespace=deployment["namespace"]
        )
        assert deployment_state["metadata"]["name"] == deployment["name"]
        assert deployment_state["spec"]["replicas"] == 2
    else:
        assert ret.changes["new"]["spec"]["replicas"] == 2
        deployment_state = kubernetes_exe.show_deployment(
            name=deployment["name"], namespace=deployment["namespace"]
        )
        assert deployment_state is None


def test_deployment_present_idempotency(kubernetes, deployment, testmode):
    """
    Test kubernetes.deployment_present is idempotent
    """
    ret = kubernetes.deployment_present(
        name=deployment["name"],
        namespace=deployment["namespace"],
        spec=deployment["spec"],
        wait=True,
        test=testmode,
    )
    assert ret.result is True
    assert "The deployment is already in the desired state" in ret.comment
    assert not ret.changes


def test_deployment_present_patch(kubernetes, deployment, kubernetes_exe, testmode):
    """
    Test kubernetes.deployment_present patches a deployment
    """
    deployment["spec"]["replicas"] = 4

    ret = kubernetes.deployment_present(
        name=deployment["name"],
        namespace=deployment["namespace"],
        spec=deployment["spec"],
        wait=True,
        test=testmode,
    )
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    assert ret.changes["new"]["spec"]["replicas"] == 4

    # Verify actual deployment state matches what we expect
    deployment_state = kubernetes_exe.show_deployment(
        name=deployment["name"], namespace=deployment["namespace"]
    )
    assert deployment_state["metadata"]["name"] == deployment["name"]
    assert (deployment_state["spec"]["replicas"] == 4) is not testmode


def test_deployment_present_patch_source(
    kubernetes, deployment, deployment_template, kubernetes_exe
):
    """
    Test kubernetes.deployment_present patches a deployment using source/template
    """
    template_context = {
        "name": deployment["name"],
        "namespace": deployment["namespace"],
        "replicas": 4,
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
    assert ret.changes["new"]["spec"]["replicas"] == 4

    # Verify actual deployment state matches what we expect
    deployment_state = kubernetes_exe.show_deployment(
        name=deployment["name"], namespace=deployment["namespace"]
    )
    assert deployment_state["metadata"]["name"] == deployment["name"]
    assert deployment_state["spec"]["replicas"] == 4


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
    assert deployment_state["spec"]["selector"]["matchLabels"]["app"] == "test"
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
        assert ret.changes["new"] == "absent"
        deployment_state = kubernetes_exe.show_deployment(
            name=deployment["name"], namespace=deployment["namespace"]
        )
        assert deployment_state is None
    else:
        assert ret.changes["new"] == "absent"
        assert "The deployment is going to be deleted" in ret.comment
        # Verify deployment still exists in test mode
        deployment_state = kubernetes_exe.show_deployment(
            name=deployment["name"], namespace=deployment["namespace"]
        )
        assert deployment_state is not None
        assert deployment_state["metadata"]["name"] == deployment["name"]


@pytest.mark.parametrize("deployment", [False], indirect=True)
def test_deployment_absent_idempotency(kubernetes, deployment, testmode):
    """
    Test kubernetes.deployment_absent is idempotent
    """

    # Test deletion of non-existent deployment
    ret = kubernetes.deployment_absent(
        name=deployment["name"], namespace=deployment["namespace"], wait=True, test=testmode
    )
    assert ret.result is True
    assert "does not exist" in ret.comment
    assert not ret.changes


@pytest.fixture
def statefulset_template(state_tree):
    sls = "k8s/statefulset-template"
    contents = dedent("""
        apiVersion: apps/v1
        kind: StatefulSet
        metadata:
          name: {{ name }}
          namespace: {{ namespace }}
          labels: {{ labels | json }}
        spec:
          serviceName: {{ service_name }}
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
        """).strip()

    with pytest.helpers.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        yield f"salt://{sls}.yml.jinja"


@pytest.mark.parametrize("statefulset", [False], indirect=True)
def test_statefulset_present(kubernetes, statefulset, testmode, kubernetes_exe):
    """
    Test kubernetes.statefulset_present creates a statefulset
    """
    ret = kubernetes.statefulset_present(
        name=statefulset["name"],
        namespace=statefulset["namespace"],
        spec=statefulset["spec"],
        wait=True,
        test=testmode,
    )

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    if not testmode:
        assert ret.changes["new"]["spec"]["replicas"] == statefulset["spec"]["replicas"]
        statefulset_state = kubernetes_exe.show_statefulset(
            name=statefulset["name"], namespace=statefulset["namespace"]
        )
        assert statefulset_state["metadata"]["name"] == statefulset["name"]
        assert statefulset_state["spec"]["replicas"] == statefulset["spec"]["replicas"]
    else:
        assert ret.changes["new"]["spec"]["replicas"] == statefulset["spec"]["replicas"]
        statefulset_state = kubernetes_exe.show_statefulset(
            name=statefulset["name"], namespace=statefulset["namespace"]
        )
        assert statefulset_state is None


def test_statefulset_present_idempotency(kubernetes, statefulset, testmode):
    """
    Test kubernetes.statefulset_present is idempotent
    """
    ret = kubernetes.statefulset_present(
        name=statefulset["name"],
        namespace=statefulset["namespace"],
        spec=statefulset["spec"],
        wait=True,
        test=testmode,
    )
    assert ret.result is True
    assert "The statefulset is already in the desired state" in ret.comment
    assert not ret.changes


def test_statefulset_present_patch(kubernetes, statefulset, kubernetes_exe, testmode):
    """
    Test kubernetes.statefulset_present patches a statefulset
    """
    statefulset["spec"]["replicas"] = 2

    ret = kubernetes.statefulset_present(
        name=statefulset["name"],
        namespace=statefulset["namespace"],
        spec=statefulset["spec"],
        wait=True,
        test=testmode,
    )
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    assert ret.changes["new"]["spec"]["replicas"] == 2

    statefulset_state = kubernetes_exe.show_statefulset(
        name=statefulset["name"], namespace=statefulset["namespace"]
    )
    assert statefulset_state["metadata"]["name"] == statefulset["name"]
    assert (statefulset_state["spec"]["replicas"] == 2) is not testmode


def test_statefulset_present_patch_source(
    kubernetes, statefulset, statefulset_template, kubernetes_exe
):
    """
    Test kubernetes.statefulset_present patches a statefulset using source/template
    """
    template_context = {
        "name": statefulset["name"],
        "namespace": statefulset["namespace"],
        "service_name": statefulset["spec"]["serviceName"],
        "replicas": statefulset["spec"]["replicas"],
        "app_label": "nginx",
        "image": "nginx:1.27",
        "labels": {"app": "nginx"},
    }

    ret = kubernetes.statefulset_present(
        name=statefulset["name"],
        namespace=statefulset["namespace"],
        source=statefulset_template,
        template="jinja",
        template_context=template_context,
        wait=True,
    )
    assert ret.result is True

    statefulset_state = kubernetes_exe.show_statefulset(
        name=statefulset["name"], namespace=statefulset["namespace"]
    )
    assert statefulset_state["metadata"]["name"] == statefulset["name"]
    assert statefulset_state["spec"]["template"]["spec"]["containers"][0]["image"] == "nginx:1.27"


@pytest.mark.parametrize("statefulset", [False], indirect=True)
def test_statefulset_present_template_context(
    kubernetes, statefulset, statefulset_template, kubernetes_exe
):
    """
    Test kubernetes.statefulset_present with template_context
    """
    template_context = {
        "name": statefulset["name"],
        "namespace": statefulset["namespace"],
        "service_name": statefulset["spec"]["serviceName"],
        "replicas": statefulset["spec"]["replicas"],
        "app_label": "test",
        "image": "nginx:latest",
        "labels": {"app": "test"},
    }

    ret = kubernetes.statefulset_present(
        name=statefulset["name"],
        namespace=statefulset["namespace"],
        source=statefulset_template,
        template="jinja",
        template_context=template_context,
        wait=True,
    )
    assert ret.result is True

    statefulset_state = kubernetes_exe.show_statefulset(
        name=statefulset["name"], namespace=statefulset["namespace"]
    )
    assert statefulset_state["metadata"]["name"] == statefulset["name"]
    assert statefulset_state["spec"]["replicas"] == statefulset["spec"]["replicas"]
    assert statefulset_state["metadata"]["labels"]["app"] == "test"
    assert statefulset_state["spec"]["selector"]["matchLabels"]["app"] == "test"
    assert statefulset_state["spec"]["template"]["spec"]["containers"][0]["image"] == "nginx:latest"


def test_statefulset_absent(kubernetes, statefulset, testmode, kubernetes_exe):
    """
    Test kubernetes.statefulset_absent deletes a statefulset
    """
    ret = kubernetes.statefulset_absent(
        name=statefulset["name"],
        namespace=statefulset["namespace"],
        wait=True,
        test=testmode,
    )

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode

    if not testmode:
        assert ret.changes["new"] == "absent"
        statefulset_state = kubernetes_exe.show_statefulset(
            name=statefulset["name"], namespace=statefulset["namespace"]
        )
        assert statefulset_state is None
    else:
        assert ret.changes["new"] == "absent"
        assert "The statefulset is going to be deleted" in ret.comment
        statefulset_state = kubernetes_exe.show_statefulset(
            name=statefulset["name"], namespace=statefulset["namespace"]
        )
        assert statefulset_state is not None
        assert statefulset_state["metadata"]["name"] == statefulset["name"]


@pytest.mark.parametrize("statefulset", [False], indirect=True)
def test_statefulset_absent_idempotency(kubernetes, statefulset, testmode):
    """
    Test kubernetes.statefulset_absent is idempotent
    """
    ret = kubernetes.statefulset_absent(
        name=statefulset["name"], namespace=statefulset["namespace"], wait=True, test=testmode
    )
    assert ret.result is True
    assert "does not exist" in ret.comment
    assert not ret.changes


@pytest.fixture
def replicaset_template(state_tree):
    sls = "k8s/replicaset-template"
    contents = dedent("""
        apiVersion: apps/v1
        kind: ReplicaSet
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
        """).strip()

    with pytest.helpers.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        yield f"salt://{sls}.yml.jinja"


@pytest.mark.parametrize("replicaset", [False], indirect=True)
def test_replicaset_present(kubernetes, replicaset, testmode, kubernetes_exe):
    """
    Test kubernetes.replicaset_present creates a replicaset
    """
    ret = kubernetes.replicaset_present(
        name=replicaset["name"],
        namespace=replicaset["namespace"],
        spec=replicaset["spec"],
        wait=True,
        test=testmode,
    )

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    if not testmode:
        assert ret.changes["new"]["spec"]["replicas"] == replicaset["spec"]["replicas"]
        replicaset_state = kubernetes_exe.show_replicaset(
            name=replicaset["name"], namespace=replicaset["namespace"]
        )
        assert replicaset_state["metadata"]["name"] == replicaset["name"]
        assert replicaset_state["spec"]["replicas"] == replicaset["spec"]["replicas"]
    else:
        assert ret.changes["new"]["spec"]["replicas"] == replicaset["spec"]["replicas"]
        replicaset_state = kubernetes_exe.show_replicaset(
            name=replicaset["name"], namespace=replicaset["namespace"]
        )
        assert replicaset_state is None


def test_replicaset_present_idempotency(kubernetes, replicaset, testmode):
    """
    Test kubernetes.replicaset_present is idempotent
    """
    ret = kubernetes.replicaset_present(
        name=replicaset["name"],
        namespace=replicaset["namespace"],
        spec=replicaset["spec"],
        wait=True,
        test=testmode,
    )
    assert ret.result is True
    assert "The replicaset is already in the desired state" in ret.comment
    assert not ret.changes


def test_replicaset_present_patch(kubernetes, replicaset, kubernetes_exe, testmode):
    """
    Test kubernetes.replicaset_present patches a replicaset
    """
    replicaset["spec"]["replicas"] = 2

    ret = kubernetes.replicaset_present(
        name=replicaset["name"],
        namespace=replicaset["namespace"],
        spec=replicaset["spec"],
        wait=True,
        test=testmode,
    )
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    assert ret.changes["new"]["spec"]["replicas"] == 2

    replicaset_state = kubernetes_exe.show_replicaset(
        name=replicaset["name"], namespace=replicaset["namespace"]
    )
    assert replicaset_state["metadata"]["name"] == replicaset["name"]
    assert (replicaset_state["spec"]["replicas"] == 2) is not testmode


def test_replicaset_present_patch_source(
    kubernetes, replicaset, replicaset_template, kubernetes_exe
):
    """
    Test kubernetes.replicaset_present patches a replicaset using source/template
    """
    template_context = {
        "name": replicaset["name"],
        "namespace": replicaset["namespace"],
        "replicas": replicaset["spec"]["replicas"],
        "app_label": "nginx",
        "image": "nginx:1.27",
        "labels": {"app": "nginx"},
    }

    ret = kubernetes.replicaset_present(
        name=replicaset["name"],
        namespace=replicaset["namespace"],
        source=replicaset_template,
        template="jinja",
        template_context=template_context,
        wait=True,
    )
    assert ret.result is True

    replicaset_state = kubernetes_exe.show_replicaset(
        name=replicaset["name"], namespace=replicaset["namespace"]
    )
    assert replicaset_state["metadata"]["name"] == replicaset["name"]
    assert replicaset_state["spec"]["template"]["spec"]["containers"][0]["image"] == "nginx:1.27"


@pytest.mark.parametrize("replicaset", [False], indirect=True)
def test_replicaset_present_template_context(
    kubernetes, replicaset, replicaset_template, kubernetes_exe
):
    """
    Test kubernetes.replicaset_present with template_context
    """
    template_context = {
        "name": replicaset["name"],
        "namespace": replicaset["namespace"],
        "replicas": replicaset["spec"]["replicas"],
        "app_label": "test",
        "image": "nginx:latest",
        "labels": {"app": "test"},
    }

    ret = kubernetes.replicaset_present(
        name=replicaset["name"],
        namespace=replicaset["namespace"],
        source=replicaset_template,
        template="jinja",
        template_context=template_context,
        wait=True,
    )
    assert ret.result is True

    replicaset_state = kubernetes_exe.show_replicaset(
        name=replicaset["name"], namespace=replicaset["namespace"]
    )
    assert replicaset_state["metadata"]["name"] == replicaset["name"]
    assert replicaset_state["spec"]["replicas"] == replicaset["spec"]["replicas"]
    assert replicaset_state["metadata"]["labels"]["app"] == "test"
    assert replicaset_state["spec"]["selector"]["matchLabels"]["app"] == "test"
    assert replicaset_state["spec"]["template"]["spec"]["containers"][0]["image"] == "nginx:latest"


def test_replicaset_absent(kubernetes, replicaset, testmode, kubernetes_exe):
    """
    Test kubernetes.replicaset_absent deletes a replicaset
    """
    ret = kubernetes.replicaset_absent(
        name=replicaset["name"],
        namespace=replicaset["namespace"],
        wait=True,
        test=testmode,
    )

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode

    if not testmode:
        assert ret.changes["new"] == "absent"
        replicaset_state = kubernetes_exe.show_replicaset(
            name=replicaset["name"], namespace=replicaset["namespace"]
        )
        assert replicaset_state is None
    else:
        assert ret.changes["new"] == "absent"
        assert "The replicaset is going to be deleted" in ret.comment
        replicaset_state = kubernetes_exe.show_replicaset(
            name=replicaset["name"], namespace=replicaset["namespace"]
        )
        assert replicaset_state is not None
        assert replicaset_state["metadata"]["name"] == replicaset["name"]


@pytest.mark.parametrize("replicaset", [False], indirect=True)
def test_replicaset_absent_idempotency(kubernetes, replicaset, testmode):
    """
    Test kubernetes.replicaset_absent is idempotent
    """
    ret = kubernetes.replicaset_absent(
        name=replicaset["name"], namespace=replicaset["namespace"], wait=True, test=testmode
    )
    assert ret.result is True
    assert "does not exist" in ret.comment
    assert not ret.changes


@pytest.fixture
def daemonset_template(state_tree):
    sls = "k8s/daemonset-template"
    contents = dedent("""
        apiVersion: apps/v1
        kind: DaemonSet
        metadata:
          name: {{ name }}
          namespace: {{ namespace }}
          labels: {{ labels | json }}
        spec:
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
        """).strip()

    with pytest.helpers.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        yield f"salt://{sls}.yml.jinja"


@pytest.mark.parametrize("daemonset", [False], indirect=True)
def test_daemonset_present(kubernetes, daemonset, testmode, kubernetes_exe):
    """
    Test kubernetes.daemonset_present creates a daemonset
    """
    ret = kubernetes.daemonset_present(
        name=daemonset["name"],
        namespace=daemonset["namespace"],
        spec=daemonset["spec"],
        wait=True,
        test=testmode,
    )

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    if not testmode:
        daemonset_state = kubernetes_exe.show_daemonset(
            name=daemonset["name"], namespace=daemonset["namespace"]
        )
        assert daemonset_state["metadata"]["name"] == daemonset["name"]
    else:
        daemonset_state = kubernetes_exe.show_daemonset(
            name=daemonset["name"], namespace=daemonset["namespace"]
        )
        assert daemonset_state is None


def test_daemonset_present_idempotency(kubernetes, daemonset, testmode):
    """
    Test kubernetes.daemonset_present is idempotent
    """
    ret = kubernetes.daemonset_present(
        name=daemonset["name"],
        namespace=daemonset["namespace"],
        spec=daemonset["spec"],
        wait=True,
        test=testmode,
    )
    assert ret.result is True
    assert "The daemonset is already in the desired state" in ret.comment
    assert not ret.changes


def test_daemonset_present_patch(kubernetes, daemonset, kubernetes_exe, testmode):
    """
    Test kubernetes.daemonset_present patches a daemonset
    """
    daemonset["spec"]["template"]["spec"]["containers"][0]["image"] = "nginx:1.27"

    ret = kubernetes.daemonset_present(
        name=daemonset["name"],
        namespace=daemonset["namespace"],
        spec=daemonset["spec"],
        wait=True,
        test=testmode,
    )
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode

    daemonset_state = kubernetes_exe.show_daemonset(
        name=daemonset["name"], namespace=daemonset["namespace"]
    )
    assert daemonset_state["metadata"]["name"] == daemonset["name"]
    assert (
        daemonset_state["spec"]["template"]["spec"]["containers"][0]["image"] == "nginx:1.27"
    ) is not testmode


def test_daemonset_present_patch_source(kubernetes, daemonset, daemonset_template, kubernetes_exe):
    """
    Test kubernetes.daemonset_present patches a daemonset using source/template
    """
    template_context = {
        "name": daemonset["name"],
        "namespace": daemonset["namespace"],
        "app_label": "nginx",
        "image": "nginx:1.27",
        "labels": {"app": "nginx"},
    }

    ret = kubernetes.daemonset_present(
        name=daemonset["name"],
        namespace=daemonset["namespace"],
        source=daemonset_template,
        template="jinja",
        template_context=template_context,
        wait=True,
    )
    assert ret.result is True

    daemonset_state = kubernetes_exe.show_daemonset(
        name=daemonset["name"], namespace=daemonset["namespace"]
    )
    assert daemonset_state["metadata"]["name"] == daemonset["name"]
    assert daemonset_state["spec"]["template"]["spec"]["containers"][0]["image"] == "nginx:1.27"


@pytest.mark.parametrize("daemonset", [False], indirect=True)
def test_daemonset_present_template_context(
    kubernetes, daemonset, daemonset_template, kubernetes_exe
):
    """
    Test kubernetes.daemonset_present with template_context
    """
    template_context = {
        "name": daemonset["name"],
        "namespace": daemonset["namespace"],
        "app_label": "test",
        "image": "nginx:latest",
        "labels": {"app": "test"},
    }

    ret = kubernetes.daemonset_present(
        name=daemonset["name"],
        namespace=daemonset["namespace"],
        source=daemonset_template,
        template="jinja",
        template_context=template_context,
        wait=True,
    )
    assert ret.result is True

    daemonset_state = kubernetes_exe.show_daemonset(
        name=daemonset["name"], namespace=daemonset["namespace"]
    )
    assert daemonset_state["metadata"]["name"] == daemonset["name"]
    assert daemonset_state["metadata"]["labels"]["app"] == "test"
    assert daemonset_state["spec"]["selector"]["matchLabels"]["app"] == "test"
    assert daemonset_state["spec"]["template"]["spec"]["containers"][0]["image"] == "nginx:latest"


def test_daemonset_absent(kubernetes, daemonset, testmode, kubernetes_exe):
    """
    Test kubernetes.daemonset_absent deletes a daemonset
    """
    ret = kubernetes.daemonset_absent(
        name=daemonset["name"],
        namespace=daemonset["namespace"],
        wait=True,
        test=testmode,
    )

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode

    if not testmode:
        assert ret.changes["new"] == "absent"
        daemonset_state = kubernetes_exe.show_daemonset(
            name=daemonset["name"], namespace=daemonset["namespace"]
        )
        assert daemonset_state is None
    else:
        assert ret.changes["new"] == "absent"
        assert "The daemonset is going to be deleted" in ret.comment
        daemonset_state = kubernetes_exe.show_daemonset(
            name=daemonset["name"], namespace=daemonset["namespace"]
        )
        assert daemonset_state is not None
        assert daemonset_state["metadata"]["name"] == daemonset["name"]


@pytest.mark.parametrize("daemonset", [False], indirect=True)
def test_daemonset_absent_idempotency(kubernetes, daemonset, testmode):
    """
    Test kubernetes.daemonset_absent is idempotent
    """
    ret = kubernetes.daemonset_absent(
        name=daemonset["name"], namespace=daemonset["namespace"], wait=True, test=testmode
    )
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
        # Verify secret is created
        secret_state = kubernetes_exe.show_secret(
            name=secret["name"], namespace=secret["namespace"], decode=True
        )
        assert secret_state["metadata"]["name"] == secret["name"]
        assert secret_state["data"]["key"] == "value"
    else:
        assert "The secret is going to be created" in ret.comment
        # Verify secret is not created in test mode
        secret_state = kubernetes_exe.show_secret(
            name=secret["name"], namespace=secret["namespace"], decode=True
        )
        assert secret_state is None


def test_secret_present_idempotency(kubernetes, secret, testmode):
    """
    Test kubernetes.secret_present is idempotent
    """
    ret = kubernetes.secret_present(
        name=secret["name"],
        namespace=secret["namespace"],
        data=secret["data"],
        wait=True,
        test=testmode,
    )
    assert ret.result is True
    assert "already in the desired state" in ret.comment
    assert not ret.changes


def test_secret_present_patch(kubernetes, secret, kubernetes_exe, testmode):
    """
    Test kubernetes.secret_present patches a secret
    """
    secret["data"]["key"] = "new_value"

    ret = kubernetes.secret_present(
        name=secret["name"],
        namespace=secret["namespace"],
        data=secret["data"],
        wait=True,
        test=testmode,
    )

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode

    # Verify actual secret state matches what we expect
    secret_state = kubernetes_exe.show_secret(
        name=secret["name"], namespace=secret["namespace"], decode=True
    )
    assert secret_state["metadata"]["name"] == secret["name"]
    assert (secret_state["data"]["key"] == "new_value") is not testmode


@pytest.fixture
def secret_template(state_tree):
    sls = "k8s/secret-template"
    contents = dedent("""
        apiVersion: v1
        kind: Secret
        metadata:
          name: {{ name }}
          namespace: {{ namespace }}
          labels: {{ labels | json }}
        type: {{ secret_type }}
        data: {{ secret_data | json }}
        """).strip()

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
def test_service_account_token_secret_present(kubernetes, secret, kubernetes_exe, testmode):
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
        test=testmode,
    )

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode

    # Verify actual secret state matches what we expect
    secret_state = kubernetes_exe.show_secret(
        name=secret["name"], namespace=secret["namespace"], decode=True
    )
    if not testmode:
        assert secret_state["metadata"]["name"] == secret["name"]
        # Passing data={} should cause kubernetes to generate and populate the secret
        assert secret_state["data"]["ca.crt"] is not None
        assert secret_state["type"] == "kubernetes.io/service-account-token"
    else:
        # Secret should not be created in test mode
        assert secret_state is None


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
        assert ret.changes["new"] == "absent"
        # Verify secret is deleted
        secret_state = kubernetes_exe.show_secret(
            name=secret["name"], namespace=secret["namespace"], decode=True
        )
        assert secret_state is None
    else:
        assert ret.changes == {"old": "present", "new": "absent"}
        assert "The secret is going to be deleted" in ret.comment
        # Verify secret still exists in test mode
        secret_state = kubernetes_exe.show_secret(
            name=secret["name"], namespace=secret["namespace"], decode=True
        )
        assert secret_state is not None
        assert secret_state["metadata"]["name"] == secret["name"]
        assert secret_state["data"]["key"] == "value"


@pytest.mark.parametrize("secret", [False], indirect=True)
def test_secret_absent_idempotency(kubernetes, secret, testmode):
    """
    Test kubernetes.secret_absent is idempotent
    """

    # Test deletion of non-existent secret
    ret = kubernetes.secret_absent(
        name=secret["name"], namespace=secret["namespace"], wait=True, test=testmode
    )
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
        # Verify service is created
        service_state = kubernetes_exe.show_service(
            name=service["name"], namespace=service["namespace"]
        )
        assert service_state["metadata"]["name"] == service["name"]
        assert service_state["spec"]["ports"][0]["name"] == "http"
        assert service_state["spec"]["ports"][0]["port"] == 80
        assert service_state["spec"]["ports"][0]["targetPort"] == 8080
        assert service_state["spec"]["ports"][1]["name"] == "https"
        assert service_state["spec"]["ports"][1]["port"] == 443
        assert service_state["spec"]["ports"][1]["targetPort"] == 8443
        assert service_state["spec"]["selector"]["app"] == "test"
        assert service_state["spec"]["type"] == "ClusterIP"
    else:
        assert "The service is going to be created" in ret.comment

        # Verify service is not created in test mode
        service_state = kubernetes_exe.show_service(
            name=service["name"], namespace=service["namespace"]
        )
        assert service_state is None


def test_service_present_idempotency(kubernetes, service, testmode):
    """
    Test kubernetes.service_present is idempotent
    """
    ret = kubernetes.service_present(
        name=service["name"],
        namespace=service["namespace"],
        spec=service["spec"],
        wait=True,
        test=testmode,
    )
    assert ret.result is True
    assert "already in the desired state" in ret.comment
    assert not ret.changes


def test_service_present_patch(kubernetes, service, kubernetes_exe, testmode):
    """
    Test kubernetes.service_present patches a service
    """
    service["spec"]["type"] = "NodePort"
    del service["spec"]["selector"]

    ret = kubernetes.service_present(
        name=service["name"],
        namespace=service["namespace"],
        spec=service["spec"],
        wait=True,
        test=testmode,
    )

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    # Verify actual service state matches what we expect
    service_state = kubernetes_exe.show_service(
        name=service["name"], namespace=service["namespace"]
    )
    assert service_state["spec"]["ports"][0]["name"] == "http"
    assert service_state["spec"]["ports"][0]["port"] == 80
    assert service_state["spec"]["ports"][0]["targetPort"] == 8080
    assert service_state["spec"]["ports"][1]["name"] == "https"
    assert service_state["spec"]["ports"][1]["port"] == 443
    assert service_state["spec"]["ports"][1]["targetPort"] == 8443
    assert (service_state["spec"]["type"] == "NodePort") is not testmode


@pytest.fixture
def service_template(state_tree):
    sls = "k8s/service-template"
    contents = dedent("""
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
        """).strip()

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
    assert service_state["spec"]["ports"][0]["targetPort"] == 8080
    assert service_state["spec"]["ports"][1]["name"] == "https"
    assert service_state["spec"]["ports"][1]["port"] == 443
    assert service_state["spec"]["ports"][1]["targetPort"] == 8443
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
        assert ret.changes["new"] == "absent"
        # Verify service is deleted
        service_state = kubernetes_exe.show_service(
            name=service["name"], namespace=service["namespace"]
        )
        assert service_state is None
    else:
        assert ret.changes == {"old": "present", "new": "absent"}
        assert "The service is going to be deleted" in ret.comment
        # Verify service still exists in test mode
        service_state = kubernetes_exe.show_service(
            name=service["name"], namespace=service["namespace"]
        )
        assert service_state is not None


@pytest.mark.parametrize("service", [False], indirect=True)
def test_service_absent_idempotency(kubernetes, service, testmode):
    """
    Test kubernetes.service_absent is idempotent
    """

    # Test deletion of non-existent service
    ret = kubernetes.service_absent(
        name=service["name"], namespace=service["namespace"], wait=True, test=testmode
    )
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
        # Verify configmap is created
        configmap_state = kubernetes_exe.show_configmap(
            name=configmap["name"], namespace=configmap["namespace"]
        )
        assert configmap_state["metadata"]["name"] == configmap["name"]
        assert configmap_state["metadata"]["namespace"] == configmap["namespace"]
        assert configmap_state["data"]["config.yaml"] == "foo: bar\nkey: value"
        assert configmap_state["data"]["app.properties"] == "app.name=myapp\napp.port=8080"
    else:
        assert "The configmap is going to be created" in ret.comment
        # Verify configmap is not created in test mode
        configmap_state = kubernetes_exe.show_configmap(
            name=configmap["name"], namespace=configmap["namespace"]
        )
        assert configmap_state is None


def test_configmap_present_idempotency(kubernetes, configmap, testmode):
    """
    Test kubernetes.configmap_present is idempotent
    """
    ret = kubernetes.configmap_present(
        name=configmap["name"],
        namespace=configmap["namespace"],
        data=configmap["data"],
        wait=True,
        test=testmode,
    )
    assert ret.result is True
    assert "already in the desired state" in ret.comment
    assert not ret.changes


def test_configmap_patch(kubernetes, configmap, kubernetes_exe, testmode):
    """
    Test kubernetes.configmap_present patches a configmap
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
        test=testmode,
    )

    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    # Verify actual configmap state matches what we expect
    configmap_state = kubernetes_exe.show_configmap(
        name=configmap["name"], namespace=configmap["namespace"]
    )
    assert configmap_state["metadata"]["name"] == configmap["name"]
    assert configmap_state["metadata"]["namespace"] == configmap["namespace"]
    assert (configmap_state["data"]["config.yaml"] == "foo: newbar\nkey: newvalue") is not testmode
    assert (
        configmap_state["data"]["app.properties"] == "app.name=newapp\napp.port=9090"
    ) is not testmode


@pytest.fixture
def configmap_template(state_tree):
    sls = "k8s/configmap-template"
    contents = dedent("""
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: {{ name }}
          namespace: {{ namespace }}
          labels: {{ labels | json }}
        data: {{ data | json }}
        """).strip()

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
    assert configmap_state["data"]["config.yaml"] == "foo: bar\nkey: value"
    assert configmap_state["data"]["app.properties"] == "app.name=myapp\napp.port=8080"


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
        assert ret.changes["new"] == "absent"

        # Verify configmap is deleted
        configmap_state = kubernetes_exe.show_configmap(
            name=configmap["name"], namespace=configmap["namespace"]
        )
        assert configmap_state is None
    else:
        assert ret.changes == {"old": "present", "new": "absent"}
        assert "The configmap is going to be deleted" in ret.comment

        # Verify configmap still exists in test mode
        configmap_state = kubernetes_exe.show_configmap(
            name=configmap["name"], namespace=configmap["namespace"]
        )
        assert configmap_state is not None


@pytest.mark.parametrize("configmap", [False], indirect=True)
def test_configmap_absent_idempotency(kubernetes, configmap, testmode):
    """
    Test kubernetes.configmap_absent is idempotent
    """

    # Test deletion of non-existent configmap
    ret = kubernetes.configmap_absent(
        name=configmap["name"],
        namespace=configmap["namespace"],
        wait=True,
        test=testmode,
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
    assert ret.changes["new"][label_name] == label_value
    assert label_name not in ret.changes["old"]
    node_label_state = kubernetes_exe.node_labels(labeled_node["name"])
    if not testmode:
        assert node_label_state[label_name] == label_value
    else:
        assert label_name not in node_label_state
        assert "The label is going to be set" in ret.comment


def test_node_label_present_idempotency(kubernetes, labeled_node, testmode):
    """
    Test kubernetes.node_label_present is idempotent
    """
    label_name = next(iter(labeled_node["labels"]))
    ret = kubernetes.node_label_present(
        name=label_name,
        node=labeled_node["name"],
        value=labeled_node["labels"][label_name],
        test=testmode,
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
    assert ret.changes["new"][label_name] == new_value
    assert ret.changes["old"][label_name] == labeled_node["labels"][label_name]
    node_label_state = kubernetes_exe.node_labels(labeled_node["name"])
    if not testmode:
        assert node_label_state[label_name] == new_value
    else:
        assert node_label_state[label_name] == labeled_node["labels"][label_name]
        assert "The label is going to be updated" in ret.comment


def test_node_label_absent(kubernetes, labeled_node, testmode, kubernetes_exe):
    """
    Test kubernetes.node_label_absent deletes a label
    """
    label_name = next(iter(labeled_node["labels"]))
    ret = kubernetes.node_label_absent(name=label_name, node=labeled_node["name"], test=testmode)
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    if not testmode:
        assert ret.changes["new"] == "absent"
        # Verify label is deleted
        node_label_state = kubernetes_exe.node_labels(labeled_node["name"])
        assert label_name not in node_label_state
        assert labeled_node["labels"][label_name] not in node_label_state
    else:
        assert ret.changes == {"old": "present", "new": "absent"}
        assert "The label is going to be deleted" in ret.comment
        # Verify label still exists in test mode
        node_label_state = kubernetes_exe.node_labels(labeled_node["name"])
        assert node_label_state[label_name] == labeled_node["labels"][label_name]


def test_node_label_absent_idempotency(kubernetes, node_name, testmode):
    """
    Test kubernetes.node_label_absent is idempotent
    """
    # Test removal of non-existent label
    ret = kubernetes.node_label_absent(
        name="test.fooo.label",
        node=node_name,
        test=testmode,
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
    assert any(test_prefix in prev for prev in ret.changes["old"])
    assert not any(test_prefix in post for post in ret.changes["new"])

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
