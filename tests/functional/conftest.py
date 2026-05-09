import logging
import shutil

import pytest
from saltfactories.utils import random_string
from saltfactories.utils.functional import Loaders

log = logging.getLogger(__name__)


@pytest.fixture(scope="package")
def minion_id():  # pragma: no cover
    return "func-tests-minion-opts"


@pytest.fixture(scope="module")
def state_tree(tmp_path_factory):  # pragma: no cover
    state_tree_path = tmp_path_factory.mktemp("state-tree-base")
    try:
        yield state_tree_path
    finally:
        shutil.rmtree(str(state_tree_path), ignore_errors=True)


@pytest.fixture(scope="module")
def state_tree_prod(tmp_path_factory):  # pragma: no cover
    state_tree_path = tmp_path_factory.mktemp("state-tree-prod")
    try:
        yield state_tree_path
    finally:
        shutil.rmtree(str(state_tree_path), ignore_errors=True)


@pytest.fixture(scope="module")
def minion_config_defaults(kind_cluster):  # pragma: no cover
    """
    Functional test modules can provide this fixture to tweak the default
    configuration dictionary passed to the minion factory
    """
    return {
        "kubernetes.kubeconfig": str(kind_cluster.kubeconfig_path),
        "kubernetes.context": "kind-salt-test",
    }


@pytest.fixture(scope="module")
def minion_config_overrides():  # pragma: no cover
    """
    Functional test modules can provide this fixture to tweak the configuration
    overrides dictionary passed to the minion factory
    """
    return {}


@pytest.fixture(scope="module")
def minion_opts(
    salt_factories,
    minion_id,
    state_tree,
    state_tree_prod,
    minion_config_defaults,
    minion_config_overrides,
):  # pragma: no cover
    minion_config_overrides.update(
        {
            "file_client": "local",
            "file_roots": {
                "base": [
                    str(state_tree),
                ],
                "prod": [
                    str(state_tree_prod),
                ],
            },
        }
    )
    factory = salt_factories.salt_minion_daemon(
        minion_id,
        defaults=minion_config_defaults or None,
        overrides=minion_config_overrides,
    )
    return factory.config.copy()


@pytest.fixture(scope="module")
def master_config_defaults():  # pragma: no cover
    """
    Functional test modules can provide this fixture to tweak the default
    configuration dictionary passed to the master factory
    """
    return {}


@pytest.fixture(scope="module")
def master_config_overrides():  # pragma: no cover
    """
    Functional test modules can provide this fixture to tweak the configuration
    overrides dictionary passed to the master factory
    """
    return {}


@pytest.fixture(scope="module")
def master_opts(
    salt_factories,
    state_tree,
    state_tree_prod,
    master_config_defaults,
    master_config_overrides,
):  # pragma: no cover
    master_config_overrides.update(
        {
            "file_client": "local",
            "file_roots": {
                "base": [
                    str(state_tree),
                ],
                "prod": [
                    str(state_tree_prod),
                ],
            },
        }
    )
    factory = salt_factories.salt_master_daemon(
        "func-tests-master-opts",
        defaults=master_config_defaults or None,
        overrides=master_config_overrides,
    )
    return factory.config.copy()


@pytest.fixture(scope="module")
def loaders(minion_opts):  # pragma: no cover
    return Loaders(minion_opts, loaded_base_name=f"{__name__}.loaded")


@pytest.fixture(autouse=True)
def reset_loaders_state(loaders):  # pragma: no cover
    try:
        # Run the tests
        yield
    finally:
        # Reset the loaders state
        loaders.reset_state()


@pytest.fixture(scope="module")
def modules(loaders):  # pragma: no cover
    return loaders.modules


@pytest.fixture(scope="module")
def states(loaders):  # pragma: no cover
    return loaders.states


@pytest.fixture
def kubernetes_exe(modules):
    """
    Return kubernetes module
    """
    return modules.kubernetes


@pytest.fixture(params=[True])
def namespace(kubernetes_exe, request):
    """
    Fixture to create a test namespace.
    """
    name = random_string("namespace-", uppercase=False)

    # Only create the namespace if requested
    if request.param:
        res = kubernetes_exe.create_namespace(name)
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name
    elif kubernetes_exe.show_namespace(name) is not None:
        kubernetes_exe.delete_namespace(name, wait=True)
    try:
        yield name
    finally:
        kubernetes_exe.delete_namespace(name, wait=True)


@pytest.fixture(params=[True])
def pod(kubernetes_exe, pod_spec, request):
    """
    Fixture to create a test pod.

    If request.param is True, pod is created before the test.
    If request.param is False, pod is not created.
    """
    name = random_string("pod-", uppercase=False)
    namespace = "default"

    # Only create the pod if requested
    if request.param:
        res = kubernetes_exe.create_pod(
            name=name,
            namespace=namespace,
            metadata={"labels": {"test": "true"}},
            spec=pod_spec,
            wait=True,
        )
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name
    try:
        yield {"name": name, "namespace": namespace, "spec": pod_spec}
    finally:
        kubernetes_exe.delete_pod(name, namespace, wait=True)
        assert kubernetes_exe.show_pod(name=name, namespace=namespace) is None


@pytest.fixture(params=[True])
def deployment(kubernetes_exe, deployment_spec, request):
    """
    Fixture to create a test deployment.

    If request.param is True, deployment is created before the test.
    If request.param is False, deployment is not created.
    """
    name = random_string("deployment-", uppercase=False)
    namespace = "default"

    # Only create the deployment if requested
    if request.param:
        res = kubernetes_exe.create_deployment(
            name=name,
            namespace=namespace,
            metadata={},
            spec=deployment_spec,
            wait=True,
        )
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name
        assert res["spec"]["replicas"] == deployment_spec["replicas"]

    try:
        yield {"name": name, "namespace": namespace, "spec": deployment_spec}
    finally:
        kubernetes_exe.delete_deployment(name=name, namespace=namespace, wait=True)
        assert kubernetes_exe.show_deployment(name=name, namespace=namespace) is None


@pytest.fixture
def statefulset_spec():
    """
    Fixture providing a basic statefulset spec
    """
    return {
        "serviceName": "statefulset-service",
        "replicas": 1,
        "selector": {"matchLabels": {"app": "nginx"}},
        "template": {
            "metadata": {"labels": {"app": "nginx"}},
            "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
        },
    }


@pytest.fixture(params=[True])
def statefulset(kubernetes_exe, statefulset_spec, request):
    """
    Fixture to create a test statefulset.

    If request.param is True, statefulset is created before the test.
    If request.param is False, statefulset is not created.
    """
    name = random_string("statefulset-", uppercase=False)
    namespace = "default"

    if request.param:
        res = kubernetes_exe.create_statefulset(
            name=name,
            namespace=namespace,
            metadata={},
            spec=statefulset_spec,
            wait=True,
        )
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name
        assert res["spec"]["replicas"] == statefulset_spec["replicas"]

    try:
        yield {"name": name, "namespace": namespace, "spec": statefulset_spec}
    finally:
        kubernetes_exe.delete_statefulset(name=name, namespace=namespace, wait=True)
        assert kubernetes_exe.show_statefulset(name=name, namespace=namespace) is None


@pytest.fixture
def replicaset_spec():
    """
    Fixture providing a basic replicaset spec
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
def replicaset(kubernetes_exe, replicaset_spec, request):
    """
    Fixture to create a test replicaset.

    If request.param is True, replicaset is created before the test.
    If request.param is False, replicaset is not created.
    """
    name = random_string("replicaset-", uppercase=False)
    namespace = "default"

    if request.param:
        res = kubernetes_exe.create_replicaset(
            name=name,
            namespace=namespace,
            metadata={},
            spec=replicaset_spec,
            wait=True,
        )
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name
        assert res["spec"]["replicas"] == replicaset_spec["replicas"]

    try:
        yield {"name": name, "namespace": namespace, "spec": replicaset_spec}
    finally:
        kubernetes_exe.delete_replicaset(name=name, namespace=namespace, wait=True)
        assert kubernetes_exe.show_replicaset(name=name, namespace=namespace) is None


@pytest.fixture
def daemonset_spec():
    """
    Fixture providing a basic daemonset spec
    """
    return {
        "selector": {"matchLabels": {"app": "nginx"}},
        "template": {
            "metadata": {"labels": {"app": "nginx"}},
            "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
        },
    }


@pytest.fixture(params=[True])
def daemonset(kubernetes_exe, daemonset_spec, request):
    """
    Fixture to create a test daemonset.

    If request.param is True, daemonset is created before the test.
    If request.param is False, daemonset is not created.
    """
    name = random_string("daemonset-", uppercase=False)
    namespace = "default"

    if request.param:
        res = kubernetes_exe.create_daemonset(
            name=name,
            namespace=namespace,
            metadata={},
            spec=daemonset_spec,
            wait=True,
        )
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name

    try:
        yield {"name": name, "namespace": namespace, "spec": daemonset_spec}
    finally:
        kubernetes_exe.delete_daemonset(name=name, namespace=namespace, wait=True)
        assert kubernetes_exe.show_daemonset(name=name, namespace=namespace) is None


@pytest.fixture
def storageclass_spec():
    """
    Fixture providing a basic storageclass spec
    """
    return {
        "provisioner": "kubernetes.io/no-provisioner",
        "volumeBindingMode": "WaitForFirstConsumer",
    }


@pytest.fixture(params=[True])
def storageclass(kubernetes_exe, storageclass_spec, request):
    """
    Fixture to create a test storageclass.

    If request.param is True, storageclass is created before the test.
    If request.param is False, storageclass is not created.
    """
    name = random_string("storageclass-", uppercase=False)

    if request.param:
        res = kubernetes_exe.create_storageclass(
            name=name,
            metadata={},
            spec=storageclass_spec,
            wait=True,
        )
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name
        assert res["provisioner"] == storageclass_spec["provisioner"]

    try:
        yield {"name": name, "spec": storageclass_spec}
    finally:
        kubernetes_exe.delete_storageclass(name=name, wait=True)
        assert kubernetes_exe.show_storageclass(name=name) is None


@pytest.fixture(params=[True])
def secret(kubernetes_exe, secret_data, request):
    """
    Fixture to create a test secret.

    If request.param is True, secret is created before the test.
    If request.param is False, secret is not created.
    """
    name = random_string("secret-", uppercase=False)
    namespace = "default"
    data, typ = secret_data

    # Only create the secret if requested
    if request.param:
        res = kubernetes_exe.create_secret(
            name, namespace=namespace, data=data, secret_type=typ, wait=True
        )
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name

    try:
        yield {"name": name, "namespace": namespace, "data": data, "type": typ}
    finally:
        kubernetes_exe.delete_secret(name, namespace, wait=True)
        assert kubernetes_exe.show_secret(name=name, namespace=namespace, decode=True) is None


@pytest.fixture(params=[True])
def service(kubernetes_exe, service_spec, request):
    """
    Fixture to create a test service with different types.

    If request.param is True, service is created before the test.
    If request.param is False, service is not created.
    """
    name = random_string("service-", uppercase=False)
    namespace = "default"

    # Only create the service if requested
    if request.param:
        res = kubernetes_exe.create_service(
            name=name,
            namespace=namespace,
            metadata={},
            spec=service_spec,
            wait=True,
        )
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name

    try:
        yield {
            "name": name,
            "namespace": namespace,
            "spec": service_spec,
            "type": service_spec.get("type", "ClusterIP"),
        }
    finally:
        kubernetes_exe.delete_service(name, namespace, wait=True)
        assert kubernetes_exe.show_service(name=name, namespace=namespace) is None


@pytest.fixture(params=[True])
def configmap(kubernetes_exe, configmap_data, request):
    """
    Fixture to create a test configmap.

    If request.param is True, configmap is created before the test.
    If request.param is False, configmap is not created.
    """
    name = random_string("configmap-", uppercase=False)
    namespace = "default"

    # Only create the configmap if requested
    if request.param:
        res = kubernetes_exe.create_configmap(
            name, namespace=namespace, data=configmap_data, wait=True
        )
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name
        assert res["metadata"]["namespace"] == namespace
        for key, val in configmap_data.items():
            assert res["data"][key] == val

    try:
        yield {"name": name, "namespace": namespace, "data": configmap_data}
    finally:
        kubernetes_exe.delete_configmap(name, namespace, wait=True)
        assert kubernetes_exe.show_configmap(name=name, namespace=namespace) is None


@pytest.fixture(scope="module")
def node_name(loaders):
    """
    Fixture providing a node name for testing
    """
    # Get a node to test with (use control-plane node)
    nodes = loaders.modules.kubernetes.nodes()
    assert nodes, "No nodes found in cluster"
    return next(node for node in nodes if "control-plane" in node)


@pytest.fixture(params=[True])
def labeled_node(kubernetes_exe, request, node_name):
    """
    Fixture to create a labeled test node.

    If request.param is True, the label is created before the test.
    If request.param is False, the label is not created.
    """

    initial_labels = kubernetes_exe.node_labels(node_name)
    assert isinstance(initial_labels, dict)
    assert "kubernetes.io/hostname" in initial_labels
    labels = None

    # Only create the node if requested
    if request.param:
        if request.param is True:
            labels = {"test.salt.label": "value"}
        else:
            labels = request.param
        for label_key, label_value in labels.items():
            kubernetes_exe.node_add_label(node_name, label_key, label_value)

        # Verify label was added
        updated_labels = kubernetes_exe.node_labels(node_name)
        for label_key, label_value in labels.items():
            assert label_key in updated_labels
            assert updated_labels[label_key] == label_value
    try:
        yield {"name": node_name, "labels": labels}
    finally:
        # cleanup labels created in the test
        final_labels = set(kubernetes_exe.node_labels(node_name))
        labels_to_remove = final_labels - set(initial_labels)
        for remove_key in labels_to_remove:
            kubernetes_exe.node_remove_label(node_name, remove_key)

        cleaned_labels = set(kubernetes_exe.node_labels(node_name))
        assert not cleaned_labels - set(initial_labels)


# ---------------------------------------------------------------------------
# RBAC fixtures (Role, RoleBinding, ClusterRole, ClusterRoleBinding,
# ServiceAccount). Each follows the existing ``params=[True]`` convention so
# tests can opt into "resource pre-created" or "test without resource" modes.
#
# .. versionadded:: 2.1.0
# ---------------------------------------------------------------------------


@pytest.fixture
def role_spec():
    return {
        "rules": [
            {
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get", "list", "watch"],
            }
        ]
    }


@pytest.fixture(params=[True])
def role(kubernetes_exe, role_spec, request):
    """Create a Role in the default namespace; clean up on teardown."""
    name = random_string("role-", uppercase=False)
    if request.param:
        res = kubernetes_exe.create_role(name=name, namespace="default", spec=role_spec)
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name
    try:
        yield {"name": name, "namespace": "default", "spec": role_spec}
    finally:
        kubernetes_exe.delete_role(name=name, namespace="default")
        assert kubernetes_exe.show_role(name=name, namespace="default") is None


@pytest.fixture
def role_binding_spec(role):
    return {
        "subjects": [{"kind": "User", "name": "alice"}],
        "roleRef": {"kind": "Role", "name": role["name"]},
    }


@pytest.fixture(params=[True])
def role_binding(kubernetes_exe, role_binding_spec, request):
    """Create a RoleBinding referencing the ``role`` fixture's Role."""
    name = random_string("rolebinding-", uppercase=False)
    if request.param:
        res = kubernetes_exe.create_role_binding(
            name=name, namespace="default", spec=role_binding_spec
        )
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name
    try:
        yield {"name": name, "namespace": "default", "spec": role_binding_spec}
    finally:
        kubernetes_exe.delete_role_binding(name=name, namespace="default")
        assert kubernetes_exe.show_role_binding(name=name, namespace="default") is None


@pytest.fixture
def cluster_role_spec():
    return {
        "rules": [
            {
                "apiGroups": [""],
                "resources": ["nodes"],
                "verbs": ["get", "list"],
            }
        ]
    }


@pytest.fixture(params=[True])
def cluster_role(kubernetes_exe, cluster_role_spec, request):
    name = random_string("clusterrole-", uppercase=False)
    if request.param:
        res = kubernetes_exe.create_cluster_role(name=name, spec=cluster_role_spec)
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name
    try:
        yield {"name": name, "spec": cluster_role_spec}
    finally:
        kubernetes_exe.delete_cluster_role(name=name)
        assert kubernetes_exe.show_cluster_role(name=name) is None


@pytest.fixture
def cluster_role_binding_spec(cluster_role):
    return {
        "subjects": [{"kind": "User", "name": "alice"}],
        "roleRef": {"kind": "ClusterRole", "name": cluster_role["name"]},
    }


@pytest.fixture(params=[True])
def cluster_role_binding(kubernetes_exe, cluster_role_binding_spec, request):
    name = random_string("clusterrolebinding-", uppercase=False)
    if request.param:
        res = kubernetes_exe.create_cluster_role_binding(name=name, spec=cluster_role_binding_spec)
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name
    try:
        yield {"name": name, "spec": cluster_role_binding_spec}
    finally:
        kubernetes_exe.delete_cluster_role_binding(name=name)
        assert kubernetes_exe.show_cluster_role_binding(name=name) is None


@pytest.fixture
def service_account_spec():
    return {"automountServiceAccountToken": False}


@pytest.fixture(params=[True])
def service_account(kubernetes_exe, service_account_spec, request):
    name = random_string("sa-", uppercase=False)
    if request.param:
        res = kubernetes_exe.create_service_account(
            name=name, namespace="default", spec=service_account_spec
        )
        assert isinstance(res, dict)
        assert res["metadata"]["name"] == name
    try:
        yield {"name": name, "namespace": "default", "spec": service_account_spec}
    finally:
        kubernetes_exe.delete_service_account(name=name, namespace="default")
        assert kubernetes_exe.show_service_account(name=name, namespace="default") is None
