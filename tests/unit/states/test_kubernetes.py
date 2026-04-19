"""
:codeauthor: :email:`Jeff Schroeder <jeffschroeder@computer.org>`
"""

import base64
from contextlib import contextmanager
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
import salt.utils.stringutils
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.modules import kubernetesmod
from saltext.kubernetes.states import kubernetes

pytestmark = [
    pytest.mark.skipif(
        kubernetesmod.HAS_LIBS is False,
        reason="Kubernetes client lib is not installed.",
    )
]


@pytest.fixture
def configure_loader_modules():
    return {kubernetes: {"__env__": "base"}}


@contextmanager
def mock_func(func_name, return_value, test=False):
    """
    Mock any of the kubernetes state function return values and set
    the test options.
    """
    name = f"kubernetes.{func_name}"
    mock_obj = MagicMock(return_value=return_value)

    # Create a new dictionary for each mock to avoid conflicts
    mocked = {name: mock_obj}

    with patch.dict(kubernetes.__salt__, mocked):
        with patch.dict(kubernetes.__opts__, {"test": test}):
            yield mock_obj


def make_configmap(name, namespace="default", data=None):
    return make_ret_dict(
        kind="ConfigMap",
        name=name,
        namespace=namespace,
        data=data,
    )


def make_secret(name, namespace="default", data=None):
    secret_data = make_ret_dict(
        kind="Secret",
        name=name,
        namespace=namespace,
        data=data,
    )
    # Base64 all of the values just like kubectl does
    for key, value in secret_data["data"].items():
        secret_data["data"][key] = base64.b64encode(salt.utils.stringutils.to_bytes(value))

    return secret_data


def make_node_labels(name="minikube"):
    return {
        "kubernetes.io/hostname": name,
        "beta.kubernetes.io/os": "linux",
        "beta.kubernetes.io/arch": "amd64",
        "failure-domain.beta.kubernetes.io/region": "us-west-1",
    }


def make_node(name="minikube"):
    node_data = make_ret_dict(kind="Node", name="minikube")
    node_data.update(
        {
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "annotations": {"node.alpha.kubernetes.io/ttl": "0"},
                "labels": make_node_labels(name=name),
                "name": name,
                "namespace": None,
                "link": f"/api/v1/nodes/{name}",
                "uid": "7811b8ae-c1a1-11e7-a55a-0800279fb61e",
            },
            "spec": {"externalID": name},
            "status": {},
        }
    )
    return node_data


def make_namespace(name="default"):
    namespace_data = make_ret_dict(kind="Namespace", name=name)
    del namespace_data["data"]
    namespace_data.update(
        {
            "status": {"phase": "Active"},
            "spec": {"finalizers": ["kubernetes"]},
            "metadata": {
                "name": name,
                "namespace": None,
                "labels": None,
                "link": f"/api/v1/namespaces/{name}",
                "annotations": None,
                "uid": "752fceeb-c1a1-11e7-a55a-0800279fb61e",
            },
        }
    )
    return namespace_data


def make_ret_dict(kind, name, namespace=None, data=None):
    """
    Make a minimal example configmap or secret for using in mocks
    """

    assert kind in ("Secret", "ConfigMap", "Namespace", "Node")

    if data is None:
        data = {}

    link = f"/api/v1/namespaces/{namespace}/{kind.lower()}s/{name}"

    return_data = {
        "kind": kind,
        "data": data,
        "apiVersion": "v1",
        "metadata": {
            "name": name,
            "labels": None,
            "namespace": namespace,
            "link": link,
            "annotations": {"kubernetes.io/change-cause": "salt-call state.apply"},
        },
    }
    return return_data


def test_configmap_present__fail():
    error = kubernetes.configmap_present(
        name="testme",
        data={1: 1},
        source="salt://beyond/oblivion.jinja",
    )
    assert error == {
        "changes": {},
        "result": False,
        "name": "testme",
        "comment": "'source' cannot be used in combination with 'data'",
    }


def test_configmap_present__create_no_data():
    # Create a new configmap with no 'data' attribute
    with mock_func("show_configmap", return_value=None):
        cm = make_configmap(
            name="test",
            namespace="default",
        )
        with mock_func("create_configmap", return_value=cm):
            actual = kubernetes.configmap_present(name="test")
            assert actual == {
                "comment": "ConfigMap created",
                "changes": {"old": {}, "new": cm},
                "name": "test",
                "result": True,
            }


def test_configmap_absent__noop_test_true():
    # Nothing to delete with test=True
    with mock_func("show_configmap", return_value=None, test=True):
        actual = kubernetes.configmap_absent(name="NOT_FOUND")
        assert actual == {
            "comment": "The configmap does not exist",
            "changes": {},
            "name": "NOT_FOUND",
            "result": True,
        }


def test_configmap_absent__noop():
    # Nothing to delete
    with mock_func("show_configmap", return_value=None):
        actual = kubernetes.configmap_absent(name="NOT_FOUND")
        assert actual == {
            "comment": "The configmap does not exist",
            "changes": {},
            "name": "NOT_FOUND",
            "result": True,
        }


def test_secret_present__fail():
    actual = kubernetes.secret_present(
        name="sekret",
        data={"password": "monk3y"},
        source="salt://nope.jinja",
    )
    assert actual == {
        "changes": {},
        "result": False,
        "name": "sekret",
        "comment": "'source' cannot be used in combination with 'data'",
    }


def test_secret_present__create_no_data():
    # Secret is created with no data
    secret = make_secret(name="sekret")
    with mock_func("show_secret", return_value=None):
        with mock_func("create_secret", return_value=secret):
            actual = kubernetes.secret_present(name="sekret")
            assert actual == {
                "changes": {
                    "old": {},
                    "new": {"data": []},
                },
                "result": True,
                "name": "sekret",
                "comment": "Secret created",
            }


def test_secret_absent__noop_test_true():
    with mock_func("show_secret", return_value=None, test=True):
        actual = kubernetes.secret_absent(name="sekret")
        assert actual == {
            "changes": {},
            "result": True,
            "name": "sekret",
            "comment": "The secret does not exist",
        }


def test_secret_absent__noop():
    with mock_func("show_secret", return_value=None):
        actual = kubernetes.secret_absent(name="passwords")
        assert actual == {
            "changes": {},
            "result": True,
            "name": "passwords",
            "comment": "The secret does not exist",
        }


def test_node_label_present__already_set():
    node_data = make_node()
    labels = node_data["metadata"]["labels"]
    with mock_func("node_labels", return_value=labels):
        with mock_func("node_add_label", return_value=node_data):
            actual = kubernetes.node_label_present(
                name="failure-domain.beta.kubernetes.io/region",
                node="minikube",
                value="us-west-1",
            )
            assert actual == {
                "changes": {},
                "result": True,
                "name": "failure-domain.beta.kubernetes.io/region",
                "comment": ("The label is already set and has the specified value"),
            }


def test_node_label_absent__noop_test_true():
    labels = make_node_labels()
    with mock_func("node_labels", return_value=labels, test=True):
        actual = kubernetes.node_label_absent(
            name="non-existent-label",
            node="minikube",
        )
        assert actual == {
            "changes": {},
            "result": True,
            "name": "non-existent-label",
            "comment": "The label does not exist",
        }


def test_node_label_absent__noop():
    labels = make_node_labels()
    with mock_func("node_labels", return_value=labels):
        actual = kubernetes.node_label_absent(
            name="non-existent-label",
            node="minikube",
        )
        assert actual == {
            "changes": {},
            "result": True,
            "name": "non-existent-label",
            "comment": "The label does not exist",
        }


def test_namespace_present__noop_test_true():
    namespace_data = make_namespace(name="saltstack")
    with mock_func("show_namespace", return_value=namespace_data, test=True):
        actual = kubernetes.namespace_present(name="saltstack")
        assert actual == {
            "changes": {},
            "result": True,
            "name": "saltstack",
            "comment": "The namespace already exists",
        }


def test_namespace_present__noop():
    namespace_data = make_namespace(name="saltstack")
    with mock_func("show_namespace", return_value=namespace_data):
        actual = kubernetes.namespace_present(name="saltstack")
        assert actual == {
            "changes": {},
            "result": True,
            "name": "saltstack",
            "comment": "The namespace already exists",
        }


def test_namespace_absent__noop_test_true():
    with mock_func("show_namespace", return_value=None, test=True):
        actual = kubernetes.namespace_absent(name="salt")
        assert actual == {
            "changes": {},
            "result": True,
            "name": "salt",
            "comment": "The namespace does not exist",
        }


def test_namespace_absent__noop():
    with mock_func("show_namespace", return_value=None):
        actual = kubernetes.namespace_absent(name="salt")
        assert actual == {
            "changes": {},
            "result": True,
            "name": "salt",
            "comment": "The namespace does not exist",
        }


def test_namespace_absent__delete_status_terminating():
    namespace_data = make_namespace(name="salt")
    deleted = namespace_data.copy()
    deleted.update(
        {
            "code": None,
            "status": "Terminating namespace",
            "message": "Terminating",
        }
    )
    with mock_func("show_namespace", return_value=namespace_data):
        with mock_func("delete_namespace", return_value=deleted):
            actual = kubernetes.namespace_absent(name="salt")
            assert actual == {
                "changes": {"old": "present", "new": "absent"},
                "result": True,
                "name": "salt",
                "comment": "Namespace salt deleted",
            }


def test_namespace_absent__delete_status_phase_terminating():
    # This is what kubernetes 1.8.0 looks like when deleting namespaces
    namespace_data = make_namespace(name="salt")
    deleted = namespace_data.copy()
    deleted.update({"code": None, "message": None, "status": {"phase": "Terminating"}})
    with mock_func("show_namespace", return_value=namespace_data):
        with mock_func("delete_namespace", return_value=deleted):
            actual = kubernetes.namespace_absent(name="salt")
            assert actual == {
                "changes": {"old": "present", "new": "absent"},
                "result": True,
                "name": "salt",
                "comment": "Namespace salt deleted",
            }


def test_namespace_absent__delete_error():
    namespace_data = make_namespace(name="salt")
    with mock_func("show_namespace", return_value=namespace_data):
        with patch.dict(
            kubernetes.__salt__,
            {
                "kubernetes.delete_namespace": MagicMock(
                    side_effect=CommandExecutionError("I'm a teapot!")
                )
            },
        ):
            actual = kubernetes.namespace_absent(name="salt")
            assert actual == {
                "changes": {},
                "result": False,
                "name": "salt",
                "comment": "I'm a teapot!",
            }


def test_deployment_present_handles_show_deployment_error():
    """
    Test deployment_present handles CommandExecutionError from show_deployment
    """
    with patch.dict(
        kubernetes.__salt__,
        {
            "kubernetes.show_deployment": MagicMock(
                side_effect=CommandExecutionError("Connection failed")
            )
        },
    ):
        with patch.dict(kubernetes.__opts__, {"test": False}):
            ret = kubernetes.deployment_present("test-deploy")

            assert ret["result"] is False
            assert "Connection failed" in ret["comment"]
            assert not ret["changes"]


def test_deployment_present_handles_create_deployment_error():
    """
    Test deployment_present handles CommandExecutionError from create_deployment
    """
    with patch.dict(
        kubernetes.__salt__,
        {
            "kubernetes.show_deployment": MagicMock(return_value=None),
            "kubernetes.create_deployment": MagicMock(
                side_effect=CommandExecutionError("Invalid spec")
            ),
        },
    ):
        with patch.dict(kubernetes.__opts__, {"test": False}):
            ret = kubernetes.deployment_present("test-deploy", spec={"invalid": "spec"})

            assert ret["result"] is False
            assert "Invalid spec" in ret["comment"]


def test_deployment_present_handles_patch_deployment_error():
    """
    Test deployment_present handles CommandExecutionError from patch_deployment
    """
    existing_deployment = {"metadata": {"name": "test"}, "spec": {"replicas": 1}}

    with patch.dict(
        kubernetes.__salt__,
        {
            "kubernetes.show_deployment": MagicMock(return_value=existing_deployment),
            "kubernetes.patch_deployment": MagicMock(
                side_effect=CommandExecutionError("Patch failed")
            ),
        },
    ):
        with patch.dict(kubernetes.__opts__, {"test": False}):
            ret = kubernetes.deployment_present("test-deploy", spec={"replicas": 3})

            assert ret["result"] is False
            assert "Patch failed" in ret["comment"]


def test_deployment_present_dry_run_fallback():
    """
    Test that deployment_present falls back gracefully when dry_run fails in test mode
    """
    with patch.dict(
        kubernetes.__salt__,
        {
            "kubernetes.show_deployment": MagicMock(return_value=None),
            "kubernetes.create_deployment": MagicMock(
                side_effect=CommandExecutionError("Dry run failed")
            ),
        },
    ):
        with patch.dict(kubernetes.__opts__, {"test": True}):
            ret = kubernetes.deployment_present("test-deploy", spec={"replicas": 3})

            assert ret["result"] is None
            assert "Dry run failed" in ret["comment"]
            assert "dependencies not created yet" in ret["comment"]


@pytest.mark.parametrize(
    "state_func,show_func",
    [
        ("deployment_absent", "show_deployment"),
        ("service_absent", "show_service"),
        ("secret_absent", "show_secret"),
        ("configmap_absent", "show_configmap"),
        ("pod_absent", "show_pod"),
    ],
)
def test_absent_handles_show_error(state_func, show_func):
    """
    Test that _absent functions handle CommandExecutionError from show
    """
    with patch.dict(
        kubernetes.__salt__,
        {f"kubernetes.{show_func}": MagicMock(side_effect=CommandExecutionError("API error"))},
    ):
        with patch.dict(kubernetes.__opts__, {"test": False}):
            func = getattr(kubernetes, state_func)
            ret = func(name="test")
            assert ret["result"] is False
            assert "API error" in ret["comment"]


@pytest.mark.parametrize(
    "state_func,show_func,delete_func",
    [
        ("deployment_absent", "show_deployment", "delete_deployment"),
        ("service_absent", "show_service", "delete_service"),
        ("secret_absent", "show_secret", "delete_secret"),
        ("configmap_absent", "show_configmap", "delete_configmap"),
        ("pod_absent", "show_pod", "delete_pod"),
    ],
)
def test_absent_handles_delete_error(state_func, show_func, delete_func):
    """
    Test that _absent functions handle CommandExecutionError from delete
    """
    with mock_func(show_func, return_value={"metadata": {"name": "test"}}):
        with patch.dict(
            kubernetes.__salt__,
            {
                f"kubernetes.{delete_func}": MagicMock(
                    side_effect=CommandExecutionError("Delete failed")
                )
            },
        ):
            func = getattr(kubernetes, state_func)
            ret = func(name="test")
            assert ret["result"] is False
            assert "Delete failed" in ret["comment"]


@pytest.mark.parametrize(
    "state_func,show_func",
    [
        ("service_present", "show_service"),
        ("secret_present", "show_secret"),
        ("configmap_present", "show_configmap"),
        ("pod_present", "show_pod"),
        ("namespace_present", "show_namespace"),
    ],
)
def test_present_handles_show_error(state_func, show_func):
    """
    Test that _present functions handle CommandExecutionError from show
    """
    with patch.dict(
        kubernetes.__salt__,
        {f"kubernetes.{show_func}": MagicMock(side_effect=CommandExecutionError("API error"))},
    ):
        with patch.dict(kubernetes.__opts__, {"test": False}):
            func = getattr(kubernetes, state_func)
            ret = func(name="test")
            assert ret["result"] is False
            assert "API error" in ret["comment"]


def test_service_present_source_conflict():
    """
    Test service_present returns error when both source and metadata/spec are provided
    """
    with patch.dict(kubernetes.__opts__, {"test": False}):
        ret = kubernetes.service_present(
            name="test",
            source="salt://test.yml",
            metadata={"labels": {"app": "test"}},
        )
        assert ret["result"] is False
        assert "source" in ret["comment"].lower()


def test_pod_present_source_conflict():
    """
    Test pod_present returns error when both source and metadata/spec are provided
    """
    with patch.dict(kubernetes.__opts__, {"test": False}):
        ret = kubernetes.pod_present(
            name="test",
            source="salt://test.yml",
            metadata={"labels": {"app": "test"}},
        )
        assert ret["result"] is False
        assert "source" in ret["comment"].lower()


def test_service_present_handles_create_error():
    """
    Test service_present handles CommandExecutionError from create_service
    """
    with patch.dict(
        kubernetes.__salt__,
        {
            "kubernetes.show_service": MagicMock(return_value=None),
            "kubernetes.create_service": MagicMock(
                side_effect=CommandExecutionError("Invalid spec")
            ),
        },
    ):
        with patch.dict(kubernetes.__opts__, {"test": False}):
            ret = kubernetes.service_present("test-svc", spec={"ports": [{"port": 80}]})
            assert ret["result"] is False
            assert "Invalid spec" in ret["comment"]


def test_service_present_handles_patch_error():
    """
    Test service_present handles CommandExecutionError from patch_service
    """
    existing = {"metadata": {"name": "test"}, "spec": {"type": "ClusterIP"}}
    with patch.dict(
        kubernetes.__salt__,
        {
            "kubernetes.show_service": MagicMock(return_value=existing),
            "kubernetes.patch_service": MagicMock(
                side_effect=CommandExecutionError("Patch failed")
            ),
        },
    ):
        with patch.dict(kubernetes.__opts__, {"test": False}):
            ret = kubernetes.service_present("test-svc", spec={"type": "NodePort"})
            assert ret["result"] is False
            assert "Patch failed" in ret["comment"]


def test_service_present_dry_run_fallback():
    """
    Test service_present falls back gracefully when dry_run fails in test mode
    """
    with patch.dict(
        kubernetes.__salt__,
        {
            "kubernetes.show_service": MagicMock(return_value=None),
            "kubernetes.create_service": MagicMock(
                side_effect=CommandExecutionError("Namespace not found")
            ),
        },
    ):
        with patch.dict(kubernetes.__opts__, {"test": True}):
            ret = kubernetes.service_present("test-svc", spec={"ports": [{"port": 80}]})
            assert ret["result"] is None
            assert "dependencies not created yet" in ret["comment"]


def test_secret_present_dry_run_fallback():
    """
    Test secret_present falls back gracefully when dry_run fails in test mode
    """
    with patch.dict(
        kubernetes.__salt__,
        {
            "kubernetes.show_secret": MagicMock(return_value=None),
            "kubernetes.create_secret": MagicMock(
                side_effect=CommandExecutionError("Namespace not found")
            ),
        },
    ):
        with patch.dict(kubernetes.__opts__, {"test": True}):
            ret = kubernetes.secret_present("test-secret", data={"key": "value"})
            assert ret["result"] is None
            assert "dependencies not created yet" in ret["comment"]


def test_configmap_present_dry_run_fallback():
    """
    Test configmap_present falls back gracefully when dry_run fails in test mode
    """
    with patch.dict(
        kubernetes.__salt__,
        {
            "kubernetes.show_configmap": MagicMock(return_value=None),
            "kubernetes.create_configmap": MagicMock(
                side_effect=CommandExecutionError("Namespace not found")
            ),
        },
    ):
        with patch.dict(kubernetes.__opts__, {"test": True}):
            ret = kubernetes.configmap_present("test-cm", data={"key": "value"})
            assert ret["result"] is None
            assert "dependencies not created yet" in ret["comment"]


def test_namespace_present_handles_create_error():
    """
    Test namespace_present handles CommandExecutionError from create_namespace
    """
    with patch.dict(
        kubernetes.__salt__,
        {
            "kubernetes.show_namespace": MagicMock(return_value=None),
            "kubernetes.create_namespace": MagicMock(
                side_effect=CommandExecutionError("Already exists")
            ),
        },
    ):
        with patch.dict(kubernetes.__opts__, {"test": False}):
            ret = kubernetes.namespace_present("test-ns")
            assert ret["result"] is False
            assert "Already exists" in ret["comment"]


def test_node_label_present_handles_error():
    """
    Test node_label_present handles CommandExecutionError from node_labels
    """
    with patch.dict(
        kubernetes.__salt__,
        {"kubernetes.node_labels": MagicMock(side_effect=CommandExecutionError("Node not found"))},
    ):
        with patch.dict(kubernetes.__opts__, {"test": False}):
            ret = kubernetes.node_label_present(
                name="test-label", node="missing-node", value="test"
            )
            assert ret["result"] is False
            assert "Node not found" in ret["comment"]


def test_node_label_absent_handles_error():
    """
    Test node_label_absent handles CommandExecutionError from node_labels
    """
    with patch.dict(
        kubernetes.__salt__,
        {"kubernetes.node_labels": MagicMock(side_effect=CommandExecutionError("Node not found"))},
    ):
        with patch.dict(kubernetes.__opts__, {"test": False}):
            ret = kubernetes.node_label_absent(name="test-label", node="missing-node")
            assert ret["result"] is False
            assert "Node not found" in ret["comment"]
