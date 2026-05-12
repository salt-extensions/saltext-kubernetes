"""
Functional tests for the resources subsystem against a real kind cluster.

The resources plug-in (``saltext.kubernetes.resources.kubernetes``) is
dormant on stock Salt: it only loads when the in-flight ``resources``
feature branch (`/home/dan/src/salt/worktree/resources`) is the active
Salt source. These tests skip cleanly if the resources subsystem isn't
available.

When enabled (set ``SALT_RESOURCES_WORKTREE`` to the path of a Salt
build that ships the resources branch), the tests exercise:

  * ``discover(opts)`` returns a flat list of bare resource IDs
  * ``grains()`` projects metadata for the active resource
  * The ``kuberesource_*`` companion modules dispatch correctly

.. versionadded:: 2.1.0
"""

import pytest
from saltfactories.utils import random_string

from saltext.kubernetes.modules import kuberesource_cmd
from saltext.kubernetes.resources import kubernetes as resource_mod

pytestmark = [pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms")]


def _resources_subsystem_available():
    """The resources plug-in's ``__virtual__`` probes ``salt.utils.resources``."""
    try:
        import salt.utils.resources  # noqa: F401  # pylint: disable=import-outside-toplevel,unused-import,import-error

        return True
    except ImportError:
        return False


pytestmark.append(
    pytest.mark.skipif(
        not _resources_subsystem_available(),
        reason="Salt resources subsystem not available; set SALT_RESOURCES_WORKTREE",
    )
)


@pytest.fixture
def resource_plugin(loaders):
    """The ``kubernetes`` resource plugin loaded by the Salt loader."""
    # The resource loader exposes the same modules namespace; we reach it
    # by name to keep the test robust against attribute renames.
    return loaders.modules.get("kubernetes_resource") or loaders.modules.kubernetes


def test_discover_returns_default_kinds(resource_plugin, kubernetes_exe):
    """``discover`` returns bare IDs for the kinds configured in pillar."""
    # Create one of each default kind so discover has something to find.
    ns = random_string("disc-", uppercase=False)
    dep = "disc-dep"
    try:
        kubernetes_exe.create_namespace(name=ns, wait=True)
        kubernetes_exe.create_deployment(
            name=dep,
            namespace=ns,
            metadata={},
            spec={
                "replicas": 1,
                "selector": {"matchLabels": {"app": dep}},
                "template": {
                    "metadata": {"labels": {"app": dep}},
                    "spec": {
                        "containers": [{"name": "pause", "image": "registry.k8s.io/pause:3.9"}]
                    },
                },
            },
            wait=True,
        )
        # discover takes opts; we pass the minion opts directly.
        # Manually initialise the resource plug-in's __context__ for the test.
        resource_mod.__context__ = {
            "kubernetes_resource": {
                "initialized": True,
                "kinds": ["deployment", "namespace"],
                "namespaces": [ns],
                "label_selector": None,
                "config": {},
            }
        }
        # The plug-in reads from __salt__ via _connection; loaders provides it.
        resource_mod.__salt__ = {"config.option": lambda k, default="": default}  # noqa: F821
        ids = resource_mod.discover({})
        assert isinstance(ids, list)
        # We don't assert exact contents (kind cluster has system namespaces)
        # but our created objects must be in there.
        assert any(f"deployment:{ns}/{dep}" == i for i in ids)
    finally:
        kubernetes_exe.delete_namespace(name=ns, wait=True)


def test_grains_projects_labels_and_phase(kubernetes_exe):
    """``grains()`` reads ``__resource__["id"]`` and projects label/phase."""
    ns = random_string("grains-", uppercase=False)
    try:
        kubernetes_exe.create_namespace(name=ns, wait=True)
        kubernetes_exe.create_configmap(
            name="conf",
            namespace=ns,
            data={"k": "v"},
            wait=True,
        )
        # Inject the resource ID and verify grains() returns the right shape.
        resource_mod.__resource__ = {"id": f"configmap:{ns}/conf"}
        resource_mod.__salt__ = {"config.option": lambda k, default="": default}
        grain_dict = resource_mod.grains()
        assert grain_dict["kind"] == "configmap"
        assert grain_dict["namespace"] == ns
        assert grain_dict["name"] == "conf"
        # ConfigMap has no labels; the projection should still include the key.
        assert "label" in grain_dict
        assert "annotation" in grain_dict
    finally:
        kubernetes_exe.delete_namespace(name=ns, wait=True)


def test_make_id_round_trips_with_parse_id():
    """The ID schema (``kind:ns/name`` and ``kind:name``) is symmetric."""
    # Namespaced
    rid = resource_mod._make_id("pod", "default", "nginx")
    assert rid == "pod:default/nginx"
    parsed = resource_mod._parse_id(rid)
    assert parsed == ("pod", "default", "nginx")
    # Cluster-scoped
    rid = resource_mod._make_id("node", None, "worker-1")
    assert rid == "node:worker-1"
    parsed = resource_mod._parse_id(rid)
    assert parsed == ("node", None, "worker-1")


def test_kuberesource_cmd_dispatches_to_exec(kubernetes_exe):
    """``kuberesource_cmd.run`` resolves __resource__ and forwards to exec."""
    pod = random_string("krsrc-", uppercase=False)
    try:
        kubernetes_exe.create_pod(
            name=pod,
            namespace="default",
            metadata={"labels": {"role": "krsrc"}},
            spec={
                "containers": [
                    {"name": "alpine", "image": "alpine:3.20", "command": ["/bin/sleep", "30"]}
                ]
            },
            wait=True,
        )
        # Inject __resource__ for the companion module.
        kuberesource_cmd.__resource__ = {"id": f"pod:default/{pod}"}
        kuberesource_cmd.__salt__ = {
            "kubernetes.exec": kubernetes_exe.exec,
            "config.option": lambda k, default="": default,
        }
        result = kuberesource_cmd.run(["/bin/echo", "hello"])
        assert "hello" in str(result)
    finally:
        kubernetes_exe.delete_pod(name=pod, namespace="default", wait=True)
