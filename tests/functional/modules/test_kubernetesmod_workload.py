"""
Functional tests for kubernetes.scale / restart / rollback / cluster_info
against the kind cluster fixture.

.. versionadded:: 2.1.0
"""

import time

import pytest
from salt.exceptions import CommandExecutionError

pytestmark = [pytest.mark.skip_unless_on_linux(reason="kind cluster fixture requires Linux")]


@pytest.fixture
def deployment_spec():
    return {
        "replicas": 1,
        "selector": {"matchLabels": {"app": "scale-test"}},
        "template": {
            "metadata": {"labels": {"app": "scale-test"}},
            "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
        },
    }


@pytest.fixture(params=[True])
def deployment(kubernetes_exe, deployment_spec, request):
    """Fresh Deployment per test; cleaned up on teardown."""
    from saltfactories.utils import random_string  # pylint: disable=import-outside-toplevel

    name = random_string("dep-", uppercase=False)
    namespace = "default"
    if request.param:
        res = kubernetes_exe.create_deployment(
            name=name,
            namespace=namespace,
            metadata={},
            spec=deployment_spec,
            wait=True,
        )
        assert res["metadata"]["name"] == name
    try:
        yield {"name": name, "namespace": namespace, "spec": deployment_spec}
    finally:
        kubernetes_exe.delete_deployment(name=name, namespace=namespace, wait=True)


# ---------------------------------------------------------------------------
# scale
# ---------------------------------------------------------------------------


def test_scale_deployment_up(kubernetes_exe, deployment):
    """Scaling up bumps spec.replicas; the live deployment converges."""
    res = kubernetes_exe.scale(
        kind="deployment",
        name=deployment["name"],
        replicas=3,
        namespace=deployment["namespace"],
    )
    assert res["spec"]["replicas"] == 3

    # Verify via show_deployment
    live = kubernetes_exe.show_deployment(
        name=deployment["name"], namespace=deployment["namespace"]
    )
    assert live["spec"]["replicas"] == 3


def test_scale_deployment_down_to_zero(kubernetes_exe, deployment):
    """
    Scale to zero is permitted (parking the workload).

    Verification goes through ``show_deployment`` rather than the V1Scale
    response object: the kubernetes-client's ``sanitize_for_serialization``
    drops ``replicas`` from the V1Scale spec when its value is 0 (the
    underlying OpenAPI type treats 0 as the implicit default and omits
    it). The deployment's own spec is unambiguous.
    """
    kubernetes_exe.scale(
        kind="deployment",
        name=deployment["name"],
        replicas=0,
        namespace=deployment["namespace"],
    )
    live = kubernetes_exe.show_deployment(
        name=deployment["name"], namespace=deployment["namespace"]
    )
    assert live["spec"]["replicas"] == 0


def test_scale_deployment_not_found_raises(kubernetes_exe):
    with pytest.raises(CommandExecutionError, match="not found"):
        kubernetes_exe.scale(
            kind="deployment", name="does-not-exist", replicas=1, namespace="default"
        )


# ---------------------------------------------------------------------------
# restart
# ---------------------------------------------------------------------------


def test_restart_deployment_stamps_pod_template(kubernetes_exe, deployment):
    """Restart must add the kubectl restartedAt annotation."""
    res = kubernetes_exe.restart(
        kind="deployment",
        name=deployment["name"],
        namespace=deployment["namespace"],
    )
    annotations = (
        res.get("spec", {}).get("template", {}).get("metadata", {}).get("annotations") or {}
    )
    assert "kubectl.kubernetes.io/restartedAt" in annotations


def test_restart_not_found_raises(kubernetes_exe):
    with pytest.raises(CommandExecutionError, match="not found"):
        kubernetes_exe.restart(kind="deployment", name="does-not-exist", namespace="default")


# ---------------------------------------------------------------------------
# rollback
# ---------------------------------------------------------------------------


def test_rollback_deployment_to_previous_revision(kubernetes_exe, deployment):
    """
    Create a Deployment, mutate its image to bump the revision, then roll
    back. The pod template's image must return to nginx:latest.
    """
    # Bump revision: change the image.
    new_spec = {
        **deployment["spec"],
        "template": {
            "metadata": {"labels": {"app": "scale-test"}},
            "spec": {"containers": [{"name": "nginx", "image": "nginx:1.25"}]},
        },
    }
    kubernetes_exe.replace_deployment(
        name=deployment["name"],
        namespace=deployment["namespace"],
        metadata={},
        spec=new_spec,
        wait=True,
    )

    # Give the controller a moment to record the new revision.
    time.sleep(2)

    # Roll back to the previous revision.
    res = kubernetes_exe.rollback(name=deployment["name"], namespace=deployment["namespace"])
    image = res["spec"]["template"]["spec"]["containers"][0]["image"]
    assert image == "nginx:latest", f"expected rollback to nginx:latest, got {image}"


def test_rollback_not_found_raises(kubernetes_exe):
    with pytest.raises(CommandExecutionError, match="not found"):
        kubernetes_exe.rollback(name="does-not-exist", namespace="default")


# ---------------------------------------------------------------------------
# cluster_info
# ---------------------------------------------------------------------------


def test_cluster_info_returns_version_and_groups(kubernetes_exe):
    """cluster_info reports a real server version + a non-empty group list."""
    info = kubernetes_exe.cluster_info()
    assert "server_version" in info
    assert info["server_version"].get("gitVersion", "").startswith("v")
    assert "api_groups" in info
    # Every cluster has at least the apps group.
    assert "apps" in info["api_groups"]
