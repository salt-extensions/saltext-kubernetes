"""
Functional tests for the ansible-parity additions on a real kind cluster:

  * ``append_hash`` on ``create_configmap`` / ``create_secret``
  * ``patch_object`` with strategic / json-merge / json-patch types
  * ``validate=True`` pre-flight on ``apply``

.. versionadded:: 2.1.0
"""

import pytest
from salt.exceptions import CommandExecutionError
from saltfactories.utils import random_string

pytestmark = [pytest.mark.skip_unless_on_linux(reason="kind cluster fixture requires Linux")]

# ---------------------------------------------------------------------------
# append_hash on ConfigMap / Secret
# ---------------------------------------------------------------------------


def test_append_hash_configmap_creates_hashed_name(kubernetes_exe):
    base = random_string("cm-hash-", uppercase=False)
    res = kubernetes_exe.create_configmap(
        name=base, namespace="default", data={"key": "value"}, append_hash=True
    )
    try:
        created_name = res["metadata"]["name"]
        # Name includes a hash suffix
        assert created_name.startswith(f"{base}-")
        assert len(created_name) > len(base) + 1
        # The hashed name is what's stored — show_configmap finds it
        assert kubernetes_exe.show_configmap(name=created_name, namespace="default") is not None
    finally:
        kubernetes_exe.delete_configmap(
            name=res["metadata"]["name"], namespace="default", wait=True
        )


def test_append_hash_configmap_data_change_yields_different_name(kubernetes_exe):
    base = random_string("cm-hash-diff-", uppercase=False)
    r1 = kubernetes_exe.create_configmap(
        name=base, namespace="default", data={"key": "v1"}, append_hash=True
    )
    r2 = kubernetes_exe.create_configmap(
        name=base, namespace="default", data={"key": "v2"}, append_hash=True
    )
    try:
        assert r1["metadata"]["name"] != r2["metadata"]["name"]
    finally:
        kubernetes_exe.delete_configmap(name=r1["metadata"]["name"], namespace="default", wait=True)
        kubernetes_exe.delete_configmap(name=r2["metadata"]["name"], namespace="default", wait=True)


def test_append_hash_secret_creates_hashed_name(kubernetes_exe):
    base = random_string("sec-hash-", uppercase=False)
    res = kubernetes_exe.create_secret(
        name=base, namespace="default", data={"token": "abc"}, append_hash=True
    )
    try:
        created = res["metadata"]["name"]
        assert created.startswith(f"{base}-")
        assert len(created) > len(base) + 1
    finally:
        kubernetes_exe.delete_secret(name=res["metadata"]["name"], namespace="default", wait=True)


# ---------------------------------------------------------------------------
# patch_object with alternate patch types
# ---------------------------------------------------------------------------


@pytest.fixture
def patch_target_deployment(kubernetes_exe):
    """A simple deployment to patch in each test."""
    name = random_string("patch-tgt-", uppercase=False)
    spec = {
        "replicas": 1,
        "selector": {"matchLabels": {"app": "patch-tgt"}},
        "template": {
            "metadata": {"labels": {"app": "patch-tgt"}},
            "spec": {"containers": [{"name": "pause", "image": "registry.k8s.io/pause:3.9"}]},
        },
    }
    kubernetes_exe.create_deployment(
        name=name, namespace="default", metadata={}, spec=spec, wait=False
    )
    yield name
    kubernetes_exe.delete_deployment(name=name, namespace="default", wait=True)


def test_patch_object_strategic_merge(kubernetes_exe, patch_target_deployment):
    name = patch_target_deployment
    kubernetes_exe.patch_object(
        kind="Deployment",
        name=name,
        namespace="default",
        patch={"spec": {"replicas": 3}},
        patch_type="strategic",
    )
    live = kubernetes_exe.show_deployment(name=name, namespace="default")
    assert live["spec"]["replicas"] == 3


def test_patch_object_json_merge(kubernetes_exe, patch_target_deployment):
    name = patch_target_deployment
    kubernetes_exe.patch_object(
        kind="Deployment",
        name=name,
        namespace="default",
        patch={"spec": {"replicas": 2}},
        patch_type="json-merge",
    )
    live = kubernetes_exe.show_deployment(name=name, namespace="default")
    assert live["spec"]["replicas"] == 2


def test_patch_object_json_patch(kubernetes_exe, patch_target_deployment):
    name = patch_target_deployment
    kubernetes_exe.patch_object(
        kind="Deployment",
        name=name,
        namespace="default",
        patch=[{"op": "replace", "path": "/spec/replicas", "value": 4}],
        patch_type="json",
    )
    live = kubernetes_exe.show_deployment(name=name, namespace="default")
    assert live["spec"]["replicas"] == 4


def test_patch_object_api_version_inferred_for_typed_kinds(kubernetes_exe, patch_target_deployment):
    """Calling without ``api_version`` works because Deployment is in the registry."""
    name = patch_target_deployment
    # No api_version kwarg — should infer apps/v1 from the kind registry.
    res = kubernetes_exe.patch_object(
        kind="Deployment",
        name=name,
        namespace="default",
        patch={"spec": {"replicas": 2}},
    )
    assert res["spec"]["replicas"] == 2


# ---------------------------------------------------------------------------
# validate=True pre-flight on apply
# ---------------------------------------------------------------------------


def test_apply_validate_succeeds_for_valid_manifest(kubernetes_exe):
    name = random_string("apply-valid-", uppercase=False)
    doc = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": "default"},
        "data": {"k": "v"},
    }
    try:
        kubernetes_exe.apply(manifest=doc, validate=True)
        # Object was actually persisted (validate must not be confused with dry-run)
        assert kubernetes_exe.show_configmap(name=name, namespace="default") is not None
    finally:
        kubernetes_exe.delete_configmap(name=name, namespace="default", wait=True)


def test_apply_validate_catches_invalid_manifest_before_persisting(kubernetes_exe):
    name = random_string("apply-invalid-", uppercase=False)
    # Service with an invalid port (negative) → API server rejects on validation.
    doc = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name, "namespace": "default"},
        "spec": {
            "selector": {"app": "x"},
            "ports": [{"port": -1, "targetPort": 80}],
        },
    }
    with pytest.raises(CommandExecutionError):
        kubernetes_exe.apply(manifest=doc, validate=True)
    # Object was NOT created — validate=True caught it before the real apply.
    assert kubernetes_exe.show_service(name=name, namespace="default") is None
