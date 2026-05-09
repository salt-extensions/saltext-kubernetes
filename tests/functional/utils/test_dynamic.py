"""
Functional tests for ``saltext.kubernetes.utils._dynamic`` against the
kind cluster fixture. Exercises the actual server-side-apply HTTP wire
path — fieldManager, force_conflicts, dry_run, namespacing.

These call into ``_dynamic`` directly (not through the Salt loader),
so we explicitly load the kind cluster's kubeconfig into the active
default Configuration. The public ``kubernetes.apply`` execution-
module function shipped in PR10 has its own functional tests that
exercise the same paths through the loader.

.. versionadded:: 2.1.0
"""

import kubernetes
import pytest
from salt.exceptions import CommandExecutionError
from saltfactories.utils import random_string

from saltext.kubernetes.utils import _dynamic


@pytest.fixture(autouse=True)
def _load_kind_kubeconfig(kind_cluster):
    """Install the kind cluster as the active default Configuration."""
    kubernetes.config.load_kube_config(config_file=str(kind_cluster.kubeconfig_path))
    # Drop caches so the new Configuration produces a fresh DynamicClient.
    _dynamic.invalidate_caches()
    yield


@pytest.fixture
def applied_configmap_name():
    """Test-scoped name for an SSA-applied ConfigMap; cleaned up via the
    same module's ``delete_object`` to round-trip the API surface."""
    name = random_string("ssa-cm-", uppercase=False)
    yield name
    try:
        _dynamic.delete_object("v1", "ConfigMap", name=name, namespace="default")
    except CommandExecutionError:
        pass


def test_apply_manifest_creates_configmap(applied_configmap_name):
    """A ConfigMap applied via SSA round-trips through get_object."""
    name = applied_configmap_name
    manifest = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": "default"},
        "data": {"k1": "v1", "k2": "v2"},
    }
    result = _dynamic.apply_manifest(manifest, field_manager="saltext-test")
    assert result["metadata"]["name"] == name
    assert result["data"] == {"k1": "v1", "k2": "v2"}

    # And it's actually in the cluster.
    live = _dynamic.get_object("v1", "ConfigMap", name=name, namespace="default")
    assert live is not None
    assert live["data"] == {"k1": "v1", "k2": "v2"}

    # And the field manager landed on the record.
    managed = (
        live.get("metadata", {}).get("managed_fields")
        or live.get("metadata", {}).get("managedFields")
        or []
    )
    assert any(
        entry.get("manager") == "saltext-test" for entry in managed
    ), f"saltext-test not found in managedFields: {managed}"


def test_apply_manifest_idempotent(applied_configmap_name):
    """Re-applying the same manifest is a no-op (cluster state unchanged)."""
    name = applied_configmap_name
    manifest = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": "default"},
        "data": {"k1": "v1"},
    }
    first = _dynamic.apply_manifest(manifest, field_manager="saltext-test")
    second = _dynamic.apply_manifest(manifest, field_manager="saltext-test")
    # resource_version may bump (it does on Kubernetes < 1.28); data must match.
    assert first["data"] == second["data"]


def test_apply_manifest_dry_run_does_not_persist():
    """dry_run=True returns the would-be object but doesn't create it."""
    name = random_string("ssa-dry-", uppercase=False)
    manifest = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": "default"},
        "data": {"k": "v"},
    }
    result = _dynamic.apply_manifest(manifest, field_manager="saltext-test", dry_run=True)
    assert result["metadata"]["name"] == name
    # Should not exist on the cluster.
    assert _dynamic.get_object("v1", "ConfigMap", name=name, namespace="default") is None


def test_get_resource_unknown_kind_raises():
    """Unknown GVKs surface a clear CommandExecutionError, not a KeyError."""
    with pytest.raises(CommandExecutionError, match="no resource for apiVersion"):
        _dynamic.get_resource("apps/v1", "FrobozzDeployment")


def test_get_object_returns_none_for_missing():
    """404 turns into None, matching the typed show_* functions."""
    out = _dynamic.get_object(
        "v1",
        "ConfigMap",
        name="absolutely-does-not-exist-1234",
        namespace="default",
    )
    assert out is None


def test_apply_manifest_namespaced_kind_requires_namespace():
    """A namespaced manifest without metadata.namespace must fail loudly."""
    manifest = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "x"},  # no namespace
        "data": {"k": "v"},
    }
    with pytest.raises(CommandExecutionError, match="requires 'metadata.namespace'"):
        _dynamic.apply_manifest(manifest, field_manager="saltext-test")
