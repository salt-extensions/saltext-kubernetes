"""
Functional tests for the public ``kubernetes.apply`` /
``kubernetes.delete_manifest`` execution-module functions, and the
``manifest_present`` / ``manifest_absent`` states they back, against
the kind cluster fixture.

.. versionadded:: 2.1.0
"""

import textwrap

import pytest
from salt.exceptions import CommandExecutionError
from saltfactories.utils import random_string

# ---------------------------------------------------------------------------
# kubernetes.apply (execution module)
# ---------------------------------------------------------------------------


def test_apply_dict_creates_configmap(kubernetes_exe):
    """Applying a single dict manifest creates the resource."""
    name = random_string("apply-cm-", uppercase=False)
    try:
        manifest = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": name, "namespace": "default"},
            "data": {"k1": "v1"},
        }
        res = kubernetes_exe.apply(manifest=manifest)
        assert res["metadata"]["name"] == name
        assert res["data"] == {"k1": "v1"}
        # Visible via the typed show path too.
        live = kubernetes_exe.show_configmap(name=name, namespace="default")
        assert live["data"] == {"k1": "v1"}
    finally:
        kubernetes_exe.delete_manifest(manifest=manifest)


def test_apply_yaml_string_multi_doc(kubernetes_exe):
    """A multi-doc YAML string applies every document."""
    name_a = random_string("apply-yml-a-", uppercase=False)
    name_b = random_string("apply-yml-b-", uppercase=False)
    yaml_str = textwrap.dedent(f"""\
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: {name_a}
          namespace: default
        data:
          a: alpha
        ---
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: {name_b}
          namespace: default
        data:
          b: bravo
        """)
    try:
        res = kubernetes_exe.apply(manifest=yaml_str)
        assert isinstance(res, list)
        assert len(res) == 2
        assert {r["metadata"]["name"] for r in res} == {name_a, name_b}
        # Confirm both landed on the cluster.
        live_a = kubernetes_exe.show_configmap(name=name_a, namespace="default")
        live_b = kubernetes_exe.show_configmap(name=name_b, namespace="default")
        assert live_a["data"] == {"a": "alpha"}
        assert live_b["data"] == {"b": "bravo"}
    finally:
        kubernetes_exe.delete_manifest(manifest=yaml_str)


def test_apply_namespace_default_filled_in(kubernetes_exe):
    """``namespace=`` kwarg fills in metadata.namespace when missing."""
    name = random_string("apply-ns-", uppercase=False)
    manifest = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name},  # no namespace declared
        "data": {"x": "y"},
    }
    try:
        res = kubernetes_exe.apply(manifest=manifest, namespace="default")
        assert res["metadata"]["namespace"] == "default"
    finally:
        kubernetes_exe.delete_manifest(manifest=manifest, namespace="default")


def test_apply_dry_run_does_not_persist(kubernetes_exe):
    """``dry_run=True`` validates but does not write."""
    name = random_string("apply-dry-", uppercase=False)
    manifest = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": "default"},
        "data": {"k": "v"},
    }
    res = kubernetes_exe.apply(manifest=manifest, dry_run=True)
    assert res["metadata"]["name"] == name
    assert kubernetes_exe.show_configmap(name=name, namespace="default") is None


def test_apply_idempotent_on_reapply(kubernetes_exe):
    """Re-applying the same manifest is a no-op functionally."""
    name = random_string("apply-idem-", uppercase=False)
    manifest = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": "default"},
        "data": {"a": "1"},
    }
    try:
        first = kubernetes_exe.apply(manifest=manifest)
        second = kubernetes_exe.apply(manifest=manifest)
        assert first["data"] == second["data"]
    finally:
        kubernetes_exe.delete_manifest(manifest=manifest)


def test_apply_unknown_kind_raises(kubernetes_exe):
    """Manifests for kinds the cluster doesn't know surface a clear error."""
    manifest = {
        "apiVersion": "frobozz.example.com/v1",
        "kind": "Magic",
        "metadata": {"name": "x", "namespace": "default"},
    }
    with pytest.raises(CommandExecutionError, match="no resource for apiVersion"):
        kubernetes_exe.apply(manifest=manifest)


def test_apply_namespaced_without_namespace_raises(kubernetes_exe):
    """Namespaced kind without metadata.namespace and without namespace= fails loudly."""
    manifest = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "x"},
        "data": {"k": "v"},
    }
    with pytest.raises(CommandExecutionError, match="requires 'metadata.namespace'"):
        kubernetes_exe.apply(manifest=manifest)


# ---------------------------------------------------------------------------
# kubernetes.delete_manifest
# ---------------------------------------------------------------------------


def test_delete_manifest_removes_object(kubernetes_exe):
    """delete_manifest removes a previously-applied object."""
    name = random_string("del-cm-", uppercase=False)
    manifest = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": "default"},
        "data": {"k": "v"},
    }
    kubernetes_exe.apply(manifest=manifest)
    assert kubernetes_exe.show_configmap(name=name, namespace="default") is not None
    kubernetes_exe.delete_manifest(manifest=manifest)
    # Allow a beat for finalizers; ConfigMaps don't have them, so the delete
    # is effectively immediate, but the cache may briefly say otherwise.
    assert kubernetes_exe.show_configmap(name=name, namespace="default") is None


def test_delete_manifest_missing_object_returns_none(kubernetes_exe):
    """delete_manifest swallows 404 like the typed delete_* do."""
    manifest = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "definitely-not-there", "namespace": "default"},
    }
    # Should not raise.
    kubernetes_exe.delete_manifest(manifest=manifest)


# ---------------------------------------------------------------------------
# manifest_present / manifest_absent state functions
# ---------------------------------------------------------------------------


def test_manifest_present_state_creates(loaders):
    """The state applies the manifest and reports changes."""
    state = loaders.states.kubernetes
    name = random_string("state-cm-", uppercase=False)
    manifest = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": "default"},
        "data": {"a": "alpha"},
    }
    try:
        ret = state.manifest_present(name="state-test", manifest=manifest)
        assert ret["result"] is True
        assert "applied" in ret["changes"]
        live = loaders.modules.kubernetes.show_configmap(name=name, namespace="default")
        assert live is not None
    finally:
        loaders.modules.kubernetes.delete_manifest(manifest=manifest)


def test_manifest_absent_state_deletes(loaders):
    """The absent state removes a previously-applied manifest."""
    mod = loaders.modules.kubernetes
    state = loaders.states.kubernetes
    name = random_string("state-cm-abs-", uppercase=False)
    manifest = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": "default"},
        "data": {"k": "v"},
    }
    mod.apply(manifest=manifest)
    ret = state.manifest_absent(name="state-test-abs", manifest=manifest)
    assert ret["result"] is True
    assert mod.show_configmap(name=name, namespace="default") is None


# Test-mode (``__opts__["test"]=True``) behaviour for manifest_present
# is exercised in ``tests/unit/states/test_kubernetes_apply.py`` —
# salt-factories' loader globals snapshot ``__opts__`` at task-prep
# time and don't see late mutations, so the test is more reliable as
# a unit test where we control the dunders directly.
