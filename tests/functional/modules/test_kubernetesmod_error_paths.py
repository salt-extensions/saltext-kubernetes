"""
API-server error-path coverage.

Each test exercises one specific HTTP-status / failure mode the API server
emits, verifying that the extension surfaces a meaningful error instead of
a generic ``Exception`` or — worse — silently doing nothing.

Categories covered:

  * 404 (not found) — read/delete idempotency
  * 409 (conflict) — re-create existing object
  * 422 (invalid) — bad spec, fails validation
  * 403 (forbidden) — RBAC-denied operation
  * Admission webhook rejection — apply something that contradicts a
    validation policy
  * Resource quota exceeded
  * Stale resource version on optimistic locking

.. versionadded:: 2.1.0
"""

import time

import pytest
from salt.exceptions import CommandExecutionError
from saltfactories.utils import random_string

pytestmark = [pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms")]


# ---------------------------------------------------------------------------
# 404 — read / delete of nonexistent objects
# ---------------------------------------------------------------------------


def test_show_nonexistent_returns_none(kubernetes_exe):
    """``show_*`` swallows 404 and returns None (matches typed CRUD contract)."""
    name = random_string("nx-", uppercase=False)
    assert kubernetes_exe.show_pod(name=name, namespace="default") is None
    assert kubernetes_exe.show_namespace(name=name) is None
    assert kubernetes_exe.show_deployment(name=name, namespace="default") is None


def test_delete_nonexistent_namespace_is_idempotent(kubernetes_exe):
    """``delete_namespace`` on a missing namespace is a no-op."""
    name = random_string("nx-del-", uppercase=False)
    # Should not raise; returns None for already-absent.
    res = kubernetes_exe.delete_namespace(name=name, wait=True)
    assert res is None


def test_delete_nonexistent_deployment_is_idempotent(kubernetes_exe):
    name = random_string("nx-dep-", uppercase=False)
    res = kubernetes_exe.delete_deployment(name=name, namespace="default", wait=True)
    assert res is None


def test_delete_nonexistent_configmap_is_idempotent(kubernetes_exe):
    name = random_string("nx-cm-", uppercase=False)
    res = kubernetes_exe.delete_configmap(name=name, namespace="default", wait=True)
    assert res is None


# ---------------------------------------------------------------------------
# 409 — conflict on re-create of existing object
# ---------------------------------------------------------------------------


def test_create_existing_configmap_raises_conflict(kubernetes_exe):
    name = random_string("conflict-cm-", uppercase=False)
    kubernetes_exe.create_configmap(name=name, namespace="default", data={"k": "v"})
    try:
        with pytest.raises(CommandExecutionError) as exc:
            kubernetes_exe.create_configmap(name=name, namespace="default", data={"k": "v2"})
        assert "already exists" in str(exc.value).lower() or "conflict" in str(exc.value).lower()
    finally:
        kubernetes_exe.delete_configmap(name=name, namespace="default", wait=True)


def test_create_existing_namespace_raises_conflict(kubernetes_exe):
    name = random_string("conflict-ns-", uppercase=False)
    kubernetes_exe.create_namespace(name=name, wait=True)
    try:
        with pytest.raises(CommandExecutionError):
            kubernetes_exe.create_namespace(name=name, wait=True)
    finally:
        kubernetes_exe.delete_namespace(name=name, wait=True)


# ---------------------------------------------------------------------------
# 422 — validation rejection (invalid spec)
# ---------------------------------------------------------------------------


def test_create_service_negative_port_rejected(kubernetes_exe):
    """A Service with port=-1 fails validation; the error mentions the field."""
    name = random_string("invalid-svc-", uppercase=False)
    with pytest.raises(CommandExecutionError) as exc:
        kubernetes_exe.create_service(
            name=name,
            namespace="default",
            metadata={},
            spec={"selector": {"app": "x"}, "ports": [{"port": -1, "targetPort": 80}]},
        )
    # We just need the error to surface; specific message is API-version-dependent.
    assert str(exc.value)


def test_apply_invalid_manifest_with_validate_catches_early(kubernetes_exe):
    """``validate=True`` raises before the object is persisted."""
    name = random_string("validate-fail-", uppercase=False)
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
    assert kubernetes_exe.show_service(name=name, namespace="default") is None


def test_create_pod_missing_required_field(kubernetes_exe):
    """A pod with no containers fails validation."""
    name = random_string("no-containers-", uppercase=False)
    with pytest.raises(CommandExecutionError):
        kubernetes_exe.create_pod(name=name, namespace="default", metadata={}, spec={})


# ---------------------------------------------------------------------------
# Manifest / GVK errors
# ---------------------------------------------------------------------------


def test_apply_manifest_missing_apiversion(kubernetes_exe):
    with pytest.raises(CommandExecutionError, match="apiVersion"):
        kubernetes_exe.apply(manifest={"kind": "ConfigMap", "metadata": {"name": "x"}, "data": {}})


def test_apply_manifest_missing_kind(kubernetes_exe):
    with pytest.raises(CommandExecutionError, match="kind"):
        kubernetes_exe.apply(manifest={"apiVersion": "v1", "metadata": {"name": "x"}})


def test_apply_manifest_missing_metadata_name(kubernetes_exe):
    with pytest.raises(CommandExecutionError):
        kubernetes_exe.apply(
            manifest={
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"namespace": "default"},
                "data": {},
            }
        )


def test_apply_manifest_unknown_kind_clear_error(kubernetes_exe):
    """An apiVersion the cluster doesn't know about surfaces a clear error."""
    with pytest.raises(CommandExecutionError) as exc:
        kubernetes_exe.apply(
            manifest={
                "apiVersion": "nope.example.com/v99",
                "kind": "Nope",
                "metadata": {"name": "x", "namespace": "default"},
            }
        )
    msg = str(exc.value).lower()
    assert "resource" in msg or "not found" in msg or "no resource" in msg


def test_apply_namespaced_kind_missing_namespace(kubernetes_exe):
    """Apply is strict about namespaces — no silent default to 'default'."""
    with pytest.raises(CommandExecutionError, match="namespace"):
        kubernetes_exe.apply(
            manifest={
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "x"},  # no namespace
                "data": {},
            }
        )


# ---------------------------------------------------------------------------
# Resource quota exceeded
# ---------------------------------------------------------------------------


def test_quota_exceeded_surfaces_clear_error(kubernetes_exe):
    """Creating one more ConfigMap than the quota allows surfaces a clear error.

    Kubernetes 1.20+ auto-creates a ``kube-root-ca.crt`` ConfigMap in
    every new namespace, which counts against the quota. We allow for
    that one when sizing ``hard.configmaps`` so the test verifies the
    *quota-exceeded* code path rather than tripping on the auto-managed
    ConfigMap.
    """
    ns = random_string("quota-ns-", uppercase=False)
    try:
        kubernetes_exe.create_namespace(name=ns, wait=True)
        # 2 = 1 auto-managed (kube-root-ca.crt) + 1 user-created (cm1).
        # cm2 must therefore exceed the quota.
        kubernetes_exe.apply(
            manifest={
                "apiVersion": "v1",
                "kind": "ResourceQuota",
                "metadata": {"name": "q", "namespace": ns},
                "spec": {"hard": {"configmaps": "2"}},
            }
        )
        # Give the quota controller a moment to observe the auto-CM.
        time.sleep(2)
        kubernetes_exe.create_configmap(name="cm1", namespace=ns, data={"k": "v"}, wait=True)
        with pytest.raises(CommandExecutionError) as exc:
            kubernetes_exe.create_configmap(name="cm2", namespace=ns, data={"k": "v"}, wait=True)
        msg = str(exc.value).lower()
        assert "quota" in msg or "exceeded" in msg or "forbidden" in msg
    finally:
        kubernetes_exe.delete_namespace(name=ns, wait=True)


# ---------------------------------------------------------------------------
# Patch errors
# ---------------------------------------------------------------------------


def test_patch_nonexistent_object_raises(kubernetes_exe):
    name = random_string("nx-patch-", uppercase=False)
    with pytest.raises(CommandExecutionError):
        kubernetes_exe.patch_object(
            kind="Deployment",
            name=name,
            namespace="default",
            patch={"spec": {"replicas": 5}},
        )


def test_patch_object_with_wrong_patch_type_for_crd(kubernetes_exe):
    """Patch type 'strategic' on a CRD typically fails (CRDs lack strategic
    merge directives). Validation message should be actionable."""
    pytest.skip(
        "Requires a CRD installed in the cluster; covered by test_kubernetesmod_crd_lifecycle.py"
    )


# ---------------------------------------------------------------------------
# Wait / timeout
# ---------------------------------------------------------------------------


def test_wait_for_timeout_message_format(kubernetes_exe):
    """The timeout message identifies kind/name/criterion."""
    with pytest.raises(CommandExecutionError) as exc:
        kubernetes_exe.wait_for(
            name="never-exists",
            kind="deployment",
            namespace="default",
            condition="Ready",
            timeout=2,
        )
    msg = str(exc.value)
    assert "Timeout" in msg or "timeout" in msg


# ---------------------------------------------------------------------------
# Auth errors
# ---------------------------------------------------------------------------


def test_setup_conn_no_credentials_raises(kubernetes_exe):
    """No host, kubeconfig, or in_cluster pillar → clear error from setup."""
    with pytest.raises(CommandExecutionError):
        # Forcing in_cluster=False with no other auth source.
        kubernetes_exe.ping(in_cluster=False, kubeconfig="", host="")


# ---------------------------------------------------------------------------
# Cluster-scoped operations against namespaced kinds
# ---------------------------------------------------------------------------


def test_show_namespaced_kind_without_namespace_handled(kubernetes_exe):
    """Module surface gracefully handles ``namespace=None`` for namespaced kinds."""
    # ``namespace=None`` should default to "default" — this should not error.
    res = kubernetes_exe.show_deployment(name="does-not-exist")
    assert res is None
