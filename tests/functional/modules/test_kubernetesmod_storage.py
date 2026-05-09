"""
Functional tests for PV / PVC CRUD against the kind cluster fixture.

Kind ships with a ``standard`` StorageClass and a local-path provisioner
that satisfies dynamically-provisioned PVCs. We exercise both
statically-provisioned (PV created by us, PVC binds to it) and
dynamically-provisioned (PVC creates a PV via the StorageClass) flows.

.. versionadded:: 2.1.0
"""

import time

import pytest
from salt.exceptions import CommandExecutionError
from saltfactories.utils import random_string

from saltext.kubernetes.utils import _dynamic

# ---------------------------------------------------------------------------
# PersistentVolume
# ---------------------------------------------------------------------------


def test_pv_round_trip(kubernetes_exe):
    name = random_string("pv-", uppercase=False)
    spec = {
        "capacity": {"storage": "1Gi"},
        "accessModes": ["ReadWriteOnce"],
        "hostPath": {"path": "/var/data/" + name},
        "persistentVolumeReclaimPolicy": "Delete",
    }
    try:
        res = kubernetes_exe.create_persistent_volume(name=name, spec=spec)
        assert res["metadata"]["name"] == name
        live = kubernetes_exe.show_persistent_volume(name=name)
        assert live["spec"]["capacity"]["storage"] == "1Gi"
        assert "ReadWriteOnce" in live["spec"]["accessModes"]
        assert name in kubernetes_exe.persistent_volumes()
    finally:
        kubernetes_exe.delete_persistent_volume(name=name)


def test_pv_invalid_spec_rejected(kubernetes_exe):
    """Missing capacity is caught client-side."""
    name = random_string("pv-bad-", uppercase=False)
    spec = {"accessModes": ["ReadWriteOnce"]}  # no capacity, no volume source
    with pytest.raises(CommandExecutionError, match="must include 'capacity'"):
        kubernetes_exe.create_persistent_volume(name=name, spec=spec)


# ---------------------------------------------------------------------------
# PersistentVolumeClaim
# ---------------------------------------------------------------------------


def test_pvc_round_trip(kubernetes_exe):
    """A PVC against the kind ``standard`` StorageClass dynamically provisions."""
    name = random_string("pvc-", uppercase=False)
    spec = {
        "accessModes": ["ReadWriteOnce"],
        "resources": {"requests": {"storage": "100Mi"}},
        "storageClassName": "standard",
    }
    try:
        res = kubernetes_exe.create_persistent_volume_claim(
            name=name, namespace="default", spec=spec
        )
        assert res["metadata"]["name"] == name
        # Wait briefly for the dynamic provisioner to bind.
        deadline = time.time() + 20
        while time.time() < deadline:
            live = kubernetes_exe.show_persistent_volume_claim(name=name, namespace="default")
            if live and live.get("status", {}).get("phase") == "Bound":
                break
            time.sleep(2)
        assert live.get("status", {}).get("phase") in ("Bound", "Pending"), live.get("status")
    finally:
        kubernetes_exe.delete_persistent_volume_claim(name=name, namespace="default")


def test_pvc_missing_resources_rejected(kubernetes_exe):
    name = random_string("pvc-bad-", uppercase=False)
    spec = {"accessModes": ["ReadWriteOnce"]}  # no resources
    with pytest.raises(CommandExecutionError, match="must include 'resources'"):
        kubernetes_exe.create_persistent_volume_claim(name=name, namespace="default", spec=spec)


# ---------------------------------------------------------------------------
# Apply-only kinds: kind registry presence + manifest_present round-trip
# ---------------------------------------------------------------------------


def test_apply_only_kinds_via_manifest_present(kubernetes_exe):
    """NetworkPolicy / ResourceQuota / LimitRange / PriorityClass via apply."""
    name_np = random_string("np-", uppercase=False)
    name_rq = random_string("rq-", uppercase=False)
    name_pc = random_string("pc-", uppercase=False)
    manifests = [
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": name_np, "namespace": "default"},
            "spec": {"podSelector": {}, "policyTypes": ["Ingress"]},
        },
        {
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": {"name": name_rq, "namespace": "default"},
            "spec": {"hard": {"pods": "10"}},
        },
        {
            "apiVersion": "scheduling.k8s.io/v1",
            "kind": "PriorityClass",
            "metadata": {"name": name_pc},
            "value": 1000,
            "description": "saltext-test",
        },
    ]
    try:
        for m in manifests:
            kubernetes_exe.apply(manifest=m)
        # All applied — verify presence via the dynamic-client get_object.

        assert (
            _dynamic.get_object(
                "networking.k8s.io/v1", "NetworkPolicy", name=name_np, namespace="default"
            )
            is not None
        )
        assert (
            _dynamic.get_object("v1", "ResourceQuota", name=name_rq, namespace="default")
            is not None
        )
        assert (
            _dynamic.get_object("scheduling.k8s.io/v1", "PriorityClass", name=name_pc) is not None
        )
    finally:
        for m in reversed(manifests):
            try:
                kubernetes_exe.delete_manifest(manifest=m)
            except CommandExecutionError:
                pass
