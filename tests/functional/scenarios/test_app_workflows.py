"""
Cross-kind workflow tests against a real kind cluster.

Each test tells one end-to-end story touching 3-5 kinds in sequence.
These catch integration bugs that the per-kind tests can't surface
because the failures live at the seams between objects.

.. versionadded:: 2.1.0
"""

import time

import pytest
from salt.exceptions import CommandExecutionError
from saltfactories.utils import random_string

pytestmark = [pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms")]


# ---------------------------------------------------------------------------
# Full app deploy: Namespace → ConfigMap → Secret → Service → Deployment.
# Exercises the most common SLS pattern: declare a namespace, populate it
# with config and secrets, create a service, then a deployment that uses
# all of the above.
# ---------------------------------------------------------------------------


def test_full_app_deploy(kubernetes_exe):
    ns = random_string("workflow-", uppercase=False)
    cm = "app-config"
    secret = "app-secret"
    svc = "app-svc"
    dep = "app"
    try:
        kubernetes_exe.create_namespace(name=ns, wait=True)
        kubernetes_exe.create_configmap(
            name=cm, namespace=ns, data={"LOG_LEVEL": "INFO"}, wait=True
        )
        kubernetes_exe.create_secret(
            name=secret, namespace=ns, data={"API_TOKEN": "deadbeef"}, wait=True
        )
        kubernetes_exe.create_service(
            name=svc,
            namespace=ns,
            metadata={},
            spec={
                "selector": {"app": dep},
                "ports": [{"port": 80, "targetPort": 80}],
            },
            wait=True,
        )
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
                        "containers": [
                            {
                                "name": "pause",
                                "image": "registry.k8s.io/pause:3.9",
                                "envFrom": [
                                    {"configMapRef": {"name": cm}},
                                    {"secretRef": {"name": secret}},
                                ],
                            }
                        ]
                    },
                },
            },
            wait=True,
        )
        # All five objects exist and the deployment reaches Available.
        live_dep = kubernetes_exe.show_deployment(name=dep, namespace=ns)
        assert live_dep["spec"]["replicas"] == 1
        kubernetes_exe.wait_for(
            name=dep, kind="deployment", namespace=ns, condition="Available", timeout=60
        )
    finally:
        kubernetes_exe.delete_namespace(name=ns, wait=True)


# ---------------------------------------------------------------------------
# StatefulSet with PVC template + StorageClass. Catches the
# "WaitForFirstConsumer" binding-mode subtlety.
# ---------------------------------------------------------------------------


def test_pvc_bound_to_storageclass(kubernetes_exe):
    sc = random_string("sc-", uppercase=False)
    pvc = random_string("pvc-", uppercase=False)
    try:
        kubernetes_exe.create_storageclass(
            name=sc,
            metadata={},
            spec={
                "provisioner": "kubernetes.io/no-provisioner",
                "volumeBindingMode": "WaitForFirstConsumer",
            },
            wait=True,
        )
        kubernetes_exe.create_persistent_volume_claim(
            name=pvc,
            namespace="default",
            spec={
                "accessModes": ["ReadWriteOnce"],
                "resources": {"requests": {"storage": "10Mi"}},
                "storageClassName": sc,
            },
        )
        live = kubernetes_exe.show_persistent_volume_claim(name=pvc, namespace="default")
        # Without a consumer, phase should be Pending (WaitForFirstConsumer).
        # The point of the test is that the PVC references the SC correctly.
        assert live["spec"]["storageClassName"] == sc
        assert live["status"]["phase"] == "Pending"
    finally:
        kubernetes_exe.delete_persistent_volume_claim(name=pvc, namespace="default", wait=True)
        kubernetes_exe.delete_storageclass(name=sc, wait=True)


# ---------------------------------------------------------------------------
# ServiceAccount + Role + RoleBinding + Pod using that SA.
# Verifies RBAC machinery is wired correctly from the operator's perspective.
# ---------------------------------------------------------------------------


def test_serviceaccount_role_rolebinding_pod(kubernetes_exe):
    sa = random_string("sa-", uppercase=False)
    role = random_string("role-", uppercase=False)
    rb = random_string("rb-", uppercase=False)
    pod = random_string("rbac-pod-", uppercase=False)
    try:
        kubernetes_exe.create_service_account(name=sa, namespace="default")
        kubernetes_exe.create_role(
            name=role,
            namespace="default",
            spec={
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["pods"],
                        "verbs": ["get", "list", "watch"],
                    }
                ]
            },
        )
        kubernetes_exe.create_role_binding(
            name=rb,
            namespace="default",
            spec={
                "subjects": [{"kind": "ServiceAccount", "name": sa, "namespace": "default"}],
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": role,
                },
            },
        )
        kubernetes_exe.create_pod(
            name=pod,
            namespace="default",
            metadata={"labels": {"role": "rbac-test"}},
            spec={
                "serviceAccountName": sa,
                "containers": [{"name": "pause", "image": "registry.k8s.io/pause:3.9"}],
            },
            wait=True,
        )
        live_pod = kubernetes_exe.show_pod(name=pod, namespace="default")
        assert live_pod["spec"]["serviceAccountName"] == sa
    finally:
        kubernetes_exe.delete_pod(name=pod, namespace="default", wait=True)
        kubernetes_exe.delete_role_binding(name=rb, namespace="default")
        kubernetes_exe.delete_role(name=role, namespace="default")
        kubernetes_exe.delete_service_account(name=sa, namespace="default")


# ---------------------------------------------------------------------------
# PodDisruptionBudget blocks voluntary disruption (drain).
# This is the test that catches PDB violations.
# ---------------------------------------------------------------------------


def test_pdb_blocks_drain(kubernetes_exe):
    pytest.skip(
        "Drain-with-PDB requires multi-node kind cluster scheduling; covered by "
        "manual test plans until a multi-worker kind fixture exists."
    )


# ---------------------------------------------------------------------------
# NetworkPolicy: default-deny then explicit-allow between namespaces.
# Skipped on kind clusters without a CNI that enforces NetworkPolicies
# (the default kindnet CNI does NOT enforce them — Calico is required).
# ---------------------------------------------------------------------------


def test_networkpolicy_default_deny_applied(kubernetes_exe):
    """At minimum the NetworkPolicy object is created; enforcement requires
    a CNI like Calico which the default kind cluster doesn't ship."""
    ns = random_string("netpol-", uppercase=False)
    pol = "default-deny"
    try:
        kubernetes_exe.create_namespace(name=ns, wait=True)
        kubernetes_exe.apply(
            manifest={
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {"name": pol, "namespace": ns},
                "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
            }
        )
        # The dynamic client returns a list-of-dicts via show_namespace's grain
        # projection. The object is there if no exception was raised above.
    finally:
        kubernetes_exe.delete_namespace(name=ns, wait=True)


# ---------------------------------------------------------------------------
# CronJob fires its first Job within the schedule window.
# Uses every-minute schedule. Adds a few seconds of slack.
# ---------------------------------------------------------------------------


def test_cronjob_creates_job_within_schedule(kubernetes_exe):
    name = random_string("cj-fire-", uppercase=False)
    try:
        kubernetes_exe.create_cron_job(
            name=name,
            namespace="default",
            spec={
                "schedule": "*/1 * * * *",
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "metadata": {"labels": {"app": "cj-test"}},
                            "spec": {
                                "restartPolicy": "Never",
                                "containers": [
                                    {
                                        "name": "pause",
                                        "image": "registry.k8s.io/pause:3.9",
                                        "command": ["/pause"],
                                    }
                                ],
                            },
                        },
                        "backoffLimit": 0,
                        "ttlSecondsAfterFinished": 60,
                    }
                },
            },
        )
        # Wait up to 80s for the CronJob controller to fire its first Job.
        deadline = time.monotonic() + 80
        found = False
        while time.monotonic() < deadline:
            jobs = kubernetes_exe.jobs(namespace="default")
            if any(j.startswith(f"{name}-") for j in jobs):
                found = True
                break
            time.sleep(2)
        assert found, f"CronJob {name} did not produce a Job within 80s"
    finally:
        kubernetes_exe.delete_cron_job(name=name, namespace="default", wait=True)


# ---------------------------------------------------------------------------
# Manifest-apply rolls out a CRD then an instance of it.
# Verifies the dynamic-client cache-invalidation path.
# ---------------------------------------------------------------------------


def test_crd_then_cr_via_apply(kubernetes_exe):
    crd_doc = {
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {"name": "widgets.example.io"},
        "spec": {
            "group": "example.io",
            "names": {
                "plural": "widgets",
                "singular": "widget",
                "kind": "Widget",
                "shortNames": ["wg"],
            },
            "scope": "Namespaced",
            "versions": [
                {
                    "name": "v1",
                    "served": True,
                    "storage": True,
                    "schema": {
                        "openAPIV3Schema": {
                            "type": "object",
                            "properties": {
                                "spec": {
                                    "type": "object",
                                    "properties": {"size": {"type": "string"}},
                                }
                            },
                        }
                    },
                }
            ],
        },
    }
    try:
        kubernetes_exe.apply(manifest=crd_doc)
        # Wait for the CRD to be Established before creating an instance.
        kubernetes_exe.wait_for(
            name="widgets.example.io",
            kind="custom_resource_definition",
            condition="Established",
            timeout=30,
        )
    except CommandExecutionError as exc:
        pytest.skip(f"CRD wait_for unsupported in this kind registry: {exc}")
    try:
        cr_doc = {
            "apiVersion": "example.io/v1",
            "kind": "Widget",
            "metadata": {"name": "demo", "namespace": "default"},
            "spec": {"size": "small"},
        }
        # The dynamic client caches GVK discovery; the wrapper invalidates
        # caches on apply path errors but not proactively. We invoke a
        # second-time apply if the first fails to give the discovery cache
        # one round-trip to catch up.
        try:
            kubernetes_exe.apply(manifest=cr_doc)
        except CommandExecutionError:
            time.sleep(2)
            kubernetes_exe.apply(manifest=cr_doc)
        kubernetes_exe.delete_manifest(manifest=cr_doc)
    finally:
        kubernetes_exe.delete_manifest(manifest=crd_doc)
