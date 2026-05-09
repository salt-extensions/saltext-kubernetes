"""
Functional tests for Ingress / HPA / PDB CRUD against the kind cluster
fixture.

The kind cluster doesn't ship with an ingress controller or
metrics-server, so we test the API surface (create, show, list,
patch, delete) without expecting the resources to actually become
operational. Operational behaviour (LoadBalancer IP for Ingress,
metric collection for HPA) is covered by integration tests against
clusters that have those components installed.

.. versionadded:: 2.1.0
"""

import pytest
from salt.exceptions import CommandExecutionError
from saltfactories.utils import random_string

# ---------------------------------------------------------------------------
# Ingress
# ---------------------------------------------------------------------------


def test_ingress_round_trip(kubernetes_exe):
    """
    Note: nested rule / path / backend dicts use the *wire* (camelCase)
    field names. The spec helper only translates top-level fields like
    ``ingressClassName`` to snake_case kwargs. Recursively wrapping
    every nested object in its V1* class would be the alternative and
    is a future improvement.
    """
    name = random_string("ing-", uppercase=False)
    spec = {
        "rules": [
            {
                "host": "example.com",
                "http": {
                    "paths": [
                        {
                            "path": "/",
                            "pathType": "Prefix",
                            "backend": {
                                "service": {
                                    "name": "my-svc",
                                    "port": {"number": 80},
                                }
                            },
                        }
                    ]
                },
            }
        ]
    }
    try:
        res = kubernetes_exe.create_ingress(name=name, namespace="default", spec=spec)
        assert res["metadata"]["name"] == name
        live = kubernetes_exe.show_ingress(name=name, namespace="default")
        assert live["spec"]["rules"][0]["host"] == "example.com"
        assert name in kubernetes_exe.ingresses(namespace="default")
    finally:
        kubernetes_exe.delete_ingress(name=name, namespace="default")


# ---------------------------------------------------------------------------
# HPA
# ---------------------------------------------------------------------------


@pytest.fixture
def hpa_target_deployment(kubernetes_exe):
    """Create a Deployment for the HPA to point at; clean up on teardown."""
    name = random_string("hpa-target-", uppercase=False)
    spec = {
        "replicas": 1,
        "selector": {"matchLabels": {"app": name}},
        "template": {
            "metadata": {"labels": {"app": name}},
            "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
        },
    }
    kubernetes_exe.create_deployment(
        name=name, namespace="default", metadata={}, spec=spec, wait=True
    )
    try:
        yield name
    finally:
        kubernetes_exe.delete_deployment(name=name, namespace="default", wait=True)


def test_hpa_round_trip(kubernetes_exe, hpa_target_deployment):
    name = random_string("hpa-", uppercase=False)
    spec = {
        "scaleTargetRef": {
            "api_version": "apps/v1",
            "kind": "Deployment",
            "name": hpa_target_deployment,
        },
        "minReplicas": 2,
        "maxReplicas": 5,
        "metrics": [
            {
                "type": "Resource",
                "resource": {
                    "name": "cpu",
                    "target": {"type": "Utilization", "averageUtilization": 70},
                },
            }
        ],
    }
    try:
        res = kubernetes_exe.create_horizontal_pod_autoscaler(
            name=name, namespace="default", spec=spec
        )
        assert res["metadata"]["name"] == name
        live = kubernetes_exe.show_horizontal_pod_autoscaler(name=name, namespace="default")
        assert live["spec"]["minReplicas"] == 2
        assert live["spec"]["maxReplicas"] == 5
        assert name in kubernetes_exe.horizontal_pod_autoscalers(namespace="default")
    finally:
        kubernetes_exe.delete_horizontal_pod_autoscaler(name=name, namespace="default")


def test_hpa_patch_changes_max_replicas(kubernetes_exe, hpa_target_deployment):
    name = random_string("hpa-pat-", uppercase=False)
    spec = {
        "scaleTargetRef": {
            "api_version": "apps/v1",
            "kind": "Deployment",
            "name": hpa_target_deployment,
        },
        "minReplicas": 1,
        "maxReplicas": 3,
    }
    try:
        kubernetes_exe.create_horizontal_pod_autoscaler(name=name, namespace="default", spec=spec)
        kubernetes_exe.patch_horizontal_pod_autoscaler(
            name=name, namespace="default", patch={"spec": {"maxReplicas": 10}}
        )
        live = kubernetes_exe.show_horizontal_pod_autoscaler(name=name, namespace="default")
        assert live["spec"]["maxReplicas"] == 10
    finally:
        kubernetes_exe.delete_horizontal_pod_autoscaler(name=name, namespace="default")


# ---------------------------------------------------------------------------
# PodDisruptionBudget
# ---------------------------------------------------------------------------


def test_pdb_round_trip(kubernetes_exe):
    name = random_string("pdb-", uppercase=False)
    spec = {
        "minAvailable": 1,
        "selector": {"match_labels": {"app": "nonexistent-just-for-pdb"}},
    }
    try:
        res = kubernetes_exe.create_pod_disruption_budget(name=name, namespace="default", spec=spec)
        assert res["metadata"]["name"] == name
        live = kubernetes_exe.show_pod_disruption_budget(name=name, namespace="default")
        assert live["spec"]["minAvailable"] == 1
        assert name in kubernetes_exe.pod_disruption_budgets(namespace="default")
    finally:
        kubernetes_exe.delete_pod_disruption_budget(name=name, namespace="default")


def test_pdb_max_unavailable_string_value(kubernetes_exe):
    """``maxUnavailable`` accepts a percent string (kubectl convention)."""
    name = random_string("pdb-pct-", uppercase=False)
    spec = {
        "maxUnavailable": "20%",
        "selector": {"match_labels": {"app": "nonexistent"}},
    }
    try:
        res = kubernetes_exe.create_pod_disruption_budget(name=name, namespace="default", spec=spec)
        assert res["spec"]["maxUnavailable"] == "20%"
    finally:
        kubernetes_exe.delete_pod_disruption_budget(name=name, namespace="default")


def test_pdb_rejects_both_min_and_max(kubernetes_exe):
    name = random_string("pdb-bad-", uppercase=False)
    spec = {
        "minAvailable": 1,
        "maxUnavailable": 1,
        "selector": {"match_labels": {"app": "x"}},
    }
    with pytest.raises(CommandExecutionError, match="cannot include both"):
        kubernetes_exe.create_pod_disruption_budget(name=name, namespace="default", spec=spec)
