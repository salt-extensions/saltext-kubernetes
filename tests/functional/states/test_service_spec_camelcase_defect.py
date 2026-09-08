"""Verify Service states preserve Kubernetes-style spec fields.

These tests cover direct and source-based Service definitions, including
acronym-bearing camelCase fields such as ``clusterIP`` and ordinary camelCase
fields such as ``externalTrafficPolicy``. They also verify that a headless
Service created from a source manifest converges after its first application.
"""

from textwrap import dedent

import pytest

pytestmark = [
    pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms"),
]


@pytest.fixture
def kubernetes(states):
    """Return the Kubernetes state module."""
    return states.kubernetes


@pytest.mark.parametrize("service", [False], indirect=True)
def test_service_present_preserves_cluster_ip_none(kubernetes, service, kubernetes_exe):
    """clusterIP: None must reach the API to make the Service headless."""
    ret = kubernetes.service_present(
        name=service["name"],
        namespace=service["namespace"],
        metadata={},
        spec={
            "clusterIP": "None",
            "selector": {"app": "headless"},
            "ports": [{"port": 27017, "targetPort": 27017}],
        },
    )

    assert ret.result is True
    live = kubernetes_exe.show_service(name=service["name"], namespace=service["namespace"])
    assert live["spec"]["clusterIP"] == "None", "clusterIP was dropped; Service is not headless"


@pytest.mark.parametrize("service", [False], indirect=True)
def test_service_present_preserves_external_traffic_policy(kubernetes, service, kubernetes_exe):
    """A camelCase spec-level field besides clusterIP must also survive."""
    ret = kubernetes.service_present(
        name=service["name"],
        namespace=service["namespace"],
        metadata={},
        spec={
            "type": "NodePort",
            "externalTrafficPolicy": "Local",
            "selector": {"app": "etp"},
            "ports": [{"port": 8080, "targetPort": 8080}],
        },
    )

    assert ret.result is True
    live = kubernetes_exe.show_service(name=service["name"], namespace=service["namespace"])
    assert live["spec"]["externalTrafficPolicy"] == "Local"


@pytest.mark.parametrize("service", [False], indirect=True)
def test_headless_service_from_source_is_idempotent(
    kubernetes, service, state_tree, kubernetes_exe
):
    """A headless Service created from a source manifest must converge."""
    sls = "k8s/service-headless-clusterip"
    contents = dedent(f"""
        apiVersion: v1
        kind: Service
        metadata:
          name: {service["name"]}
          namespace: {service["namespace"]}
        spec:
          clusterIP: None
          selector:
            app: converge-headless
          ports:
            - port: 27017
              targetPort: 27017
        """).strip()

    with pytest.helpers.temp_file(f"{sls}.yml", contents, state_tree):
        first = kubernetes.service_present(
            name=service["name"], namespace=service["namespace"], source=f"salt://{sls}.yml"
        )
        assert first.result is True

        second = kubernetes.service_present(
            name=service["name"], namespace=service["namespace"], source=f"salt://{sls}.yml"
        )

    assert second.result is True
    assert not second.changes, f"service did not converge; still reporting {second.changes}"
