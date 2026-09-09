"""Regression coverage for Service port fields being silently dropped.

These tests guard against a subtle bug in ``__dict_to_service_spec`` where
``targetPort`` and ``nodePort`` were validated but then lost when copied onto the
underlying ``V1ServicePort`` object. Kubernetes exposes the port attributes as
snake_case names, so the check must translate camelCase keys before setting the
attribute.

Without this regression, a Service can be created successfully while sending
traffic to the wrong backend port because Kubernetes defaults missing
``targetPort`` values to the Service ``port``.
"""

from textwrap import dedent

import pytest


@pytest.mark.parametrize("service", [False], indirect=True)
def test_service_present_preserves_target_port(kubernetes, service, kubernetes_exe):
    """targetPort must reach the API, not be defaulted to port."""
    ret = kubernetes.service_present(
        name=service["name"],
        namespace=service["namespace"],
        metadata={},
        spec={
            "type": "ClusterIP",
            "selector": {"app": "target-port"},
            "ports": [{"port": 3389, "targetPort": 22, "protocol": "TCP"}],
        },
    )

    assert ret.result is True
    live = kubernetes_exe.show_service(name=service["name"], namespace=service["namespace"])
    port = live["spec"]["ports"][0]
    assert port["port"] == 3389
    assert port["targetPort"] == 22, "targetPort was dropped and defaulted to port"


@pytest.mark.parametrize("service", [False], indirect=True)
def test_service_present_preserves_named_target_port(kubernetes, service, kubernetes_exe):
    """A string targetPort refers to a container port by name and must survive."""
    ret = kubernetes.service_present(
        name=service["name"],
        namespace=service["namespace"],
        metadata={},
        spec={
            "selector": {"app": "named-target"},
            "ports": [{"port": 8080, "targetPort": "http"}],
        },
    )

    assert ret.result is True
    live = kubernetes_exe.show_service(name=service["name"], namespace=service["namespace"])
    assert live["spec"]["ports"][0]["targetPort"] == "http"


@pytest.mark.parametrize("service", [False], indirect=True)
def test_service_present_from_source_is_idempotent(kubernetes, service, state_tree, kubernetes_exe):
    """A dropped field also means the state can never converge."""
    sls = "k8s/service-target-port"
    contents = dedent(f"""
        apiVersion: v1
        kind: Service
        metadata:
          name: {service["name"]}
          namespace: {service["namespace"]}
        spec:
          type: ClusterIP
          selector:
            app: converge
          ports:
            - port: 3389
              targetPort: 22
              protocol: TCP
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
