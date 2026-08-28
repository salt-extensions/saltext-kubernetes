"""Regression test for Service targetPort / nodePort being silently dropped.

DEFECT
------
``__dict_to_service_spec`` copies the remaining port attributes like this::

    for port_key, port_value in port.items():
        if port_key != "port":
            if port_key in ["nodePort", "targetPort"]:
                ...validate and coerce port_value...
            if hasattr(kube_port, port_key):
                setattr(kube_port, port_key, port_value)

``V1ServicePort`` exposes snake_case attributes (``target_port``, ``node_port``,
``app_protocol``), so ``hasattr(kube_port, "targetPort")`` is ``False`` and the
value is discarded -- immediately after the code went to the trouble of
validating and coercing it.

IMPACT
------
This fails silently and destructively. Kubernetes defaults ``targetPort`` to
``port`` when it is absent, so the Service is created successfully and looks
plausible, but sends traffic to the wrong container port. A Service declaring
``port: 3389, targetPort: 22`` lands as ``3389 -> 3389``.

The state then never converges: each run re-sends ``targetPort`` and the cluster
keeps reporting the defaulted value, so the resource shows changes on every
single run.

Only manifests using the documented camelCase spelling are affected, which is
every manifest written to the Kubernetes API reference -- so the bug looks like
"the typed Service state is broken" and pushes users to ``manifest_present``.

FIX
---
Translate the key to snake_case with ``_camel_to_snake`` before the
``hasattr``/``setattr`` pair.
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
def test_service_present_from_source_is_idempotent(
    kubernetes, service, state_tree, kubernetes_exe
):
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
