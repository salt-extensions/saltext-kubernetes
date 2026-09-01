"""Regression test for top-level Service spec keys being silently dropped.

DEFECT
------
``__dict_to_service_spec`` copies every spec key other than ``ports`` like
this::

    elif hasattr(spec_obj, key):
        setattr(spec_obj, key, value)

``V1ServiceSpec`` exposes snake_case attributes (``cluster_ip``,
``session_affinity``, ``external_traffic_policy``, ...), so
``hasattr(spec_obj, "clusterIP")`` is ``False`` and the value is discarded --
the same class of bug as the ``targetPort``/``nodePort`` drop inside the ports
loop (fixed separately), just one level up.

IMPACT
------
Any manifest written in the documented camelCase spelling silently loses
spec-level fields. The sharpest case is a headless Service: ``clusterIP: None``
is the field that makes a Service headless (required for StatefulSet pod DNS).
Dropping it produces an ordinary ClusterIP Service instead -- the resource is
created successfully and looks plausible, but StatefulSet pod-level DNS
resolution breaks.

FIX
---
Try the key as-is first (covers already-snake_case callers), then fall back to
``_camel_to_snake(key)``, before the ``hasattr``/``setattr`` pair -- mirroring
the fix already applied to the ports loop.
"""

from textwrap import dedent

import pytest


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
    """A dropped clusterIP also means the state can never converge."""
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
