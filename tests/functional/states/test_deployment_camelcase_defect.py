"""Regression test for camelCase spec fields on Deployment.

DEFECT
------
``__dict_to_deployment_spec`` passed the caller's dict straight into the typed
constructor::

    return V1DeploymentSpec(**processed_spec)

``V1DeploymentSpec`` takes snake_case keyword arguments, so any top-level spec
field written the way a Kubernetes manifest writes it raises::

    V1DeploymentSpec.__init__() got an unexpected keyword argument
    'revisionHistoryLimit'. Did you mean 'revision_history_limit'?

Affected fields include ``revisionHistoryLimit``, ``progressDeadlineSeconds`` and
``minReadySeconds``.

INCONSISTENCY
-------------
``__dict_to_statefulset_spec`` already ended with
``processed_spec = _normalise_field_map(processed_spec)`` and carries a comment
explaining exactly why. Deployment simply never got the same line, so the two
sibling kinds disagreed about whether a manifest-shaped spec is acceptable.

Nested structures are unaffected either way: ``selector`` and ``template`` are
converted to typed objects before this point and pass through untouched.

FIX
---
Call ``_normalise_field_map`` before constructing ``V1DeploymentSpec``, matching
the StatefulSet path.
"""

from textwrap import dedent

import pytest


@pytest.mark.parametrize("deployment", [False], indirect=True)
def test_deployment_present_accepts_camelcase_spec_fields(kubernetes, deployment, kubernetes_exe):
    """revisionHistoryLimit is valid manifest YAML and must be accepted."""
    ret = kubernetes.deployment_present(
        name=deployment["name"],
        namespace=deployment["namespace"],
        metadata={},
        spec={
            "replicas": 1,
            "revisionHistoryLimit": 3,
            "progressDeadlineSeconds": 120,
            "minReadySeconds": 5,
            "selector": {"matchLabels": {"app": "camel"}},
            "template": {
                "metadata": {"labels": {"app": "camel"}},
                "spec": {"containers": [{"name": "nginx", "image": "nginx:1.27"}]},
            },
        },
    )

    assert ret.result is True
    live = kubernetes_exe.show_deployment(
        name=deployment["name"], namespace=deployment["namespace"]
    )
    assert live["spec"]["revisionHistoryLimit"] == 3
    assert live["spec"]["progressDeadlineSeconds"] == 120
    assert live["spec"]["minReadySeconds"] == 5


@pytest.mark.parametrize("deployment", [False], indirect=True)
def test_deployment_present_from_source_manifest_with_camelcase(
    kubernetes, deployment, state_tree, kubernetes_exe
):
    """The same fields arriving from a manifest file, which is the common case."""
    sls = "k8s/deployment-camelcase"
    contents = dedent(f"""
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: {deployment["name"]}
          namespace: {deployment["namespace"]}
        spec:
          replicas: 1
          revisionHistoryLimit: 7
          selector:
            matchLabels:
              app: camel-src
          template:
            metadata:
              labels:
                app: camel-src
            spec:
              containers:
                - name: nginx
                  image: nginx:1.27
        """).strip()

    with pytest.helpers.temp_file(f"{sls}.yml", contents, state_tree):
        ret = kubernetes.deployment_present(
            name=deployment["name"],
            namespace=deployment["namespace"],
            source=f"salt://{sls}.yml",
        )

    assert ret.result is True
    live = kubernetes_exe.show_deployment(
        name=deployment["name"], namespace=deployment["namespace"]
    )
    assert live["spec"]["revisionHistoryLimit"] == 7
