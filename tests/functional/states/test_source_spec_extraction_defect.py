"""Regression tests for sourced manifests of spec-based kinds.

DEFECT
------
``_resolve_rbac_source`` (``modules/kubernetesmod.py``) derived the object spec
from every top-level key except ``apiVersion``/``kind``/``metadata``::

    spec = {k: v for k, v in src_obj.items()
            if k not in ("apiVersion", "kind", "metadata")}

That is correct for the RBAC kinds it was written for, whose fields genuinely sit
at the top level (``rules`` for Role/ClusterRole, ``subjects``/``roleRef`` for the
bindings), and for ServiceAccount and PriorityClass.

It is wrong for every kind that nests its fields under ``spec:``. For those, a
normal Kubernetes manifest yields ``{"spec": {...}}`` -- a dict whose only key is
``spec`` -- instead of the spec contents, so the typed ``__dict_to_*_spec``
validator sees none of the fields it requires.
"""

from textwrap import dedent

import pytest

pytestmark = [
    pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms"),
]


@pytest.fixture
def kubernetes(states):
    """
    Return kubernetes state module
    """
    return states.kubernetes


@pytest.fixture(params=[False, True])
def testmode(request):
    return request.param


@pytest.mark.parametrize("persistent_volume_claim", [False], indirect=True)
def test_persistent_volume_claim_present_from_source_manifest(
    kubernetes, persistent_volume_claim, state_tree, kubernetes_exe
):
    """A PVC manifest declaring accessModes under spec must be accepted."""
    sls = "k8s/pvc-source"
    contents = dedent(f"""
        apiVersion: v1
        kind: PersistentVolumeClaim
        metadata:
          name: {persistent_volume_claim["name"]}
          namespace: {persistent_volume_claim["namespace"]}
        spec:
          accessModes:
            - ReadWriteOnce
          resources:
            requests:
              storage: 1Gi
          storageClassName: standard
        """).strip()

    with pytest.helpers.temp_file(f"{sls}.yml", contents, state_tree):
        ret = kubernetes.persistent_volume_claim_present(
            name=persistent_volume_claim["name"],
            namespace=persistent_volume_claim["namespace"],
            source=f"salt://{sls}.yml",
        )

    assert ret.result is True
    live = kubernetes_exe.show_persistent_volume_claim(
        name=persistent_volume_claim["name"], namespace=persistent_volume_claim["namespace"]
    )
    assert live["spec"]["accessModes"] == ["ReadWriteOnce"]
    assert live["spec"]["resources"]["requests"]["storage"] == "1Gi"


@pytest.mark.parametrize("network_policy", [False], indirect=True)
def test_network_policy_present_from_source_manifest(
    kubernetes, network_policy, state_tree, kubernetes_exe
):
    """The same defect, on a second spec-based kind."""
    sls = "k8s/netpol-source"
    contents = dedent(f"""
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: {network_policy["name"]}
          namespace: {network_policy["namespace"]}
        spec:
          podSelector:
            matchLabels:
              app: guarded
          policyTypes:
            - Ingress
        """).strip()

    with pytest.helpers.temp_file(f"{sls}.yml", contents, state_tree):
        ret = kubernetes.network_policy_present(
            name=network_policy["name"],
            namespace=network_policy["namespace"],
            source=f"salt://{sls}.yml",
        )

    assert ret.result is True
    live = kubernetes_exe.show_network_policy(
        name=network_policy["name"], namespace=network_policy["namespace"]
    )
    assert live["spec"]["podSelector"]["matchLabels"] == {"app": "guarded"}


@pytest.mark.parametrize("role", [False], indirect=True)
def test_role_present_from_source_manifest_still_works(
    kubernetes, role, state_tree, kubernetes_exe
):
    """Guards the other half of the fix: RBAC kinds keep top-level extraction."""
    sls = "k8s/role-source"
    contents = dedent(f"""
        apiVersion: rbac.authorization.k8s.io/v1
        kind: Role
        metadata:
          name: {role["name"]}
          namespace: {role["namespace"]}
        rules:
          - apiGroups: [""]
            resources: ["pods"]
            verbs: ["get", "list"]
        """).strip()

    with pytest.helpers.temp_file(f"{sls}.yml", contents, state_tree):
        ret = kubernetes.role_present(
            name=role["name"],
            namespace=role["namespace"],
            source=f"salt://{sls}.yml",
        )

    assert ret.result is True
    live = kubernetes_exe.show_role(name=role["name"], namespace=role["namespace"])
    assert live["rules"][0]["resources"] == ["pods"]
