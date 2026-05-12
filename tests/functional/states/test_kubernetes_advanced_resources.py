"""
Functional tests for first-class state coverage of the remaining kinds
called out in issue #14: NetworkPolicy, ResourceQuota, LimitRange,
PriorityClass, CustomResourceDefinition.

Each pair of tests exercises:

  * create-then-show via the typed module function (proof the wrappers
    talk to the API server with the right body)
  * present/absent via the state surface, including ``test=True`` mode

.. versionadded:: 2.1.0
"""

import time

import pytest
from saltfactories.utils import random_string

pytestmark = [pytest.mark.skip_unless_on_linux(reason="kind cluster fixture requires Linux")]


@pytest.fixture
def kubernetes(states):
    return states.kubernetes


# ---------------------------------------------------------------------------
# NetworkPolicy
# ---------------------------------------------------------------------------


def test_network_policy_module_crud(kubernetes_exe):
    name = random_string("np-", uppercase=False)
    spec = {
        "podSelector": {"matchLabels": {"app": "web"}},
        "policyTypes": ["Ingress", "Egress"],
    }
    try:
        res = kubernetes_exe.create_network_policy(name=name, namespace="default", spec=spec)
        assert res["metadata"]["name"] == name
        live = kubernetes_exe.show_network_policy(name=name, namespace="default")
        assert live["spec"]["podSelector"]["matchLabels"] == {"app": "web"}
        assert set(live["spec"]["policyTypes"]) == {"Ingress", "Egress"}
    finally:
        kubernetes_exe.delete_network_policy(name=name, namespace="default")
        assert kubernetes_exe.show_network_policy(name=name, namespace="default") is None


def test_network_policy_state_present_then_absent(kubernetes, kubernetes_exe):
    name = random_string("np-state-", uppercase=False)
    spec = {"podSelector": {}, "policyTypes": ["Ingress"]}
    try:
        ret = kubernetes.network_policy_present(name=name, namespace="default", spec=spec)
        assert ret.result is True
        # Idempotent re-apply reports no change.
        ret2 = kubernetes.network_policy_present(name=name, namespace="default", spec=spec)
        assert ret2.result is True
        assert not ret2.changes
        live = kubernetes_exe.show_network_policy(name=name, namespace="default")
        assert live is not None
    finally:
        ret = kubernetes.network_policy_absent(name=name, namespace="default", wait=True)
        assert ret.result is True
        assert kubernetes_exe.show_network_policy(name=name, namespace="default") is None


# ---------------------------------------------------------------------------
# ResourceQuota
# ---------------------------------------------------------------------------


def test_resource_quota_module_crud(kubernetes_exe):
    ns = random_string("rq-ns-", uppercase=False)
    try:
        kubernetes_exe.create_namespace(name=ns, wait=True)
        name = "rq"
        spec = {"hard": {"pods": "10", "configmaps": "5"}}
        res = kubernetes_exe.create_resource_quota(name=name, namespace=ns, spec=spec)
        assert res["spec"]["hard"]["pods"] == "10"
        live = kubernetes_exe.show_resource_quota(name=name, namespace=ns)
        assert live["spec"]["hard"]["configmaps"] == "5"
        # Patch to a different limit.
        kubernetes_exe.patch_resource_quota(
            name=name, namespace=ns, patch={"spec": {"hard": {"pods": "20"}}}
        )
        # Quota status takes a moment to refresh.
        time.sleep(1)
        live2 = kubernetes_exe.show_resource_quota(name=name, namespace=ns)
        assert live2["spec"]["hard"]["pods"] == "20"
    finally:
        kubernetes_exe.delete_namespace(name=ns, wait=True)


def test_resource_quota_state_present_test_mode(kubernetes, kubernetes_exe):
    ns = random_string("rq-state-", uppercase=False)
    try:
        kubernetes_exe.create_namespace(name=ns, wait=True)
        ret = kubernetes.resource_quota_present(
            name="rq",
            namespace=ns,
            spec={"hard": {"pods": "5"}},
            test=True,
        )
        # Object doesn't exist yet → result=None, would create.
        assert ret.result is None
        assert kubernetes_exe.show_resource_quota(name="rq", namespace=ns) is None
        # Now apply for real.
        ret2 = kubernetes.resource_quota_present(
            name="rq", namespace=ns, spec={"hard": {"pods": "5"}}
        )
        assert ret2.result is True
        assert kubernetes_exe.show_resource_quota(name="rq", namespace=ns) is not None
    finally:
        kubernetes_exe.delete_namespace(name=ns, wait=True)


# ---------------------------------------------------------------------------
# LimitRange
# ---------------------------------------------------------------------------


def test_limit_range_module_crud(kubernetes_exe):
    ns = random_string("lr-ns-", uppercase=False)
    try:
        kubernetes_exe.create_namespace(name=ns, wait=True)
        name = "mem-defaults"
        spec = {
            "limits": [
                {
                    "type": "Container",
                    "default": {"memory": "256Mi"},
                    "defaultRequest": {"memory": "128Mi"},
                }
            ]
        }
        res = kubernetes_exe.create_limit_range(name=name, namespace=ns, spec=spec)
        assert res["metadata"]["name"] == name
        live = kubernetes_exe.show_limit_range(name=name, namespace=ns)
        limit = live["spec"]["limits"][0]
        assert limit["type"] == "Container"
        assert limit["default"]["memory"] == "256Mi"
        assert limit["defaultRequest"]["memory"] == "128Mi"
    finally:
        kubernetes_exe.delete_namespace(name=ns, wait=True)


def test_limit_range_state_idempotency(kubernetes, kubernetes_exe):
    ns = random_string("lr-state-", uppercase=False)
    try:
        kubernetes_exe.create_namespace(name=ns, wait=True)
        spec = {"limits": [{"type": "Pod", "max": {"cpu": "2"}}]}
        ret = kubernetes.limit_range_present(name="lr", namespace=ns, spec=spec)
        assert ret.result is True
        # Same spec applied again is a no-op.
        ret2 = kubernetes.limit_range_present(name="lr", namespace=ns, spec=spec)
        assert ret2.result is True
        assert not ret2.changes
    finally:
        kubernetes_exe.delete_namespace(name=ns, wait=True)


# ---------------------------------------------------------------------------
# PriorityClass (cluster-scoped)
# ---------------------------------------------------------------------------


def test_priority_class_module_crud(kubernetes_exe):
    name = random_string("prio-", uppercase=False)
    try:
        res = kubernetes_exe.create_priority_class(
            name=name,
            spec={
                "value": 1000,
                "description": "Test priority",
                "globalDefault": False,
                "preemptionPolicy": "Never",
            },
        )
        assert res["value"] == 1000
        assert res["preemptionPolicy"] == "Never"
        live = kubernetes_exe.show_priority_class(name=name)
        assert live["description"] == "Test priority"
        # Listing includes the class.
        names = kubernetes_exe.priority_classes()
        assert name in names
    finally:
        kubernetes_exe.delete_priority_class(name=name)
        assert kubernetes_exe.show_priority_class(name=name) is None


def test_priority_class_state_present_then_absent(kubernetes, kubernetes_exe):
    name = random_string("prio-state-", uppercase=False)
    spec = {"value": 5000, "description": "State-driven prio", "globalDefault": False}
    try:
        ret = kubernetes.priority_class_present(name=name, spec=spec)
        assert ret.result is True
        assert kubernetes_exe.show_priority_class(name=name)["value"] == 5000
    finally:
        ret = kubernetes.priority_class_absent(name=name)
        assert ret.result is True
        assert kubernetes_exe.show_priority_class(name=name) is None


# ---------------------------------------------------------------------------
# CustomResourceDefinition (cluster-scoped)
# ---------------------------------------------------------------------------


def _widget_crd_spec(plural, group="example.io"):
    return {
        "group": group,
        "scope": "Namespaced",
        "names": {
            "plural": plural,
            "singular": plural.rstrip("s") or plural,
            "kind": plural.capitalize().rstrip("s") or plural.capitalize(),
            "shortNames": [plural[:3]],
        },
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
                                "properties": {"color": {"type": "string"}},
                            }
                        },
                    }
                },
            }
        ],
    }


def test_custom_resource_definition_module_crud(kubernetes_exe):
    plural = "salttestwidgets"
    crd_name = f"{plural}.example.io"
    try:
        res = kubernetes_exe.create_custom_resource_definition(
            name=crd_name, spec=_widget_crd_spec(plural)
        )
        assert res["metadata"]["name"] == crd_name
        live = kubernetes_exe.show_custom_resource_definition(name=crd_name)
        assert live["spec"]["group"] == "example.io"
        assert live["spec"]["names"]["kind"] == "Salttestwidget"
        listing = kubernetes_exe.custom_resource_definitions()
        assert crd_name in listing
    finally:
        kubernetes_exe.delete_custom_resource_definition(name=crd_name, wait=True)


def test_custom_resource_definition_state_present_then_absent(kubernetes, kubernetes_exe):
    plural = "salttestgizmos"
    crd_name = f"{plural}.example.io"
    spec = _widget_crd_spec(plural)
    try:
        ret = kubernetes.custom_resource_definition_present(name=crd_name, spec=spec)
        assert ret.result is True
        assert kubernetes_exe.show_custom_resource_definition(name=crd_name) is not None
    finally:
        ret = kubernetes.custom_resource_definition_absent(name=crd_name, wait=True)
        assert ret.result is True
        # Deletion may be async due to finalizer; poll briefly.
        for _ in range(30):
            if kubernetes_exe.show_custom_resource_definition(name=crd_name) is None:
                break
            time.sleep(1)
        assert kubernetes_exe.show_custom_resource_definition(name=crd_name) is None


# ---------------------------------------------------------------------------
# Deeper scenarios — prove the kinds actually behave as users expect, not
# just that the API server accepts the body. These tests catch bugs where
# the wrapper succeeds at create-time but the resulting object doesn't
# enforce its intended policy.
# ---------------------------------------------------------------------------


def test_network_policy_with_matchexpressions_selector(kubernetes_exe):
    """A NetworkPolicy with a ``matchExpressions`` podSelector survives
    the wrapper's normalisation and lands on the apiserver intact."""
    name = random_string("np-expr-", uppercase=False)
    spec = {
        "podSelector": {
            "matchExpressions": [{"key": "tier", "operator": "In", "values": ["frontend", "api"]}]
        },
        "policyTypes": ["Ingress"],
    }
    try:
        kubernetes_exe.create_network_policy(name=name, namespace="default", spec=spec)
        live = kubernetes_exe.show_network_policy(name=name, namespace="default")
        exprs = live["spec"]["podSelector"]["matchExpressions"]
        assert exprs[0]["key"] == "tier"
        assert exprs[0]["operator"] == "In"
        assert set(exprs[0]["values"]) == {"frontend", "api"}
    finally:
        kubernetes_exe.delete_network_policy(name=name, namespace="default")


def test_network_policy_with_ingress_rules_and_ports(kubernetes_exe):
    """Ingress rules with ``from`` selectors and ``ports`` round-trip."""
    name = random_string("np-rules-", uppercase=False)
    spec = {
        "podSelector": {"matchLabels": {"app": "api"}},
        "policyTypes": ["Ingress"],
        "ingress": [
            {
                "from": [{"podSelector": {"matchLabels": {"app": "web"}}}],
                "ports": [{"protocol": "TCP", "port": 8080}],
            }
        ],
    }
    try:
        kubernetes_exe.create_network_policy(name=name, namespace="default", spec=spec)
        live = kubernetes_exe.show_network_policy(name=name, namespace="default")
        rule = live["spec"]["ingress"][0]
        assert rule["from"][0]["podSelector"]["matchLabels"] == {"app": "web"}
        assert rule["ports"][0]["port"] == 8080
        assert rule["ports"][0]["protocol"] == "TCP"
    finally:
        kubernetes_exe.delete_network_policy(name=name, namespace="default")


def test_resource_quota_enforces_pod_limit(kubernetes_exe):
    """A ResourceQuota of pods=1 actually rejects the second pod.

    This is the user-visible reason a ResourceQuota exists. If the
    wrapper produced a quota that *looked* right but didn't enforce,
    the kind tests-as-mini-program contract would be broken.
    """
    ns = random_string("rq-enforce-", uppercase=False)
    try:
        kubernetes_exe.create_namespace(name=ns, wait=True)
        # 2 = 1 auto-managed kube-root-ca.crt CM allowance + 1 pod allowance,
        # but configmap quotas count CMs not pods. Apply only to pods here.
        kubernetes_exe.create_resource_quota(
            name="pod-quota", namespace=ns, spec={"hard": {"pods": "1"}}
        )
        time.sleep(2)  # quota controller observes
        kubernetes_exe.create_pod(
            name="first",
            namespace=ns,
            metadata={},
            spec={"containers": [{"name": "pause", "image": "registry.k8s.io/pause:3.9"}]},
        )
        # Second pod must be rejected — quota exhausted.
        from salt.exceptions import CommandExecutionError  # pylint: disable=import-outside-toplevel

        with pytest.raises(CommandExecutionError) as exc:
            kubernetes_exe.create_pod(
                name="second",
                namespace=ns,
                metadata={},
                spec={"containers": [{"name": "pause", "image": "registry.k8s.io/pause:3.9"}]},
            )
        msg = str(exc.value).lower()
        assert "quota" in msg or "forbidden" in msg or "exceeded" in msg
    finally:
        kubernetes_exe.delete_namespace(name=ns, wait=True)


def test_limit_range_applies_defaults_to_new_pod(kubernetes_exe):
    """The kubelet/admission controller applies LimitRange defaults to
    pods created without explicit resource requests.

    This proves the LimitRange wrapper produces an object the admission
    plugin actually honours — not just one the apiserver accepts.
    """
    ns = random_string("lr-defaults-", uppercase=False)
    try:
        kubernetes_exe.create_namespace(name=ns, wait=True)
        kubernetes_exe.create_limit_range(
            name="mem-default",
            namespace=ns,
            spec={
                "limits": [
                    {
                        "type": "Container",
                        "default": {"memory": "64Mi"},
                        "defaultRequest": {"memory": "32Mi"},
                    }
                ]
            },
        )
        time.sleep(1)
        # Pod created without explicit resources.
        kubernetes_exe.create_pod(
            name="dflt-pod",
            namespace=ns,
            metadata={},
            spec={"containers": [{"name": "pause", "image": "registry.k8s.io/pause:3.9"}]},
        )
        live = kubernetes_exe.show_pod(name="dflt-pod", namespace=ns)
        resources = live["spec"]["containers"][0].get("resources") or {}
        # LimitRange admission should have injected default + defaultRequest.
        assert resources.get("limits", {}).get("memory") == "64Mi"
        assert resources.get("requests", {}).get("memory") == "32Mi"
    finally:
        kubernetes_exe.delete_namespace(name=ns, wait=True)


def test_priority_class_assigned_to_pod_reaches_scheduler(kubernetes_exe):
    """A pod that references a PriorityClass gets its ``.priority`` value
    populated by the scheduler / admission controller.

    Verifies the typed PriorityClass wrapper produces a usable object —
    not just one that round-trips through the apiserver.
    """
    pc_name = random_string("prio-pod-", uppercase=False)
    pod_name = random_string("prio-pod-app-", uppercase=False)
    try:
        kubernetes_exe.create_priority_class(
            name=pc_name,
            spec={
                "value": 12345,
                "description": "Test prio for pod",
                "globalDefault": False,
                "preemptionPolicy": "Never",
            },
        )
        kubernetes_exe.create_pod(
            name=pod_name,
            namespace="default",
            metadata={},
            spec={
                "priorityClassName": pc_name,
                "containers": [{"name": "pause", "image": "registry.k8s.io/pause:3.9"}],
            },
        )
        # Apiserver fills ``.spec.priority`` from the named PriorityClass.
        live = kubernetes_exe.show_pod(name=pod_name, namespace="default")
        assert live["spec"]["priority"] == 12345
        assert live["spec"].get("preemptionPolicy") == "Never"
    finally:
        kubernetes_exe.delete_pod(name=pod_name, namespace="default", wait=True)
        kubernetes_exe.delete_priority_class(name=pc_name)


def test_custom_resource_definition_then_create_cr(kubernetes_exe):
    """The typed CRD wrapper produces a CRD that accepts CRs.

    End-to-end: install via the typed wrapper, wait for SSA route, apply
    a CR via the generic ``apply`` path. If the wrapper builds a broken
    CRD, the CR apply fails — proving the wrapper's contract reaches
    user-visible behaviour.
    """
    plural = "saltcrwidgets"
    crd_name = f"{plural}.example.io"
    cr_name = random_string("cr-", uppercase=False)
    try:
        kubernetes_exe.create_custom_resource_definition(
            name=crd_name,
            spec={
                "group": "example.io",
                "scope": "Namespaced",
                "names": {
                    "plural": plural,
                    "singular": "saltcrwidget",
                    "kind": "SaltCRWidget",
                    "shortNames": ["scrw"],
                },
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
        )
        # Wait for SSA route to come up (Established + handler wired).
        from saltext.kubernetes.utils import _dynamic  # pylint: disable=import-outside-toplevel

        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                _dynamic.apply_manifest(
                    {
                        "apiVersion": "example.io/v1",
                        "kind": "SaltCRWidget",
                        "metadata": {"name": "probe", "namespace": "default"},
                        "spec": {"size": "tiny"},
                    },
                    dry_run=True,
                )
                break
            except Exception:  # pylint: disable=broad-except
                _dynamic.invalidate_caches()
                time.sleep(1)
        else:
            pytest.fail("CRD SSA route never came up")

        # Now create a real CR through the generic apply path.
        kubernetes_exe.apply(
            manifest={
                "apiVersion": "example.io/v1",
                "kind": "SaltCRWidget",
                "metadata": {"name": cr_name, "namespace": "default"},
                "spec": {"size": "small"},
            }
        )
        live = _dynamic.get_object(
            "example.io/v1", "SaltCRWidget", name=cr_name, namespace="default"
        )
        assert live is not None
        assert live["spec"]["size"] == "small"
    finally:
        try:
            kubernetes_exe.delete_manifest(
                manifest={
                    "apiVersion": "example.io/v1",
                    "kind": "SaltCRWidget",
                    "metadata": {"name": cr_name, "namespace": "default"},
                }
            )
        except Exception:  # pylint: disable=broad-except
            pass
        kubernetes_exe.delete_custom_resource_definition(name=crd_name, wait=True)


def test_priority_class_state_idempotency(kubernetes, kubernetes_exe):
    """Re-applying an unchanged PriorityClass spec is a no-op."""
    name = random_string("prio-idem-", uppercase=False)
    spec = {"value": 7000, "description": "Idempotency check"}
    try:
        ret1 = kubernetes.priority_class_present(name=name, spec=spec)
        assert ret1.result is True
        ret2 = kubernetes.priority_class_present(name=name, spec=spec)
        assert ret2.result is True
        assert not ret2.changes
    finally:
        kubernetes.priority_class_absent(name=name)


def test_resource_quota_state_idempotency(kubernetes, kubernetes_exe):
    """Re-applying an unchanged ResourceQuota spec is a no-op."""
    ns = random_string("rq-idem-", uppercase=False)
    spec = {"hard": {"pods": "5"}}
    try:
        kubernetes_exe.create_namespace(name=ns, wait=True)
        ret1 = kubernetes.resource_quota_present(name="rq", namespace=ns, spec=spec)
        assert ret1.result is True
        ret2 = kubernetes.resource_quota_present(name="rq", namespace=ns, spec=spec)
        assert ret2.result is True
        assert not ret2.changes
    finally:
        kubernetes_exe.delete_namespace(name=ns, wait=True)


def test_network_policy_state_test_mode_reports_pending_change(kubernetes, kubernetes_exe):
    """``test=True`` on a present-state for a missing object reports result=None."""
    name = random_string("np-test-", uppercase=False)
    spec = {"podSelector": {}, "policyTypes": ["Ingress"]}
    try:
        ret = kubernetes.network_policy_present(
            name=name, namespace="default", spec=spec, test=True
        )
        assert ret.result is None
        # And the object was NOT persisted.
        assert kubernetes_exe.show_network_policy(name=name, namespace="default") is None
    finally:
        kubernetes_exe.delete_network_policy(name=name, namespace="default")


def test_custom_resource_definition_state_idempotency(kubernetes, kubernetes_exe):
    """Re-applying an unchanged CRD spec is a no-op."""
    plural = "saltidemwidgets"
    crd_name = f"{plural}.example.io"
    spec = _widget_crd_spec(plural)
    try:
        ret1 = kubernetes.custom_resource_definition_present(name=crd_name, spec=spec)
        assert ret1.result is True
        ret2 = kubernetes.custom_resource_definition_present(name=crd_name, spec=spec)
        assert ret2.result is True
        assert not ret2.changes
    finally:
        kubernetes.custom_resource_definition_absent(name=crd_name, wait=True)
        # Poll for actual disappearance.
        for _ in range(30):
            if kubernetes_exe.show_custom_resource_definition(name=crd_name) is None:
                break
            time.sleep(1)
