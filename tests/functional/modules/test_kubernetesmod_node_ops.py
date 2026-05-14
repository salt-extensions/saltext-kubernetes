"""
Functional tests for the node lifecycle ops (cordon, uncordon, taint,
untaint, drain) against the kind cluster fixture.

.. versionadded:: 2.1.0

Drain is exercised against a fresh deployment-managed pod scheduled on
the kind worker node. The kind cluster has DaemonSets (kindnet, kube-
proxy) that drain must skip with ``ignore_daemonsets=True`` (the
default); we verify both that those pods are reported as skipped and
that the deployment's pod is actually evicted.
"""

import time

import pytest
from salt.exceptions import CommandExecutionError
from saltfactories.utils import random_string

pytestmark = [pytest.mark.skip_unless_on_linux(reason="kind cluster fixture requires Linux")]


@pytest.fixture
def worker_node_name(loaders):
    """Pick a worker node from the kind cluster (the first non-control-plane)."""
    nodes = loaders.modules.kubernetes.nodes()
    assert nodes, "kind cluster reported no nodes"
    # kind names worker nodes ``<cluster>-worker``. If only a control-plane
    # exists (single-node), use it — drain still works against it.
    workers = [n for n in nodes if "worker" in n]
    return workers[0] if workers else nodes[0]


# ---------------------------------------------------------------------------
# cordon / uncordon
# ---------------------------------------------------------------------------


def test_cordon_uncordon_round_trip(kubernetes_exe, worker_node_name):
    """
    cordon → unschedulable=True; uncordon → unschedulable absent/False.

    Always uncordon at the end so subsequent tests find a healthy cluster.
    """
    try:
        res = kubernetes_exe.cordon(name=worker_node_name)
        assert (res.get("spec") or {}).get("unschedulable") is True
    finally:
        kubernetes_exe.uncordon(name=worker_node_name)

    final = kubernetes_exe.node(name=worker_node_name)
    # uncordon strips the field via strategic-merge null; either absent
    # or False is acceptable, both meaning "schedulable".
    assert not (final.get("spec") or {}).get("unschedulable", False)


def test_cordon_node_not_found_raises(kubernetes_exe):
    with pytest.raises(CommandExecutionError, match="not found"):
        kubernetes_exe.cordon(name="does-not-exist-1234")


def test_uncordon_node_not_found_raises(kubernetes_exe):
    with pytest.raises(CommandExecutionError, match="not found"):
        kubernetes_exe.uncordon(name="does-not-exist-1234")


# ---------------------------------------------------------------------------
# taint / untaint
# ---------------------------------------------------------------------------


def test_taint_then_untaint(kubernetes_exe, worker_node_name):
    """Add a taint, verify it lands; remove it, verify it's gone."""
    key = "saltext-test/taint"
    try:
        res = kubernetes_exe.taint(
            name=worker_node_name, key=key, effect="NoSchedule", value="true"
        )
        taints = (res.get("spec") or {}).get("taints") or []
        assert any(
            t["key"] == key and t["effect"] == "NoSchedule" and t.get("value") == "true"
            for t in taints
        ), f"taint not found in spec.taints: {taints}"
    finally:
        kubernetes_exe.untaint(name=worker_node_name, key=key)

    final = kubernetes_exe.node(name=worker_node_name)
    final_taints = (final.get("spec") or {}).get("taints") or []
    assert not any(t.get("key") == key for t in final_taints), final_taints


def test_taint_replaces_existing_with_same_key_and_effect(kubernetes_exe, worker_node_name):
    """Re-tainting with the same (key,effect) replaces the value rather than dups."""
    key = "saltext-test/replace"
    try:
        kubernetes_exe.taint(name=worker_node_name, key=key, effect="NoSchedule", value="v1")
        res = kubernetes_exe.taint(name=worker_node_name, key=key, effect="NoSchedule", value="v2")
        taints = (res.get("spec") or {}).get("taints") or []
        matching = [t for t in taints if t["key"] == key and t["effect"] == "NoSchedule"]
        assert len(matching) == 1, f"expected one taint, got {matching}"
        assert matching[0].get("value") == "v2"
    finally:
        kubernetes_exe.untaint(name=worker_node_name, key=key)


def test_taint_invalid_effect_raises(kubernetes_exe, worker_node_name):
    with pytest.raises(CommandExecutionError, match="Invalid taint effect"):
        kubernetes_exe.taint(name=worker_node_name, key="x", effect="not-real")


# ---------------------------------------------------------------------------
# annotations
# ---------------------------------------------------------------------------


def test_node_annotation_add_and_remove(kubernetes_exe, worker_node_name):
    """Adding then removing a node annotation round-trips cleanly."""
    key = "saltext-test/owner"
    try:
        # Snapshot original annotation set so we don't disturb anything else.
        before = kubernetes_exe.node_annotations(name=worker_node_name)
        assert key not in before

        kubernetes_exe.node_add_annotation(
            node_name=worker_node_name,
            annotation_name=key,
            annotation_value="platform",
        )
        after_add = kubernetes_exe.node_annotations(name=worker_node_name)
        assert after_add.get(key) == "platform"
    finally:
        kubernetes_exe.node_remove_annotation(node_name=worker_node_name, annotation_name=key)

    final = kubernetes_exe.node_annotations(name=worker_node_name)
    assert key not in final


def test_node_annotation_update_replaces_value(kubernetes_exe, worker_node_name):
    """Re-adding with a different value updates instead of duplicating."""
    key = "saltext-test/replace"
    try:
        kubernetes_exe.node_add_annotation(
            node_name=worker_node_name, annotation_name=key, annotation_value="v1"
        )
        kubernetes_exe.node_add_annotation(
            node_name=worker_node_name, annotation_name=key, annotation_value="v2"
        )
        live = kubernetes_exe.node_annotations(name=worker_node_name)
        assert live.get(key) == "v2"
    finally:
        kubernetes_exe.node_remove_annotation(node_name=worker_node_name, annotation_name=key)


def test_node_add_annotation_missing_node_raises(kubernetes_exe):
    with pytest.raises(CommandExecutionError, match="not found"):
        kubernetes_exe.node_add_annotation(
            node_name="does-not-exist-1234",
            annotation_name="k",
            annotation_value="v",
        )


# ---------------------------------------------------------------------------
# drain
# ---------------------------------------------------------------------------


def test_drain_evicts_managed_pod_skips_daemonsets(kubernetes_exe, worker_node_name):
    """
    Schedule a Deployment-managed pod on the worker node; drain it; verify
    the pod is reported in ``evicted`` and the kind/kube-proxy DaemonSet
    pods are reported in ``skipped``. Always uncordon the node afterwards.
    """

    name = random_string("drain-test-", uppercase=False)
    deployment_spec = {
        "replicas": 1,
        "selector": {"matchLabels": {"app": name}},
        "template": {
            "metadata": {"labels": {"app": name}},
            "spec": {
                "containers": [{"name": "nginx", "image": "nginx:latest"}],
                # Pin to the specific worker we're about to drain.
                # Note: snake_case here — __dict_to_pod_spec passes the
                # dict straight to V1PodSpec which uses snake_case kwargs.
                "node_selector": {"kubernetes.io/hostname": worker_node_name},
                # No emptyDir, no PVCs — keeps the drain default-safe.
            },
        },
    }
    kubernetes_exe.create_deployment(
        name=name,
        namespace="default",
        metadata={},
        spec=deployment_spec,
        wait=True,
    )

    try:
        # Wait for the pod to actually land on the target node.
        deadline = time.time() + 30
        pod_id = None
        while time.time() < deadline:
            pods_resp = kubernetes_exe.pods("default")
            matching = [p for p in pods_resp if p.startswith(name)]
            if matching:
                show = kubernetes_exe.show_pod(name=matching[0], namespace="default")
                if (
                    show
                    and show.get("spec", {}).get("nodeName") == worker_node_name
                    and show.get("status", {}).get("phase") == "Running"
                ):
                    pod_id = f"default/{matching[0]}"
                    break
            time.sleep(2)
        assert pod_id, "managed pod never reached Running on the target node"

        # Run the drain.
        result = kubernetes_exe.drain(
            name=worker_node_name,
            ignore_daemonsets=True,
            timeout=120,
        )

        assert result["node"] == worker_node_name
        assert pod_id in result["evicted"], (
            f"expected {pod_id} in evicted; got evicted={result['evicted']} "
            f"errors={result['errors']}"
        )
        # kind always has at least kindnet + kube-proxy DaemonSets.
        assert any(
            entry["reason"] == "daemonset" for entry in result["skipped"]
        ), f"expected daemonset entries in skipped: {result['skipped']}"
        # No errors expected for this clean test.
        assert not result["errors"], result["errors"]
    finally:
        # Always uncordon and clean up the deployment, even on failure.
        kubernetes_exe.uncordon(name=worker_node_name)
        kubernetes_exe.delete_deployment(name=name, namespace="default", wait=True)


def test_drain_node_not_found_raises(kubernetes_exe):
    with pytest.raises(CommandExecutionError, match="not found"):
        kubernetes_exe.drain(name="does-not-exist-1234")
