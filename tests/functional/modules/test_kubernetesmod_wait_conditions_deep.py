"""
Deep coverage for ``kubernetes.wait_for`` against a real kind cluster.

The shallow test file (``test_kubernetesmod_wait_conditions.py``) covers
the happy paths; this file targets edge cases:

  * ``status=False`` matching against a deliberately-failing pod
  * Nested jsonpath resolution
  * Cluster-scoped kinds (no namespace)
  * Unknown kind error path
  * Concurrent waits don't interfere
  * Wait against an object that doesn't exist yet (creation race)

.. versionadded:: 2.1.0
"""

import threading
import time

import pytest
from salt.exceptions import CommandExecutionError
from saltfactories.utils import random_string

pytestmark = [pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms")]


@pytest.fixture
def failing_pod_spec():
    """A pod whose image pull will always fail → Ready condition stays False."""
    return {
        "containers": [
            {
                "name": "nonexistent",
                # An image that definitely doesn't exist will fail to pull
                "image": "registry.invalid/saltext-tests/nonexistent:0.0.0",
                "imagePullPolicy": "Always",
            }
        ],
        "restartPolicy": "Never",
    }


def test_wait_for_condition_false_status(kubernetes_exe, failing_pod_spec):
    """A pod with an unpullable image satisfies condition=Ready status=False."""
    name = random_string("wait-false-", uppercase=False)
    kubernetes_exe.create_pod(
        name=name, namespace="default", metadata={}, spec=failing_pod_spec, wait=False
    )
    try:
        # The Ready condition flips to False once image pull fails.
        # Allow a generous timeout for the kubelet to register the failure.
        result = kubernetes_exe.wait_for(
            name=name,
            kind="pod",
            namespace="default",
            condition="Ready",
            status="False",
            timeout=60,
        )
        assert result is True
    finally:
        kubernetes_exe.delete_pod(name=name, namespace="default", wait=True)


def test_wait_for_cluster_scoped_kind_no_namespace(kubernetes_exe):
    """``namespace=None`` works for cluster-scoped kinds (Namespace, Node)."""
    name = random_string("wait-cluster-", uppercase=False)
    kubernetes_exe.create_namespace(name=name, wait=False)
    try:
        # Namespaces have an Active phase, asserted via jsonpath.
        result = kubernetes_exe.wait_for(
            name=name, kind="namespace", jsonpath=".status.phase", value="Active", timeout=20
        )
        assert result is True
    finally:
        kubernetes_exe.delete_namespace(name=name, wait=True)


def test_wait_for_unknown_kind_raises(kubernetes_exe):
    """A kind not in the registry surfaces a clear error before any API call."""
    with pytest.raises(CommandExecutionError, match="Unsupported"):
        kubernetes_exe.wait_for(
            name="x", kind="not_a_real_kind", namespace="default", condition="Ready"
        )


def test_wait_for_concurrent_waits_independent(kubernetes_exe):
    """Two concurrent wait_for calls against different objects don't interfere."""
    a = random_string("concurrent-a-", uppercase=False)
    b = random_string("concurrent-b-", uppercase=False)
    kubernetes_exe.create_namespace(name=a, wait=False)
    kubernetes_exe.create_namespace(name=b, wait=False)
    try:
        results = {}

        def _wait(target):
            try:
                results[target] = kubernetes_exe.wait_for(
                    name=target,
                    kind="namespace",
                    jsonpath=".status.phase",
                    value="Active",
                    timeout=20,
                )
            except Exception as exc:  # pylint: disable=broad-exception-caught
                results[target] = exc

        ta = threading.Thread(target=_wait, args=(a,))
        tb = threading.Thread(target=_wait, args=(b,))
        ta.start()
        tb.start()
        ta.join(30)
        tb.join(30)
        assert results.get(a) is True, f"wait_for({a}) result: {results.get(a)}"
        assert results.get(b) is True, f"wait_for({b}) result: {results.get(b)}"
    finally:
        kubernetes_exe.delete_namespace(name=a, wait=True)
        kubernetes_exe.delete_namespace(name=b, wait=True)


def test_wait_for_object_not_existing_yet(kubernetes_exe):
    """An object created mid-wait satisfies the predicate when it shows up."""
    name = random_string("race-", uppercase=False)

    def _create_after_delay():
        time.sleep(2)
        kubernetes_exe.create_namespace(name=name, wait=False)

    # Start the wait; the watch streams CREATED events as they happen.
    thr = threading.Thread(target=_create_after_delay)
    thr.start()
    try:
        result = kubernetes_exe.wait_for(
            name=name, kind="namespace", jsonpath=".status.phase", value="Active", timeout=20
        )
        assert result is True
    finally:
        thr.join(30)
        kubernetes_exe.delete_namespace(name=name, wait=True)


def test_wait_for_timeout_message_includes_criterion(kubernetes_exe):
    """The timeout error message identifies what we were waiting for."""
    name = random_string("never-match-", uppercase=False)
    kubernetes_exe.create_namespace(name=name, wait=False)
    try:
        with pytest.raises(CommandExecutionError) as excinfo:
            kubernetes_exe.wait_for(
                name=name,
                kind="namespace",
                condition="NeverGonnaHappen",
                timeout=3,
            )
        msg = str(excinfo.value)
        assert "Timeout" in msg
        assert "NeverGonnaHappen" in msg
        assert name in msg
    finally:
        kubernetes_exe.delete_namespace(name=name, wait=True)


def test_wait_for_jsonpath_nested_resolution(kubernetes_exe):
    """Deeply-nested jsonpath resolves on a Service's status."""
    name = random_string("nested-svc-", uppercase=False)
    kubernetes_exe.create_service(
        name=name,
        namespace="default",
        metadata={},
        spec={"selector": {"app": "x"}, "ports": [{"port": 80, "targetPort": 80}]},
        wait=False,
    )
    try:
        # Service has spec.clusterIP populated synchronously by the API server.
        result = kubernetes_exe.wait_for(
            name=name,
            kind="service",
            namespace="default",
            jsonpath=".spec.clusterIP",
            regex=r"^\d+\.\d+\.\d+\.\d+$",
            timeout=10,
        )
        assert result is True
    finally:
        kubernetes_exe.delete_service(name=name, namespace="default", wait=True)
