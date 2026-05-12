"""
Functional tests for ``kubernetes.wait_for`` against a real kind cluster.

Covers the user-driven wait surface added in 2.1.0:

  * ``condition=`` waits on ``status.conditions[*].type``
  * ``jsonpath=`` waits on an arbitrary kubectl-style path
  * Timeout error path is exercised against a never-satisfied predicate

.. versionadded:: 2.1.0
"""

import time

import pytest
from salt.exceptions import CommandExecutionError
from saltfactories.utils import random_string  # pylint: disable=import-outside-toplevel

pytestmark = [pytest.mark.skip_unless_on_linux(reason="kind cluster fixture requires Linux")]


@pytest.fixture
def quick_deployment_spec():
    """A tiny deployment that reaches ``Available=True`` in seconds on kind."""
    return {
        "replicas": 1,
        "selector": {"matchLabels": {"app": "wait-test"}},
        "template": {
            "metadata": {"labels": {"app": "wait-test"}},
            "spec": {
                "containers": [
                    {
                        "name": "pause",
                        "image": "registry.k8s.io/pause:3.9",
                    }
                ]
            },
        },
    }


def test_wait_for_condition_available(kubernetes_exe, quick_deployment_spec):
    """A healthy Deployment satisfies ``condition=Available`` quickly."""
    name = random_string("wait-cond-", uppercase=False)
    kubernetes_exe.create_deployment(
        name=name, namespace="default", metadata={}, spec=quick_deployment_spec, wait=False
    )
    try:
        # Should match within the default timeout; kind reaches Available in
        # well under 60s for a single-replica pause image.
        result = kubernetes_exe.wait_for(
            name=name,
            kind="deployment",
            namespace="default",
            condition="Available",
            timeout=60,
        )
        assert result is True
    finally:
        kubernetes_exe.delete_deployment(name=name, namespace="default", wait=True)


def test_wait_for_jsonpath_cluster_ip(kubernetes_exe):
    """Service ClusterIP is populated synchronously; jsonpath wait returns fast."""
    name = random_string("wait-svc-", uppercase=False)
    spec = {
        "selector": {"app": "wait-test"},
        "ports": [{"port": 80, "targetPort": 80}],
        "type": "ClusterIP",
    }
    kubernetes_exe.create_service(
        name=name, namespace="default", metadata={}, spec=spec, wait=False
    )
    try:
        result = kubernetes_exe.wait_for(
            name=name,
            kind="service",
            namespace="default",
            jsonpath=".spec.clusterIP",
            timeout=30,
        )
        assert result is True
    finally:
        kubernetes_exe.delete_service(name=name, namespace="default", wait=True)


def test_wait_for_timeout_raises(kubernetes_exe, quick_deployment_spec):
    """A condition that never matches raises with a clear message."""
    name = random_string("wait-fail-", uppercase=False)
    kubernetes_exe.create_deployment(
        name=name, namespace="default", metadata={}, spec=quick_deployment_spec, wait=False
    )
    try:
        # Wait for a non-existent condition type; should timeout fast.
        start = time.time()
        with pytest.raises(CommandExecutionError, match="Timeout waiting"):
            kubernetes_exe.wait_for(
                name=name,
                kind="deployment",
                namespace="default",
                condition="DefinitelyNotAReal Condition",
                timeout=5,
            )
        # And actually honoured the timeout (within a generous margin)
        assert time.time() - start < 15
    finally:
        kubernetes_exe.delete_deployment(name=name, namespace="default", wait=True)


def test_wait_for_rejects_both_condition_and_jsonpath(kubernetes_exe):
    """Mutually exclusive — caller must pick one."""
    with pytest.raises(CommandExecutionError, match="either"):
        kubernetes_exe.wait_for(
            name="x",
            kind="deployment",
            namespace="default",
            condition="Available",
            jsonpath=".status.phase",
        )


def test_wait_for_rejects_missing_criteria(kubernetes_exe):
    """At least one of condition / jsonpath is required."""
    with pytest.raises(CommandExecutionError, match="requires"):
        kubernetes_exe.wait_for(name="x", kind="deployment", namespace="default")
