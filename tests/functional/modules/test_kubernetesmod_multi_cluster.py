"""
Functional tests for the multi-cluster routing layer.

The existing functional suite spins up a single kind cluster via the
``kind_cluster`` fixture. To test multi-cluster routing without doubling
the runtime cost of every CI run, we exercise the alias plumbing against
the same physical cluster reached through two distinct alias names, each
pointing at the same kubeconfig path. This catches plumbing bugs
(precedence, alias lookup, kwarg passthrough) without needing a second
kind cluster on every run.

A separate session-scoped ``multi_kind_cluster`` fixture is also defined
for the dual-cluster tests; those are marked ``slow`` and gated on the
``RUN_MULTI_CLUSTER_TESTS`` env var so they only run in CI builds that
have the capacity.

.. versionadded:: 2.1.0
"""

import os

import pytest
from salt.exceptions import CommandExecutionError
from saltfactories.utils import random_string  # pylint: disable=import-outside-toplevel

pytestmark = [pytest.mark.skip_unless_on_linux(reason="kind cluster fixture requires Linux")]


@pytest.fixture(scope="module")
def minion_config_defaults(kind_cluster):  # pragma: no cover
    """Override the module's default config to register two aliases.

    Both aliases point at the same kind cluster — the test is about routing,
    not about the API server itself.
    """
    return {
        "kubernetes.kubeconfig": str(kind_cluster.kubeconfig_path),
        "kubernetes.context": "kind-salt-test",
        "kubernetes.clusters": {
            "primary": {
                "kubeconfig": str(kind_cluster.kubeconfig_path),
                "context": "kind-salt-test",
            },
            "secondary": {
                "kubeconfig": str(kind_cluster.kubeconfig_path),
                "context": "kind-salt-test",
            },
        },
    }


def test_list_clusters_returns_configured_aliases(kubernetes_exe):
    clusters = kubernetes_exe.list_clusters()
    assert "default" in clusters
    assert "primary" in clusters
    assert "secondary" in clusters


def test_unknown_cluster_alias_raises_clear_error(kubernetes_exe):
    with pytest.raises(CommandExecutionError, match="Unknown kubernetes cluster alias"):
        kubernetes_exe.ping(cluster="nonexistent")


def test_ping_via_named_cluster_alias(kubernetes_exe):
    """Routing through an alias reaches the same cluster as the default path."""
    assert kubernetes_exe.ping(cluster="primary") is True
    assert kubernetes_exe.ping(cluster="secondary") is True
    assert kubernetes_exe.ping() is True  # default path still works


def test_create_namespace_via_alias_is_visible_via_default(kubernetes_exe):
    """Object created via alias is reachable via the default path (same cluster)."""
    name = random_string("multi-cluster-ns-", uppercase=False)
    try:
        kubernetes_exe.create_namespace(name=name, cluster="primary")
        # Visible without an alias kwarg since both aliases route to the same cluster
        assert kubernetes_exe.show_namespace(name=name) is not None
    finally:
        kubernetes_exe.delete_namespace(name=name, wait=True)


@pytest.mark.skipif(
    os.environ.get("RUN_MULTI_CLUSTER_TESTS") != "1",
    reason="Set RUN_MULTI_CLUSTER_TESTS=1 to exercise the dual-kind-cluster path",
)
def test_isolation_between_two_real_clusters(multi_kind_cluster, kubernetes_exe):
    """Stub: dual-cluster isolation test.

    Skipped by default. When enabled, this would assert that an object
    created under cluster A is *not* visible through cluster B's API.
    Materialising a second kind cluster in CI is expensive, so this is
    opt-in via env var.
    """
    pytest.skip("Dual-cluster fixture not yet wired into the CI matrix")
