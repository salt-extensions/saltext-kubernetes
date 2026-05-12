"""
Real-isolation multi-cluster tests using two distinct kind clusters.

Gated by ``RUN_MULTI_CLUSTER_TESTS=1`` because materialising a second kind
cluster on every CI run is wasteful. When enabled, these tests verify
that the alias-routing code truly targets independent clusters — an
object on cluster A is not visible on cluster B, and the auth context
for each call uses the matching kubeconfig.

.. versionadded:: 2.1.0
"""

import pytest
from saltfactories.utils import random_string

pytestmark = [pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms")]


@pytest.fixture(scope="module")
def minion_config_defaults(kind_cluster, multi_kind_cluster):  # pragma: no cover
    """Wire both kind clusters as distinct aliases on the minion."""
    return {
        # Default path → primary cluster
        "kubernetes.kubeconfig": str(kind_cluster.kubeconfig_path),
        "kubernetes.context": "kind-salt-test",
        # Named aliases
        "kubernetes.clusters": {
            "primary": {
                "kubeconfig": str(kind_cluster.kubeconfig_path),
                "context": multi_kind_cluster["primary_context"],
            },
            "secondary": {
                "kubeconfig": multi_kind_cluster["secondary_kubeconfig"],
                "context": multi_kind_cluster["secondary_context"],
            },
        },
    }


def test_object_created_on_primary_not_visible_on_secondary(kubernetes_exe):
    """Namespace created via cluster=primary is absent on cluster=secondary."""
    name = random_string("isol-", uppercase=False)
    try:
        kubernetes_exe.create_namespace(name=name, cluster="primary", wait=True)
        # Visible on primary
        assert kubernetes_exe.show_namespace(name=name, cluster="primary") is not None
        # Invisible on secondary
        assert kubernetes_exe.show_namespace(name=name, cluster="secondary") is None
    finally:
        kubernetes_exe.delete_namespace(name=name, cluster="primary", wait=True)


def test_object_created_on_secondary_not_visible_on_primary(kubernetes_exe):
    name = random_string("isol-2-", uppercase=False)
    try:
        kubernetes_exe.create_namespace(name=name, cluster="secondary", wait=True)
        assert kubernetes_exe.show_namespace(name=name, cluster="secondary") is not None
        assert kubernetes_exe.show_namespace(name=name, cluster="primary") is None
    finally:
        kubernetes_exe.delete_namespace(name=name, cluster="secondary", wait=True)


def test_default_alias_targets_primary(kubernetes_exe):
    """The legacy non-aliased path targets the primary kubeconfig."""
    name = random_string("isol-default-", uppercase=False)
    try:
        # No cluster= kwarg
        kubernetes_exe.create_namespace(name=name, wait=True)
        # Visible without the alias kwarg
        assert kubernetes_exe.show_namespace(name=name) is not None
        # And visible explicitly via primary
        assert kubernetes_exe.show_namespace(name=name, cluster="primary") is not None
        # But not visible on secondary
        assert kubernetes_exe.show_namespace(name=name, cluster="secondary") is None
    finally:
        kubernetes_exe.delete_namespace(name=name, wait=True)


def test_concurrent_calls_to_different_clusters(kubernetes_exe):
    """Two same-thread calls to different clusters route independently."""
    n_a = random_string("concur-a-", uppercase=False)
    n_b = random_string("concur-b-", uppercase=False)
    try:
        kubernetes_exe.create_namespace(name=n_a, cluster="primary", wait=True)
        kubernetes_exe.create_namespace(name=n_b, cluster="secondary", wait=True)
        # Each is visible only on its own cluster
        assert kubernetes_exe.show_namespace(name=n_a, cluster="primary") is not None
        assert kubernetes_exe.show_namespace(name=n_a, cluster="secondary") is None
        assert kubernetes_exe.show_namespace(name=n_b, cluster="primary") is None
        assert kubernetes_exe.show_namespace(name=n_b, cluster="secondary") is not None
    finally:
        kubernetes_exe.delete_namespace(name=n_a, cluster="primary", wait=True)
        kubernetes_exe.delete_namespace(name=n_b, cluster="secondary", wait=True)


def test_list_clusters_returns_both_aliases(kubernetes_exe):
    clusters = kubernetes_exe.list_clusters()
    assert "default" in clusters
    assert "primary" in clusters
    assert "secondary" in clusters
