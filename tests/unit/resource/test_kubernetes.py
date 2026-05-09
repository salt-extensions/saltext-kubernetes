"""
Unit tests for ``saltext.kubernetes.resource.kubernetes`` — the
Kubernetes resource type for Salt's resources subsystem.

The plugin is dormant on stock Salt (where ``salt.utils.resources``
isn't shipped) and only "lights up" once a build that includes the
resources branch is in use. These tests verify:

* The dormant ``__virtual__`` behaviour on stock Salt.
* The ID composition and parsing helpers.
* That the lifecycle functions don't NameError when ``__context__``
  isn't injected (the loader injects it; bare-import tests don't).

End-to-end tests against an actual resources-aware Salt build are
gated behind the worktree-existence check in
``tests/integration/test_resource_plugin_against_worktree.py``.
"""

import pytest

from saltext.kubernetes.resource import kubernetes as resource_mod

# ---------------------------------------------------------------------------
# __virtual__ — dormant on stock Salt
# ---------------------------------------------------------------------------


def test_virtual_returns_false_when_resources_subsystem_absent():
    """
    On stock Salt (no salt.utils.resources), ``__virtual__`` returns
    ``(False, <reason>)`` with a clear, actionable message.
    """
    result = resource_mod.__virtual__()
    assert isinstance(result, tuple)
    assert result[0] is False
    assert "resources" in result[1].lower()


def test_virtual_returns_virtualname_when_resources_present(monkeypatch):
    """
    With a stub ``salt.utils.resources`` module on the import path,
    ``__virtual__`` returns the virtualname so the loader registers
    this plugin under the ``kubernetes`` resource type.
    """
    import sys  # pylint: disable=import-outside-toplevel
    import types  # pylint: disable=import-outside-toplevel

    fake_module = types.ModuleType("salt.utils.resources")
    fake_module.pillar_resources_tree = lambda opts: {}  # noqa: ARG005
    monkeypatch.setitem(sys.modules, "salt.utils.resources", fake_module)
    assert resource_mod.__virtual__() == "kubernetes"


# ---------------------------------------------------------------------------
# ID composition / parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kind,namespace,name,expected",
    [
        ("pod", "default", "nginx-abc", "pod:default/nginx-abc"),
        ("deployment", "production", "api", "deployment:production/api"),
        ("node", None, "gke-prod-pool-1", "node:gke-prod-pool-1"),
        ("namespace", None, "kube-system", "namespace:kube-system"),
        # Empty-string namespace treated as cluster-scoped:
        ("priority_class", "", "system-node-critical", "priority_class:system-node-critical"),
    ],
)
def test_make_id(kind, namespace, name, expected):
    assert resource_mod._make_id(kind, namespace, name) == expected


@pytest.mark.parametrize(
    "rid,expected",
    [
        ("pod:default/nginx-abc", ("pod", "default", "nginx-abc")),
        ("deployment:production/api", ("deployment", "production", "api")),
        ("node:gke-prod-pool-1", ("node", None, "gke-prod-pool-1")),
        ("namespace:kube-system", ("namespace", None, "kube-system")),
    ],
)
def test_parse_id(rid, expected):
    assert resource_mod._parse_id(rid) == expected


def test_parse_id_rejects_missing_colon():
    with pytest.raises(ValueError, match="missing ':' kind separator"):
        resource_mod._parse_id("just-a-name")


def test_make_parse_id_round_trip():
    """make → parse → make must produce the same ID for any input."""
    cases = [
        ("pod", "default", "nginx-abc"),
        ("node", None, "gke-prod-1"),
    ]
    for kind, ns, name in cases:
        rid = resource_mod._make_id(kind, ns, name)
        parsed_kind, parsed_ns, parsed_name = resource_mod._parse_id(rid)
        assert (parsed_kind, parsed_ns, parsed_name) == (kind, ns, name)


# ---------------------------------------------------------------------------
# Lifecycle: initialized() and grains() handle missing dunders gracefully
# ---------------------------------------------------------------------------


def test_initialized_returns_false_without_context():
    """
    ``initialized()`` is checked by the loader before per-resource
    dispatch. Outside loader context (where ``__context__`` is not
    injected), it must return False rather than NameError.
    """
    # Module-level __context__ is not defined when imported plain.
    assert resource_mod.initialized() is False


def test_grains_returns_empty_without_resource_dunder():
    """
    Calling grains() without an active resource context (no
    ``__resource__`` injected) returns an empty dict rather than
    crashing.
    """
    assert not resource_mod.grains()


def test_default_kinds_are_workload_controllers_not_pods():
    """
    The default kind set is conservative — workload controllers and
    cluster scope, NOT individual Pods. Pods are too numerous and
    short-lived to register by default.
    """
    assert "deployment" in resource_mod._DEFAULT_KINDS
    assert "node" in resource_mod._DEFAULT_KINDS
    assert "pod" not in resource_mod._DEFAULT_KINDS
