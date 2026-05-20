"""
Unit tests for ``saltext.kubernetes.resources.kubernetes`` — the
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

import sys
import types

import pytest

from saltext.kubernetes.resources import kubernetes as resource_mod

# ---------------------------------------------------------------------------
# __virtual__ — dormant on stock Salt
# ---------------------------------------------------------------------------


def test_virtual_returns_false_when_resources_subsystem_absent():
    """
    On Salt < 3008 (no salt.utils.resources), ``__virtual__`` returns
    ``(False, <reason>)`` with a clear, actionable message that names
    the minimum Salt version.
    """
    result = resource_mod.__virtual__()
    assert isinstance(result, tuple)
    assert result[0] is False
    # The dormant-mode message must tell operators what to upgrade to.
    assert (
        "3008" in result[1]
    ), f"expected the dormant-mode message to name Salt 3008.0, got {result[1]!r}"
    assert "resources" in result[1].lower()


def test_virtual_returns_virtualname_when_resources_present(monkeypatch):
    """
    With a stub ``salt.utils.resources`` module on the import path,
    ``__virtual__`` returns the virtualname so the loader registers
    this plugin under the ``kubernetes`` resource type.
    """

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


def test_every_default_kind_resolves_in_registry():
    """A typo in ``_DEFAULT_KINDS`` would silently disable a kind for
    every minion running without an explicit ``kinds:`` override.

    This regression guard catches the pre-PR-37 bug where
    ``_DEFAULT_KINDS`` listed ``stateful_set`` / ``daemon_set`` —
    neither a valid registry key — and only ``deployment`` /
    ``namespace`` actually enumerated.
    """
    from saltext.kubernetes.utils import _kinds  # pylint: disable=import-outside-toplevel

    for kind in resource_mod._DEFAULT_KINDS:
        assert (
            kind in _kinds._KIND_REGISTRY
        ), f"_DEFAULT_KINDS has unknown kind {kind!r} — typo or registry omission"


def test_node_and_crd_in_registry():
    """``node`` and ``custom_resource_definition`` must be discoverable.

    Both are commonly-targeted cluster-scoped kinds; their absence from
    the registry made them unaddressable via the resources subsystem
    even though users could legally enable them in pillar.
    """
    from saltext.kubernetes.utils import _kinds  # pylint: disable=import-outside-toplevel

    assert "node" in _kinds._KIND_REGISTRY
    assert "custom_resource_definition" in _kinds._KIND_REGISTRY


# ---------------------------------------------------------------------------
# Pillar-only mode: declared resources skip API discovery entirely.
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_context(monkeypatch):
    """Install ``__context__`` and ``__salt__`` dunders on the resource module."""
    ctx = {}
    monkeypatch.setattr(resource_mod, "__context__", ctx, raising=False)
    monkeypatch.setattr(
        resource_mod, "__salt__", {"config.option": lambda *a, **k: ""}, raising=False
    )
    return ctx


def test_ids_from_declared_namespaced(fake_context):
    ids = resource_mod._ids_from_declared(
        [
            {"kind": "deployment", "namespace": "prod", "name": "web"},
            {"kind": "deployment", "namespace": "prod", "name": "api"},
        ]
    )
    assert ids == ["deployment:prod/web", "deployment:prod/api"]


def test_ids_from_declared_cluster_scoped(fake_context):
    ids = resource_mod._ids_from_declared(
        [
            {"kind": "namespace", "name": "bootstrap"},
            {"kind": "node", "name": "worker-0"},
            {"kind": "priority_class", "name": "high"},
        ]
    )
    assert ids == ["namespace:bootstrap", "node:worker-0", "priority_class:high"]


def test_ids_from_declared_rejects_unknown_kind(fake_context):
    from salt.exceptions import CommandExecutionError  # pylint: disable=import-outside-toplevel

    with pytest.raises(CommandExecutionError, match="unknown kind"):
        resource_mod._ids_from_declared([{"kind": "not_a_kind", "namespace": "x", "name": "y"}])


def test_ids_from_declared_requires_namespace_for_namespaced_kind(fake_context):
    from salt.exceptions import CommandExecutionError  # pylint: disable=import-outside-toplevel

    with pytest.raises(CommandExecutionError, match="requires 'namespace'"):
        resource_mod._ids_from_declared([{"kind": "deployment", "name": "web"}])


def test_ids_from_declared_warns_on_namespace_for_cluster_scoped(fake_context, caplog):
    """Cluster-scoped kinds with a namespace field log a warning and drop it."""
    import logging  # pylint: disable=import-outside-toplevel

    caplog.set_level(logging.WARNING)
    ids = resource_mod._ids_from_declared(
        [{"kind": "node", "namespace": "should-be-ignored", "name": "n1"}]
    )
    # The namespace is dropped from the resulting ID.
    assert ids == ["node:n1"]
    assert "cluster-scoped" in caplog.text


def test_ids_from_declared_rejects_missing_kind_or_name(fake_context):
    from salt.exceptions import CommandExecutionError  # pylint: disable=import-outside-toplevel

    with pytest.raises(CommandExecutionError, match="missing 'kind' or 'name'"):
        resource_mod._ids_from_declared([{"namespace": "x", "name": "y"}])
    with pytest.raises(CommandExecutionError, match="missing 'kind' or 'name'"):
        resource_mod._ids_from_declared([{"kind": "deployment", "namespace": "x"}])


def test_ids_from_declared_rejects_non_dict_entry(fake_context):
    from salt.exceptions import CommandExecutionError  # pylint: disable=import-outside-toplevel

    with pytest.raises(CommandExecutionError, match="must be a dict"):
        resource_mod._ids_from_declared(["deployment:prod/web"])


# ---------------------------------------------------------------------------
# init() pillar parsing — mode inference & validation
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_resources_helper(monkeypatch):
    """Stub ``salt.utils.resources.pillar_resources_tree`` to return a fixed dict.

    The plugin does ``import salt.utils.resources`` then calls
    ``salt.utils.resources.pillar_resources_tree(opts)`` — the second
    line resolves via attribute access on the already-imported
    ``salt.utils`` package, so the stub has to land both in
    ``sys.modules`` *and* as an attribute of ``salt.utils``.
    """
    import salt.utils  # pylint: disable=import-outside-toplevel

    def _factory(tree):
        fake = types.ModuleType("salt.utils.resources")
        fake.pillar_resources_tree = lambda _opts: tree
        monkeypatch.setitem(sys.modules, "salt.utils.resources", fake)
        monkeypatch.setattr(salt.utils, "resources", fake, raising=False)
        return tree

    return _factory


def test_init_infers_pillar_mode_when_resources_listed(fake_context, fake_resources_helper):
    fake_resources_helper(
        {
            "kubernetes": {
                "resources": [
                    {"kind": "namespace", "name": "prod"},
                ],
            }
        }
    )
    resource_mod.init({})
    assert fake_context["kubernetes_resource"]["mode"] == "pillar"


def test_init_infers_discover_mode_when_no_resources_listed(fake_context, fake_resources_helper):
    fake_resources_helper({"kubernetes": {"kinds": ["deployment"]}})
    resource_mod.init({})
    assert fake_context["kubernetes_resource"]["mode"] == "discover"


def test_init_explicit_merge_mode(fake_context, fake_resources_helper):
    fake_resources_helper(
        {
            "kubernetes": {
                "mode": "merge",
                "resources": [{"kind": "namespace", "name": "prod"}],
                "kinds": ["deployment"],
            }
        }
    )
    resource_mod.init({})
    assert fake_context["kubernetes_resource"]["mode"] == "merge"


def test_init_rejects_unknown_mode(fake_context, fake_resources_helper):
    from salt.exceptions import CommandExecutionError  # pylint: disable=import-outside-toplevel

    fake_resources_helper({"kubernetes": {"mode": "live-stream"}})
    with pytest.raises(CommandExecutionError, match="must be one of"):
        resource_mod.init({})


def test_init_rejects_non_list_resources(fake_context, fake_resources_helper):
    from salt.exceptions import CommandExecutionError  # pylint: disable=import-outside-toplevel

    fake_resources_helper({"kubernetes": {"mode": "pillar", "resources": "not-a-list"}})
    with pytest.raises(CommandExecutionError, match="must be a list"):
        resource_mod.init({})


# ---------------------------------------------------------------------------
# discover() honours the mode — pillar mode never calls the API.
# ---------------------------------------------------------------------------


def test_discover_pillar_mode_does_not_call_api(fake_context, fake_resources_helper, monkeypatch):
    """``mode: pillar`` returns exactly the declared IDs and skips
    ``_setup_conn`` entirely.

    The user-facing contract: declaring a static inventory in pillar
    must not require a working Kubernetes API connection.
    """
    fake_resources_helper(
        {
            "kubernetes": {
                "mode": "pillar",
                "resources": [
                    {"kind": "deployment", "namespace": "prod", "name": "web"},
                    {"kind": "namespace", "name": "prod"},
                ],
            }
        }
    )
    resource_mod.init({})

    setup_called = []

    def _boom(*args, **kwargs):
        setup_called.append((args, kwargs))
        raise AssertionError("_setup_conn must not be invoked in pillar mode")

    from saltext.kubernetes.utils import _connection  # pylint: disable=import-outside-toplevel

    monkeypatch.setattr(_connection, "_setup_conn", _boom)

    ids = resource_mod.discover({})
    assert ids == ["deployment:prod/web", "namespace:prod"]
    assert not setup_called


def test_init_explicit_mode_discover_overrides_inference(fake_context, fake_resources_helper):
    """Explicit ``mode: discover`` wins even when ``resources:`` is set.

    The inference rule (``resources:`` → pillar mode) is a convenience;
    when both are present and the user wants discovery anyway, the
    explicit ``mode:`` must be honoured.
    """
    fake_resources_helper(
        {
            "kubernetes": {
                "mode": "discover",
                "resources": [{"kind": "namespace", "name": "ignored"}],
                "kinds": ["deployment"],
            }
        }
    )
    resource_mod.init({})
    assert fake_context["kubernetes_resource"]["mode"] == "discover"
    # The declared list is still parsed and stashed — discover-mode
    # ignores it for enumeration, but the parsed shape is kept so an
    # operator who flips mode at runtime doesn't need re-init.
    assert fake_context["kubernetes_resource"]["declared"] == [
        {"kind": "namespace", "name": "ignored"}
    ]


# ---------------------------------------------------------------------------
# Discover mode: live-API path. Mocks every kubernetes.client API class
# the plug-in might instantiate so the test never touches the network.
# ---------------------------------------------------------------------------


def _api_list_result(objects):
    """Wrap ``[{name,namespace}, ...]`` into the kubernetes-client list shape."""
    from types import SimpleNamespace  # pylint: disable=import-outside-toplevel

    items = []
    for obj in objects:
        items.append(
            SimpleNamespace(
                metadata=SimpleNamespace(
                    name=obj["name"],
                    namespace=obj.get("namespace"),
                )
            )
        )
    return SimpleNamespace(items=items)


@pytest.fixture
def discover_mode_context(fake_context):
    """Install ``__context__`` for an arbitrary discover-mode run.

    Returns a factory that lets each test override individual context
    keys (mode, kinds, namespaces, label_selector, declared) without
    restating the full shape.
    """

    def _factory(**overrides):
        cfg = {
            "initialized": True,
            "mode": "discover",
            "kinds": ["deployment", "namespace"],
            "namespaces": [],
            "label_selector": None,
            "declared": [],
            "config": {},
        }
        cfg.update(overrides)
        fake_context["kubernetes_resource"] = cfg
        return cfg

    return _factory


def _patch_kubernetes_api(monkeypatch, api_responses):
    """Install fake list_* methods on ``kubernetes.client.<ApiClass>()``.

    *api_responses* maps ``(ApiClass, method_name)`` → list of object
    dicts. Each matching call returns those objects wrapped in the
    list-response shape; calls to unmocked methods raise an
    AssertionError so the test fails loudly on unexpected API traffic.
    """
    import kubernetes.client  # pylint: disable=import-outside-toplevel

    call_log = []

    class _FakeApi:
        def __init__(self, name):
            self._name = name

        def __getattr__(self, attr):
            def _call(*args, **kwargs):
                call_log.append((self._name, attr, args, kwargs))
                key = (self._name, attr)
                if key not in api_responses:
                    raise AssertionError(
                        f"unexpected API call {self._name}.{attr}({args}, {kwargs})"
                    )
                return _api_list_result(api_responses[key])

            return _call

    for cls_name in {key[0] for key in api_responses}:
        monkeypatch.setattr(
            kubernetes.client,
            cls_name,
            lambda _cls=cls_name: _FakeApi(_cls),
        )
    return call_log


@pytest.fixture
def patch_setup_conn(monkeypatch):
    """No-op ``_setup_conn`` / ``_cleanup`` so discover() doesn't authenticate."""
    from saltext.kubernetes.utils import _connection  # pylint: disable=import-outside-toplevel

    monkeypatch.setattr(_connection, "_setup_conn", lambda *a, **k: {})
    monkeypatch.setattr(_connection, "_cleanup", lambda *a, **k: None)


def test_discover_mode_enumerates_each_kind(discover_mode_context, patch_setup_conn, monkeypatch):
    """Discover mode calls the correct list method on each kind's API class."""
    discover_mode_context(kinds=["deployment", "namespace"])
    call_log = _patch_kubernetes_api(
        monkeypatch,
        {
            ("AppsV1Api", "list_deployment_for_all_namespaces"): [
                {"name": "web", "namespace": "prod"},
                {"name": "api", "namespace": "prod"},
            ],
            ("CoreV1Api", "list_namespace"): [
                {"name": "prod"},
                {"name": "default"},
            ],
        },
    )
    ids = resource_mod.discover({})
    assert sorted(ids) == sorted(
        [
            "deployment:prod/web",
            "deployment:prod/api",
            "namespace:prod",
            "namespace:default",
        ]
    )
    methods = {(cls, m) for cls, m, _a, _k in call_log}
    assert ("AppsV1Api", "list_deployment_for_all_namespaces") in methods
    assert ("CoreV1Api", "list_namespace") in methods


def test_discover_mode_with_namespaces_filter_calls_per_namespace(
    discover_mode_context, patch_setup_conn, monkeypatch
):
    """A ``namespaces:`` filter triggers one list-per-namespace call."""
    discover_mode_context(kinds=["deployment"], namespaces=["prod", "staging"])
    call_log = _patch_kubernetes_api(
        monkeypatch,
        {
            ("AppsV1Api", "list_namespaced_deployment"): [{"name": "web", "namespace": "prod"}],
        },
    )
    ids = resource_mod.discover({})
    ns_calls = [c for c in call_log if c[1] == "list_namespaced_deployment"]
    assert len(ns_calls) == 2
    assert {c[2][0] for c in ns_calls} == {"prod", "staging"}
    # The mock returns the same item from both calls; merge-set
    # semantics dedupe so we still see one "deployment:prod/web".
    assert "deployment:prod/web" in ids


def test_discover_mode_passes_label_selector(discover_mode_context, patch_setup_conn, monkeypatch):
    """``label_selector:`` is forwarded to every list call."""
    discover_mode_context(kinds=["namespace"], label_selector="managed-by=salt")
    call_log = _patch_kubernetes_api(
        monkeypatch,
        {("CoreV1Api", "list_namespace"): []},
    )
    resource_mod.discover({})
    assert call_log[0][3] == {"label_selector": "managed-by=salt"}


def test_discover_mode_skips_unknown_kind_without_raising(
    discover_mode_context, patch_setup_conn, monkeypatch, caplog
):
    """An unknown kind in ``kinds:`` is logged and skipped, not fatal.

    Opposite of pillar mode — there a typo raises (config-time error
    is louder than a silently broken minion). Here, discover() is
    best-effort: one bad kind doesn't break the others.
    """
    import logging  # pylint: disable=import-outside-toplevel

    caplog.set_level(logging.WARNING)
    discover_mode_context(kinds=["depolyment", "namespace"])  # typo
    _patch_kubernetes_api(
        monkeypatch,
        {("CoreV1Api", "list_namespace"): [{"name": "prod"}]},
    )
    ids = resource_mod.discover({})
    assert ids == ["namespace:prod"]
    assert "skipping unknown kind depolyment" in caplog.text


def test_discover_mode_cluster_scoped_kind_ignores_namespaces_filter(
    discover_mode_context, patch_setup_conn, monkeypatch
):
    """Cluster-scoped kinds use the bare ``list_*`` method even when
    ``namespaces:`` is set — the filter doesn't apply."""
    discover_mode_context(kinds=["node"], namespaces=["ignored"])
    call_log = _patch_kubernetes_api(
        monkeypatch,
        {("CoreV1Api", "list_node"): [{"name": "worker-0"}, {"name": "worker-1"}]},
    )
    ids = resource_mod.discover({})
    assert sorted(ids) == ["node:worker-0", "node:worker-1"]
    node_calls = [c for c in call_log if c[1] == "list_node"]
    assert len(node_calls) == 1
    assert node_calls[0][2] == ()


def test_discover_mode_with_empty_kinds_returns_empty(
    discover_mode_context, patch_setup_conn, monkeypatch
):
    """``mode: discover`` with an empty ``kinds:`` list returns ``[]``."""
    discover_mode_context(kinds=[])
    _patch_kubernetes_api(monkeypatch, {})
    assert not resource_mod.discover({})


# ---------------------------------------------------------------------------
# Merge mode: union of declared + discovered, deduplicating overlaps.
# ---------------------------------------------------------------------------


def test_merge_mode_unions_declared_and_discovered(
    discover_mode_context, patch_setup_conn, monkeypatch
):
    """``mode: merge`` returns the declared inventory plus the API-discovered set."""
    discover_mode_context(
        mode="merge",
        kinds=["namespace"],
        declared=[
            {"kind": "namespace", "name": "bootstrap-only"},
            {"kind": "priority_class", "name": "pinned"},
        ],
    )
    _patch_kubernetes_api(
        monkeypatch,
        {("CoreV1Api", "list_namespace"): [{"name": "discovered"}]},
    )
    ids = resource_mod.discover({})
    assert ids[:2] == ["namespace:bootstrap-only", "priority_class:pinned"]
    assert "namespace:discovered" in ids


def test_merge_mode_deduplicates_when_declared_id_also_discovered(
    discover_mode_context, patch_setup_conn, monkeypatch
):
    """An ID present in both the declared list and the API result appears once."""
    discover_mode_context(
        mode="merge",
        kinds=["namespace"],
        declared=[{"kind": "namespace", "name": "overlap"}],
    )
    _patch_kubernetes_api(
        monkeypatch,
        {("CoreV1Api", "list_namespace"): [{"name": "overlap"}, {"name": "extra"}]},
    )
    ids = resource_mod.discover({})
    assert ids.count("namespace:overlap") == 1
    assert "namespace:extra" in ids


def test_merge_mode_with_empty_kinds_equals_pillar(
    discover_mode_context, patch_setup_conn, monkeypatch
):
    """``mode: merge`` with no ``kinds:`` returns just the declared set."""
    discover_mode_context(
        mode="merge",
        kinds=[],
        declared=[{"kind": "namespace", "name": "only-this"}],
    )
    _patch_kubernetes_api(monkeypatch, {})
    ids = resource_mod.discover({})
    assert ids == ["namespace:only-this"]


def test_merge_mode_with_empty_declared_equals_discover(
    discover_mode_context, patch_setup_conn, monkeypatch
):
    """``mode: merge`` with no declared list behaves like ``mode: discover``."""
    discover_mode_context(mode="merge", kinds=["namespace"], declared=[])
    _patch_kubernetes_api(
        monkeypatch,
        {("CoreV1Api", "list_namespace"): [{"name": "default"}]},
    )
    ids = resource_mod.discover({})
    assert ids == ["namespace:default"]


def test_discover_uninitialized_returns_empty(monkeypatch):
    """``discover()`` before ``init()`` returns ``[]``, not an exception.

    The loader may probe ``discover()`` before the init lifecycle has
    completed; returning ``[]`` lets the lifecycle complete instead of
    crashing the minion.
    """
    monkeypatch.setattr(resource_mod, "__context__", {}, raising=False)
    assert not resource_mod.discover({})


def test_init_pillar_mode_with_explicit_list_records_declared(fake_context, fake_resources_helper):
    """``init()`` stashes the parsed ``resources:`` list in __context__."""
    declared = [
        {"kind": "deployment", "namespace": "prod", "name": "web"},
        {"kind": "namespace", "name": "prod"},
    ]
    fake_resources_helper({"kubernetes": {"resources": declared}})
    resource_mod.init({})
    ctx = fake_context["kubernetes_resource"]
    assert ctx["mode"] == "pillar"
    assert ctx["declared"] == declared


def test_init_empty_pillar_uses_default_kinds(fake_context, fake_resources_helper):
    """With no pillar config the plug-in falls back to ``_DEFAULT_KINDS``."""
    fake_resources_helper({})
    resource_mod.init({})
    assert fake_context["kubernetes_resource"]["mode"] == "discover"
    assert tuple(fake_context["kubernetes_resource"]["kinds"]) == resource_mod._DEFAULT_KINDS
