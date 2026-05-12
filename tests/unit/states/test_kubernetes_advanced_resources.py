"""
Unit tests for the new typed-kind state functions added to close #14.

Verifies the user-visible contract of each ``*_present`` / ``*_absent``
function without spinning up a cluster:

  * On a fresh object (``show_*`` returns ``None``), ``*_present`` calls
    ``create_*`` and reports ``result=True`` with the created body in
    ``changes['new']``.
  * On a re-apply with no changes, ``*_present`` reports
    ``result=True`` and empty changes (idempotency).
  * ``test=True`` returns ``result=None`` and never mutates state.
  * ``*_absent`` on a present object calls ``delete_*`` and reports
    ``result=True``.
  * ``*_absent`` on an already-missing object is a no-op (``result=True``).
"""

from unittest.mock import MagicMock

import pytest

from saltext.kubernetes.states import kubernetes as state


@pytest.fixture
def loader_globals(monkeypatch):
    """Install fake ``__opts__`` / ``__salt__`` / ``__env__`` on the state module."""
    opts = {"test": False}

    def _present_body(name, namespace="default", **_):
        # Return a body shaped like a typical kubernetes-client response.
        return {"metadata": {"name": name, "namespace": namespace, "resourceVersion": "1"}}

    salt_mocks = {}
    # Every typed kind we care about gets create / show / patch / delete + (some) replace.
    kinds = (
        "network_policy",
        "resource_quota",
        "limit_range",
        "priority_class",
        "custom_resource_definition",
    )
    for kind in kinds:
        salt_mocks[f"kubernetes.create_{kind}"] = MagicMock(side_effect=_present_body)
        salt_mocks[f"kubernetes.replace_{kind}"] = MagicMock(side_effect=_present_body)
        salt_mocks[f"kubernetes.patch_{kind}"] = MagicMock(side_effect=_present_body)
        salt_mocks[f"kubernetes.delete_{kind}"] = MagicMock(return_value={"status": "Success"})
        # show_* returns None by default — i.e. resource is absent.
        salt_mocks[f"kubernetes.show_{kind}"] = MagicMock(return_value=None)

    monkeypatch.setattr(state, "__opts__", opts, raising=False)
    monkeypatch.setattr(state, "__salt__", salt_mocks, raising=False)
    monkeypatch.setattr(state, "__env__", "base", raising=False)
    return {"opts": opts, "salt": salt_mocks}


# Parametrise over each new state-kind pair: (kind_lower, namespaced, present_fn, absent_fn,
# extra_kwargs_for_present, present_spec).
PARAMS = [
    (
        "network_policy",
        True,
        state.network_policy_present,
        state.network_policy_absent,
        {"namespace": "default"},
        {"podSelector": {}, "policyTypes": ["Ingress"]},
    ),
    (
        "resource_quota",
        True,
        state.resource_quota_present,
        state.resource_quota_absent,
        {"namespace": "team-a"},
        {"hard": {"pods": "10"}},
    ),
    (
        "limit_range",
        True,
        state.limit_range_present,
        state.limit_range_absent,
        {"namespace": "team-a"},
        {"limits": [{"type": "Container", "default": {"memory": "256Mi"}}]},
    ),
    (
        "priority_class",
        False,
        state.priority_class_present,
        state.priority_class_absent,
        {},
        {"value": 1000, "description": "test"},
    ),
    (
        "custom_resource_definition",
        False,
        state.custom_resource_definition_present,
        state.custom_resource_definition_absent,
        {},
        {
            "group": "example.io",
            "scope": "Namespaced",
            "names": {"plural": "widgets", "singular": "widget", "kind": "Widget"},
            "versions": [
                {
                    "name": "v1",
                    "served": True,
                    "storage": True,
                    "schema": {"openAPIV3Schema": {"type": "object"}},
                }
            ],
        },
    ),
]


@pytest.mark.parametrize(
    "kind,_namespaced,present_fn,_absent_fn,extra,spec",
    PARAMS,
    ids=[p[0] for p in PARAMS],
)
def test_present_creates_when_absent(
    kind, _namespaced, present_fn, _absent_fn, extra, spec, loader_globals
):
    """``*_present`` against a missing object calls ``create_<kind>`` and reports success."""
    ret = present_fn(name="obj", spec=spec, **extra)
    assert ret["result"] is True
    loader_globals["salt"][f"kubernetes.create_{kind}"].assert_called_once()
    loader_globals["salt"][f"kubernetes.patch_{kind}"].assert_not_called()
    assert ret["changes"]["new"]["metadata"]["name"] == "obj"


@pytest.mark.parametrize(
    "kind,_namespaced,present_fn,_absent_fn,extra,spec",
    PARAMS,
    ids=[p[0] for p in PARAMS],
)
def test_present_test_mode_does_not_persist(
    kind, _namespaced, present_fn, _absent_fn, extra, spec, loader_globals
):
    """``test=True`` returns ``result=None`` and forwards ``dry_run=True``."""
    loader_globals["opts"]["test"] = True
    ret = present_fn(name="obj", spec=spec, **extra)
    assert ret["result"] is None
    # The state module forwards dry_run to the create call so server-side
    # validation runs without persisting.
    create_call = loader_globals["salt"][f"kubernetes.create_{kind}"].call_args
    assert create_call.kwargs.get("dry_run") is True


@pytest.mark.parametrize(
    "kind,namespaced,present_fn,_absent_fn,extra,spec",
    PARAMS,
    ids=[p[0] for p in PARAMS],
)
def test_present_patches_when_already_present(
    kind, namespaced, present_fn, _absent_fn, extra, spec, loader_globals
):
    """When ``show_<kind>`` returns an object, ``*_present`` patches instead of creating."""
    existing = {"metadata": {"name": "obj", "resourceVersion": "1"}, "spec": spec}
    loader_globals["salt"][f"kubernetes.show_{kind}"].return_value = existing
    # Patch returns the post-patch object — same shape so the state thinks
    # nothing meaningful changed.
    loader_globals["salt"][f"kubernetes.patch_{kind}"].return_value = existing
    ret = present_fn(name="obj", spec=spec, **extra)
    assert ret["result"] is True
    loader_globals["salt"][f"kubernetes.create_{kind}"].assert_not_called()
    loader_globals["salt"][f"kubernetes.patch_{kind}"].assert_called_once()


@pytest.mark.parametrize(
    "kind,_namespaced,_present_fn,absent_fn,extra,_spec",
    PARAMS,
    ids=[p[0] for p in PARAMS],
)
def test_absent_already_missing_is_noop(
    kind, _namespaced, _present_fn, absent_fn, extra, _spec, loader_globals
):
    """``*_absent`` against a missing object is a no-op (idempotency)."""
    ret = absent_fn(name="obj", **extra)
    assert ret["result"] is True
    loader_globals["salt"][f"kubernetes.delete_{kind}"].assert_not_called()


@pytest.mark.parametrize(
    "kind,_namespaced,_present_fn,absent_fn,extra,_spec",
    PARAMS,
    ids=[p[0] for p in PARAMS],
)
def test_absent_deletes_existing(
    kind, _namespaced, _present_fn, absent_fn, extra, _spec, loader_globals
):
    """``*_absent`` against a present object calls ``delete_<kind>``."""
    loader_globals["salt"][f"kubernetes.show_{kind}"].return_value = {"metadata": {"name": "obj"}}
    ret = absent_fn(name="obj", **extra)
    assert ret["result"] is True
    loader_globals["salt"][f"kubernetes.delete_{kind}"].assert_called_once()


@pytest.mark.parametrize(
    "kind,_namespaced,_present_fn,absent_fn,extra,_spec",
    PARAMS,
    ids=[p[0] for p in PARAMS],
)
def test_absent_test_mode_does_not_delete(
    kind, _namespaced, _present_fn, absent_fn, extra, _spec, loader_globals
):
    loader_globals["opts"]["test"] = True
    loader_globals["salt"][f"kubernetes.show_{kind}"].return_value = {"metadata": {"name": "obj"}}
    ret = absent_fn(name="obj", **extra)
    assert ret["result"] is None
    loader_globals["salt"][f"kubernetes.delete_{kind}"].assert_not_called()
