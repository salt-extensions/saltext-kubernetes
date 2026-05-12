"""
Unit tests for the manifest_present / manifest_absent state functions
on ``saltext.kubernetes.states.kubernetes``.

The state-level dry-run branching (``__opts__["test"]`` → pass
``dry_run=True`` to ``kubernetes.apply``) is verified here rather than
in the functional tier because salt-factories' Loaders snapshots the
state module's ``__opts__`` at task-prep time; flipping the dict
mid-test doesn't reach the state body.
"""

from unittest.mock import MagicMock

import pytest

from saltext.kubernetes.states import kubernetes as state


@pytest.fixture
def fake_loader_globals(monkeypatch):
    """
    Install the loader-injected dunders that the state module relies on,
    using mocks we control. Yields a dict so tests can flip ``test``
    mid-run.
    """
    opts = {"test": False}
    # ``manifest_present`` / ``manifest_absent`` in test mode now do
    # real change-detection: dry-run apply + live-object diff. The
    # fixture mocks ``kubernetes.apply`` to return a single doc
    # matching the input manifest, ``kubernetes.get_object`` to return
    # ``None`` by default (so dry-run mode reports "would create"),
    # and ``kubernetes.normalise_manifest_input`` to echo the input.
    salt_mocks = {
        "kubernetes.apply": MagicMock(
            return_value={
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "x", "namespace": "default"},
                "data": {"k": "v"},
            }
        ),
        "kubernetes.delete_manifest": MagicMock(return_value={"deleted": "ok"}),
        "kubernetes.get_object": MagicMock(return_value=None),
        "kubernetes.normalise_manifest_input": MagicMock(
            side_effect=lambda manifest=None, source=None, **kw: (
                manifest if isinstance(manifest, list) else [manifest] if manifest else []
            )
        ),
    }
    monkeypatch.setattr(state, "__opts__", opts, raising=False)
    monkeypatch.setattr(state, "__salt__", salt_mocks, raising=False)
    monkeypatch.setattr(state, "__env__", "base", raising=False)
    return {"opts": opts, "salt": salt_mocks}


def test_manifest_present_test_mode_passes_dry_run(fake_loader_globals):
    """test=True forwards dry_run=True and returns result=None."""
    fake_loader_globals["opts"]["test"] = True
    manifest = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "x", "namespace": "default"},
        "data": {"k": "v"},
    }
    ret = state.manifest_present(name="state-test", manifest=manifest)
    assert ret["result"] is None
    assert "dry run" in ret["comment"].lower()
    # The execution-module function was called with dry_run=True.
    apply_call = fake_loader_globals["salt"]["kubernetes.apply"].call_args
    assert apply_call.kwargs.get("dry_run") is True


def test_manifest_present_normal_mode_applies(fake_loader_globals):
    """test=False applies for real (no dry_run kwarg) and returns result=True."""
    manifest = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "x", "namespace": "default"},
        "data": {"k": "v"},
    }
    ret = state.manifest_present(name="state-test", manifest=manifest)
    assert ret["result"] is True
    apply_call = fake_loader_globals["salt"]["kubernetes.apply"].call_args
    assert apply_call.kwargs.get("dry_run") is None or apply_call.kwargs.get("dry_run") is False


def test_manifest_present_rejects_both_source_and_manifest(fake_loader_globals):
    """source and manifest are mutually exclusive."""
    ret = state.manifest_present(
        name="x",
        source="salt://m.yaml",
        manifest={"apiVersion": "v1", "kind": "ConfigMap"},
    )
    assert ret["result"] is False
    assert "mutually exclusive" in ret["comment"]


def test_manifest_present_rejects_neither(fake_loader_globals):
    ret = state.manifest_present(name="x")
    assert ret["result"] is False
    assert "Provide either" in ret["comment"]


def test_manifest_absent_test_mode_skips_call(fake_loader_globals):
    """test=True returns result=None without calling delete_manifest when target exists."""
    fake_loader_globals["opts"]["test"] = True
    # Object exists → test mode reports "would delete" (result=None).
    fake_loader_globals["salt"]["kubernetes.get_object"].return_value = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "x", "namespace": "default"},
    }
    manifest = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "x", "namespace": "default"},
    }
    ret = state.manifest_absent(name="state-test", manifest=manifest)
    assert ret["result"] is None
    fake_loader_globals["salt"]["kubernetes.delete_manifest"].assert_not_called()


def test_manifest_absent_test_mode_already_absent_is_idempotent(fake_loader_globals):
    """test=True with target already absent returns result=True (no pending change)."""
    fake_loader_globals["opts"]["test"] = True
    # get_object returns None by default → already-absent → result=True.
    manifest = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "x", "namespace": "default"},
    }
    ret = state.manifest_absent(name="state-test", manifest=manifest)
    assert ret["result"] is True
    assert not ret["changes"]
    fake_loader_globals["salt"]["kubernetes.delete_manifest"].assert_not_called()


def test_manifest_absent_normal_mode_deletes(fake_loader_globals):
    manifest = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "x", "namespace": "default"},
    }
    ret = state.manifest_absent(name="state-test", manifest=manifest)
    assert ret["result"] is True
    fake_loader_globals["salt"]["kubernetes.delete_manifest"].assert_called_once()
