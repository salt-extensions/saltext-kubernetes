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
    salt_mocks = {
        "kubernetes.apply": MagicMock(return_value={"applied": "ok"}),
        "kubernetes.delete_manifest": MagicMock(return_value={"deleted": "ok"}),
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
    """test=True returns result=None without calling delete_manifest."""
    fake_loader_globals["opts"]["test"] = True
    manifest = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "x", "namespace": "default"},
    }
    ret = state.manifest_absent(name="state-test", manifest=manifest)
    assert ret["result"] is None
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
