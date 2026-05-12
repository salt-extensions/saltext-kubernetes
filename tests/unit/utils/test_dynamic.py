"""
Unit tests for ``saltext.kubernetes.utils._dynamic``.

Exercises the input-validation paths that don't require an active
cluster connection. The end-to-end SSA wire-format test lives in
``tests/functional/utils/test_dynamic.py`` against the kind cluster.
"""

import pytest
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.utils import _dynamic

# ---------------------------------------------------------------------------
# _resolve_gvk_from_manifest
# ---------------------------------------------------------------------------


def test_resolve_gvk_extracts_apiversion_and_kind():
    api_version, kind = _dynamic._resolve_gvk_from_manifest(
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "x"}}
    )
    assert api_version == "apps/v1"
    assert kind == "Deployment"


def test_resolve_gvk_rejects_non_dict():
    with pytest.raises(CommandExecutionError, match="must be a dictionary"):
        _dynamic._resolve_gvk_from_manifest("not-a-dict")


def test_resolve_gvk_rejects_missing_apiversion():
    with pytest.raises(CommandExecutionError, match="missing 'apiVersion'"):
        _dynamic._resolve_gvk_from_manifest({"kind": "Deployment"})


def test_resolve_gvk_rejects_missing_kind():
    with pytest.raises(CommandExecutionError, match="missing 'kind'"):
        _dynamic._resolve_gvk_from_manifest({"apiVersion": "v1"})


# ---------------------------------------------------------------------------
# apply_manifest input validation
# ---------------------------------------------------------------------------


def test_apply_manifest_rejects_missing_name():
    """Without metadata.name, apply must fail before hitting the API."""
    with pytest.raises(CommandExecutionError, match="missing 'metadata.name'"):
        _dynamic.apply_manifest({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {}})


# ---------------------------------------------------------------------------
# Cache management
# ---------------------------------------------------------------------------


def test_invalidate_caches_clears_both_caches():
    """invalidate_caches drops both the client and resource caches."""
    _dynamic._DYN_CLIENT[42] = "fake-client"
    _dynamic._RESOURCE_CACHE[(42, "v1", "Pod")] = "fake-resource"
    _dynamic.invalidate_caches()
    assert not _dynamic._DYN_CLIENT
    assert not _dynamic._RESOURCE_CACHE
