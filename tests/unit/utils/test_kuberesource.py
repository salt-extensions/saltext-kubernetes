"""
Unit tests for ``saltext.kubernetes.utils._kuberesource`` — the shared
helpers used by every ``kuberesource_*`` companion module.
"""

import sys
import types

import pytest
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.utils import _kuberesource


def test_virtual_or_dormant_returns_false_on_stock_salt():
    result = _kuberesource.virtual_or_dormant()
    assert isinstance(result, tuple)
    assert result[0] is False


def test_virtual_or_dormant_returns_kubernetes_when_resources_present(monkeypatch):

    fake = types.ModuleType("salt.utils.resources")
    monkeypatch.setitem(sys.modules, "salt.utils.resources", fake)
    assert _kuberesource.virtual_or_dormant() == "kubernetes"


@pytest.mark.parametrize(
    "rid,expected",
    [
        ("pod:default/nginx-abc", ("pod", "default", "nginx-abc")),
        ("node:gke-prod-1", ("node", None, "gke-prod-1")),
        ("namespace:kube-system", ("namespace", None, "kube-system")),
        ("deployment:prod/api", ("deployment", "prod", "api")),
    ],
)
def test_resource_identity_parses_id(rid, expected):
    assert _kuberesource.resource_identity({"id": rid}) == expected


def test_resource_identity_rejects_missing_id():
    with pytest.raises(CommandExecutionError, match="outside a resource dispatch"):
        _kuberesource.resource_identity({})


def test_resource_identity_rejects_none_dunder():
    with pytest.raises(CommandExecutionError, match="outside a resource dispatch"):
        _kuberesource.resource_identity(None)


def test_resource_identity_rejects_malformed_id():
    with pytest.raises(CommandExecutionError, match="missing ':'"):
        _kuberesource.resource_identity({"id": "no-colon-here"})


def test_require_kind_passes_when_match():
    # No raise = pass
    _kuberesource.require_kind("pod", "pod")
    _kuberesource.require_kind("pod", "pod", "deployment")
    _kuberesource.require_kind("deployment", "pod", "deployment")


def test_require_kind_rejects_mismatch():
    with pytest.raises(CommandExecutionError, match="not valid for resource kind 'pod'"):
        _kuberesource.require_kind("pod", "deployment", "stateful_set")
