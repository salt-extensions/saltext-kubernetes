"""
Unit tests for the ansible-parity additions:

  * ``append_hash`` on ``create_configmap`` / ``create_secret``
  * ``patch_object`` with alternate patch types
  * ``validate=True`` pre-flight on ``apply``

The functional behaviour against a real cluster is exercised in
``tests/functional/modules/test_kubernetesmod_ansible_parity.py``; this
file covers pure-Python invariants (determinism, error messages, GVK
inference) without touching the kubernetes API.
"""

from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.modules import kubernetesmod
from saltext.kubernetes.utils import _dynamic

# ---------------------------------------------------------------------------
# append_hash determinism
# ---------------------------------------------------------------------------


def test_hash_suffix_deterministic_for_same_input():
    a = kubernetesmod._hash_suffix({"k": "v"})
    b = kubernetesmod._hash_suffix({"k": "v"})
    assert a == b


def test_hash_suffix_changes_when_data_changes():
    a = kubernetesmod._hash_suffix({"k": "v1"})
    b = kubernetesmod._hash_suffix({"k": "v2"})
    assert a != b


def test_hash_suffix_dict_ordering_independent():
    a = kubernetesmod._hash_suffix({"a": "1", "b": "2"})
    b = kubernetesmod._hash_suffix({"b": "2", "a": "1"})
    assert a == b


def test_hash_suffix_length_fits_dns_label_budget():
    """63 - len('-') - len(suffix) must leave room for a meaningful base name."""
    suffix = kubernetesmod._hash_suffix({"k": "v"})
    assert len(suffix) <= 12  # 10 plus margin
    # DNS-label-safe character set
    assert all(c.isdigit() or (c.islower() and c.isalpha()) for c in suffix)


def test_hash_suffix_distinguishes_value_vs_key_changes():
    """Swapping value-vs-key (same letters, different positions) gives different hashes."""
    a = kubernetesmod._hash_suffix({"foo": "bar"})
    b = kubernetesmod._hash_suffix({"bar": "foo"})
    assert a != b


# ---------------------------------------------------------------------------
# patch_object GVK inference
# ---------------------------------------------------------------------------


def test_infer_api_version_snake_case():
    assert kubernetesmod._infer_api_version("deployment") == "apps/v1"
    assert kubernetesmod._infer_api_version("configmap") == "v1"
    assert kubernetesmod._infer_api_version("cluster_role") == "rbac.authorization.k8s.io/v1"


def test_infer_api_version_camel_case():
    assert kubernetesmod._infer_api_version("Deployment") == "apps/v1"
    assert kubernetesmod._infer_api_version("ConfigMap") == "v1"
    assert kubernetesmod._infer_api_version("ClusterRole") == "rbac.authorization.k8s.io/v1"


def test_infer_api_version_unknown_kind_raises():
    with pytest.raises(CommandExecutionError, match="Cannot infer api_version"):
        kubernetesmod._infer_api_version("MyCustomResource")


# ---------------------------------------------------------------------------
# _dynamic.patch_object validation
# ---------------------------------------------------------------------------


def test_patch_object_rejects_unknown_patch_type():
    """Bad ``patch_type`` produces an actionable error before any API call."""
    with pytest.raises(CommandExecutionError, match="Unknown patch_type"):
        _dynamic.patch_object(
            api_version="v1",
            kind="ConfigMap",
            name="x",
            patch={"data": {"k": "v"}},
            namespace="default",
            patch_type="bogus",
        )


def test_patch_object_json_patch_requires_list():
    """RFC 6902 patches must be lists of operation dicts, not a single dict."""
    with pytest.raises(CommandExecutionError, match="requires a list"):
        _dynamic.patch_object(
            api_version="v1",
            kind="ConfigMap",
            name="x",
            patch={"data": {"k": "v"}},
            namespace="default",
            patch_type="json",
        )


def test_patch_object_strategic_uses_correct_content_type():
    """The Content-Type header drives server-side merge semantics."""
    fake_resource = MagicMock()
    fake_resource.namespaced = True
    fake_resource.patch.return_value.to_dict.return_value = {"applied": True}
    with patch.object(_dynamic, "get_resource", return_value=fake_resource):
        _dynamic.patch_object(
            api_version="apps/v1",
            kind="Deployment",
            name="x",
            patch={"spec": {"replicas": 3}},
            namespace="default",
            patch_type="strategic",
        )
    assert (
        fake_resource.patch.call_args.kwargs["content_type"]
        == "application/strategic-merge-patch+json"
    )


def test_patch_object_json_merge_uses_correct_content_type():
    fake_resource = MagicMock()
    fake_resource.namespaced = True
    fake_resource.patch.return_value.to_dict.return_value = {}
    with patch.object(_dynamic, "get_resource", return_value=fake_resource):
        _dynamic.patch_object(
            api_version="example.com/v1",
            kind="MyCR",
            name="x",
            patch={"spec": {"replicas": 3}},
            namespace="default",
            patch_type="json-merge",
        )
    assert fake_resource.patch.call_args.kwargs["content_type"] == "application/merge-patch+json"


def test_patch_object_json_patch_uses_correct_content_type():
    fake_resource = MagicMock()
    fake_resource.namespaced = True
    fake_resource.patch.return_value.to_dict.return_value = {}
    with patch.object(_dynamic, "get_resource", return_value=fake_resource):
        _dynamic.patch_object(
            api_version="apps/v1",
            kind="Deployment",
            name="x",
            patch=[{"op": "replace", "path": "/spec/replicas", "value": 5}],
            namespace="default",
            patch_type="json",
        )
    assert fake_resource.patch.call_args.kwargs["content_type"] == "application/json-patch+json"


def test_patch_object_namespaced_kind_requires_namespace():
    fake_resource = MagicMock()
    fake_resource.namespaced = True
    with patch.object(_dynamic, "get_resource", return_value=fake_resource):
        with pytest.raises(CommandExecutionError, match="requires 'namespace'"):
            _dynamic.patch_object(
                api_version="apps/v1",
                kind="Deployment",
                name="x",
                patch={"spec": {}},
                patch_type="strategic",
            )
