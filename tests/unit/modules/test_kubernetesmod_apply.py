"""
Unit tests for the public generic-apply path on
``saltext.kubernetes.modules.kubernetesmod``.

These exercise input shaping (manifest vs source vs YAML string),
multi-doc parsing, namespace defaulting, and the parameter validation
that fires before any API call.
"""

import pytest
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.modules import kubernetesmod

# ---------------------------------------------------------------------------
# _normalise_apply_input
# ---------------------------------------------------------------------------


def test_normalise_apply_input_dict_passthrough():
    out = kubernetesmod._normalise_apply_input(
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "x"}},
        None,
        None,
        None,
        None,
    )
    assert len(out) == 1
    assert out[0]["kind"] == "ConfigMap"


def test_normalise_apply_input_list_passthrough():
    docs = [
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "x"}},
        {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "y"}},
    ]
    out = kubernetesmod._normalise_apply_input(docs, None, None, None, None)
    assert len(out) == 2
    assert {d["kind"] for d in out} == {"ConfigMap", "Secret"}


def test_normalise_apply_input_yaml_string_single_doc():
    yaml_str = """
apiVersion: v1
kind: ConfigMap
metadata:
  name: x
"""
    out = kubernetesmod._normalise_apply_input(yaml_str, None, None, None, None)
    assert len(out) == 1
    assert out[0]["kind"] == "ConfigMap"


def test_normalise_apply_input_yaml_string_multi_doc():
    """Multi-doc YAML splits cleanly into a list."""
    yaml_str = """
apiVersion: v1
kind: ConfigMap
metadata:
  name: a
---
apiVersion: v1
kind: Secret
metadata:
  name: b
"""
    out = kubernetesmod._normalise_apply_input(yaml_str, None, None, None, None)
    assert len(out) == 2
    assert out[0]["kind"] == "ConfigMap"
    assert out[1]["kind"] == "Secret"


def test_normalise_apply_input_drops_empty_docs():
    """Empty doc separators (e.g. trailing ---) yield no document."""
    yaml_str = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n---\n---\n"
    out = kubernetesmod._normalise_apply_input(yaml_str, None, None, None, None)
    assert len(out) == 1


def test_normalise_apply_input_neither_arg_raises():
    with pytest.raises(CommandExecutionError, match="Either 'manifest' or 'source'"):
        kubernetesmod._normalise_apply_input(None, None, None, None, None)


def test_normalise_apply_input_rejects_bad_type():
    with pytest.raises(CommandExecutionError, match="must be a dict, list, or YAML string"):
        kubernetesmod._normalise_apply_input(42, None, None, None, None)


def test_normalise_apply_input_list_with_non_dict_entry_raises():
    with pytest.raises(CommandExecutionError, match="must be a dictionary"):
        kubernetesmod._normalise_apply_input(
            [{"apiVersion": "v1"}, "not-a-dict"], None, None, None, None
        )


# ---------------------------------------------------------------------------
# _apply_namespace_default
# ---------------------------------------------------------------------------


def test_namespace_default_fills_when_missing():
    doc = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "x"}}
    kubernetesmod._apply_namespace_default(doc, "production")
    assert doc["metadata"]["namespace"] == "production"


def test_namespace_default_does_not_overwrite():
    doc = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "x", "namespace": "kube-system"},
    }
    kubernetesmod._apply_namespace_default(doc, "production")
    assert doc["metadata"]["namespace"] == "kube-system"


def test_namespace_default_with_no_default_is_noop():
    doc = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "x"}}
    kubernetesmod._apply_namespace_default(doc, None)
    assert "namespace" not in doc["metadata"]


def test_namespace_default_creates_metadata_if_missing():
    """A doc without metadata at all gets a fresh metadata dict."""
    doc = {"apiVersion": "v1", "kind": "ConfigMap"}
    kubernetesmod._apply_namespace_default(doc, "production")
    assert doc["metadata"] == {"namespace": "production"}
