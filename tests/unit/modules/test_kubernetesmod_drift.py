"""
Unit tests for the drift-suppression hooks on ``kubernetes.apply``
(``ignore_labels`` / ``ignore_annotations`` / ``ignore_fields``).
"""

from saltext.kubernetes.modules import kubernetesmod


def _doc(**overrides):
    """Build a minimal valid manifest, optionally overriding fields."""
    base = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "nginx",
            "namespace": "default",
            "labels": {
                "app": "nginx",
                "environment": "prod",
                "owner": "platform-team",
            },
            "annotations": {
                "salt-managed": "true",
                "external-tool/last-sync": "2026-01-01",
            },
        },
        "spec": {
            "replicas": 3,
            "selector": {"matchLabels": {"app": "nginx"}},
            "template": {
                "metadata": {"labels": {"app": "nginx"}},
                "spec": {"containers": [{"name": "c", "image": "nginx:1.27"}]},
            },
        },
    }
    base.update(overrides)
    return base


def test_strip_ignored_noop_when_no_filters():
    doc = _doc()
    assert kubernetesmod._strip_ignored(doc, None, None, None) is doc


def test_strip_ignored_removes_named_labels():
    doc = _doc()
    out = kubernetesmod._strip_ignored(doc, ["environment"], None, None)
    assert "environment" not in out["metadata"]["labels"]
    # Untouched keys preserved
    assert out["metadata"]["labels"]["app"] == "nginx"
    assert out["metadata"]["labels"]["owner"] == "platform-team"
    # Original input not mutated
    assert "environment" in doc["metadata"]["labels"]


def test_strip_ignored_removes_all_labels_drops_key():
    doc = _doc()
    out = kubernetesmod._strip_ignored(doc, ["app", "environment", "owner"], None, None)
    assert "labels" not in out["metadata"]


def test_strip_ignored_removes_named_annotations():
    doc = _doc()
    out = kubernetesmod._strip_ignored(doc, None, ["external-tool/last-sync"], None)
    assert "external-tool/last-sync" not in out["metadata"]["annotations"]
    assert out["metadata"]["annotations"]["salt-managed"] == "true"


def test_strip_ignored_drops_json_pointer_field():
    doc = _doc()
    out = kubernetesmod._strip_ignored(doc, None, None, ["/spec/replicas"])
    assert "replicas" not in out["spec"]
    # Sibling keys preserved
    assert "selector" in out["spec"]


def test_strip_ignored_accepts_dotted_field_pointer():
    doc = _doc()
    out = kubernetesmod._strip_ignored(doc, None, None, ["spec.replicas"])
    assert "replicas" not in out["spec"]


def test_strip_ignored_missing_field_is_noop():
    doc = _doc()
    # Removing a non-existent path doesn't raise
    out = kubernetesmod._strip_ignored(doc, None, None, ["/spec/does/not/exist"])
    # The deepcopy still preserves all original fields
    assert out["spec"]["replicas"] == 3


def test_strip_ignored_combined_filters():
    doc = _doc()
    out = kubernetesmod._strip_ignored(
        doc,
        ignore_labels=["environment"],
        ignore_annotations=["external-tool/last-sync"],
        ignore_fields=["/spec/replicas"],
    )
    assert "environment" not in out["metadata"]["labels"]
    assert "external-tool/last-sync" not in out["metadata"]["annotations"]
    assert "replicas" not in out["spec"]


def test_strip_ignored_label_pop_handles_missing_metadata_labels():
    doc = _doc()
    doc["metadata"].pop("labels", None)
    # Should not raise even though metadata.labels is missing
    out = kubernetesmod._strip_ignored(doc, ["environment"], None, None)
    assert "labels" not in out["metadata"]


def test_drop_json_pointer_handles_nested_paths():
    target = {"spec": {"template": {"spec": {"serviceAccountName": "x", "containers": []}}}}
    kubernetesmod._drop_json_pointer(target, "/spec/template/spec/serviceAccountName")
    assert "serviceAccountName" not in target["spec"]["template"]["spec"]
    assert "containers" in target["spec"]["template"]["spec"]


def test_drop_json_pointer_handles_empty_pointer():
    target = {"spec": {"replicas": 3}}
    kubernetesmod._drop_json_pointer(target, "")
    assert target == {"spec": {"replicas": 3}}


def test_drop_json_pointer_handles_non_dict_intermediate():
    target = {"spec": {"replicas": 3}}
    # ``replicas`` is an int; traversing into it should be a no-op
    kubernetesmod._drop_json_pointer(target, "/spec/replicas/anything")
    assert target["spec"]["replicas"] == 3


def test_drop_json_pointer_drops_field_inside_list_element():
    """RFC 6901: integer segments index into lists.

    Pointers like ``/spec/template/spec/containers/0/image`` are the
    canonical way to target a field inside a specific list element —
    if this didn't traverse lists, ``ignore_fields`` could not be used
    to suppress drift on container images, ports, or env vars.
    """
    target = {
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {"name": "app", "image": "old:tag"},
                        {"name": "sidecar", "image": "log:tag"},
                    ]
                }
            }
        }
    }
    kubernetesmod._drop_json_pointer(target, "/spec/template/spec/containers/0/image")
    assert "image" not in target["spec"]["template"]["spec"]["containers"][0]
    # The second element is untouched.
    assert target["spec"]["template"]["spec"]["containers"][1]["image"] == "log:tag"


def test_drop_json_pointer_drops_whole_list_element():
    target = {"items": [{"a": 1}, {"b": 2}, {"c": 3}]}
    kubernetesmod._drop_json_pointer(target, "/items/1")
    assert target == {"items": [{"a": 1}, {"c": 3}]}


def test_drop_json_pointer_out_of_range_list_index_is_noop():
    target = {"items": [{"a": 1}]}
    kubernetesmod._drop_json_pointer(target, "/items/5/a")
    assert target == {"items": [{"a": 1}]}


def test_drop_json_pointer_non_integer_segment_into_list_is_noop():
    target = {"items": [{"a": 1}]}
    kubernetesmod._drop_json_pointer(target, "/items/notanumber/a")
    assert target == {"items": [{"a": 1}]}
