"""
Unit tests for the node-annotation functions on
``saltext.kubernetes.modules.kubernetesmod``.

  * ``node_annotations`` — read
  * ``node_add_annotation`` — create/update
  * ``node_remove_annotation`` — delete via JSON-merge null
"""

from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from kubernetes.client.rest import ApiException
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.modules import kubernetesmod


def test_node_annotations_returns_dict_when_present():
    """A node with annotations returns the dict verbatim."""
    with patch("saltext.kubernetes.modules.kubernetesmod.node") as mock_node:
        mock_node.return_value = {
            "metadata": {
                "annotations": {
                    "example.com/owner": "ops",
                    "node.alpha.kubernetes.io/ttl": "0",
                }
            }
        }
        assert kubernetesmod.node_annotations("worker-1") == {
            "example.com/owner": "ops",
            "node.alpha.kubernetes.io/ttl": "0",
        }


def test_node_annotations_returns_empty_when_node_missing():
    """A node that doesn't exist returns an empty dict (mirrors node_labels)."""
    with patch("saltext.kubernetes.modules.kubernetesmod.node", return_value=None):
        assert kubernetesmod.node_annotations("nope") == {}


def test_node_annotations_returns_empty_when_metadata_lacks_key():
    """A node whose metadata has no ``annotations`` key returns an empty dict."""
    with patch(
        "saltext.kubernetes.modules.kubernetesmod.node",
        return_value={"metadata": {}},
    ):
        assert kubernetesmod.node_annotations("worker-1") == {}


def test_node_add_annotation_patches_with_string_value():
    """``annotation_value`` is coerced to str and sent as a strategic-merge patch."""
    fake_api = MagicMock()
    fake_api.read_node.return_value = MagicMock()  # node exists
    fake_api.patch_node.return_value = MagicMock(metadata=MagicMock(name="worker-1"))
    with (
        patch.object(kubernetesmod, "kubernetes") as mock_k8s,
        patch.object(kubernetesmod, "_setup_conn", return_value={}),
        patch.object(kubernetesmod, "_cleanup"),
    ):
        mock_k8s.client.CoreV1Api.return_value = fake_api
        kubernetesmod.node_add_annotation("worker-1", "example.com/owner", 42)
    fake_api.patch_node.assert_called_once()
    sent_body = fake_api.patch_node.call_args[0][1]
    assert sent_body == {"metadata": {"annotations": {"example.com/owner": "42"}}}


def test_node_add_annotation_raises_clear_error_when_node_missing():
    """A 404 from ``read_node`` is surfaced as a clear error."""
    fake_api = MagicMock()
    fake_api.read_node.side_effect = ApiException(status=404)
    with (
        patch.object(kubernetesmod, "kubernetes") as mock_k8s,
        patch.object(kubernetesmod, "_setup_conn", return_value={}),
        patch.object(kubernetesmod, "_cleanup"),
    ):
        mock_k8s.client.CoreV1Api.return_value = fake_api
        with pytest.raises(CommandExecutionError, match="not found"):
            kubernetesmod.node_add_annotation("nope", "key", "value")


def test_node_remove_annotation_patches_with_null():
    """Removing sends a null value under the annotation key (JSON-merge delete)."""
    fake_api = MagicMock()
    fake_api.patch_node.return_value = MagicMock()
    with (
        patch.object(kubernetesmod, "kubernetes") as mock_k8s,
        patch.object(kubernetesmod, "_setup_conn", return_value={}),
        patch.object(kubernetesmod, "_cleanup"),
    ):
        mock_k8s.client.CoreV1Api.return_value = fake_api
        kubernetesmod.node_remove_annotation("worker-1", "example.com/owner")
    sent_body = fake_api.patch_node.call_args[0][1]
    assert sent_body == {"metadata": {"annotations": {"example.com/owner": None}}}


def test_node_remove_annotation_raises_when_node_missing():
    fake_api = MagicMock()
    fake_api.patch_node.side_effect = ApiException(status=404)
    with (
        patch.object(kubernetesmod, "kubernetes") as mock_k8s,
        patch.object(kubernetesmod, "_setup_conn", return_value={}),
        patch.object(kubernetesmod, "_cleanup"),
    ):
        mock_k8s.client.CoreV1Api.return_value = fake_api
        with pytest.raises(CommandExecutionError, match="not found"):
            kubernetesmod.node_remove_annotation("nope", "key")
