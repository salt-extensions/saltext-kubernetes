"""
Deep coverage for the drift-suppression kwargs on ``kubernetes.apply``.

The shallow file (``test_kubernetesmod_drift_suppression.py``) covers one
test per ignore_* kwarg; this file exercises:

  * Multiple ignore_* kwargs combined in a single apply
  * Nested ignore_fields paths (image, env)
  * Re-apply after kubectl-equivalent foreign mutation
  * Idempotency of repeated applies with ignore_* set

.. versionadded:: 2.1.0
"""

import json
import subprocess
import time

import pytest
from saltfactories.utils import random_string

pytestmark = [pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms")]


def _kubectl_apply_as(kind_cluster, doc, field_manager):
    """Apply *doc* via ``kubectl apply --server-side`` under a named field manager.

    Used by tests that need to simulate a foreign tool's ownership of
    specific fields. Server-side-apply tracks ownership per-manager, so
    this is the only realistic way to set up the "another tool owns
    this label" scenario that ``ignore_*`` is meant to handle.
    """
    subprocess.run(
        [
            "kubectl",
            "--kubeconfig",
            str(kind_cluster.kubeconfig_path),
            "apply",
            "--server-side",
            f"--field-manager={field_manager}",
            "--force-conflicts",
            "-f",
            "-",
        ],
        input=json.dumps(doc),
        text=True,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def cm_manifest_builder():
    def _build(**overrides):
        name = random_string("drift-deep-cm-", uppercase=False)
        doc = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": name,
                "namespace": "default",
                "labels": {
                    "app": "drift-deep",
                    "environment": "test",
                    "team": "platform",
                },
                "annotations": {
                    "salt-managed": "true",
                    "tool/sync": "v1",
                },
            },
            "data": {"key": "value"},
        }
        doc.update(overrides)
        return name, doc

    return _build


def test_combined_ignore_labels_annotations_fields(
    kubernetes_exe, cm_manifest_builder, kind_cluster
):
    """All three ignore_* kwargs simultaneously: each suppression honoured.

    Simulates a foreign tool (``external-tool``) that owns its own
    label and annotation on the object. After re-applying the salt
    manifest with the relevant keys listed in ``ignore_*``, those
    foreign-owned fields must survive — that's the user-facing
    contract for drift suppression.
    """
    name, doc = cm_manifest_builder()
    kubernetes_exe.apply(manifest=doc)
    try:
        # A foreign tool establishes ownership of its own label + annotation.
        # We use kubectl SSA with a distinct field manager so the apiserver
        # sees these as owned by ``external-tool``, not by ``salt``.
        foreign_doc = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": name,
                "namespace": "default",
                "labels": {"external-team": "owns"},
                "annotations": {"external-tool/heartbeat": "2026-05-12"},
            },
        }
        _kubectl_apply_as(kind_cluster, foreign_doc, "external-tool")
        live = kubernetes_exe.show_configmap(name=name, namespace="default")
        assert live["metadata"]["labels"]["external-team"] == "owns"
        assert live["metadata"]["annotations"]["external-tool/heartbeat"] == "2026-05-12"

        # Re-apply the salt manifest with all three ignore_* kwargs.
        kubernetes_exe.apply(
            manifest=doc,
            ignore_labels=["external-team"],
            ignore_annotations=["external-tool/heartbeat"],
            ignore_fields=["/data/nonexistent"],
        )
        live2 = kubernetes_exe.show_configmap(name=name, namespace="default")
        # Foreign-owned keys survive because salt never claimed them.
        assert live2["metadata"]["labels"].get("external-team") == "owns"
        assert live2["metadata"]["annotations"].get("external-tool/heartbeat") == "2026-05-12"
        # Salt-owned keys are still applied.
        assert live2["metadata"]["labels"]["app"] == "drift-deep"
    finally:
        kubernetes_exe.delete_configmap(name=name, namespace="default", wait=True)


def test_idempotent_apply_with_ignore_kwargs(kubernetes_exe, cm_manifest_builder):
    """Re-applying the same manifest with ignore_* set should be a no-op."""
    name, doc = cm_manifest_builder()
    try:
        kubernetes_exe.apply(manifest=doc, ignore_labels=["non-existent"])
        # Second apply: SSA fast-path, no-op on the server.
        kubernetes_exe.apply(manifest=doc, ignore_labels=["non-existent"])
        live = kubernetes_exe.show_configmap(name=name, namespace="default")
        assert live["data"]["key"] == "value"
    finally:
        kubernetes_exe.delete_configmap(name=name, namespace="default", wait=True)


def test_ignore_fields_nested_path(kubernetes_exe):
    """``ignore_fields`` accepts nested JSON-pointer paths like containers/0/image."""
    name = random_string("drift-nested-", uppercase=False)
    doc = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": "default"},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "nested"}},
            "template": {
                "metadata": {"labels": {"app": "nested"}},
                "spec": {"containers": [{"name": "pause", "image": "registry.k8s.io/pause:3.9"}]},
            },
        },
    }
    kubernetes_exe.apply(manifest=doc)
    try:
        # Foreign tool bumps the image tag.
        kubernetes_exe.patch_deployment(
            name=name,
            namespace="default",
            patch={
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [{"name": "pause", "image": "registry.k8s.io/pause:3.10"}]
                        }
                    }
                }
            },
        )
        time.sleep(1)
        # Re-apply our manifest with the container image path ignored.
        kubernetes_exe.apply(
            manifest=doc,
            ignore_fields=["/spec/template/spec/containers/0/image"],
        )
        time.sleep(1)
        live = kubernetes_exe.show_deployment(name=name, namespace="default")
        # The image bump survives because we declared we don't own the field.
        assert live["spec"]["template"]["spec"]["containers"][0]["image"].endswith(":3.10")
    finally:
        kubernetes_exe.delete_deployment(name=name, namespace="default", wait=True)


def test_ignore_labels_drops_only_named_keys(kubernetes_exe, cm_manifest_builder, kind_cluster):
    """ignore_labels=['environment'] drops only that key from salt's apply.

    The user-facing contract: when a foreign tool owns a label, listing
    it in ``ignore_labels`` makes salt's subsequent apply leave it
    alone, while still updating the keys salt does claim. Without a
    foreign owner the apiserver would garbage-collect the field once
    salt stopped claiming it — that's SSA's documented behaviour and
    is intentionally not what this kwarg protects against.
    """
    name, doc = cm_manifest_builder()
    try:
        # Salt applies its initial set of labels.
        kubernetes_exe.apply(manifest=doc)
        # Foreign tool takes ownership of the ``environment`` label.
        foreign_doc = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": name,
                "namespace": "default",
                "labels": {"environment": "test"},
            },
        }
        _kubectl_apply_as(kind_cluster, foreign_doc, "external-tool")

        # Salt re-applies, updating ``app`` and ignoring ``environment``.
        doc["metadata"]["labels"]["app"] = "drift-deep-v2"
        del doc["metadata"]["labels"]["environment"]
        kubernetes_exe.apply(manifest=doc, ignore_labels=["environment"])
        live2 = kubernetes_exe.show_configmap(name=name, namespace="default")
        # Salt-claimed key updated.
        assert live2["metadata"]["labels"]["app"] == "drift-deep-v2"
        # Foreign-owned key survives.
        assert live2["metadata"]["labels"]["environment"] == "test"
        # Other salt-claimed keys untouched.
        assert live2["metadata"]["labels"]["team"] == "platform"
    finally:
        kubernetes_exe.delete_configmap(name=name, namespace="default", wait=True)
