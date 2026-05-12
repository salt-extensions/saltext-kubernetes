"""
Functional tests for the drift-suppression kwargs on ``kubernetes.apply``.

Each test:

  1. Applies a manifest.
  2. Mutates the live object out-of-band (simulating a foreign controller
     or operator).
  3. Re-applies the original manifest with a matching ``ignore_*``.
  4. Asserts the foreign mutation is preserved.

.. versionadded:: 2.1.0
"""

import json
import subprocess
import time

import pytest
from saltfactories.utils import random_string  # pylint: disable=import-outside-toplevel

pytestmark = [pytest.mark.skip_unless_on_linux(reason="kind cluster fixture requires Linux")]


def _kubectl_apply_as(kind_cluster, doc, field_manager):
    """Apply *doc* via kubectl SSA under *field_manager* to simulate a foreign tool."""
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
def cm_manifest():
    """Build a fresh ConfigMap manifest dict for each test."""
    name = random_string("drift-cm-", uppercase=False)

    def _build(**overrides):
        doc = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": name,
                "namespace": "default",
                "labels": {"app": "drift-test", "environment": "prod"},
                "annotations": {"salt-managed": "true"},
            },
            "data": {"key": "value"},
        }
        doc.update(overrides)
        return doc, name

    return _build


def test_apply_ignore_labels_preserves_foreign_label(kubernetes_exe, cm_manifest, kind_cluster):
    doc, name = cm_manifest()
    kubernetes_exe.apply(manifest=doc)
    try:
        # Foreign tool takes ownership of its own label under a distinct
        # field manager (kubectl --field-manager=external-tool).
        _kubectl_apply_as(
            kind_cluster,
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": name,
                    "namespace": "default",
                    "labels": {"foreign-tool": "owns-this"},
                },
            },
            "external-tool",
        )
        # Salt re-applies, drifting its own label and ignoring the foreign one.
        doc["metadata"]["labels"]["app"] = "drift-test-v2"
        kubernetes_exe.apply(manifest=doc, ignore_labels=["foreign-tool"])
        live2 = kubernetes_exe.show_configmap(name=name, namespace="default")
        assert live2["metadata"]["labels"]["app"] == "drift-test-v2"
        assert live2["metadata"]["labels"].get("foreign-tool") == "owns-this"
    finally:
        kubernetes_exe.delete_configmap(name=name, namespace="default", wait=True)


def test_apply_ignore_annotations_preserves_foreign_annotation(
    kubernetes_exe, cm_manifest, kind_cluster
):
    doc, name = cm_manifest()
    kubernetes_exe.apply(manifest=doc)
    try:
        _kubectl_apply_as(
            kind_cluster,
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": name,
                    "namespace": "default",
                    "annotations": {"external-tool/last-sync": "2026-05-12T00:00:00Z"},
                },
            },
            "external-tool",
        )
        kubernetes_exe.apply(manifest=doc, ignore_annotations=["external-tool/last-sync"])
        live2 = kubernetes_exe.show_configmap(name=name, namespace="default")
        assert (
            live2["metadata"]["annotations"].get("external-tool/last-sync")
            == "2026-05-12T00:00:00Z"
        )
    finally:
        kubernetes_exe.delete_configmap(name=name, namespace="default", wait=True)


def test_apply_ignore_fields_preserves_foreign_scale(kubernetes_exe):
    """An HPA-like controller scaled the Deployment; we ignore_fields=replicas."""
    name = random_string("drift-dep-", uppercase=False)
    doc = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": "default"},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "drift"}},
            "template": {
                "metadata": {"labels": {"app": "drift"}},
                "spec": {"containers": [{"name": "pause", "image": "registry.k8s.io/pause:3.9"}]},
            },
        },
    }
    kubernetes_exe.apply(manifest=doc)
    try:
        # Simulate HPA scaling the Deployment to 3 replicas.
        kubernetes_exe.scale(kind="deployment", name=name, namespace="default", replicas=3)
        time.sleep(1)
        # Re-apply original (replicas=1) with ignore_fields → scale is preserved.
        kubernetes_exe.apply(manifest=doc, ignore_fields=["/spec/replicas"])
        time.sleep(1)
        live = kubernetes_exe.show_deployment(name=name, namespace="default")
        assert live["spec"]["replicas"] == 3
    finally:
        kubernetes_exe.delete_deployment(name=name, namespace="default", wait=True)
