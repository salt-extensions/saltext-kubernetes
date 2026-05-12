"""
Functional tests for ``manifest_present`` / ``manifest_absent`` states.

These cover the generic apply path — the state-level wrapper around
``kubernetes.apply`` shipped in 2.1.0. Each test exercises a different
manifest shape: inline dict, source file, multi-doc YAML, CRD-style
arbitrary GVK.

.. versionadded:: 2.1.0
"""

from textwrap import dedent

import pytest
from saltfactories.utils import random_string

pytestmark = [pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms")]


@pytest.fixture
def kubernetes(states):
    return states.kubernetes


@pytest.fixture(params=[False, True])
def testmode(request):
    return request.param


@pytest.fixture
def cm_manifest():
    """A minimal ConfigMap manifest as an inline dict."""
    name = random_string("manifest-cm-", uppercase=False)
    return name, {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": "default"},
        "data": {"key": "value"},
    }


def test_manifest_present_inline_dict(kubernetes, cm_manifest, testmode, kubernetes_exe):
    name, doc = cm_manifest
    try:
        ret = kubernetes.manifest_present(name="apply-inline", manifest=doc, test=testmode)
        assert ret.result in (None, True)
        if not testmode:
            assert kubernetes_exe.show_configmap(name=name, namespace="default") is not None
        else:
            assert kubernetes_exe.show_configmap(name=name, namespace="default") is None
    finally:
        kubernetes_exe.delete_configmap(name=name, namespace="default", wait=True)


def test_manifest_present_idempotency(kubernetes, cm_manifest, testmode, kubernetes_exe):
    name, doc = cm_manifest
    try:
        kubernetes.manifest_present(name="apply-inline", manifest=doc)
        ret = kubernetes.manifest_present(name="apply-inline", manifest=doc, test=testmode)
        # Server-side apply on an unchanged manifest is a no-op.
        assert ret.result is True
    finally:
        kubernetes_exe.delete_configmap(name=name, namespace="default", wait=True)


def test_manifest_absent_inline_dict(kubernetes, cm_manifest, testmode, kubernetes_exe):
    name, doc = cm_manifest
    # First make it present so we have something to remove
    kubernetes.manifest_present(name="apply-inline", manifest=doc)
    ret = kubernetes.manifest_absent(name="apply-absent", manifest=doc, test=testmode)
    assert ret.result in (None, True)
    if not testmode:
        assert kubernetes_exe.show_configmap(name=name, namespace="default") is None


def test_manifest_absent_idempotency(kubernetes, cm_manifest, testmode, kubernetes_exe):
    name, doc = cm_manifest
    # Object never created — absent is already True.
    ret = kubernetes.manifest_absent(name="apply-absent", manifest=doc, test=testmode)
    assert ret.result is True
    assert kubernetes_exe.show_configmap(name=name, namespace="default") is None


@pytest.fixture
def multi_doc_source(state_tree):
    """A salt:// YAML source with two docs (ConfigMap + Service)."""
    cm_name = random_string("multi-cm-", uppercase=False)
    svc_name = random_string("multi-svc-", uppercase=False)
    contents = dedent(f"""
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: {cm_name}
          namespace: default
        data:
          key: value
        ---
        apiVersion: v1
        kind: Service
        metadata:
          name: {svc_name}
          namespace: default
        spec:
          selector:
            app: multidoc
          ports:
            - port: 80
              targetPort: 80
        """).strip()
    sls = "k8s/multi-doc-manifest"
    with pytest.helpers.temp_file(f"{sls}.yml", contents, state_tree):
        yield {"source": f"salt://{sls}.yml", "cm": cm_name, "svc": svc_name}


def test_manifest_present_multi_doc_source(kubernetes, multi_doc_source, kubernetes_exe):
    src = multi_doc_source
    try:
        ret = kubernetes.manifest_present(name="apply-multi", source=src["source"])
        assert ret.result is True
        assert kubernetes_exe.show_configmap(name=src["cm"], namespace="default") is not None
        assert kubernetes_exe.show_service(name=src["svc"], namespace="default") is not None
    finally:
        kubernetes_exe.delete_configmap(name=src["cm"], namespace="default", wait=True)
        kubernetes_exe.delete_service(name=src["svc"], namespace="default", wait=True)


@pytest.fixture
def templated_source(state_tree):
    """A Jinja-templated manifest source."""
    name = random_string("tmpl-cm-", uppercase=False)
    contents = dedent("""
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: {{ obj_name }}
          namespace: default
        data:
          env: {{ env }}
        """).strip()
    sls = "k8s/templated-manifest"
    with pytest.helpers.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        yield {"source": f"salt://{sls}.yml.jinja", "name": name}


def test_manifest_present_template_context(kubernetes, templated_source, kubernetes_exe):
    src = templated_source
    try:
        kubernetes.manifest_present(
            name="apply-tmpl",
            source=src["source"],
            template="jinja",
            template_context={"obj_name": src["name"], "env": "prod"},
        )
        live = kubernetes_exe.show_configmap(name=src["name"], namespace="default")
        assert live is not None
        assert live["data"]["env"] == "prod"
    finally:
        kubernetes_exe.delete_configmap(name=src["name"], namespace="default", wait=True)
