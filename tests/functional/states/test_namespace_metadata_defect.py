"""Regression test for: ``namespace_present`` cannot manage labels or annotations.

DEFECT
------
Every typed ``*_present`` state in this module accepts ``metadata``, ``spec``,
``source``, ``template`` and ``template_context``. ``namespace_present`` does
not (``states/kubernetes.py``)::

    def namespace_present(name, **kwargs):

It can only assert existence. It also short-circuits on an existing object::

    else:
        ret["result"] = True
        ret["comment"] = "The namespace already exists"

so it never reconciles drift, unlike its siblings which patch toward the
declared state.

IMPACT
------
Namespace metadata is not decorative. Pod Security Admission is configured
entirely through namespace labels::

    pod-security.kubernetes.io/enforce: restricted

as are Istio/Linkerd sidecar injection, many network-policy selectors, and cost
attribution labels. None of these can be expressed through this state today, so
a namespace that must carry them has to be managed out of band, or through
``manifest_present``, which gives up the typed state's reporting and test-mode
behaviour.

The inconsistency is also a usability trap: the argument shape that works for
every other kind silently does nothing here, because the extra arguments are
swallowed by ``**kwargs`` and forwarded to the connection setup instead of
being applied to the object.

SUGGESTED FIX
-------------
Bring it in line with the other typed states::

    def namespace_present(
        name, metadata=None, source="", template="", template_context=None, **kwargs
    ):

and patch an existing namespace when the declared metadata differs, rather than
returning early. ``create_namespace`` already accepts ``body``/``template``, so
most of the plumbing exists; the state is the part that never wired it up.
"""

from textwrap import dedent

import pytest


@pytest.mark.xfail(reason="defect: namespace_present ignores metadata", strict=True)
@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_namespace_present_applies_metadata(kubernetes, namespace, kubernetes_exe):
    """Labels passed to the state must land on the namespace."""
    ret = kubernetes.namespace_present(
        name=namespace,
        metadata={"labels": {"pod-security.kubernetes.io/enforce": "restricted"}},
    )
    assert ret.result is True

    namespace_state = kubernetes_exe.show_namespace(name=namespace)
    labels = namespace_state["metadata"].get("labels") or {}
    assert labels.get("pod-security.kubernetes.io/enforce") == "restricted"


@pytest.mark.xfail(reason="defect: namespace_present accepts no source/template", strict=True)
@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_namespace_present_from_source_manifest(kubernetes, namespace, state_tree, kubernetes_exe):
    """A sourced manifest must be honoured, as it is for every other kind."""
    sls = "k8s/namespace-labelled"
    contents = dedent("""
        apiVersion: v1
        kind: Namespace
        metadata:
          name: {{ name }}
          labels:
            name: {{ name }}
            team: platform
        """).strip()

    with pytest.helpers.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        ret = kubernetes.namespace_present(
            name=namespace,
            source=f"salt://{sls}.yml.jinja",
            template="jinja",
            template_context={"name": namespace},
        )
    assert ret.result is True

    namespace_state = kubernetes_exe.show_namespace(name=namespace)
    assert (namespace_state["metadata"].get("labels") or {}).get("team") == "platform"


@pytest.mark.xfail(reason="defect: namespace_present never reconciles an existing object", strict=True)
@pytest.mark.parametrize("namespace", [False], indirect=True)
def test_namespace_present_reconciles_drift(kubernetes, namespace, kubernetes_exe):
    """A second run with changed metadata must patch, not report success and do nothing."""
    kubernetes.namespace_present(name=namespace, metadata={"labels": {"stage": "one"}})
    ret = kubernetes.namespace_present(name=namespace, metadata={"labels": {"stage": "two"}})
    assert ret.result is True

    namespace_state = kubernetes_exe.show_namespace(name=namespace)
    assert (namespace_state["metadata"].get("labels") or {}).get("stage") == "two"
