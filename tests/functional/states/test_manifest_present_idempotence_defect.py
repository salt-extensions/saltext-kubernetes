"""Regression test for manifest_present never reporting idempotence.

DEFECT
------
On a live (non-test) run, ``manifest_present`` ends with::

    ret["comment"] = "Manifests applied via server-side apply"
    ret["changes"] = {"applied": res}

``changes`` is populated unconditionally from the apply response, without any
comparison against the object already in the cluster. The state therefore
reports changes on every run, forever, even when the manifest and the live
object are byte-identical.

The capability is already present: the ``test=True`` branch a few lines above
performs a server-side dry run and builds a real diff, emitting
``{"old": None, "new": "would create"}`` or
``{"old": "present", "new": "would update"}``, and correctly reports no changes
when there is nothing to do. Only the live path skips it.

IMPACT
------
This is a reporting defect rather than a behavioural one -- server-side apply is
still idempotent against the cluster -- but the consequences are practical:

* Every highstate reports changed resources, so genuine drift is buried in noise.
* Any workflow keyed on "did anything change" (notify/onchanges requisites,
  change-gated CI, drift dashboards) fires on every run.
* ``manifest_present`` is the only option for kinds with no typed state, such as
  cert-manager's Certificate and Issuer, so users managing CRDs cannot get
  trustworthy change reporting at all.

SUGGESTED FIX
-------------
Reuse the dry-run comparison on the live path: fetch the current object, apply,
and populate ``changes`` only where the two differ, ignoring server-managed
fields (``resourceVersion``, ``managedFields``, ``generation``, ``status``,
``creationTimestamp``, ``uid``).
"""

from textwrap import dedent

import pytest


@pytest.mark.xfail(
    reason="defect: live apply sets changes unconditionally instead of diffing",
    strict=True,
)
@pytest.mark.parametrize("configmap", [False], indirect=True)
def test_manifest_present_is_idempotent(kubernetes, configmap, state_tree):
    """Re-applying an unchanged manifest must report no changes."""
    sls = "k8s/manifest-idempotent"
    contents = dedent(f"""
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: {configmap["name"]}
          namespace: {configmap["namespace"]}
        data:
          greeting: hello
        """).strip()

    with pytest.helpers.temp_file(f"{sls}.yml", contents, state_tree):
        first = kubernetes.manifest_present(
            name="manifest-idempotent", source=f"salt://{sls}.yml"
        )
        assert first.result is True
        assert first.changes, "the first apply should report a creation"

        second = kubernetes.manifest_present(
            name="manifest-idempotent", source=f"salt://{sls}.yml"
        )

    assert second.result is True
    assert not second.changes, f"unchanged manifest still reported {second.changes}"
