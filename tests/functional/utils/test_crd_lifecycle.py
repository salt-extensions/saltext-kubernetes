"""
Functional tests for CRD lifecycle via the generic apply / patch path.

The extension claims to support arbitrary CRDs via ``kubernetes.apply``
and ``kubernetes.patch_object``. This file proves it end-to-end:

  1. Install a CRD via ``apply``.
  2. Wait for the CRD to reach ``Established``.
  3. Invalidate the dynamic-client discovery cache.
  4. Create a CR via ``apply``.
  5. Patch the CR with ``patch_type='json-merge'`` (CRDs reject
     strategic-merge because the registry has no merge directives).
  6. Validate with ``validate=True``.
  7. Delete the CR, then the CRD.

.. versionadded:: 2.1.0
"""

import subprocess
import time

import pytest
import yaml as _pyyaml
from salt.exceptions import CommandExecutionError
from saltfactories.utils import random_string

from saltext.kubernetes.utils import _dynamic

pytestmark = [pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms")]


CRD_GROUP = "example.io"
CRD_PLURAL = "saltwidgets"
CRD_KIND = "SaltWidget"
CRD_NAME = f"{CRD_PLURAL}.{CRD_GROUP}"


@pytest.fixture(scope="module")
def crd_manifest():
    """The CRD manifest used by every test in this file."""
    return {
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {"name": CRD_NAME},
        "spec": {
            "group": CRD_GROUP,
            "names": {
                "plural": CRD_PLURAL,
                "singular": "saltwidget",
                "kind": CRD_KIND,
                "shortNames": ["swg"],
            },
            "scope": "Namespaced",
            "versions": [
                {
                    "name": "v1",
                    "served": True,
                    "storage": True,
                    "schema": {
                        "openAPIV3Schema": {
                            "type": "object",
                            "properties": {
                                "spec": {
                                    "type": "object",
                                    "properties": {
                                        "color": {"type": "string"},
                                        "count": {"type": "integer"},
                                    },
                                }
                            },
                        }
                    },
                }
            ],
        },
    }


@pytest.fixture(scope="module")
def installed_crd(kind_cluster, crd_manifest):
    """Install the CRD once per module and wait until its API route serves traffic.

    Installed via ``kubectl apply`` (subprocess), not via the extension's
    own ``apply`` — these tests are meant to exercise the extension
    against a CRD, not to bootstrap the CRD with the very feature under
    test. Module-scoped because reinstalling the same CRD per-test
    triggers a race: the previous test's delete (which kicks off async
    garbage collection of any CRs and storage-route teardown) isn't
    finished by the time the next test's install fires. The apiserver
    then accepts the new CRD definition but can take tens of seconds to
    fully wire up the storage routes, during which SSA PATCH against
    the custom-resource handler returns a plain-text ``404 page not
    found`` from Go's default mux.

    Two-stage readiness wait: the CRD's ``Established`` condition only
    means the apiserver has registered the GVK in *discovery*. The
    aggregated storage handler that serves PATCH/GET/LIST against
    ``/apis/<group>/<version>/<resource>`` can take several more
    seconds. So we probe both: first wait for discovery to find the
    kind, then probe the exact code path the tests use (a dry-run SSA)
    until it succeeds.
    """
    kubeconfig = str(kind_cluster.kubeconfig_path)
    crd_yaml = _pyyaml.safe_dump(crd_manifest)
    subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "-"],
        input=crd_yaml,
        text=True,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "kubectl",
            "--kubeconfig",
            kubeconfig,
            "wait",
            "--for=condition=Established",
            f"crd/{CRD_NAME}",
            "--timeout=60s",
        ],
        check=True,
        capture_output=True,
    )

    # Prime the kubernetes-client default Configuration so the
    # ``_dynamic`` helpers (which read the default Configuration) can
    # reach the cluster. Without this they default to localhost:80.
    import kubernetes  # pylint: disable=import-outside-toplevel

    kubernetes.config.load_kube_config(  # pylint: disable=no-member
        config_file=kubeconfig, context="kind-salt-test"
    )
    _dynamic.invalidate_caches()

    deadline = time.monotonic() + 60
    resource = None
    while time.monotonic() < deadline:
        try:
            resource = _dynamic.get_resource(f"{CRD_GROUP}/v1", CRD_KIND)
            break
        except CommandExecutionError:
            _dynamic.invalidate_caches()
            time.sleep(1)
    assert resource is not None, "CRD never became discoverable"

    probe_doc = {
        "apiVersion": f"{CRD_GROUP}/v1",
        "kind": CRD_KIND,
        "metadata": {"name": "ready-probe", "namespace": "default"},
        "spec": {"color": "probe", "count": 0},
    }
    while time.monotonic() < deadline:
        try:
            _dynamic.apply_manifest(probe_doc, dry_run=True)
            break
        except CommandExecutionError:
            time.sleep(1)
    else:
        raise AssertionError("CRD SSA endpoint never started serving traffic")

    yield
    subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig, "delete", "crd", CRD_NAME, "--ignore-not-found"],
        check=False,
        capture_output=True,
    )
    _dynamic.invalidate_caches()


def test_crd_install_makes_kind_discoverable(installed_crd):
    """After CRD install + cache invalidation, ``get_resource`` finds the kind."""
    res = _dynamic.get_resource(f"{CRD_GROUP}/v1", CRD_KIND)
    assert res.namespaced is True
    assert res.kind == CRD_KIND


def test_cr_create_via_apply(kubernetes_exe, installed_crd):
    """A CR can be created via ``kubernetes.apply``."""
    name = random_string("widget-", uppercase=False)
    doc = {
        "apiVersion": f"{CRD_GROUP}/v1",
        "kind": CRD_KIND,
        "metadata": {"name": name, "namespace": "default"},
        "spec": {"color": "blue", "count": 3},
    }
    try:
        kubernetes_exe.apply(manifest=doc)
        live = _dynamic.get_object(f"{CRD_GROUP}/v1", CRD_KIND, name=name, namespace="default")
        assert live["spec"]["color"] == "blue"
        assert live["spec"]["count"] == 3
    finally:
        kubernetes_exe.delete_manifest(manifest=doc)


def test_cr_patch_json_merge(kubernetes_exe, installed_crd):
    """``patch_object`` with ``patch_type='json-merge'`` updates a CR."""
    name = random_string("widget-merge-", uppercase=False)
    doc = {
        "apiVersion": f"{CRD_GROUP}/v1",
        "kind": CRD_KIND,
        "metadata": {"name": name, "namespace": "default"},
        "spec": {"color": "red", "count": 1},
    }
    try:
        kubernetes_exe.apply(manifest=doc)
        kubernetes_exe.patch_object(
            kind=CRD_KIND,
            name=name,
            namespace="default",
            api_version=f"{CRD_GROUP}/v1",
            patch={"spec": {"count": 5}},
            patch_type="json-merge",
        )
        live = _dynamic.get_object(f"{CRD_GROUP}/v1", CRD_KIND, name=name, namespace="default")
        assert live["spec"]["color"] == "red"  # untouched
        assert live["spec"]["count"] == 5  # updated
    finally:
        kubernetes_exe.delete_manifest(manifest=doc)


def test_cr_patch_json_6902(kubernetes_exe, installed_crd):
    """``patch_type='json'`` applies an RFC 6902 op list."""
    name = random_string("widget-6902-", uppercase=False)
    doc = {
        "apiVersion": f"{CRD_GROUP}/v1",
        "kind": CRD_KIND,
        "metadata": {"name": name, "namespace": "default"},
        "spec": {"color": "green", "count": 2},
    }
    try:
        kubernetes_exe.apply(manifest=doc)
        kubernetes_exe.patch_object(
            kind=CRD_KIND,
            name=name,
            namespace="default",
            api_version=f"{CRD_GROUP}/v1",
            patch=[{"op": "replace", "path": "/spec/count", "value": 99}],
            patch_type="json",
        )
        live = _dynamic.get_object(f"{CRD_GROUP}/v1", CRD_KIND, name=name, namespace="default")
        assert live["spec"]["count"] == 99
    finally:
        kubernetes_exe.delete_manifest(manifest=doc)


def test_cr_validate_catches_schema_violation(kubernetes_exe, installed_crd):
    """``validate=True`` rejects a CR whose ``count`` is the wrong type."""
    name = random_string("widget-bad-", uppercase=False)
    bad_doc = {
        "apiVersion": f"{CRD_GROUP}/v1",
        "kind": CRD_KIND,
        "metadata": {"name": name, "namespace": "default"},
        "spec": {"count": "not-an-integer"},
    }
    with pytest.raises(CommandExecutionError):
        kubernetes_exe.apply(manifest=bad_doc, validate=True)
    # No CR was persisted because validate ran first.
    assert _dynamic.get_object(f"{CRD_GROUP}/v1", CRD_KIND, name=name, namespace="default") is None


def test_cr_delete_via_delete_manifest(kubernetes_exe, installed_crd):
    """``delete_manifest`` removes a CR identified by its manifest."""
    name = random_string("widget-del-", uppercase=False)
    doc = {
        "apiVersion": f"{CRD_GROUP}/v1",
        "kind": CRD_KIND,
        "metadata": {"name": name, "namespace": "default"},
        "spec": {"count": 1},
    }
    kubernetes_exe.apply(manifest=doc)
    assert (
        _dynamic.get_object(f"{CRD_GROUP}/v1", CRD_KIND, name=name, namespace="default") is not None
    )
    kubernetes_exe.delete_manifest(manifest=doc)
    # Delete may be async — poll briefly.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if _dynamic.get_object(f"{CRD_GROUP}/v1", CRD_KIND, name=name, namespace="default") is None:
            break
        time.sleep(0.5)
    assert _dynamic.get_object(f"{CRD_GROUP}/v1", CRD_KIND, name=name, namespace="default") is None
