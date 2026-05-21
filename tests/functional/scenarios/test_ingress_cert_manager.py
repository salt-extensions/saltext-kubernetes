"""
End-to-end scenario for the Ingress + cert-manager TLS pattern
documented in ``docs/topics/examples-terraform-equivalents.md``.

The pattern: declare a ``ClusterIssuer`` (self-signed for the test —
production would use Let's Encrypt ACME), then create an Ingress with
a ``cert-manager.io/cluster-issuer`` annotation and a ``tls:`` block.
cert-manager observes the Ingress, mints a Certificate, the Certificate
controller stamps a Secret holding the cert chain, and the Ingress is
TLS-ready.

These tests verify the documentation matches reality: every snippet in
the docs gets exercised against a kind cluster running cert-manager
(installed by the ``kind_cluster`` fixture).

.. versionadded:: 2.1.0
"""

import time

import pytest
from saltfactories.utils import random_string

pytestmark = [pytest.mark.skip_unless_on_linux(reason="kind cluster fixture requires Linux")]


@pytest.fixture
def kubernetes(states):
    return states.kubernetes


def _wait_for(predicate, timeout=60, interval=2, what="condition"):
    """Poll ``predicate()`` until truthy or ``timeout`` elapses."""
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f"Timed out after {timeout}s waiting for {what}; last result: {last!r}")


def test_selfsigned_cluster_issuer_via_manifest_present(kubernetes_exe):
    """A self-signed ClusterIssuer applied via ``manifest_present`` becomes Ready.

    The simplest cert-manager primitive: a ClusterIssuer that signs
    certificates with an ephemeral CA. Used as the test stand-in for
    Let's Encrypt — the cert-manager wiring is identical, only the
    ``spec.acme.*`` vs ``spec.selfSigned: {}`` choice differs.
    """
    issuer_name = random_string("ci-selfsigned-", uppercase=False)
    try:
        kubernetes_exe.apply(
            manifest={
                "apiVersion": "cert-manager.io/v1",
                "kind": "ClusterIssuer",
                "metadata": {"name": issuer_name},
                "spec": {"selfSigned": {}},
            }
        )

        from saltext.kubernetes.utils import _dynamic  # pylint: disable=import-outside-toplevel

        def _ready():
            live = _dynamic.get_object("cert-manager.io/v1", "ClusterIssuer", name=issuer_name)
            for cond in (live or {}).get("status", {}).get("conditions", []):
                if cond.get("type") == "Ready":
                    return cond.get("status") == "True"
            return False

        _wait_for(_ready, timeout=60, what="ClusterIssuer Ready=True")
    finally:
        kubernetes_exe.delete_manifest(
            manifest={
                "apiVersion": "cert-manager.io/v1",
                "kind": "ClusterIssuer",
                "metadata": {"name": issuer_name},
            }
        )


def test_ingress_with_cert_manager_annotation_provisions_certificate(kubernetes_exe):
    """The full documented scenario: Ingress + ClusterIssuer + TLS annotation.

    Exercises exactly the SLS pattern in
    ``docs/topics/examples-terraform-equivalents.md`` section 3.

      1. Install a self-signed ClusterIssuer.
      2. Create the Ingress with the ``cert-manager.io/cluster-issuer``
         annotation and a ``tls:`` block.
      3. cert-manager observes the Ingress, creates a Certificate
         resource, then materialises the cert chain into the named
         Secret.
      4. Once the Secret exists, the Ingress is TLS-ready.

    We verify the chain end-to-end by polling for the Certificate's
    ``Ready=True`` condition; cert-manager owns that lifecycle and
    transitions to Ready only after the Secret has been written.
    """
    ns = random_string("im-ingress-", uppercase=False)
    issuer = random_string("ci-", uppercase=False)
    secret = random_string("tls-", uppercase=False)
    ingress = random_string("ing-", uppercase=False)
    host = "salt-test.example.com"
    try:
        kubernetes_exe.create_namespace(name=ns, wait=True)

        kubernetes_exe.apply(
            manifest={
                "apiVersion": "cert-manager.io/v1",
                "kind": "ClusterIssuer",
                "metadata": {"name": issuer},
                "spec": {"selfSigned": {}},
            }
        )

        kubernetes_exe.create_ingress(
            name=ingress,
            namespace=ns,
            metadata={"annotations": {"cert-manager.io/cluster-issuer": issuer}},
            spec={
                "ingressClassName": "nginx",
                "tls": [{"hosts": [host], "secretName": secret}],
                "rules": [
                    {
                        "host": host,
                        "http": {
                            "paths": [
                                {
                                    "path": "/",
                                    "pathType": "Prefix",
                                    "backend": {
                                        "service": {"name": "stub", "port": {"number": 80}}
                                    },
                                }
                            ]
                        },
                    }
                ],
            },
        )

        # cert-manager creates a Certificate object named after the
        # tls.secretName (its default convention for Ingress-shim).
        from saltext.kubernetes.utils import _dynamic  # pylint: disable=import-outside-toplevel

        def _certificate_ready():
            cert = _dynamic.get_object(
                "cert-manager.io/v1", "Certificate", name=secret, namespace=ns
            )
            if cert is None:
                return False
            for cond in (cert or {}).get("status", {}).get("conditions", []):
                if cond.get("type") == "Ready":
                    return cond.get("status") == "True"
            return False

        _wait_for(_certificate_ready, timeout=120, what="Certificate Ready=True")

        # The Secret holding the chain must exist and carry the
        # expected kubernetes.io/tls keys.
        secret_obj = kubernetes_exe.show_secret(name=secret, namespace=ns)
        assert secret_obj is not None, f"cert-manager never wrote Secret {secret}"
        assert secret_obj["type"] == "kubernetes.io/tls"
        # The Secret's data is base64-encoded; just confirm both pieces are present.
        assert "tls.crt" in secret_obj["data"]
        assert "tls.key" in secret_obj["data"]
    finally:
        kubernetes_exe.delete_manifest(
            manifest={
                "apiVersion": "cert-manager.io/v1",
                "kind": "ClusterIssuer",
                "metadata": {"name": issuer},
            }
        )
        kubernetes_exe.delete_namespace(name=ns, wait=True)


def test_state_ingress_present_with_cert_manager_annotation(kubernetes, kubernetes_exe):
    """The state-level ``ingress_present`` honours the annotation contract.

    Same scenario as above, but driven through the state surface a
    user would actually write in SLS. Verifies the state wrapper
    forwards the metadata.annotations dict verbatim — cert-manager
    relies on that exact key (``cert-manager.io/cluster-issuer``) to
    pick up the certificate request.
    """
    ns = random_string("im-state-", uppercase=False)
    issuer = random_string("ci-state-", uppercase=False)
    secret = random_string("tls-state-", uppercase=False)
    ingress = random_string("ing-state-", uppercase=False)
    try:
        kubernetes_exe.create_namespace(name=ns, wait=True)
        kubernetes_exe.apply(
            manifest={
                "apiVersion": "cert-manager.io/v1",
                "kind": "ClusterIssuer",
                "metadata": {"name": issuer},
                "spec": {"selfSigned": {}},
            }
        )

        ret = kubernetes.ingress_present(
            name=ingress,
            namespace=ns,
            metadata={"annotations": {"cert-manager.io/cluster-issuer": issuer}},
            spec={
                "ingressClassName": "nginx",
                "tls": [{"hosts": ["state.salt-test.example.com"], "secretName": secret}],
                "rules": [
                    {
                        "host": "state.salt-test.example.com",
                        "http": {
                            "paths": [
                                {
                                    "path": "/",
                                    "pathType": "Prefix",
                                    "backend": {
                                        "service": {"name": "stub", "port": {"number": 80}}
                                    },
                                }
                            ]
                        },
                    }
                ],
            },
        )
        assert ret.result is True

        # The cluster-issuer annotation must round-trip through the
        # state path onto the live Ingress, or cert-manager won't act
        # on it.
        live = kubernetes_exe.show_ingress(name=ingress, namespace=ns)
        annotations = (live.get("metadata") or {}).get("annotations") or {}
        assert annotations.get("cert-manager.io/cluster-issuer") == issuer
    finally:
        kubernetes_exe.delete_manifest(
            manifest={
                "apiVersion": "cert-manager.io/v1",
                "kind": "ClusterIssuer",
                "metadata": {"name": issuer},
            }
        )
        kubernetes_exe.delete_namespace(name=ns, wait=True)
