"""Functional execution-module coverage for stable Gateway API resources."""

import pytest

pytestmark = [
    pytest.mark.skip_unless_on_linux(reason="Gateway API kind tests require Linux"),
]


@pytest.fixture
def gateway_class_spec():
    return {"controllerName": "example.net/test-controller"}


def test_gateway_class_create_and_show(kubernetes_exe, gateway_class):
    live = kubernetes_exe.show_gateway_class(gateway_class["name"])
    assert live is not None
    assert live["kind"] == "GatewayClass"
    assert live["spec"] == gateway_class["spec"]


def test_gateway_class_absent_fixture_is_not_created(kubernetes_exe, gateway_class_spec):
    """The false fixture mode can be used by callers to test creation paths."""
    name = "gateway-class-not-created"
    assert kubernetes_exe.show_gateway_class(name) is None
    created = kubernetes_exe.create_gateway_class(name, spec=gateway_class_spec)
    assert created["metadata"]["name"] == name
    kubernetes_exe.delete_gateway_class(name)


def test_gateway_crud_and_patch(kubernetes_exe, gateway):
    live = kubernetes_exe.show_gateway(gateway["name"], namespace=gateway["namespace"])
    assert live["spec"]["gatewayClassName"] == gateway["spec"]["gatewayClassName"]

    replaced = kubernetes_exe.replace_gateway(
        gateway["name"],
        namespace=gateway["namespace"],
        spec={
            **gateway["spec"],
            "listeners": [{"name": "https", "protocol": "HTTPS", "port": 443}],
        },
    )
    assert replaced["spec"]["listeners"][0]["protocol"] == "HTTPS"

    patched = kubernetes_exe.patch_gateway(
        gateway["name"],
        namespace=gateway["namespace"],
        patch={"metadata": {"labels": {"managed-by": "salt"}}},
    )
    assert patched["metadata"]["labels"]["managed-by"] == "salt"


def test_http_route_create_and_show(kubernetes_exe, http_route):
    live = kubernetes_exe.show_http_route(http_route["name"], namespace=http_route["namespace"])
    assert live["kind"] == "HTTPRoute"
    parent_ref = live["spec"]["parentRefs"][0]
    assert parent_ref["name"] == http_route["spec"]["parentRefs"][0]["name"]
    assert parent_ref["group"] == "gateway.networking.k8s.io"
    assert parent_ref["kind"] == "Gateway"


def test_reference_grant_create_and_show(kubernetes_exe, reference_grant):
    live = kubernetes_exe.show_reference_grant(
        reference_grant["name"], namespace=reference_grant["namespace"]
    )
    assert live["kind"] == "ReferenceGrant"
    assert live["spec"]["from"] == reference_grant["spec"]["from"]


def test_gateway_listener_references_cert_manager_secret(kubernetes_exe, gateway_tls_secret):
    gateway = kubernetes_exe.create_gateway(
        name="tls-gateway",
        namespace=gateway_tls_secret["namespace"],
        spec={
            "gatewayClassName": "test-controller",
            "listeners": [
                {
                    "name": "https",
                    "protocol": "HTTPS",
                    "port": 443,
                    "tls": {"certificateRefs": [{"name": gateway_tls_secret["name"]}]},
                }
            ],
        },
    )
    try:
        assert gateway["spec"]["listeners"][0]["tls"]["certificateRefs"] == [
            {"group": "", "kind": "Secret", "name": gateway_tls_secret["name"]}
        ]
    finally:
        kubernetes_exe.delete_gateway("tls-gateway", namespace=gateway_tls_secret["namespace"])


def test_gateway_delete_is_idempotent(kubernetes_exe, gateway):
    name = gateway["name"]
    namespace = gateway["namespace"]
    kubernetes_exe.delete_gateway(name, namespace=namespace, wait=True)
    assert kubernetes_exe.delete_gateway(name, namespace=namespace) is None
    assert kubernetes_exe.show_gateway(name, namespace=namespace) is None
