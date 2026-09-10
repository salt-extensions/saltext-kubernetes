"""Unit tests for the Gateway API execution-module wrappers."""

from unittest.mock import MagicMock

import pytest
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.modules import kubernetesmod


@pytest.fixture
def no_connection(monkeypatch):
    monkeypatch.setattr(kubernetesmod, "_setup_conn", lambda **kwargs: {})
    monkeypatch.setattr(kubernetesmod, "_cleanup", lambda **kwargs: None)


def test_gateway_manifest_preserves_gateway_api_spec():
    manifest = kubernetesmod._gateway_manifest(
        "Gateway",
        "edge",
        "prod",
        metadata={"labels": {"team": "platform"}},
        spec={
            "gatewayClassName": "standard",
            "listeners": [{"name": "https", "protocol": "HTTPS", "port": 443}],
        },
    )

    assert manifest == {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": {"name": "edge", "namespace": "prod", "labels": {"team": "platform"}},
        "spec": {
            "gatewayClassName": "standard",
            "listeners": [{"name": "https", "protocol": "HTTPS", "port": 443}],
        },
    }


def test_reference_grant_manifest_uses_served_api_version():
    manifest = kubernetesmod._gateway_manifest(
        "ReferenceGrant", "grant", "backend", spec={"from": [], "to": []}
    )

    assert manifest["apiVersion"] == "gateway.networking.k8s.io/v1beta1"


def test_gateway_source_rejects_wrong_kind():
    with pytest.raises(CommandExecutionError, match="should define only a Gateway"):
        kubernetesmod._validate_gateway_source(
            {"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute"},
            "Gateway",
        )


def test_create_gateway_uses_namespaced_dynamic_resource(no_connection, monkeypatch):
    resource = MagicMock(namespaced=True)
    resource.create.return_value = {"metadata": {"name": "edge"}}
    monkeypatch.setattr(kubernetesmod._dynamic, "get_resource", lambda *args: resource)

    result = kubernetesmod.create_gateway(
        "edge",
        namespace="prod",
        spec={"gatewayClassName": "standard", "listeners": []},
    )

    assert result == {"metadata": {"name": "edge"}}
    kwargs = resource.create.call_args.kwargs
    assert kwargs["namespace"] == "prod"
    assert kwargs["body"]["kind"] == "Gateway"
    assert kwargs["body"]["spec"]["gatewayClassName"] == "standard"


def test_create_gateway_class_does_not_add_namespace(no_connection, monkeypatch):
    resource = MagicMock(namespaced=False)
    resource.create.return_value = {"metadata": {"name": "standard"}}
    monkeypatch.setattr(kubernetesmod._dynamic, "get_resource", lambda *args: resource)

    kubernetesmod.create_gateway_class(
        "standard",
        spec={"controllerName": "example.net/gateway-controller"},
    )

    kwargs = resource.create.call_args.kwargs
    assert "namespace" not in kwargs
    assert kwargs["body"]["metadata"] == {"name": "standard"}


def test_patch_http_route_uses_merge_patch(no_connection, monkeypatch):
    patch_object = MagicMock(return_value={"metadata": {"name": "app"}})
    monkeypatch.setattr(kubernetesmod._dynamic, "patch_object", patch_object)

    result = kubernetesmod.patch_http_route(
        "app",
        namespace="prod",
        patch={"spec": {"hostnames": ["example.test"]}},
    )

    assert result == {"metadata": {"name": "app"}}
    call = patch_object.call_args
    assert call.args[:2] == ("gateway.networking.k8s.io/v1", "HTTPRoute")
    assert call.kwargs["name"] == "app"
    assert call.kwargs["patch_type"] == "merge"
    assert call.kwargs["namespace"] == "prod"


def test_delete_reference_grant_uses_dynamic_delete(no_connection, monkeypatch):
    delete = MagicMock(return_value=None)
    monkeypatch.setattr(kubernetesmod._dynamic, "delete_object", delete)

    assert kubernetesmod.delete_reference_grant("grant", namespace="backend") is None
    delete.assert_called_once_with(
        "gateway.networking.k8s.io/v1beta1",
        "ReferenceGrant",
        name="grant",
        namespace="backend",
    )


def test_gateway_list_and_show_use_dynamic_reads(no_connection, monkeypatch):
    list_resource = MagicMock(return_value=[{"metadata": {"name": "edge"}}])
    get_object = MagicMock(return_value={"metadata": {"name": "edge"}})
    monkeypatch.setattr(kubernetesmod._dynamic, "list_resource", list_resource)
    monkeypatch.setattr(kubernetesmod._dynamic, "get_object", get_object)

    assert kubernetesmod.gateways(namespace="prod") == [{"metadata": {"name": "edge"}}]
    assert kubernetesmod.show_gateway("edge", namespace="prod") == {"metadata": {"name": "edge"}}
    list_resource.assert_called_once_with(
        "gateway.networking.k8s.io/v1", "Gateway", namespace="prod"
    )
    get_object.assert_called_once_with(
        "gateway.networking.k8s.io/v1", "Gateway", name="edge", namespace="prod"
    )


def test_replace_gateway_preserves_nested_spec(no_connection, monkeypatch):
    resource = MagicMock(namespaced=True)
    resource.replace.return_value = {"metadata": {"name": "edge"}}
    monkeypatch.setattr(kubernetesmod._dynamic, "get_resource", lambda *args: resource)

    kubernetesmod.replace_gateway(
        "edge",
        namespace="prod",
        spec={"listeners": [{"name": "https", "tls": {"certificateRefs": [{"name": "tls"}]}}]},
    )

    body = resource.replace.call_args.kwargs["body"]
    assert body["metadata"]["namespace"] == "prod"
    assert body["spec"]["listeners"][0]["tls"]["certificateRefs"] == [{"name": "tls"}]
