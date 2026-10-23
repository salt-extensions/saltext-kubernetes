from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.modules import kubernetesmod


def test_list_objects_sets_up_and_cleans_connection(monkeypatch):
    setup = MagicMock(return_value={"token": "sentinel"})
    cleanup = MagicMock()
    list_resource = MagicMock(return_value=[{"kind": "Pod"}])
    monkeypatch.setattr(kubernetesmod, "_setup_conn", setup)
    monkeypatch.setattr(kubernetesmod, "_cleanup", cleanup)
    monkeypatch.setattr(kubernetesmod._dynamic, "list_resource", list_resource)

    result = kubernetesmod.list_objects("v1", "Pod", namespace="default", label_selector="app=web")

    assert result == [{"kind": "Pod"}]
    list_resource.assert_called_once_with(
        "v1", "Pod", namespace="default", label_selector="app=web", field_selector=None
    )
    cleanup.assert_called_once_with(token="sentinel")


def test_rollback_supports_daemonset_controller_revision(monkeypatch):
    owner = SimpleNamespace(kind="DaemonSet", uid="ds-uid")
    daemonset = SimpleNamespace(
        metadata=SimpleNamespace(uid="ds-uid", generation=4),
        spec=SimpleNamespace(selector=SimpleNamespace(match_labels={"app": "agent"})),
    )
    revision = SimpleNamespace(
        metadata=SimpleNamespace(
            owner_references=[owner],
            annotations={"deprecated.daemonset.template.generation": "3"},
        ),
        data={"spec": {"template": {"metadata": {"labels": {"app": "agent"}}}}},
    )
    api = MagicMock()
    api.read_namespaced_daemon_set.return_value = daemonset
    api.list_namespaced_controller_revision.return_value = SimpleNamespace(items=[revision])
    api.patch_namespaced_daemon_set.return_value = {
        "kind": "DaemonSet",
        "metadata": {"name": "agent"},
    }
    client = MagicMock()
    client.client.AppsV1Api.return_value = api
    monkeypatch.setattr(kubernetesmod, "kubernetes", client)
    monkeypatch.setattr(kubernetesmod, "_setup_conn", lambda **_: {})
    monkeypatch.setattr(kubernetesmod, "_cleanup", lambda **_: None)

    result = kubernetesmod.rollback("agent", kind="DaemonSet")

    assert result["kind"] == "DaemonSet"
    api.list_namespaced_controller_revision.assert_called_once_with(
        "default", label_selector="app=agent"
    )
    api.patch_namespaced_daemon_set.assert_called_once_with("agent", "default", revision.data)


def test_rollback_rejects_unsupported_kind(monkeypatch):
    monkeypatch.setattr(kubernetesmod, "_setup_conn", lambda **_: {})
    monkeypatch.setattr(kubernetesmod, "_cleanup", lambda **_: None)
    with pytest.raises(CommandExecutionError, match="Deployment.*DaemonSet"):
        kubernetesmod.rollback("example", kind="StatefulSet")


def test_drain_accepts_label_selectors(monkeypatch):
    api = MagicMock()
    api.list_pod_for_all_namespaces.return_value = SimpleNamespace(items=[])
    client = MagicMock()
    client.client.CoreV1Api.return_value = api
    monkeypatch.setattr(kubernetesmod, "kubernetes", client)
    monkeypatch.setattr(kubernetesmod, "_setup_conn", lambda **_: {})
    monkeypatch.setattr(kubernetesmod, "_cleanup", lambda **_: None)

    result = kubernetesmod.drain("node-a", pod_selectors=["app=api", "tier=backend"])

    assert result["node"] == "node-a"
    api.list_pod_for_all_namespaces.assert_called_once_with(
        field_selector="spec.nodeName=node-a", label_selector="app=api,tier=backend"
    )


def test_raw_api_call_uses_kubernetes_37_rest_transport():
    response = SimpleNamespace(data=b"ok")
    rest_client = SimpleNamespace(request=MagicMock(return_value=response))
    config = SimpleNamespace(
        host="https://cluster.example/",
        auth_settings=lambda: {
            "BearerToken": {
                "key": "Authorization",
                "type": "Bearer",
                "value": "test-token",
            }
        },
    )

    class ModernApiClient:
        def call_api(
            self,
            method,
            url,
            header_params=None,
            body=None,
            post_params=None,
            _request_timeout=None,
        ):
            raise AssertionError("modern clients should use the REST transport")

    client = ModernApiClient()
    client.configuration = config
    client.rest_client = rest_client
    result = kubernetesmod._api_client_call_api(
        client,
        "/healthz",
        "GET",
        response_type="str",
        _preload_content=True,
        auth_settings=["BearerToken"],
    )

    assert result == "ok"
    rest_client.request.assert_called_once_with(
        "GET",
        "https://cluster.example/healthz",
        headers={"Authorization": "Bearer test-token"},
    )
