from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.modules import k8s


def test_info_selects_single_object_or_list():
    get_object = MagicMock(return_value={"metadata": {"name": "web"}})
    list_objects = MagicMock(return_value=[])
    with patch.object(
        k8s,
        "__salt__",
        {"kubernetes.get_object": get_object, "kubernetes.list_objects": list_objects},
        create=True,
    ):
        assert k8s.info("apps/v1", "Deployment", name="web", namespace="prod") == {
            "metadata": {"name": "web"}
        }
        assert (
            k8s.info(
                "v1",
                "Pod",
                namespace="prod",
                label_selector="app=web",
                field_selector="status.phase=Running",
            )
            == []
        )
    get_object.assert_called_once()
    list_objects.assert_called_once_with(
        api_version="v1",
        kind="Pod",
        namespace="prod",
        label_selector="app=web",
        field_selector="status.phase=Running",
    )


def test_info_waits_for_named_resource_to_appear():
    get_object = MagicMock(side_effect=[None, {"metadata": {"name": "web"}}])
    with patch.object(k8s, "__salt__", {"kubernetes.get_object": get_object}, create=True):
        with patch("saltext.kubernetes.modules.k8s.time.sleep") as sleep:
            result = k8s.info("apps/v1", "Deployment", name="web", wait=True)
    assert result["metadata"]["name"] == "web"
    assert get_object.call_count == 2
    sleep.assert_called_once_with(5)


def test_info_wait_times_out_for_missing_named_resource():
    get_object = MagicMock(return_value=None)
    with patch.object(k8s, "__salt__", {"kubernetes.get_object": get_object}, create=True):
        with patch("saltext.kubernetes.modules.k8s.time.monotonic", side_effect=[0, 0, 2]):
            with patch("saltext.kubernetes.modules.k8s.time.sleep"):
                with pytest.raises(CommandExecutionError, match="Timed out"):
                    k8s.info("v1", "Pod", name="web", wait=True, wait_sleep=1, wait_timeout=1)


def test_info_rejects_invalid_wait_options():
    with patch.object(k8s, "__salt__", {"kubernetes.get_object": MagicMock()}, create=True):
        with pytest.raises(CommandExecutionError, match="wait_sleep must be positive"):
            k8s.info("v1", "Pod", name="web", wait=True, wait_sleep=0)


def test_apply_patch_and_cluster_info_delegate_to_existing_api():
    apply = MagicMock(return_value={"kind": "ConfigMap"})
    patch_object = MagicMock(return_value={"kind": "ConfigMap"})
    cluster_info = MagicMock(return_value={"version": "1.31"})
    with patch.object(
        k8s,
        "__salt__",
        {
            "kubernetes.apply": apply,
            "kubernetes.patch_object": patch_object,
            "kubernetes.cluster_info": cluster_info,
        },
        create=True,
    ):
        k8s.apply(manifest={"kind": "ConfigMap"})
        k8s.json_patch(
            "v1", "ConfigMap", "cfg", [{"op": "replace", "path": "/data/x", "value": "y"}]
        )
        assert k8s.cluster_info() == {"version": "1.31"}
    apply.assert_called_once()
    assert patch_object.call_args.kwargs["patch_type"] == "json-patch"


def test_config_resource_name_is_stable_and_does_not_mutate_input():
    resource = {
        "kind": "ConfigMap",
        "metadata": {"name": "app-config"},
        "data": {"z": "last", "a": "first"},
    }
    before = {
        "kind": "ConfigMap",
        "metadata": {"name": "app-config"},
        "data": {"z": "last", "a": "first"},
    }
    first = k8s.config_resource_name(resource)
    assert first == k8s.config_resource_name(resource)
    assert first.startswith("app-config-")
    assert resource == before


def test_config_resource_name_rejects_unsupported_or_incomplete_resource():
    with pytest.raises(CommandExecutionError):
        k8s.config_resource_name({"kind": "Pod", "metadata": {"name": "pod"}})
    with pytest.raises(CommandExecutionError):
        k8s.config_resource_name({"kind": "Secret", "metadata": {}})
