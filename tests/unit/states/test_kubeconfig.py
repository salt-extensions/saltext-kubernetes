from unittest.mock import MagicMock
from unittest.mock import patch

from saltext.kubernetes.states import kubeconfig


def test_kubeconfig_state_test_mode_returns_only_entry_names():
    merge = MagicMock(
        return_value={"changed": True, "path": "/tmp/config", "changes": {"users": ["bot"]}}
    )
    with patch.object(kubeconfig, "__salt__", {"kubeconfig.merge": merge}, create=True):
        with patch.object(kubeconfig, "__opts__", {"test": True}, create=True):
            ret = kubeconfig.managed(
                "config", path="/tmp/config", users=[{"name": "bot", "user": {"token": "secret"}}]
            )
    assert ret["result"] is None
    assert ret["changes"] == {"/tmp/config": {"users": ["bot"]}}
    assert "secret" not in repr(ret)
    assert merge.call_args.kwargs["test"] is True
