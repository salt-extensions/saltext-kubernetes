from unittest.mock import MagicMock
from unittest.mock import patch

from saltext.kubernetes.states import helm
from saltext.kubernetes.states import helm_plugin
from saltext.kubernetes.states import helm_repo


def test_release_present_test_mode_reports_without_running_upgrade():
    status = MagicMock(return_value=None)
    upgrade = MagicMock()
    with patch.object(
        helm,
        "__salt__",
        {"helm.release_status": status, "helm.release_present": upgrade},
        create=True,
    ):
        with patch.object(helm, "__opts__", {"test": True}, create=True):
            ret = helm.release_present("web", "repo/web", version="1.2.3")
    assert ret["result"] is None
    assert ret["changes"] == {"default/web": {"old": "absent", "new": "present"}}
    upgrade.assert_not_called()


def test_release_present_forwards_typed_values_and_new_helm_options():
    status = MagicMock(
        return_value={"chart": "web-1.2.3", "info": {"status": "deployed"}}
    )
    upgrade = MagicMock()
    set_values = [{"value": "replicaCount=3", "value_type": "raw"}]
    with patch.object(
        helm,
        "__salt__",
        {"helm.release_status": status, "helm.release_present": upgrade},
        create=True,
    ):
        with patch.object(helm, "__opts__", {"test": False}, create=True):
            ret = helm.release_present(
                "web",
                "repo/web",
                version="1.2.3",
                set_values=set_values,
                take_ownership=True,
                skip_schema_validation=True,
            )
    assert ret["result"] is True
    assert upgrade.call_args.kwargs["set_values"] == set_values
    assert upgrade.call_args.kwargs["take_ownership"] is True
    assert upgrade.call_args.kwargs["skip_schema_validation"] is True


def test_release_absent_is_idempotent():
    status = MagicMock(return_value=None)
    uninstall = MagicMock()
    with patch.object(
        helm,
        "__salt__",
        {"helm.release_status": status, "helm.release_absent": uninstall},
        create=True,
    ):
        with patch.object(helm, "__opts__", {"test": False}, create=True):
            ret = helm.release_absent("web")
    assert ret["result"] is True
    assert ret["changes"] == {}
    uninstall.assert_not_called()


def test_release_state_uses_chart_metadata_for_arbitrarily_named_archive():
    status = MagicMock(return_value={"chart": "actual-chart-1.2.3", "info": {"status": "deployed"}})
    metadata = MagicMock(return_value={"name": "actual-chart"})
    upgrade = MagicMock()
    with patch.object(
        helm,
        "__salt__",
        {
            "helm.release_status": status,
            "helm.chart_info": metadata,
            "helm.release_present": upgrade,
        },
        create=True,
    ):
        with patch.object(helm, "__opts__", {"test": False}, create=True):
            ret = helm.release_present(
                "web", "/tmp/arbitrary.tgz", version="1.2.3", binary_path="helm"
            )
    assert ret["result"] is True
    assert ret["changes"] == {}
    metadata.assert_called_once()
    upgrade.assert_not_called()


def test_repository_state_is_idempotent_and_test_mode_does_not_mutate():
    repo_list = MagicMock(return_value=[])
    repo_add = MagicMock()
    with patch.object(
        helm_repo,
        "__salt__",
        {"helm.repository_list": repo_list, "helm.repository_present": repo_add},
        create=True,
    ):
        with patch.object(helm_repo, "__opts__", {"test": True}, create=True):
            ret = helm_repo.present("stable", "https://charts.example")
    assert ret["result"] is None
    repo_add.assert_not_called()

    with patch.object(
        helm_repo,
        "__salt__",
        {
            "helm.repository_list": MagicMock(
                return_value=[{"name": "stable", "url": "https://charts.example"}]
            )
        },
        create=True,
    ):
        ret = helm_repo.present("stable", "https://charts.example")
    assert ret["result"] is True
    assert ret["changes"] == {}


def test_plugin_absent_test_mode_does_not_uninstall():
    plugin_list = MagicMock(return_value=[{"name": "diff", "version": "1.0"}])
    uninstall = MagicMock()
    with patch.object(
        helm_plugin,
        "__salt__",
        {"helm.plugin_list": plugin_list, "helm.plugin_absent": uninstall},
        create=True,
    ):
        with patch.object(helm_plugin, "__opts__", {"test": True}, create=True):
            ret = helm_plugin.absent("diff")
    assert ret["result"] is None
    assert ret["changes"] == {"diff": {"old": "1.0", "new": None}}
    uninstall.assert_not_called()
