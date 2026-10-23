from types import SimpleNamespace
from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.modules import helm


def _proc(stdout="", stderr="", retcode=0):
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=retcode)


def test_release_present_passes_values_through_private_temp_file():
    seen = {}

    def run(args, **kwargs):
        values_path = args[args.index("--values") + 1]
        with open(values_path, encoding="utf-8") as values_file:
            seen["values"] = values_file.read()
        seen["mode"] = __import__("stat").S_IMODE(__import__("os").stat(values_path).st_mode)
        seen["args"] = args
        return _proc("ok")

    with patch("saltext.kubernetes.modules.helm.shutil.which", return_value="/usr/bin/helm"):
        with patch("saltext.kubernetes.modules.helm.subprocess.run", side_effect=run):
            result = helm.release_present(
                "web", "repo/web", version="1.2.3", namespace="prod", values={"token": "secret"}
            )
    assert result["retcode"] == 0
    assert '"token":"secret"' in seen["values"]
    assert seen["mode"] == 0o600
    assert "secret" not in repr(seen["args"])
    assert not __import__("os").path.exists(seen["args"][seen["args"].index("--values") + 1])


def test_release_present_supports_typed_set_values_and_lifecycle_options():
    seen = {}

    def run(args, **kwargs):
        seen["args"] = args
        return _proc("ok")

    with patch("saltext.kubernetes.modules.helm.shutil.which", return_value="helm"):
        with patch("saltext.kubernetes.modules.helm.subprocess.run", side_effect=run):
            helm.release_present(
                "web",
                "repo/web",
                set_values=[
                    {"value": "replicaCount=3", "value_type": "raw"},
                    {"value": "image.tag=1.2", "value_type": "string"},
                    {"value": "config.password=secret.txt", "value_type": "file"},
                    {"value": 'feature={"enabled":true}', "value_type": "json"},
                ],
                skip_schema_validation=True,
                take_ownership=True,
                disable_hooks=True,
                post_renderer="/usr/local/bin/render",
                post_renderer_args=["--mode", "strict"],
                reset_then_reuse_values=True,
            )
    args = seen["args"]
    assert args[args.index("--set") + 1] == "replicaCount=3"
    assert args[args.index("--set-string") + 1] == "image.tag=1.2"
    assert args[args.index("--set-file") + 1] == "config.password=secret.txt"
    assert args[args.index("--set-json") + 1] == 'feature={"enabled":true}'
    for flag in (
        "--skip-schema-validation",
        "--take-ownership",
        "--no-hooks",
        "--reset-then-reuse-values",
    ):
        assert flag in args
    assert args[args.index("--post-renderer") + 1] == "/usr/local/bin/render"
    assert args.count("--post-renderer-args") == 2


def test_release_present_rejects_invalid_set_value_type():
    with pytest.raises(CommandExecutionError, match="value_type"):
        helm.release_present(
            "web", "repo/web", set_values=[{"value": "x=y", "value_type": "unknown"}]
        )


def test_release_present_rejects_conflicting_value_reset_options():
    with pytest.raises(CommandExecutionError, match="mutually exclusive"):
        helm.release_present("web", "repo/web", reset_values=True, reuse_values=True)


def test_registry_password_is_sent_on_stdin_not_in_argv():
    seen = {}

    def run(args, **kwargs):
        seen["args"] = args
        seen["stdin"] = kwargs["input"]
        return _proc(stdout="logged in")

    with patch("saltext.kubernetes.modules.helm.shutil.which", return_value="helm"):
        with patch("saltext.kubernetes.modules.helm.subprocess.run", side_effect=run):
            result = helm.registry_auth("registry.example", username="robot", password="top-secret")
    assert seen["stdin"] == "top-secret"
    assert "top-secret" not in repr(seen["args"])
    assert result["changed"] is True


def test_registry_login_requires_credentials():
    with pytest.raises(CommandExecutionError, match="requires both"):
        helm.registry_auth("registry.example")


def test_run_redacts_sensitive_output_and_uses_argv_without_shell():
    with patch(
        "saltext.kubernetes.modules.helm.subprocess.run", return_value=_proc("secret echoed")
    ) as run:
        result = helm._run(["version"], binary_path="helm", sensitive=("secret",))
    assert result["stdout"] == "<redacted> echoed"
    assert run.call_args.args[0] == ["helm", "version"]
    assert run.call_args.kwargs.get("shell", False) is False


def test_repository_password_is_rejected_instead_of_exposed_in_process_args():
    with pytest.raises(CommandExecutionError, match="cannot be passed safely"):
        helm.repository_present("private", "https://repo.example", password="secret")


def test_plugin_list_parses_table_output():
    with patch("saltext.kubernetes.modules.helm.shutil.which", return_value="helm"):
        with patch(
            "saltext.kubernetes.modules.helm.subprocess.run",
            return_value=_proc("NAME\tVERSION\tDESCRIPTION\ndiff\t3.9.0\tPreview upgrades"),
        ):
            assert helm.plugin_list() == [
                {"name": "diff", "version": "3.9.0", "description": "Preview upgrades"}
            ]


def test_chart_info_parses_helm_yaml():
    with patch("saltext.kubernetes.modules.helm.shutil.which", return_value="helm"):
        with patch(
            "saltext.kubernetes.modules.helm.subprocess.run",
            return_value=_proc("name: actual-chart\nversion: 1.2.3\n"),
        ):
            assert helm.chart_info("/tmp/arbitrary-name.tgz") == {
                "name": "actual-chart",
                "version": "1.2.3",
            }
