"""
Unit tests for the Pod operations on
``saltext.kubernetes.modules.kubernetesmod`` (exec, logs, cp_to, cp_from).

These exercise the input-shaping and error-channel-parsing logic without
opening a real WebSocket. End-to-end exec/logs/cp tests against a real
Pod live in the functional tier.
"""

import json

import pytest
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.modules import kubernetesmod

# ---------------------------------------------------------------------------
# _wrap_command
# ---------------------------------------------------------------------------


def test_wrap_command_string_runs_via_sh():
    """A string command becomes ``/bin/sh -c <string>``."""
    result = kubernetesmod._wrap_command("echo hello")
    assert result == ["/bin/sh", "-c", "echo hello"]


def test_wrap_command_list_passed_through():
    """A list of argv tokens is preserved as-is."""
    result = kubernetesmod._wrap_command(["cat", "/etc/hostname"])
    assert result == ["cat", "/etc/hostname"]


def test_wrap_command_rejects_other_types():
    with pytest.raises(CommandExecutionError, match="must be a string or list"):
        kubernetesmod._wrap_command({"not": "valid"})


# ---------------------------------------------------------------------------
# _parse_exit_code_from_error_channel
# ---------------------------------------------------------------------------


def test_parse_exit_code_success():
    """Status=Success → exit code 0."""
    payload = json.dumps({"metadata": {}, "status": "Success"})
    assert kubernetesmod._parse_exit_code_from_error_channel(payload) == 0


def test_parse_exit_code_failure_with_explicit_code():
    """Status=Failure with an ExitCode cause → that integer."""
    payload = json.dumps(
        {
            "metadata": {},
            "status": "Failure",
            "reason": "NonZeroExitCode",
            "details": {"causes": [{"reason": "ExitCode", "message": "42"}]},
        }
    )
    assert kubernetesmod._parse_exit_code_from_error_channel(payload) == 42


def test_parse_exit_code_failure_without_cause_defaults_to_one():
    """Failure without ExitCode metadata reports rc=1 (truthy non-zero)."""
    payload = json.dumps({"metadata": {}, "status": "Failure"})
    assert kubernetesmod._parse_exit_code_from_error_channel(payload) == 1


def test_parse_exit_code_empty_payload_is_success():
    """No error-channel payload at all → exit code 0."""
    assert kubernetesmod._parse_exit_code_from_error_channel("") == 0
    assert kubernetesmod._parse_exit_code_from_error_channel(None) == 0


def test_parse_exit_code_unparseable_payload_marks_minus_one():
    """Garbled JSON gets a sentinel -1 so callers can distinguish."""
    assert kubernetesmod._parse_exit_code_from_error_channel("not-json") == -1


def test_parse_exit_code_message_not_an_integer():
    """If the ExitCode message isn't an int, fall back to rc=1."""
    payload = json.dumps(
        {
            "status": "Failure",
            "details": {"causes": [{"reason": "ExitCode", "message": "oops"}]},
        }
    )
    assert kubernetesmod._parse_exit_code_from_error_channel(payload) == 1


# ---------------------------------------------------------------------------
# exec_() pre-flight pod existence check.
#
# Works around a kubernetes-client 36.0.0 regression: the websocket-upgrade
# path used by exec returns ApiException with ``e.body=None`` on 404, and
# the client's error handler tries to ``.decode('utf-8')`` that ``None``,
# raising AttributeError instead of the typed 404 we expect. Calling
# read_namespaced_pod first turns a missing pod into a clean
# CommandExecutionError before we hit the upgrade path.
# ---------------------------------------------------------------------------


def test_exec_pre_flight_translates_404_to_command_execution_error(monkeypatch):
    """A 404 from read_namespaced_pod becomes ``Pod {name} not found in {ns}``.

    The websocket-upgrade exec path must NOT be invoked — that's where
    the kubernetes-36 ``AttributeError`` is, and the pre-flight exists
    to side-step it.
    """
    from unittest.mock import MagicMock  # pylint: disable=import-outside-toplevel

    from kubernetes.client.rest import ApiException  # pylint: disable=import-outside-toplevel

    fake_api = MagicMock()
    fake_api.read_namespaced_pod.side_effect = ApiException(status=404, reason="Not Found")

    fake_module = MagicMock()
    fake_module.client.CoreV1Api.return_value = fake_api
    monkeypatch.setattr(kubernetesmod, "kubernetes", fake_module)
    monkeypatch.setattr(kubernetesmod, "_setup_conn", lambda **_: {})
    monkeypatch.setattr(kubernetesmod, "_cleanup", lambda **_: None)

    with pytest.raises(CommandExecutionError, match="Pod missing not found in default"):
        kubernetesmod.exec_(name="missing", command="true", namespace="default")
    # The websocket upgrade path was never invoked because the pre-flight
    # raised first — that's the entire point of the pre-flight.
    fake_api.connect_get_namespaced_pod_exec.assert_not_called()


def test_exec_pre_flight_non_404_propagates_as_command_execution_error(monkeypatch):
    """ApiException with a non-404 status surfaces as a generic CommandExecutionError."""
    from unittest.mock import MagicMock  # pylint: disable=import-outside-toplevel

    from kubernetes.client.rest import ApiException  # pylint: disable=import-outside-toplevel

    fake_api = MagicMock()
    fake_api.read_namespaced_pod.side_effect = ApiException(status=500, reason="Server")

    fake_module = MagicMock()
    fake_module.client.CoreV1Api.return_value = fake_api
    monkeypatch.setattr(kubernetesmod, "kubernetes", fake_module)
    monkeypatch.setattr(kubernetesmod, "_setup_conn", lambda **_: {})
    monkeypatch.setattr(kubernetesmod, "_cleanup", lambda **_: None)

    with pytest.raises(CommandExecutionError):
        kubernetesmod.exec_(name="x", command="true", namespace="default")
    fake_api.connect_get_namespaced_pod_exec.assert_not_called()
