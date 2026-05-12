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
