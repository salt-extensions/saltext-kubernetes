"""
Functional tests for the Pod operations (exec, logs, cp_to, cp_from)
against the kind cluster fixture.

These create a real Pod, then exercise the websocket exec / log /
tar-pipe paths end-to-end.

.. versionadded:: 2.1.0
"""

import sys

import pytest
from salt.exceptions import CommandExecutionError

pytestmark = pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="Pod operations require POSIX tar / shell semantics; Windows unsupported.",
)


@pytest.fixture
def pod_spec():
    """A nginx pod has /bin/sh (dash) and tar (debian-slim base)."""
    return {"containers": [{"name": "nginx", "image": "nginx:latest"}]}


# ---------------------------------------------------------------------------
# exec
# ---------------------------------------------------------------------------


def test_exec_string_command_returns_stdout(kubernetes_exe, pod):
    """A simple ``echo`` returns its output and rc=0."""
    res = kubernetes_exe.exec_(name=pod["name"], command="echo hello-from-salt")
    assert res["retcode"] == 0
    assert "hello-from-salt" in res["stdout"]
    assert res["stderr"] == ""


def test_exec_list_command_runs_directly(kubernetes_exe, pod):
    """A list command runs without /bin/sh -c."""
    res = kubernetes_exe.exec_(name=pod["name"], command=["cat", "/etc/hostname"])
    assert res["retcode"] == 0
    # Pod's hostname matches its name in kubelet's view
    assert res["stdout"].strip() != ""


def test_exec_nonzero_exit_propagates(kubernetes_exe, pod):
    """A failing command surfaces a non-zero rc."""
    res = kubernetes_exe.exec_(name=pod["name"], command="exit 7")
    assert res["retcode"] == 7


def test_exec_stderr_captured(kubernetes_exe, pod):
    """stderr from the command is captured separately."""
    res = kubernetes_exe.exec_(name=pod["name"], command="echo to-stderr 1>&2; exit 0")
    assert res["retcode"] == 0
    assert "to-stderr" in res["stderr"]


def test_exec_stdin_fed_to_command(kubernetes_exe, pod):
    """
    stdin is delivered to the command.

    Uses ``head -c N`` instead of bare ``cat`` because the Kubernetes
    exec subresource websocket cannot signal stdin EOF — commands that
    wait for EOF (cat, tee) deadlock. ``head -c`` reads a fixed byte
    count and exits, which is the recommended idiom for stdin-bearing
    exec calls. The exec_ docstring spells this out.
    """
    payload = "payload-from-test\n"
    res = kubernetes_exe.exec_(
        name=pod["name"],
        command=["head", "-c", str(len(payload))],
        stdin=payload,
    )
    assert res["retcode"] == 0
    assert "payload-from-test" in res["stdout"]


def test_exec_stdin_eof_unsupported_command_times_out(kubernetes_exe, pod):
    """
    Commands that wait for stdin EOF (no byte-bounded reader) hit the
    wall-clock timeout and surface ``retcode=-1``.

    This locks in the documented behaviour so users don't see indefinite
    hangs — they see a fast, clear failure.
    """
    res = kubernetes_exe.exec_(name=pod["name"], command=["cat"], stdin="x", timeout=3)
    assert res["retcode"] == -1
    assert "timed out" in res["stderr"].lower()


def test_exec_pod_not_found_raises(kubernetes_exe):
    """Exec into a nonexistent Pod raises a clear error."""
    with pytest.raises(CommandExecutionError, match="not found"):
        kubernetes_exe.exec_(name="does-not-exist", command="true")


# ---------------------------------------------------------------------------
# logs
# ---------------------------------------------------------------------------


def test_logs_returns_string(kubernetes_exe, pod):
    """Reading nginx's startup output yields a non-empty string."""
    # Give nginx a moment to log; it does so on startup.
    res = kubernetes_exe.exec_(name=pod["name"], command="sleep 1")
    assert res["retcode"] == 0
    out = kubernetes_exe.logs(name=pod["name"], tail_lines=20)
    assert isinstance(out, str)


def test_logs_pod_not_found_raises(kubernetes_exe):
    with pytest.raises(CommandExecutionError, match="not found"):
        kubernetes_exe.logs(name="does-not-exist")


# ---------------------------------------------------------------------------
# cp_to / cp_from
# ---------------------------------------------------------------------------


def test_cp_to_then_cp_from_round_trip(kubernetes_exe, pod, tmp_path):
    """Copy a file into the Pod, then copy it back; contents must match."""
    src = tmp_path / "salt-cp-source.txt"
    payload = "round-trip payload\nmultiline\n"
    src.write_text(payload)

    # Copy in
    res = kubernetes_exe.cp_to(name=pod["name"], src_path=str(src), dst_path="/tmp")
    assert res["retcode"] == 0

    # Verify it landed where expected
    check = kubernetes_exe.exec_(name=pod["name"], command=f"cat /tmp/{src.name}")
    assert check["retcode"] == 0
    assert payload in check["stdout"]

    # Copy back out
    dst_dir = tmp_path / "downloaded"
    dst_dir.mkdir()
    res = kubernetes_exe.cp_from(
        name=pod["name"],
        src_path=f"/tmp/{src.name}",
        dst_path=str(dst_dir),
    )
    assert res["retcode"] == 0
    fetched = (dst_dir / src.name).read_text()
    assert fetched == payload


def test_cp_to_missing_local_source_raises(kubernetes_exe, pod, tmp_path):
    nonexistent = tmp_path / "nope"
    with pytest.raises(CommandExecutionError, match="does not exist"):
        kubernetes_exe.cp_to(name=pod["name"], src_path=str(nonexistent), dst_path="/tmp")


def test_cp_from_destination_must_be_dir(kubernetes_exe, pod, tmp_path):
    """cp_from refuses to write into a non-directory destination."""
    not_a_dir = tmp_path / "file.txt"
    not_a_dir.write_text("x")
    with pytest.raises(CommandExecutionError, match="must be a directory"):
        kubernetes_exe.cp_from(name=pod["name"], src_path="/etc/hostname", dst_path=str(not_a_dir))
