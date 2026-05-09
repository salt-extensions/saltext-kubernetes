"""
Functional tests for the Job/CronJob CRUD surface against the kind
cluster fixture. Includes a wait_for_completion lifecycle test
(create a hello-world Job, wait for it to terminate, verify status).

.. versionadded:: 2.1.0
"""

import time

import pytest
from salt.exceptions import CommandExecutionError
from saltfactories.utils import random_string


@pytest.fixture
def quick_job_spec():
    """A Job spec that runs ``echo hi`` and exits 0 immediately."""
    return {
        "backoffLimit": 1,
        "template": {
            "spec": {
                "restartPolicy": "Never",
                "containers": [
                    {
                        "name": "hello",
                        "image": "busybox:latest",
                        "command": ["echo", "hello-from-saltext-job"],
                    }
                ],
            }
        },
    }


@pytest.fixture
def cron_job_spec(quick_job_spec):
    """A CronJob that fires the quick-job spec on a future-dated schedule."""
    return {
        "schedule": "0 0 1 1 *",  # Jan 1st — won't actually fire during tests
        "concurrencyPolicy": "Forbid",
        "jobTemplate": {"spec": quick_job_spec},
    }


# ---------------------------------------------------------------------------
# Job CRUD
# ---------------------------------------------------------------------------


def test_job_round_trip(kubernetes_exe, quick_job_spec):
    """Create + show + list + delete round-trip."""
    name = random_string("job-rt-", uppercase=False)
    try:
        res = kubernetes_exe.create_job(name=name, namespace="default", spec=quick_job_spec)
        assert res["metadata"]["name"] == name
        assert kubernetes_exe.show_job(name=name, namespace="default") is not None
        assert name in kubernetes_exe.jobs(namespace="default")
    finally:
        kubernetes_exe.delete_job(name=name, namespace="default")
        # Allow the BG deletion to finalize before the next test.
        for _ in range(15):
            if kubernetes_exe.show_job(name=name, namespace="default") is None:
                break
            time.sleep(1)


def test_job_wait_for_completion(kubernetes_exe, quick_job_spec):
    """create_job with wait_for_completion blocks until the Job is done."""
    name = random_string("job-wait-", uppercase=False)
    try:
        res = kubernetes_exe.create_job(
            name=name,
            namespace="default",
            spec=quick_job_spec,
            wait_for_completion=True,
            timeout=120,
        )
        assert res["status"]["succeeded"] == 1, res["status"]
    finally:
        kubernetes_exe.delete_job(name=name, namespace="default")


def test_job_invalid_restart_policy_rejected(kubernetes_exe, quick_job_spec):
    """A Job with restartPolicy=Always is rejected client-side."""
    spec = dict(quick_job_spec)
    spec["template"] = dict(spec["template"])
    spec["template"]["spec"] = dict(spec["template"]["spec"])
    spec["template"]["spec"]["restartPolicy"] = "Always"
    name = random_string("job-bad-", uppercase=False)
    with pytest.raises(CommandExecutionError, match="restartPolicy"):
        kubernetes_exe.create_job(name=name, namespace="default", spec=spec)


# ---------------------------------------------------------------------------
# CronJob CRUD
# ---------------------------------------------------------------------------


def test_cron_job_round_trip(kubernetes_exe, cron_job_spec):
    name = random_string("cron-rt-", uppercase=False)
    try:
        res = kubernetes_exe.create_cron_job(name=name, namespace="default", spec=cron_job_spec)
        assert res["metadata"]["name"] == name
        live = kubernetes_exe.show_cron_job(name=name, namespace="default")
        assert live["spec"]["schedule"] == "0 0 1 1 *"
        assert live["spec"]["concurrencyPolicy"] == "Forbid"
        assert name in kubernetes_exe.cron_jobs(namespace="default")
    finally:
        kubernetes_exe.delete_cron_job(name=name, namespace="default")


def test_cron_job_patch_toggles_suspend(kubernetes_exe, cron_job_spec):
    """Patching with suspend=True works (the canonical use case)."""
    name = random_string("cron-suspend-", uppercase=False)
    try:
        kubernetes_exe.create_cron_job(name=name, namespace="default", spec=cron_job_spec)
        kubernetes_exe.patch_cron_job(
            name=name, namespace="default", patch={"spec": {"suspend": True}}
        )
        live = kubernetes_exe.show_cron_job(name=name, namespace="default")
        assert live["spec"]["suspend"] is True
    finally:
        kubernetes_exe.delete_cron_job(name=name, namespace="default")


def test_cron_job_invalid_concurrency_rejected(kubernetes_exe, cron_job_spec):
    spec = dict(cron_job_spec)
    spec["concurrencyPolicy"] = "Frobozz"
    name = random_string("cron-bad-", uppercase=False)
    with pytest.raises(CommandExecutionError, match="Invalid concurrency_policy"):
        kubernetes_exe.create_cron_job(name=name, namespace="default", spec=spec)


def test_cron_job_missing_schedule_rejected(kubernetes_exe, cron_job_spec):
    spec = {k: v for k, v in cron_job_spec.items() if k != "schedule"}
    name = random_string("cron-bad-", uppercase=False)
    with pytest.raises(CommandExecutionError, match="must include 'schedule'"):
        kubernetes_exe.create_cron_job(name=name, namespace="default", spec=spec)
