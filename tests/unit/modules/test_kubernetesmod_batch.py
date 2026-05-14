"""
Unit tests for the Job/CronJob spec helpers on
``saltext.kubernetes.modules.kubernetesmod``.

Functional tests against a real cluster live in the functional tier.
"""

import pytest
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.modules import kubernetesmod

# ---------------------------------------------------------------------------
# __dict_to_job_spec
# ---------------------------------------------------------------------------


def _minimal_job_spec():
    return {
        "template": {
            "spec": {
                "containers": [{"name": "c", "image": "busybox"}],
                "restartPolicy": "OnFailure",
            }
        }
    }


def test_job_spec_accepts_minimal_input():
    out = kubernetesmod.__dict_to_job_spec(_minimal_job_spec())
    assert out["template"].spec.containers[0].name == "c"


def test_job_spec_translates_camelcase_keys():
    spec = _minimal_job_spec()
    spec["backoffLimit"] = 3
    spec["ttlSecondsAfterFinished"] = 60
    out = kubernetesmod.__dict_to_job_spec(spec)
    assert out["backoff_limit"] == 3
    assert out["ttl_seconds_after_finished"] == 60


def test_job_spec_default_restart_policy_never():
    spec = _minimal_job_spec()
    del spec["template"]["spec"]["restartPolicy"]
    # Default kicks in when not specified.
    out = kubernetesmod.__dict_to_job_spec(spec)
    assert out["template"].spec.restart_policy == "Never"


def test_job_spec_rejects_invalid_restart_policy():
    spec = _minimal_job_spec()
    spec["template"]["spec"]["restartPolicy"] = "Always"
    with pytest.raises(CommandExecutionError, match="restartPolicy"):
        kubernetesmod.__dict_to_job_spec(spec)


def test_job_spec_rejects_missing_template():
    with pytest.raises(CommandExecutionError, match="must include 'template'"):
        kubernetesmod.__dict_to_job_spec({})


def test_job_spec_rejects_non_dict():
    with pytest.raises(CommandExecutionError, match="Job spec must be a dictionary"):
        kubernetesmod.__dict_to_job_spec("nope")


# ---------------------------------------------------------------------------
# __dict_to_cron_job_spec
# ---------------------------------------------------------------------------


def _minimal_cronjob_spec():
    return {
        "schedule": "*/5 * * * *",
        "jobTemplate": {"spec": _minimal_job_spec()},
    }


def test_cronjob_spec_accepts_minimal():
    out = kubernetesmod.__dict_to_cron_job_spec(_minimal_cronjob_spec())
    assert out["schedule"] == "*/5 * * * *"


def test_cronjob_spec_rejects_missing_schedule():
    spec = _minimal_cronjob_spec()
    del spec["schedule"]
    with pytest.raises(CommandExecutionError, match="must include 'schedule'"):
        kubernetesmod.__dict_to_cron_job_spec(spec)


def test_cronjob_spec_rejects_missing_job_template():
    with pytest.raises(CommandExecutionError, match="must include 'job_template'"):
        kubernetesmod.__dict_to_cron_job_spec({"schedule": "* * * * *"})


@pytest.mark.parametrize(
    "policy",
    ["Allow", "Forbid", "Replace"],
)
def test_cronjob_spec_valid_concurrency(policy):
    spec = _minimal_cronjob_spec()
    spec["concurrencyPolicy"] = policy
    out = kubernetesmod.__dict_to_cron_job_spec(spec)
    assert out["concurrency_policy"] == policy


def test_cronjob_spec_rejects_invalid_concurrency():
    spec = _minimal_cronjob_spec()
    spec["concurrencyPolicy"] = "Frobozz"
    with pytest.raises(CommandExecutionError, match="Invalid concurrency_policy"):
        kubernetesmod.__dict_to_cron_job_spec(spec)


def test_cronjob_spec_translates_camelcase_keys():
    spec = _minimal_cronjob_spec()
    spec["successfulJobsHistoryLimit"] = 5
    spec["failedJobsHistoryLimit"] = 1
    spec["startingDeadlineSeconds"] = 30
    spec["timeZone"] = "UTC"
    out = kubernetesmod.__dict_to_cron_job_spec(spec)
    assert out["successful_jobs_history_limit"] == 5
    assert out["failed_jobs_history_limit"] == 1
    assert out["starting_deadline_seconds"] == 30
    assert out["time_zone"] == "UTC"
