"""
Functional tests for the batch state functions:

  * ``kubernetes.job_present`` / ``job_absent``
  * ``kubernetes.cron_job_present`` / ``cron_job_absent``

.. versionadded:: 2.1.0
"""

import pytest

pytestmark = [pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms")]


@pytest.fixture
def kubernetes(states):
    return states.kubernetes


@pytest.fixture(params=[False, True])
def testmode(request):
    return request.param


# ---------------------------------------------------------------------------
# Job
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("job", [False], indirect=True)
def test_job_present(kubernetes, job, testmode, kubernetes_exe):
    ret = kubernetes.job_present(
        name=job["name"], namespace=job["namespace"], spec=job["spec"], test=testmode
    )
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    if not testmode:
        live = kubernetes_exe.show_job(name=job["name"], namespace=job["namespace"])
        assert live is not None
        assert live["metadata"]["name"] == job["name"]
    else:
        assert kubernetes_exe.show_job(name=job["name"], namespace=job["namespace"]) is None


def test_job_present_idempotency(kubernetes, job, testmode):
    ret = kubernetes.job_present(
        name=job["name"], namespace=job["namespace"], spec=job["spec"], test=testmode
    )
    assert ret.result is True
    assert not ret.changes


def test_job_absent(kubernetes, job, testmode, kubernetes_exe):
    ret = kubernetes.job_absent(name=job["name"], namespace=job["namespace"], test=testmode)
    assert ret.result in (None, True)
    if not testmode:
        assert kubernetes_exe.show_job(name=job["name"], namespace=job["namespace"]) is None


@pytest.mark.parametrize("job", [False], indirect=True)
def test_job_absent_idempotency(kubernetes, job, testmode):
    ret = kubernetes.job_absent(name=job["name"], namespace=job["namespace"], test=testmode)
    assert ret.result is True
    assert not ret.changes


# ---------------------------------------------------------------------------
# CronJob
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cron_job", [False], indirect=True)
def test_cron_job_present(kubernetes, cron_job, testmode, kubernetes_exe):
    ret = kubernetes.cron_job_present(
        name=cron_job["name"],
        namespace=cron_job["namespace"],
        spec=cron_job["spec"],
        test=testmode,
    )
    assert ret.result in (None, True)
    if not testmode:
        assert (
            kubernetes_exe.show_cron_job(name=cron_job["name"], namespace=cron_job["namespace"])
            is not None
        )


def test_cron_job_present_idempotency(kubernetes, cron_job, testmode):
    ret = kubernetes.cron_job_present(
        name=cron_job["name"],
        namespace=cron_job["namespace"],
        spec=cron_job["spec"],
        test=testmode,
    )
    assert ret.result is True
    assert not ret.changes


def test_cron_job_absent(kubernetes, cron_job, testmode, kubernetes_exe):
    ret = kubernetes.cron_job_absent(
        name=cron_job["name"], namespace=cron_job["namespace"], test=testmode
    )
    assert ret.result in (None, True)
    if not testmode:
        assert (
            kubernetes_exe.show_cron_job(name=cron_job["name"], namespace=cron_job["namespace"])
            is None
        )
