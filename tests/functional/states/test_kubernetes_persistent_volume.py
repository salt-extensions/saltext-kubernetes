"""
Functional tests for the persistent-volume state functions:

  * ``kubernetes.persistent_volume_present`` / ``persistent_volume_absent``
  * ``kubernetes.persistent_volume_claim_present`` / ``..._claim_absent``

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
# PersistentVolume (cluster-scoped)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("persistent_volume", [False], indirect=True)
def test_persistent_volume_present(kubernetes, persistent_volume, testmode, kubernetes_exe):
    pv = persistent_volume
    ret = kubernetes.persistent_volume_present(name=pv["name"], spec=pv["spec"], test=testmode)
    assert ret.result in (None, True)
    if not testmode:
        assert kubernetes_exe.show_persistent_volume(name=pv["name"]) is not None


def test_persistent_volume_present_idempotency(kubernetes, persistent_volume, testmode):
    pv = persistent_volume
    ret = kubernetes.persistent_volume_present(name=pv["name"], spec=pv["spec"], test=testmode)
    assert ret.result is True
    assert not ret.changes


def test_persistent_volume_absent(kubernetes, persistent_volume, testmode, kubernetes_exe):
    pv = persistent_volume
    ret = kubernetes.persistent_volume_absent(name=pv["name"], test=testmode)
    assert ret.result in (None, True)
    if not testmode:
        assert kubernetes_exe.show_persistent_volume(name=pv["name"]) is None


@pytest.mark.parametrize("persistent_volume", [False], indirect=True)
def test_persistent_volume_absent_idempotency(kubernetes, persistent_volume, testmode):
    pv = persistent_volume
    ret = kubernetes.persistent_volume_absent(name=pv["name"], test=testmode)
    assert ret.result is True
    assert not ret.changes


# ---------------------------------------------------------------------------
# PersistentVolumeClaim (namespaced)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("persistent_volume_claim", [False], indirect=True)
def test_persistent_volume_claim_present(
    kubernetes, persistent_volume_claim, testmode, kubernetes_exe
):
    pvc = persistent_volume_claim
    ret = kubernetes.persistent_volume_claim_present(
        name=pvc["name"], namespace=pvc["namespace"], spec=pvc["spec"], test=testmode
    )
    assert ret.result in (None, True)
    if not testmode:
        assert (
            kubernetes_exe.show_persistent_volume_claim(
                name=pvc["name"], namespace=pvc["namespace"]
            )
            is not None
        )


def test_persistent_volume_claim_present_idempotency(kubernetes, persistent_volume_claim, testmode):
    pvc = persistent_volume_claim
    ret = kubernetes.persistent_volume_claim_present(
        name=pvc["name"], namespace=pvc["namespace"], spec=pvc["spec"], test=testmode
    )
    assert ret.result is True
    assert not ret.changes


def test_persistent_volume_claim_absent(
    kubernetes, persistent_volume_claim, testmode, kubernetes_exe
):
    pvc = persistent_volume_claim
    ret = kubernetes.persistent_volume_claim_absent(
        name=pvc["name"], namespace=pvc["namespace"], test=testmode
    )
    assert ret.result in (None, True)
    if not testmode:
        assert (
            kubernetes_exe.show_persistent_volume_claim(
                name=pvc["name"], namespace=pvc["namespace"]
            )
            is None
        )
