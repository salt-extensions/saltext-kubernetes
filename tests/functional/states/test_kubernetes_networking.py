"""
Functional tests for the networking / scaling / policy state functions:

  * ``kubernetes.ingress_present`` / ``ingress_absent``
  * ``kubernetes.horizontal_pod_autoscaler_present`` / ``..._absent``
  * ``kubernetes.pod_disruption_budget_present`` / ``..._absent``

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
# Ingress
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ingress", [False], indirect=True)
def test_ingress_present(kubernetes, ingress, testmode, kubernetes_exe):
    ret = kubernetes.ingress_present(
        name=ingress["name"], namespace=ingress["namespace"], spec=ingress["spec"], test=testmode
    )
    assert ret.result in (None, True)
    if not testmode:
        live = kubernetes_exe.show_ingress(name=ingress["name"], namespace=ingress["namespace"])
        assert live is not None


def test_ingress_present_idempotency(kubernetes, ingress, testmode):
    ret = kubernetes.ingress_present(
        name=ingress["name"], namespace=ingress["namespace"], spec=ingress["spec"], test=testmode
    )
    assert ret.result is True
    assert not ret.changes


def test_ingress_absent(kubernetes, ingress, testmode, kubernetes_exe):
    ret = kubernetes.ingress_absent(
        name=ingress["name"], namespace=ingress["namespace"], test=testmode
    )
    assert ret.result in (None, True)
    if not testmode:
        assert (
            kubernetes_exe.show_ingress(name=ingress["name"], namespace=ingress["namespace"])
            is None
        )


# ---------------------------------------------------------------------------
# HorizontalPodAutoscaler
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("horizontal_pod_autoscaler", [False], indirect=True)
def test_horizontal_pod_autoscaler_present(
    kubernetes, horizontal_pod_autoscaler, testmode, kubernetes_exe
):
    hpa = horizontal_pod_autoscaler
    ret = kubernetes.horizontal_pod_autoscaler_present(
        name=hpa["name"], namespace=hpa["namespace"], spec=hpa["spec"], test=testmode
    )
    assert ret.result in (None, True)
    if not testmode:
        assert (
            kubernetes_exe.show_horizontal_pod_autoscaler(
                name=hpa["name"], namespace=hpa["namespace"]
            )
            is not None
        )


def test_horizontal_pod_autoscaler_present_idempotency(
    kubernetes, horizontal_pod_autoscaler, testmode
):
    hpa = horizontal_pod_autoscaler
    ret = kubernetes.horizontal_pod_autoscaler_present(
        name=hpa["name"], namespace=hpa["namespace"], spec=hpa["spec"], test=testmode
    )
    assert ret.result is True
    assert not ret.changes


def test_horizontal_pod_autoscaler_absent(
    kubernetes, horizontal_pod_autoscaler, testmode, kubernetes_exe
):
    hpa = horizontal_pod_autoscaler
    ret = kubernetes.horizontal_pod_autoscaler_absent(
        name=hpa["name"], namespace=hpa["namespace"], test=testmode
    )
    assert ret.result in (None, True)
    if not testmode:
        assert (
            kubernetes_exe.show_horizontal_pod_autoscaler(
                name=hpa["name"], namespace=hpa["namespace"]
            )
            is None
        )


# ---------------------------------------------------------------------------
# PodDisruptionBudget
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pod_disruption_budget", [False], indirect=True)
@pytest.mark.skip(
    reason="needs kind-env calibration — see PR #36; feature is unit-tested, this kind test needs SSA/eviction-semantics tuning"
)
def test_pod_disruption_budget_present(kubernetes, pod_disruption_budget, testmode, kubernetes_exe):
    pdb = pod_disruption_budget
    ret = kubernetes.pod_disruption_budget_present(
        name=pdb["name"], namespace=pdb["namespace"], spec=pdb["spec"], test=testmode
    )
    assert ret.result in (None, True)
    if not testmode:
        assert (
            kubernetes_exe.show_pod_disruption_budget(name=pdb["name"], namespace=pdb["namespace"])
            is not None
        )


def test_pod_disruption_budget_present_idempotency(kubernetes, pod_disruption_budget, testmode):
    pdb = pod_disruption_budget
    ret = kubernetes.pod_disruption_budget_present(
        name=pdb["name"], namespace=pdb["namespace"], spec=pdb["spec"], test=testmode
    )
    assert ret.result is True
    assert not ret.changes


def test_pod_disruption_budget_absent(kubernetes, pod_disruption_budget, testmode, kubernetes_exe):
    pdb = pod_disruption_budget
    ret = kubernetes.pod_disruption_budget_absent(
        name=pdb["name"], namespace=pdb["namespace"], test=testmode
    )
    assert ret.result in (None, True)
    if not testmode:
        assert (
            kubernetes_exe.show_pod_disruption_budget(name=pdb["name"], namespace=pdb["namespace"])
            is None
        )
