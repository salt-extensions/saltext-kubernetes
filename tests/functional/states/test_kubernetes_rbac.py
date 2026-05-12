"""
Functional tests for the RBAC state functions:

  * ``kubernetes.role_present`` / ``role_absent``
  * ``kubernetes.role_binding_present`` / ``role_binding_absent``
  * ``kubernetes.cluster_role_present`` / ``cluster_role_absent``
  * ``kubernetes.cluster_role_binding_present`` / ``cluster_role_binding_absent``
  * ``kubernetes.service_account_present`` / ``service_account_absent``

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
# Role
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", [False], indirect=True)
def test_role_present(kubernetes, role, testmode, kubernetes_exe):
    ret = kubernetes.role_present(
        name=role["name"], namespace=role["namespace"], spec=role["spec"], test=testmode
    )
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    if not testmode:
        live = kubernetes_exe.show_role(name=role["name"], namespace=role["namespace"])
        assert live is not None
        assert live["metadata"]["name"] == role["name"]
    else:
        assert kubernetes_exe.show_role(name=role["name"], namespace=role["namespace"]) is None


def test_role_present_idempotency(kubernetes, role, testmode):
    ret = kubernetes.role_present(
        name=role["name"], namespace=role["namespace"], spec=role["spec"], test=testmode
    )
    assert ret.result is True
    assert not ret.changes


def test_role_absent(kubernetes, role, testmode, kubernetes_exe):
    ret = kubernetes.role_absent(name=role["name"], namespace=role["namespace"], test=testmode)
    assert ret.result in (None, True)
    if not testmode:
        assert kubernetes_exe.show_role(name=role["name"], namespace=role["namespace"]) is None


@pytest.mark.parametrize("role", [False], indirect=True)
def test_role_absent_idempotency(kubernetes, role, testmode):
    ret = kubernetes.role_absent(name=role["name"], namespace=role["namespace"], test=testmode)
    assert ret.result is True
    assert not ret.changes


# ---------------------------------------------------------------------------
# RoleBinding
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role_binding", [False], indirect=True)
def test_role_binding_present(kubernetes, role_binding, testmode, kubernetes_exe):
    ret = kubernetes.role_binding_present(
        name=role_binding["name"],
        namespace=role_binding["namespace"],
        spec=role_binding["spec"],
        test=testmode,
    )
    assert ret.result in (None, True)
    if not testmode:
        live = kubernetes_exe.show_role_binding(
            name=role_binding["name"], namespace=role_binding["namespace"]
        )
        assert live is not None


def test_role_binding_present_idempotency(kubernetes, role_binding, testmode):
    ret = kubernetes.role_binding_present(
        name=role_binding["name"],
        namespace=role_binding["namespace"],
        spec=role_binding["spec"],
        test=testmode,
    )
    assert ret.result is True
    assert not ret.changes


def test_role_binding_absent(kubernetes, role_binding, testmode, kubernetes_exe):
    ret = kubernetes.role_binding_absent(
        name=role_binding["name"], namespace=role_binding["namespace"], test=testmode
    )
    assert ret.result in (None, True)
    if not testmode:
        assert (
            kubernetes_exe.show_role_binding(
                name=role_binding["name"], namespace=role_binding["namespace"]
            )
            is None
        )


# ---------------------------------------------------------------------------
# ClusterRole
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cluster_role", [False], indirect=True)
def test_cluster_role_present(kubernetes, cluster_role, testmode, kubernetes_exe):
    ret = kubernetes.cluster_role_present(
        name=cluster_role["name"], spec=cluster_role["spec"], test=testmode
    )
    assert ret.result in (None, True)
    if not testmode:
        assert kubernetes_exe.show_cluster_role(name=cluster_role["name"]) is not None


def test_cluster_role_present_idempotency(kubernetes, cluster_role, testmode):
    ret = kubernetes.cluster_role_present(
        name=cluster_role["name"], spec=cluster_role["spec"], test=testmode
    )
    assert ret.result is True
    assert not ret.changes


def test_cluster_role_absent(kubernetes, cluster_role, testmode, kubernetes_exe):
    ret = kubernetes.cluster_role_absent(name=cluster_role["name"], test=testmode)
    assert ret.result in (None, True)
    if not testmode:
        assert kubernetes_exe.show_cluster_role(name=cluster_role["name"]) is None


# ---------------------------------------------------------------------------
# ClusterRoleBinding
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cluster_role_binding", [False], indirect=True)
def test_cluster_role_binding_present(kubernetes, cluster_role_binding, testmode, kubernetes_exe):
    ret = kubernetes.cluster_role_binding_present(
        name=cluster_role_binding["name"], spec=cluster_role_binding["spec"], test=testmode
    )
    assert ret.result in (None, True)
    if not testmode:
        assert (
            kubernetes_exe.show_cluster_role_binding(name=cluster_role_binding["name"]) is not None
        )


def test_cluster_role_binding_present_idempotency(kubernetes, cluster_role_binding, testmode):
    ret = kubernetes.cluster_role_binding_present(
        name=cluster_role_binding["name"], spec=cluster_role_binding["spec"], test=testmode
    )
    assert ret.result is True
    assert not ret.changes


def test_cluster_role_binding_absent(kubernetes, cluster_role_binding, testmode, kubernetes_exe):
    ret = kubernetes.cluster_role_binding_absent(name=cluster_role_binding["name"], test=testmode)
    assert ret.result in (None, True)
    if not testmode:
        assert kubernetes_exe.show_cluster_role_binding(name=cluster_role_binding["name"]) is None


# ---------------------------------------------------------------------------
# ServiceAccount
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("service_account", [False], indirect=True)
def test_service_account_present(kubernetes, service_account, testmode, kubernetes_exe):
    ret = kubernetes.service_account_present(
        name=service_account["name"],
        namespace=service_account["namespace"],
        spec=service_account["spec"],
        test=testmode,
    )
    assert ret.result in (None, True)
    if not testmode:
        assert (
            kubernetes_exe.show_service_account(
                name=service_account["name"], namespace=service_account["namespace"]
            )
            is not None
        )


def test_service_account_present_idempotency(kubernetes, service_account, testmode):
    ret = kubernetes.service_account_present(
        name=service_account["name"],
        namespace=service_account["namespace"],
        spec=service_account["spec"],
        test=testmode,
    )
    assert ret.result is True
    assert not ret.changes


def test_service_account_absent(kubernetes, service_account, testmode, kubernetes_exe):
    ret = kubernetes.service_account_absent(
        name=service_account["name"], namespace=service_account["namespace"], test=testmode
    )
    assert ret.result in (None, True)
    if not testmode:
        assert (
            kubernetes_exe.show_service_account(
                name=service_account["name"], namespace=service_account["namespace"]
            )
            is None
        )
