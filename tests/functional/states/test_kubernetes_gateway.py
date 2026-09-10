"""Functional state coverage for stable Gateway API resources."""

import pytest

pytestmark = [
    pytest.mark.skip_unless_on_linux(reason="Gateway API kind tests require Linux"),
]


@pytest.fixture
def kubernetes(states):
    return states.kubernetes


@pytest.fixture(params=[False, True])
def testmode(request):
    return request.param


@pytest.mark.parametrize("gateway_class", [False], indirect=True)
def test_gateway_class_present(kubernetes, gateway_class, testmode, kubernetes_exe):
    result = kubernetes.gateway_class_present(
        gateway_class["name"], spec=gateway_class["spec"], test=testmode
    )
    assert result.result in (None, True)
    assert (result.result is None) is testmode
    live = kubernetes_exe.show_gateway_class(gateway_class["name"])
    assert (live is not None) is not testmode


def test_gateway_class_present_idempotency(kubernetes, gateway_class):
    result = kubernetes.gateway_class_present(gateway_class["name"], spec=gateway_class["spec"])
    assert result.result is True
    assert not result.changes


def test_gateway_class_absent(kubernetes, gateway_class, testmode, kubernetes_exe):
    result = kubernetes.gateway_class_absent(gateway_class["name"], test=testmode)
    assert result.result in (None, True)
    assert (result.result is None) is testmode
    live = kubernetes_exe.show_gateway_class(gateway_class["name"])
    assert (live is None) is not testmode


@pytest.mark.parametrize("gateway", [False], indirect=True)
def test_gateway_present(kubernetes, gateway, testmode, kubernetes_exe):
    result = kubernetes.gateway_present(
        gateway["name"],
        namespace=gateway["namespace"],
        spec=gateway["spec"],
        test=testmode,
    )
    assert result.result in (None, True)
    assert (result.result is None) is testmode
    live = kubernetes_exe.show_gateway(gateway["name"], namespace=gateway["namespace"])
    assert (live is not None) is not testmode


def test_gateway_present_idempotency(kubernetes, gateway):
    result = kubernetes.gateway_present(
        gateway["name"], namespace=gateway["namespace"], spec=gateway["spec"]
    )
    assert result.result is True
    assert not result.changes


def test_gateway_absent(kubernetes, gateway, testmode, kubernetes_exe):
    result = kubernetes.gateway_absent(
        gateway["name"], namespace=gateway["namespace"], test=testmode
    )
    assert result.result in (None, True)
    assert (result.result is None) is testmode
    live = kubernetes_exe.show_gateway(gateway["name"], namespace=gateway["namespace"])
    assert (live is None) is not testmode


@pytest.mark.parametrize("http_route", [False], indirect=True)
def test_http_route_present_and_absent(kubernetes, http_route, testmode, kubernetes_exe):
    result = kubernetes.http_route_present(
        http_route["name"],
        namespace=http_route["namespace"],
        spec=http_route["spec"],
        test=testmode,
    )
    assert result.result in (None, True)
    assert (result.result is None) is testmode
    live = kubernetes_exe.show_http_route(http_route["name"], namespace=http_route["namespace"])
    assert (live is not None) is not testmode


@pytest.mark.parametrize("http_route", [True], indirect=True)
def test_http_route_absent(kubernetes, http_route, testmode, kubernetes_exe):
    result = kubernetes.http_route_absent(
        http_route["name"], namespace=http_route["namespace"], test=testmode
    )
    assert result.result in (None, True)
    assert (result.result is None) is testmode
    live = kubernetes_exe.show_http_route(http_route["name"], namespace=http_route["namespace"])
    assert (live is None) is not testmode


@pytest.mark.parametrize("reference_grant", [False], indirect=True)
def test_reference_grant_present(kubernetes, reference_grant, testmode, kubernetes_exe):
    result = kubernetes.reference_grant_present(
        reference_grant["name"],
        namespace=reference_grant["namespace"],
        spec=reference_grant["spec"],
        test=testmode,
    )
    assert result.result in (None, True)
    assert (result.result is None) is testmode
    live = kubernetes_exe.show_reference_grant(
        reference_grant["name"], namespace=reference_grant["namespace"]
    )
    assert (live is not None) is not testmode


@pytest.mark.parametrize("reference_grant", [True], indirect=True)
def test_reference_grant_absent(kubernetes, reference_grant, testmode, kubernetes_exe):
    result = kubernetes.reference_grant_absent(
        reference_grant["name"], namespace=reference_grant["namespace"], test=testmode
    )
    assert result.result in (None, True)
    assert (result.result is None) is testmode
    live = kubernetes_exe.show_reference_grant(
        reference_grant["name"], namespace=reference_grant["namespace"]
    )
    assert (live is None) is not testmode
