"""
Unit tests for the user-driven wait predicates in
``saltext.kubernetes.utils._kinds``.
"""

from types import SimpleNamespace

import pytest
from kubernetes.client import V1Service
from kubernetes.client import V1ServiceSpec
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.utils import _kinds


def _make_obj(**status):
    return SimpleNamespace(status=SimpleNamespace(**status))


def test_match_condition_true():
    obj = _make_obj(
        conditions=[
            SimpleNamespace(type="Available", status="True"),
            SimpleNamespace(type="Progressing", status="True"),
        ]
    )
    assert _kinds.match_condition(obj, "Available") is True


def test_match_condition_case_insensitive_status():
    obj = _make_obj(conditions=[SimpleNamespace(type="Ready", status="true")])
    assert _kinds.match_condition(obj, "Ready", "True") is True


def test_match_condition_missing_returns_false():
    obj = _make_obj(conditions=[SimpleNamespace(type="Available", status="True")])
    assert _kinds.match_condition(obj, "Ready") is False


def test_match_condition_no_status_returns_false():
    obj = SimpleNamespace(status=None)
    assert _kinds.match_condition(obj, "Ready") is False


def test_match_condition_explicit_false_status():
    obj = _make_obj(conditions=[SimpleNamespace(type="Ready", status="False")])
    assert _kinds.match_condition(obj, "Ready", "False") is True
    assert _kinds.match_condition(obj, "Ready", "True") is False


def test_match_jsonpath_existence():
    obj = _make_obj(load_balancer=SimpleNamespace(ingress=[SimpleNamespace(ip="10.0.0.1")]))
    assert _kinds.match_jsonpath(obj, ".status.loadBalancer.ingress[0].ip") is True


def test_match_jsonpath_equality():
    obj = _make_obj(phase="Running")
    assert _kinds.match_jsonpath(obj, ".status.phase", value="Running") is True
    assert _kinds.match_jsonpath(obj, ".status.phase", value="Pending") is False


def test_match_jsonpath_regex():
    obj = _make_obj(load_balancer=SimpleNamespace(ingress=[SimpleNamespace(ip="192.168.1.42")]))
    assert (
        _kinds.match_jsonpath(
            obj, ".status.loadBalancer.ingress[0].ip", regex=r"^\d+\.\d+\.\d+\.\d+$"
        )
        is True
    )


def test_match_jsonpath_missing_path():
    obj = _make_obj(phase="Pending")
    assert _kinds.match_jsonpath(obj, ".status.loadBalancer.ingress[0].ip") is False


def test_match_jsonpath_star_index_returns_last():
    obj = _make_obj(
        load_balancer=SimpleNamespace(
            ingress=[SimpleNamespace(ip="10.0.0.1"), SimpleNamespace(ip="10.0.0.2")]
        )
    )
    assert (
        _kinds.match_jsonpath(obj, ".status.loadBalancer.ingress[*].ip", value="10.0.0.2") is True
    )


def test_match_jsonpath_braces_stripped():
    obj = _make_obj(phase="Running")
    assert _kinds.match_jsonpath(obj, "{.status.phase}", value="Running") is True


def test_build_predicate_requires_one_of():
    with pytest.raises(CommandExecutionError):
        _kinds.build_predicate()


def test_build_predicate_rejects_both():
    with pytest.raises(CommandExecutionError):
        _kinds.build_predicate(condition="Ready", jsonpath=".status.phase")


def test_build_predicate_condition_returns_callable():
    pred = _kinds.build_predicate(condition="Ready")
    obj = _make_obj(conditions=[SimpleNamespace(type="Ready", status="True")])
    assert pred(obj) is True


def test_build_predicate_jsonpath_returns_callable():
    pred = _kinds.build_predicate(jsonpath=".status.phase", value="Running")
    assert pred(_make_obj(phase="Running")) is True
    assert pred(_make_obj(phase="Pending")) is False


def test_match_jsonpath_resolves_camelcase_acronym_field():
    """kubectl-style ``.spec.clusterIP`` must resolve on a V1ServiceSpec.

    The kubernetes-client OpenAPI generator translates ``clusterIP`` to
    the Python attribute ``cluster_ip`` (smart snake_case), not the
    naive ``cluster_i_p``. A user typing the YAML/kubectl spelling
    cannot be expected to know that distinction.
    """
    svc = V1Service(spec=V1ServiceSpec(cluster_ip="10.96.0.42"))
    assert _kinds.match_jsonpath(svc, ".spec.clusterIP") is True
    assert _kinds.match_jsonpath(svc, ".spec.clusterIP", value="10.96.0.42") is True


def test_match_jsonpath_resolves_dict_camelcase_path():
    """Dicts use their native key spelling; user-written camelCase wins."""
    obj = {"spec": {"clusterIP": "10.0.0.1", "ports": [{"targetPort": 80}]}}
    assert _kinds.match_jsonpath(obj, ".spec.clusterIP", value="10.0.0.1") is True
    assert _kinds.match_jsonpath(obj, ".spec.ports[0].targetPort", value=80) is True
