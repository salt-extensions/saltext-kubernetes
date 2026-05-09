"""
Unit tests for the Ingress / HPA / PDB spec helpers.

Functional tests against a real cluster live in the functional tier.
"""

import kubernetes.client
import pytest
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.modules import kubernetesmod

# ---------------------------------------------------------------------------
# Ingress
# ---------------------------------------------------------------------------


def test_ingress_spec_camelcase_translation():
    spec = {"ingressClassName": "nginx", "rules": []}
    out = kubernetesmod.__dict_to_ingress_spec(spec)
    assert out["ingress_class_name"] == "nginx"


def test_ingress_spec_rules_must_be_list():
    with pytest.raises(CommandExecutionError, match="rules must be a list"):
        kubernetesmod.__dict_to_ingress_spec({"rules": "not-a-list"})


def test_ingress_spec_tls_must_be_list():
    with pytest.raises(CommandExecutionError, match="tls must be a list"):
        kubernetesmod.__dict_to_ingress_spec({"tls": "not-a-list"})


def test_ingress_spec_rejects_non_dict():
    with pytest.raises(CommandExecutionError, match="Ingress spec must be a dictionary"):
        kubernetesmod.__dict_to_ingress_spec("nope")


# ---------------------------------------------------------------------------
# HPA
# ---------------------------------------------------------------------------


def _minimal_hpa_spec():
    return {
        "scaleTargetRef": {"api_version": "apps/v1", "kind": "Deployment", "name": "my-app"},
        "minReplicas": 1,
        "maxReplicas": 5,
    }


def test_hpa_spec_minimal():
    out = kubernetesmod.__dict_to_hpa_spec(_minimal_hpa_spec())
    assert out["min_replicas"] == 1
    assert out["max_replicas"] == 5
    # scale_target_ref was wrapped in a V2CrossVersionObjectReference

    assert isinstance(out["scale_target_ref"], kubernetes.client.V2CrossVersionObjectReference)


def test_hpa_spec_rejects_missing_scale_target_ref():
    spec = _minimal_hpa_spec()
    del spec["scaleTargetRef"]
    with pytest.raises(CommandExecutionError, match="must include 'scaleTargetRef'"):
        kubernetesmod.__dict_to_hpa_spec(spec)


def test_hpa_spec_rejects_missing_max_replicas():
    spec = _minimal_hpa_spec()
    del spec["maxReplicas"]
    with pytest.raises(CommandExecutionError, match="must include 'maxReplicas'"):
        kubernetesmod.__dict_to_hpa_spec(spec)


def test_hpa_spec_scale_target_must_be_dict():
    spec = _minimal_hpa_spec()
    spec["scaleTargetRef"] = "not-a-dict"
    with pytest.raises(CommandExecutionError, match="scaleTargetRef must be a dict"):
        kubernetesmod.__dict_to_hpa_spec(spec)


# ---------------------------------------------------------------------------
# PDB
# ---------------------------------------------------------------------------


def test_pdb_spec_min_available():
    out = kubernetesmod.__dict_to_pdb_spec(
        {"minAvailable": 2, "selector": {"match_labels": {"app": "x"}}}
    )
    assert out["min_available"] == 2


def test_pdb_spec_max_unavailable():
    out = kubernetesmod.__dict_to_pdb_spec(
        {"maxUnavailable": "20%", "selector": {"match_labels": {"app": "x"}}}
    )
    assert out["max_unavailable"] == "20%"


def test_pdb_spec_rejects_both_min_and_max():
    with pytest.raises(CommandExecutionError, match="cannot include both"):
        kubernetesmod.__dict_to_pdb_spec(
            {
                "minAvailable": 1,
                "maxUnavailable": 1,
                "selector": {"match_labels": {"app": "x"}},
            }
        )


def test_pdb_spec_rejects_neither_min_nor_max():
    with pytest.raises(CommandExecutionError, match="must include exactly one of"):
        kubernetesmod.__dict_to_pdb_spec({"selector": {"match_labels": {"app": "x"}}})


def test_pdb_spec_requires_selector():
    with pytest.raises(CommandExecutionError, match="must include 'selector'"):
        kubernetesmod.__dict_to_pdb_spec({"minAvailable": 1})
