"""
Unit tests for the PV / PVC spec helpers.

End-to-end functional tests against a real cluster live in the
functional tier.
"""

import kubernetes.client
import pytest
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.modules import kubernetesmod

# ---------------------------------------------------------------------------
# PV
# ---------------------------------------------------------------------------


def _minimal_pv_spec():
    return {
        "capacity": {"storage": "10Gi"},
        "accessModes": ["ReadWriteOnce"],
        "hostPath": {"path": "/var/data"},
    }


def test_pv_spec_minimal():
    out = kubernetesmod.__dict_to_persistent_volume_spec(_minimal_pv_spec())
    assert out["access_modes"] == ["ReadWriteOnce"]
    assert out["capacity"] == {"storage": "10Gi"}


def test_pv_spec_camelcase_translation():
    spec = _minimal_pv_spec()
    spec["storageClassName"] = "standard"
    spec["persistentVolumeReclaimPolicy"] = "Retain"
    spec["volumeMode"] = "Filesystem"
    out = kubernetesmod.__dict_to_persistent_volume_spec(spec)
    assert out["storage_class_name"] == "standard"
    assert out["persistent_volume_reclaim_policy"] == "Retain"
    assert out["volume_mode"] == "Filesystem"


def test_pv_spec_rejects_missing_capacity():
    spec = _minimal_pv_spec()
    del spec["capacity"]
    with pytest.raises(CommandExecutionError, match="must include 'capacity'"):
        kubernetesmod.__dict_to_persistent_volume_spec(spec)


def test_pv_spec_rejects_missing_access_modes():
    spec = _minimal_pv_spec()
    del spec["accessModes"]
    with pytest.raises(CommandExecutionError, match="must include 'accessModes'"):
        kubernetesmod.__dict_to_persistent_volume_spec(spec)


def test_pv_spec_access_modes_must_be_list():
    spec = _minimal_pv_spec()
    spec["accessModes"] = "ReadWriteOnce"
    with pytest.raises(CommandExecutionError, match="must be a list"):
        kubernetesmod.__dict_to_persistent_volume_spec(spec)


# ---------------------------------------------------------------------------
# PVC
# ---------------------------------------------------------------------------


def _minimal_pvc_spec():
    return {
        "accessModes": ["ReadWriteOnce"],
        "resources": {"requests": {"storage": "1Gi"}},
    }


def test_pvc_spec_minimal():

    out = kubernetesmod.__dict_to_pvc_spec(_minimal_pvc_spec())
    assert out["access_modes"] == ["ReadWriteOnce"]
    assert isinstance(out["resources"], kubernetes.client.V1VolumeResourceRequirements)


def test_pvc_spec_camelcase_translation():
    spec = _minimal_pvc_spec()
    spec["storageClassName"] = "standard"
    spec["volumeMode"] = "Filesystem"
    spec["volumeName"] = "explicit-pv"
    out = kubernetesmod.__dict_to_pvc_spec(spec)
    assert out["storage_class_name"] == "standard"
    assert out["volume_mode"] == "Filesystem"
    assert out["volume_name"] == "explicit-pv"


def test_pvc_spec_rejects_missing_access_modes():
    spec = _minimal_pvc_spec()
    del spec["accessModes"]
    with pytest.raises(CommandExecutionError, match="must include 'accessModes'"):
        kubernetesmod.__dict_to_pvc_spec(spec)


def test_pvc_spec_rejects_missing_resources():
    spec = _minimal_pvc_spec()
    del spec["resources"]
    with pytest.raises(CommandExecutionError, match="must include 'resources'"):
        kubernetesmod.__dict_to_pvc_spec(spec)


def test_pvc_spec_wraps_selector_dict():

    spec = _minimal_pvc_spec()
    spec["selector"] = {"match_labels": {"app": "x"}}
    out = kubernetesmod.__dict_to_pvc_spec(spec)
    assert isinstance(out["selector"], kubernetes.client.V1LabelSelector)
