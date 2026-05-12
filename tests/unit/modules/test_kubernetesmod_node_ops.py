"""
Unit tests for the node lifecycle ops on
``saltext.kubernetes.modules.kubernetesmod`` (cordon, uncordon, taint,
untaint, drain).

These exercise input-validation and the pod-classification helpers used
by drain (DaemonSet detection, mirror-pod detection, emptyDir detection)
without touching the kubernetes API.
"""

from types import SimpleNamespace

import pytest
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.modules import kubernetesmod

# ---------------------------------------------------------------------------
# taint / untaint validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_effect", ["", "noschedule", "Schedule", "FORCE"])
def test_taint_rejects_invalid_effect(bad_effect):
    with pytest.raises(CommandExecutionError, match="Invalid taint effect"):
        kubernetesmod.taint("nodename", key="k", effect=bad_effect)


@pytest.mark.parametrize("good_effect", ["NoSchedule", "PreferNoSchedule", "NoExecute"])
def test_taint_valid_effects(good_effect):
    """Each canonical effect is in the validated set."""
    assert good_effect in kubernetesmod._VALID_TAINT_EFFECTS


def test_untaint_rejects_invalid_effect():
    with pytest.raises(CommandExecutionError, match="Invalid taint effect"):
        kubernetesmod.untaint("nodename", key="k", effect="bogus")


def test_untaint_allows_no_effect():
    """
    ``effect=None`` is the documented "remove all with this key" mode.

    We can't easily reach the API in a unit test, so we just confirm
    the validation block (which only checks ``effect is not None``)
    accepts ``None`` without raising the "Invalid taint effect" error
    that any explicit-but-invalid value would trigger.
    """
    # Trigger only the validation path: a None effect is permitted, an
    # invalid string is not. We compare the two error surfaces.
    with pytest.raises(CommandExecutionError, match="Invalid taint effect"):
        kubernetesmod.untaint("nodename", key="k", effect="bogus")
    # ``effect=None`` doesn't fire the "Invalid taint effect" check —
    # confirmed by the fact that a different exception fires later.
    with pytest.raises(Exception) as excinfo:
        kubernetesmod.untaint("nodename", key="k", effect=None)
    assert "Invalid taint effect" not in str(excinfo.value)


# ---------------------------------------------------------------------------
# Pod-classification helpers used by drain
# ---------------------------------------------------------------------------


def _pod(owner_kinds=(), annotations=None, volume_kinds=()):
    """Build a SimpleNamespace pod with the shape drain helpers expect."""
    refs = [SimpleNamespace(kind=k) for k in owner_kinds]
    vols = []
    for vk in volume_kinds:
        vol = SimpleNamespace(empty_dir=None, persistent_volume_claim=None)
        if vk == "emptyDir":
            vol.empty_dir = SimpleNamespace()
        vols.append(vol)
    return SimpleNamespace(
        metadata=SimpleNamespace(
            owner_references=refs,
            annotations=annotations or {},
        ),
        spec=SimpleNamespace(volumes=vols),
    )


def test_is_daemonset_pod_detects_ds_owner():
    assert kubernetesmod._is_daemonset_pod(_pod(owner_kinds=["DaemonSet"])) is True
    assert kubernetesmod._is_daemonset_pod(_pod(owner_kinds=["ReplicaSet"])) is False
    assert kubernetesmod._is_daemonset_pod(_pod()) is False


def test_is_mirror_pod_detects_kubelet_annotation():
    pod = _pod(annotations={"kubernetes.io/config.mirror": "0123abc"})
    assert kubernetesmod._is_mirror_pod(pod) is True
    assert kubernetesmod._is_mirror_pod(_pod()) is False


def test_has_emptydir_volume_detects():
    assert kubernetesmod._has_emptydir_volume(_pod(volume_kinds=["emptyDir"])) is True
    assert kubernetesmod._has_emptydir_volume(_pod(volume_kinds=["pvc"])) is False
    assert kubernetesmod._has_emptydir_volume(_pod()) is False
