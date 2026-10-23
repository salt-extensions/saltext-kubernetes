from unittest.mock import MagicMock
from unittest.mock import patch

from saltext.kubernetes.states import k8s


def test_manifest_aliases_delegate_to_generic_states():
    present = MagicMock(return_value={"result": True})
    absent = MagicMock(return_value={"result": True})
    patched = MagicMock(return_value={"result": True})
    with patch.object(k8s._states, "manifest_present", present):
        with patch.object(k8s._states, "manifest_absent", absent):
            with patch.object(k8s._states, "manifest_patched", patched):
                assert k8s.present("app", manifest={"kind": "ConfigMap"}) == {"result": True}
                assert k8s.absent("app", source="salt://app.yaml") == {"result": True}
                assert k8s.patched("app", manifest={"kind": "ConfigMap"}) == {"result": True}
    present.assert_called_once()
    absent.assert_called_once()
    patched.assert_called_once()
