"""
Unit tests for the RBAC spec helpers in
``saltext.kubernetes.modules.kubernetesmod``.

These exercise the input-normalisation and validation layer (the
``__dict_to_*_spec`` helpers and the immutable-roleRef error
recogniser) without touching the kubernetes API. Functional tests
that exercise the full create/show/replace/patch/delete round-trip
against a real cluster live alongside the other functional tests.
"""

import kubernetes.client
import pytest
from kubernetes.client.rest import ApiException
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.modules import kubernetesmod

# ---------------------------------------------------------------------------
# __dict_to_policy_rule_list / __dict_to_role_spec / __dict_to_cluster_role_spec
# ---------------------------------------------------------------------------


def test_role_spec_accepts_camelcase_rule_keys():
    """camelCase fields in rule dicts are translated to the snake_case
    constructor kwargs the kubernetes-client expects."""
    spec = {
        "rules": [
            {
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get", "list"],
                "resourceNames": ["foo"],
                "nonResourceURLs": ["/healthz"],
            }
        ]
    }
    result = kubernetesmod.__dict_to_role_spec(spec)
    assert len(result["rules"]) == 1
    rule = result["rules"][0]
    assert rule.api_groups == [""]
    assert rule.resource_names == ["foo"]
    # The kubernetes-client OpenAPI generator names this attribute
    # ``non_resource_ur_ls`` (note the awkward second underscore — an
    # artefact of how the all-caps URL token is split). Both
    # ``nonResourceURLs`` and ``non_resource_urls`` from the caller map
    # to it.
    assert rule.non_resource_ur_ls == ["/healthz"]


def test_role_spec_rejects_non_dict():
    with pytest.raises(CommandExecutionError, match="Role spec must be a dictionary"):
        kubernetesmod.__dict_to_role_spec("not-a-dict")


def test_role_spec_rejects_rule_without_verbs():
    spec = {"rules": [{"apiGroups": [""], "resources": ["pods"]}]}
    with pytest.raises(CommandExecutionError, match="non-empty 'verbs'"):
        kubernetesmod.__dict_to_role_spec(spec)


def test_role_spec_with_no_rules_is_empty_list():
    """A Role with no rules is permitted by the API; we must not reject it."""
    result = kubernetesmod.__dict_to_role_spec({})
    assert result == {"rules": []}


def test_cluster_role_spec_with_aggregation_rule():
    spec = {
        "rules": [],
        "aggregationRule": {"clusterRoleSelectors": [{"match_labels": {"role": "aggregated"}}]},
    }
    result = kubernetesmod.__dict_to_cluster_role_spec(spec)
    assert "aggregation_rule" in result
    assert isinstance(result["aggregation_rule"], kubernetes.client.V1AggregationRule)


def test_cluster_role_spec_aggregation_rule_must_be_dict():
    with pytest.raises(CommandExecutionError, match="aggregationRule must be a dictionary"):
        kubernetesmod.__dict_to_cluster_role_spec({"rules": [], "aggregationRule": "nope"})


# ---------------------------------------------------------------------------
# __dict_to_subject_list / __dict_to_role_ref / __dict_to_role_binding_spec
# ---------------------------------------------------------------------------


def test_subject_list_normalises_apigroup_camelcase():
    subjects = [{"kind": "User", "name": "alice", "apiGroup": "rbac.authorization.k8s.io"}]
    result = kubernetesmod.__dict_to_subject_list(subjects)
    assert result[0].kind == "User"
    assert result[0].name == "alice"
    assert result[0].api_group == "rbac.authorization.k8s.io"


def test_subject_list_rejects_missing_kind_or_name():
    with pytest.raises(CommandExecutionError, match="must include 'kind' and 'name'"):
        kubernetesmod.__dict_to_subject_list([{"name": "alice"}])
    with pytest.raises(CommandExecutionError, match="must include 'kind' and 'name'"):
        kubernetesmod.__dict_to_subject_list([{"kind": "User"}])


def test_subject_list_rejects_non_list():
    with pytest.raises(CommandExecutionError, match="Subjects must be a list"):
        kubernetesmod.__dict_to_subject_list({"not": "a list"})


def test_role_ref_defaults_api_group():
    """``roleRef.apiGroup`` defaults to ``rbac.authorization.k8s.io``."""
    ref = kubernetesmod.__dict_to_role_ref({"kind": "Role", "name": "r1"})
    assert ref.api_group == "rbac.authorization.k8s.io"
    assert ref.kind == "Role"
    assert ref.name == "r1"


def test_role_ref_camelcase_apigroup_normalised():
    ref = kubernetesmod.__dict_to_role_ref(
        {"kind": "Role", "name": "r1", "apiGroup": "custom.example.com"}
    )
    assert ref.api_group == "custom.example.com"


def test_role_ref_rejects_missing_required():
    with pytest.raises(CommandExecutionError, match="must include 'kind' and 'name'"):
        kubernetesmod.__dict_to_role_ref({"name": "r1"})


def test_role_binding_spec_full():
    spec = {
        "subjects": [{"kind": "User", "name": "alice"}],
        "roleRef": {"kind": "Role", "name": "pod-reader"},
    }
    result = kubernetesmod.__dict_to_role_binding_spec(spec)
    assert len(result["subjects"]) == 1
    assert result["role_ref"].name == "pod-reader"


def test_role_binding_spec_rejects_missing_subjects_or_roleref():
    with pytest.raises(CommandExecutionError, match="must include 'subjects'"):
        kubernetesmod.__dict_to_role_binding_spec({"roleRef": {"kind": "Role", "name": "r"}})
    with pytest.raises(CommandExecutionError, match="must include 'roleRef'"):
        kubernetesmod.__dict_to_role_binding_spec({"subjects": []})


# ---------------------------------------------------------------------------
# __dict_to_service_account_spec
# ---------------------------------------------------------------------------


def test_service_account_spec_empty_is_ok():
    """A ServiceAccount with no spec fields is valid (and common)."""
    assert not kubernetesmod.__dict_to_service_account_spec({})
    assert not kubernetesmod.__dict_to_service_account_spec(None)


def test_service_account_spec_image_pull_secrets():
    spec = {"imagePullSecrets": [{"name": "my-registry"}]}
    result = kubernetesmod.__dict_to_service_account_spec(spec)
    assert len(result["image_pull_secrets"]) == 1
    assert result["image_pull_secrets"][0].name == "my-registry"


def test_service_account_spec_automount_token_camelcase():
    spec = {"automountServiceAccountToken": False}
    result = kubernetesmod.__dict_to_service_account_spec(spec)
    assert result["automount_service_account_token"] is False


def test_service_account_spec_rejects_image_pull_secrets_non_list():
    with pytest.raises(CommandExecutionError, match="imagePullSecrets must be a list"):
        kubernetesmod.__dict_to_service_account_spec({"imagePullSecrets": "not-a-list"})


# ---------------------------------------------------------------------------
# _is_immutable_role_ref_error
# ---------------------------------------------------------------------------


class _FakeApiException(Exception):
    """Stand-in for kubernetes.client.rest.ApiException with a ``.body`` attr."""

    def __init__(self, body):
        super().__init__(body)
        self.body = body


def test_immutable_role_ref_recognised_in_real_k8s_message():
    """Match the actual phrasing observed from K8s 1.28 / 1.35 API servers."""

    exc = ApiException(status=422, reason="Invalid")
    exc.body = (
        '{"kind":"Status","message":"RoleBinding.rbac.authorization.k8s.io '
        '\\"r\\" is invalid: roleRef: Invalid value: rbac.RoleRef{...}: '
        'cannot change roleRef","reason":"Invalid"}'
    )
    assert kubernetesmod._is_immutable_role_ref_error(exc) is True


def test_immutable_role_ref_recognised_in_immutable_phrasing():
    """Older K8s versions used 'is immutable' / 'cannot be modified'."""

    exc = ApiException(status=422, reason="Invalid")
    exc.body = '{"message":"RoleBinding ... roleRef: Invalid value: cannot be modified"}'
    assert kubernetesmod._is_immutable_role_ref_error(exc) is True


def test_immutable_role_ref_not_a_match_for_other_errors():

    exc = ApiException(status=403, reason="Forbidden")
    exc.body = "forbidden: user does not have permission"
    assert kubernetesmod._is_immutable_role_ref_error(exc) is False


def test_immutable_role_ref_handles_non_apiexception():
    """Plain exceptions (HTTPError, ValueError, ...) are not roleRef errors."""
    assert kubernetesmod._is_immutable_role_ref_error(ValueError("x")) is False


# ---------------------------------------------------------------------------
# _normalise_rbac_patch
# ---------------------------------------------------------------------------


def test_normalise_rbac_patch_flattens_state_style_spec():
    """Patches wrapped under ``spec:`` (as the state functions emit) get flattened."""
    patch = {"metadata": {"labels": {"x": "y"}}, "spec": {"rules": [...]}}
    result = kubernetesmod._normalise_rbac_patch(patch, "Role")
    # spec contents lifted to top level; metadata preserved
    assert "rules" in result
    assert result["metadata"] == {"labels": {"x": "y"}}
    assert "spec" not in result


def test_normalise_rbac_patch_rejects_non_dict():
    with pytest.raises(CommandExecutionError, match="Role patch must be a dictionary"):
        kubernetesmod._normalise_rbac_patch("not-a-dict", "Role")


def test_normalise_rbac_patch_rejects_non_dict_spec():
    with pytest.raises(CommandExecutionError, match="spec patch must be a dictionary"):
        kubernetesmod._normalise_rbac_patch({"spec": [1, 2, 3]}, "Role")
