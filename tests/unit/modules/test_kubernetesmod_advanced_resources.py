"""
Unit tests for the typed-kind spec helpers added to close issue #14:

  * ``__dict_to_network_policy_spec`` (NetworkPolicy)
  * ``__dict_to_resource_quota_spec`` (ResourceQuota)
  * ``__dict_to_limit_range_spec`` (LimitRange)
  * ``__dict_to_priority_class_kwargs`` (PriorityClass)
  * ``__dict_to_crd_spec`` (CustomResourceDefinition)

Plus the helpers they share:

  * ``_label_selector_from_dict`` — converts a kubectl-style selector
    dict (``matchLabels`` / ``matchExpressions``) to a V1LabelSelector.
  * ``_snake_caseify_keys`` — generic camelCase→snake_case key mapper,
    used by container/pod-spec normalization and the limit-range item
    builder.

Functional behaviour against a kind cluster lives in the functional tier;
these tests pin down the validation, normalisation, and error-message
contracts that user-supplied dicts depend on.
"""

import kubernetes.client
import pytest
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.modules import kubernetesmod

# ---------------------------------------------------------------------------
# _label_selector_from_dict
# ---------------------------------------------------------------------------


def test_label_selector_camelcase_matchlabels():
    sel = kubernetesmod._label_selector_from_dict({"matchLabels": {"app": "web"}})
    assert isinstance(sel, kubernetes.client.V1LabelSelector)
    assert sel.match_labels == {"app": "web"}


def test_label_selector_snake_case_match_labels():
    """The kubernetes-client native spelling also works."""
    sel = kubernetesmod._label_selector_from_dict({"match_labels": {"app": "web"}})
    assert sel.match_labels == {"app": "web"}


def test_label_selector_matchexpressions_passes_through():
    expr = [{"key": "tier", "operator": "In", "values": ["frontend"]}]
    sel = kubernetesmod._label_selector_from_dict({"matchExpressions": expr})
    # match_expressions accepts list-of-dicts; the client serializes at request time.
    assert sel.match_expressions == expr


def test_label_selector_none_returns_none():
    assert kubernetesmod._label_selector_from_dict(None) is None


def test_label_selector_rejects_non_mapping():
    with pytest.raises(CommandExecutionError, match="selector must be a dictionary"):
        kubernetesmod._label_selector_from_dict("nope")


def test_label_selector_empty_dict_is_match_everything():
    """An empty selector means "select all" — V1LabelSelector with no fields."""
    sel = kubernetesmod._label_selector_from_dict({})
    assert sel.match_labels is None
    assert sel.match_expressions is None


# ---------------------------------------------------------------------------
# _snake_caseify_keys
# ---------------------------------------------------------------------------


def test_snake_caseify_keys_translates_camelcase():
    out = kubernetesmod._snake_caseify_keys({"imagePullPolicy": "Always", "name": "x"})
    assert out == {"image_pull_policy": "Always", "name": "x"}


def test_snake_caseify_keys_passes_snake_case_through():
    out = kubernetesmod._snake_caseify_keys({"image_pull_policy": "Always"})
    assert out == {"image_pull_policy": "Always"}


def test_snake_caseify_keys_handles_non_mapping():
    """Lists / scalars pass through unchanged so callers can use it unconditionally."""
    assert kubernetesmod._snake_caseify_keys([1, 2]) == [1, 2]
    assert kubernetesmod._snake_caseify_keys("x") == "x"
    assert kubernetesmod._snake_caseify_keys(None) is None


def test_snake_caseify_keys_does_not_recurse():
    """Nested dicts are intentionally left alone — only top-level keys translate."""
    out = kubernetesmod._snake_caseify_keys({"outerKey": {"innerKey": 1}})
    assert out == {"outer_key": {"innerKey": 1}}


# ---------------------------------------------------------------------------
# _normalise_field_map — the underlying helper that _snake_caseify_keys
# delegates to. Verifies the contract the per-kind FIELD_MAPs depend on.
# ---------------------------------------------------------------------------


def test_normalise_field_map_explicit_override_wins():
    """An entry in the mapping always wins over the naive fallback."""
    out = kubernetesmod._normalise_field_map({"clusterIP": "10.0.0.1"}, {"clusterIP": "cluster_ip"})
    # Without the override the naive fallback would produce "cluster_i_p"
    # because _camel_to_snake splits before every uppercase letter.
    assert out == {"cluster_ip": "10.0.0.1"}


def test_normalise_field_map_falls_back_to_naive_translation():
    """Unmapped camelCase keys use the generic camel→snake fallback."""
    out = kubernetesmod._normalise_field_map({"reclaimPolicy": "Retain"}, {})
    assert out == {"reclaim_policy": "Retain"}


def test_normalise_field_map_mapping_optional():
    """Calling without a mapping is equivalent to _snake_caseify_keys."""
    out = kubernetesmod._normalise_field_map({"imagePullPolicy": "Always"})
    assert out == {"image_pull_policy": "Always"}


def test_normalise_field_map_passes_non_mapping_through():
    """Non-dict inputs (lists, scalars, None) survive unchanged."""
    assert kubernetesmod._normalise_field_map([1, 2]) == [1, 2]
    assert kubernetesmod._normalise_field_map(None) is None
    assert kubernetesmod._normalise_field_map("x") == "x"


def test_normalise_field_map_snake_case_keys_pass_through():
    """Keys already in snake_case are not double-translated."""
    out = kubernetesmod._normalise_field_map({"image_pull_policy": "Always"}, {})
    assert out == {"image_pull_policy": "Always"}


def test_snake_caseify_keys_is_thin_alias_for_normalise_field_map():
    """The two helpers must produce identical output for any dict input."""
    spec = {"imagePullPolicy": "Always", "restartPolicy": "Never", "snake_already": 1}
    assert kubernetesmod._snake_caseify_keys(spec) == kubernetesmod._normalise_field_map(spec)


# ---------------------------------------------------------------------------
# _STORAGECLASS_FIELD_MAP integration — the new explicit FIELD_MAP entry
# for StorageClass replaces five hand-coded ``processed_spec.pop`` lines.
# ---------------------------------------------------------------------------


def test_storageclass_field_map_covers_all_five_renames():
    """Every previously hand-translated key has a FIELD_MAP entry."""
    expected = {
        "reclaimPolicy",
        "allowVolumeExpansion",
        "volumeBindingMode",
        "mountOptions",
        "allowedTopologies",
    }
    assert set(kubernetesmod._STORAGECLASS_FIELD_MAP) == expected


# ---------------------------------------------------------------------------
# NetworkPolicy spec
# ---------------------------------------------------------------------------


def test_network_policy_spec_camelcase_normalisation():
    out = kubernetesmod.__dict_to_network_policy_spec(
        {"podSelector": {}, "policyTypes": ["Ingress"]}
    )
    assert isinstance(out["pod_selector"], kubernetes.client.V1LabelSelector)
    assert out["policy_types"] == ["Ingress"]


def test_network_policy_spec_pod_selector_matchlabels():
    out = kubernetesmod.__dict_to_network_policy_spec(
        {"podSelector": {"matchLabels": {"app": "api"}}, "policyTypes": ["Ingress"]}
    )
    assert out["pod_selector"].match_labels == {"app": "api"}


def test_network_policy_spec_requires_pod_selector():
    with pytest.raises(CommandExecutionError, match="must include 'podSelector'"):
        kubernetesmod.__dict_to_network_policy_spec({"policyTypes": ["Ingress"]})


def test_network_policy_spec_policy_types_must_be_list():
    with pytest.raises(CommandExecutionError, match="policyTypes must be a list"):
        kubernetesmod.__dict_to_network_policy_spec({"podSelector": {}, "policyTypes": "Ingress"})


def test_network_policy_spec_rejects_non_dict():
    with pytest.raises(CommandExecutionError, match="must be a dictionary"):
        kubernetesmod.__dict_to_network_policy_spec("not-a-dict")


def test_network_policy_spec_passes_ingress_egress_through():
    """The rule schema is large — we pass it through and let the API server
    validate. Just check the helper doesn't strip or mangle these keys."""
    spec = {
        "podSelector": {"matchLabels": {"app": "api"}},
        "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "web"}}}]}],
        "egress": [{"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}],
        "policyTypes": ["Ingress", "Egress"],
    }
    out = kubernetesmod.__dict_to_network_policy_spec(spec)
    assert out["ingress"] == spec["ingress"]
    assert out["egress"] == spec["egress"]


# ---------------------------------------------------------------------------
# ResourceQuota spec
# ---------------------------------------------------------------------------


def test_resource_quota_spec_hard_must_be_dict():
    with pytest.raises(CommandExecutionError, match="'hard' must be a dictionary"):
        kubernetesmod.__dict_to_resource_quota_spec({"hard": "10"})


def test_resource_quota_spec_scopes_must_be_list():
    with pytest.raises(CommandExecutionError, match="'scopes' must be a list"):
        kubernetesmod.__dict_to_resource_quota_spec({"scopes": "BestEffort"})


def test_resource_quota_spec_camelcase_scope_selector():
    out = kubernetesmod.__dict_to_resource_quota_spec(
        {
            "hard": {"pods": "10"},
            "scopeSelector": {"matchExpressions": [{"operator": "Exists"}]},
        }
    )
    # Top-level scopeSelector key normalised; nested dict left alone (it's
    # passed into V1ScopeSelector unchanged at request time).
    assert "scope_selector" in out
    assert "scopeSelector" not in out


def test_resource_quota_spec_rejects_non_dict():
    with pytest.raises(CommandExecutionError, match="must be a dictionary"):
        kubernetesmod.__dict_to_resource_quota_spec("not-a-dict")


# ---------------------------------------------------------------------------
# LimitRange spec
# ---------------------------------------------------------------------------


def test_limit_range_spec_builds_v1_limit_range_items():
    out = kubernetesmod.__dict_to_limit_range_spec(
        {
            "limits": [
                {
                    "type": "Container",
                    "default": {"memory": "256Mi"},
                    "defaultRequest": {"memory": "128Mi"},
                }
            ]
        }
    )
    assert len(out["limits"]) == 1
    item = out["limits"][0]
    assert isinstance(item, kubernetes.client.V1LimitRangeItem)
    assert item.type == "Container"
    assert item.default == {"memory": "256Mi"}
    # camelCase defaultRequest translated to snake_case default_request.
    assert item.default_request == {"memory": "128Mi"}


def test_limit_range_spec_requires_non_empty_limits():
    with pytest.raises(CommandExecutionError, match="non-empty 'limits' list"):
        kubernetesmod.__dict_to_limit_range_spec({"limits": []})


def test_limit_range_spec_limits_must_be_list():
    with pytest.raises(CommandExecutionError, match="non-empty 'limits' list"):
        kubernetesmod.__dict_to_limit_range_spec({"limits": "not-a-list"})


def test_limit_range_spec_each_entry_must_be_dict():
    with pytest.raises(CommandExecutionError, match="must be a dictionary"):
        kubernetesmod.__dict_to_limit_range_spec({"limits": ["not-a-dict"]})


def test_limit_range_spec_max_limit_request_ratio_translated():
    out = kubernetesmod.__dict_to_limit_range_spec(
        {"limits": [{"type": "Container", "maxLimitRequestRatio": {"memory": "2"}}]}
    )
    assert out["limits"][0].max_limit_request_ratio == {"memory": "2"}


# ---------------------------------------------------------------------------
# PriorityClass kwargs
# ---------------------------------------------------------------------------


def test_priority_class_kwargs_requires_value():
    with pytest.raises(CommandExecutionError, match="must include 'value'"):
        kubernetesmod.__dict_to_priority_class_kwargs({"description": "x"})


def test_priority_class_kwargs_camelcase_translation():
    out = kubernetesmod.__dict_to_priority_class_kwargs(
        {
            "value": 1000,
            "globalDefault": True,
            "preemptionPolicy": "Never",
            "description": "test",
        }
    )
    assert out["value"] == 1000
    assert out["global_default"] is True
    assert out["preemption_policy"] == "Never"
    assert out["description"] == "test"


def test_priority_class_kwargs_rejects_non_dict():
    with pytest.raises(CommandExecutionError, match="must be a dictionary"):
        kubernetesmod.__dict_to_priority_class_kwargs(1000)


# ---------------------------------------------------------------------------
# CRD spec
# ---------------------------------------------------------------------------


def _minimal_crd_spec(**overrides):
    spec = {
        "group": "example.io",
        "scope": "Namespaced",
        "names": {
            "plural": "widgets",
            "singular": "widget",
            "kind": "Widget",
        },
        "versions": [
            {
                "name": "v1",
                "served": True,
                "storage": True,
                "schema": {"openAPIV3Schema": {"type": "object"}},
            }
        ],
    }
    spec.update(overrides)
    return spec


def test_crd_spec_builds_typed_names_and_versions():
    out = kubernetesmod.__dict_to_crd_spec(_minimal_crd_spec())
    assert out["group"] == "example.io"
    assert out["scope"] == "Namespaced"
    assert isinstance(out["names"], kubernetes.client.V1CustomResourceDefinitionNames)
    assert out["names"].plural == "widgets"
    assert out["names"].kind == "Widget"
    assert isinstance(out["versions"], list)
    assert isinstance(out["versions"][0], kubernetes.client.V1CustomResourceDefinitionVersion)
    assert out["versions"][0].name == "v1"
    assert out["versions"][0].served is True


def test_crd_spec_camelcase_in_names_translated():
    """``shortNames`` and ``listKind`` are camelCase in YAML."""
    spec = _minimal_crd_spec()
    spec["names"]["shortNames"] = ["wg"]
    spec["names"]["listKind"] = "WidgetList"
    out = kubernetesmod.__dict_to_crd_spec(spec)
    assert out["names"].short_names == ["wg"]
    assert out["names"].list_kind == "WidgetList"


def test_crd_spec_requires_group():
    spec = _minimal_crd_spec()
    del spec["group"]
    with pytest.raises(CommandExecutionError, match="must include 'group'"):
        kubernetesmod.__dict_to_crd_spec(spec)


def test_crd_spec_requires_names():
    spec = _minimal_crd_spec()
    del spec["names"]
    with pytest.raises(CommandExecutionError, match="must include 'names'"):
        kubernetesmod.__dict_to_crd_spec(spec)


def test_crd_spec_requires_versions():
    spec = _minimal_crd_spec()
    del spec["versions"]
    with pytest.raises(CommandExecutionError, match="must include 'versions'"):
        kubernetesmod.__dict_to_crd_spec(spec)


def test_crd_spec_requires_scope():
    spec = _minimal_crd_spec()
    del spec["scope"]
    with pytest.raises(CommandExecutionError, match="must include 'scope'"):
        kubernetesmod.__dict_to_crd_spec(spec)


def test_crd_spec_versions_must_be_non_empty_list():
    spec = _minimal_crd_spec()
    spec["versions"] = []
    with pytest.raises(CommandExecutionError, match="versions must be a non-empty list"):
        kubernetesmod.__dict_to_crd_spec(spec)


def test_crd_spec_each_version_must_be_dict():
    spec = _minimal_crd_spec()
    spec["versions"] = ["not-a-dict"]
    with pytest.raises(CommandExecutionError, match="must be a dictionary"):
        kubernetesmod.__dict_to_crd_spec(spec)


def test_crd_spec_names_must_be_dict():
    spec = _minimal_crd_spec()
    spec["names"] = "widgets"
    with pytest.raises(CommandExecutionError, match="names must be a dictionary"):
        kubernetesmod.__dict_to_crd_spec(spec)
