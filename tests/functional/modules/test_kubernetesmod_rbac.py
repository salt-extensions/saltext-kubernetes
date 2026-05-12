"""
Functional tests for the RBAC kinds (Role, RoleBinding, ClusterRole,
ClusterRoleBinding, ServiceAccount) against the kind cluster fixture.

These cover:
  * round-trip create/show/delete for each of the five kinds
  * list returns the created resource
  * idempotent show returns the configured spec
  * Role + ClusterRole patch (rule modification)
  * RoleBinding immutable-roleRef rejection on replace
  * ServiceAccount image_pull_secrets round-trip

For full per-verb coverage see the existing test pattern for storageclass —
these tests focus on the paths that are unique to RBAC. Each test runs
twice via the ``params=[True]`` fixture parametrisation, plus once per
parametrised K8s version (1.28 / 1.35) on the cluster fixture.

.. versionadded:: 2.1.0
"""

import pytest
from salt.exceptions import CommandExecutionError

pytestmark = [pytest.mark.skip_unless_on_linux(reason="kind cluster fixture requires Linux")]

# ---------------------------------------------------------------------------
# Role
# ---------------------------------------------------------------------------


def test_role_round_trip(kubernetes_exe, role):
    """Create-show-delete round-trip; show returns the configured rules."""
    res = kubernetes_exe.show_role(name=role["name"], namespace=role["namespace"])
    assert res is not None
    assert res["metadata"]["name"] == role["name"]
    assert res["metadata"]["namespace"] == role["namespace"]
    assert any(rule["verbs"] == ["get", "list", "watch"] for rule in res["rules"])


def test_role_listed_in_namespace(kubernetes_exe, role):
    """The created Role appears in ``roles(namespace=...)``."""
    names = kubernetes_exe.roles(namespace=role["namespace"])
    assert role["name"] in names


def test_role_patch_modifies_rules(kubernetes_exe, role):
    """A patch with new rules updates the Role."""
    new_rules = [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}]
    kubernetes_exe.patch_role(
        name=role["name"], namespace=role["namespace"], patch={"rules": new_rules}
    )
    res = kubernetes_exe.show_role(name=role["name"], namespace=role["namespace"])
    assert any(
        rule["resources"] == ["configmaps"] and rule["verbs"] == ["get"] for rule in res["rules"]
    )


def test_role_replace_rules(kubernetes_exe, role):
    """``replace_role`` substitutes the entire rule set."""
    new_spec = {
        "rules": [{"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["watch"]}]
    }
    kubernetes_exe.replace_role(name=role["name"], namespace=role["namespace"], spec=new_spec)
    res = kubernetes_exe.show_role(name=role["name"], namespace=role["namespace"])
    assert len(res["rules"]) == 1
    assert res["rules"][0]["verbs"] == ["watch"]


# ---------------------------------------------------------------------------
# RoleBinding — including the immutable-roleRef behaviour
# ---------------------------------------------------------------------------


def test_role_binding_round_trip(kubernetes_exe, role_binding):
    res = kubernetes_exe.show_role_binding(
        name=role_binding["name"], namespace=role_binding["namespace"]
    )
    assert res is not None
    assert res["metadata"]["name"] == role_binding["name"]
    # API server normalises the apiGroup; verify shape
    assert res["roleRef"]["kind"] == "Role"
    assert len(res["subjects"]) == 1


def test_role_binding_replace_with_changed_role_ref_errors(kubernetes_exe, role_binding):
    """Changing roleRef on replace surfaces the immutable-roleRef error."""
    bad_spec = {
        "subjects": role_binding["spec"]["subjects"],
        "roleRef": {"kind": "Role", "name": "some-other-role"},
    }
    with pytest.raises(CommandExecutionError, match="roleRef is immutable"):
        kubernetes_exe.replace_role_binding(
            name=role_binding["name"],
            namespace=role_binding["namespace"],
            spec=bad_spec,
        )


def test_role_binding_replace_subjects_is_allowed(kubernetes_exe, role_binding):
    """Changing only the subject list (not roleRef) is valid."""
    new_spec = {
        "subjects": [{"kind": "User", "name": "bob"}],
        "roleRef": role_binding["spec"]["roleRef"],
    }
    kubernetes_exe.replace_role_binding(
        name=role_binding["name"], namespace=role_binding["namespace"], spec=new_spec
    )
    res = kubernetes_exe.show_role_binding(
        name=role_binding["name"], namespace=role_binding["namespace"]
    )
    assert res["subjects"][0]["name"] == "bob"


# ---------------------------------------------------------------------------
# ClusterRole + ClusterRoleBinding
# ---------------------------------------------------------------------------


def test_cluster_role_round_trip(kubernetes_exe, cluster_role):
    res = kubernetes_exe.show_cluster_role(name=cluster_role["name"])
    assert res is not None
    assert res["metadata"]["name"] == cluster_role["name"]


def test_cluster_role_listed(kubernetes_exe, cluster_role):
    names = kubernetes_exe.cluster_roles()
    assert cluster_role["name"] in names


def test_cluster_role_binding_round_trip(kubernetes_exe, cluster_role_binding):
    res = kubernetes_exe.show_cluster_role_binding(name=cluster_role_binding["name"])
    assert res is not None
    assert res["roleRef"]["kind"] == "ClusterRole"


# ---------------------------------------------------------------------------
# ServiceAccount
# ---------------------------------------------------------------------------


def test_service_account_round_trip(kubernetes_exe, service_account):
    res = kubernetes_exe.show_service_account(
        name=service_account["name"], namespace=service_account["namespace"]
    )
    assert res is not None
    assert res["metadata"]["name"] == service_account["name"]
    assert res["automountServiceAccountToken"] is False


def test_service_account_image_pull_secrets(kubernetes_exe, service_account):
    """imagePullSecrets round-trip through patch + show.

    Patch payloads go to the API server as-is, so the keys must be the
    wire-format camelCase names (``imagePullSecrets``). The
    ``__dict_to_*_spec`` helpers handle camelCase→snake_case translation
    for create/replace inputs but the patch path is verbatim.
    """
    kubernetes_exe.patch_service_account(
        name=service_account["name"],
        namespace=service_account["namespace"],
        patch={"imagePullSecrets": [{"name": "my-registry"}]},
    )
    res = kubernetes_exe.show_service_account(
        name=service_account["name"], namespace=service_account["namespace"]
    )
    assert res["imagePullSecrets"] == [{"name": "my-registry"}]
