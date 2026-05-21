"""
Unit tests for the kubernetes-client version-compat shims in
``saltext.kubernetes.modules.kubernetesmod``.

kubernetes-client 36.0.0 changed two surfaces we touch:

* ``V1PolicyRule.non_resource_ur_ls`` was renamed ``non_resource_urls``
  (acronym translation fixed in the OpenAPI generator).
* ``ApiClient.call_api(response_type=...)`` was renamed
  ``response_types_map=...`` (and re-shaped as a dict keyed by HTTP
  status).

These tests pin the contract of the compat helpers so they keep
working against the spelling the installed client actually exposes —
and so a future kubernetes-client release that changes either surface
again fails loudly here rather than at runtime in the field.
"""

from unittest.mock import MagicMock

from saltext.kubernetes.modules import kubernetesmod

# ---------------------------------------------------------------------------
# V1PolicyRule kwarg translation
# ---------------------------------------------------------------------------


def test_v1_policy_rule_kwargs_passes_through_when_match():
    """If the caller's spelling matches the installed client, nothing changes."""
    # Probe the installed client's openapi_types to know which spelling is
    # active locally; the helper should pass the matching name through.
    import kubernetes.client  # pylint: disable=import-outside-toplevel

    types_map = kubernetes.client.V1PolicyRule.openapi_types
    if "non_resource_urls" in types_map:
        active = "non_resource_urls"
    else:
        active = "non_resource_ur_ls"

    out = kubernetesmod._v1_policy_rule_kwargs({active: ["/healthz"], "verbs": ["get"]})
    assert out[active] == ["/healthz"]
    assert "verbs" in out


def test_v1_policy_rule_kwargs_translates_to_installed_spelling():
    """The opposite spelling is rewritten to whichever the client accepts.

    On kubernetes 36+ a caller-supplied ``non_resource_ur_ls`` is
    rewritten to ``non_resource_urls``; on kubernetes 24-35 the reverse
    happens. Either way, the returned dict's key is the one
    ``V1PolicyRule.__init__`` will accept.
    """
    import kubernetes.client  # pylint: disable=import-outside-toplevel

    types_map = kubernetes.client.V1PolicyRule.openapi_types
    if "non_resource_urls" in types_map:
        # New client: caller using legacy spelling gets rewritten.
        out = kubernetesmod._v1_policy_rule_kwargs({"non_resource_ur_ls": ["/x"]})
        assert "non_resource_urls" in out
        assert "non_resource_ur_ls" not in out
    else:
        # Old client: caller using new spelling gets rewritten.
        out = kubernetesmod._v1_policy_rule_kwargs({"non_resource_urls": ["/x"]})
        assert "non_resource_ur_ls" in out
        assert "non_resource_urls" not in out


def test_v1_policy_rule_kwargs_does_not_touch_other_keys():
    """The shim only renames the one acronym field; the rest passes through."""
    spec = {
        "api_groups": [""],
        "resources": ["pods"],
        "verbs": ["get", "list"],
        "resource_names": ["foo"],
    }
    out = kubernetesmod._v1_policy_rule_kwargs(spec)
    assert out == spec


def test_v1_policy_rule_round_trip_constructs_object():
    """The translated kwargs build a real V1PolicyRule against any installed client.

    This is the end-to-end pin: if the shim or the field map ever drift
    such that the resulting kwarg name doesn't match the installed
    client's constructor, V1PolicyRule(**...) raises and the test fails.
    """
    import kubernetes.client  # pylint: disable=import-outside-toplevel

    translated = kubernetesmod._v1_policy_rule_kwargs(
        {
            "api_groups": [""],
            "resources": ["pods"],
            "verbs": ["get"],
            "non_resource_urls": ["/healthz"],
        }
    )
    rule = kubernetes.client.V1PolicyRule(**translated)
    assert rule.verbs == ["get"]
    assert kubernetesmod._v1_policy_rule_non_resource_urls(rule) == ["/healthz"]


def test_v1_policy_rule_non_resource_urls_reader():
    """The reader returns the value regardless of which attribute the
    client exposes."""
    import kubernetes.client  # pylint: disable=import-outside-toplevel

    rule = kubernetes.client.V1PolicyRule(
        verbs=["get"],
        **kubernetesmod._v1_policy_rule_kwargs({"non_resource_urls": ["/a", "/b"]}),
    )
    assert kubernetesmod._v1_policy_rule_non_resource_urls(rule) == ["/a", "/b"]


# ---------------------------------------------------------------------------
# ApiClient.call_api kwarg shim
# ---------------------------------------------------------------------------


def test_call_api_uses_response_types_map_when_new_signature():
    """On kubernetes 36+, the shim translates ``response_type`` into the
    new ``response_types_map={"*": ...}`` form expected by
    ``ApiClient.call_api``."""
    fake = MagicMock()
    # Simulate the kubernetes-36 signature: only ``response_types_map``.
    import inspect  # pylint: disable=import-outside-toplevel

    def _new_call_api(self, resource_path, method, response_types_map=None, **_):
        del self, resource_path, method, _
        return response_types_map

    # Patch signature inspection by binding a real function.
    fake.call_api = lambda *args, **kwargs: _new_call_api(None, *args, **kwargs)
    fake.call_api.__signature__ = inspect.signature(_new_call_api)

    result = kubernetesmod._api_client_call_api(fake, "/healthz", "GET", response_type="str")
    assert result == {"*": "str"}


def test_call_api_uses_response_type_when_legacy_signature():
    """On kubernetes 24-35, the shim forwards ``response_type`` directly."""
    import inspect  # pylint: disable=import-outside-toplevel

    captured = {}

    def _legacy_call_api(self, resource_path, method, response_type=None, **_):
        del self, resource_path, method, _
        captured["response_type"] = response_type
        return response_type

    fake = MagicMock()
    fake.call_api = lambda *args, **kwargs: _legacy_call_api(None, *args, **kwargs)
    fake.call_api.__signature__ = inspect.signature(_legacy_call_api)

    result = kubernetesmod._api_client_call_api(fake, "/healthz", "GET", response_type="str")
    assert captured["response_type"] == "str"
    assert result == "str"


def test_call_api_passes_through_extra_kwargs():
    """The shim forwards arbitrary other kwargs unchanged."""
    import inspect  # pylint: disable=import-outside-toplevel

    captured = {}

    def _call_api(self, resource_path, method, **kwargs):
        del self, resource_path, method
        captured.update(kwargs)

    fake = MagicMock()
    fake.call_api = lambda *args, **kwargs: _call_api(None, *args, **kwargs)
    fake.call_api.__signature__ = inspect.signature(_call_api)

    kubernetesmod._api_client_call_api(
        fake,
        "/healthz",
        "GET",
        response_type="str",
        _preload_content=True,
        auth_settings=["BearerToken"],
    )
    assert captured["_preload_content"] is True
    assert captured["auth_settings"] == ["BearerToken"]


def test_call_api_no_response_type_kwarg_at_all():
    """When the caller doesn't pass ``response_type``, the shim doesn't inject one."""
    captured = {}

    def _call_api(self, resource_path, method, **kwargs):
        del self, resource_path, method
        captured.update(kwargs)

    fake = MagicMock()
    fake.call_api = lambda *args, **kwargs: _call_api(None, *args, **kwargs)

    kubernetesmod._api_client_call_api(fake, "/x", "GET")
    assert "response_type" not in captured
    assert "response_types_map" not in captured
