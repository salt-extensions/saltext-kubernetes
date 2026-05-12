"""
Internal dynamic-client wrapper for the saltext-kubernetes extension.

Wraps :py:class:`kubernetes.dynamic.DynamicClient` with the small
helpers the generic-apply / generic-patch / generic-read code paths
need:

* :py:func:`get_dynamic_client` — lazily-cached client per process,
  rebuilt when the auth Configuration changes (which happens whenever
  ``_setup_conn`` runs against a different kubeconfig/host).

* :py:func:`get_resource` — resolves a ``(api_version, kind)`` pair to
  a :py:class:`kubernetes.dynamic.Resource`, with a small in-process
  cache keyed by ``(group/version, kind)`` to avoid re-running API
  discovery on every call.

* :py:func:`apply_manifest` — performs a server-side apply against the
  resolved resource, surfacing the field-manager and force-conflicts
  knobs that ``kubectl apply --server-side`` exposes.

* :py:func:`patch_object` — generic kind-agnostic patch with selectable
  patch type (strategic / RFC 7396 merge / RFC 6902 json-patch).

* :py:func:`get_object`, :py:func:`delete_object`,
  :py:func:`list_resource` — generic read/delete/list-by-GVK
  counterparts to the typed CRUD wrappers in
  :py:mod:`saltext.kubernetes.modules.kubernetesmod`.

This module is **internal**. Public callers should never import from
here — every helper has a public counterpart in the ``kubernetes``
execution module (:py:mod:`saltext.kubernetes.modules.kubernetesmod`)
that adds the user-facing concerns these helpers deliberately omit:

* connection lifecycle (``_setup_conn`` / ``_cleanup`` around each call)
* kwarg marshalling from the Salt loader (kubeconfig, context, cluster
  alias, env-var precedence, etc.)
* kind-name inference from the typed kind-registry so callers can pass
  ``kind="Deployment"`` without spelling out ``api_version="apps/v1"``
* source-file rendering, multi-doc YAML, diff/idempotency tracking,
  ``test=True`` plumbing on the apply path

In short: this module's functions are **pure GVK plumbing**, and they
assume an already-installed default Configuration on
``kubernetes.client.Configuration``. The public ``kubernetes.*``
execution-module functions are the thin wrappers that bring those
preconditions about.

Public ↔ internal counterparts:

================================  ========================================
``kubernetes.apply``              :py:func:`apply_manifest`
``kubernetes.patch_object``       :py:func:`patch_object`
``kubernetes.get_object``         :py:func:`get_object`
``kubernetes.delete_manifest``    :py:func:`delete_object`
``kubernetes.list_*``             :py:func:`list_resource`
================================  ========================================

.. versionadded:: 2.1.0
"""

from __future__ import annotations

import logging
from typing import Any

from salt.exceptions import CommandExecutionError

# pylint: disable=import-error,no-name-in-module
try:
    import kubernetes  # pylint: disable=import-self
    import kubernetes.client
    from kubernetes import dynamic as k8s_dynamic
    from kubernetes.client import ApiClient
    from kubernetes.client.rest import ApiException
    from urllib3.exceptions import HTTPError

    HAS_LIBS = True
except ImportError:
    HAS_LIBS = False
# pylint: enable=import-error,no-name-in-module


log = logging.getLogger(__name__)


# Module-level caches:
#
# * ``_DYN_CLIENT`` is a single :py:class:`DynamicClient` keyed by the
#   identity of the active default ``Configuration``. We rebuild when
#   the user switches kubeconfig/host between calls.
#
# * ``_RESOURCE_CACHE`` maps ``(client_id, api_version, kind)`` to the
#   resolved :py:class:`Resource`, so repeated ``apply`` calls against
#   the same kind don't pay the API-discovery cost twice.
_DYN_CLIENT: dict[int, k8s_dynamic.DynamicClient] = {}
_RESOURCE_CACHE: dict[tuple, k8s_dynamic.Resource] = {}


def _active_config_id() -> int:
    """Identity of the currently-installed default Configuration."""
    return id(kubernetes.client.Configuration.get_default_copy())


def _api_client_with_default_config() -> ApiClient:
    """
    Build an :py:class:`ApiClient` that picks up the current default
    Configuration. We recreate per call rather than caching because the
    auth refactor in PR3 installs a new default Configuration each
    time ``_setup_conn`` runs.
    """
    return ApiClient(configuration=kubernetes.client.Configuration.get_default_copy())


def get_dynamic_client() -> k8s_dynamic.DynamicClient:
    """
    Return a cached DynamicClient bound to the active default
    Configuration. Building the discoverer is expensive (an API
    discovery round-trip), so we hold one per Configuration instance.
    """
    if not HAS_LIBS:
        raise CommandExecutionError("kubernetes Python client not installed")
    cfg_id = _active_config_id()
    if cfg_id not in _DYN_CLIENT:
        _DYN_CLIENT[cfg_id] = k8s_dynamic.DynamicClient(_api_client_with_default_config())
    return _DYN_CLIENT[cfg_id]


def get_resource(api_version: str, kind: str) -> k8s_dynamic.Resource:
    """
    Resolve ``(api_version, kind)`` to a Resource via API discovery.

    ``api_version`` may be either a bare core version (``"v1"``) or a
    group/version (``"apps/v1"``, ``"rbac.authorization.k8s.io/v1"``).

    Raises :py:class:`CommandExecutionError` with a clear message when
    the GVK isn't known to the cluster (e.g. CRD not installed,
    typo'd apiVersion, or the user's RBAC scope can't see the API).
    """
    dyn = get_dynamic_client()
    cache_key = (id(dyn), api_version, kind)
    cached = _RESOURCE_CACHE.get(cache_key)
    if cached is not None:
        return cached
    try:
        res = dyn.resources.get(api_version=api_version, kind=kind)
    except k8s_dynamic.exceptions.ResourceNotFoundError as exc:
        raise CommandExecutionError(
            f"Kubernetes API has no resource for apiVersion={api_version!r}, "
            f"kind={kind!r}. If this is a CRD, ensure it is installed first."
        ) from exc
    except (ApiException, HTTPError) as exc:
        raise CommandExecutionError(exc) from exc
    _RESOURCE_CACHE[cache_key] = res
    return res


def invalidate_caches() -> None:
    """
    Drop the dynamic-client and resource caches. Call after creating
    a CustomResourceDefinition in the same Salt run as the CR that
    uses it; otherwise the discoverer's snapshot won't include the
    new GVK.
    """
    _DYN_CLIENT.clear()
    _RESOURCE_CACHE.clear()


def _resolve_gvk_from_manifest(manifest: dict) -> tuple[str, str]:
    """Pull (apiVersion, kind) out of a manifest dict; surface clear errors."""
    if not isinstance(manifest, dict):
        raise CommandExecutionError(f"Manifest must be a dictionary, not {type(manifest).__name__}")
    api_version = manifest.get("apiVersion")
    kind = manifest.get("kind")
    if not api_version:
        raise CommandExecutionError("Manifest is missing 'apiVersion'")
    if not kind:
        raise CommandExecutionError("Manifest is missing 'kind'")
    return api_version, kind


def apply_manifest(
    manifest: dict,
    field_manager: str = "salt",
    force_conflicts: bool = False,
    dry_run: bool = False,
) -> dict:
    """
    Server-side apply *manifest* and return the applied object.

    *manifest* must include ``apiVersion``, ``kind`` and ``metadata.name``.
    Namespaced resources must include ``metadata.namespace`` (the typed
    CRUD paths default to ``"default"``; we deliberately do not, because
    silently scoping a manifest to ``default`` is a footgun).

    The HTTP request is a PATCH with
    ``Content-Type: application/apply-patch+yaml``, ``fieldManager``
    set to *field_manager*, and ``force=true`` when *force_conflicts*
    is set. ``dry_run=True`` adds ``dryRun=All`` so the API server
    validates the manifest and reports the resulting object without
    persisting changes.

    Raises :py:class:`CommandExecutionError` for both API-side errors
    (404, conflicts, validation rejections) and client-side issues
    (missing apiVersion/kind, bad GVK).
    """
    api_version, kind = _resolve_gvk_from_manifest(manifest)
    name = (manifest.get("metadata") or {}).get("name")
    if not name:
        raise CommandExecutionError("Manifest is missing 'metadata.name'")
    namespace = (manifest.get("metadata") or {}).get("namespace")

    resource = get_resource(api_version, kind)
    if resource.namespaced and not namespace:
        raise CommandExecutionError(
            f"Namespaced kind {kind} requires 'metadata.namespace'; "
            "the apply path does not silently default to 'default'."
        )

    apply_kwargs: dict[str, Any] = {
        "body": manifest,
        "name": name,
        "field_manager": field_manager,
    }
    if namespace:
        apply_kwargs["namespace"] = namespace
    if force_conflicts:
        apply_kwargs["force_conflicts"] = True
    if dry_run:
        # The dynamic client's server_side_apply forwards **kwargs as
        # query params; ``dryRun=All`` is the documented value.
        apply_kwargs["dry_run"] = "All"

    try:
        result = resource.server_side_apply(**apply_kwargs)
    except (ApiException, HTTPError) as exc:
        raise CommandExecutionError(exc) from exc

    # ``server_side_apply`` returns a ResourceInstance whose ``.to_dict()``
    # produces the same shape ``ApiClient().sanitize_for_serialization``
    # produces for the typed paths.
    if hasattr(result, "to_dict"):
        return result.to_dict()
    return ApiClient().sanitize_for_serialization(result)


def patch_object(
    api_version: str,
    kind: str,
    name: str,
    patch,
    namespace: str | None = None,
    patch_type: str = "strategic",
    field_manager: str | None = None,
    dry_run: bool = False,
) -> dict:
    """
    Patch an object by GVK with a caller-selected patch type.

    Internal plumbing for the public
    :py:func:`saltext.kubernetes.modules.kubernetesmod.patch_object`.
    That public function is the one users call from Salt; it handles
    connection setup, accepts the Salt-loader kwarg conventions, and
    can infer ``api_version`` from the typed kind-registry when the
    caller omits it. **This** function assumes both are already
    resolved — ``api_version`` and ``kind`` must be supplied, and a
    default :py:class:`kubernetes.client.Configuration` must already
    be installed (as :py:func:`_setup_conn` installs on every call).

    ``patch_type`` selects the HTTP ``Content-Type`` and, with it, the
    semantics of how ``patch`` is interpreted server-side:

      * ``"strategic"`` — ``application/strategic-merge-patch+json``
        (kubectl's default; works only on built-in kinds with
        registered strategic-merge directives).
      * ``"merge"`` / ``"json-merge"`` — ``application/merge-patch+json``
        (RFC 7396); whole-object replacement at each key. Works on
        CRDs and any kind.
      * ``"json"`` / ``"json-patch"`` — ``application/json-patch+json``
        (RFC 6902); ``patch`` must be a list of operation dicts like
        ``[{"op": "replace", "path": "/spec/replicas", "value": 5}]``.

    Returns the patched object as a dict (same shape as
    :py:func:`apply_manifest`).
    """
    content_types = {
        "strategic": "application/strategic-merge-patch+json",
        "merge": "application/merge-patch+json",
        "json-merge": "application/merge-patch+json",
        "json": "application/json-patch+json",
        "json-patch": "application/json-patch+json",
    }
    if patch_type not in content_types:
        raise CommandExecutionError(
            f"Unknown patch_type {patch_type!r}. " f"Accepted: {sorted(set(content_types))}"
        )
    if patch_type in ("json", "json-patch") and not isinstance(patch, list):
        raise CommandExecutionError(
            "json-patch requires a list of operation dicts "
            "(e.g. [{'op': 'replace', 'path': '/spec/replicas', 'value': 5}])"
        )

    resource = get_resource(api_version, kind)
    if resource.namespaced and not namespace:
        raise CommandExecutionError(f"Namespaced kind {kind} requires 'namespace'.")

    patch_kwargs: dict[str, Any] = {
        "name": name,
        "body": patch,
        "content_type": content_types[patch_type],
    }
    if namespace:
        patch_kwargs["namespace"] = namespace
    if field_manager:
        patch_kwargs["field_manager"] = field_manager
    if dry_run:
        patch_kwargs["dry_run"] = "All"

    try:
        result = resource.patch(**patch_kwargs)
    except (ApiException, HTTPError) as exc:
        raise CommandExecutionError(exc) from exc

    if hasattr(result, "to_dict"):
        return result.to_dict()
    return ApiClient().sanitize_for_serialization(result)


def list_resource(
    api_version: str,
    kind: str,
    namespace: str | None = None,
    label_selector: str | None = None,
    field_selector: str | None = None,
) -> list[dict]:
    """
    Generic list-by-GVK. Returns a list of object dicts.

    Used by the ``kubernetes.list_`` execution-module function (PR10).
    """
    resource = get_resource(api_version, kind)
    list_kwargs: dict[str, Any] = {}
    if namespace and resource.namespaced:
        list_kwargs["namespace"] = namespace
    if label_selector:
        list_kwargs["label_selector"] = label_selector
    if field_selector:
        list_kwargs["field_selector"] = field_selector
    try:
        result = resource.get(**list_kwargs)
    except (ApiException, HTTPError) as exc:
        raise CommandExecutionError(exc) from exc
    payload = result.to_dict() if hasattr(result, "to_dict") else result
    return payload.get("items", []) if isinstance(payload, dict) else []


def get_object(
    api_version: str,
    kind: str,
    name: str,
    namespace: str | None = None,
) -> dict | None:
    """
    Generic read-by-GVK. Returns ``None`` when the object doesn't exist
    (matching the existing typed ``show_*`` functions' behaviour).
    """
    resource = get_resource(api_version, kind)
    if resource.namespaced and not namespace:
        raise CommandExecutionError(f"Namespaced kind {kind} requires 'namespace'.")
    try:
        result = resource.get(name=name, namespace=namespace)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    return result.to_dict() if hasattr(result, "to_dict") else result


def delete_object(
    api_version: str,
    kind: str,
    name: str,
    namespace: str | None = None,
    propagation_policy: str | None = None,
    grace_period_seconds: int | None = None,
) -> dict | None:
    """
    Generic delete-by-GVK. Returns ``None`` if the object was already
    absent (404 swallowed); otherwise returns the API server's
    response body.
    """
    resource = get_resource(api_version, kind)
    if resource.namespaced and not namespace:
        raise CommandExecutionError(f"Namespaced kind {kind} requires 'namespace'.")
    delete_kwargs: dict[str, Any] = {"name": name}
    if namespace:
        delete_kwargs["namespace"] = namespace
    if propagation_policy is not None:
        delete_kwargs["propagation_policy"] = propagation_policy
    if grace_period_seconds is not None:
        delete_kwargs["grace_period_seconds"] = grace_period_seconds
    try:
        result = resource.delete(**delete_kwargs)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    return result.to_dict() if hasattr(result, "to_dict") else result
