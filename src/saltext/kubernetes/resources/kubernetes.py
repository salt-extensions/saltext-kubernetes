"""
Kubernetes resource type for Salt's resources subsystem.

.. versionadded:: 2.1.0

.. note::
    Requires **Salt 3008.0 or newer** — the resources subsystem
    (``salt.utils.resources`` / ``salt.utils.resource_registry``) is
    only present from 3008. On 3006 or 3007 this module's
    ``__virtual__`` returns ``False`` and the loader skips it.

This module is the Kubernetes-side companion to Salt's resources
subsystem. Every minion declaring a ``kubernetes`` resources block in
its pillar publishes each cluster's pods, deployments, nodes, etc. up
to the master's resource registry, where they become first-class
targets:

.. code-block:: bash

    # Target every Pod with label app=nginx, across all clusters every
    # minion in the fleet manages:
    salt -G 'app:nginx' kubernetes.show_pod

    # Drain a node by bare resource ID:
    salt 'node:gke-prod-pool-1-abc' kubernetes.drain

The plugin is intentionally **dormant on Salt versions earlier than
3008**: its ``__virtual__`` returns ``False`` unless
``salt.utils.resources`` is importable, which is only true on Salt
3008+. On older Salt the module is a no-op — present on the loader
path, but never loaded.

Pillar shape — discovery mode (filters apply, API enumerates):

.. code-block:: yaml

    resources:
      kubernetes:
        # discovery mode is selected when ``resources:`` is absent (or
        # ``mode: discover`` is set explicitly). The plug-in connects via
        # ``_setup_conn`` (same auth path the typed kubernetes execution
        # module uses) and lists every matching API object.
        mode: discover                          # optional; the default
        kinds:
          - pod
          - deployment
          - node
          - namespace
        namespaces: ["default", "production"]   # optional scope
        label_selector: "managed-by=salt"       # optional filter

Pillar shape — pillar-only mode (no API call):

.. code-block:: yaml

    resources:
      kubernetes:
        # When ``resources:`` is present the plug-in returns exactly the
        # objects listed there and skips API discovery. Useful for air-
        # gapped clusters, strict RBAC, bootstrap (declare resources
        # before they exist), or to avoid paying the discovery cost on
        # busy clusters. ``kinds:`` / ``namespaces:`` / ``label_selector:``
        # are ignored in this mode.
        mode: pillar                            # optional; inferred from ``resources:``
        resources:
          - {kind: deployment, namespace: prod, name: web}
          - {kind: deployment, namespace: prod, name: api}
          - {kind: namespace, name: prod}
          - {kind: node, name: gke-prod-pool-1-abc}

Pillar shape — merge mode (declared + discovered, union):

.. code-block:: yaml

    resources:
      kubernetes:
        mode: merge
        resources:
          - {kind: namespace, name: bootstrap-only}
        kinds: [deployment, namespace]
        namespaces: [prod]

When the resources subsystem is not loaded, importing this module is
a no-op — the public functions are defined but ``__virtual__``
returns ``(False, ...)`` so the loader never dispatches into them.
"""

# pylint: disable=undefined-variable

from __future__ import annotations

import logging

from salt.exceptions import CommandExecutionError

# pylint: disable=import-error,no-name-in-module
try:
    import kubernetes  # pylint: disable=import-self
    import kubernetes.client
    from kubernetes.client.rest import ApiException
    from urllib3.exceptions import HTTPError
except ImportError:
    kubernetes = None  # type: ignore[assignment]
    ApiException = Exception  # type: ignore[assignment,misc]
    HTTPError = Exception  # type: ignore[assignment,misc]
# pylint: enable=import-error,no-name-in-module

from saltext.kubernetes.utils import _connection
from saltext.kubernetes.utils import _kinds

log = logging.getLogger(__name__)


__virtualname__ = "kubernetes"


# Default kinds to discover when the user gives no explicit list.
# Every name must be a valid key in ``_kinds._KIND_REGISTRY`` — the
# resource subsystem skips unknown kinds with a warning, so a typo here
# silently disables discovery for that kind. Conservative — workload
# controllers and cluster-scoped infrastructure, NOT individual Pods
# (too many, too short-lived) by default. Users opt in to Pods (or
# anything else not listed) via pillar ``kinds: [..., pod]``.
_DEFAULT_KINDS = (
    "deployment",
    "statefulset",
    "daemonset",
    "replicaset",
    "node",
    "namespace",
    "service",
    "configmap",
    "secret",
    "persistent_volume",
    "persistent_volume_claim",
    "ingress",
    "network_policy",
    "resource_quota",
    "priority_class",
    "custom_resource_definition",
)


# Recognised values for the pillar ``mode:`` key. Inferred when the
# caller omits it: ``pillar`` if ``resources:`` is present, otherwise
# ``discover``.
_VALID_MODES = ("discover", "pillar", "merge")


def __virtual__():
    """
    Available only when Salt's resources subsystem is loadable.

    The resources subsystem ships in **Salt 3008.0** and newer; on
    earlier versions ``salt.utils.resources`` does not exist and the
    loader skips this module. We probe ``salt.utils.resources`` rather
    than ``salt.loader.resource`` because the loader function is a
    Python callable that may be present in unrelated forks; the utils
    module is more uniquely diagnostic of the resources feature.
    """
    try:
        # Imported lazily so the import cost is only paid when the
        # subsystem actually exists. The 'noqa' / 'pylint: disable'
        # marks the dormant-gate intent: the import is the probe, the
        # symbol is intentionally unused.
        # pylint: disable=import-outside-toplevel,unused-import,import-error
        import salt.utils.resources  # noqa: F401
    except ImportError:
        return (
            False,
            "saltext.kubernetes resource plugin requires Salt 3008.0 or "
            "newer (the 'resources' subsystem under salt.utils.resources "
            "is not available on this Salt build).",
        )
    return __virtualname__


# ---------------------------------------------------------------------------
# Lifecycle: init / initialized / shutdown
# ---------------------------------------------------------------------------


def init(opts):
    """
    Initialise the Kubernetes resource type for this minion.

    Called once when the resource type is loaded, before any per-
    resource operations. Reads the ``kubernetes`` block from the
    pillar's resources tree and stashes it in
    ``__context__["kubernetes_resource"]``.
    """
    # pylint: disable=import-outside-toplevel,import-error,no-name-in-module
    import salt.utils.resources

    config = salt.utils.resources.pillar_resources_tree(opts).get("kubernetes", {}) or {}
    kinds = list(config.get("kinds") or _DEFAULT_KINDS)
    namespaces = config.get("namespaces") or []
    label_selector = config.get("label_selector") or None
    declared = config.get("resources") or []
    mode = (config.get("mode") or "").lower() or None
    if mode is None:
        # Infer: explicit ``resources:`` list → pillar-only; otherwise discover.
        mode = "pillar" if declared else "discover"
    if mode not in _VALID_MODES:
        raise CommandExecutionError(
            f"kubernetes resource pillar 'mode' must be one of {list(_VALID_MODES)}, "
            f"not {mode!r}"
        )
    if mode in ("pillar", "merge") and not isinstance(declared, list):
        raise CommandExecutionError(
            "kubernetes resource pillar 'resources' must be a list of "
            "{kind, namespace?, name} dicts"
        )

    __context__["kubernetes_resource"] = {
        "initialized": True,
        "mode": mode,
        "kinds": kinds,
        "namespaces": namespaces,
        "label_selector": label_selector,
        "declared": declared,
        "config": config,
    }
    log.debug(
        "kubernetes resource init(): mode=%s kinds=%s namespaces=%s "
        "label_selector=%s declared=%d entries",
        mode,
        kinds,
        namespaces,
        label_selector,
        len(declared),
    )


def initialized():
    """Return True if :py:func:`init` has run successfully for this type."""
    try:
        return __context__.get("kubernetes_resource", {}).get("initialized", False)  # noqa: F821
    except NameError:
        return False


def shutdown(opts):  # pylint: disable=unused-argument
    """Drop type-level context. Called when the resource type unloads."""
    try:
        __context__.pop("kubernetes_resource", None)
    except NameError:
        pass


# ---------------------------------------------------------------------------
# Discovery + grain projection
# ---------------------------------------------------------------------------


def _make_id(kind: str, namespace: str | None, name: str) -> str:
    """
    Compose a bare resource ID from a kind + (namespace) + name.

    Schema:

    * Cluster-scoped: ``<kind>:<name>`` — e.g. ``node:gke-prod-pool-1``
    * Namespaced:     ``<kind>:<namespace>/<name>`` — e.g. ``pod:default/nginx-abc``
    """
    if namespace:
        return f"{kind}:{namespace}/{name}"
    return f"{kind}:{name}"


def _parse_id(resource_id: str) -> tuple[str, str | None, str]:
    """Inverse of :py:func:`_make_id`. Returns ``(kind, namespace_or_None, name)``."""
    if ":" not in resource_id:
        raise ValueError(f"Resource ID {resource_id!r} missing ':' kind separator")
    kind, rest = resource_id.split(":", 1)
    if "/" in rest:
        namespace, name = rest.split("/", 1)
        return kind, namespace, name
    return kind, None, rest


def _ids_from_declared(declared):
    """Translate the pillar ``resources:`` list into bare IDs.

    Each entry is a ``{kind, namespace?, name}`` dict. ``kind`` and
    ``name`` are required; ``namespace`` is omitted for cluster-scoped
    kinds. Unknown kinds raise — the user spelt one wrong and silently
    dropping it would surface as a "resource not found" later.
    """
    out = []
    for i, entry in enumerate(declared):
        if not isinstance(entry, dict):
            raise CommandExecutionError(
                f"kubernetes resource pillar 'resources[{i}]' must be a dict, "
                f"not {type(entry).__name__}"
            )
        kind = entry.get("kind")
        name = entry.get("name")
        namespace = entry.get("namespace")
        if not kind or not name:
            raise CommandExecutionError(
                f"kubernetes resource pillar 'resources[{i}]' missing 'kind' or 'name'"
            )
        try:
            kind_ops = _kinds.get_kind(kind)
        except CommandExecutionError as exc:
            raise CommandExecutionError(
                f"kubernetes resource pillar 'resources[{i}]' has unknown kind {kind!r}: {exc}"
            ) from exc
        if kind_ops.namespaced and not namespace:
            raise CommandExecutionError(
                f"kubernetes resource pillar 'resources[{i}]' kind={kind!r} is "
                "namespaced and requires 'namespace'"
            )
        if not kind_ops.namespaced and namespace:
            log.warning(
                "kubernetes resource pillar 'resources[%d]' kind=%r is cluster-scoped; "
                "ignoring namespace=%r",
                i,
                kind,
                namespace,
            )
            namespace = None
        out.append(_make_id(kind, namespace, name))
    return out


def discover(opts):  # pylint: disable=unused-argument
    """
    Return the list of bare Kubernetes resource IDs this minion manages.

    Behaviour is controlled by the pillar ``mode`` key (or the inferred
    mode when omitted — see :py:func:`init`):

    * ``mode: discover`` — connect to the cluster and enumerate every
      object whose kind / namespace / label matches the configured
      filters. The historical default.
    * ``mode: pillar`` — return exactly the IDs derived from the pillar
      ``resources:`` list. **No API call is made.** Useful for air-
      gapped clusters, strict RBAC where the discovery user lacks
      ``list`` permission, bootstrap (declare resources before they
      exist), and to avoid discovery cost on busy clusters.
    * ``mode: merge`` — union of the two: declared IDs first, then
      discovered IDs not already in the declared set.

    The return value is a flat list of bare IDs (not SRNs); the
    resource subsystem prefixes ``kubernetes:`` automatically.
    """
    if not initialized():
        log.debug("kubernetes resource.discover() called before init(); returning []")
        return []

    cfg_ctx = __context__["kubernetes_resource"]
    kinds = cfg_ctx["kinds"]
    namespaces = cfg_ctx["namespaces"]
    label_selector = cfg_ctx["label_selector"]
    # ``mode`` / ``declared`` default to the discover-no-pillar-overrides
    # shape so test harnesses (and any older code paths that pre-date the
    # mode key) keep working without explicit init() context injection.
    mode = cfg_ctx.get("mode", "discover")
    declared = cfg_ctx.get("declared") or []

    declared_ids = _ids_from_declared(declared) if declared else []
    if mode == "pillar":
        log.debug(
            "kubernetes resource.discover() pillar-mode returning %d declared ids",
            len(declared_ids),
        )
        return declared_ids

    # The resource layer is loaded by the same minion that has the
    # kubernetes execution module on its loader path; reuse that
    # module's auth seam.
    cfg = _connection._setup_conn(__salt__["config.option"])
    try:
        out = list(declared_ids)  # 'merge' starts with declared IDs
        declared_set = set(declared_ids)
        for kind in kinds:
            try:
                kind_ops = _kinds.get_kind(kind)
            except CommandExecutionError as exc:  # registry must know each kind
                log.warning("kubernetes resource.discover skipping unknown kind %s: %s", kind, exc)
                continue
            list_ns = namespaces if (kind_ops.namespaced and namespaces) else [None]
            for ns in list_ns:
                api_class = getattr(kubernetes.client, kind_ops.api_class_attr)
                api_instance = api_class()
                if kind_ops.namespaced and ns:
                    items = getattr(api_instance, kind_ops.list_method)(
                        ns, **({"label_selector": label_selector} if label_selector else {})
                    )
                elif kind_ops.namespaced:
                    # No specific namespaces — list all via the *_for_all_namespaces
                    # variant if it exists; otherwise fall back to the namespaced
                    # list against "default" and let the user explicitly scope.
                    all_ns_method = (
                        kind_ops.list_method.replace("list_namespaced_", "list_")
                        + "_for_all_namespaces"
                    )
                    if hasattr(api_instance, all_ns_method):
                        items = getattr(api_instance, all_ns_method)(
                            **({"label_selector": label_selector} if label_selector else {})
                        )
                    else:  # pragma: no cover - all current namespaced kinds have the all-ns variant
                        log.warning(
                            "kubernetes resource.discover: kind %s has no list_*_for_all_namespaces; "
                            "specify namespaces in pillar to discover it",
                            kind,
                        )
                        continue
                else:
                    items = getattr(api_instance, kind_ops.list_method)(
                        **({"label_selector": label_selector} if label_selector else {})
                    )
                for obj in items.items or []:
                    name = obj.metadata.name
                    namespace = getattr(obj.metadata, "namespace", None)
                    rid = _make_id(kind, namespace, name)
                    if rid in declared_set:
                        # In 'merge' mode we already added the declared
                        # form; don't duplicate.
                        continue
                    out.append(rid)
        log.debug(
            "kubernetes resource.discover() mode=%s returning %d ids (%d declared, %d from API)",
            mode,
            len(out),
            len(declared_ids),
            len(out) - len(declared_ids),
        )
        return out
    finally:
        _connection._cleanup(**cfg)


def grains():
    """
    Return a grain dict for the resource currently in scope.

    Reads ``__resource__["id"]`` (set by the resource dispatch layer),
    re-fetches the live object, and projects:

    * ``kind``, ``namespace``, ``name`` — identity
    * ``label.<key>`` for each label
    * ``annotation.<key>`` for selected annotations
      (kubectl-prefixed annotations are excluded — they're noisy and
      change on every apply)
    """
    try:
        resource_id = __resource__["id"]
    except NameError:
        log.debug(
            "kubernetes resource.grains() called outside dispatch context; returning empty dict"
        )
        return {}

    kind, namespace, name = _parse_id(resource_id)

    cfg = _connection._setup_conn(__salt__["config.option"])
    try:
        try:
            kind_ops = _kinds.get_kind(kind)
        except CommandExecutionError as exc:
            log.warning("kubernetes resource.grains: unknown kind %s (%s)", kind, exc)
            return {"kind": kind, "namespace": namespace, "name": name}

        # Use the registry's API class to read the object directly. We
        # could go through the dynamic client here too, but the typed
        # path is faster and the resource type only knows about kinds
        # already in the registry.
        api_class = getattr(kubernetes.client, kind_ops.api_class_attr)
        api = api_class()
        try:
            if kind_ops.namespaced:
                obj = getattr(api, kind_ops.read_method)(name, namespace)
            else:
                obj = getattr(api, kind_ops.read_method)(name)
        except (ApiException, HTTPError) as exc:
            log.warning("kubernetes resource.grains read failed for %s: %s", resource_id, exc)
            return {"kind": kind, "namespace": namespace, "name": name}

        labels = (obj.metadata.labels or {}) if hasattr(obj.metadata, "labels") else {}
        annotations = (
            (obj.metadata.annotations or {}) if hasattr(obj.metadata, "annotations") else {}
        )
        # Drop kubectl's noisy bookkeeping annotations.
        annotations = {
            k: v
            for k, v in annotations.items()
            if not k.startswith("kubectl.kubernetes.io/")
            and not k.startswith("deployment.kubernetes.io/")
        }

        grain_dict = {
            "kind": kind,
            "namespace": namespace,
            "name": name,
            "label": dict(labels),
            "annotation": annotations,
        }
        # Include phase for kinds that have it (Pod, Namespace).
        status = getattr(obj, "status", None)
        if status is not None and getattr(status, "phase", None):
            grain_dict["phase"] = status.phase
        return grain_dict
    finally:
        _connection._cleanup(**cfg)


def grains_refresh():
    """Equivalent to :py:func:`grains` (no client-side caching today)."""
    return grains()
