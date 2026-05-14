"""
Kubernetes resource type for Salt's resources subsystem.

.. versionadded:: 2.1.0

This module is the Kubernetes-side companion to the in-flight Salt
``resources`` feature (still on a feature branch as of this writing;
the upstream PR has not yet been opened). When that
branch lands, every minion declaring a ``kubernetes`` resources block
in its pillar will publish each cluster's pods, deployments, nodes,
etc. up to the master's resource registry, where they become
first-class targets:

.. code-block:: bash

    # Target every Pod with label app=nginx, across all clusters every
    # minion in the fleet manages:
    salt -G 'app:nginx' kubernetes.show_pod

    # Drain a node by bare resource ID:
    salt 'node:gke-prod-pool-1-abc' kubernetes.drain

The plugin is intentionally **dormant** on stock Salt: its
``__virtual__`` returns ``False`` unless ``salt.loader.resource`` is a
callable, which is only true on a Salt build that includes the
resources subsystem. On stock Salt the module is a no-op — present
on the loader path, but never loaded.

Pillar shape:

.. code-block:: yaml

    resources:
      kubernetes:
        # By default discovers from whatever ``_setup_conn`` resolves —
        # the same auth path the typed kubernetes execution module uses.
        # Multi-cluster discovery is a future enhancement; for the v1
        # plug-in we discover from the active default Configuration.
        kinds:
          - pod
          - deployment
          - node
          - namespace
        namespaces: ["default", "production"]   # optional scope
        label_selector: "managed-by=salt"       # optional filter

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
# Conservative — workload controllers and cluster-scoped infrastructure,
# NOT individual Pods (too many, too short-lived) by default. Users opt
# in to Pod discovery via pillar ``kinds: [..., pod]``.
_DEFAULT_KINDS = ("deployment", "stateful_set", "daemon_set", "node", "namespace")


def __virtual__():
    """
    Available only when Salt's resources subsystem is loadable.

    On stock Salt the loader has no ``salt.loader.resource`` (or the
    ``salt.utils.resources`` helper); on a build that ships the
    resources branch, both are present. We probe ``salt.utils.resources``
    rather than ``salt.loader.resource`` because the loader function is
    a Python callable that may be present in unrelated forks; the
    utils module is more uniquely diagnostic.
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
            "saltext.kubernetes resource plugin requires the Salt "
            "'resources' subsystem (not yet merged to mainline as of "
            "saltext-kubernetes 2.1.0).",
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

    __context__["kubernetes_resource"] = {
        "initialized": True,
        "kinds": kinds,
        "namespaces": namespaces,
        "label_selector": label_selector,
        "config": config,
    }
    log.debug(
        "kubernetes resource init(): kinds=%s namespaces=%s label_selector=%s",
        kinds,
        namespaces,
        label_selector,
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


def discover(opts):  # pylint: disable=unused-argument
    """
    Return the list of bare Kubernetes resource IDs this minion manages.

    Reads the kinds + namespace filters configured in pillar (set up by
    :py:func:`init`), connects via the same auth path the typed
    kubernetes module uses, and lists every matching resource. The
    return value is a flat list of bare IDs (not SRNs); the resource
    subsystem prefixes ``kubernetes:`` automatically.
    """
    if not initialized():
        log.debug("kubernetes resource.discover() called before init(); returning []")
        return []

    cfg_ctx = __context__["kubernetes_resource"]
    kinds = cfg_ctx["kinds"]
    namespaces = cfg_ctx["namespaces"]
    label_selector = cfg_ctx["label_selector"]

    # The resource layer is loaded by the same minion that has the
    # kubernetes execution module on its loader path; reuse that
    # module's auth seam.
    cfg = _connection._setup_conn(__salt__["config.option"])
    try:
        out = []
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
                    out.append(_make_id(kind, namespace, name))
        log.debug("kubernetes resource.discover() returning %d ids", len(out))
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
