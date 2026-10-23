"""Kubernetes manifest state aliases for Salt SLS files."""

from saltext.kubernetes.states import kubernetes as _states


def _call_state(function, *args, **kwargs):
    """Pass this loader's runtime globals into the shared state module."""
    opts = globals().get("__opts__", {})
    for name in ("__salt__", "__opts__", "__pillar__", "__grains__"):
        if name in globals():
            setattr(_states, name, globals()[name])
    _states.__env__ = globals().get("__env__") or opts.get("saltenv", "base")
    return function(*args, **kwargs)


def present(name, manifest=None, source=None, namespace=None, **kwargs):
    """Ensure manifest resources are present with server-side apply.

    Uses the extension's generic state implementation. For its full semantics,
    see ``kubernetes.manifest_present``.

    Provide ``manifest`` inline or a ``source`` path, plus an optional fallback
    ``namespace``. Extra options include template rendering and field manager.
    Set ``wait: True`` to wait for registered readiness after reconciliation;
    use ``wait_condition`` with ``type`` and optional ``status`` to wait for a
    specific Kubernetes condition. ``wait_timeout`` defaults to 120 seconds.
    Test mode reports proposed changes without waiting or applying them. The
    state reports resource identifiers rather than manifest contents. Example::

        web:
          k8s.present:
            - source: salt://apps/web.yaml
            - wait: True
            - wait_condition:
                type: Available
                status: "True"
    """
    return _call_state(
        _states.manifest_present,
        name=name,
        manifest=manifest,
        source=source,
        namespace=namespace,
        **kwargs,
    )


def absent(name, manifest=None, source=None, namespace=None, **kwargs):
    """Ensure manifest resources are deleted.

    Provide inline ``manifest`` or ``source`` and optional fallback
    ``namespace``. Honors Salt test mode; see ``kubernetes.manifest_absent``
    for validation, multi-document behavior, and supported options.
    """
    return _call_state(
        _states.manifest_absent,
        name=name,
        manifest=manifest,
        source=source,
        namespace=namespace,
        **kwargs,
    )


def patched(name, manifest=None, source=None, namespace=None, **kwargs):
    """Patch existing resources; missing resources are skipped.

    Provide inline ``manifest`` or ``source`` and optional fallback
    ``namespace``. Extra options include ``patch_type`` (``strategic`` or
    ``merge``) and ``field_manager``. Honors Salt test mode with a Kubernetes
    dry-run. See ``kubernetes.manifest_patched`` for limitations.
    """
    return _call_state(
        _states.manifest_patched,
        name=name,
        manifest=manifest,
        source=source,
        namespace=namespace,
        **kwargs,
    )
