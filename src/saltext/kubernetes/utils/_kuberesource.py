"""
Shared helpers for the ``kuberesource_*`` companion execution modules.

Each ``kuberesource_*`` module is a thin wrapper that pulls resource
identity from ``__resource__["id"]`` (set by Salt's resources-layer
dispatcher) and forwards to the existing ``kubernetes.*`` execution
module functions. The shared logic lives here so each companion
module stays small and predictable.

.. versionadded:: 2.1.0
"""

# pylint: disable=undefined-variable

from __future__ import annotations

import logging

from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)


def virtual_or_dormant():
    """
    Shared ``__virtual__`` for kuberesource companion modules.

    Returns ``"kubernetes"`` when Salt's resources subsystem is
    loadable, the (False, reason) sentinel otherwise. Identical
    contract to ``saltext.kubernetes.resources.kubernetes.__virtual__``.
    """
    try:
        # The import IS the probe — the symbol is intentionally unused.
        # pylint: disable=import-outside-toplevel,unused-import,import-error
        import salt.utils.resources  # noqa: F401
    except ImportError:
        return (
            False,
            "kuberesource_* companion modules require the Salt 'resources' "
            "subsystem (not yet merged to mainline as of saltext-kubernetes 2.1.0).",
        )
    return "kubernetes"


def resource_identity(resource_dunder):
    """
    Parse the active resource's identity from ``__resource__["id"]``.

    Schema (mirrors ``saltext.kubernetes.resources.kubernetes._make_id``):

      Cluster-scoped: ``<kind>:<name>`` -> (kind, None, name)
      Namespaced:     ``<kind>:<namespace>/<name>`` -> (kind, namespace, name)

    Raises :py:class:`CommandExecutionError` if the dunder is missing
    or malformed — should never happen if the dispatcher is wired
    correctly, but a clear error beats a NameError when it does.
    """
    if not resource_dunder or "id" not in resource_dunder:
        raise CommandExecutionError(
            "kuberesource module called outside a resource dispatch context "
            "(no __resource__['id'] available)."
        )
    rid = resource_dunder["id"]
    if ":" not in rid:
        raise CommandExecutionError(
            f"Resource ID {rid!r} missing ':' kind separator; "
            "expected form '<kind>:<name>' or '<kind>:<namespace>/<name>'."
        )
    kind, rest = rid.split(":", 1)
    if "/" in rest:
        namespace, name = rest.split("/", 1)
        return kind, namespace, name
    return kind, None, rest


def require_kind(actual_kind, *expected_kinds):
    """
    Reject a dispatch when the resource's kind doesn't match any expected.

    Companion modules like ``kuberesource_cmd`` (Pod-only),
    ``kuberesource_node`` (Node-only), ``kuberesource_workload``
    (workload kinds) need to refuse dispatches against the wrong
    kind early with a clear error.
    """
    if actual_kind not in expected_kinds:
        raise CommandExecutionError(
            f"This operation is not valid for resource kind {actual_kind!r}; "
            f"expected one of: {', '.join(expected_kinds)}."
        )
