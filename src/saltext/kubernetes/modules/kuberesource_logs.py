"""
Per-resource log fetch for Kubernetes pods.

.. versionadded:: 2.1.0

Dormant on stock Salt — see ``saltext.kubernetes.resource.kubernetes``.
"""

# pylint: disable=undefined-variable

from saltext.kubernetes.utils._kuberesource import require_kind
from saltext.kubernetes.utils._kuberesource import resource_identity
from saltext.kubernetes.utils._kuberesource import virtual_or_dormant

__virtualname__ = "kubernetes"


def __virtual__():
    return virtual_or_dormant()


def fetch(
    container=None,
    previous=False,
    since_seconds=None,
    tail_lines=None,
    timestamps=False,
):
    """
    Fetch logs from the active Pod resource.

    Mirrors ``kubernetes.logs``; the pod identity comes from
    ``__resource__["id"]``.

    CLI Example:

    .. code-block:: bash

        salt '*' kuberesource_logs.fetch
    """
    kind, namespace, name = resource_identity(__resource__)  # noqa: F821
    require_kind(kind, "pod")
    return __salt__["kubernetes.logs"](  # noqa: F821
        name=name,
        namespace=namespace or "default",
        container=container,
        previous=previous,
        since_seconds=since_seconds,
        tail_lines=tail_lines,
        timestamps=timestamps,
    )


def tail(lines=50, container=None):
    """
    Convenience: last *lines* lines from the active pod.

    CLI Example:

    .. code-block:: bash

        salt '*' kuberesource_logs.tail
    """
    return fetch(container=container, tail_lines=lines)
