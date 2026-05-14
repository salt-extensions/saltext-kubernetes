"""
Per-resource workload ops (scale / restart / rollback).

.. versionadded:: 2.1.0

Dormant on stock Salt — see ``saltext.kubernetes.resources.kubernetes``.
"""

# pylint: disable=undefined-variable

from saltext.kubernetes.utils._kuberesource import require_kind
from saltext.kubernetes.utils._kuberesource import resource_identity
from saltext.kubernetes.utils._kuberesource import virtual_or_dormant

__virtualname__ = "kubernetes"


_SCALABLE_KINDS = ("deployment", "stateful_set", "replica_set")
_RESTARTABLE_KINDS = ("deployment", "stateful_set", "replica_set", "daemon_set")


def __virtual__():
    return virtual_or_dormant()


def scale(replicas):
    """
    Set replicas on the active workload resource.

    CLI Example:

    .. code-block:: bash

        salt '*' kuberesource_workload.scale
    """
    kind, namespace, name = resource_identity(__resource__)  # noqa: F821
    require_kind(kind, *_SCALABLE_KINDS)
    return __salt__["kubernetes.scale"](  # noqa: F821
        kind=kind, name=name, replicas=replicas, namespace=namespace or "default"
    )


def restart():
    """
    Trigger a rolling restart on the active workload resource.

    CLI Example:

    .. code-block:: bash

        salt '*' kuberesource_workload.restart
    """
    kind, namespace, name = resource_identity(__resource__)  # noqa: F821
    require_kind(kind, *_RESTARTABLE_KINDS)
    return __salt__["kubernetes.restart"](  # noqa: F821
        kind=kind, name=name, namespace=namespace or "default"
    )


def rollback(to_revision=None):
    """
    Roll the active Deployment resource back to a previous revision.

    CLI Example:

    .. code-block:: bash

        salt '*' kuberesource_workload.rollback
    """
    kind, namespace, name = resource_identity(__resource__)  # noqa: F821
    require_kind(kind, "deployment")
    return __salt__["kubernetes.rollback"](  # noqa: F821
        name=name, namespace=namespace or "default", to_revision=to_revision
    )
