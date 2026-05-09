"""
Per-resource node lifecycle ops.

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


def cordon():
    """
    Cordon the active Node resource.

    CLI Example:

    .. code-block:: bash

        salt '*' kuberesource_node.cordon
    """
    kind, _, name = resource_identity(__resource__)  # noqa: F821
    require_kind(kind, "node")
    return __salt__["kubernetes.cordon"](name=name)  # noqa: F821


def uncordon():
    """
    Uncordon the active Node resource.

    CLI Example:

    .. code-block:: bash

        salt '*' kuberesource_node.uncordon
    """
    kind, _, name = resource_identity(__resource__)  # noqa: F821
    require_kind(kind, "node")
    return __salt__["kubernetes.uncordon"](name=name)  # noqa: F821


def drain(
    ignore_daemonsets=True,
    delete_emptydir_data=False,
    disable_eviction=False,
    force=False,
    grace_period_seconds=None,
    timeout=300,
):
    """
    Drain the active Node resource.

    CLI Example:

    .. code-block:: bash

        salt '*' kuberesource_node.drain
    """
    kind, _, name = resource_identity(__resource__)  # noqa: F821
    require_kind(kind, "node")
    return __salt__["kubernetes.drain"](  # noqa: F821
        name=name,
        ignore_daemonsets=ignore_daemonsets,
        delete_emptydir_data=delete_emptydir_data,
        disable_eviction=disable_eviction,
        force=force,
        grace_period_seconds=grace_period_seconds,
        timeout=timeout,
    )


def taint(key, effect, value=None):
    """
    Add (or replace) a taint on the active Node resource.

    CLI Example:

    .. code-block:: bash

        salt '*' kuberesource_node.taint
    """
    kind, _, name = resource_identity(__resource__)  # noqa: F821
    require_kind(kind, "node")
    return __salt__["kubernetes.taint"](  # noqa: F821
        name=name, key=key, effect=effect, value=value
    )


def untaint(key, effect=None):
    """
    Remove a taint from the active Node resource.

    CLI Example:

    .. code-block:: bash

        salt '*' kuberesource_node.untaint
    """
    kind, _, name = resource_identity(__resource__)  # noqa: F821
    require_kind(kind, "node")
    return __salt__["kubernetes.untaint"](name=name, key=key, effect=effect)  # noqa: F821
