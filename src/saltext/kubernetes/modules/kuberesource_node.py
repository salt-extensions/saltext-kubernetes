"""
Per-resource node lifecycle ops.

.. versionadded:: 2.1.0

Dormant on stock Salt — see ``saltext.kubernetes.resources.kubernetes``.
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

    key
        Taint key to remove.

    effect
        Optional effect filter. When ``None`` every taint matching the key
        is removed regardless of effect.

    CLI Example:

    .. code-block:: bash

        salt '*' kuberesource_node.untaint
    """
    kind, _, name = resource_identity(__resource__)  # noqa: F821
    require_kind(kind, "node")
    return __salt__["kubernetes.untaint"](name=name, key=key, effect=effect)  # noqa: F821


def annotations():
    """
    Return the annotations on the active Node resource.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kuberesource_node.annotations
    """
    kind, _, name = resource_identity(__resource__)  # noqa: F821
    require_kind(kind, "node")
    return __salt__["kubernetes.node_annotations"](name=name)  # noqa: F821


def add_annotation(annotation_name, annotation_value):
    """
    Set or update an annotation on the active Node resource.

    .. versionadded:: 2.1.0

    annotation_name
        Annotation key. May contain ``/`` to namespace the key.

    annotation_value
        Annotation value. Coerced to ``str`` by the underlying
        ``kubernetes.node_add_annotation`` call.

    CLI Example:

    .. code-block:: bash

        salt '*' kuberesource_node.add_annotation \
            annotation_name=example.com/owner annotation_value=ops
    """
    kind, _, name = resource_identity(__resource__)  # noqa: F821
    require_kind(kind, "node")
    return __salt__["kubernetes.node_add_annotation"](  # noqa: F821
        node_name=name,
        annotation_name=annotation_name,
        annotation_value=annotation_value,
    )


def remove_annotation(annotation_name):
    """
    Remove an annotation from the active Node resource.

    .. versionadded:: 2.1.0

    Removing an annotation that is not present is a no-op (no error
    raised).

    annotation_name
        Annotation key to remove.

    CLI Example:

    .. code-block:: bash

        salt '*' kuberesource_node.remove_annotation \
            annotation_name=example.com/owner
    """
    kind, _, name = resource_identity(__resource__)  # noqa: F821
    require_kind(kind, "node")
    return __salt__["kubernetes.node_remove_annotation"](  # noqa: F821
        node_name=name, annotation_name=annotation_name
    )
