"""
Per-resource file copy for Kubernetes pods.

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


def to_pod(src_path, dst_path, container=None):
    """
    Copy a local file or directory into the active Pod resource.

    Mirrors ``kubernetes.cp_to``.

    CLI Example:

    .. code-block:: bash

        salt '*' kuberesource_cp.to_pod
    """
    kind, namespace, name = resource_identity(__resource__)  # noqa: F821
    require_kind(kind, "pod")
    return __salt__["kubernetes.cp_to"](  # noqa: F821
        name=name,
        namespace=namespace or "default",
        src_path=src_path,
        dst_path=dst_path,
        container=container,
    )


def from_pod(src_path, dst_path, container=None):
    """
    Copy a file or directory out of the active Pod resource.

    Mirrors ``kubernetes.cp_from``.

    CLI Example:

    .. code-block:: bash

        salt '*' kuberesource_cp.from_pod
    """
    kind, namespace, name = resource_identity(__resource__)  # noqa: F821
    require_kind(kind, "pod")
    return __salt__["kubernetes.cp_from"](  # noqa: F821
        name=name,
        namespace=namespace or "default",
        src_path=src_path,
        dst_path=dst_path,
        container=container,
    )
