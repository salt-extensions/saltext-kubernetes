"""
Per-resource command execution for Kubernetes pods.

.. versionadded:: 2.1.0

This module is dispatched by Salt's resources subsystem when an
operation runs against a ``kubernetes`` resource. It pulls the pod
identity from ``__resource__`` and forwards to
``kubernetes.exec`` / ``kubernetes.logs``.

Dormant on stock Salt — see ``saltext.kubernetes.resources.kubernetes``.
"""

# pylint: disable=undefined-variable

from saltext.kubernetes.utils._kuberesource import require_kind
from saltext.kubernetes.utils._kuberesource import resource_identity
from saltext.kubernetes.utils._kuberesource import virtual_or_dormant

__virtualname__ = "kubernetes"


def __virtual__():
    return virtual_or_dormant()


def run(command, container=None, stdin=None, tty=False, timeout=60):
    """
    Run *command* inside the active Pod resource.

    Mirrors ``kubernetes.exec`` but the pod name + namespace are
    pulled from ``__resource__["id"]``.

    CLI Example:

    .. code-block:: bash

        salt '*' kuberesource_cmd.run
    """
    kind, namespace, name = resource_identity(__resource__)  # noqa: F821
    require_kind(kind, "pod")
    return __salt__["kubernetes.exec"](  # noqa: F821
        name=name,
        namespace=namespace or "default",
        command=command,
        container=container,
        stdin=stdin,
        tty=tty,
        timeout=timeout,
    )


def run_all(command, container=None, stdin=None, timeout=60):
    """
    Alias for :py:func:`run` matching Salt's ``cmd.run_all`` shape.

    CLI Example:

    .. code-block:: bash

        salt '*' kuberesource_cmd.run_all
    """
    return run(command, container=container, stdin=stdin, timeout=timeout)


def run_stdout(command, container=None, stdin=None, timeout=60):
    """
    Return only stdout from the exec, like ``cmd.run_stdout``.

    CLI Example:

    .. code-block:: bash

        salt '*' kuberesource_cmd.run_stdout
    """
    result = run(command, container=container, stdin=stdin, timeout=timeout)
    return result["stdout"]
