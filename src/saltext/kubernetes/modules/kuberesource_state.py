"""
Per-resource state apply.

.. versionadded:: 2.1.0

Forwards a manifest through ``kubernetes.apply`` while leaving the
resource identity available to the manifest's Jinja templates via
``template_context`` (so a single manifest can be customised per
resource at dispatch time).

Dormant on stock Salt — see ``saltext.kubernetes.resources.kubernetes``.
"""

# pylint: disable=undefined-variable

from saltext.kubernetes.utils._kuberesource import resource_identity
from saltext.kubernetes.utils._kuberesource import virtual_or_dormant

__virtualname__ = "kubernetes"


def __virtual__():
    return virtual_or_dormant()


def apply_(
    source=None,
    manifest=None,
    namespace=None,
    field_manager="salt",
    force_conflicts=False,
    template=None,
    template_context=None,
):
    """
    Apply a manifest, with the active resource's identity exposed to
    the template context.

    The active resource's ``kind``, ``namespace`` and ``name`` are
    merged into *template_context* under the ``resource`` key, so
    Jinja-templated manifests can interpolate them:

    .. code-block:: yaml

        # salt://manifests/per-pod-cm.yaml
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: cm-{{ resource.name }}
          namespace: {{ resource.namespace }}
        data:
          owner: {{ resource.name }}

    CLI Example:

    .. code-block:: bash

        salt '*' kuberesource_state.apply_
    """
    kind, ns, name = resource_identity(__resource__)  # noqa: F821
    ctx = dict(template_context or {})
    ctx.setdefault("resource", {"kind": kind, "namespace": ns, "name": name})
    return __salt__["kubernetes.apply"](  # noqa: F821
        source=source,
        manifest=manifest,
        namespace=namespace or ns,
        field_manager=field_manager,
        force_conflicts=force_conflicts,
        template=template,
        template_context=ctx,
    )
