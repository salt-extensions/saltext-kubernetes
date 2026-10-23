"""Render Helm charts without installing them."""

from saltext.kubernetes.modules import helm as _helm


def render(chart, name="release-name", namespace="default", **kwargs):
    """Render chart templates to stdout or a directory.

        ``values`` are supplied as a mapping and written to a temporary private
        file by the shared Helm execution module.

        ``chart`` may be a local chart path or repository reference; ``name`` and
        ``namespace`` set the rendered release identity. Keyword arguments pass
        chart version, values, selected templates, and output options to Helm.
        Returns a mapping with rendered ``stdout`` and ``stderr``. The Helm binary
        and any local chart files must be available on the executing minion.

    CLI Example:

        salt-call helm_template.render repo/web name=web
    """
    return _helm.template(chart=chart, name=name, namespace=namespace, **kwargs)
