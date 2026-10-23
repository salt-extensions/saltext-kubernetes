"""Read-only Helm release and plugin information functions."""

from saltext.kubernetes.modules import helm as _helm


def release(name, namespace="default", **kwargs):
    """Return release status and explicitly requested values or manifests.

        Values, manifests, hooks, and notes are opt-in because they may contain
        credentials or other sensitive data. See :func:`helm.release_get`.

        ``name`` and ``namespace`` identify the release. Optional keyword
        arguments select values, manifest, hooks, or notes and configure the Helm
        binary and Kubernetes context. Returns ``None`` when absent, otherwise a
        mapping containing status and only the requested payloads. Helm errors
        raise ``CommandExecutionError``.

    CLI Example:

        salt-call helm_info.release web namespace=default
    """
    return _helm.release_get(name=name, namespace=namespace, **kwargs)


def releases(namespace=None, all_namespaces=False, all_releases=False, **kwargs):
    """List Helm release records.

        ``namespace`` optionally limits results; ``all_namespaces`` includes all
        namespaces and ``all_releases`` includes non-deployed history. Returns a
        list of Helm JSON records.

    CLI Example:

        salt-call helm_info.releases namespace=default
    """
    return _helm.release_list(
        namespace=namespace,
        all_namespaces=all_namespaces,
        all_releases=all_releases,
        **kwargs,
    )


def plugins(name=None, **kwargs):
    """List installed Helm plugins.

        ``name`` optionally filters to one plugin. Returns records containing the
        plugin name, version, and description.

    CLI Example:

        salt-call helm_info.plugins
    """
    return _helm.plugin_list(name=name, **kwargs)
