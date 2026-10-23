"""Salt states for Helm plugin lifecycle management."""

from salt.exceptions import CommandExecutionError


def _result(name):
    return {"name": name, "result": False, "changes": {}, "comment": ""}


def present(name, path, version=None, **kwargs):
    """Ensure a Helm plugin is installed from a local path or URL.

    ``name`` identifies the expected installed plugin; ``path`` selects its
    trusted source and ``version`` optionally pins the requested version.
    Test mode reports a pending installation. An already installed plugin is
    treated as present; version drift is not upgraded automatically.
    """
    ret = _result(name)
    try:
        plugins = __salt__["helm.plugin_list"](**kwargs)
        current = next((plugin for plugin in plugins if plugin.get("name") == name), None)
        if current:
            ret.update(result=True, comment="Helm plugin is already installed")
            return ret
        if __opts__.get("test", False):
            ret.update(
                result=None,
                changes={
                    name: {
                        "old": current.get("version") if current else None,
                        "new": version or "installed",
                    }
                },
                comment="Helm plugin would be installed or updated",
            )
            return ret
        __salt__["helm.plugin_present"](path=path, version=version, **kwargs)
    except CommandExecutionError as exc:
        ret["comment"] = str(exc)
        return ret
    ret.update(
        result=True,
        changes={
            name: {
                "old": current.get("version") if current else None,
                "new": version or "installed",
            }
        },
        comment="Helm plugin is installed",
    )
    return ret


def absent(name, **kwargs):
    """Ensure a Helm plugin is uninstalled.

    ``name`` is the installed plugin name. Test mode reports removal without
    invoking Helm; an absent plugin is an idempotent success.
    """
    ret = _result(name)
    try:
        current = next(
            (
                plugin
                for plugin in __salt__["helm.plugin_list"](**kwargs)
                if plugin.get("name") == name
            ),
            None,
        )
        if current is None:
            ret.update(result=True, comment="Helm plugin is already absent")
            return ret
        if __opts__.get("test", False):
            ret.update(
                result=None,
                changes={name: {"old": current.get("version"), "new": None}},
                comment="Helm plugin would be uninstalled",
            )
            return ret
        __salt__["helm.plugin_absent"](name=name, **kwargs)
    except CommandExecutionError as exc:
        ret["comment"] = str(exc)
        return ret
    ret.update(
        result=True,
        changes={name: {"old": current.get("version"), "new": None}},
        comment="Helm plugin is uninstalled",
    )
    return ret


def latest(name, **kwargs):
    """Update an installed Helm plugin to its latest available version.

    ``name`` must identify an installed plugin. Test mode reports the
    prospective update; execution invokes ``helm plugin update`` and always
    reports a change because the remote version is not queried in advance.
    """
    ret = _result(name)
    try:
        current = next(
            (
                plugin
                for plugin in __salt__["helm.plugin_list"](**kwargs)
                if plugin.get("name") == name
            ),
            None,
        )
        if current is None:
            ret["comment"] = f"Helm plugin {name!r} is not installed"
            return ret
        if __opts__.get("test", False):
            ret.update(
                result=None,
                changes={name: {"old": current.get("version"), "new": "latest"}},
                comment="Helm plugin would be updated",
            )
            return ret
        __salt__["helm.plugin_latest"](name=name, **kwargs)
    except CommandExecutionError as exc:
        ret["comment"] = str(exc)
        return ret
    ret.update(
        result=True,
        changes={name: {"old": current.get("version"), "new": "latest"}},
        comment="Helm plugin is updated",
    )
    return ret
