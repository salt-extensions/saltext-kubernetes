"""Salt states for public Helm repository configuration."""

from salt.exceptions import CommandExecutionError


def _result(name):
    return {"name": name, "result": False, "changes": {}, "comment": ""}


def present(name, url, force_update=False, **kwargs):
    """Ensure a Helm repository exists at the requested URL.

    Password-authenticated repositories must be configured outside this state
    so credentials do not appear in process arguments or state output.

    ``name`` is the local repository name and ``url`` its chart index URL.
    ``force_update`` replaces an entry already configured at a different URL.
    Test mode reports the URL change without modifying Helm configuration.
    """
    ret = _result(name)
    try:
        entries = __salt__["helm.repository_list"](**kwargs)
        current = next((entry for entry in entries if entry.get("name") == name), None)
        if current and current.get("url") == url:
            ret.update(result=True, comment="Helm repository is already configured")
            return ret
        if __opts__.get("test", False):
            ret.update(
                result=None,
                changes={name: {"old": current.get("url") if current else None, "new": url}},
                comment="Helm repository would be added or updated",
            )
            return ret
        __salt__["helm.repository_present"](name=name, url=url, force_update=force_update, **kwargs)
    except CommandExecutionError as exc:
        ret["comment"] = str(exc)
        return ret
    ret.update(
        result=True,
        changes={name: {"old": current.get("url") if current else None, "new": url}},
        comment="Helm repository is configured",
    )
    return ret


def absent(name, **kwargs):
    """Ensure a Helm repository is removed.

    ``name`` selects the local repository entry. Test mode reports removal
    without changing Helm configuration; an already absent entry succeeds
    without changes. This does not uninstall releases that use the repo.
    """
    ret = _result(name)
    try:
        entries = __salt__["helm.repository_list"](**kwargs)
        current = next((entry for entry in entries if entry.get("name") == name), None)
        if current is None:
            ret.update(result=True, comment="Helm repository is already absent")
            return ret
        if __opts__.get("test", False):
            ret.update(
                result=None,
                changes={name: {"old": current.get("url"), "new": None}},
                comment="Helm repository would be removed",
            )
            return ret
        __salt__["helm.repository_absent"](name=name, **kwargs)
    except CommandExecutionError as exc:
        ret["comment"] = str(exc)
        return ret
    ret.update(
        result=True,
        changes={name: {"old": current.get("url"), "new": None}},
        comment="Helm repository is removed",
    )
    return ret
