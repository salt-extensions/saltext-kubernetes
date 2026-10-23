"""Manage merged kubeconfig files without exposing their contents in changes."""

from salt.exceptions import CommandExecutionError


def managed(
    name,
    path,
    dest=None,
    clusters=None,
    users=None,
    contexts=None,
    preferences=None,
    current_context=None,
    mode="0600",
):
    """Ensure a kubeconfig contains the requested named entries.

    Test mode reports which entry names would change and never writes the
    kubeconfig. File contents, including tokens and certificate data, are not
    returned in state changes.

    ``path`` is the source config; ``dest`` optionally selects output. Supply
    named ``clusters``, ``users``, and ``contexts`` using merge/replace/keep/
    remove behavior, and optionally ``preferences`` or ``current_context``.
    The output is written atomically with ``mode`` (default ``0600``). Invalid
    YAML or entries produce a failed state. Example::

        dev-config:
          kubeconfig.managed:
            - path: /home/salt/.kube/config
            - contexts:
              - name: dev
                context: {cluster: dev, user: automation}
    """
    ret = {"name": name, "result": False, "changes": {}, "comment": ""}
    try:
        result = __salt__["kubeconfig.merge"](
            path=path,
            dest=dest,
            clusters=clusters,
            users=users,
            contexts=contexts,
            preferences=preferences,
            current_context=current_context,
            test=__opts__.get("test", False),
            mode=mode,
        )
    except CommandExecutionError as exc:
        ret["comment"] = str(exc)
        return ret
    if not result["changed"]:
        ret.update(result=True, comment="Kubeconfig is already up to date")
        return ret
    ret.update(
        result=None if __opts__.get("test", False) else True,
        changes={result["path"]: result["changes"] or {"created": True}},
        comment=(
            "Kubeconfig would be updated" if __opts__.get("test", False) else "Kubeconfig updated"
        ),
    )
    return ret
