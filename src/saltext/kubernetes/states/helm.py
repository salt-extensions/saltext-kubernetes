"""Salt states for Helm release lifecycle management."""

import os

from salt.exceptions import CommandExecutionError


def _result(name):
    return {"name": name, "result": False, "changes": {}, "comment": ""}


def _values_match(name, namespace, values, **kwargs):
    current = __salt__["helm_info.release"](
        name=name, namespace=namespace, get_values=True, **kwargs
    )
    return (current or {}).get("values", {}) == values


def _up_to_date(
    status,
    chart,
    version,
    name,
    namespace,
    values,
    values_files,
    set_values,
    chart_info=None,
    **kwargs,
):
    if not status or not version:
        return False
    chart_id = str(status.get("chart", ""))
    if chart_info and chart_info.get("name"):
        chart_name = chart_info["name"]
    else:
        chart_name = os.path.basename(chart).removesuffix(".tgz").split(":", 1)[0]
        if chart_name.endswith(f"-{version}"):
            chart_name = chart_name[: -(len(version) + 1)]
    if not chart_id.endswith(f"{chart_name}-{version}"):
        return False
    if values_files or set_values:
        return False
    if values is not None and not _values_match(name, namespace, values, **kwargs):
        return False
    return str(status.get("info", {}).get("status", status.get("status", ""))).lower() in (
        "deployed",
        "superseded",
    )


def release_present(
    name,
    chart,
    namespace="default",
    version=None,
    values=None,
    values_files=None,
    set_values=None,
    repo_url=None,
    create_namespace=False,
    wait=False,
    atomic=False,
    force=False,
    dependency_update=False,
    update_repo_cache=False,
    history_max=None,
    reset_values=False,
    reuse_values=False,
    wait_for_jobs=False,
    skip_crds=False,
    cleanup_on_fail=False,
    skip_schema_validation=False,
    take_ownership=False,
    disable_hooks=False,
    post_renderer=None,
    post_renderer_args=None,
    reset_then_reuse_values=False,
    timeout="5m",
    binary_path=None,
    kubeconfig=None,
    context=None,
):
    """Install or upgrade a chart and report a concise, idempotent state result.

    Salt test mode checks for the release and pinned chart version, but does
    not contact a Helm diff plugin. Without a pinned chart version, test mode
    conservatively reports that an upgrade may occur.

    ``chart`` is a local chart path or Helm chart reference. Pin ``version``
    for reliable idempotency. ``values`` is a mapping; ``values_files`` is a
    path or list of paths. ``set_values`` accepts Helm typed overrides as a
    list of ``value``/``value_type`` mappings (raw, string, file, or json).
    Helm does not expose a normalized representation of these overrides, so
    their presence triggers a conservative upgrade check on each run.
    Changes contain only the release identity and action, never values.
    Example::

        web:
          helm.release_present:
            - chart: stable/nginx
            - version: 15.0.0
            - namespace: production
    """
    ret = _result(name)
    try:
        status = __salt__["helm.release_status"](
            name=name,
            namespace=namespace,
            binary_path=binary_path,
            kubeconfig=kubeconfig,
            context=context,
        )
        metadata = None
        if status and version and (chart.endswith(".tgz") or os.path.isdir(chart)):
            metadata = __salt__["helm.chart_info"](
                chart=chart,
                version=version,
                repo_url=repo_url,
                binary_path=binary_path,
                kubeconfig=kubeconfig,
                context=context,
            )
        if _up_to_date(
            status,
            chart,
            version,
            name,
            namespace,
            values,
            values_files,
            set_values,
            chart_info=metadata,
            binary_path=binary_path,
            kubeconfig=kubeconfig,
            context=context,
        ):
            ret.update(result=True, comment="Helm release is already up to date")
            return ret
        if __opts__.get("test", False):
            ret.update(
                result=None,
                changes={
                    f"{namespace}/{name}": {
                        "old": "present" if status else "absent",
                        "new": "present",
                    }
                },
                comment="Helm release would be installed or upgraded",
            )
            return ret
        __salt__["helm.release_present"](
            name=name,
            chart=chart,
            namespace=namespace,
            version=version,
            values=values,
            values_files=values_files,
            set_values=set_values,
            repo_url=repo_url,
            create_namespace=create_namespace,
            wait=wait,
            atomic=atomic,
            force=force,
            dependency_update=dependency_update,
            update_repo_cache=update_repo_cache,
            history_max=history_max,
            reset_values=reset_values,
            reuse_values=reuse_values,
            wait_for_jobs=wait_for_jobs,
            skip_crds=skip_crds,
            cleanup_on_fail=cleanup_on_fail,
            skip_schema_validation=skip_schema_validation,
            take_ownership=take_ownership,
            disable_hooks=disable_hooks,
            post_renderer=post_renderer,
            post_renderer_args=post_renderer_args,
            reset_then_reuse_values=reset_then_reuse_values,
            timeout=timeout,
            binary_path=binary_path,
            kubeconfig=kubeconfig,
            context=context,
        )
    except CommandExecutionError as exc:
        ret["comment"] = str(exc)
        return ret
    ret.update(
        result=True,
        changes={
            f"{namespace}/{name}": {"old": "present" if status else "absent", "new": "present"}
        },
        comment="Helm release is installed or upgraded",
    )
    return ret


def release_absent(
    name,
    namespace="default",
    keep_history=False,
    binary_path=None,
    kubeconfig=None,
    context=None,
):
    """Uninstall a Helm release; repeated runs are no-ops.

    ``name`` and ``namespace`` select the release; ``keep_history`` retains
    history when true. Test mode reports the planned removal without calling
    Helm. This removes release-managed resources, so use a dedicated release
    name and review dependent resources before removal.
    """
    ret = _result(name)
    try:
        status = __salt__["helm.release_status"](
            name=name,
            namespace=namespace,
            binary_path=binary_path,
            kubeconfig=kubeconfig,
            context=context,
        )
        if status is None:
            ret.update(result=True, comment="Helm release is already absent")
            return ret
        if __opts__.get("test", False):
            ret.update(
                result=None,
                changes={f"{namespace}/{name}": {"old": "present", "new": "absent"}},
                comment="Helm release would be uninstalled",
            )
            return ret
        __salt__["helm.release_absent"](
            name=name,
            namespace=namespace,
            keep_history=keep_history,
            binary_path=binary_path,
            kubeconfig=kubeconfig,
            context=context,
        )
    except CommandExecutionError as exc:
        ret["comment"] = str(exc)
        return ret
    ret.update(
        result=True,
        changes={f"{namespace}/{name}": {"old": "present", "new": "absent"}},
        comment="Helm release is uninstalled",
    )
    return ret
