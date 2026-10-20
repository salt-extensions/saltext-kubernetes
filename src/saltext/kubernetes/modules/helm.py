"""Execution functions for Helm CLI operations.

The functions in this module invoke Helm without a shell. Install Helm on
the minion that runs these functions. Values dictionaries are passed through
temporary mode-0600 JSON files, and registry passwords use stdin.
"""

import json
import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager

import yaml
from salt.exceptions import CommandExecutionError


def __virtual__():
    """Load the module even when Helm is absent; calls then return a clear error."""
    return True


def _clean(text, sensitive):
    for value in sensitive:
        if value:
            text = text.replace(str(value), "<redacted>")
    return text


def _run(
    args,
    binary_path=None,
    kubeconfig=None,
    context=None,
    timeout=300,
    stdin=None,
    sensitive=(),
    allow_failure=False,
    env=None,
):
    """Run Helm with argv (never a shell) and return captured output."""
    executable = binary_path or shutil.which("helm")
    if not executable:
        raise CommandExecutionError("Helm is not installed or not present on PATH")
    argv = [executable, *[str(arg) for arg in args]]
    if kubeconfig:
        argv.extend(["--kubeconfig", str(kubeconfig)])
    if context:
        argv.extend(["--kube-context", str(context)])
    run_env = os.environ.copy()
    if env:
        run_env.update(env)
    try:
        proc = subprocess.run(
            argv,
            input=stdin,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
            env=run_env,
        )
    except FileNotFoundError as exc:
        raise CommandExecutionError(f"Helm executable was not found: {executable}") from exc
    except subprocess.TimeoutExpired as exc:
        raise CommandExecutionError(f"Helm command timed out after {timeout} seconds") from exc
    stdout = _clean(proc.stdout or "", sensitive)
    stderr = _clean(proc.stderr or "", sensitive)
    result = {"stdout": stdout, "stderr": stderr, "retcode": proc.returncode}
    if proc.returncode and not allow_failure:
        details = stderr.strip() or stdout.strip() or "no command output"
        raise CommandExecutionError(
            f"Helm {args[0] if args else 'command'} failed with exit code "
            f"{proc.returncode}: {details[:1000]}"
        )
    return result


def _flag(args, option, value):
    if value is not None and value is not False:
        if value is True:
            args.append(option)
        else:
            args.extend([option, str(value)])


def _add_values(args, values=None, values_files=None):
    files = [values_files] if isinstance(values_files, str) else list(values_files or [])
    for path in files:
        args.extend(["--values", str(path)])
    if values is not None:
        fd, path = tempfile.mkstemp(prefix="salt-helm-values-", suffix=".json")
        os.fchmod(fd, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(values, stream, separators=(",", ":"))
            args.extend(["--values", path])
            return path
        except Exception:
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
    return None


def _add_set_values(args, set_values):
    """Append typed Helm ``--set`` options after validating their shape."""
    option_by_type = {
        "raw": "--set",
        "string": "--set-string",
        "file": "--set-file",
        "json": "--set-json",
    }
    for item in set_values or []:
        if not isinstance(item, dict) or "value" not in item:
            raise CommandExecutionError(
                "Each set_values item must be a mapping with a 'value' string"
            )
        value = item["value"]
        if not isinstance(value, str) or "=" not in value:
            raise CommandExecutionError(
                "Each set_values value must be a string in 'key=value' form"
            )
        value_type = item.get("value_type", "raw")
        if value_type not in option_by_type:
            raise CommandExecutionError(
                "set_values value_type must be raw, string, file, or json"
            )
        args.extend([option_by_type[value_type], value])


def _remove_temp(path):
    if path:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def _decode_json(result, operation):
    try:
        return json.loads(result["stdout"] or "null")
    except json.JSONDecodeError as exc:
        raise CommandExecutionError(f"Helm {operation} returned invalid JSON") from exc


def release_list(
    namespace=None, all_namespaces=False, all_releases=False, release_state=None, **kwargs
):
    """List Helm releases as dictionaries.

    ``namespace`` filters one namespace; ``all_namespaces`` includes cluster
    namespaces; ``all_releases`` includes history; ``release_state`` accepts
    status names such as ``deployed`` or ``failed``. Returns Helm JSON records.
    Requires the Helm binary and a valid Kubernetes context.
    """
    args = ["list", "--output", "json"]
    _flag(args, "--namespace", namespace)
    _flag(args, "--all-namespaces", all_namespaces)
    _flag(args, "--all", all_releases)
    result = _run(args, **kwargs)
    rows = _decode_json(result, "list") or []
    statuses = {str(item).lower() for item in (release_state or [])}
    return [row for row in rows if not statuses or str(row.get("status", "")).lower() in statuses]


def release_status(name, namespace="default", **kwargs):
    """Return one release status record, or ``None`` when absent.

    ``name`` and ``namespace`` identify the release. Helm errors other than
    not-found are raised as ``CommandExecutionError``. The chart name/version
    are enriched from ``helm list`` when the Helm version omits them.
    """
    result = _run(
        ["status", name, "--namespace", namespace, "--output", "json"],
        allow_failure=True,
        **kwargs,
    )
    if result["retcode"]:
        if "not found" in (result["stderr"] + result["stdout"]).lower():
            return None
        raise CommandExecutionError(
            f"Helm status failed with exit code {result['retcode']}: "
            f"{(result['stderr'] or result['stdout']).strip()[:1000]}"
        )
    status = _decode_json(result, "status")
    # Helm 3 status JSON omits the chart field, while `helm list -o json`
    # includes the chart name and version used for idempotency checks.
    if isinstance(status, dict) and not status.get("chart"):
        releases = release_list(namespace=namespace, all_releases=True, **kwargs)
        match = next((item for item in releases if item.get("name") == name), None)
        if match:
            for key, value in match.items():
                if status.get(key) in (None, ""):
                    status[key] = value
    return status


def release_get(
    name,
    namespace="default",
    get_values=False,
    all_values=False,
    get_manifest=False,
    get_hooks=False,
    get_notes=False,
    **kwargs,
):
    """Gather release status and optionally values, manifest, hooks, or notes.

    Values and manifests can contain secrets. They are returned only when the
    corresponding opt-in argument is true.
    """
    status = release_status(name, namespace=namespace, **kwargs)
    if status is None:
        return None
    result = {"status": status}
    if get_values:
        args = ["get", "values", name, "--namespace", namespace, "--output", "json"]
        _flag(args, "--all", all_values)
        result["values"] = _decode_json(_run(args, **kwargs), "get values") or {}
    for enabled, field, subcommand in (
        (get_manifest, "manifest", "manifest"),
        (get_hooks, "hooks", "hooks"),
        (get_notes, "notes", "notes"),
    ):
        if enabled:
            result[field] = _run(["get", subcommand, name, "--namespace", namespace], **kwargs)[
                "stdout"
            ]
    return result


def chart_info(chart, version=None, repo_url=None, **kwargs):
    """Return the chart metadata for a local archive, directory, or repository ref.

    ``version`` and ``repo_url`` select remote chart versions. The returned
    metadata is parsed from Helm's YAML output; no release is installed.
    """
    args = ["show", "chart", chart]
    _flag(args, "--version", version)
    _flag(args, "--repo", repo_url)
    result = _run(args, **kwargs)
    try:
        metadata = yaml.safe_load(result["stdout"])
    except yaml.YAMLError as exc:
        raise CommandExecutionError("Helm show chart returned invalid YAML") from exc
    if not isinstance(metadata, dict) or not metadata.get("name"):
        raise CommandExecutionError("Helm chart metadata is missing its name")
    return metadata


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
    **kwargs,
):
    """Install or upgrade a chart using ``helm upgrade --install``.

    ``values`` are written to a private temporary file rather than placed in
    process arguments. A values file may be provided by path. ``set_values``
    is a list of mappings with a ``value`` in ``key=value`` form and optional
    ``value_type`` of ``raw`` (default), ``string``, ``file``, or ``json``.
    Other supported controls include schema validation, ownership, hooks,
    post-renderer path/arguments, and reset-then-reuse behavior. These newer
    flags require a Helm version that supports the matching CLI options.
    The return omits command arguments and values. ``update_repo_cache``
    refreshes repository indexes first.

    Example::

        salt-call helm.release_present web repo/web set_values='[{"value": "replicaCount=3", "value_type": "raw"}]'
    """
    value_reset_options = (reset_values, reuse_values, reset_then_reuse_values)
    if sum(bool(option) for option in value_reset_options) > 1:
        raise CommandExecutionError(
            "reset_values, reuse_values, and reset_then_reuse_values are mutually exclusive"
        )
    if post_renderer_args is not None and not isinstance(post_renderer_args, (list, tuple)):
        raise CommandExecutionError("post_renderer_args must be a list of strings")
    if update_repo_cache:
        repository_update(
            binary_path=kwargs.get("binary_path"),
            kubeconfig=kwargs.get("kubeconfig"),
            context=kwargs.get("context"),
        )
    args = ["upgrade", "--install", name, chart, "--namespace", namespace]
    for option, value in (
        ("--version", version),
        ("--repo", repo_url),
        ("--timeout", timeout),
    ):
        _flag(args, option, value)
    for option, value in (
        ("--create-namespace", create_namespace),
        ("--wait", wait),
        ("--atomic", atomic),
        ("--force", force),
        ("--dependency-update", dependency_update),
        ("--reset-values", reset_values),
        ("--reuse-values", reuse_values),
        ("--wait-for-jobs", wait_for_jobs),
        ("--skip-crds", skip_crds),
        ("--cleanup-on-fail", cleanup_on_fail),
        ("--skip-schema-validation", skip_schema_validation),
        ("--take-ownership", take_ownership),
        ("--no-hooks", disable_hooks),
        ("--reset-then-reuse-values", reset_then_reuse_values),
    ):
        _flag(args, option, value)
    _flag(args, "--history-max", history_max)
    _flag(args, "--post-renderer", post_renderer)
    for post_renderer_arg in post_renderer_args or []:
        args.extend(["--post-renderer-args", str(post_renderer_arg)])
    set_args = []
    _add_set_values(set_args, set_values)
    values_path = _add_values(args, values=values, values_files=values_files)
    args.extend(set_args)
    try:
        return _run(args, **kwargs)
    finally:
        _remove_temp(values_path)


def release_absent(name, namespace="default", keep_history=False, **kwargs):
    """Uninstall a release; an absent release is an idempotent no-op.

    ``keep_history`` retains release history when true. Returns command
    output with a ``changed`` field. Uninstall removes chart-managed resources
    in the selected namespace.
    """
    current = release_status(name, namespace=namespace, **kwargs)
    if current is None:
        return {"changed": False, "stdout": "", "stderr": "", "retcode": 0}
    args = ["uninstall", name, "--namespace", namespace]
    _flag(args, "--keep-history", keep_history)
    result = _run(args, **kwargs)
    result["changed"] = True
    return result


def repository_list(**kwargs):
    """List repositories configured in the active Helm configuration.

    Returns a list of ``name``/``url`` records; an empty configuration
    returns an empty list. The Helm binary and its repository config must be
    available to the executing minion.
    """
    result = _run(["repo", "list", "--output", "json"], allow_failure=True, **kwargs)
    if result["retcode"]:
        if "no repositories" in result["stderr"].lower():
            return []
        raise CommandExecutionError(
            f"Helm repo list failed: {(result['stderr'] or result['stdout']).strip()[:1000]}"
        )
    try:
        return _decode_json(result, "repo list") or []
    except CommandExecutionError:
        rows = [line.split(None, 1) for line in result["stdout"].splitlines()[1:] if line.strip()]
        return [{"name": row[0], "url": row[1] if len(row) > 1 else ""} for row in rows]


def repository_present(
    name,
    url,
    force_update=False,
    pass_credentials=False,
    insecure_skip_tls_verify=False,
    **kwargs,
):
    """Add or update a Helm chart repository.

    ``name`` and ``url`` identify the repository. ``force_update`` replaces
    an existing entry; ``pass_credentials`` and
    ``insecure_skip_tls_verify`` map to Helm options. Returns command output.
    Basic-auth credentials are rejected rather than exposed in process args;
    configure private credentials in protected Helm config separately.
    """
    username = kwargs.pop("repo_username", kwargs.pop("username", None))
    password = kwargs.pop("repo_password", kwargs.pop("password", None))
    if username or password:
        raise CommandExecutionError(
            "Repository basic-auth credentials cannot be passed safely to Helm CLI; "
            "configure them in Helm's protected repository config before using this state"
        )
    args = ["repo", "add", name, url]
    for option, value in (
        ("--force-update", force_update),
        ("--pass-credentials", pass_credentials),
        ("--insecure-skip-tls-verify", insecure_skip_tls_verify),
    ):
        _flag(args, option, value)
    return _run(args, **kwargs)


def repository_absent(name, **kwargs):
    """Remove a Helm repository; an absent entry is an idempotent no-op.

    ``name`` selects the configured repository. Returns command output with
    ``changed`` indicating removal.
    """
    existing = repository_list(**kwargs)
    if not any(row.get("name") == name for row in existing):
        return {"changed": False, "stdout": "", "stderr": "", "retcode": 0}
    result = _run(["repo", "remove", name], **kwargs)
    result["changed"] = True
    return result


def repository_update(name=None, **kwargs):
    """Refresh one or all repository indexes.

    ``name`` optionally limits the refresh to one configured repository.
    Returns Helm command output; repository network or configuration errors
    raise ``CommandExecutionError``.
    """
    args = ["repo", "update"]
    if name:
        args.append(name)
    return _run(args, **kwargs)


def _plugin_rows(output):
    rows = []
    for line in output.splitlines():
        parts = line.split(None, 2)
        if (
            len(parts) >= 2
            and parts[0].lower() not in ("name", "plugin")
            and not set(parts[0]) <= {"-", "="}
        ):
            rows.append(
                {
                    "name": parts[0],
                    "version": parts[1],
                    "description": parts[2] if len(parts) > 2 else "",
                }
            )
    return rows


def plugin_list(name=None, **kwargs):
    """List installed Helm plugins, optionally selecting one by name."""
    result = _run(["plugin", "list"], **kwargs)
    rows = _plugin_rows(result["stdout"])
    return [row for row in rows if row["name"] == name] if name else rows


def plugin_present(path, version=None, verify=None, keyring=None, **kwargs):
    """Install a Helm plugin from a local path or remote URL.

    ``version`` selects a plugin version; ``verify`` and ``keyring`` control
    provenance verification. Returns Helm command output. Plugin code runs on
    the minion, so install only trusted sources.
    """
    args = ["plugin", "install", path]
    _flag(args, "--version", version)
    _flag(args, "--verify", verify)
    _flag(args, "--keyring", keyring)
    return _run(args, **kwargs)


def plugin_absent(name, **kwargs):
    """Uninstall an installed Helm plugin; absent plugins are a no-op.

    ``name`` is the installed plugin name. Returns output and ``changed``.
    """
    if not plugin_list(name, **kwargs):
        return {"changed": False, "stdout": "", "stderr": "", "retcode": 0}
    result = _run(["plugin", "uninstall", name], **kwargs)
    result["changed"] = True
    return result


def plugin_latest(name, **kwargs):
    """Update an installed Helm plugin to its latest available version.

    ``name`` must identify an installed plugin. Returns Helm command output;
    a missing plugin or update failure raises ``CommandExecutionError``.
    """
    if not plugin_list(name, **kwargs):
        raise CommandExecutionError(f"Helm plugin {name!r} is not installed")
    return _run(["plugin", "update", name], **kwargs)


def registry_auth(
    host,
    state="present",
    username=None,
    password=None,
    insecure=False,
    plain_http=False,
    ca_file=None,
    cert_file=None,
    key_file=None,
    **kwargs,
):
    """Log in to or out of an OCI registry.

    ``state`` is ``present`` (default) or ``absent``. Login requires both
    ``username`` and ``password``; the password is passed on stdin and
    redacted from captured output. TLS options include ``ca_file``,
    ``cert_file``, ``key_file``, ``insecure``, and ``plain_http``. Returns
    command output and ``changed``; credentials are stored by Helm locally.
    """
    if state not in ("present", "absent"):
        raise CommandExecutionError("state must be 'present' or 'absent'")
    if state == "present" and (not username or not password):
        raise CommandExecutionError("registry login requires both username and password")
    args = ["registry", "login" if state == "present" else "logout"]
    for option, value in (
        ("--username", username),
        ("--ca-file", ca_file),
        ("--cert-file", cert_file),
        ("--key-file", key_file),
    ):
        _flag(args, option, value)
    if insecure:
        args.append("--insecure")
    if plain_http:
        args.append("--plain-http")
    if state == "present" and password is not None:
        args.append("--password-stdin")
    args.append(host)
    result = _run(
        args,
        stdin=password if state == "present" else None,
        sensitive=(password,),
        allow_failure=state == "absent",
        **kwargs,
    )
    if result["retcode"]:
        if state == "absent" and "not logged in" in result["stderr"].lower():
            result["changed"] = False
            return result
        raise CommandExecutionError(
            f"Helm registry {state} failed with exit code {result['retcode']}: "
            f"{(result['stderr'] or result['stdout']).strip()[:1000]}"
        )
    result["changed"] = True
    return result


def pull(
    chart,
    version=None,
    repo_url=None,
    destination=None,
    untar=False,
    untar_directory=None,
    verify=False,
    provenance=False,
    insecure_skip_tls_verify=False,
    pass_credentials=False,
    ca_file=None,
    cert_file=None,
    key_file=None,
    plain_http=False,
    username=None,
    password=None,
    **kwargs,
):
    """Download a Helm chart archive, optionally unpacking it.

    ``chart`` is a repository/chart or OCI reference. Optional ``version``,
    ``repo_url``, ``destination``, ``untar``, ``verify``, TLS, and provenance
    arguments map to Helm pull options. Returns command output; the downloaded
    archive is a filesystem side effect on the minion. Credentials must be
    configured in protected Helm repository settings.
    """
    if username or password:
        raise CommandExecutionError(
            "Chart credentials must be configured in Helm's protected repository config; "
            "they are not accepted as command arguments"
        )
    args = ["pull", chart]
    for option, value in (
        ("--version", version),
        ("--repo", repo_url),
        ("--destination", destination),
        ("--untar", untar),
        ("--untardir", untar_directory),
        ("--verify", verify),
        ("--prov", provenance),
        ("--insecure-skip-tls-verify", insecure_skip_tls_verify),
        ("--pass-credentials", pass_credentials),
        ("--ca-file", ca_file),
        ("--cert-file", cert_file),
        ("--key-file", key_file),
        ("--plain-http", plain_http),
    ):
        _flag(args, option, value)
    return _run(args, **kwargs)


def template(
    chart,
    name="release-name",
    namespace="default",
    version=None,
    repo_url=None,
    values=None,
    values_files=None,
    output_dir=None,
    include_crds=False,
    show_only=None,
    skip_tests=False,
    dependency_update=False,
    kube_version=None,
    api_versions=None,
    is_upgrade=False,
    no_hooks=False,
    username=None,
    password=None,
    **kwargs,
):
    """Render a Helm chart without installing a release.

    ``chart`` may be a local path or repository/OCI reference. ``name`` and
    ``namespace`` set the template release identity. ``values`` is written to
    a private temporary file; ``values_files`` are passed by path. Version,
    CRD, hook, API version, Kubernetes version, and output options map to Helm
    template flags. Returns rendered stdout/stderr or writes files under
    ``output_dir``. Chart credentials must be configured separately.
    """
    if username or password:
        raise CommandExecutionError(
            "Chart credentials must be configured in Helm's protected repository config; "
            "they are not accepted as command arguments"
        )
    args = ["template", name, chart, "--namespace", namespace]
    for option, value in (
        ("--version", version),
        ("--repo", repo_url),
        ("--output-dir", output_dir),
        ("--kube-version", kube_version),
    ):
        _flag(args, option, value)
    for option, value in (
        ("--include-crds", include_crds),
        ("--skip-tests", skip_tests),
        ("--dependency-update", dependency_update),
        ("--is-upgrade", is_upgrade),
        ("--no-hooks", no_hooks),
    ):
        _flag(args, option, value)
    for api_version in api_versions or []:
        args.extend(["--api-versions", str(api_version)])
    for template_path in show_only or []:
        args.extend(["--show-only", str(template_path)])
    values_path = _add_values(args, values=values, values_files=values_files)
    try:
        return _run(args, **kwargs)
    finally:
        _remove_temp(values_path)
