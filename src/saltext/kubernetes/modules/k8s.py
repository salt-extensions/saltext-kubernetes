"""Salt execution facade for common Kubernetes API operations.

These functions delegate to the extension's established ``kubernetes``
execution module and provide concise entry points for common Kubernetes tasks.
"""

import hashlib
import json
import os
import shutil
import subprocess
import time
from collections import OrderedDict

from salt.exceptions import CommandExecutionError


def __virtual__():
    """Load the facade; individual calls report missing dependencies."""
    return True


def info(
    api_version,
    kind,
    name=None,
    namespace=None,
    label_selector=None,
    field_selector=None,
    wait=False,
    wait_sleep=5,
    wait_timeout=120,
    **kwargs,
):
    """Read Kubernetes resources using their API version and kind.

    Args:
        api_version: API group/version, such as ``v1`` or ``apps/v1``.
        kind: Kubernetes kind, such as ``Pod`` or ``Deployment``.
        name: Optional object name. Omit to list matching resources.
        namespace: Optional namespace for namespaced resources.
        label_selector: Optional Kubernetes label selector for lists.
        field_selector: Optional Kubernetes field selector for lists.
        wait: Poll for a named object to appear before returning it. Waiting
            requires ``name`` and is ignored for list queries.
        wait_sleep: Seconds between polls when waiting (default 5).
        wait_timeout: Maximum seconds to wait for a named object (default 120).

    Returns one serialized resource, ``None`` if a named resource is absent,
    or a list of serialized resources. API errors raise
    :class:`salt.exceptions.CommandExecutionError`.

    Example: ``salt-call k8s.info v1 ConfigMap namespace=default``.
    """
    if name:
        if wait:
            if wait_sleep <= 0 or wait_timeout < 0:
                raise CommandExecutionError(
                    "wait_sleep must be positive and wait_timeout must be non-negative"
                )
            deadline = time.monotonic() + wait_timeout
            while True:
                obj = __salt__["kubernetes.get_object"](
                    api_version=api_version, kind=kind, name=name, namespace=namespace, **kwargs
                )
                if obj is not None:
                    return obj
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CommandExecutionError(
                        f"Timed out after {wait_timeout} seconds waiting for {kind}/{name}"
                    )
                time.sleep(min(wait_sleep, remaining))
        return __salt__["kubernetes.get_object"](
            api_version=api_version, kind=kind, name=name, namespace=namespace, **kwargs
        )
    return __salt__["kubernetes.list_objects"](
        api_version=api_version,
        kind=kind,
        namespace=namespace,
        label_selector=label_selector,
        field_selector=field_selector,
        **kwargs,
    )


def apply(manifest=None, source=None, namespace=None, **kwargs):
    """Create or reconcile manifests through the Kubernetes API.

    Supply either ``manifest`` (a mapping/list/YAML string) or ``source``
    (a local or Salt fileserver path). ``namespace`` is the fallback for
    documents without one. Remaining keyword arguments are passed to
    ``kubernetes.apply`` (including field manager and dry-run options).
    Returns serialized applied objects. API or validation errors raise
    ``CommandExecutionError``.
    """
    return __salt__["kubernetes.apply"](
        manifest=manifest, source=source, namespace=namespace, **kwargs
    )


def delete(manifest=None, source=None, namespace=None, **kwargs):
    """Delete resources identified by one or more manifest documents.

    ``manifest`` and ``source`` follow :func:`apply`; ``namespace`` supplies
    the fallback namespace. Returns deletion results and raises
    ``CommandExecutionError`` on API or validation failures. This operation
    is imperative; use the ``k8s.absent`` state for idempotent desired state.
    """
    return __salt__["kubernetes.delete_manifest"](
        manifest=manifest, source=source, namespace=namespace, **kwargs
    )


def patch(api_version, kind, name, patch, namespace=None, patch_type="strategic", **kwargs):
    """Patch an existing resource.

    ``patch_type`` accepts ``strategic`` (default), ``merge``, or the
    ``json-patch`` variant used by :func:`json_patch`. ``patch`` is the
    patch body; ``namespace`` is optional for cluster-scoped objects.
    Returns the updated serialized object. Missing objects and API errors
    raise ``CommandExecutionError``.
    """
    return __salt__["kubernetes.patch_object"](
        api_version=api_version,
        kind=kind,
        name=name,
        namespace=namespace,
        patch=patch,
        patch_type=patch_type,
        **kwargs,
    )


def json_patch(api_version, kind, name, operations, namespace=None, **kwargs):
    """Apply RFC 6902 JSON Patch operations to an existing resource.

    ``operations`` is a list of JSON Patch mappings such as
    ``[{"op": "replace", "path": "/spec/replicas", "value": 2}]``.
    Returns the updated serialized object; invalid operations and API errors
    raise ``CommandExecutionError``.
    """
    return patch(
        api_version,
        kind,
        name,
        operations,
        namespace=namespace,
        patch_type="json-patch",
        **kwargs,
    )


def cluster_info(**kwargs):
    """Return API server version, health endpoint, and API group discovery.

    Returns a mapping with ``server_version``, ``healthz``, and sorted
    ``api_groups``. Requires valid cluster authentication; API errors raise
    ``CommandExecutionError``.
    """
    return __salt__["kubernetes.cluster_info"](**kwargs)


def execute(
    name,
    namespace="default",
    command=None,
    container=None,
    stdin=None,
    tty=False,
    timeout=60,
    **kwargs,
):
    """Execute a command in a pod.

    ``command`` is an argv list; ``container`` selects a container, ``stdin``
    supplies input, ``tty`` enables a TTY, and ``timeout`` bounds the request
    in seconds (default 60). Returns command output and status. The pod must
    be running and the caller needs pod exec permission.
    """
    return __salt__["kubernetes.exec"](
        name=name,
        namespace=namespace,
        command=command,
        container=container,
        stdin=stdin,
        tty=tty,
        timeout=timeout,
        **kwargs,
    )


def logs(name, namespace="default", container=None, tail_lines=None, since_seconds=None, **kwargs):
    """Fetch logs from a pod container.

    ``namespace`` defaults to ``default``; ``container`` is optional.
    ``tail_lines`` and ``since_seconds`` limit returned log history.
    Returns log text. The caller needs pod get/log permission.
    """
    return __salt__["kubernetes.logs"](
        name=name,
        namespace=namespace,
        container=container,
        tail_lines=tail_lines,
        since_seconds=since_seconds,
        **kwargs,
    )


def copy_to(name, namespace, source, destination, container=None, **kwargs):
    """Copy a minion-local file or directory into a pod.

    ``source`` is read on the minion executing Salt; ``destination`` is the
    container path. ``container`` is optional. The pod must support ``tar``
    and exec permission; returns the underlying copy result.
    """
    return __salt__["kubernetes.cp_to"](
        name=name,
        namespace=namespace,
        src_path=source,
        dst_path=destination,
        container=container,
        **kwargs,
    )


def copy_from(name, namespace, source, destination, container=None, **kwargs):
    """Copy a file or directory from a pod to the executing minion.

    ``source`` is the container path and ``destination`` is a minion-local
    path. ``container`` is optional. The pod must support ``tar`` and exec
    permission; returns the underlying copy result.
    """
    return __salt__["kubernetes.cp_from"](
        name=name,
        namespace=namespace,
        src_path=source,
        dst_path=destination,
        container=container,
        **kwargs,
    )


def drain(name, **kwargs):
    """Cordon a node and evict eligible pods through the eviction API.

    Keyword arguments are passed to ``kubernetes.drain``; supported controls
    include selector, timeout, grace period, and whether to ignore daemon-set
    or mirror pods. Pod disruption budgets are honored unless eviction is
    explicitly disabled. This is disruptive and imperative; inspect its
    returned evicted/skipped pod lists before relying on it.
    """
    return __salt__["kubernetes.drain"](name=name, **kwargs)


def scale(kind, name, replicas, namespace="default", **kwargs):
    """Set the replica count for a supported workload.

    ``kind`` and ``name`` identify the workload; ``replicas`` is the desired
    non-negative count and ``namespace`` defaults to ``default``. Returns
    the updated resource. Use a declarative workload state for persistent
    configuration rather than repeatedly invoking this imperative function.
    """
    return __salt__["kubernetes.scale"](
        kind=kind, name=name, replicas=replicas, namespace=namespace, **kwargs
    )


def rollback(name, namespace="default", kind="Deployment", to_revision=None, **kwargs):
    """Roll a Deployment or DaemonSet back to an earlier revision.

    ``kind`` defaults to ``Deployment`` and also accepts ``DaemonSet``;
    ``to_revision`` selects a revision when supported. Returns the updated
    workload or raises ``CommandExecutionError`` if it cannot be rolled back.
    This operation changes live workload configuration.
    """
    return __salt__["kubernetes.rollback"](
        name=name, namespace=namespace, kind=kind, to_revision=to_revision, **kwargs
    )


def services(namespace="default", **kwargs):
    """List Services in ``namespace`` (default ``default``).

    Returns serialized Service objects and raises ``CommandExecutionError``
    on API failures.
    """
    return __salt__["kubernetes.services"](namespace=namespace, **kwargs)


def service(name, namespace="default", **kwargs):
    """Read one Service by name and namespace.

    Returns the serialized Service or ``None`` if absent.
    """
    return __salt__["kubernetes.show_service"](name=name, namespace=namespace, **kwargs)


def cordon(name, **kwargs):
    """Mark a node unschedulable to prevent new pod scheduling.

    ``name`` is the cluster-scoped node name. Returns the updated Node; this
    imperative change does not evict existing pods.
    """
    return __salt__["kubernetes.cordon"](name=name, **kwargs)


def uncordon(name, **kwargs):
    """Allow new pods to schedule on a previously cordoned node.

    ``name`` is the cluster-scoped node name. Returns the updated Node.
    """
    return __salt__["kubernetes.uncordon"](name=name, **kwargs)


def taint(name, key, effect, value=None, **kwargs):
    """Add or update a taint on a node.

    ``effect`` must be ``NoSchedule``, ``PreferNoSchedule``, or ``NoExecute``;
    ``value`` is optional. Returns the updated Node. Taints may change where
    workloads can schedule.
    """
    return __salt__["kubernetes.taint"](name=name, key=key, effect=effect, value=value, **kwargs)


def untaint(name, key, effect=None, **kwargs):
    """Remove a node taint selected by key and optional effect.

    ``name`` is the node name; ``key`` identifies the taint and ``effect``
    narrows the match. Returns the updated Node or a no-op result if absent.
    """
    return __salt__["kubernetes.untaint"](name=name, key=key, effect=effect, **kwargs)


def config_resource_name(resource):
    """Return a content-derived ConfigMap or Secret name.

    The generated name follows content-derived Kubernetes naming conventions
    and does not mutate ``resource``.
    """
    if not isinstance(resource, dict) or not isinstance(resource.get("metadata"), dict):
        raise CommandExecutionError("resource must include metadata.name or metadata.generateName")
    metadata = resource["metadata"]
    name_key = "name" if metadata.get("name") else "generateName"
    name = metadata.get(name_key)
    kind = resource.get("kind")
    if not name or kind not in ("ConfigMap", "Secret"):
        raise CommandExecutionError("resource must be a ConfigMap or Secret with a metadata name")
    keys = ["data", "kind", name_key]
    if kind == "Secret":
        keys.append("type")

    def sort_nested(value):
        if isinstance(value, dict):
            return OrderedDict((key, sort_nested(value[key])) for key in sorted(value))
        if isinstance(value, list):
            return [sort_nested(item) for item in value]
        return value

    canonical = OrderedDict((key, sort_nested(resource.get(key, ""))) for key in keys)
    payload = json.dumps(canonical, separators=(",", ":")).encode("utf-8")
    token = hashlib.sha256(payload).hexdigest()[:10].translate(str.maketrans("013ae", "ghkmt"))
    return f"{name}-{token}"


def kustomize_build(path, binary_path=None, **kwargs):
    """Build a local Kustomize directory and return rendered YAML text.

    ``path`` is a local directory or file path available to the executing
    minion. ``binary_path`` optionally selects the executable; otherwise
    ``kustomize`` must be on ``PATH``. Returns rendered YAML text. This is a
    read-only helper. Source files must be available on the minion.
    """
    executable = binary_path or shutil.which("kustomize")
    if not executable:
        raise CommandExecutionError("kustomize executable is not installed or not present on PATH")
    args = [executable, "build", os.path.expanduser(path)]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, check=False, timeout=300)
    except subprocess.TimeoutExpired as exc:
        raise CommandExecutionError("kustomize build timed out") from exc
    if proc.returncode:
        raise CommandExecutionError(f"kustomize build failed: {(proc.stderr or '').strip()[:1000]}")
    return proc.stdout
