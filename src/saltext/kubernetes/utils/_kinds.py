"""
Kind registry for the saltext-kubernetes extension.

A single source of truth for per-Kubernetes-kind metadata used by the
wait subsystem and (future) the operations modules:

* which kubernetes-client API class hosts the kind's CRUD methods
  (e.g. ``CoreV1Api`` for Pod, ``AppsV1Api`` for Deployment)
* the name of the ``list_*`` and ``read_*`` methods on that class
* whether the kind is namespaced or cluster-scoped
* a readiness predicate evaluated against a live API object

Adding a new typed kind is one entry in :py:data:`_KIND_REGISTRY` plus
its public CRUD functions on :py:mod:`...kubernetesmod`. Before this
registry existed the kind→method mapping lived as a duplicated literal
dict in :py:func:`_wait_for_resource_status` (twice — once for the
"deleted" path's ``read_*`` lookup, once for the "created/ready"
path's ``list_*`` lookup).
"""

from collections.abc import Callable
from dataclasses import dataclass

from salt.exceptions import CommandExecutionError

# pylint: disable=import-error,no-name-in-module
try:
    import kubernetes.client.rest  # noqa: F401  pylint: disable=unused-import

    HAS_LIBS = True
except ImportError:
    HAS_LIBS = False
# pylint: enable=import-error,no-name-in-module


@dataclass(frozen=True)
class KindOps:
    """Per-kind metadata for the wait subsystem."""

    api_class_attr: str
    """Attribute name on ``kubernetes.client`` (e.g. ``"AppsV1Api"``)."""

    list_method: str
    """Method on the API class used by Watch.stream (e.g. ``"list_namespaced_deployment"``)."""

    read_method: str
    """Method on the API class used for existence checks (e.g. ``"read_namespaced_deployment"``)."""

    namespaced: bool
    """``False`` for cluster-scoped kinds (Node, StorageClass, Namespace, ...)."""

    ready_predicate: Callable[[object], bool]
    """Returns ``True`` when an API object is considered Ready."""


# ---------------------------------------------------------------------------
# Ready predicates. Behaviour is preserved exactly from the previous in-line
# logic in ``_wait_for_resource_status`` so that storageclass / replicaset /
# daemonset wait timing in the kind-cluster fixture does not flake.
# ---------------------------------------------------------------------------


def _always_ready(_obj):
    """Default predicate: any object that exists is considered ready."""
    return True


def _deployment_ready(obj):
    """A Deployment is ready when ``available_replicas == spec.replicas``."""
    avail = obj.status.available_replicas
    spec_replicas = obj.spec.replicas
    return bool(avail) and avail == spec_replicas


def _pod_ready(obj):
    """A Pod is ready when phase is Running and every container is ready."""
    if obj.status.phase != "Running":
        return False
    container_statuses = obj.status.container_statuses
    if not container_statuses:
        return False
    return all(cs.ready for cs in container_statuses)


def _service_ready(obj):
    """A Service is ready once the API server has assigned a clusterIP."""
    return bool(obj.spec.cluster_ip)


# ---------------------------------------------------------------------------
# The registry. New kinds get an entry here and (in the same PR) their CRUD
# functions on kubernetesmod. The wait subsystem then supports them for free.
# ---------------------------------------------------------------------------

_KIND_REGISTRY: dict[str, KindOps] = {
    # Workloads
    "deployment": KindOps(
        api_class_attr="AppsV1Api",
        list_method="list_namespaced_deployment",
        read_method="read_namespaced_deployment",
        namespaced=True,
        ready_predicate=_deployment_ready,
    ),
    "statefulset": KindOps(
        api_class_attr="AppsV1Api",
        list_method="list_namespaced_stateful_set",
        read_method="read_namespaced_stateful_set",
        namespaced=True,
        ready_predicate=_always_ready,
    ),
    "replicaset": KindOps(
        api_class_attr="AppsV1Api",
        list_method="list_namespaced_replica_set",
        read_method="read_namespaced_replica_set",
        namespaced=True,
        ready_predicate=_always_ready,
    ),
    "daemonset": KindOps(
        api_class_attr="AppsV1Api",
        list_method="list_namespaced_daemon_set",
        read_method="read_namespaced_daemon_set",
        namespaced=True,
        ready_predicate=_always_ready,
    ),
    "pod": KindOps(
        api_class_attr="CoreV1Api",
        list_method="list_namespaced_pod",
        read_method="read_namespaced_pod",
        namespaced=True,
        ready_predicate=_pod_ready,
    ),
    # Services & Config
    "service": KindOps(
        api_class_attr="CoreV1Api",
        list_method="list_namespaced_service",
        read_method="read_namespaced_service",
        namespaced=True,
        ready_predicate=_service_ready,
    ),
    "secret": KindOps(
        api_class_attr="CoreV1Api",
        list_method="list_namespaced_secret",
        read_method="read_namespaced_secret",
        namespaced=True,
        ready_predicate=_always_ready,
    ),
    "configmap": KindOps(
        api_class_attr="CoreV1Api",
        list_method="list_namespaced_config_map",
        read_method="read_namespaced_config_map",
        namespaced=True,
        ready_predicate=_always_ready,
    ),
    # Cluster-scoped
    "namespace": KindOps(
        api_class_attr="CoreV1Api",
        list_method="list_namespace",
        read_method="read_namespace",
        namespaced=False,
        ready_predicate=_always_ready,
    ),
    "storageclass": KindOps(
        api_class_attr="StorageV1Api",
        list_method="list_storage_class",
        read_method="read_storage_class",
        namespaced=False,
        ready_predicate=_always_ready,
    ),
    # RBAC
    "role": KindOps(
        api_class_attr="RbacAuthorizationV1Api",
        list_method="list_namespaced_role",
        read_method="read_namespaced_role",
        namespaced=True,
        ready_predicate=_always_ready,
    ),
    "role_binding": KindOps(
        api_class_attr="RbacAuthorizationV1Api",
        list_method="list_namespaced_role_binding",
        read_method="read_namespaced_role_binding",
        namespaced=True,
        ready_predicate=_always_ready,
    ),
    "cluster_role": KindOps(
        api_class_attr="RbacAuthorizationV1Api",
        list_method="list_cluster_role",
        read_method="read_cluster_role",
        namespaced=False,
        ready_predicate=_always_ready,
    ),
    "cluster_role_binding": KindOps(
        api_class_attr="RbacAuthorizationV1Api",
        list_method="list_cluster_role_binding",
        read_method="read_cluster_role_binding",
        namespaced=False,
        ready_predicate=_always_ready,
    ),
    "service_account": KindOps(
        api_class_attr="CoreV1Api",
        list_method="list_namespaced_service_account",
        read_method="read_namespaced_service_account",
        namespaced=True,
        ready_predicate=_always_ready,
    ),
    # Batch
    "job": KindOps(
        api_class_attr="BatchV1Api",
        list_method="list_namespaced_job",
        read_method="read_namespaced_job",
        namespaced=True,
        # A Job is "ready" once it exists; completion is a separate
        # state checked via _wait_for_job_completion.
        ready_predicate=_always_ready,
    ),
    "cron_job": KindOps(
        api_class_attr="BatchV1Api",
        list_method="list_namespaced_cron_job",
        read_method="read_namespaced_cron_job",
        namespaced=True,
        ready_predicate=_always_ready,
    ),
}


def get_kind(resource_type: str) -> KindOps:
    """
    Return the :py:class:`KindOps` for ``resource_type``.

    Raised exception type matches the legacy
    ``CommandExecutionError("Unsupported resource type for wait operation: ...")``
    behaviour so existing callers and tests are not surprised.
    """
    try:
        return _KIND_REGISTRY[resource_type]
    except KeyError as exc:
        raise CommandExecutionError(
            f"Unsupported resource type for wait operation: {resource_type}"
        ) from exc
