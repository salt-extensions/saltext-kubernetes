"""
Module for handling kubernetes calls.

:optdepends:    - kubernetes Python client >= v19.15.0
                - PyYAML >= 5.3.1
:configuration: The k8s API settings are provided either in a pillar, in
    the minion's config file, or in master's config file. The classic
    kubeconfig-based setup looks like::

        kubernetes.kubeconfig: '/path/to/kubeconfig'
        kubernetes.kubeconfig-data: '<base64 encoded kubeconfig content>'
        kubernetes.context: 'context'

    For other auth modes — in-cluster ServiceAccount, bearer token, basic
    auth, or explicit client certificates with optional proxy support — see
    the dedicated :doc:`/topics/auth` guide. All settings can also be
    supplied via ``K8S_AUTH_*`` environment variables (compatible with
    Ansible's ``kubernetes.core`` collection) or as per-call kwargs that
    take precedence over both env and config.

The data format for `kubernetes.kubeconfig-data` value is the content of
`kubeconfig` base64 encoded in one line.

These settings can be overridden by adding `context` and `kubeconfig` or
`kubeconfig_data` parameters when calling a function.

Only `kubeconfig` or `kubeconfig-data` should be provided. In case both are
provided `kubeconfig` entry is preferred.

CLI Example:

.. code-block:: bash

    salt '*' kubernetes.nodes
    salt '*' kubernetes.nodes kubeconfig=/etc/salt/k8s/kubeconfig context=minikube

.. versionadded:: 2017.7.0
.. versionchanged:: 2019.2.0
.. versionchanged:: 2.1.0

    Added in-cluster ServiceAccount, bearer token, basic auth, explicit
    client-certificate, proxy, and ``K8S_AUTH_*`` environment-variable
    auth modes. The legacy kubeconfig path is unchanged and remains the
    default. See :doc:`/topics/auth`.

.. warning::

    Configuration options changed in 2019.2.0. The following configuration options have been removed:

    - kubernetes.user
    - kubernetes.password
    - kubernetes.api_url
    - kubernetes.certificate-authority-data/file
    - kubernetes.client-certificate-data/file
    - kubernetes.client-key-data/file

    These options were re-introduced under different names in 2.1.0 as
    part of the rich-auth work — see the auth guide. The 2019.2.0
    removal warning still stands for the *legacy* names; use the new
    ``kubernetes.host`` / ``kubernetes.api_key`` / ``kubernetes.username``
    / ``kubernetes.client_cert`` / etc. options instead.

"""

import base64
import copy
import datetime
import hashlib
import io
import json
import logging
import os.path
import re
import sys
import tarfile
import time

import salt.utils.files
import salt.utils.platform
import salt.utils.templates
import salt.utils.yaml
import yaml as _pyyaml
from salt.exceptions import CommandExecutionError

from saltext.kubernetes.utils import _dynamic
from saltext.kubernetes.utils import _kinds

# Re-exports kept on the module surface for backwards compatibility with any
# external code that imported these from ``kubernetesmod`` before the helpers
# were extracted to ``saltext.kubernetes.utils._connection``.
# pylint: disable=unused-import
from saltext.kubernetes.utils._connection import POLLING_TIME_LIMIT  # noqa: F401
from saltext.kubernetes.utils._connection import _cleanup  # noqa: F401
from saltext.kubernetes.utils._connection import _setup_conn as _setup_conn_impl  # noqa: F401
from saltext.kubernetes.utils._connection import list_configured_clusters

# pylint: enable=unused-import

if not salt.utils.platform.is_windows():
    # pylint: disable=unused-import
    from saltext.kubernetes.utils._connection import _time_limit  # noqa: F401

# pylint: disable=import-error,no-name-in-module
try:
    import kubernetes  # pylint: disable=import-self
    import kubernetes.client
    from kubernetes.client import ApiClient
    from kubernetes.client import V1ClusterRole
    from kubernetes.client import V1ClusterRoleBinding
    from kubernetes.client import V1CronJob
    from kubernetes.client import V1CronJobSpec
    from kubernetes.client import V1CustomResourceDefinition
    from kubernetes.client import V1CustomResourceDefinitionNames
    from kubernetes.client import V1CustomResourceDefinitionSpec
    from kubernetes.client import V1CustomResourceDefinitionVersion
    from kubernetes.client import V1Deployment
    from kubernetes.client import V1DeploymentSpec
    from kubernetes.client import V1Ingress
    from kubernetes.client import V1IngressSpec
    from kubernetes.client import V1Job
    from kubernetes.client import V1JobSpec
    from kubernetes.client import V1JobTemplateSpec
    from kubernetes.client import V1LimitRange
    from kubernetes.client import V1LimitRangeItem
    from kubernetes.client import V1LimitRangeSpec
    from kubernetes.client import V1NetworkPolicy
    from kubernetes.client import V1NetworkPolicySpec
    from kubernetes.client import V1PersistentVolume
    from kubernetes.client import V1PersistentVolumeClaim
    from kubernetes.client import V1PersistentVolumeClaimSpec
    from kubernetes.client import V1PersistentVolumeSpec
    from kubernetes.client import V1PodDisruptionBudget
    from kubernetes.client import V1PodDisruptionBudgetSpec
    from kubernetes.client import V1PolicyRule
    from kubernetes.client import V1PriorityClass
    from kubernetes.client import V1ResourceQuota
    from kubernetes.client import V1ResourceQuotaSpec
    from kubernetes.client import V1Role
    from kubernetes.client import V1RoleBinding
    from kubernetes.client import V1RoleRef
    from kubernetes.client import V1ServiceAccount
    from kubernetes.client import V2HorizontalPodAutoscaler
    from kubernetes.client import V2HorizontalPodAutoscalerSpec
    from kubernetes.client.rest import ApiException
    from kubernetes.stream import stream as ws_stream
    from kubernetes.stream.ws_client import ERROR_CHANNEL
    from kubernetes.watch import Watch
    from urllib3.exceptions import HTTPError

    # The RBAC-V1 Subject class was renamed from ``V1Subject`` to
    # ``RbacV1Subject`` in kubernetes-client 26.x to disambiguate from
    # other ``*Subject`` types. Both names refer to the same wire shape;
    # we accept whichever the installed client provides so the extension
    # remains compatible with our ``kubernetes>=19.15.0`` floor.
    try:
        from kubernetes.client import RbacV1Subject as V1Subject
    except ImportError:  # kubernetes-client < 26
        from kubernetes.client import V1Subject  # noqa: F401

    HAS_LIBS = True
except ImportError:
    HAS_LIBS = False
# pylint: enable=import-error,no-name-in-module

log = logging.getLogger(__name__)

__virtualname__ = "kubernetes"


def __virtual__():
    """
    Check dependencies
    """
    if HAS_LIBS:
        return __virtualname__

    return False, "python kubernetes library not found"


def _setup_conn(**kwargs):
    """
    Setup kubernetes API connection singleton.

    Backwards-compatible shim around
    :py:func:`saltext.kubernetes.utils._connection._setup_conn`. The
    signature, kwargs handling, and return shape are preserved so that
    existing call sites and ``mock.patch("...kubernetesmod._setup_conn")``
    paths continue to work.
    """
    return _setup_conn_impl(__salt__["config.option"], **kwargs)


def ping(**kwargs):
    """
    Checks connection with the kubernetes API server.
    Returns True if the API is available.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.ping
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.get_api_resources()
        return bool(api_response and hasattr(api_response, "resources") and api_response.resources)
    except (ApiException, HTTPError):
        log.error(
            "Exception when calling CoreV1Api->get_api_resources",
            exc_info_on_loglevel=logging.DEBUG,
        )
        return False
    finally:
        _cleanup(**cfg)


def nodes(**kwargs):
    """
    Return the names of the nodes composing the kubernetes cluster

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.nodes
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.list_node()

        return [
            k8s_node["metadata"]["name"]
            for k8s_node in ApiClient().sanitize_for_serialization(api_response).get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def node(name, **kwargs):
    """
    Return the details of the node identified by the specified name

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.node name='minikube'
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.list_node()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)

    for k8s_node in api_response.items:
        if k8s_node.metadata.name == name:
            return ApiClient().sanitize_for_serialization(k8s_node)

    return None


def node_labels(name, **kwargs):
    """
    Return the labels of the node identified by the specified name

    name
        The name of the node

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.node_labels name="minikube"
    """
    match = node(name, **kwargs)

    if match is not None:
        return match["metadata"]["labels"]

    return {}


def node_add_label(node_name, label_name, label_value, **kwargs):
    """
    Set the value of the label identified by `label_name` to `label_value` on
    the node identified by the name `node_name`.
    Creates the label if not present.

    node_name
        The name of the node

    label_name
        The name of the label

    label_value
        The value of the label

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.node_add_label node_name="minikube" \
            label_name="foo" label_value="bar"
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        # First verify the node exists
        try:
            api_instance.read_node(node_name)
        except ApiException as exc:
            if exc.status == 404:
                raise CommandExecutionError(f"Node {node_name} not found") from exc
            raise

        body = {"metadata": {"labels": {label_name: label_value}}}
        api_response = api_instance.patch_node(node_name, body)
        return api_response
    except (ApiException, HTTPError) as exc:
        raise CommandExecutionError(str(exc)) from exc
    finally:
        _cleanup(**cfg)


def node_remove_label(node_name, label_name, **kwargs):
    """
    Removes the label identified by `label_name` from
    the node identified by the name `node_name`.

    node_name
        The name of the node

    label_name
        The name of the label

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.node_remove_label node_name="minikube" \
            label_name="foo"
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        body = {"metadata": {"labels": {label_name: None}}}
        api_response = api_instance.patch_node(node_name, body)
        return api_response
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Node {node_name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def node_annotations(name, **kwargs):
    """
    Return the annotations on the named node, or an empty dict if the node
    is absent.

    .. versionadded:: 2.1.0

    name
        Name of the node to read.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.node_annotations name="minikube"
    """
    match = node(name, **kwargs)
    if match is not None:
        return match["metadata"].get("annotations") or {}
    return {}


def node_add_annotation(node_name, annotation_name, annotation_value, **kwargs):
    """
    Set or update an annotation on the named node.

    .. versionadded:: 2.1.0

    Creates the annotation if not present; updates the value if it is.
    Annotations differ from labels in that they accept arbitrary string
    values (no DNS-label syntax restriction) and are not used for
    selectors. See the Kubernetes docs:
    https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/

    node_name
        Name of the node to annotate.

    annotation_name
        Annotation key. May contain ``/`` to namespace the key.

    annotation_value
        Annotation value. Coerced to ``str``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.node_add_annotation node_name="minikube" \
            annotation_name="example.com/owner" annotation_value="ops"
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        try:
            api_instance.read_node(node_name)
        except ApiException as exc:
            if exc.status == 404:
                raise CommandExecutionError(f"Node {node_name} not found") from exc
            raise

        body = {"metadata": {"annotations": {annotation_name: str(annotation_value)}}}
        api_response = api_instance.patch_node(node_name, body)
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        raise CommandExecutionError(str(exc)) from exc
    finally:
        _cleanup(**cfg)


def node_remove_annotation(node_name, annotation_name, **kwargs):
    """
    Remove an annotation from the named node.

    .. versionadded:: 2.1.0

    Removing an annotation that is not present is a no-op (no error
    raised); the function still returns the live node object.

    node_name
        Name of the node.

    annotation_name
        Annotation key to remove.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.node_remove_annotation node_name="minikube" \
            annotation_name="example.com/owner"
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        # JSON-merge null deletes the key.
        body = {"metadata": {"annotations": {annotation_name: None}}}
        api_response = api_instance.patch_node(node_name, body)
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Node {node_name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def namespaces(**kwargs):
    """
    Return the names of the available namespaces.

    Returns a list of namespace name strings.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.namespaces
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.list_namespace()

        return [
            nms["metadata"]["name"]
            for nms in ApiClient().sanitize_for_serialization(api_response).get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def deployments(namespace="default", **kwargs):
    """
    Return a list of kubernetes deployments defined in the namespace

    namespace
        The namespace to list deployments from. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.deployments
        salt '*' kubernetes.deployments namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.list_namespaced_deployment(namespace)

        serialized_response = ApiClient().sanitize_for_serialization(api_response)
        items = serialized_response.get("items") or []
        return [dep["metadata"]["name"] for dep in items]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def services(namespace="default", **kwargs):
    """
    Return a list of kubernetes services defined in the namespace

    namespace
        The namespace to list services from. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.services
        salt '*' kubernetes.services namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.list_namespaced_service(namespace)

        return [
            srv["metadata"]["name"]
            for srv in ApiClient().sanitize_for_serialization(api_response).get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def pods(namespace="default", **kwargs):
    """
    Return a list of kubernetes pods defined in the namespace

    namespace
        The namespace to list pods from. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.pods
        salt '*' kubernetes.pods namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.list_namespaced_pod(namespace)
        return [
            pod["metadata"]["name"]
            for pod in ApiClient().sanitize_for_serialization(api_response).get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []  # Return empty list for nonexistent namespace
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def secrets(namespace="default", **kwargs):
    """
    Return a list of kubernetes secrets defined in the namespace

    namespace
        The namespace to list secrets from. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.secrets
        salt '*' kubernetes.secrets namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.list_namespaced_secret(namespace)

        return [
            secret["metadata"]["name"]
            for secret in ApiClient().sanitize_for_serialization(api_response).get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def configmaps(namespace="default", **kwargs):
    """
    Return a list of kubernetes configmaps defined in the namespace

    namespace
        The namespace to list configmaps from. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.configmaps
        salt '*' kubernetes.configmaps namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.list_namespaced_config_map(namespace)

        return [
            configmap["metadata"]["name"]
            for configmap in ApiClient().sanitize_for_serialization(api_response).get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []  # Return empty list for nonexistent namespace
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def statefulsets(namespace="default", **kwargs):
    """
    .. versionadded:: 2.1.0

    Return a list of kubernetes statefulsets defined in the namespace

    namespace
        The namespace to list statefulsets from. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.statefulsets
        salt '*' kubernetes.statefulsets namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.list_namespaced_stateful_set(namespace)

        return [
            statefulset["metadata"]["name"]
            for statefulset in ApiClient().sanitize_for_serialization(api_response).get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []  # Return empty list for nonexistent namespace
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replicasets(namespace="default", **kwargs):
    """
    .. versionadded:: 2.1.0

    Return a list of kubernetes replicasets defined in the namespace

    namespace
        The namespace to list replicasets from. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replicasets
        salt '*' kubernetes.replicasets namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.list_namespaced_replica_set(namespace)

        return [
            replicaset["metadata"]["name"]
            for replicaset in ApiClient().sanitize_for_serialization(api_response).get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def daemonsets(namespace="default", **kwargs):
    """
    .. versionadded:: 2.1.0

    Return a list of kubernetes daemonsets defined in the namespace

    namespace
        The namespace to list daemonsets from. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.daemonsets
        salt '*' kubernetes.daemonsets namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.list_namespaced_daemon_set(namespace)

        return [
            daemonset["metadata"]["name"]
            for daemonset in ApiClient().sanitize_for_serialization(api_response).get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def storageclasses(**kwargs):
    """
    .. versionadded:: 2.1.0

    Return a list of kubernetes storageclasses.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.storageclasses
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.StorageV1Api()
        api_response = api_instance.list_storage_class()

        return [
            storageclass["metadata"]["name"]
            for storageclass in ApiClient()
            .sanitize_for_serialization(api_response)
            .get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_deployment(name, namespace="default", **kwargs):
    """
    Return the kubernetes deployment defined by name and namespace

    name
        The name of the deployment

    namespace
        The namespace to look for the deployment. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_deployment my-nginx default
        salt '*' kubernetes.show_deployment name=my-nginx namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.read_namespaced_deployment(name, namespace)

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_service(name, namespace="default", **kwargs):
    """
    Return the kubernetes service defined by name and namespace

    name
        The name of the service

    namespace
        The namespace to look for the service. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_service my-nginx default
        salt '*' kubernetes.show_service name=my-nginx namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.read_namespaced_service(name, namespace)

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_pod(name, namespace="default", **kwargs):
    """
    Return POD information for a given pod name defined in the namespace

    name
        The name of the pod

    namespace
        The namespace to look for the pod. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_pod guestbook-708336848-fqr2x
        salt '*' kubernetes.show_pod guestbook-708336848-fqr2x namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.read_namespaced_pod(name, namespace)

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_namespace(name, **kwargs):
    """
    Return information for a given namespace defined by the specified name

    name
        The name of the namespace to show

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_namespace kube-system
    """
    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.read_namespace(name)
        return ApiClient().sanitize_for_serialization(api_response)
    except ApiException as exc:
        if exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    except HTTPError as exc:
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_secret(name, namespace="default", decode=False, **kwargs):
    """
    Return the kubernetes secret defined by name and namespace.
    The secrets can be decoded if specified by the user. Warning: this has
    security implications.

    name
        The name of the secret

    namespace
        The namespace to look for the secret. Defaults to ``default``.

    decode
        Decode the secret values. Default is False

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_secret confidential default
        salt '*' kubernetes.show_secret name=confidential namespace=default
        salt '*' kubernetes.show_secret name=confidential decode=True
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.read_namespaced_secret(name, namespace)
        response_dict = ApiClient().sanitize_for_serialization(api_response)

        if response_dict.get("data") and decode:
            decoded_data = {}
            for key, value in response_dict["data"].items():
                try:
                    decoded_data[key] = base64.b64decode(value).decode("utf-8")
                except UnicodeDecodeError:
                    decoded_data[key] = base64.b64decode(value)
            response_dict["data"] = decoded_data

        return response_dict
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_configmap(name, namespace="default", **kwargs):
    """
    Return the kubernetes configmap defined by name and namespace.

    name
        The name of the configmap

    namespace
        The namespace to look for the configmap. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_configmap game-config default
        salt '*' kubernetes.show_configmap name=game-config namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.read_namespaced_config_map(name, namespace)

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_statefulset(name, namespace="default", **kwargs):
    """
    .. versionadded:: 2.1.0

    Return the kubernetes statefulset defined by name and namespace.

    name
        The name of the statefulset

    namespace
        The namespace to look for the statefulset. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_statefulset my-statefulset default
        salt '*' kubernetes.show_statefulset name=my-statefulset namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.read_namespaced_stateful_set(name, namespace)

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_replicaset(name, namespace="default", **kwargs):
    """
    .. versionadded:: 2.1.0

    Return the kubernetes replicaset defined by name and namespace.

    name
        The name of the replicaset

    namespace
        The namespace to look for the replicaset. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_replicaset my-replicaset default
        salt '*' kubernetes.show_replicaset name=my-replicaset namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.read_namespaced_replica_set(name, namespace)

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_daemonset(name, namespace="default", **kwargs):
    """
    .. versionadded:: 2.1.0

    Return the kubernetes daemonset defined by name and namespace.

    name
        The name of the daemonset

    namespace
        The namespace to look for the daemonset. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_daemonset my-daemonset default
        salt '*' kubernetes.show_daemonset name=my-daemonset namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.read_namespaced_daemon_set(name, namespace)

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_storageclass(name, **kwargs):
    """
    .. versionadded:: 2.1.0

    Return the kubernetes storageclass defined by name.

    name
        The name of the storageclass

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_storageclass my-storageclass
        salt '*' kubernetes.show_storageclass name=my-storageclass
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.StorageV1Api()
        api_response = api_instance.read_storage_class(name)

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_deployment(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    Deletes the kubernetes deployment defined by name and namespace

    name
        The name of the deployment

    namespace
        The namespace to delete the deployment from. Defaults to ``default``.

    wait
        .. versionadded:: 2.0.0

        Wait for deployment deletion to complete (default: False)

    timeout
        .. versionadded:: 2.0.0

        Timeout in seconds to wait for deletion (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_deployment my-nginx default wait=True
    """
    cfg = _setup_conn(**kwargs)
    body = kubernetes.client.V1DeleteOptions(orphan_dependents=True)

    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.delete_namespaced_deployment(
            name=name, namespace=namespace, body=body
        )

        if wait:
            if not _wait_for_resource_status(
                api_instance, "deployment", name, namespace, "deleted", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for deployment {name} to be deleted")

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_service(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    Deletes the kubernetes service defined by name and namespace

    name
        The name of the service

    namespace
        The namespace to delete the service from. Defaults to ``default``.

    wait
        .. versionadded:: 2.0.0

        Wait for service deletion to complete (default: False)

    timeout
        .. versionadded:: 2.0.0

        Timeout in seconds to wait for deletion (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_service my-nginx default
        salt '*' kubernetes.delete_service name=my-nginx namespace=default
    """
    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.delete_namespaced_service(name=name, namespace=namespace)

        if wait:
            if not _wait_for_resource_status(
                api_instance, "service", name, namespace, "deleted", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for service {name} to be deleted")

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_pod(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    Deletes the kubernetes pod defined by name and namespace

    name
        The name of the pod

    namespace
        The namespace to delete the pod from. Defaults to ``default``.

    wait
        .. versionadded:: 2.0.0

        Wait for pod deletion to complete (default: False)

    timeout
        .. versionadded:: 2.0.0

        Timeout in seconds to wait for deletion (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_pod guestbook-708336848-5nl8c default
        salt '*' kubernetes.delete_pod name=guestbook-708336848-5nl8c namespace=default
    """
    cfg = _setup_conn(**kwargs)
    body = kubernetes.client.V1DeleteOptions(orphan_dependents=True)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.delete_namespaced_pod(name=name, namespace=namespace, body=body)

        if wait:
            if not _wait_for_resource_status(
                api_instance, "pod", name, namespace, "deleted", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for pod {name} to be deleted")

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_namespace(name, wait=False, timeout=60, **kwargs):
    """
    Deletes the kubernetes namespace defined by name

    name
        The name of the namespace

    wait
        .. versionadded:: 2.0.0

        Wait for namespace deletion to complete (default: False)

    timeout
        .. versionadded:: 2.0.0

        Timeout in seconds to wait for deletion (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_namespace salt
        salt '*' kubernetes.delete_namespace name=salt
    """
    cfg = _setup_conn(**kwargs)
    body = kubernetes.client.V1DeleteOptions(orphan_dependents=True)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.delete_namespace(name=name, body=body)

        if wait:
            if not _wait_for_resource_status(
                api_instance, "namespace", name, None, "deleted", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for namespace {name} to be deleted")

        return ApiClient().sanitize_for_serialization(api_response)
    except ApiException as exc:
        if exc.status == 404:
            return None
        if exc.status == 403:
            raise CommandExecutionError(f"Cannot delete namespace {name}: {exc.reason}") from exc
        raise CommandExecutionError(exc) from exc
    except HTTPError as exc:
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_secret(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    Deletes the kubernetes secret defined by name and namespace

    name
        The name of the secret

    namespace
        The namespace to delete the secret from. Defaults to ``default``.

    wait
        .. versionadded:: 2.0.0

        Wait for secret deletion to complete (default: False)

    timeout
        .. versionadded:: 2.0.0

        Timeout in seconds to wait for deletion (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_secret confidential default
        salt '*' kubernetes.delete_secret name=confidential namespace=default
    """
    cfg = _setup_conn(**kwargs)
    body = kubernetes.client.V1DeleteOptions(orphan_dependents=True)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.delete_namespaced_secret(
            name=name, namespace=namespace, body=body
        )

        if wait:
            if not _wait_for_resource_status(
                api_instance, "secret", name, namespace, "deleted", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for secret {name} to be deleted")

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_configmap(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    Deletes the kubernetes configmap defined by name and namespace

    name
        The name of the configmap

    namespace
        The namespace to delete the configmap from. Defaults to ``default``.

    wait
        .. versionadded:: 2.0.0

        Wait for configmap deletion to complete (default: False)

    timeout
        .. versionadded:: 2.0.0

        Timeout in seconds to wait for deletion (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_configmap settings default
        salt '*' kubernetes.delete_configmap name=settings namespace=default
    """
    cfg = _setup_conn(**kwargs)
    body = kubernetes.client.V1DeleteOptions(orphan_dependents=True)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.delete_namespaced_config_map(
            name=name, namespace=namespace, body=body
        )

        if wait:
            if not _wait_for_resource_status(
                api_instance, "configmap", name, namespace, "deleted", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for configmap {name} to be deleted")

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_statefulset(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    .. versionadded:: 2.1.0

    Deletes the kubernetes statefulset defined by name and namespace

    name
        The name of the statefulset

    namespace
        The namespace to delete the statefulset from. Defaults to ``default``.

    wait
        Wait for statefulset deletion to complete (default: False)

    timeout
        Timeout in seconds to wait for deletion (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_statefulset my-statefulset default
        salt '*' kubernetes.delete_statefulset name=my-statefulset namespace=default
    """
    cfg = _setup_conn(**kwargs)
    body = kubernetes.client.V1DeleteOptions(orphan_dependents=True)

    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.delete_namespaced_stateful_set(
            name=name, namespace=namespace, body=body
        )

        if wait:
            if not _wait_for_resource_status(
                api_instance, "statefulset", name, namespace, "deleted", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for statefulset {name} to be deleted")

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_replicaset(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    .. versionadded:: 2.1.0

    Deletes the kubernetes replicaset defined by name and namespace

    name
        The name of the replicaset

    namespace
        The namespace to delete the replicaset from. Defaults to ``default``.

    wait
        Wait for replicaset deletion to complete (default: False)

    timeout
        Timeout in seconds to wait for deletion (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_replicaset my-replicaset default
        salt '*' kubernetes.delete_replicaset name=my-replicaset namespace=default
    """
    cfg = _setup_conn(**kwargs)
    body = kubernetes.client.V1DeleteOptions(orphan_dependents=True)

    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.delete_namespaced_replica_set(
            name=name, namespace=namespace, body=body
        )

        if wait:
            if not _wait_for_resource_status(
                api_instance, "replicaset", name, namespace, "deleted", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for replicaset {name} to be deleted")

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_daemonset(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    .. versionadded:: 2.1.0

    Deletes the kubernetes daemonset defined by name and namespace

    name
        The name of the daemonset

    namespace
        The namespace to delete the daemonset from. Defaults to ``default``.

    wait
        Wait for daemonset deletion to complete (default: False)

    timeout
        Timeout in seconds to wait for deletion (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_daemonset my-daemonset default
        salt '*' kubernetes.delete_daemonset name=my-daemonset namespace=default
    """
    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.AppsV1Api()
        # No explicit V1DeleteOptions body — the API server's default
        # ``propagationPolicy=Background`` cleans up child pods, matching
        # ``kubectl delete daemonset`` behaviour. The deprecated
        # ``orphan_dependents=True`` field was previously hard-wired here;
        # K8s 1.7+ replaces it with propagationPolicy and orphaning a
        # daemonset's pods is rarely what callers want anyway.
        api_response = api_instance.delete_namespaced_daemon_set(name=name, namespace=namespace)

        if wait:
            if not _wait_for_resource_status(
                api_instance, "daemonset", name, namespace, "deleted", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for daemonset {name} to be deleted")

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_storageclass(name, wait=False, timeout=60, **kwargs):
    """
    .. versionadded:: 2.1.0

    Deletes the kubernetes storageclass defined by name

    name
        The name of the storageclass

    wait
        Wait for storageclass deletion to complete (default: False)

    timeout
        Timeout in seconds to wait for deletion (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_storageclass my-storageclass
        salt '*' kubernetes.delete_storageclass name=my-storageclass
    """
    cfg = _setup_conn(**kwargs)
    body = kubernetes.client.V1DeleteOptions(orphan_dependents=True)

    try:
        api_instance = kubernetes.client.StorageV1Api()
        api_response = api_instance.delete_storage_class(name=name, body=body)

        if wait:
            if not _wait_for_resource_status(
                api_instance, "storageclass", name, None, "deleted", timeout
            ):
                raise CommandExecutionError(
                    f"Timeout waiting for storageclass {name} to be deleted"
                )

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def create_deployment(
    name,
    namespace,
    metadata,
    spec,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    Creates the kubernetes deployment as defined by the user.

    name
        The name of the deployment

    namespace
        The namespace to create the deployment in

    metadata
        Deployment metadata dict

    spec
        Deployment spec dict following kubernetes API conventions

    source
        File path to deployment definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

        .. versionchanged:: 2.0.0
            Defaults to the value of the :conf_minion:`saltenv` minion option or ``base``.

    template_context
        .. versionadded:: 2.0.0

        Variables to make available in templated files

    dry_run
        .. versionadded:: 2.0.0

        If True, only simulates the creation of the deployment

    wait
        .. versionadded:: 2.0.0

        Wait for deployment to become ready (default: False)

    timeout
        .. versionadded:: 2.0.0

        Timeout in seconds to wait for deployment (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_deployment name=nginx namespace=default spec='{"replicas": 1}' wait=True
    """
    body = __create_object_body(
        kind="Deployment",
        obj_class=V1Deployment,
        spec_creator=__dict_to_deployment_spec,
        name=name,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        source=source,
        template=template,
        saltenv=saltenv,
        template_context=template_context,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.create_namespaced_deployment(
            namespace, body, dry_run="All" if dry_run else None
        )

        if wait:
            if not _wait_for_resource_status(
                api_instance, "deployment", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(
                    f"Timeout waiting for deployment {name} to become ready"
                )

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException):
            if exc.status == 404:
                raise CommandExecutionError(f"Deployment {namespace}/{name} not found") from exc
            if exc.status == 409:
                raise CommandExecutionError(f"Deployment {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def create_pod(
    name,
    namespace,
    metadata,
    spec,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    Creates a kubernetes pod as defined by the user.

    name
        The name of the pod

    namespace
        The namespace to create the pod in

    metadata
        Pod metadata dict

    spec
        Pod spec dict following kubernetes API conventions

    source
        File path to pod definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

        .. versionchanged:: 2.0.0
            Defaults to the value of the :conf_minion:`saltenv` minion option or ``base``.

    template_context
        .. versionadded:: 2.0.0

        Variables to make available in templated files

    wait
        .. versionadded:: 2.0.0

        Wait for pod to become ready (default: False)

    timeout
        .. versionadded:: 2.0.0

        Timeout in seconds to wait for pod (default: 60)

    Pod spec must follow kubernetes API conventions:

    .. code-block:: yaml

        - spec:
            ports:
            - containerPort: 8080
                name: http
                protocol: TCP

    CLI Examples:

    .. code-block:: bash

        salt '*' kubernetes.create_pod name=nginx namespace=default spec='{"containers": [{"name": "nginx", "image": "nginx"}]}'
    """
    body = __create_object_body(
        kind="Pod",
        obj_class=kubernetes.client.V1Pod,
        spec_creator=__dict_to_pod_spec,
        name=name,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        source=source,
        template=template,
        saltenv=saltenv,
        template_context=template_context,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.create_namespaced_pod(namespace, body)

        if wait:
            if not _wait_for_resource_status(
                api_instance, "pod", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for pod {name} to become ready")

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException):
            if exc.status == 404:
                raise CommandExecutionError(f"Pod {namespace}/{name} not found") from exc
            if exc.status == 409:
                raise CommandExecutionError(f"Pod {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def create_service(
    name,
    namespace,
    metadata,
    spec,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    Creates the kubernetes service as defined by the user.

    name
        The name of the service

    namespace
        The namespace to create the service in

    metadata
        Service metadata dict

    spec
        Service spec dict that follows kubernetes API conventions

    source
        File path to service definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

        .. versionchanged:: 2.0.0
            Defaults to the value of the :conf_minion:`saltenv` minion option or ``base``.

    template_context
        .. versionadded:: 2.0.0

        Variables to make available in templated files

    wait
        .. versionadded:: 2.0.0

        Wait for service to become ready (default: False)

    timeout
        .. versionadded:: 2.0.0

        Timeout in seconds to wait for service (default: 60)

    Service spec must follow kubernetes API conventions. Port specifications can be:

    Simple integer for basic port definition: ``[80, 443]``

    Dictionary for advanced configuration:

    .. code-block:: yaml

        - spec:
            ports:
              - port: 80
                targetPort: 8080
                name: http    # Required if multiple ports are specified
              - port: 443
                targetPort: web-https  # targetPort can reference container port names
                name: https
                nodePort: 30443       # nodePort must be between 30000-32767

    CLI Examples:

    .. code-block:: bash

        salt '*' kubernetes.create_service name=nginx namespace=default spec='{"ports": [80]}'

        salt '*' kubernetes.create_service name=nginx namespace=default spec='{
            "ports": [{"port": 80, "targetPort": 8000, "name": "http"}],
            "selector": {"app": "nginx"},
            "type": "LoadBalancer"
        }'
    """
    body = __create_object_body(
        kind="Service",
        obj_class=kubernetes.client.V1Service,
        spec_creator=__dict_to_service_spec,
        name=name,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        source=source,
        template=template,
        saltenv=saltenv,
        template_context=template_context,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.create_namespaced_service(
            namespace, body, dry_run="All" if dry_run else None
        )

        if wait:
            if not _wait_for_resource_status(
                api_instance, "service", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for service {name} to become ready")

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException):
            if exc.status == 404:
                raise CommandExecutionError(f"Service {namespace}/{name} not found") from exc
            if exc.status == 409:
                raise CommandExecutionError(f"Service {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def create_secret(
    name,
    namespace="default",
    data=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    secret_type=None,
    metadata=None,
    dry_run=False,
    wait=False,
    timeout=60,
    append_hash=False,
    **kwargs,
):
    """
    Creates the kubernetes secret as defined by the user.
    Values that are already base64 encoded will not be re-encoded.

    .. note::
        Automatic encoding of secret values might cause issues if the values are not correctly identified as base64.
        If you run into issues - encode the values before passing them to this function.

    name
        The name of the secret

    namespace
        The namespace to create the secret in. Defaults to ``default``.

    data
        A dictionary of key-value pairs to store in the secret

    source
        File path to secret definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

        .. versionchanged:: 2.0.0
            Defaults to the value of the :conf_minion:`saltenv` minion option or ``base``.

    template_context
        .. versionadded:: 2.0.0

        Variables to make available in templated files

    secret_type
        .. versionadded:: 2.0.0

        The type of the secret

    metadata
        .. versionadded:: 2.0.0

        Secret metadata dict

    wait
        .. versionadded:: 2.0.0

        Wait for secret to become ready (default: False)

    timeout
        .. versionadded:: 2.0.0

        Timeout in seconds to wait for secret (default: 60)

    CLI Example:

    .. code-block:: bash

        # For regular secrets with plain text values
        salt 'minion1' kubernetes.create_secret \
            passwords default '{"db": "letmein"}'

        # For secrets with pre-encoded values
        salt 'minion2' kubernetes.create_secret \
            name=passwords namespace=default data='{"db": "bGV0bWVpbg=="}'

        # For docker registry secrets
        salt 'minion3' kubernetes.create_secret \
            name=docker-registry \
            type=kubernetes.io/dockerconfigjson \
            data='{".dockerconfigjson": "{\"auths\":{...}}"}'

        # For TLS secrets
        salt 'minion4' kubernetes.create_secret \
            name=tls-secret \
            type=kubernetes.io/tls \
            data='{"tls.crt": "...", "tls.key": "..."}'
    """
    cfg = _setup_conn(**kwargs)
    if source:
        src_obj = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if not isinstance(src_obj, dict):
            raise CommandExecutionError("`source` did not render to a dictionary")
        if "data" in src_obj:
            data = src_obj["data"]
        secret_type = src_obj.get("secret_type")
    elif data is None:
        data = {}

    data = __enforce_only_strings_dict(data)

    # Encode the secrets using base64 if not already encoded
    encoded_data = {}
    for key, value in data.items():
        if __is_base64(value):
            encoded_data[key] = value
        else:
            encoded_data[key] = base64.b64encode(str(value).encode("utf-8")).decode("utf-8")

    # ``append_hash`` makes the resulting object effectively immutable:
    # any change to data produces a new name, so consumers (Deployments
    # mounting the secret) trigger a rollout on data drift instead of
    # silently picking up new values. Mirrors kubectl/Ansible behaviour.
    if append_hash:
        name = f"{name}-{_hash_suffix(encoded_data, secret_type or '')}"

    body = kubernetes.client.V1Secret(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        data=encoded_data,
        type=secret_type,
    )

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.create_namespaced_secret(
            namespace, body, dry_run="All" if dry_run else None
        )

        if wait:
            if not _wait_for_resource_status(
                api_instance, "secret", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for secret {name} to become ready")

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException):
            if exc.status == 409:
                raise CommandExecutionError(
                    f"Secret {name} already exists in namespace {namespace}. Use replace_secret to update it."
                ) from exc
            if exc.status == 404:
                raise CommandExecutionError(f"Secret {namespace}/{name} not found") from exc
        raise CommandExecutionError(str(exc)) from exc
    finally:
        _cleanup(**cfg)


def create_configmap(
    name,
    namespace,
    data,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    wait=False,
    timeout=60,
    append_hash=False,
    **kwargs,
):
    """
    Creates the kubernetes configmap as defined by the user.

    name
        The name of the configmap

    namespace
        The namespace to create the configmap in

    data
        A dictionary of key-value pairs to store in the configmap

    source
        File path to configmap definition

        .. versionchanged:: 2.0.0
            The configmap definition must be a proper spec with the configmap data in
            the ``data`` key. In previous versions, the rendered output was used as the
            data directly.

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

        .. versionchanged:: 2.0.0
            Defaults to the value of the :conf_minion:`saltenv` minion option or ``base``.

    template_context
        .. versionadded:: 2.0.0

        Variables to make available in templated files

    wait
        .. versionadded:: 2.0.0

        Wait for configmap to become ready (default: False)

    timeout
        .. versionadded:: 2.0.0

        Timeout in seconds to wait for configmap (default: 60)

    CLI Example:

    .. code-block:: bash

        salt 'minion1' kubernetes.create_configmap \
            settings default '{"example.conf": "# example file"}'

        salt 'minion2' kubernetes.create_configmap \
            name=settings namespace=default data='{"example.conf": "# example file"}'
    """
    if source:
        rendered = __read_and_render_yaml_file(source, template, saltenv, template_context)
        try:
            data = rendered["data"]
        except KeyError as err:
            raise CommandExecutionError(
                f"The template for configmap '{name}' (at '{source}') did not render to a spec: Missing `data` key."
            ) from err
        except TypeError as err:
            raise CommandExecutionError(
                f"The template for configmap '{name}' (at '{source}') did not render to a spec: Expected mapping, got '{type(rendered).__name__}'."
            ) from err
    elif data is None:
        data = {}

    if not isinstance(data, dict):
        raise CommandExecutionError("Data must be a dictionary")

    data = __enforce_only_strings_dict(data)

    # See ``create_secret`` for the rationale behind ``append_hash``.
    if append_hash:
        name = f"{name}-{_hash_suffix(data)}"

    body = kubernetes.client.V1ConfigMap(
        metadata=__dict_to_object_meta(name, namespace, {}), data=data
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.create_namespaced_config_map(
            namespace, body, dry_run="All" if dry_run else None
        )

        if wait:
            if not _wait_for_resource_status(
                api_instance, "configmap", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for configmap {name} to become ready")

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException):
            if exc.status == 404:
                raise CommandExecutionError(f"ConfigMap {namespace}/{name} not found") from exc
            if exc.status == 409:
                raise CommandExecutionError(f"ConfigMap {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def create_namespace(name, **kwargs):
    """
    Creates a namespace with the specified name.

    name
        The name of the namespace to create

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_namespace salt
        salt '*' kubernetes.create_namespace name=salt
    """
    meta_obj = kubernetes.client.V1ObjectMeta(name=name)
    body = kubernetes.client.V1Namespace(metadata=meta_obj)
    body.metadata.name = name

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.create_namespace(body)
        return ApiClient().sanitize_for_serialization(api_response)
    except ApiException as exc:
        if exc.status == 409:
            raise CommandExecutionError(f"Namespace {name} already exists: {exc.reason}") from exc
        if exc.status == 422:
            raise CommandExecutionError(f"Invalid namespace name {name}: {exc.reason}") from exc
        raise CommandExecutionError(exc) from exc
    except HTTPError as exc:
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def create_statefulset(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    .. versionadded:: 2.1.0

    Creates a statefulset with the specified name, namespace, metadata, and spec.

    name
        The name of the statefulset

    namespace
        The namespace to create the statefulset in. Defaults to ``default``.

    metadata
        StatefulSet metadata dict

    spec
        StatefulSet spec dict following kubernetes API conventions

    source
        File path to statefulset definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

    template_context
        Variables to make available in templated files

    dry_run
        If True, only simulates the creation of the statefulset

    wait
        Wait for statefulset to become ready (default: False)

    timeout
        Timeout in seconds to wait for statefulset (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_statefulset name=my-statefulset namespace=default spec='{"replicas": 3}' wait=True
    """
    body = __create_object_body(
        kind="StatefulSet",
        obj_class=kubernetes.client.V1StatefulSet,
        spec_creator=__dict_to_statefulset_spec,
        name=name,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        source=source,
        template=template,
        saltenv=saltenv,
        template_context=template_context,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.create_namespaced_stateful_set(
            namespace, body, dry_run="All" if dry_run else None
        )

        if wait:
            if not _wait_for_resource_status(
                api_instance, "statefulset", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(
                    f"Timeout waiting for statefulset {name} to become ready"
                )

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException):
            if exc.status == 404:
                raise CommandExecutionError(f"StatefulSet {namespace}/{name} not found") from exc
            if exc.status == 409:
                raise CommandExecutionError(f"StatefulSet {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def create_replicaset(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    .. versionadded:: 2.1.0

    Creates a replicaset with the specified name, namespace, metadata, and spec.

    name
        The name of the replicaset

    namespace
        The namespace to create the replicaset in. Defaults to ``default``.

    metadata
        ReplicaSet metadata dict

    spec
        ReplicaSet spec dict following kubernetes API conventions

    source
        File path to replicaset definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

    template_context
        Variables to make available in templated files

    dry_run
        If True, only simulates the creation of the replicaset

    wait
        Wait for replicaset to become ready (default: False)

    timeout
        Timeout in seconds to wait for replicaset (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_replicaset name=my-rs namespace=default spec='{"replicas": 3}' wait=True
    """
    body = __create_object_body(
        kind="ReplicaSet",
        obj_class=kubernetes.client.V1ReplicaSet,
        spec_creator=__dict_to_replicaset_spec,
        name=name,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        source=source,
        template=template,
        saltenv=saltenv,
        template_context=template_context,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.create_namespaced_replica_set(
            namespace, body, dry_run="All" if dry_run else None
        )

        if wait:
            if not _wait_for_resource_status(
                api_instance, "replicaset", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(
                    f"Timeout waiting for replicaset {name} to become ready"
                )

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException):
            if exc.status == 404:
                raise CommandExecutionError(f"ReplicaSet {namespace}/{name} not found") from exc
            if exc.status == 409:
                raise CommandExecutionError(f"ReplicaSet {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def create_daemonset(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    .. versionadded:: 2.1.0

    Creates a daemonset with the specified name, namespace, metadata, and spec.

    name
        The name of the daemonset

    namespace
        The namespace to create the daemonset in. Defaults to ``default``.

    metadata
        DaemonSet metadata dict

    spec
        DaemonSet spec dict following kubernetes API conventions

    source
        File path to daemonset definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

    template_context
        Variables to make available in templated files

    dry_run
        If True, only simulates the creation of the daemonset

    wait
        Wait for daemonset to become ready (default: False)

    timeout
        Timeout in seconds to wait for daemonset (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_daemonset name=my-ds namespace=default wait=True
    """
    body = __create_object_body(
        kind="DaemonSet",
        obj_class=kubernetes.client.V1DaemonSet,
        spec_creator=__dict_to_daemonset_spec,
        name=name,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        source=source,
        template=template,
        saltenv=saltenv,
        template_context=template_context,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.create_namespaced_daemon_set(
            namespace, body, dry_run="All" if dry_run else None
        )

        if wait:
            if not _wait_for_resource_status(
                api_instance, "daemonset", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for daemonset {name} to become ready")

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException):
            if exc.status == 404:
                raise CommandExecutionError(f"DaemonSet {namespace}/{name} not found") from exc
            if exc.status == 409:
                raise CommandExecutionError(f"DaemonSet {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def create_storageclass(
    name,
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    .. versionadded:: 2.1.0

    Creates a storageclass with the specified name, metadata, and spec.

    name
        The name of the storageclass

    metadata
        StorageClass metadata dict

    spec
        StorageClass spec dict following kubernetes API conventions

    source
        File path to storageclass definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

    template_context
        Variables to make available in templated files

    dry_run
        If True, only simulates the creation of the storageclass

    wait
        Wait for storageclass to become ready (default: False)

    timeout
        Timeout in seconds to wait for storageclass (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_storageclass name=fast-sc spec='{"provisioner": "kubernetes.io/no-provisioner"}'
    """
    if source:
        src_obj = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if not isinstance(src_obj, dict) or src_obj.get("kind") != "StorageClass":
            raise CommandExecutionError("The source file should define only a StorageClass object")

        if "metadata" in src_obj:
            metadata = src_obj["metadata"]
        if "spec" in src_obj:
            spec = src_obj["spec"]
        elif spec is None:
            spec = {
                key: value
                for key, value in src_obj.items()
                if key not in ("apiVersion", "kind", "metadata")
            }

    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}

    created_spec = __dict_to_storageclass_spec(spec)
    body = kubernetes.client.V1StorageClass(
        metadata=__dict_to_object_meta(name, None, metadata),
        **created_spec,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.StorageV1Api()
        api_response = api_instance.create_storage_class(body, dry_run="All" if dry_run else None)

        if wait:
            if not _wait_for_resource_status(
                api_instance, "storageclass", name, None, "ready", timeout
            ):
                raise CommandExecutionError(
                    f"Timeout waiting for storageclass {name} to become ready"
                )

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException):
            if exc.status == 404:
                raise CommandExecutionError(f"StorageClass {name} not found") from exc
            if exc.status == 409:
                raise CommandExecutionError(f"StorageClass {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_deployment(
    name,
    metadata,
    spec,
    source=None,
    template=None,
    saltenv=None,
    namespace="default",
    template_context=None,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    Replaces an existing deployment with a new one defined by name and
    namespace, having the specificed metadata and spec.

    name
        The name of the deployment

    metadata
        Deployment metadata dict

    spec
        Deployment spec dict following kubernetes API conventions

    source
        File path to deployment definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

        .. versionchanged:: 2.0.0
            Defaults to the value of the :conf_minion:`saltenv` minion option or ``base``.

    namespace
        The namespace to replace the deployment in. Defaults to ``default``.

    template_context
        .. versionadded:: 2.0.0

        Variables to make available in templated files

    wait
        .. versionadded:: 2.0.0

        Wait for deployment to become ready (default: False)

    timeout
        .. versionadded:: 2.0.0

        Timeout in seconds to wait for deployment (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replace_deployment *args
    """
    body = __create_object_body(
        kind="Deployment",
        obj_class=V1Deployment,
        spec_creator=__dict_to_deployment_spec,
        name=name,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        source=source,
        template=template,
        saltenv=saltenv,
        template_context=template_context,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.replace_namespaced_deployment(name, namespace, body)

        if wait:
            if not _wait_for_resource_status(
                api_instance, "deployment", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(
                    f"Timeout waiting for deployment {name} to become ready"
                )

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Deployment {namespace}/{name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_service(
    name,
    old_service,
    metadata,
    spec,
    source=None,
    template=None,
    saltenv=None,
    namespace="default",
    template_context=None,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    .. versionchanged:: 2.0.0
        The `old_service` parameter was moved to the second position,
        which pushes `metadata`, `spec`, `source` and `template` one position
        further down the parameter list.

    Replaces an existing service with a new one defined by name and namespace,
    having the specified metadata and spec.

    name
        The name of the service

    old_service
        The existing service to replace

    metadata
        Service metadata dict

    spec
        Service spec dict following kubernetes API conventions

    source
        File path to service definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

        .. versionchanged:: 2.0.0
            Defaults to the value of the :conf_minion:`saltenv` minion option or ``base``.

    namespace
        The namespace to replace the service in. Defaults to ``default``.

    template_context
        .. versionadded:: 2.0.0

        Variables to make available in templated files

    wait
        .. versionadded:: 2.0.0

        Wait for service to become ready (default: False)

    timeout
        .. versionadded:: 2.0.0

        Timeout in seconds to wait for service (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replace_service name=my-service \
            old_service='{"metadata": {"resourceVersion": "12345"}, "spec": {"clusterIP": "10.0.0.1"}}' \
            metadata='{"labels": {"app": "my-app"}}' \
            spec='{"ports": [{"port": 80, "targetPort": 8080}], "selector": {"app": "my-app"}}' \
            source=/path/to/service.yaml \
            template=jinja \
            saltenv=base \
            namespace=default \
            template_context='{"var1": "value1"}'
    """
    body = __create_object_body(
        kind="Service",
        obj_class=kubernetes.client.V1Service,
        spec_creator=__dict_to_service_spec,
        name=name,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        source=source,
        template=template,
        saltenv=saltenv,
        template_context=template_context,
    )

    # Some attributes have to be preserved
    # otherwise exceptions will be thrown
    body.spec.cluster_ip = old_service["spec"]["clusterIP"]
    body.metadata.resource_version = old_service["metadata"]["resourceVersion"]

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.replace_namespaced_service(name, namespace, body)

        if wait:
            if not _wait_for_resource_status(
                api_instance, "service", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for service {name} to become ready")

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Service {namespace}/{name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_secret(
    name,
    data,
    source=None,
    template=None,
    saltenv=None,
    namespace="default",
    template_context=None,
    secret_type=None,
    metadata=None,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    Replaces an existing secret with a new one defined by name and namespace.
    Values that are already base64 encoded will not be re-encoded.
    If a source file is specified, the secret type will be read from the template.

    .. note::
        Automatic encoding of secret values might cause issues if the values are not correctly identified as base64.
        If you run into issues - encode the values before passing them to this function.

    name
        The name of the secret

    data
        A dictionary of key-value pairs to store in the secret

    source
        File path to secret definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

        .. versionchanged:: 2.0.0
            Defaults to the value of the :conf_minion:`saltenv` minion option or ``base``.

    namespace
        The namespace to replace the secret in. Defaults to ``default``.

    template_context
        .. versionadded:: 2.0.0

        Variables to make available in templated files

    secret_type
        .. versionadded:: 2.0.0

        The type of the secret

    metadata
        .. versionadded:: 2.0.0

        Secret metadata dict

    wait
        .. versionadded:: 2.0.0

        Wait for secret to become ready (default: False)

    timeout
        .. versionadded:: 2.0.0

        Timeout in seconds to wait for secret (default: 60)

    CLI Example:

    .. code-block:: bash

        # For regular secrets with plain text values
        salt 'minion1' kubernetes.replace_secret \
            name=passwords data='{"db": "letmein"}'

        # For secrets with pre-encoded values
        salt 'minion2' kubernetes.replace_secret \
            name=passwords data='{"db": "bGV0bWVpbg=="}'

        # For docker registry secrets
        salt 'minion3' kubernetes.replace_secret \
            name=docker-registry \
            source=/path/to/docker-secret.yaml \
            secret_type=kubernetes.io/dockerconfigjson

        # For TLS secrets
        salt 'minion4' kubernetes.replace_secret \
            name=tls-secret \
            source=/path/to/tls-secret.yaml \
            secret_type=kubernetes.io/tls
    """
    if source:
        src_obj = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if not isinstance(src_obj, dict):
            raise CommandExecutionError("`source` did not render to a dictionary")
        if "data" in src_obj:
            data = src_obj["data"]
        secret_type = src_obj.get("secret_type")
    elif data is None:
        data = {}

    data = __enforce_only_strings_dict(data)

    # Encode the secrets using base64 if not already encoded
    encoded_data = {}
    for key, value in data.items():
        if __is_base64(value):
            encoded_data[key] = value
        else:
            encoded_data[key] = base64.b64encode(str(value).encode("utf-8")).decode("utf-8")

    # Get existing secret type if not specified
    if not type:
        existing_secret = kubernetes.client.CoreV1Api().read_namespaced_secret(name, namespace)
        secret_type = existing_secret.type

    body = kubernetes.client.V1Secret(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        data=encoded_data,
        type=secret_type,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.replace_namespaced_secret(name, namespace, body)

        if wait:
            if not _wait_for_resource_status(
                api_instance, "secret", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for secret {name} to be ready")

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Secret {namespace}/{name} not found") from exc
        raise CommandExecutionError(str(exc)) from exc
    finally:
        _cleanup(**cfg)


def replace_configmap(
    name,
    data,
    source=None,
    template=None,
    saltenv=None,
    namespace="default",
    template_context=None,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    Replaces an existing configmap with a new one defined by name and
    namespace with the specified data.

    name
        The name of the configmap

    data
        A dictionary of key-value pairs to store in the configmap

    source
        File path to configmap definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

        .. versionchanged:: 2.0.0
            Defaults to the value of the :conf_minion:`saltenv` minion option or ``base``.

    namespace
        The namespace to replace the configmap in. Defaults to ``default``.

    template_context
        .. versionadded:: 2.0.0

        Variables to make available in templated files

    wait
        .. versionadded:: 2.0.0

        Wait for configmap to become ready (default: False)

    timeout
        .. versionadded:: 2.0.0

        Timeout in seconds to wait for configmap (default: 60)

    CLI Example:

    .. code-block:: bash

        salt 'minion1' kubernetes.replace_configmap \
            settings default '{"example.conf": "# example file"}'

        salt 'minion2' kubernetes.replace_configmap \
            name=settings namespace=default data='{"example.conf": "# example file"}'
    """
    if source:
        data = __read_and_render_yaml_file(source, template, saltenv, template_context)

    data = __enforce_only_strings_dict(data)

    body = kubernetes.client.V1ConfigMap(
        metadata=__dict_to_object_meta(name, namespace, {}), data=data
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.replace_namespaced_config_map(name, namespace, body)

        if wait:
            if not _wait_for_resource_status(
                api_instance, "configmap", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for configmap {name} to be ready")

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"ConfigMap {namespace}/{name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_statefulset(
    name,
    namespace,
    spec,
    metadata=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    .. versionadded:: 2.1.0

    Replaces an existing statefulset with a new one defined by name and
    namespace with the specified spec.

    name
        The name of the statefulset

    namespace
        The namespace of the statefulset

    spec
        A dictionary representing the spec of the statefulset

    metadata
        A dictionary representing the metadata of the statefulset

    source
        File path to statefulset definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

    template_context
        Variables to make available in templated files

    wait
        Wait for statefulset to become ready (default: False)

    timeout
        Timeout in seconds to wait for statefulset (default: 60)

    CLI Example:

    .. code-block:: bash

        salt 'minion1' kubernetes.replace_statefulset \
            name=my-statefulset namespace=default spec='{"replicas": 3}'
    """
    body = __create_object_body(
        kind="StatefulSet",
        obj_class=kubernetes.client.V1StatefulSet,
        spec_creator=__dict_to_statefulset_spec,
        name=name,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        source=source,
        template=template,
        saltenv=saltenv,
        template_context=template_context,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.replace_namespaced_stateful_set(name, namespace, body)

        if wait:
            if not _wait_for_resource_status(
                api_instance, "statefulset", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(
                    f"Timeout waiting for statefulset {name} to become ready"
                )

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"StatefulSet {namespace}/{name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_replicaset(
    name,
    namespace,
    spec,
    metadata=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    .. versionadded:: 2.1.0

    Replaces an existing replicaset with a new one defined by name and
    namespace with the specified spec.

    name
        The name of the replicaset

    namespace
        The namespace of the replicaset

    spec
        A dictionary representing the spec of the replicaset

    metadata
        A dictionary representing the metadata of the replicaset

    source
        File path to replicaset definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

    template_context
        Variables to make available in templated files

    wait
        Wait for replicaset to become ready (default: False)

    timeout
        Timeout in seconds to wait for replicaset (default: 60)

    CLI Example:

    .. code-block:: bash

        salt 'minion1' kubernetes.replace_replicaset \
            name=my-replicaset namespace=default spec='{"replicas": 3}'
    """
    body = __create_object_body(
        kind="ReplicaSet",
        obj_class=kubernetes.client.V1ReplicaSet,
        spec_creator=__dict_to_replicaset_spec,
        name=name,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        source=source,
        template=template,
        saltenv=saltenv,
        template_context=template_context,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.replace_namespaced_replica_set(name, namespace, body)

        if wait:
            if not _wait_for_resource_status(
                api_instance, "replicaset", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(
                    f"Timeout waiting for replicaset {name} to become ready"
                )

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"ReplicaSet {namespace}/{name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_daemonset(
    name,
    namespace,
    spec,
    metadata=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    .. versionadded:: 2.1.0

    Replaces an existing daemonset with a new one defined by name and
    namespace with the specified spec.

    name
        The name of the daemonset

    namespace
        The namespace of the daemonset

    spec
        A dictionary representing the spec of the daemonset

    metadata
        A dictionary representing the metadata of the daemonset

    source
        File path to daemonset definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

    template_context
        Variables to make available in templated files

    wait
        Wait for daemonset to become ready (default: False)

    timeout
        Timeout in seconds to wait for daemonset (default: 60)

    CLI Example:

    .. code-block:: bash

        salt 'minion1' kubernetes.replace_daemonset \
            name=my-daemonset namespace=default spec='{"replicas": 3}'
    """
    body = __create_object_body(
        kind="DaemonSet",
        obj_class=kubernetes.client.V1DaemonSet,
        spec_creator=__dict_to_daemonset_spec,
        name=name,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        source=source,
        template=template,
        saltenv=saltenv,
        template_context=template_context,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.replace_namespaced_daemon_set(name, namespace, body)

        if wait:
            if not _wait_for_resource_status(
                api_instance, "daemonset", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for daemonset {name} to become ready")

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"DaemonSet {namespace}/{name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_storageclass(
    name,
    spec,
    metadata=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    .. versionadded:: 2.1.0

    Replaces an existing storageclass with a new one defined by name.

    name
        The name of the storageclass

    spec
        A dictionary representing the spec of the storageclass

    metadata
        A dictionary representing the metadata of the storageclass

    source
        File path to storageclass definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

    template_context
        Variables to make available in templated files

    wait
        Wait for storageclass to become ready (default: False)

    timeout
        Timeout in seconds to wait for storageclass (default: 60)

    CLI Example:

    .. code-block:: bash

        salt 'minion1' kubernetes.replace_storageclass \
            name=my-storageclass spec='{"provisioner": "kubernetes.io/no-provisioner"}'
    """
    if source:
        src_obj = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if not isinstance(src_obj, dict) or src_obj.get("kind") != "StorageClass":
            raise CommandExecutionError("The source file should define only a StorageClass object")

        if "metadata" in src_obj:
            metadata = src_obj["metadata"]
        if "spec" in src_obj:
            spec = src_obj["spec"]
        elif spec is None:
            spec = {
                key: value
                for key, value in src_obj.items()
                if key not in ("apiVersion", "kind", "metadata")
            }

    if metadata is None:
        metadata = {}

    created_spec = __dict_to_storageclass_spec(spec)
    body = kubernetes.client.V1StorageClass(
        metadata=__dict_to_object_meta(name, None, metadata),
        **created_spec,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.StorageV1Api()
        current_storageclass = api_instance.read_storage_class(name)
        body.metadata.resource_version = current_storageclass.metadata.resource_version
        api_response = api_instance.replace_storage_class(name, body)

        if wait:
            if not _wait_for_resource_status(
                api_instance, "storageclass", name, None, "ready", timeout
            ):
                raise CommandExecutionError(
                    f"Timeout waiting for storageclass {name} to become ready"
                )

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"StorageClass {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_service(
    name,
    namespace,
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    .. versionadded:: 2.0.0

    Patches an existing service with the provided patch dictionary.

    name
        The name of the service

    namespace
        The namespace of the service

    patch
        A dictionary representing the patch to apply to the service

    source
        File path to patch definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

    template_context
        Variables to make available in templated files

    dry_run
        If True, only simulates the patch without applying it (default: False)

    wait
        Wait for service to become ready (default: False)

    timeout
        Timeout in seconds to wait for service (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_service \\
            name=my-service \\
            namespace=default \\
            patch='{"spec": {"type": "LoadBalancer"}}'
    """
    if source:
        rendered = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if not isinstance(rendered, dict):
            raise CommandExecutionError("The source file did not render to a dictionary")
        patch = rendered

    if not isinstance(patch, dict):
        raise CommandExecutionError("Patch must be a dictionary")

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.patch_namespaced_service(
            name, namespace, patch, dry_run="All" if dry_run else None
        )

        if wait:
            if not _wait_for_resource_status(
                api_instance, "service", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for service {name} to become ready")

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Service {namespace}/{name} not found") from exc
        if isinstance(exc, ApiException) and exc.status == 409:
            raise CommandExecutionError(f"Conflict when patching service {name}") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_secret(
    name,
    namespace,
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    .. versionadded:: 2.0.0

    Patches an existing secret with the provided patch dictionary.

    name
        The name of the secret

    namespace
        The namespace of the secret

    patch
        A dictionary representing the patch to apply to the secret

    source
        File path to patch definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

    template_context
        Variables to make available in templated files

    dry_run
        If True, only simulates the patch without applying it (default: False)

    wait
        Wait for secret to become ready (default: False)

    timeout
        Timeout in seconds to wait for secret (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_secret \\
            name=my-secret \\
            namespace=default \\
            patch='{"data": {"password": "bmV3cGFzcw=="}}'
    """
    if source:
        rendered = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if not isinstance(rendered, dict):
            raise CommandExecutionError("The source file did not render to a dictionary")
        patch = rendered

    if not isinstance(patch, dict):
        raise CommandExecutionError("Patch must be a dictionary")

    # Encode secret data values to base64 if not already encoded
    if "data" in patch and isinstance(patch["data"], dict):
        encoded_data = {}
        for key, value in patch["data"].items():
            value = str(value)
            if __is_base64(value):
                encoded_data[key] = value
            else:
                encoded_data[key] = base64.b64encode(value.encode("utf-8")).decode("utf-8")
        patch = {**patch, "data": encoded_data}

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.patch_namespaced_secret(
            name, namespace, patch, dry_run="All" if dry_run else None
        )

        if wait:
            if not _wait_for_resource_status(
                api_instance, "secret", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for secret {name} to become ready")

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Secret {namespace}/{name} not found") from exc
        if isinstance(exc, ApiException) and exc.status == 409:
            raise CommandExecutionError(f"Conflict when patching secret {name}") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_configmap(
    name,
    namespace,
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    .. versionadded:: 2.0.0

    Patches an existing configmap with the provided patch dictionary.

    name
        The name of the configmap

    namespace
        The namespace of the configmap

    patch
        A dictionary representing the patch to apply to the configmap

    source
        File path to patch definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

    template_context
        Variables to make available in templated files

    dry_run
        If True, only simulates the patch without applying it (default: False)

    wait
        Wait for configmap to become ready (default: False)

    timeout
        Timeout in seconds to wait for configmap (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_configmap \\
            name=my-config \\
            namespace=default \\
            patch='{"data": {"key": "new-value"}}'
    """
    if source:
        rendered = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if not isinstance(rendered, dict):
            raise CommandExecutionError("The source file did not render to a dictionary")
        patch = rendered

    if not isinstance(patch, dict):
        raise CommandExecutionError("Patch must be a dictionary")

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.patch_namespaced_config_map(
            name, namespace, patch, dry_run="All" if dry_run else None
        )

        if wait:
            if not _wait_for_resource_status(
                api_instance, "configmap", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for configmap {name} to become ready")

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"ConfigMap {namespace}/{name} not found") from exc
        if isinstance(exc, ApiException) and exc.status == 409:
            raise CommandExecutionError(f"Conflict when patching configmap {name}") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_deployment(
    name,
    namespace,
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    .. versionadded:: 2.0.0

    Patches an existing deployment with the provided patch dictionary.

    name
        The name of the deployment

    namespace
        The namespace of the deployment

    patch
        A dictionary representing the patch to apply to the deployment

    source
        File path to patch definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

    template_context
        Variables to make available in templated files

    dry_run
        If True, only simulates the patch without applying it (default: False)

    wait
        Wait for deployment to become ready (default: False)

    timeout
        Timeout in seconds to wait for deployment (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_deployment \
            name=my-deployment \
            namespace=default \
            patch='{"spec": {"replicas": 5}}'
    """
    if source:
        rendered = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if not isinstance(rendered, dict):
            raise CommandExecutionError("The source file did not render to a dictionary")
        patch = rendered

    if not isinstance(patch, dict):
        raise CommandExecutionError("Patch must be a dictionary")

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.patch_namespaced_deployment(
            name, namespace, patch, dry_run="All" if dry_run else None
        )

        if wait:
            if not _wait_for_resource_status(
                api_instance, "deployment", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(
                    f"Timeout waiting for deployment {name} to become ready"
                )

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Deployment {namespace}/{name} not found") from exc
        if isinstance(exc, ApiException) and exc.status == 409:
            raise CommandExecutionError(f"Conflict when patching deployment {name}") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_statefulset(
    name,
    namespace,
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    .. versionadded:: 2.1.0

    Patches an existing statefulset with the provided patch dictionary.

    name
        The name of the statefulset

    namespace
        The namespace of the statefulset

    patch
        A dictionary representing the patch to apply to the statefulset

    source
        File path to patch definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

    template_context
        Variables to make available in templated files

    dry_run
        If True, only simulates the patch without applying it (default: False)

    wait
        Wait for statefulset to become ready (default: False)

    timeout
        Timeout in seconds to wait for statefulset (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_statefulset \
            name=my-statefulset \
            namespace=default \
            patch='{"spec": {"replicas": 5}}'
    """
    if source:
        rendered = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if not isinstance(rendered, dict):
            raise CommandExecutionError("The source file did not render to a dictionary")
        patch = rendered

    if not isinstance(patch, dict):
        raise CommandExecutionError("Patch must be a dictionary")

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.patch_namespaced_stateful_set(
            name, namespace, patch, dry_run="All" if dry_run else None
        )

        if wait:
            if not _wait_for_resource_status(
                api_instance, "statefulset", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(
                    f"Timeout waiting for statefulset {name} to become ready"
                )

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"StatefulSet {namespace}/{name} not found") from exc
        if isinstance(exc, ApiException) and exc.status == 409:
            raise CommandExecutionError(f"Conflict when patching statefulset {name}") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_replicaset(
    name,
    namespace,
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    .. versionadded:: 2.1.0

    Patches an existing replicaset with the provided patch dictionary.

    name
        The name of the replicaset

    namespace
        The namespace of the replicaset

    patch
        A dictionary representing the patch to apply to the replicaset

    source
        File path to patch definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

    template_context
        Variables to make available in templated files

    dry_run
        If True, only simulates the patch without applying it (default: False)

    wait
        Wait for replicaset to become ready (default: False)

    timeout
        Timeout in seconds to wait for replicaset (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_replicaset \
            name=my-replicaset \
            namespace=default \
            patch='{"spec": {"replicas": 5}}'
    """
    if source:
        rendered = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if not isinstance(rendered, dict):
            raise CommandExecutionError("The source file did not render to a dictionary")
        patch = rendered

    if not isinstance(patch, dict):
        raise CommandExecutionError("Patch must be a dictionary")

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.patch_namespaced_replica_set(
            name, namespace, patch, dry_run="All" if dry_run else None
        )

        if wait:
            if not _wait_for_resource_status(
                api_instance, "replicaset", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(
                    f"Timeout waiting for replicaset {name} to become ready"
                )

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"ReplicaSet {namespace}/{name} not found") from exc
        if isinstance(exc, ApiException) and exc.status == 409:
            raise CommandExecutionError(f"Conflict when patching replicaset {name}") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_daemonset(
    name,
    namespace,
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    .. versionadded:: 2.1.0

    Patches an existing daemonset with the provided patch dictionary.

    name
        The name of the daemonset

    namespace
        The namespace of the daemonset

    patch
        A dictionary representing the patch to apply to the daemonset

    source
        File path to patch definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

    template_context
        Variables to make available in templated files

    dry_run
        If True, only simulates the patch without applying it (default: False)

    wait
        Wait for daemonset to become ready (default: False)

    timeout
        Timeout in seconds to wait for daemonset (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_daemonset \
            name=my-daemonset \
            namespace=default \
            patch='{"spec": {"replicas": 5}}'
    """
    if source:
        rendered = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if not isinstance(rendered, dict):
            raise CommandExecutionError("The source file did not render to a dictionary")
        patch = rendered

    if not isinstance(patch, dict):
        raise CommandExecutionError("Patch must be a dictionary")

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.patch_namespaced_daemon_set(
            name, namespace, patch, dry_run="All" if dry_run else None
        )

        if wait:
            if not _wait_for_resource_status(
                api_instance, "daemonset", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for daemonset {name} to become ready")

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"DaemonSet {namespace}/{name} not found") from exc
        if isinstance(exc, ApiException) and exc.status == 409:
            raise CommandExecutionError(f"Conflict when patching daemonset {name}") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_storageclass(
    name,
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    .. versionadded:: 2.1.0

    Patches an existing storageclass with the provided patch dictionary.

    name
        The name of the storageclass

    patch
        A dictionary representing the patch to apply to the storageclass

    source
        File path to patch definition

    template
        Template engine to use to render the source file

    saltenv
        Salt environment to pull the source file from

    template_context
        Variables to make available in templated files

    dry_run
        If True, only simulates the patch without applying it (default: False)

    wait
        Wait for storageclass to become ready (default: False)

    timeout
        Timeout in seconds to wait for storageclass (default: 60)

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_storageclass \
            name=my-storageclass \
            patch='{"reclaimPolicy": "Retain"}'
    """
    if source:
        rendered = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if not isinstance(rendered, dict):
            raise CommandExecutionError("The source file did not render to a dictionary")
        if rendered.get("kind") == "StorageClass":
            metadata = rendered.get("metadata")
            spec = rendered.get("spec")
            if spec is None:
                spec = {
                    key: value
                    for key, value in rendered.items()
                    if key not in ("apiVersion", "kind", "metadata")
                }

            patch = {}
            if metadata:
                metadata_patch = {
                    key: value
                    for key, value in metadata.items()
                    if key
                    not in (
                        "name",
                        "namespace",
                        "resourceVersion",
                        "uid",
                        "creationTimestamp",
                        "managedFields",
                        "generation",
                        "selfLink",
                    )
                }
                if metadata_patch:
                    patch["metadata"] = metadata_patch

            if spec:
                patch.update(spec)
        else:
            patch = rendered

    if not isinstance(patch, dict):
        raise CommandExecutionError("Patch must be a dictionary")

    # Allow state-style payloads that wrap StorageClass fields under `spec`.
    if "spec" in patch:
        spec_patch = patch.get("spec")
        if not isinstance(spec_patch, dict):
            raise CommandExecutionError("StorageClass spec patch must be a dictionary")
        patch = {key: value for key, value in patch.items() if key != "spec"}
        patch.update(spec_patch)

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.StorageV1Api()
        api_response = api_instance.patch_storage_class(
            name, patch, dry_run="All" if dry_run else None
        )

        if wait:
            if not _wait_for_resource_status(
                api_instance, "storageclass", name, None, "ready", timeout
            ):
                raise CommandExecutionError(
                    f"Timeout waiting for storageclass {name} to become ready"
                )

        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"StorageClass {name} not found") from exc
        if isinstance(exc, ApiException) and exc.status == 409:
            raise CommandExecutionError(f"Conflict when patching storageclass {name}") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# ---------------------------------------------------------------------------
# RBAC: Role, RoleBinding, ClusterRole, ClusterRoleBinding, ServiceAccount
#
# All five share the same six-verb surface (list/show/create/replace/patch/
# delete). Role and RoleBinding are namespaced; ClusterRole and
# ClusterRoleBinding are cluster-scoped; ServiceAccount is namespaced and
# lives on CoreV1Api rather than RbacAuthorizationV1Api.
#
# .. versionadded:: 2.1.0
# ---------------------------------------------------------------------------


def _rbac_api():
    """Convenience: the RbacAuthorizationV1Api instance."""
    return kubernetes.client.RbacAuthorizationV1Api()


def _is_immutable_role_ref_error(exc):
    """
    Recognise the API server's 'roleRef cannot change' rejection.

    The exact phrasing varies across K8s versions; the empirically
    observed forms include "cannot change roleRef", "is immutable",
    and "cannot be modified". Match any of them so the user sees the
    helpful Salt-side error rather than a raw 422.
    """
    if not isinstance(exc, ApiException):
        return False
    msg = (exc.body or "").lower()
    if "roleref" not in msg:
        return False
    return any(phrase in msg for phrase in ("cannot change", "immutable", "cannot be modified"))


# --- list -------------------------------------------------------------------


def roles(namespace="default", **kwargs):
    """
    Return a list of role names in *namespace*.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.roles namespace=kube-system
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_response = _rbac_api().list_namespaced_role(namespace)
        return [
            r["metadata"]["name"]
            for r in ApiClient().sanitize_for_serialization(api_response).get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def role_bindings(namespace="default", **kwargs):
    """
    Return a list of role-binding names in *namespace*.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.role_bindings namespace=kube-system
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_response = _rbac_api().list_namespaced_role_binding(namespace)
        return [
            r["metadata"]["name"]
            for r in ApiClient().sanitize_for_serialization(api_response).get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def cluster_roles(**kwargs):
    """
    Return a list of cluster-role names.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.cluster_roles
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_response = _rbac_api().list_cluster_role()
        return [
            r["metadata"]["name"]
            for r in ApiClient().sanitize_for_serialization(api_response).get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def cluster_role_bindings(**kwargs):
    """
    Return a list of cluster-role-binding names.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.cluster_role_bindings
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_response = _rbac_api().list_cluster_role_binding()
        return [
            r["metadata"]["name"]
            for r in ApiClient().sanitize_for_serialization(api_response).get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def service_accounts(namespace="default", **kwargs):
    """
    Return a list of service-account names in *namespace*.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.service_accounts namespace=kube-system
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.list_namespaced_service_account(namespace)
        return [
            sa["metadata"]["name"]
            for sa in ApiClient().sanitize_for_serialization(api_response).get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# --- show -------------------------------------------------------------------


def show_role(name, namespace="default", **kwargs):
    """
    Return the role *name* in *namespace*, or ``None`` if absent.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_role
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_response = _rbac_api().read_namespaced_role(name, namespace)
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_role_binding(name, namespace="default", **kwargs):
    """
    Return the role-binding *name* in *namespace*, or ``None`` if absent.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_role_binding
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_response = _rbac_api().read_namespaced_role_binding(name, namespace)
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_cluster_role(name, **kwargs):
    """
    Return the cluster-role *name*, or ``None`` if absent.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_cluster_role
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_response = _rbac_api().read_cluster_role(name)
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_cluster_role_binding(name, **kwargs):
    """
    Return the cluster-role-binding *name*, or ``None`` if absent.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_cluster_role_binding
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_response = _rbac_api().read_cluster_role_binding(name)
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_service_account(name, namespace="default", **kwargs):
    """
    Return the service-account *name* in *namespace*, or ``None`` if absent.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_service_account
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.read_namespaced_service_account(name, namespace)
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# --- create -----------------------------------------------------------------


def _resolve_rbac_source(source, kind, template, saltenv, template_context, metadata, spec):
    """
    Shared source-file loading for RBAC create/replace/patch.

    *kind* is the K8s ``kind:`` value the source must declare. Returns
    the (possibly updated) ``metadata`` and ``spec`` tuple.
    """
    src_obj = __read_and_render_yaml_file(source, template, saltenv, template_context)
    if not isinstance(src_obj, dict) or src_obj.get("kind") != kind:
        raise CommandExecutionError(f"The source file should define only a {kind} object")
    if "metadata" in src_obj:
        metadata = src_obj["metadata"]
    if spec is None:
        spec = {
            key: value
            for key, value in src_obj.items()
            if key not in ("apiVersion", "kind", "metadata")
        }
    return metadata, spec


def create_role(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """
    Create a Role in *namespace* from a *spec* dict (with a ``rules`` list)
    or a *source* file path. Returns the created object.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_role name=pod-reader namespace=default \
            spec='{"rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get","list"]}]}'
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "Role", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}

    body_kwargs = __dict_to_role_spec(spec)
    body = V1Role(metadata=__dict_to_object_meta(name, namespace, metadata), **body_kwargs)

    cfg = _setup_conn(**kwargs)
    try:
        api_response = _rbac_api().create_namespaced_role(
            namespace, body, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException):
            if exc.status == 404:
                raise CommandExecutionError(f"Role {name} not found") from exc
            if exc.status == 409:
                raise CommandExecutionError(f"Role {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def create_role_binding(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """
    Create a RoleBinding in *namespace* from a *spec* dict (with ``subjects``
    + ``roleRef``) or a *source* file path.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_role_binding
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "RoleBinding", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}

    body_kwargs = __dict_to_role_binding_spec(spec)
    body = V1RoleBinding(metadata=__dict_to_object_meta(name, namespace, metadata), **body_kwargs)

    cfg = _setup_conn(**kwargs)
    try:
        api_response = _rbac_api().create_namespaced_role_binding(
            namespace, body, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException):
            if exc.status == 404:
                raise CommandExecutionError(f"RoleBinding {name} not found") from exc
            if exc.status == 409:
                raise CommandExecutionError(f"RoleBinding {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def create_cluster_role(
    name,
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """
    Create a ClusterRole from a *spec* dict (``rules`` and optional
    ``aggregationRule``) or a *source* file path.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_cluster_role
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "ClusterRole", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}

    body_kwargs = __dict_to_cluster_role_spec(spec)
    body = V1ClusterRole(metadata=__dict_to_object_meta(name, None, metadata), **body_kwargs)

    cfg = _setup_conn(**kwargs)
    try:
        api_response = _rbac_api().create_cluster_role(body, dry_run="All" if dry_run else None)
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException):
            if exc.status == 404:
                raise CommandExecutionError(f"ClusterRole {name} not found") from exc
            if exc.status == 409:
                raise CommandExecutionError(f"ClusterRole {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def create_cluster_role_binding(
    name,
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """
    Create a ClusterRoleBinding from a *spec* dict (``subjects`` +
    ``roleRef``) or a *source* file path.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_cluster_role_binding
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "ClusterRoleBinding", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}

    body_kwargs = __dict_to_role_binding_spec(spec)
    body = V1ClusterRoleBinding(metadata=__dict_to_object_meta(name, None, metadata), **body_kwargs)

    cfg = _setup_conn(**kwargs)
    try:
        api_response = _rbac_api().create_cluster_role_binding(
            body, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException):
            if exc.status == 404:
                raise CommandExecutionError(f"ClusterRoleBinding {name} not found") from exc
            if exc.status == 409:
                raise CommandExecutionError(f"ClusterRoleBinding {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def create_service_account(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """
    Create a ServiceAccount in *namespace* from optional fields
    (``automount_service_account_token``, ``image_pull_secrets``, ``secrets``)
    or a *source* file path.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_service_account
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "ServiceAccount", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}

    body_kwargs = __dict_to_service_account_spec(spec)
    body = V1ServiceAccount(
        metadata=__dict_to_object_meta(name, namespace, metadata), **body_kwargs
    )

    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.create_namespaced_service_account(
            namespace, body, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException):
            if exc.status == 404:
                raise CommandExecutionError(f"ServiceAccount {name} not found") from exc
            if exc.status == 409:
                raise CommandExecutionError(f"ServiceAccount {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# --- replace ---------------------------------------------------------------


def replace_role(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    **kwargs,
):
    """
    Replace an existing Role.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replace_role
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "Role", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}

    body_kwargs = __dict_to_role_spec(spec)
    body = V1Role(metadata=__dict_to_object_meta(name, namespace, metadata), **body_kwargs)

    cfg = _setup_conn(**kwargs)
    try:
        api_response = _rbac_api().replace_namespaced_role(name, namespace, body)
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Role {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_role_binding(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    **kwargs,
):
    """
    Replace an existing RoleBinding.

    .. versionadded:: 2.1.0

    .. note::
        The Kubernetes API server treats ``roleRef`` as immutable. If your
        replacement changes ``roleRef``, the API will reject it; this
        function surfaces the error explicitly with a clear message rather
        than silently no-op'ing. To change a binding's ``roleRef`` you
        must delete and recreate the binding.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replace_role_binding
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "RoleBinding", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}

    body_kwargs = __dict_to_role_binding_spec(spec)
    body = V1RoleBinding(metadata=__dict_to_object_meta(name, namespace, metadata), **body_kwargs)

    cfg = _setup_conn(**kwargs)
    try:
        api_response = _rbac_api().replace_namespaced_role_binding(name, namespace, body)
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if _is_immutable_role_ref_error(exc):
            raise CommandExecutionError(
                f"RoleBinding {name}: roleRef is immutable. To change the "
                "referenced role, delete the binding and create a new one."
            ) from exc
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"RoleBinding {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_cluster_role(
    name,
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    **kwargs,
):
    """
    Replace an existing ClusterRole.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replace_cluster_role
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "ClusterRole", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}

    body_kwargs = __dict_to_cluster_role_spec(spec)
    body = V1ClusterRole(metadata=__dict_to_object_meta(name, None, metadata), **body_kwargs)

    cfg = _setup_conn(**kwargs)
    try:
        api_response = _rbac_api().replace_cluster_role(name, body)
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"ClusterRole {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_cluster_role_binding(
    name,
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    **kwargs,
):
    """
    Replace an existing ClusterRoleBinding.

    .. versionadded:: 2.1.0

    .. note::
        ``roleRef`` is immutable; see :py:func:`replace_role_binding`.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replace_cluster_role_binding
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "ClusterRoleBinding", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}

    body_kwargs = __dict_to_role_binding_spec(spec)
    body = V1ClusterRoleBinding(metadata=__dict_to_object_meta(name, None, metadata), **body_kwargs)

    cfg = _setup_conn(**kwargs)
    try:
        api_response = _rbac_api().replace_cluster_role_binding(name, body)
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if _is_immutable_role_ref_error(exc):
            raise CommandExecutionError(
                f"ClusterRoleBinding {name}: roleRef is immutable. To change "
                "the referenced role, delete the binding and create a new one."
            ) from exc
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"ClusterRoleBinding {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_service_account(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    **kwargs,
):
    """
    Replace an existing ServiceAccount.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replace_service_account
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "ServiceAccount", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}

    body_kwargs = __dict_to_service_account_spec(spec)
    body = V1ServiceAccount(
        metadata=__dict_to_object_meta(name, namespace, metadata), **body_kwargs
    )

    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.replace_namespaced_service_account(name, namespace, body)
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"ServiceAccount {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# --- patch ------------------------------------------------------------------


def _normalise_rbac_patch(patch, kind):
    """Allow state-style ``{spec: ...}`` payloads; flatten to top-level keys."""
    if not isinstance(patch, dict):
        raise CommandExecutionError(f"{kind} patch must be a dictionary")
    if "spec" in patch:
        spec_patch = patch.get("spec")
        if not isinstance(spec_patch, dict):
            raise CommandExecutionError(f"{kind} spec patch must be a dictionary")
        patch = {key: value for key, value in patch.items() if key != "spec"}
        patch.update(spec_patch)
    return patch


def patch_role(
    name,
    namespace="default",
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """
    Patch a Role with a strategic-merge patch.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_role
    """
    if source:
        patch = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if isinstance(patch, dict) and patch.get("kind") == "Role":
            patch = {k: v for k, v in patch.items() if k not in ("apiVersion", "kind")}
    patch = _normalise_rbac_patch(patch, "Role")
    cfg = _setup_conn(**kwargs)
    try:
        api_response = _rbac_api().patch_namespaced_role(
            name, namespace, patch, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Role {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_role_binding(
    name,
    namespace="default",
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """Patch a RoleBinding.

    .. versionadded:: 2.1.0

    .. note::
        ``roleRef`` is immutable; including it in *patch* will be rejected.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_role_binding
    """
    if source:
        patch = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if isinstance(patch, dict) and patch.get("kind") == "RoleBinding":
            patch = {k: v for k, v in patch.items() if k not in ("apiVersion", "kind")}
    patch = _normalise_rbac_patch(patch, "RoleBinding")
    cfg = _setup_conn(**kwargs)
    try:
        api_response = _rbac_api().patch_namespaced_role_binding(
            name, namespace, patch, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if _is_immutable_role_ref_error(exc):
            raise CommandExecutionError(
                f"RoleBinding {name}: roleRef is immutable; remove it from the patch."
            ) from exc
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"RoleBinding {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_cluster_role(
    name,
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """
    Patch a ClusterRole.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_cluster_role
    """
    if source:
        patch = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if isinstance(patch, dict) and patch.get("kind") == "ClusterRole":
            patch = {k: v for k, v in patch.items() if k not in ("apiVersion", "kind")}
    patch = _normalise_rbac_patch(patch, "ClusterRole")
    cfg = _setup_conn(**kwargs)
    try:
        api_response = _rbac_api().patch_cluster_role(
            name, patch, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"ClusterRole {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_cluster_role_binding(
    name,
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """Patch a ClusterRoleBinding.

    .. versionadded:: 2.1.0

    .. note::
        ``roleRef`` is immutable; including it in *patch* will be rejected.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_cluster_role_binding
    """
    if source:
        patch = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if isinstance(patch, dict) and patch.get("kind") == "ClusterRoleBinding":
            patch = {k: v for k, v in patch.items() if k not in ("apiVersion", "kind")}
    patch = _normalise_rbac_patch(patch, "ClusterRoleBinding")
    cfg = _setup_conn(**kwargs)
    try:
        api_response = _rbac_api().patch_cluster_role_binding(
            name, patch, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if _is_immutable_role_ref_error(exc):
            raise CommandExecutionError(
                f"ClusterRoleBinding {name}: roleRef is immutable; " "remove it from the patch."
            ) from exc
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"ClusterRoleBinding {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_service_account(
    name,
    namespace="default",
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """
    Patch a ServiceAccount.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_service_account
    """
    if source:
        patch = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if isinstance(patch, dict) and patch.get("kind") == "ServiceAccount":
            patch = {k: v for k, v in patch.items() if k not in ("apiVersion", "kind")}
    patch = _normalise_rbac_patch(patch, "ServiceAccount")
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.patch_namespaced_service_account(
            name, namespace, patch, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"ServiceAccount {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# --- delete -----------------------------------------------------------------


def delete_role(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    Delete a Role.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_role
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = _rbac_api()
        api_response = api_instance.delete_namespaced_role(name, namespace)
        if wait:
            if not _wait_for_resource_status(
                api_instance, "role", name, namespace, "deleted", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for Role {name} to be deleted")
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_role_binding(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    Delete a RoleBinding.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_role_binding
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = _rbac_api()
        api_response = api_instance.delete_namespaced_role_binding(name, namespace)
        if wait:
            if not _wait_for_resource_status(
                api_instance, "role_binding", name, namespace, "deleted", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for RoleBinding {name} to be deleted")
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_cluster_role(name, wait=False, timeout=60, **kwargs):
    """
    Delete a ClusterRole.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_cluster_role
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = _rbac_api()
        api_response = api_instance.delete_cluster_role(name)
        if wait:
            if not _wait_for_resource_status(
                api_instance, "cluster_role", name, None, "deleted", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for ClusterRole {name} to be deleted")
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_cluster_role_binding(name, wait=False, timeout=60, **kwargs):
    """
    Delete a ClusterRoleBinding.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_cluster_role_binding
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = _rbac_api()
        api_response = api_instance.delete_cluster_role_binding(name)
        if wait:
            if not _wait_for_resource_status(
                api_instance, "cluster_role_binding", name, None, "deleted", timeout
            ):
                raise CommandExecutionError(
                    f"Timeout waiting for ClusterRoleBinding {name} to be deleted"
                )
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_service_account(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    Delete a ServiceAccount.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_service_account
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.delete_namespaced_service_account(name, namespace)
        if wait:
            if not _wait_for_resource_status(
                api_instance, "service_account", name, namespace, "deleted", timeout
            ):
                raise CommandExecutionError(
                    f"Timeout waiting for ServiceAccount {name} to be deleted"
                )
        return ApiClient().sanitize_for_serialization(api_response)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# ---------------------------------------------------------------------------
# Batch: Job, CronJob
#
# Same six-verb surface as the other typed kinds. Job optionally waits
# for completion (kubectl-create-job + kubectl-wait equivalent).
#
# .. versionadded:: 2.1.0
# ---------------------------------------------------------------------------


def _batch_api():
    return kubernetes.client.BatchV1Api()


def _wait_for_job_completion(api, name, namespace, timeout):
    """Poll a Job until status.conditions has Complete or Failed."""

    deadline = time.time() + max(timeout, 1)
    while time.time() < deadline:
        try:
            job = api.read_namespaced_job(name, namespace)
        except ApiException as exc:
            if exc.status == 404:
                return False
            raise
        for cond in job.status.conditions or []:
            if cond.type == "Complete" and cond.status == "True":
                return True
            if cond.type == "Failed" and cond.status == "True":
                return False
        time.sleep(2)
    return False


# --- list -------------------------------------------------------------------


def jobs(namespace="default", **kwargs):
    """
    Return a list of Job names in *namespace*.

    .. versionadded:: 2.1.0

    namespace
        The namespace to operate in. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.jobs
    """
    cfg = _setup_conn(**kwargs)
    try:
        resp = _batch_api().list_namespaced_job(namespace)
        return [
            j["metadata"]["name"]
            for j in ApiClient().sanitize_for_serialization(resp).get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def cron_jobs(namespace="default", **kwargs):
    """
    Return a list of CronJob names in *namespace*.

    .. versionadded:: 2.1.0

    namespace
        The namespace to operate in. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.cron_jobs
    """
    cfg = _setup_conn(**kwargs)
    try:
        resp = _batch_api().list_namespaced_cron_job(namespace)
        return [
            j["metadata"]["name"]
            for j in ApiClient().sanitize_for_serialization(resp).get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# --- show -------------------------------------------------------------------


def show_job(name, namespace="default", **kwargs):
    """
    Return the Job named *name* in *namespace*.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_job
    """
    cfg = _setup_conn(**kwargs)
    try:
        return ApiClient().sanitize_for_serialization(
            _batch_api().read_namespaced_job(name, namespace)
        )
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_cron_job(name, namespace="default", **kwargs):
    """
    Return the CronJob named *name* in *namespace*.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_cron_job
    """
    cfg = _setup_conn(**kwargs)
    try:
        return ApiClient().sanitize_for_serialization(
            _batch_api().read_namespaced_cron_job(name, namespace)
        )
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# --- create -----------------------------------------------------------------


def create_job(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    wait_for_completion=False,
    timeout=300,
    **kwargs,
):
    """
    Create a Job from a *spec* dict (with ``template``) or a *source* file.

    .. versionadded:: 2.1.0

    wait_for_completion
        Poll the Job's status.conditions until ``Complete=True`` (return
        the Job) or ``Failed=True`` (raise CommandExecutionError) or
        the wall-clock *timeout* elapses (raise).

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_job
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "Job", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}
    body = V1Job(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        spec=V1JobSpec(**__dict_to_job_spec(spec)),
    )
    cfg = _setup_conn(**kwargs)
    try:
        api = _batch_api()
        resp = api.create_namespaced_job(namespace, body, dry_run="All" if dry_run else None)
        if wait_for_completion and not dry_run:
            done = _wait_for_job_completion(api, name, namespace, timeout)
            if not done:
                raise CommandExecutionError(f"Job {name} did not complete within {timeout}s")
            resp = api.read_namespaced_job(name, namespace)
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException):
            if exc.status == 409:
                raise CommandExecutionError(f"Job {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def create_cron_job(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """
    Create a CronJob.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    metadata
        Object metadata dict (labels, annotations,
        ``ownerReferences``, etc.). The function fills in ``name`` and
        ``namespace`` itself; supply other fields here.

    spec
        Object spec dict mapped onto the typed Kubernetes
        ``V1*Spec`` for this kind. Either supply directly or via
        ``source``.

    source
        Salt fileserver path (``salt://...``) to a YAML
        manifest. Mutually exclusive with ``metadata`` + ``spec``.

    template
        Template engine used to render ``source``
        (e.g. ``"jinja"``).

    saltenv
        Salt environment from which to resolve
        ``source``. Defaults to the minion's configured ``saltenv``
        or ``base``.

    template_context
        Variables made available when rendering
        ``source``.

    dry_run
        If ``True`` the API server validates and returns
        what would be written without persisting it. Useful for
        state-mode ``test=True`` previews.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_cron_job
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "CronJob", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}
    body = V1CronJob(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        spec=V1CronJobSpec(**__dict_to_cron_job_spec(spec)),
    )
    cfg = _setup_conn(**kwargs)
    try:
        resp = _batch_api().create_namespaced_cron_job(
            namespace, body, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 409:
            raise CommandExecutionError(f"CronJob {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# --- replace ----------------------------------------------------------------


def replace_job(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    **kwargs,
):
    """
    Replace a Job.

    .. versionadded:: 2.1.0

    .. note::

        Job ``spec.selector`` and most of ``spec.template`` are immutable
        after creation. The API server will reject a replace that
        changes them; for those cases delete and recreate.

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    metadata
        Object metadata dict (labels, annotations,
        ``ownerReferences``, etc.). The function fills in ``name`` and
        ``namespace`` itself; supply other fields here.

    spec
        Object spec dict mapped onto the typed Kubernetes
        ``V1*Spec`` for this kind. Either supply directly or via
        ``source``.

    source
        Salt fileserver path (``salt://...``) to a YAML
        manifest. Mutually exclusive with ``metadata`` + ``spec``.

    template
        Template engine used to render ``source``
        (e.g. ``"jinja"``).

    saltenv
        Salt environment from which to resolve
        ``source``. Defaults to the minion's configured ``saltenv``
        or ``base``.

    template_context
        Variables made available when rendering
        ``source``.

    dry_run
        If ``True`` the API server validates and returns
        what would be written without persisting it. Useful for
        state-mode ``test=True`` previews.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replace_job
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "Job", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}
    body = V1Job(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        spec=V1JobSpec(**__dict_to_job_spec(spec)),
    )
    cfg = _setup_conn(**kwargs)
    try:
        resp = _batch_api().replace_namespaced_job(name, namespace, body)
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Job {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_cron_job(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    **kwargs,
):
    """
    Replace a CronJob.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    metadata
        Object metadata dict (labels, annotations,
        ``ownerReferences``, etc.). The function fills in ``name`` and
        ``namespace`` itself; supply other fields here.

    spec
        Object spec dict mapped onto the typed Kubernetes
        ``V1*Spec`` for this kind. Either supply directly or via
        ``source``.

    source
        Salt fileserver path (``salt://...``) to a YAML
        manifest. Mutually exclusive with ``metadata`` + ``spec``.

    template
        Template engine used to render ``source``
        (e.g. ``"jinja"``).

    saltenv
        Salt environment from which to resolve
        ``source``. Defaults to the minion's configured ``saltenv``
        or ``base``.

    template_context
        Variables made available when rendering
        ``source``.

    dry_run
        If ``True`` the API server validates and returns
        what would be written without persisting it. Useful for
        state-mode ``test=True`` previews.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replace_cron_job
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "CronJob", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}
    body = V1CronJob(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        spec=V1CronJobSpec(**__dict_to_cron_job_spec(spec)),
    )
    cfg = _setup_conn(**kwargs)
    try:
        resp = _batch_api().replace_namespaced_cron_job(name, namespace, body)
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"CronJob {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# --- patch ------------------------------------------------------------------


def patch_job(
    name,
    namespace="default",
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """Patch a Job (e.g. to update labels or ttlSecondsAfterFinished).

    .. versionadded:: 2.1.0

    Unlike RBAC kinds (where the patch path flattens ``spec:`` because
    those kinds have no real .spec field), Job/CronJob patches are
    passed through verbatim so callers can target nested fields like
    ``spec.suspend`` or ``spec.template.metadata.labels``.

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    patch
        Strategic-merge patch dict. Mutually exclusive
        with ``source``.

    source
        Salt fileserver path (``salt://...``) to a YAML
        manifest. Mutually exclusive with ``metadata`` + ``spec``.

    template
        Template engine used to render ``source``
        (e.g. ``"jinja"``).

    saltenv
        Salt environment from which to resolve
        ``source``. Defaults to the minion's configured ``saltenv``
        or ``base``.

    template_context
        Variables made available when rendering
        ``source``.

    dry_run
        If ``True`` the API server validates and returns
        what would be written without persisting it. Useful for
        state-mode ``test=True`` previews.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_job
    """
    if source:
        patch = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if isinstance(patch, dict) and patch.get("kind") == "Job":
            patch = {k: v for k, v in patch.items() if k not in ("apiVersion", "kind")}
    if not isinstance(patch, dict):
        raise CommandExecutionError("Job patch must be a dictionary")
    cfg = _setup_conn(**kwargs)
    try:
        resp = _batch_api().patch_namespaced_job(
            name, namespace, patch, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Job {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_cron_job(
    name,
    namespace="default",
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """Patch a CronJob (e.g. toggle ``spec.suspend`` or change ``spec.schedule``).

    .. versionadded:: 2.1.0

    Patches are passed through verbatim — callers must include the
    ``spec:`` wrapper for nested fields, matching kubectl-patch semantics.

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    patch
        Strategic-merge patch dict. Mutually exclusive
        with ``source``.

    source
        Salt fileserver path (``salt://...``) to a YAML
        manifest. Mutually exclusive with ``metadata`` + ``spec``.

    template
        Template engine used to render ``source``
        (e.g. ``"jinja"``).

    saltenv
        Salt environment from which to resolve
        ``source``. Defaults to the minion's configured ``saltenv``
        or ``base``.

    template_context
        Variables made available when rendering
        ``source``.

    dry_run
        If ``True`` the API server validates and returns
        what would be written without persisting it. Useful for
        state-mode ``test=True`` previews.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_cron_job
    """
    if source:
        patch = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if isinstance(patch, dict) and patch.get("kind") == "CronJob":
            patch = {k: v for k, v in patch.items() if k not in ("apiVersion", "kind")}
    if not isinstance(patch, dict):
        raise CommandExecutionError("CronJob patch must be a dictionary")
    cfg = _setup_conn(**kwargs)
    try:
        resp = _batch_api().patch_namespaced_cron_job(
            name, namespace, patch, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"CronJob {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# --- delete -----------------------------------------------------------------


def delete_job(
    name,
    namespace="default",
    propagation_policy="Background",
    wait=False,
    timeout=60,
    **kwargs,
):
    """Delete a Job.

    .. versionadded:: 2.1.0

    Default ``propagation_policy=Background`` deletes the underlying Pods
    too — matches kubectl. Pass ``Orphan`` to keep them.

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    wait
        Block until the resource reaches its kind-specific
        ready predicate.

    timeout
        Seconds to wait when ``wait=True`` (default 60).

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_job
    """
    cfg = _setup_conn(**kwargs)
    try:
        api = _batch_api()
        opts = kubernetes.client.V1DeleteOptions(propagation_policy=propagation_policy)
        resp = api.delete_namespaced_job(name, namespace, body=opts)
        if wait:
            if not _wait_for_resource_status(api, "job", name, namespace, "deleted", timeout):
                raise CommandExecutionError(f"Timeout waiting for Job {name} to be deleted")
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_cron_job(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    Delete a CronJob.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    wait
        Block until the resource reaches its kind-specific
        ready predicate.

    timeout
        Seconds to wait when ``wait=True`` (default 60).

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_cron_job
    """
    cfg = _setup_conn(**kwargs)
    try:
        api = _batch_api()
        resp = api.delete_namespaced_cron_job(name, namespace)
        if wait:
            if not _wait_for_resource_status(api, "cron_job", name, namespace, "deleted", timeout):
                raise CommandExecutionError(f"Timeout waiting for CronJob {name} to be deleted")
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# ---------------------------------------------------------------------------
# PersistentVolume + PersistentVolumeClaim
#
# PV is cluster-scoped. PVC is namespaced. Both are reasonably simple
# wrappers over the V1*Spec classes — most volume-type-specific
# validation happens server-side, so the helpers do shape checks (dict
# vs not, required keys present) and let the API server catch the rest.
#
# .. versionadded:: 2.1.0
# ---------------------------------------------------------------------------


_PV_FIELD_MAP = {
    "accessModes": "access_modes",
    "claimRef": "claim_ref",
    "persistentVolumeReclaimPolicy": "persistent_volume_reclaim_policy",
    "storageClassName": "storage_class_name",
    "volumeMode": "volume_mode",
    "mountOptions": "mount_options",
    "nodeAffinity": "node_affinity",
}


def __dict_to_persistent_volume_spec(spec):
    """Validate dict, return kwargs for V1PersistentVolumeSpec."""
    if not isinstance(spec, dict):
        raise CommandExecutionError(f"PV spec must be a dictionary, not {type(spec).__name__}")
    normalised = _normalise_field_map(spec, _PV_FIELD_MAP)
    if not normalised.get("capacity"):
        raise CommandExecutionError("PV spec must include 'capacity'")
    if not normalised.get("access_modes"):
        raise CommandExecutionError("PV spec must include 'accessModes'")
    if not isinstance(normalised["access_modes"], list):
        raise CommandExecutionError("PV accessModes must be a list")
    try:
        V1PersistentVolumeSpec(**normalised)
    except (TypeError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid PV spec: {exc}") from exc
    return normalised


_PVC_FIELD_MAP = {
    "accessModes": "access_modes",
    "dataSource": "data_source",
    "dataSourceRef": "data_source_ref",
    "storageClassName": "storage_class_name",
    "volumeMode": "volume_mode",
    "volumeName": "volume_name",
    "volumeAttributesClassName": "volume_attributes_class_name",
}


def __dict_to_pvc_spec(spec):
    """Validate dict, return kwargs for V1PersistentVolumeClaimSpec."""
    if not isinstance(spec, dict):
        raise CommandExecutionError(f"PVC spec must be a dictionary, not {type(spec).__name__}")
    normalised = _normalise_field_map(spec, _PVC_FIELD_MAP)
    if not normalised.get("access_modes"):
        raise CommandExecutionError("PVC spec must include 'accessModes'")
    if not isinstance(normalised["access_modes"], list):
        raise CommandExecutionError("PVC accessModes must be a list")
    if not normalised.get("resources"):
        raise CommandExecutionError("PVC spec must include 'resources' (with .requests.storage)")
    if "selector" in normalised and isinstance(normalised["selector"], dict):
        normalised["selector"] = kubernetes.client.V1LabelSelector(**normalised["selector"])
    if "resources" in normalised and isinstance(normalised["resources"], dict):
        normalised["resources"] = kubernetes.client.V1VolumeResourceRequirements(
            **normalised["resources"]
        )
    try:
        V1PersistentVolumeClaimSpec(**normalised)
    except (TypeError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid PVC spec: {exc}") from exc
    return normalised


# --- PV (cluster-scoped) ----------------------------------------------------


def persistent_volumes(**kwargs):
    """
    Return PV names.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.persistent_volumes
    """
    cfg = _setup_conn(**kwargs)
    try:
        api = kubernetes.client.CoreV1Api()
        resp = api.list_persistent_volume()
        return [
            p["metadata"]["name"]
            for p in ApiClient().sanitize_for_serialization(resp).get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_persistent_volume(name, **kwargs):
    """
    Return the PV named *name*.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_persistent_volume
    """
    cfg = _setup_conn(**kwargs)
    try:
        return ApiClient().sanitize_for_serialization(
            kubernetes.client.CoreV1Api().read_persistent_volume(name)
        )
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def create_persistent_volume(
    name,
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """
    Create a PV.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    metadata
        Object metadata dict (labels, annotations,
        ``ownerReferences``, etc.). The function fills in ``name`` and
        ``namespace`` itself; supply other fields here.

    spec
        Object spec dict mapped onto the typed Kubernetes
        ``V1*Spec`` for this kind. Either supply directly or via
        ``source``.

    source
        Salt fileserver path (``salt://...``) to a YAML
        manifest. Mutually exclusive with ``metadata`` + ``spec``.

    template
        Template engine used to render ``source``
        (e.g. ``"jinja"``).

    saltenv
        Salt environment from which to resolve
        ``source``. Defaults to the minion's configured ``saltenv``
        or ``base``.

    template_context
        Variables made available when rendering
        ``source``.

    dry_run
        If ``True`` the API server validates and returns
        what would be written without persisting it. Useful for
        state-mode ``test=True`` previews.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_persistent_volume
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "PersistentVolume", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}
    body = V1PersistentVolume(
        metadata=__dict_to_object_meta(name, None, metadata),
        spec=V1PersistentVolumeSpec(**__dict_to_persistent_volume_spec(spec)),
    )
    cfg = _setup_conn(**kwargs)
    try:
        resp = kubernetes.client.CoreV1Api().create_persistent_volume(
            body, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 409:
            raise CommandExecutionError(f"PV {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_persistent_volume(
    name,
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    **kwargs,
):
    """Replace a PV.

    .. versionadded:: 2.1.0

    .. note::
        Most PV fields are immutable after binding. The API server
        will reject changes to the volume source, capacity, or
        accessModes once a PVC has bound to the PV.

    name
        The name of the object.

    metadata
        Object metadata dict (labels, annotations,
        ``ownerReferences``, etc.). The function fills in ``name`` and
        ``namespace`` itself; supply other fields here.

    spec
        Object spec dict mapped onto the typed Kubernetes
        ``V1*Spec`` for this kind. Either supply directly or via
        ``source``.

    source
        Salt fileserver path (``salt://...``) to a YAML
        manifest. Mutually exclusive with ``metadata`` + ``spec``.

    template
        Template engine used to render ``source``
        (e.g. ``"jinja"``).

    saltenv
        Salt environment from which to resolve
        ``source``. Defaults to the minion's configured ``saltenv``
        or ``base``.

    template_context
        Variables made available when rendering
        ``source``.

    dry_run
        If ``True`` the API server validates and returns
        what would be written without persisting it. Useful for
        state-mode ``test=True`` previews.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replace_persistent_volume
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "PersistentVolume", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}
    body = V1PersistentVolume(
        metadata=__dict_to_object_meta(name, None, metadata),
        spec=V1PersistentVolumeSpec(**__dict_to_persistent_volume_spec(spec)),
    )
    cfg = _setup_conn(**kwargs)
    try:
        resp = kubernetes.client.CoreV1Api().replace_persistent_volume(name, body)
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"PV {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_persistent_volume(
    name,
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """
    Patch a PV.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    patch
        Strategic-merge patch dict. Mutually exclusive
        with ``source``.

    source
        Salt fileserver path (``salt://...``) to a YAML
        manifest. Mutually exclusive with ``metadata`` + ``spec``.

    template
        Template engine used to render ``source``
        (e.g. ``"jinja"``).

    saltenv
        Salt environment from which to resolve
        ``source``. Defaults to the minion's configured ``saltenv``
        or ``base``.

    template_context
        Variables made available when rendering
        ``source``.

    dry_run
        If ``True`` the API server validates and returns
        what would be written without persisting it. Useful for
        state-mode ``test=True`` previews.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_persistent_volume
    """
    if source:
        patch = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if isinstance(patch, dict) and patch.get("kind") == "PersistentVolume":
            patch = {k: v for k, v in patch.items() if k not in ("apiVersion", "kind")}
    if not isinstance(patch, dict):
        raise CommandExecutionError("PV patch must be a dictionary")
    cfg = _setup_conn(**kwargs)
    try:
        resp = kubernetes.client.CoreV1Api().patch_persistent_volume(
            name, patch, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"PV {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_persistent_volume(name, wait=False, timeout=60, **kwargs):
    """
    Delete a PV.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    wait
        Block until the resource reaches its kind-specific
        ready predicate.

    timeout
        Seconds to wait when ``wait=True`` (default 60).

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_persistent_volume
    """
    cfg = _setup_conn(**kwargs)
    try:
        api = kubernetes.client.CoreV1Api()
        resp = api.delete_persistent_volume(name)
        if wait:
            if not _wait_for_resource_status(
                api, "persistent_volume", name, None, "deleted", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for PV {name} to be deleted")
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# --- PVC (namespaced) ------------------------------------------------------


def persistent_volume_claims(namespace="default", **kwargs):
    """
    Return PVC names in *namespace*.

    .. versionadded:: 2.1.0

    namespace
        The namespace to operate in. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.persistent_volume_claims
    """
    cfg = _setup_conn(**kwargs)
    try:
        api = kubernetes.client.CoreV1Api()
        resp = api.list_namespaced_persistent_volume_claim(namespace)
        return [
            p["metadata"]["name"]
            for p in ApiClient().sanitize_for_serialization(resp).get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_persistent_volume_claim(name, namespace="default", **kwargs):
    """
    Return the PVC *name* in *namespace*.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_persistent_volume_claim
    """
    cfg = _setup_conn(**kwargs)
    try:
        return ApiClient().sanitize_for_serialization(
            kubernetes.client.CoreV1Api().read_namespaced_persistent_volume_claim(name, namespace)
        )
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def create_persistent_volume_claim(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """
    Create a PVC.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    metadata
        Object metadata dict (labels, annotations,
        ``ownerReferences``, etc.). The function fills in ``name`` and
        ``namespace`` itself; supply other fields here.

    spec
        Object spec dict mapped onto the typed Kubernetes
        ``V1*Spec`` for this kind. Either supply directly or via
        ``source``.

    source
        Salt fileserver path (``salt://...``) to a YAML
        manifest. Mutually exclusive with ``metadata`` + ``spec``.

    template
        Template engine used to render ``source``
        (e.g. ``"jinja"``).

    saltenv
        Salt environment from which to resolve
        ``source``. Defaults to the minion's configured ``saltenv``
        or ``base``.

    template_context
        Variables made available when rendering
        ``source``.

    dry_run
        If ``True`` the API server validates and returns
        what would be written without persisting it. Useful for
        state-mode ``test=True`` previews.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_persistent_volume_claim
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "PersistentVolumeClaim", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}
    body = V1PersistentVolumeClaim(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        spec=V1PersistentVolumeClaimSpec(**__dict_to_pvc_spec(spec)),
    )
    cfg = _setup_conn(**kwargs)
    try:
        resp = kubernetes.client.CoreV1Api().create_namespaced_persistent_volume_claim(
            namespace, body, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 409:
            raise CommandExecutionError(f"PVC {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_persistent_volume_claim(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    **kwargs,
):
    """Replace a PVC.

    .. versionadded:: 2.1.0

    .. note::

        After binding, ``accessModes``, ``selector``, ``volumeName``,
        and ``storageClassName`` are immutable. ``resources.requests
        .storage`` can be expanded (only) on storage classes with
        ``allowVolumeExpansion: true``. The API server will reject
        invalid changes — :py:func:`replace_persistent_volume_claim`
        does not silently no-op on immutable-field violations; the
        rejection surfaces as a clear error.

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    metadata
        Object metadata dict (labels, annotations,
        ``ownerReferences``, etc.). The function fills in ``name`` and
        ``namespace`` itself; supply other fields here.

    spec
        Object spec dict mapped onto the typed Kubernetes
        ``V1*Spec`` for this kind. Either supply directly or via
        ``source``.

    source
        Salt fileserver path (``salt://...``) to a YAML
        manifest. Mutually exclusive with ``metadata`` + ``spec``.

    template
        Template engine used to render ``source``
        (e.g. ``"jinja"``).

    saltenv
        Salt environment from which to resolve
        ``source``. Defaults to the minion's configured ``saltenv``
        or ``base``.

    template_context
        Variables made available when rendering
        ``source``.

    dry_run
        If ``True`` the API server validates and returns
        what would be written without persisting it. Useful for
        state-mode ``test=True`` previews.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replace_persistent_volume_claim
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "PersistentVolumeClaim", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}
    body = V1PersistentVolumeClaim(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        spec=V1PersistentVolumeClaimSpec(**__dict_to_pvc_spec(spec)),
    )
    cfg = _setup_conn(**kwargs)
    try:
        resp = kubernetes.client.CoreV1Api().replace_namespaced_persistent_volume_claim(
            name, namespace, body
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"PVC {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_persistent_volume_claim(
    name,
    namespace="default",
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """
    Patch a PVC.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    patch
        Strategic-merge patch dict. Mutually exclusive
        with ``source``.

    source
        Salt fileserver path (``salt://...``) to a YAML
        manifest. Mutually exclusive with ``metadata`` + ``spec``.

    template
        Template engine used to render ``source``
        (e.g. ``"jinja"``).

    saltenv
        Salt environment from which to resolve
        ``source``. Defaults to the minion's configured ``saltenv``
        or ``base``.

    template_context
        Variables made available when rendering
        ``source``.

    dry_run
        If ``True`` the API server validates and returns
        what would be written without persisting it. Useful for
        state-mode ``test=True`` previews.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_persistent_volume_claim
    """
    if source:
        patch = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if isinstance(patch, dict) and patch.get("kind") == "PersistentVolumeClaim":
            patch = {k: v for k, v in patch.items() if k not in ("apiVersion", "kind")}
    if not isinstance(patch, dict):
        raise CommandExecutionError("PVC patch must be a dictionary")
    cfg = _setup_conn(**kwargs)
    try:
        resp = kubernetes.client.CoreV1Api().patch_namespaced_persistent_volume_claim(
            name, namespace, patch, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"PVC {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_persistent_volume_claim(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    Delete a PVC.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    wait
        Block until the resource reaches its kind-specific
        ready predicate.

    timeout
        Seconds to wait when ``wait=True`` (default 60).

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_persistent_volume_claim
    """
    cfg = _setup_conn(**kwargs)
    try:
        api = kubernetes.client.CoreV1Api()
        resp = api.delete_namespaced_persistent_volume_claim(name, namespace)
        if wait:
            if not _wait_for_resource_status(
                api, "persistent_volume_claim", name, namespace, "deleted", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for PVC {name} to be deleted")
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# ---------------------------------------------------------------------------
# Networking / Autoscaling / Policy: Ingress, HorizontalPodAutoscaler,
# PodDisruptionBudget
#
# Same six-verb surface as the other typed kinds.
#
# .. versionadded:: 2.1.0
# ---------------------------------------------------------------------------


# --- spec helpers ----------------------------------------------------------


_CAMEL_TO_SNAKE_RE = None


def _camel_to_snake(name):
    """Convert ``camelCase`` to ``snake_case`` for unmapped keys.

    The kubernetes-client OpenAPI generator's wire→python translation is
    ``camelCase → snake_case`` for almost every field. Where the
    auto-generated translation differs from the obvious one (e.g.
    ``nonResourceURLs → non_resource_ur_ls``) we override via the
    per-kind ``mapping`` dict in :py:func:`_normalise_field_map`. For
    everything else, falling back to a regex split on capital letters
    works.
    """
    global _CAMEL_TO_SNAKE_RE  # pylint: disable=global-statement
    if _CAMEL_TO_SNAKE_RE is None:

        _CAMEL_TO_SNAKE_RE = re.compile(r"(?<!^)(?=[A-Z])")
    return _CAMEL_TO_SNAKE_RE.sub("_", name).lower()


def _normalise_field_map(spec, mapping=None):
    """
    Translate top-level camelCase keys to snake_case.

    *mapping* is an optional per-kind override dict, consulted first so
    fields with awkward auto-translations (acronyms like ``clusterIP``
    → ``cluster_ip``, suffixed plurals like ``nonResourceURLs`` →
    ``non_resource_urls``) can be pinned explicitly. Keys not in
    *mapping* fall back to a generic camel→snake conversion via
    :py:func:`_camel_to_snake`. Keys already in snake_case pass through
    unchanged.

    Non-mapping inputs (lists, scalars, ``None``) are returned
    unchanged so callers can apply this defensively to user input.
    """
    if not isinstance(spec, dict):
        return spec
    mapping = mapping or {}
    out = {}
    for k, v in spec.items():
        if k in mapping:
            out[mapping[k]] = v
        elif any(c.isupper() for c in k):
            out[_camel_to_snake(k)] = v
        else:
            out[k] = v
    return out


def _snake_caseify_keys(spec):
    """Translate top-level camelCase keys to snake_case (no overrides).

    Thin alias for :py:func:`_normalise_field_map` with no per-kind
    override mapping. Use this when no field needs an explicit override
    (no acronyms or plurals the OpenAPI generator translates oddly);
    use :py:func:`_normalise_field_map` directly when one is needed.
    """
    return _normalise_field_map(spec)


_INGRESS_FIELD_MAP = {
    "ingressClassName": "ingress_class_name",
    "defaultBackend": "default_backend",
}


def __dict_to_ingress_spec(spec):
    """Validate dict, return kwargs for V1IngressSpec."""
    if not isinstance(spec, dict):
        raise CommandExecutionError(f"Ingress spec must be a dictionary, not {type(spec).__name__}")
    normalised = _normalise_field_map(spec, _INGRESS_FIELD_MAP)
    rules = normalised.get("rules")
    if rules is not None and not isinstance(rules, list):
        raise CommandExecutionError("Ingress rules must be a list")
    tls = normalised.get("tls")
    if tls is not None and not isinstance(tls, list):
        raise CommandExecutionError("Ingress tls must be a list")
    try:
        V1IngressSpec(**normalised)
    except (TypeError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid ingress spec: {exc}") from exc
    return normalised


_HPA_FIELD_MAP = {
    "scaleTargetRef": "scale_target_ref",
    "minReplicas": "min_replicas",
    "maxReplicas": "max_replicas",
}


def __dict_to_hpa_spec(spec):
    """Validate dict, return kwargs for V2HorizontalPodAutoscalerSpec."""
    if not isinstance(spec, dict):
        raise CommandExecutionError(f"HPA spec must be a dictionary, not {type(spec).__name__}")
    normalised = _normalise_field_map(spec, _HPA_FIELD_MAP)
    if "scale_target_ref" not in normalised:
        raise CommandExecutionError("HPA spec must include 'scaleTargetRef'")
    if "max_replicas" not in normalised:
        raise CommandExecutionError("HPA spec must include 'maxReplicas'")
    target = normalised["scale_target_ref"]
    if not isinstance(target, dict):
        raise CommandExecutionError("scaleTargetRef must be a dict")
    # The CrossVersionObjectReference accepts api_version/kind/name; translate
    # camelCase apiVersion if present.
    if "apiVersion" in target:
        target = {k: v for k, v in target.items() if k != "apiVersion"}
        target["api_version"] = normalised["scale_target_ref"]["apiVersion"]
    normalised["scale_target_ref"] = kubernetes.client.V2CrossVersionObjectReference(**target)
    try:
        V2HorizontalPodAutoscalerSpec(**normalised)
    except (TypeError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid HPA spec: {exc}") from exc
    return normalised


_PDB_FIELD_MAP = {
    "minAvailable": "min_available",
    "maxUnavailable": "max_unavailable",
    "unhealthyPodEvictionPolicy": "unhealthy_pod_eviction_policy",
}


def __dict_to_pdb_spec(spec):
    """Validate dict, return kwargs for V1PodDisruptionBudgetSpec."""
    if not isinstance(spec, dict):
        raise CommandExecutionError(f"PDB spec must be a dictionary, not {type(spec).__name__}")
    normalised = _normalise_field_map(spec, _PDB_FIELD_MAP)
    if normalised.get("min_available") is None and normalised.get("max_unavailable") is None:
        raise CommandExecutionError(
            "PDB spec must include exactly one of 'minAvailable' or 'maxUnavailable'"
        )
    if (
        normalised.get("min_available") is not None
        and normalised.get("max_unavailable") is not None
    ):
        raise CommandExecutionError(
            "PDB spec cannot include both 'minAvailable' and 'maxUnavailable'"
        )
    if not isinstance(normalised.get("selector"), dict):
        raise CommandExecutionError("PDB spec must include 'selector' (a label-selector dict)")
    selector = normalised["selector"]
    selector_kwargs = {}
    if "matchLabels" in selector:
        selector_kwargs["match_labels"] = selector["matchLabels"]
    elif "match_labels" in selector:
        selector_kwargs["match_labels"] = selector["match_labels"]
    if "matchExpressions" in selector:
        selector_kwargs["match_expressions"] = selector["matchExpressions"]
    elif "match_expressions" in selector:
        selector_kwargs["match_expressions"] = selector["match_expressions"]
    normalised["selector"] = kubernetes.client.V1LabelSelector(**selector_kwargs)
    try:
        V1PodDisruptionBudgetSpec(**normalised)
    except (TypeError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid PDB spec: {exc}") from exc
    return normalised


def _label_selector_from_dict(selector):
    """Build a V1LabelSelector from a kubectl-style mixed-case dict.

    Accepts both YAML-native ``matchLabels``/``matchExpressions`` and the
    snake_case spellings the kubernetes-client uses.
    """
    if selector is None:
        return None
    if not isinstance(selector, dict):
        raise CommandExecutionError("selector must be a dictionary")
    kwargs = {}
    if "matchLabels" in selector or "match_labels" in selector:
        kwargs["match_labels"] = selector.get("matchLabels") or selector.get("match_labels")
    if "matchExpressions" in selector or "match_expressions" in selector:
        kwargs["match_expressions"] = selector.get("matchExpressions") or selector.get(
            "match_expressions"
        )
    return kubernetes.client.V1LabelSelector(**kwargs)


_NETPOL_FIELD_MAP = {
    "podSelector": "pod_selector",
    "policyTypes": "policy_types",
}


def __dict_to_network_policy_spec(spec):
    """Validate dict, return kwargs for V1NetworkPolicySpec.

    The full NetworkPolicy rule schema (ingress/egress rules with
    ``from``/``to`` selectors, ports, ipBlock CIDRs) is large; we pass
    ingress/egress through as-is and let the kubernetes-client OpenAPI
    serializer validate at request time. We do normalize the top-level
    camelCase keys and convert ``podSelector`` to a V1LabelSelector.
    """
    if not isinstance(spec, dict):
        raise CommandExecutionError(
            f"NetworkPolicy spec must be a dictionary, not {type(spec).__name__}"
        )
    normalised = _normalise_field_map(spec, _NETPOL_FIELD_MAP)
    if "pod_selector" not in normalised:
        raise CommandExecutionError("NetworkPolicy spec must include 'podSelector'")
    normalised["pod_selector"] = _label_selector_from_dict(normalised["pod_selector"])
    if normalised.get("policy_types") is not None and not isinstance(
        normalised["policy_types"], list
    ):
        raise CommandExecutionError("NetworkPolicy policyTypes must be a list")
    try:
        V1NetworkPolicySpec(**normalised)
    except (TypeError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid NetworkPolicy spec: {exc}") from exc
    return normalised


_RESOURCE_QUOTA_FIELD_MAP = {
    "scopeSelector": "scope_selector",
}


def __dict_to_resource_quota_spec(spec):
    """Validate dict, return kwargs for V1ResourceQuotaSpec."""
    if not isinstance(spec, dict):
        raise CommandExecutionError(
            f"ResourceQuota spec must be a dictionary, not {type(spec).__name__}"
        )
    normalised = _normalise_field_map(spec, _RESOURCE_QUOTA_FIELD_MAP)
    if "hard" in normalised and not isinstance(normalised["hard"], dict):
        raise CommandExecutionError("ResourceQuota 'hard' must be a dictionary")
    if "scopes" in normalised and not isinstance(normalised["scopes"], list):
        raise CommandExecutionError("ResourceQuota 'scopes' must be a list")
    try:
        V1ResourceQuotaSpec(**normalised)
    except (TypeError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid ResourceQuota spec: {exc}") from exc
    return normalised


def __dict_to_limit_range_spec(spec):
    """Validate dict, return kwargs for V1LimitRangeSpec.

    Each entry in ``limits`` is a V1LimitRangeItem — we translate camelCase
    keys (``defaultRequest``, ``maxLimitRequestRatio``) to snake_case before
    construction so users can write kubectl-style YAML.
    """
    if not isinstance(spec, dict):
        raise CommandExecutionError(
            f"LimitRange spec must be a dictionary, not {type(spec).__name__}"
        )
    limits = spec.get("limits")
    if not isinstance(limits, list) or not limits:
        raise CommandExecutionError("LimitRange spec must include a non-empty 'limits' list")
    items = []
    for entry in limits:
        if not isinstance(entry, dict):
            raise CommandExecutionError("Each LimitRange 'limits' entry must be a dictionary")
        item_kwargs = _snake_caseify_keys(entry)
        try:
            items.append(V1LimitRangeItem(**item_kwargs))
        except (TypeError, ValueError) as exc:
            raise CommandExecutionError(f"Invalid LimitRange item: {exc}") from exc
    return {"limits": items}


_PRIORITY_CLASS_FIELD_MAP = {
    "globalDefault": "global_default",
    "preemptionPolicy": "preemption_policy",
}


def __dict_to_priority_class_kwargs(spec):
    """Validate dict, return kwargs for V1PriorityClass.

    V1PriorityClass has no separate spec class; ``value``,
    ``description``, ``globalDefault`` and ``preemptionPolicy`` live on
    the object itself. ``value`` is required.
    """
    if not isinstance(spec, dict):
        raise CommandExecutionError(
            f"PriorityClass spec must be a dictionary, not {type(spec).__name__}"
        )
    normalised = _normalise_field_map(spec, _PRIORITY_CLASS_FIELD_MAP)
    if "value" not in normalised:
        raise CommandExecutionError("PriorityClass spec must include 'value' (integer)")
    return normalised


def _build_crd_names(names):
    """V1CustomResourceDefinitionNames from a dict, camelCase-tolerant."""
    if not isinstance(names, dict):
        raise CommandExecutionError("CRD spec.names must be a dictionary")
    kwargs = _snake_caseify_keys(names)
    try:
        return V1CustomResourceDefinitionNames(**kwargs)
    except (TypeError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid CRD names: {exc}") from exc


def _build_crd_versions(versions):
    """List of V1CustomResourceDefinitionVersion from a list-of-dicts."""
    if not isinstance(versions, list) or not versions:
        raise CommandExecutionError("CRD spec.versions must be a non-empty list")
    built = []
    for entry in versions:
        if not isinstance(entry, dict):
            raise CommandExecutionError("Each CRD version entry must be a dictionary")
        kwargs = _snake_caseify_keys(entry)
        try:
            built.append(V1CustomResourceDefinitionVersion(**kwargs))
        except (TypeError, ValueError) as exc:
            raise CommandExecutionError(f"Invalid CRD version entry: {exc}") from exc
    return built


def __dict_to_crd_spec(spec):
    """Validate dict, return kwargs for V1CustomResourceDefinitionSpec.

    Builds the nested ``names`` and ``versions`` objects from their dict
    representations. Schema validation is delegated to the API server —
    OpenAPI schemas are deeply nested and best validated server-side.
    """
    if not isinstance(spec, dict):
        raise CommandExecutionError(f"CRD spec must be a dictionary, not {type(spec).__name__}")
    if "group" not in spec:
        raise CommandExecutionError("CRD spec must include 'group'")
    if "names" not in spec:
        raise CommandExecutionError("CRD spec must include 'names'")
    if "versions" not in spec:
        raise CommandExecutionError("CRD spec must include 'versions'")
    if "scope" not in spec:
        raise CommandExecutionError("CRD spec must include 'scope' ('Namespaced' or 'Cluster')")
    return {
        "group": spec["group"],
        "names": _build_crd_names(spec["names"]),
        "scope": spec["scope"],
        "versions": _build_crd_versions(spec["versions"]),
    }


# --- API instance helpers --------------------------------------------------


def _networking_api():
    return kubernetes.client.NetworkingV1Api()


def _autoscaling_api():
    return kubernetes.client.AutoscalingV2Api()


def _policy_api():
    return kubernetes.client.PolicyV1Api()


def _scheduling_api():
    return kubernetes.client.SchedulingV1Api()


def _apiextensions_api():
    return kubernetes.client.ApiextensionsV1Api()


def _core_v1_api():
    return kubernetes.client.CoreV1Api()


# --- Ingress ---------------------------------------------------------------


def ingresses(namespace="default", **kwargs):
    """
    Return Ingress names in *namespace*.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.ingresses
    """
    cfg = _setup_conn(**kwargs)
    try:
        resp = _networking_api().list_namespaced_ingress(namespace)
        return [
            i["metadata"]["name"]
            for i in ApiClient().sanitize_for_serialization(resp).get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_ingress(name, namespace="default", **kwargs):
    """
    Return the Ingress *name* in *namespace*.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_ingress
    """
    cfg = _setup_conn(**kwargs)
    try:
        return ApiClient().sanitize_for_serialization(
            _networking_api().read_namespaced_ingress(name, namespace)
        )
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def create_ingress(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """
    Create an Ingress.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    metadata
        Object metadata dict (labels, annotations,
        ``ownerReferences``, etc.). The function fills in ``name`` and
        ``namespace`` itself; supply other fields here.

    spec
        Object spec dict mapped onto the typed Kubernetes
        ``V1*Spec`` for this kind. Either supply directly or via
        ``source``.

    source
        Salt fileserver path (``salt://...``) to a YAML
        manifest. Mutually exclusive with ``metadata`` + ``spec``.

    template
        Template engine used to render ``source``
        (e.g. ``"jinja"``).

    saltenv
        Salt environment from which to resolve
        ``source``. Defaults to the minion's configured ``saltenv``
        or ``base``.

    template_context
        Variables made available when rendering
        ``source``.

    dry_run
        If ``True`` the API server validates and returns
        what would be written without persisting it. Useful for
        state-mode ``test=True`` previews.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_ingress
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "Ingress", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}
    body = V1Ingress(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        spec=V1IngressSpec(**__dict_to_ingress_spec(spec)),
    )
    cfg = _setup_conn(**kwargs)
    try:
        resp = _networking_api().create_namespaced_ingress(
            namespace, body, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 409:
            raise CommandExecutionError(f"Ingress {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_ingress(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    **kwargs,
):
    """
    Replace an Ingress.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    metadata
        Object metadata dict (labels, annotations,
        ``ownerReferences``, etc.). The function fills in ``name`` and
        ``namespace`` itself; supply other fields here.

    spec
        Object spec dict mapped onto the typed Kubernetes
        ``V1*Spec`` for this kind. Either supply directly or via
        ``source``.

    source
        Salt fileserver path (``salt://...``) to a YAML
        manifest. Mutually exclusive with ``metadata`` + ``spec``.

    template
        Template engine used to render ``source``
        (e.g. ``"jinja"``).

    saltenv
        Salt environment from which to resolve
        ``source``. Defaults to the minion's configured ``saltenv``
        or ``base``.

    template_context
        Variables made available when rendering
        ``source``.

    dry_run
        If ``True`` the API server validates and returns
        what would be written without persisting it. Useful for
        state-mode ``test=True`` previews.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replace_ingress
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "Ingress", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}
    body = V1Ingress(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        spec=V1IngressSpec(**__dict_to_ingress_spec(spec)),
    )
    cfg = _setup_conn(**kwargs)
    try:
        resp = _networking_api().replace_namespaced_ingress(name, namespace, body)
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Ingress {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_ingress(
    name,
    namespace="default",
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """
    Patch an Ingress.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    patch
        Strategic-merge patch dict. Mutually exclusive
        with ``source``.

    source
        Salt fileserver path (``salt://...``) to a YAML
        manifest. Mutually exclusive with ``metadata`` + ``spec``.

    template
        Template engine used to render ``source``
        (e.g. ``"jinja"``).

    saltenv
        Salt environment from which to resolve
        ``source``. Defaults to the minion's configured ``saltenv``
        or ``base``.

    template_context
        Variables made available when rendering
        ``source``.

    dry_run
        If ``True`` the API server validates and returns
        what would be written without persisting it. Useful for
        state-mode ``test=True`` previews.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_ingress
    """
    if source:
        patch = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if isinstance(patch, dict) and patch.get("kind") == "Ingress":
            patch = {k: v for k, v in patch.items() if k not in ("apiVersion", "kind")}
    if not isinstance(patch, dict):
        raise CommandExecutionError("Ingress patch must be a dictionary")
    cfg = _setup_conn(**kwargs)
    try:
        resp = _networking_api().patch_namespaced_ingress(
            name, namespace, patch, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Ingress {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_ingress(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    Delete an Ingress.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    wait
        Block until the resource reaches its kind-specific
        ready predicate.

    timeout
        Seconds to wait when ``wait=True`` (default 60).

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_ingress
    """
    cfg = _setup_conn(**kwargs)
    try:
        api = _networking_api()
        resp = api.delete_namespaced_ingress(name, namespace)
        if wait:
            if not _wait_for_resource_status(api, "ingress", name, namespace, "deleted", timeout):
                raise CommandExecutionError(f"Timeout waiting for Ingress {name} to be deleted")
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# --- HorizontalPodAutoscaler -----------------------------------------------


def horizontal_pod_autoscalers(namespace="default", **kwargs):
    """
    Return HPA names in *namespace*.

    .. versionadded:: 2.1.0

    namespace
        The namespace to operate in. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.horizontal_pod_autoscalers
    """
    cfg = _setup_conn(**kwargs)
    try:
        resp = _autoscaling_api().list_namespaced_horizontal_pod_autoscaler(namespace)
        return [
            h["metadata"]["name"]
            for h in ApiClient().sanitize_for_serialization(resp).get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_horizontal_pod_autoscaler(name, namespace="default", **kwargs):
    """
    Return the HPA *name* in *namespace*.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_horizontal_pod_autoscaler
    """
    cfg = _setup_conn(**kwargs)
    try:
        return ApiClient().sanitize_for_serialization(
            _autoscaling_api().read_namespaced_horizontal_pod_autoscaler(name, namespace)
        )
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def create_horizontal_pod_autoscaler(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """
    Create an HPA (autoscaling/v2).

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    metadata
        Object metadata dict (labels, annotations,
        ``ownerReferences``, etc.). The function fills in ``name`` and
        ``namespace`` itself; supply other fields here.

    spec
        Object spec dict mapped onto the typed Kubernetes
        ``V1*Spec`` for this kind. Either supply directly or via
        ``source``.

    source
        Salt fileserver path (``salt://...``) to a YAML
        manifest. Mutually exclusive with ``metadata`` + ``spec``.

    template
        Template engine used to render ``source``
        (e.g. ``"jinja"``).

    saltenv
        Salt environment from which to resolve
        ``source``. Defaults to the minion's configured ``saltenv``
        or ``base``.

    template_context
        Variables made available when rendering
        ``source``.

    dry_run
        If ``True`` the API server validates and returns
        what would be written without persisting it. Useful for
        state-mode ``test=True`` previews.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_horizontal_pod_autoscaler
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "HorizontalPodAutoscaler", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}
    body = V2HorizontalPodAutoscaler(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        spec=V2HorizontalPodAutoscalerSpec(**__dict_to_hpa_spec(spec)),
    )
    cfg = _setup_conn(**kwargs)
    try:
        resp = _autoscaling_api().create_namespaced_horizontal_pod_autoscaler(
            namespace, body, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 409:
            raise CommandExecutionError(f"HPA {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_horizontal_pod_autoscaler(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    **kwargs,
):
    """
    Replace an HPA.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    metadata
        Object metadata dict (labels, annotations,
        ``ownerReferences``, etc.). The function fills in ``name`` and
        ``namespace`` itself; supply other fields here.

    spec
        Object spec dict mapped onto the typed Kubernetes
        ``V1*Spec`` for this kind. Either supply directly or via
        ``source``.

    source
        Salt fileserver path (``salt://...``) to a YAML
        manifest. Mutually exclusive with ``metadata`` + ``spec``.

    template
        Template engine used to render ``source``
        (e.g. ``"jinja"``).

    saltenv
        Salt environment from which to resolve
        ``source``. Defaults to the minion's configured ``saltenv``
        or ``base``.

    template_context
        Variables made available when rendering
        ``source``.

    dry_run
        If ``True`` the API server validates and returns
        what would be written without persisting it. Useful for
        state-mode ``test=True`` previews.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replace_horizontal_pod_autoscaler
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "HorizontalPodAutoscaler", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}
    body = V2HorizontalPodAutoscaler(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        spec=V2HorizontalPodAutoscalerSpec(**__dict_to_hpa_spec(spec)),
    )
    cfg = _setup_conn(**kwargs)
    try:
        resp = _autoscaling_api().replace_namespaced_horizontal_pod_autoscaler(
            name, namespace, body
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"HPA {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_horizontal_pod_autoscaler(
    name,
    namespace="default",
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """
    Patch an HPA.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    patch
        Strategic-merge patch dict. Mutually exclusive
        with ``source``.

    source
        Salt fileserver path (``salt://...``) to a YAML
        manifest. Mutually exclusive with ``metadata`` + ``spec``.

    template
        Template engine used to render ``source``
        (e.g. ``"jinja"``).

    saltenv
        Salt environment from which to resolve
        ``source``. Defaults to the minion's configured ``saltenv``
        or ``base``.

    template_context
        Variables made available when rendering
        ``source``.

    dry_run
        If ``True`` the API server validates and returns
        what would be written without persisting it. Useful for
        state-mode ``test=True`` previews.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_horizontal_pod_autoscaler
    """
    if source:
        patch = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if isinstance(patch, dict) and patch.get("kind") == "HorizontalPodAutoscaler":
            patch = {k: v for k, v in patch.items() if k not in ("apiVersion", "kind")}
    if not isinstance(patch, dict):
        raise CommandExecutionError("HPA patch must be a dictionary")
    cfg = _setup_conn(**kwargs)
    try:
        resp = _autoscaling_api().patch_namespaced_horizontal_pod_autoscaler(
            name, namespace, patch, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"HPA {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_horizontal_pod_autoscaler(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    Delete an HPA.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    wait
        Block until the resource reaches its kind-specific
        ready predicate.

    timeout
        Seconds to wait when ``wait=True`` (default 60).

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_horizontal_pod_autoscaler
    """
    cfg = _setup_conn(**kwargs)
    try:
        api = _autoscaling_api()
        resp = api.delete_namespaced_horizontal_pod_autoscaler(name, namespace)
        if wait:
            if not _wait_for_resource_status(
                api, "horizontal_pod_autoscaler", name, namespace, "deleted", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for HPA {name} to be deleted")
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# --- PodDisruptionBudget ---------------------------------------------------


def pod_disruption_budgets(namespace="default", **kwargs):
    """
    Return PDB names in *namespace*.

    .. versionadded:: 2.1.0

    namespace
        The namespace to operate in. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.pod_disruption_budgets
    """
    cfg = _setup_conn(**kwargs)
    try:
        resp = _policy_api().list_namespaced_pod_disruption_budget(namespace)
        return [
            p["metadata"]["name"]
            for p in ApiClient().sanitize_for_serialization(resp).get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_pod_disruption_budget(name, namespace="default", **kwargs):
    """
    Return the PDB *name* in *namespace*.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_pod_disruption_budget
    """
    cfg = _setup_conn(**kwargs)
    try:
        return ApiClient().sanitize_for_serialization(
            _policy_api().read_namespaced_pod_disruption_budget(name, namespace)
        )
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def create_pod_disruption_budget(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """
    Create a PDB.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    metadata
        Object metadata dict (labels, annotations,
        ``ownerReferences``, etc.). The function fills in ``name`` and
        ``namespace`` itself; supply other fields here.

    spec
        Object spec dict mapped onto the typed Kubernetes
        ``V1*Spec`` for this kind. Either supply directly or via
        ``source``.

    source
        Salt fileserver path (``salt://...``) to a YAML
        manifest. Mutually exclusive with ``metadata`` + ``spec``.

    template
        Template engine used to render ``source``
        (e.g. ``"jinja"``).

    saltenv
        Salt environment from which to resolve
        ``source``. Defaults to the minion's configured ``saltenv``
        or ``base``.

    template_context
        Variables made available when rendering
        ``source``.

    dry_run
        If ``True`` the API server validates and returns
        what would be written without persisting it. Useful for
        state-mode ``test=True`` previews.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_pod_disruption_budget
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "PodDisruptionBudget", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}
    body = V1PodDisruptionBudget(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        spec=V1PodDisruptionBudgetSpec(**__dict_to_pdb_spec(spec)),
    )
    cfg = _setup_conn(**kwargs)
    try:
        resp = _policy_api().create_namespaced_pod_disruption_budget(
            namespace, body, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 409:
            raise CommandExecutionError(f"PDB {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_pod_disruption_budget(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    **kwargs,
):
    """
    Replace a PDB.

    .. versionadded:: 2.1.0

    .. note::
        PDB ``spec.selector`` is immutable. Replacing with a different
        selector will be rejected by the API server.

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    metadata
        Object metadata dict (labels, annotations,
        ``ownerReferences``, etc.). The function fills in ``name`` and
        ``namespace`` itself; supply other fields here.

    spec
        Object spec dict mapped onto the typed Kubernetes
        ``V1*Spec`` for this kind. Either supply directly or via
        ``source``.

    source
        Salt fileserver path (``salt://...``) to a YAML
        manifest. Mutually exclusive with ``metadata`` + ``spec``.

    template
        Template engine used to render ``source``
        (e.g. ``"jinja"``).

    saltenv
        Salt environment from which to resolve
        ``source``. Defaults to the minion's configured ``saltenv``
        or ``base``.

    template_context
        Variables made available when rendering
        ``source``.

    dry_run
        If ``True`` the API server validates and returns
        what would be written without persisting it. Useful for
        state-mode ``test=True`` previews.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replace_pod_disruption_budget
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "PodDisruptionBudget", template, saltenv, template_context, metadata, spec
        )
    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}
    body = V1PodDisruptionBudget(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        spec=V1PodDisruptionBudgetSpec(**__dict_to_pdb_spec(spec)),
    )
    cfg = _setup_conn(**kwargs)
    try:
        resp = _policy_api().replace_namespaced_pod_disruption_budget(name, namespace, body)
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"PDB {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_pod_disruption_budget(
    name,
    namespace="default",
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """
    Patch a PDB.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    patch
        Strategic-merge patch dict. Mutually exclusive
        with ``source``.

    source
        Salt fileserver path (``salt://...``) to a YAML
        manifest. Mutually exclusive with ``metadata`` + ``spec``.

    template
        Template engine used to render ``source``
        (e.g. ``"jinja"``).

    saltenv
        Salt environment from which to resolve
        ``source``. Defaults to the minion's configured ``saltenv``
        or ``base``.

    template_context
        Variables made available when rendering
        ``source``.

    dry_run
        If ``True`` the API server validates and returns
        what would be written without persisting it. Useful for
        state-mode ``test=True`` previews.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_pod_disruption_budget
    """
    if source:
        patch = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if isinstance(patch, dict) and patch.get("kind") == "PodDisruptionBudget":
            patch = {k: v for k, v in patch.items() if k not in ("apiVersion", "kind")}
    if not isinstance(patch, dict):
        raise CommandExecutionError("PDB patch must be a dictionary")
    cfg = _setup_conn(**kwargs)
    try:
        resp = _policy_api().patch_namespaced_pod_disruption_budget(
            name, namespace, patch, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"PDB {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_pod_disruption_budget(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    Delete a PDB.

    .. versionadded:: 2.1.0

    name
        The name of the object.

    namespace
        The namespace to operate in. Defaults to ``default``.

    wait
        Block until the resource reaches its kind-specific
        ready predicate.

    timeout
        Seconds to wait when ``wait=True`` (default 60).

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_pod_disruption_budget
    """
    cfg = _setup_conn(**kwargs)
    try:
        api = _policy_api()
        resp = api.delete_namespaced_pod_disruption_budget(name, namespace)
        if wait:
            if not _wait_for_resource_status(
                api, "pod_disruption_budget", name, namespace, "deleted", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for PDB {name} to be deleted")
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# ---------------------------------------------------------------------------
# Typed wrappers for the remaining "first-class" kinds called out in #14:
# NetworkPolicy, ResourceQuota, LimitRange, PriorityClass,
# CustomResourceDefinition.
#
# Each kind gets the standard six-function surface (list, show, create,
# replace, patch, delete) plus a present/absent state pair in
# saltext.kubernetes.states.kubernetes. The generic kubernetes.apply path
# also works for them, but typed wrappers make them targetable from SLS
# (via ``*_present``/``*_absent``) and addressable by the resources
# subsystem.
#
# .. versionadded:: 2.1.0
# ---------------------------------------------------------------------------


# --- NetworkPolicy (namespaced) --------------------------------------------


def network_policies(namespace="default", **kwargs):
    """List NetworkPolicies in *namespace*.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.network_policies namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        resp = _networking_api().list_namespaced_network_policy(namespace)
        return [item.metadata.name for item in resp.items]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_network_policy(name, namespace="default", **kwargs):
    """Return the NetworkPolicy or ``None`` if absent.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_network_policy name=deny-all namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        return ApiClient().sanitize_for_serialization(
            _networking_api().read_namespaced_network_policy(name, namespace)
        )
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def _build_network_policy(name, namespace, metadata, spec):
    return V1NetworkPolicy(
        metadata=__dict_to_object_meta(name, namespace, metadata or {}),
        spec=V1NetworkPolicySpec(**__dict_to_network_policy_spec(spec or {})),
    )


def create_network_policy(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """Create a NetworkPolicy.

    .. versionadded:: 2.1.0

    name
        Name of the NetworkPolicy.

    namespace
        Namespace to create the policy in. Defaults to ``default``.

    metadata
        Object metadata dict (labels, annotations).

    spec
        NetworkPolicySpec dict. ``podSelector`` is required (an empty
        ``{}`` selects every pod in the namespace). Optional
        ``policyTypes``, ``ingress``, ``egress``.

    source
        Salt fileserver path to a YAML manifest. Mutually exclusive
        with ``metadata`` + ``spec``.

    template
        Template engine for ``source`` (e.g. ``"jinja"``).

    saltenv
        Salt environment for ``source``.

    template_context
        Variables for the renderer.

    dry_run
        Server-side validate only; do not persist.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_network_policy name=deny-all namespace=default \
            spec='{"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}'
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "NetworkPolicy", template, saltenv, template_context, metadata, spec
        )
    body = _build_network_policy(name, namespace, metadata, spec)
    cfg = _setup_conn(**kwargs)
    try:
        resp = _networking_api().create_namespaced_network_policy(
            namespace, body, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 409:
            raise CommandExecutionError(f"NetworkPolicy {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_network_policy(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """Replace a NetworkPolicy in full.

    .. versionadded:: 2.1.0

    name
        Name of the existing NetworkPolicy.

    namespace
        Namespace of the NetworkPolicy.

    metadata, spec, source, template, saltenv, template_context, dry_run
        See :py:func:`create_network_policy`.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replace_network_policy name=deny-all namespace=default \
            spec='{"podSelector": {"matchLabels": {"app": "web"}}}'
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "NetworkPolicy", template, saltenv, template_context, metadata, spec
        )
    body = _build_network_policy(name, namespace, metadata, spec)
    cfg = _setup_conn(**kwargs)
    try:
        resp = _networking_api().replace_namespaced_network_policy(
            name, namespace, body, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"NetworkPolicy {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_network_policy(
    name,
    namespace="default",
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """Strategic-merge-patch a NetworkPolicy.

    .. versionadded:: 2.1.0

    name
        Name of the existing NetworkPolicy.

    namespace
        Namespace of the NetworkPolicy.

    patch
        Patch dictionary applied via strategic merge.

    source
        Salt fileserver path to a YAML patch document.

    template, saltenv, template_context
        Renderer wiring for ``source``.

    dry_run
        Server-side validate only.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_network_policy name=deny-all namespace=default \
            patch='{"spec": {"policyTypes": ["Ingress"]}}'
    """
    if source:
        patch_doc = __read_and_render_yaml_file(source, template, saltenv, template_context)
    else:
        patch_doc = patch
    cfg = _setup_conn(**kwargs)
    try:
        resp = _networking_api().patch_namespaced_network_policy(
            name, namespace, patch_doc, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"NetworkPolicy {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_network_policy(name, namespace="default", wait=False, timeout=60, **kwargs):
    """Delete a NetworkPolicy.

    .. versionadded:: 2.1.0

    name
        Name of the NetworkPolicy.

    namespace
        Namespace of the NetworkPolicy.

    wait
        Block until the object is fully gone.

    timeout
        Seconds to wait when ``wait=True``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_network_policy name=deny-all namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api = _networking_api()
        resp = api.delete_namespaced_network_policy(name, namespace)
        if wait and not _wait_for_resource_status(
            api, "network_policy", name, namespace, "deleted", timeout
        ):
            raise CommandExecutionError(f"Timeout waiting for NetworkPolicy {name} to be deleted")
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# --- ResourceQuota (namespaced) -------------------------------------------


def resource_quotas(namespace="default", **kwargs):
    """List ResourceQuotas in *namespace*.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.resource_quotas namespace=team-a
    """
    cfg = _setup_conn(**kwargs)
    try:
        resp = _core_v1_api().list_namespaced_resource_quota(namespace)
        return [item.metadata.name for item in resp.items]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_resource_quota(name, namespace="default", **kwargs):
    """Return the ResourceQuota or ``None`` if absent.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_resource_quota name=team-a-quota namespace=team-a
    """
    cfg = _setup_conn(**kwargs)
    try:
        return ApiClient().sanitize_for_serialization(
            _core_v1_api().read_namespaced_resource_quota(name, namespace)
        )
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def _build_resource_quota(name, namespace, metadata, spec):
    return V1ResourceQuota(
        metadata=__dict_to_object_meta(name, namespace, metadata or {}),
        spec=V1ResourceQuotaSpec(**__dict_to_resource_quota_spec(spec or {})),
    )


def create_resource_quota(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """Create a ResourceQuota.

    .. versionadded:: 2.1.0

    name
        Name of the ResourceQuota.

    namespace
        Namespace to create the quota in.

    metadata
        Object metadata dict.

    spec
        ResourceQuotaSpec dict (``hard``, optional ``scopes`` /
        ``scopeSelector``).

    source, template, saltenv, template_context, dry_run
        Standard manifest-source plumbing.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_resource_quota name=team-quota namespace=team-a \
            spec='{"hard": {"pods": "10", "limits.cpu": "4"}}'
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "ResourceQuota", template, saltenv, template_context, metadata, spec
        )
    body = _build_resource_quota(name, namespace, metadata, spec)
    cfg = _setup_conn(**kwargs)
    try:
        resp = _core_v1_api().create_namespaced_resource_quota(
            namespace, body, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 409:
            raise CommandExecutionError(f"ResourceQuota {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_resource_quota(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """Replace a ResourceQuota.

    .. versionadded:: 2.1.0

    name, namespace, metadata, spec, source, template, saltenv, template_context, dry_run
        See :py:func:`create_resource_quota`.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replace_resource_quota name=team-quota namespace=team-a \
            spec='{"hard": {"pods": "20"}}'
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "ResourceQuota", template, saltenv, template_context, metadata, spec
        )
    body = _build_resource_quota(name, namespace, metadata, spec)
    cfg = _setup_conn(**kwargs)
    try:
        resp = _core_v1_api().replace_namespaced_resource_quota(
            name, namespace, body, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"ResourceQuota {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_resource_quota(
    name,
    namespace="default",
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """Patch a ResourceQuota (strategic merge).

    .. versionadded:: 2.1.0

    name
        Name of the ResourceQuota.

    namespace
        Namespace of the ResourceQuota.

    patch
        Patch dict.

    source
        Salt fileserver path to a YAML patch document.

    template, saltenv, template_context
        Renderer wiring for ``source``.

    dry_run
        Server-side validate only.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_resource_quota name=team-quota namespace=team-a \
            patch='{"spec": {"hard": {"pods": "15"}}}'
    """
    if source:
        patch_doc = __read_and_render_yaml_file(source, template, saltenv, template_context)
    else:
        patch_doc = patch
    cfg = _setup_conn(**kwargs)
    try:
        resp = _core_v1_api().patch_namespaced_resource_quota(
            name, namespace, patch_doc, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"ResourceQuota {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_resource_quota(name, namespace="default", wait=False, timeout=60, **kwargs):
    """Delete a ResourceQuota.

    .. versionadded:: 2.1.0

    name, namespace
        Identify the ResourceQuota.

    wait
        Block until the object is fully gone.

    timeout
        Seconds to wait when ``wait=True``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_resource_quota name=team-quota namespace=team-a
    """
    cfg = _setup_conn(**kwargs)
    try:
        api = _core_v1_api()
        resp = api.delete_namespaced_resource_quota(name, namespace)
        if wait and not _wait_for_resource_status(
            api, "resource_quota", name, namespace, "deleted", timeout
        ):
            raise CommandExecutionError(f"Timeout waiting for ResourceQuota {name} to be deleted")
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# --- LimitRange (namespaced) -----------------------------------------------


def limit_ranges(namespace="default", **kwargs):
    """List LimitRanges in *namespace*.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.limit_ranges namespace=team-a
    """
    cfg = _setup_conn(**kwargs)
    try:
        resp = _core_v1_api().list_namespaced_limit_range(namespace)
        return [item.metadata.name for item in resp.items]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_limit_range(name, namespace="default", **kwargs):
    """Return the LimitRange or ``None`` if absent.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_limit_range name=mem-defaults namespace=team-a
    """
    cfg = _setup_conn(**kwargs)
    try:
        return ApiClient().sanitize_for_serialization(
            _core_v1_api().read_namespaced_limit_range(name, namespace)
        )
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def _build_limit_range(name, namespace, metadata, spec):
    return V1LimitRange(
        metadata=__dict_to_object_meta(name, namespace, metadata or {}),
        spec=V1LimitRangeSpec(**__dict_to_limit_range_spec(spec or {})),
    )


def create_limit_range(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """Create a LimitRange.

    .. versionadded:: 2.1.0

    name
        Name of the LimitRange.

    namespace
        Namespace to operate in.

    metadata
        Object metadata.

    spec
        LimitRangeSpec dict — ``limits`` is a list of
        ``LimitRangeItem`` entries (``type``, ``max``, ``min``,
        ``default``, ``defaultRequest``, ``maxLimitRequestRatio``).

    source, template, saltenv, template_context, dry_run
        Standard manifest-source plumbing.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_limit_range name=mem-defaults namespace=team-a \
            spec='{"limits": [{"type": "Container", "default": {"memory": "256Mi"}}]}'
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "LimitRange", template, saltenv, template_context, metadata, spec
        )
    body = _build_limit_range(name, namespace, metadata, spec)
    cfg = _setup_conn(**kwargs)
    try:
        resp = _core_v1_api().create_namespaced_limit_range(
            namespace, body, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 409:
            raise CommandExecutionError(f"LimitRange {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_limit_range(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """Replace a LimitRange.

    .. versionadded:: 2.1.0

    name, namespace, metadata, spec, source, template, saltenv, template_context, dry_run
        See :py:func:`create_limit_range`.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replace_limit_range name=mem-defaults namespace=team-a \
            spec='{"limits": [{"type": "Container", "default": {"memory": "512Mi"}}]}'
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "LimitRange", template, saltenv, template_context, metadata, spec
        )
    body = _build_limit_range(name, namespace, metadata, spec)
    cfg = _setup_conn(**kwargs)
    try:
        resp = _core_v1_api().replace_namespaced_limit_range(
            name, namespace, body, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"LimitRange {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_limit_range(
    name,
    namespace="default",
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """Patch a LimitRange (strategic merge).

    .. versionadded:: 2.1.0

    name, namespace, patch, source, template, saltenv, template_context, dry_run
        See :py:func:`patch_resource_quota`.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_limit_range name=mem-defaults namespace=team-a \
            patch='{"spec": {"limits": [{"type": "Container", "default": {"memory": "1Gi"}}]}}'
    """
    if source:
        patch_doc = __read_and_render_yaml_file(source, template, saltenv, template_context)
    else:
        patch_doc = patch
    cfg = _setup_conn(**kwargs)
    try:
        resp = _core_v1_api().patch_namespaced_limit_range(
            name, namespace, patch_doc, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"LimitRange {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_limit_range(name, namespace="default", wait=False, timeout=60, **kwargs):
    """Delete a LimitRange.

    .. versionadded:: 2.1.0

    name, namespace, wait, timeout
        See :py:func:`delete_resource_quota`.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_limit_range name=mem-defaults namespace=team-a
    """
    cfg = _setup_conn(**kwargs)
    try:
        api = _core_v1_api()
        resp = api.delete_namespaced_limit_range(name, namespace)
        if wait and not _wait_for_resource_status(
            api, "limit_range", name, namespace, "deleted", timeout
        ):
            raise CommandExecutionError(f"Timeout waiting for LimitRange {name} to be deleted")
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# --- PriorityClass (cluster-scoped) ----------------------------------------


def priority_classes(**kwargs):
    """List PriorityClasses cluster-wide.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.priority_classes
    """
    cfg = _setup_conn(**kwargs)
    try:
        resp = _scheduling_api().list_priority_class()
        return [item.metadata.name for item in resp.items]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_priority_class(name, **kwargs):
    """Return the PriorityClass or ``None`` if absent.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_priority_class name=high-priority
    """
    cfg = _setup_conn(**kwargs)
    try:
        return ApiClient().sanitize_for_serialization(_scheduling_api().read_priority_class(name))
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def _build_priority_class(name, metadata, spec):
    fields = __dict_to_priority_class_kwargs(spec or {})
    return V1PriorityClass(metadata=__dict_to_object_meta(name, None, metadata or {}), **fields)


def create_priority_class(
    name,
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """Create a PriorityClass (cluster-scoped).

    .. versionadded:: 2.1.0

    name
        Name of the PriorityClass.

    metadata
        Object metadata dict (labels, annotations).

    spec
        Body fields (PriorityClass has no nested spec):

        * ``value`` (int) — required priority weight.
        * ``description`` (str) — optional human-readable text.
        * ``globalDefault`` (bool) — at most one PriorityClass per
          cluster may set this to ``true``.
        * ``preemptionPolicy`` — ``"PreemptLowerPriority"`` (default)
          or ``"Never"``.

    source, template, saltenv, template_context, dry_run
        Standard manifest-source plumbing.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_priority_class name=high \
            spec='{"value": 1000000, "globalDefault": false, "description": "High prio"}'
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "PriorityClass", template, saltenv, template_context, metadata, spec
        )
    body = _build_priority_class(name, metadata, spec)
    cfg = _setup_conn(**kwargs)
    try:
        resp = _scheduling_api().create_priority_class(body, dry_run="All" if dry_run else None)
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 409:
            raise CommandExecutionError(f"PriorityClass {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_priority_class(
    name,
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """Replace a PriorityClass.

    .. versionadded:: 2.1.0

    name, metadata, spec, source, template, saltenv, template_context, dry_run
        See :py:func:`create_priority_class`. Note: the ``value`` and
        ``globalDefault`` fields are immutable post-creation.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replace_priority_class name=high \
            spec='{"value": 1000000, "description": "Updated description"}'
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source, "PriorityClass", template, saltenv, template_context, metadata, spec
        )
    body = _build_priority_class(name, metadata, spec)
    cfg = _setup_conn(**kwargs)
    try:
        resp = _scheduling_api().replace_priority_class(
            name, body, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"PriorityClass {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_priority_class(
    name,
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """Patch a PriorityClass (strategic merge).

    .. versionadded:: 2.1.0

    name
        Name of the PriorityClass.

    patch
        Patch dict.

    source, template, saltenv, template_context, dry_run
        Standard plumbing.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_priority_class name=high \
            patch='{"metadata": {"annotations": {"reviewed": "2026-05"}}}'
    """
    if source:
        patch_doc = __read_and_render_yaml_file(source, template, saltenv, template_context)
    else:
        patch_doc = patch
    cfg = _setup_conn(**kwargs)
    try:
        resp = _scheduling_api().patch_priority_class(
            name, patch_doc, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"PriorityClass {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_priority_class(name, wait=False, timeout=60, **kwargs):
    """Delete a PriorityClass.

    .. versionadded:: 2.1.0

    name
        Name of the PriorityClass.

    wait
        Block until the object is fully gone.

    timeout
        Seconds to wait when ``wait=True``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_priority_class name=high
    """
    cfg = _setup_conn(**kwargs)
    try:
        api = _scheduling_api()
        resp = api.delete_priority_class(name)
        if wait and not _wait_for_resource_status(
            api, "priority_class", name, None, "deleted", timeout
        ):
            raise CommandExecutionError(f"Timeout waiting for PriorityClass {name} to be deleted")
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# --- CustomResourceDefinition (cluster-scoped) ----------------------------


def custom_resource_definitions(**kwargs):
    """List installed CustomResourceDefinitions.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.custom_resource_definitions
    """
    cfg = _setup_conn(**kwargs)
    try:
        resp = _apiextensions_api().list_custom_resource_definition()
        return [item.metadata.name for item in resp.items]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def show_custom_resource_definition(name, **kwargs):
    """Return the CRD or ``None`` if absent.

    .. versionadded:: 2.1.0

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_custom_resource_definition name=widgets.example.io
    """
    cfg = _setup_conn(**kwargs)
    try:
        return ApiClient().sanitize_for_serialization(
            _apiextensions_api().read_custom_resource_definition(name)
        )
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def _build_crd(name, metadata, spec):
    return V1CustomResourceDefinition(
        metadata=__dict_to_object_meta(name, None, metadata or {}),
        spec=V1CustomResourceDefinitionSpec(**__dict_to_crd_spec(spec or {})),
    )


def create_custom_resource_definition(
    name,
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """Create a CustomResourceDefinition.

    .. versionadded:: 2.1.0

    name
        Fully-qualified CRD name (``<plural>.<group>``).

    metadata
        Object metadata.

    spec
        ``CustomResourceDefinitionSpec`` dict — ``group``, ``names`` (plural,
        singular, kind, shortNames), ``scope`` (``Namespaced`` or
        ``Cluster``) and ``versions`` (each with ``name``, ``served``,
        ``storage``, ``schema``).

    source, template, saltenv, template_context, dry_run
        Standard plumbing.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_custom_resource_definition name=widgets.example.io \
            spec='{"group": "example.io", "scope": "Namespaced", \
                  "names": {"plural": "widgets", "singular": "widget", "kind": "Widget"}, \
                  "versions": [{"name": "v1", "served": true, "storage": true, \
                  "schema": {"openAPIV3Schema": {"type": "object"}}}]}'
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source,
            "CustomResourceDefinition",
            template,
            saltenv,
            template_context,
            metadata,
            spec,
        )
    body = _build_crd(name, metadata, spec)
    cfg = _setup_conn(**kwargs)
    try:
        resp = _apiextensions_api().create_custom_resource_definition(
            body, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 409:
            raise CommandExecutionError(f"CustomResourceDefinition {name} already exists") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def replace_custom_resource_definition(
    name,
    metadata=None,
    spec=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """Replace a CRD.

    .. versionadded:: 2.1.0

    name, metadata, spec, source, template, saltenv, template_context, dry_run
        See :py:func:`create_custom_resource_definition`.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replace_custom_resource_definition name=widgets.example.io \
            spec=@/path/to/spec.json
    """
    if source:
        metadata, spec = _resolve_rbac_source(
            source,
            "CustomResourceDefinition",
            template,
            saltenv,
            template_context,
            metadata,
            spec,
        )
    body = _build_crd(name, metadata, spec)
    cfg = _setup_conn(**kwargs)
    try:
        resp = _apiextensions_api().replace_custom_resource_definition(
            name, body, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"CustomResourceDefinition {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_custom_resource_definition(
    name,
    patch=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
    dry_run=False,
    **kwargs,
):
    """Patch a CRD (strategic merge).

    .. versionadded:: 2.1.0

    name
        Name of the CRD.

    patch
        Patch dict.

    source, template, saltenv, template_context, dry_run
        Standard plumbing.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.patch_custom_resource_definition name=widgets.example.io \
            patch='{"metadata": {"annotations": {"owner": "platform"}}}'
    """
    if source:
        patch_doc = __read_and_render_yaml_file(source, template, saltenv, template_context)
    else:
        patch_doc = patch
    cfg = _setup_conn(**kwargs)
    try:
        resp = _apiextensions_api().patch_custom_resource_definition(
            name, patch_doc, dry_run="All" if dry_run else None
        )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"CustomResourceDefinition {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def delete_custom_resource_definition(name, wait=False, timeout=60, **kwargs):
    """Delete a CRD.

    .. versionadded:: 2.1.0

    Deletes the definition and (cascade) every instance of the custom
    resource. Use with care.

    name
        Name of the CRD.

    wait
        Block until the object is fully gone (the apiserver garbage-
        collects custom-resource instances first).

    timeout
        Seconds to wait when ``wait=True``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_custom_resource_definition name=widgets.example.io wait=True
    """
    cfg = _setup_conn(**kwargs)
    try:
        api = _apiextensions_api()
        resp = api.delete_custom_resource_definition(name)
        if wait:
            # No registry entry for the CRD kind itself; poll show_ to
            # confirm deletion. The apiserver clears the route in a
            # finite window after the finalizer runs.
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if show_custom_resource_definition(name) is None:
                    break
                time.sleep(1)
            else:
                raise CommandExecutionError(
                    f"Timeout waiting for CustomResourceDefinition {name} to be deleted"
                )
        return ApiClient().sanitize_for_serialization(resp)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# ---------------------------------------------------------------------------
# Pod operations: exec, logs, cp_to, cp_from
#
# These don't fit the {verb}_{kind} CRUD pattern — they're imperative Pod
# operations driven through the kubectl-style ``exec`` and ``log``
# subresources. cp_to / cp_from are tar pipes routed through exec, the
# same approach kubectl uses internally.
#
# .. versionadded:: 2.1.0
# ---------------------------------------------------------------------------


def _wrap_command(command):
    """Accept a string (run via /bin/sh -c) or a list of argv tokens."""
    if isinstance(command, str):
        return ["/bin/sh", "-c", command]
    if isinstance(command, list):
        return command
    raise CommandExecutionError("exec command must be a string or list of strings")


def _parse_exit_code_from_error_channel(error_payload):
    """
    Pull the command's exit code out of the websocket error-channel payload.

    Format observed across K8s versions::

        {"metadata":{}, "status":"Success"}
        {"metadata":{}, "status":"Failure", "reason":"NonZeroExitCode",
         "details":{"causes":[{"reason":"ExitCode","message":"42"}]}}

    Returns ``0`` when status is Success and a best-effort integer when
    Failure carries an ExitCode cause; ``-1`` if the payload is unparseable.
    """
    if not error_payload:
        return 0
    try:

        data = json.loads(error_payload)
    except (ValueError, TypeError):
        return -1
    if data.get("status") == "Success":
        return 0
    for cause in (data.get("details") or {}).get("causes") or []:
        if cause.get("reason") == "ExitCode":
            try:
                return int(cause["message"])
            except (KeyError, ValueError):
                pass
    return 1


def exec_(
    name,
    command,
    namespace="default",
    container=None,
    stdin=None,
    tty=False,
    timeout=60,
    **kwargs,
):
    """
    Execute *command* inside a running Pod (kubectl-exec equivalent).

    .. versionadded:: 2.1.0

    Returns a dict with ``stdout``, ``stderr`` and ``retcode``. If the
    wall-clock ``timeout`` elapses before the command exits, ``retcode``
    is ``-1`` and ``stderr`` contains a "timed out" sentinel; whatever
    was already buffered on stdout/stderr is returned.

    name
        Pod name.

    command
        Either a string (executed via ``/bin/sh -c``) or a list of argv
        tokens (executed directly).

    namespace
        Pod namespace. Default: ``default``.

    container
        Container name to exec into. Required when the Pod has more than
        one container.

    stdin
        Optional string fed to the command's stdin.

        .. note::

            The Kubernetes exec subresource websocket protocol does not
            expose a portable way to signal stdin EOF. Commands that
            block waiting for EOF (``cat``, ``tee``, ``read``) will run
            until the wall-clock ``timeout``. Wrap such commands with a
            byte-bounded reader (``head -c N``, ``dd count=N``) or use a
            shell heredoc to deliver fixed input.

    tty
        Allocate a TTY (rarely useful in non-interactive contexts).

    timeout
        Wall-clock cap in seconds. The exec is forcibly closed when the
        timeout elapses; whatever was buffered up to that point is
        returned. Default: 60.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.exec mypod 'echo hello'
        salt '*' kubernetes.exec mypod command='["cat", "/etc/hostname"]'
    """

    cfg = _setup_conn(**kwargs)
    try:
        api = kubernetes.client.CoreV1Api()
        cmd = _wrap_command(command)
        exec_kwargs = {
            "name": name,
            "namespace": namespace,
            "command": cmd,
            "stderr": True,
            "stdin": stdin is not None,
            "stdout": True,
            "tty": tty,
            "_preload_content": False,
        }
        if container:
            exec_kwargs["container"] = container
        resp = ws_stream(api.connect_get_namespaced_pod_exec, **exec_kwargs)

        try:
            if stdin is not None:
                resp.write_stdin(stdin)
                # Force the channel buffer onto the wire before we start
                # the read loop.
                resp.update(timeout=1)

            stdout_chunks = []
            stderr_chunks = []
            error_payload = None
            deadline = time.time() + max(timeout, 1)
            timed_out = False

            while resp.is_open():
                if time.time() >= deadline:
                    timed_out = True
                    break
                # Short per-poll timeout so the wall-clock check stays responsive.
                resp.update(timeout=1)
                if resp.peek_stdout():
                    stdout_chunks.append(resp.read_stdout())
                if resp.peek_stderr():
                    stderr_chunks.append(resp.read_stderr())
                if resp.peek_channel(ERROR_CHANNEL):
                    error_payload = resp.read_channel(ERROR_CHANNEL)
                    # Server signals end-of-stream on this channel.
                    break

            # Drain anything still buffered after the channel signal or timeout.
            if resp.peek_stdout():
                stdout_chunks.append(resp.read_stdout())
            if resp.peek_stderr():
                stderr_chunks.append(resp.read_stderr())
        finally:
            resp.close()

        if timed_out:
            stderr_chunks.append(
                f"\n[saltext.kubernetes] exec timed out after {timeout}s; "
                "command may still be running in the pod.\n"
            )
            return {
                "stdout": "".join(stdout_chunks),
                "stderr": "".join(stderr_chunks),
                "retcode": -1,
            }

        return {
            "stdout": "".join(stdout_chunks),
            "stderr": "".join(stderr_chunks),
            "retcode": _parse_exit_code_from_error_channel(error_payload),
        }
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Pod {name} not found in {namespace}") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def logs(
    name,
    namespace="default",
    container=None,
    previous=False,
    since_seconds=None,
    tail_lines=None,
    timestamps=False,
    **kwargs,
):
    """
    Fetch logs from a Pod (kubectl-logs equivalent).

    .. versionadded:: 2.1.0

    Returns the log text as a single string.

    name
        Pod name.

    namespace
        Pod namespace. Default: ``default``.

    container
        Container to fetch logs from. Required when the Pod has more than
        one container.

    previous
        If True, return logs from the *previous* terminated container
        instance (e.g. after a crash).

    since_seconds
        Only return logs from the last N seconds.

    tail_lines
        Only return the last N lines.

    timestamps
        Prefix each line with the API server's RFC3339 timestamp.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.logs mypod tail_lines=50
        salt '*' kubernetes.logs mypod container=app since_seconds=600
    """
    cfg = _setup_conn(**kwargs)
    try:
        api = kubernetes.client.CoreV1Api()
        log_kwargs = {
            "name": name,
            "namespace": namespace,
            "previous": previous,
            "timestamps": timestamps,
        }
        if container:
            log_kwargs["container"] = container
        if since_seconds is not None:
            log_kwargs["since_seconds"] = since_seconds
        if tail_lines is not None:
            log_kwargs["tail_lines"] = tail_lines
        return api.read_namespaced_pod_log(**log_kwargs)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Pod {name} not found in {namespace}") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def _filter_tar_members_for_extract(members, dst_path):
    """
    Return only those tar members whose resolved extraction path stays
    inside *dst_path*.

    Mirrors the Python 3.12 ``filter="data"`` semantics for the older
    Python patch releases that don't ship that parameter. Mitigates
    CWE-22 (path traversal) on archives produced by an in-pod ``tar``.
    """
    safe = []
    real_dst = os.path.realpath(dst_path)
    for member in members:
        if os.path.isabs(member.name) or member.name.startswith("/"):
            continue
        candidate = os.path.realpath(os.path.join(dst_path, member.name))
        if candidate == real_dst or candidate.startswith(real_dst + os.sep):
            safe.append(member)
    return safe


def _exec_for_cp(api, name, namespace, container, command, stdin_bytes=None):
    """
    Run a command via the exec websocket and return (stdout_bytes, stderr_str, retcode).

    Used by cp_to / cp_from for the underlying tar pipe. Unlike :py:func:`exec_`,
    this returns stdout as raw bytes so binary archives survive the round-trip.

    Implementation note: ``WSClient.write_stdin`` *replaces* the channel
    buffer rather than appending, so we must send the entire stdin in a
    single call (and immediately drive ``update()`` to flush it onto the
    wire) — chunked writes silently lose all but the last chunk. The
    in-pod tar detects end-of-archive from the tar format's own marker
    blocks rather than relying on stdin EOF, which the websocket wrapper
    cannot signal cleanly.
    """
    exec_kwargs = {
        "name": name,
        "namespace": namespace,
        "command": command,
        "stderr": True,
        "stdin": stdin_bytes is not None,
        "stdout": True,
        "tty": False,
        "_preload_content": False,
    }
    if container:
        exec_kwargs["container"] = container
    resp = ws_stream(api.connect_get_namespaced_pod_exec, **exec_kwargs)
    try:
        if stdin_bytes is not None:
            # The kubernetes-client WSClient encodes the channel buffer as a
            # single websocket frame on the next update(); decoding the
            # buffer expects a str, so we use surrogateescape to round-trip
            # arbitrary bytes through unicode without loss.
            resp.write_stdin(stdin_bytes.decode("utf-8", errors="surrogateescape"))
            # Force the channel buffer onto the wire before we start
            # waiting for stdout.
            resp.update(timeout=1)

        stdout = bytearray()
        stderr_chunks = []
        error_payload = None

        while resp.is_open():
            resp.update(timeout=5)
            if resp.peek_stdout():
                stdout.extend(resp.read_stdout().encode("utf-8", errors="surrogateescape"))
            if resp.peek_stderr():
                stderr_chunks.append(resp.read_stderr())
            if resp.peek_channel(ERROR_CHANNEL):
                error_payload = resp.read_channel(ERROR_CHANNEL)
                break
        # Drain remaining buffers after the loop exits.
        if resp.peek_stdout():
            stdout.extend(resp.read_stdout().encode("utf-8", errors="surrogateescape"))
        if resp.peek_stderr():
            stderr_chunks.append(resp.read_stderr())
    finally:
        resp.close()

    return bytes(stdout), "".join(stderr_chunks), _parse_exit_code_from_error_channel(error_payload)


def cp_to(
    name,
    src_path,
    dst_path,
    namespace="default",
    container=None,
    **kwargs,
):
    """
    Copy a local file or directory into a Pod (kubectl-cp equivalent).

    .. versionadded:: 2.1.0

    Implementation: tar the local source into a memory buffer and pipe it
    into the Pod via ``tar xf - -C <dst>``. The Pod must have a ``tar``
    binary on PATH.

    name
        Pod name.

    src_path
        Local file or directory to copy from.

    dst_path
        Destination directory inside the Pod. The local source is
        extracted *into* this directory (preserving its base name).

    namespace
        Pod namespace. Default: ``default``.

    container
        Target container in a multi-container Pod.

    Returns ``{"retcode": 0}`` on success; raises CommandExecutionError
    on tar failure or pod-side error.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.cp_to mypod /tmp/file.txt /var/data
    """
    if salt.utils.platform.is_windows():
        raise CommandExecutionError(
            "kubernetes.cp_to is not supported on Windows; the tar-pipe path "
            "depends on POSIX tar semantics."
        )

    if not os.path.exists(src_path):
        raise CommandExecutionError(f"Local source path does not exist: {src_path}")

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.add(src_path, arcname=os.path.basename(src_path))
    archive = buf.getvalue()

    cfg = _setup_conn(**kwargs)
    try:
        api = kubernetes.client.CoreV1Api()
        _stdout, err, rc = _exec_for_cp(
            api,
            name,
            namespace,
            container,
            command=["tar", "xf", "-", "-C", dst_path],
            stdin_bytes=archive,
        )
        if rc != 0:
            raise CommandExecutionError(
                f"cp_to failed (retcode={rc}); pod stderr: {err.strip() or '(empty)'}"
            )
        return {"retcode": rc}
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Pod {name} not found in {namespace}") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def cp_from(
    name,
    src_path,
    dst_path,
    namespace="default",
    container=None,
    **kwargs,
):
    """
    Copy a file or directory *from* a Pod to the local filesystem.

    .. versionadded:: 2.1.0

    Implementation: ``tar cf - <src>`` inside the Pod, capturing the
    archive over stdout, and extract it locally into *dst_path*.

    name
        Pod name.

    src_path
        Source path inside the Pod.

    dst_path
        Local destination directory. The source's base name is preserved
        as a child of this directory.

    namespace
        Pod namespace. Default: ``default``.

    container
        Source container in a multi-container Pod.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.cp_from mypod /var/log/app.log /tmp
    """
    if salt.utils.platform.is_windows():
        raise CommandExecutionError(
            "kubernetes.cp_from is not supported on Windows; the tar-pipe path "
            "depends on POSIX tar semantics."
        )

    if not os.path.isdir(dst_path):
        raise CommandExecutionError(f"Local destination must be a directory: {dst_path}")

    cfg = _setup_conn(**kwargs)
    try:
        api = kubernetes.client.CoreV1Api()
        # ``tar cf -`` from the parent so the archive includes the basename.
        parent = os.path.dirname(src_path.rstrip("/")) or "/"
        leaf = os.path.basename(src_path.rstrip("/"))
        archive_bytes, err, rc = _exec_for_cp(
            api,
            name,
            namespace,
            container,
            command=["tar", "cf", "-", "-C", parent, leaf],
        )
        if rc != 0 or not archive_bytes:
            raise CommandExecutionError(
                f"cp_from failed (retcode={rc}); pod stderr: {err.strip() or '(empty)'}"
            )
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r") as tar:
            # CWE-22: validate every member's resolved path stays inside
            # the destination before extracting. Python 3.12+ ships a
            # ``filter="data"`` parameter that does this, with backports
            # to recent 3.10.x / 3.11.x patch releases; for compatibility
            # across the full ``requires-python = ">= 3.10"`` range we
            # do the same check explicitly.
            safe_members = _filter_tar_members_for_extract(tar.getmembers(), dst_path)
            try:
                tar.extractall(dst_path, members=safe_members, filter="data")
            except TypeError:
                # Patch release predates the filter backport; the explicit
                # member filter above already enforces path safety.
                tar.extractall(dst_path, members=safe_members)  # nosec B202
        return {"retcode": rc}
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Pod {name} not found in {namespace}") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# ---------------------------------------------------------------------------
# Workload + cluster operations: scale, rollback, restart, cluster_info
#
# These wrap kubectl-style verbs for Deployment / StatefulSet / DaemonSet /
# ReplicaSet that don't fit the typed CRUD pattern. They use the dedicated
# /scale subresource where possible (so RBAC permissions can be scoped to
# scale separately from the parent object), and the same pod-template
# annotation trick kubectl uses for rollouts.
#
# .. versionadded:: 2.1.0
# ---------------------------------------------------------------------------


# Map workload kind -> (api_class_attr, scale_method, parent_methods).
# scale_method: ``patch_*_scale``. We use PATCH rather than READ-then-REPLACE
# because the deployment controller reconciles concurrently with our edit
# and a stale ``resourceVersion`` on the /scale subresource produces 409
# conflicts. PATCH on the scale subresource has no resourceVersion
# requirement and matches the behaviour kubectl ``scale`` falls back to.
# parent_methods: (read, patch) — for restart annotation tweaks.
_SCALABLE_KINDS = {
    "deployment": (
        "AppsV1Api",
        "patch_namespaced_deployment_scale",
        ("read_namespaced_deployment", "patch_namespaced_deployment"),
    ),
    "stateful_set": (
        "AppsV1Api",
        "patch_namespaced_stateful_set_scale",
        ("read_namespaced_stateful_set", "patch_namespaced_stateful_set"),
    ),
    "statefulset": (  # alias
        "AppsV1Api",
        "patch_namespaced_stateful_set_scale",
        ("read_namespaced_stateful_set", "patch_namespaced_stateful_set"),
    ),
    "replica_set": (
        "AppsV1Api",
        "patch_namespaced_replica_set_scale",
        ("read_namespaced_replica_set", "patch_namespaced_replica_set"),
    ),
    "replicaset": (  # alias
        "AppsV1Api",
        "patch_namespaced_replica_set_scale",
        ("read_namespaced_replica_set", "patch_namespaced_replica_set"),
    ),
}

# DaemonSet has no /scale subresource (it doesn't have a replicas concept)
# but it does support the restart annotation trick.
_RESTARTABLE_ONLY_KINDS = {
    "daemonset": (
        "AppsV1Api",
        ("read_namespaced_daemon_set", "patch_namespaced_daemon_set"),
    ),
    "daemon_set": (
        "AppsV1Api",
        ("read_namespaced_daemon_set", "patch_namespaced_daemon_set"),
    ),
}


def _normalise_workload_kind(kind):
    """Lower-case + underscore-normalise a kind name."""
    if not isinstance(kind, str):
        raise CommandExecutionError("kind must be a string")
    return kind.lower().replace(" ", "_").replace("-", "_")


def scale(kind, name, replicas, namespace="default", **kwargs):
    """
    Set the desired replica count for a Deployment, StatefulSet, or
    ReplicaSet via the ``/scale`` subresource (kubectl-scale equivalent).

    .. versionadded:: 2.1.0

    Returns the updated V1Scale dict.

    kind
        One of ``deployment``, ``statefulset``, ``replicaset``
        (underscore-tolerant: ``stateful_set``, ``replica_set`` also accepted).

    name
        Resource name.

    replicas
        New desired replica count (non-negative integer).

    namespace
        Namespace. Default: ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.scale deployment nginx 5
        salt '*' kubernetes.scale kind=statefulset name=db replicas=3
    """
    norm_kind = _normalise_workload_kind(kind)
    if norm_kind not in _SCALABLE_KINDS:
        raise CommandExecutionError(
            f"Unsupported scalable kind '{kind}'. Supported: "
            "deployment, statefulset, replicaset."
        )
    if not isinstance(replicas, int) or replicas < 0:
        raise CommandExecutionError("replicas must be a non-negative integer")

    api_attr, patch_scale_method, _ = _SCALABLE_KINDS[norm_kind]

    cfg = _setup_conn(**kwargs)
    try:
        api = getattr(kubernetes.client, api_attr)()
        # Use PATCH rather than read-modify-write to avoid 409 conflicts
        # from concurrent reconciliation by the deployment controller.
        body = {"spec": {"replicas": replicas}}
        updated = getattr(api, patch_scale_method)(name, namespace, body)
        return ApiClient().sanitize_for_serialization(updated)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"{kind} {name} not found in {namespace}") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def restart(kind, name, namespace="default", **kwargs):
    """
    Trigger a rolling restart of a Deployment / StatefulSet / DaemonSet /
    ReplicaSet by stamping the pod template with the same
    ``kubectl.kubernetes.io/restartedAt`` annotation kubectl uses.

    .. versionadded:: 2.1.0

    Returns the patched object.

    kind
        ``deployment``, ``statefulset``, ``replicaset``, or ``daemonset``
        (underscore-tolerant).

    name
        Resource name.

    namespace
        Namespace. Default: ``default``.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.restart deployment nginx
        salt '*' kubernetes.restart kind=daemonset name=fluentd
    """

    norm_kind = _normalise_workload_kind(kind)
    if norm_kind in _SCALABLE_KINDS:
        api_attr, _scale_method, parent_methods = _SCALABLE_KINDS[norm_kind]
    elif norm_kind in _RESTARTABLE_ONLY_KINDS:
        api_attr, parent_methods = _RESTARTABLE_ONLY_KINDS[norm_kind]
    else:
        raise CommandExecutionError(
            f"Unsupported restartable kind '{kind}'. Supported: "
            "deployment, statefulset, replicaset, daemonset."
        )

    _, patch_method = parent_methods
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    patch_body = {
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "kubectl.kubernetes.io/restartedAt": now,
                    }
                }
            }
        }
    }

    cfg = _setup_conn(**kwargs)
    try:
        api = getattr(kubernetes.client, api_attr)()
        result = getattr(api, patch_method)(name, namespace, patch_body)
        return ApiClient().sanitize_for_serialization(result)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"{kind} {name} not found in {namespace}") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def rollback(name, namespace="default", to_revision=None, **kwargs):
    """
    Roll a Deployment back to a previous revision (kubectl-rollout-undo
    equivalent for Deployments).

    .. versionadded:: 2.1.0

    Implementation: list the ReplicaSets owned by the Deployment, sort
    them by the ``deployment.kubernetes.io/revision`` annotation, pick
    the target (the second-newest by default, or the one matching
    *to_revision* if given), and patch the Deployment's
    ``.spec.template`` to that ReplicaSet's pod template.

    This avoids the deprecated v1 ``/rollback`` subresource (removed in
    K8s 1.16+) and matches the modern kubectl behaviour.

    name
        Deployment name.

    namespace
        Namespace. Default: ``default``.

    to_revision
        Revision number to roll back to. If ``None``, picks the
        immediately preceding revision.

    Returns the patched Deployment.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.rollback nginx
        salt '*' kubernetes.rollback nginx to_revision=3
    """
    cfg = _setup_conn(**kwargs)
    try:
        apps_api = kubernetes.client.AppsV1Api()
        deployment = apps_api.read_namespaced_deployment(name, namespace)
        current_rev = (deployment.metadata.annotations or {}).get(
            "deployment.kubernetes.io/revision"
        )

        # The Deployment owns its ReplicaSets via ownerReferences; we
        # filter on that rather than on label selector so we get exactly
        # the right revision lineage.
        all_rs = apps_api.list_namespaced_replica_set(namespace).items
        owned = [
            rs
            for rs in all_rs
            if any(
                ref.kind == "Deployment" and ref.uid == deployment.metadata.uid
                for ref in (rs.metadata.owner_references or [])
            )
        ]
        if not owned:
            raise CommandExecutionError(f"Deployment {name} has no ReplicaSets to roll back to")

        def _rev(rs):
            try:
                return int(
                    (rs.metadata.annotations or {}).get("deployment.kubernetes.io/revision", "0")
                )
            except ValueError:
                return 0

        owned.sort(key=_rev, reverse=True)

        if to_revision is None:
            # Skip the current revision; take the next one down.
            target = next(
                (rs for rs in owned if str(_rev(rs)) != str(current_rev)),
                None,
            )
        else:
            target = next(
                (rs for rs in owned if _rev(rs) == int(to_revision)),
                None,
            )

        if target is None:
            raise CommandExecutionError(
                f"No suitable rollback target for Deployment {name} "
                f"(to_revision={to_revision}, current={current_rev})"
            )

        # Patch the deployment's pod template with the target RS's
        # template. We strip the pod-template-hash that the controller
        # owns; the deployment controller will re-add it.
        target_template = ApiClient().sanitize_for_serialization(target.spec.template)
        labels = (target_template.get("metadata", {}) or {}).get("labels", {})
        labels.pop("pod-template-hash", None)

        patch_body = {"spec": {"template": target_template}}
        result = apps_api.patch_namespaced_deployment(name, namespace, patch_body)
        return ApiClient().sanitize_for_serialization(result)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Deployment {name} not found in {namespace}") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def patch_object(
    kind,
    name,
    patch,
    api_version=None,
    namespace=None,
    patch_type="strategic",
    field_manager=None,
    dry_run=False,
    **kwargs,
):
    """
    Generic object patch with a caller-selected merge strategy.

    .. versionadded:: 2.1.0

    Lets callers pick between strategic-merge (the kubectl/typed default),
    JSON merge patch (RFC 7396), and JSON patch (RFC 6902). Useful for
    CRDs (which only support merge / json patches) and for explicit
    list-element manipulation via RFC 6902 operations.

    This is the **public, user-facing** patch entry point. It is a thin
    wrapper around the internal
    :py:func:`saltext.kubernetes.utils._dynamic.patch_object` plumbing —
    callers should never reach into ``_dynamic`` directly. The wrapping
    adds three things on top of the GVK-level patch primitive:

    1. Connection lifecycle — runs ``_setup_conn`` (which honours every
       Salt config / pillar / kwarg / env-var precedence rule documented
       on :py:func:`_setup_conn`) before the call and ``_cleanup`` after.
    2. Kwarg marshalling — accepts the standard Salt-loader ``**kwargs``
       (``kubeconfig``, ``context``, ``cluster``, ``host``, ``api_key``,
       etc.) that the loader forwards to module functions.
    3. ``api_version`` inference — when omitted, the function looks up
       the GVK in the typed kind-registry (``_KIND_TO_GVK``) so callers
       can pass ``kind="Deployment"`` without spelling out the
       group/version. CRDs and other off-registry kinds require an
       explicit ``api_version``.

    kind
        Kubernetes ``Kind`` (case-sensitive, e.g. ``"Deployment"``,
        ``"ConfigMap"``, ``"MyCustomResource"``).

    name
        Object name.

    patch
        For ``patch_type="strategic"`` or ``"merge"``: a dict describing
        the partial object. For ``patch_type="json"``: a list of
        operation dicts in RFC 6902 format.

    api_version
        Group/version for the resource (e.g. ``"apps/v1"``,
        ``"example.com/v1"``). If omitted, the function attempts to
        infer it from the typed kind-registry — works for the bundled
        kinds; CRDs require an explicit ``api_version``.

    namespace
        Namespace for namespaced kinds.

    patch_type
        One of ``"strategic"`` (default), ``"merge"`` /
        ``"json-merge"``, or ``"json"`` / ``"json-patch"``.

    field_manager
        Optional fieldManager name (server-side apply convention).

    dry_run
        If ``True``, the API server validates the patch and returns the
        resulting object without persisting changes.

    CLI Examples:

    .. code-block:: bash

        # Strategic-merge replace replicas
        salt '*' kubernetes.patch_object kind=Deployment name=nginx \
            namespace=default api_version=apps/v1 \
            patch='{"spec": {"replicas": 5}}'

        # RFC 6902 JSON patch
        salt '*' kubernetes.patch_object kind=Deployment name=nginx \
            namespace=default api_version=apps/v1 patch_type=json \
            patch='[{"op": "replace", "path": "/spec/replicas", "value": 5}]'
    """
    if api_version is None:
        api_version = _infer_api_version(kind)
    cfg = _setup_conn(**kwargs)
    try:
        return _dynamic.patch_object(
            api_version=api_version,
            kind=kind,
            name=name,
            patch=patch,
            namespace=namespace,
            patch_type=patch_type,
            field_manager=field_manager,
            dry_run=dry_run,
        )
    finally:
        _cleanup(**cfg)


# Maps the snake_case kind names used in ``_KIND_REGISTRY`` to the
# (api_version, Kind) pair the dynamic client expects. Used by
# ``patch_object`` when the caller omits ``api_version``.
_KIND_TO_GVK = {
    "deployment": ("apps/v1", "Deployment"),
    "statefulset": ("apps/v1", "StatefulSet"),
    "replicaset": ("apps/v1", "ReplicaSet"),
    "daemonset": ("apps/v1", "DaemonSet"),
    "pod": ("v1", "Pod"),
    "service": ("v1", "Service"),
    "secret": ("v1", "Secret"),
    "configmap": ("v1", "ConfigMap"),
    "namespace": ("v1", "Namespace"),
    "storageclass": ("storage.k8s.io/v1", "StorageClass"),
    "role": ("rbac.authorization.k8s.io/v1", "Role"),
    "role_binding": ("rbac.authorization.k8s.io/v1", "RoleBinding"),
    "cluster_role": ("rbac.authorization.k8s.io/v1", "ClusterRole"),
    "cluster_role_binding": ("rbac.authorization.k8s.io/v1", "ClusterRoleBinding"),
    "service_account": ("v1", "ServiceAccount"),
    "job": ("batch/v1", "Job"),
    "cron_job": ("batch/v1", "CronJob"),
    "ingress": ("networking.k8s.io/v1", "Ingress"),
    "horizontal_pod_autoscaler": ("autoscaling/v2", "HorizontalPodAutoscaler"),
    "pod_disruption_budget": ("policy/v1", "PodDisruptionBudget"),
    "persistent_volume": ("v1", "PersistentVolume"),
    "persistent_volume_claim": ("v1", "PersistentVolumeClaim"),
}


def _infer_api_version(kind):
    """
    Return apiVersion for a registered Kind; raise for unknowns.

    Caller may pass the kind in CamelCase (matching ``metadata.kind``), in
    snake_case with separators (matching the kind-registry's
    ``"cluster_role"`` form), or in lowercase-no-separator form
    (matching the registry's ``"configmap"`` form). All three are tried.
    """
    lookup = _KIND_TO_GVK.get(kind)
    if lookup is None:
        snake = re.sub(r"(?<!^)(?=[A-Z])", "_", kind).lower()
        lookup = _KIND_TO_GVK.get(snake) or _KIND_TO_GVK.get(snake.replace("_", ""))
    if lookup is None:
        raise CommandExecutionError(
            f"Cannot infer api_version for kind {kind!r}; pass it explicitly."
        )
    return lookup[0]


def _hash_suffix(*components):
    """
    Produce a short deterministic suffix from one or more dict / scalar
    components. Used by ``append_hash=True`` on ``create_configmap`` and
    ``create_secret``.

    The suffix is the first 10 chars of the SHA-256 of the canonicalised
    JSON encoding of *components*. This is not byte-identical to
    kubectl's custom base32 algorithm, but achieves the same goals:
    deterministic, DNS-label-safe, short enough for the 63-char name
    limit, low collision risk for realistic data sizes. Stable across
    Python versions because ``sort_keys=True`` removes dict-ordering
    nondeterminism.
    """
    payload = _pyyaml.safe_dump(list(components), default_flow_style=False, sort_keys=True)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return digest[:10]


def list_clusters():
    """
    Return the configured cluster aliases for this minion.

    .. versionadded:: 2.1.0

    Aliases are defined under the ``kubernetes.clusters`` pillar key:

    .. code-block:: yaml

        kubernetes:
          clusters:
            prod:
              kubeconfig: /etc/k8s/prod.conf
              context: prod-admin
            staging:
              host: https://staging.example.com:6443
              api_key: ...

    The implicit alias ``"default"`` always appears, representing the
    top-level ``kubernetes.*`` config block.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.list_clusters
    """
    return list_configured_clusters(__salt__["config.option"])


def wait_for(
    name,
    kind,
    namespace=None,
    condition=None,
    status="True",
    jsonpath=None,
    value=None,
    regex=None,
    timeout=60,
    **kwargs,
):
    """
    Block until a live resource matches a user-supplied condition or jsonpath.

    .. versionadded:: 2.1.0

    Mirrors ``kubectl wait`` ergonomics. Pass exactly one of ``condition``
    or ``jsonpath``.

    name
        Object name.

    kind
        Resource type as recognised by the kind registry
        (e.g. ``deployment``, ``service``, ``pod``).

    namespace
        Namespace for namespaced kinds. Ignored for cluster-scoped kinds.

    condition
        ``status.conditions[*].type`` to match (e.g. ``Available``,
        ``Ready``). The matching condition's ``status`` must equal ``status``.

    status
        Expected condition status when ``condition`` is given. Defaults to
        ``"True"``.

    jsonpath
        kubectl-style jsonpath to resolve against the live object
        (e.g. ``.status.loadBalancer.ingress[0].ip``). Mutually exclusive
        with ``condition``.

    value
        When ``jsonpath`` is given, require equality with ``value``.

    regex
        When ``jsonpath`` is given, require the stringified value to match
        this regex (``re.search``).

    timeout
        Seconds to wait before giving up. Default 60.

    Returns ``True`` on match, raises :py:class:`CommandExecutionError` on
    timeout or on watch errors.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.wait_for nginx kind=deployment condition=Available
    """
    predicate = _kinds.build_predicate(
        condition=condition, status=status, jsonpath=jsonpath, value=value, regex=regex
    )
    kind_ops = _kinds.get_kind(kind)
    cfg = _setup_conn(**kwargs)
    try:
        api_class = getattr(kubernetes.client, kind_ops.api_class_attr)
        api_instance = api_class()
        ok = _wait_for_resource_status(
            api_instance, kind, name, namespace, "ready", timeout=timeout, predicate=predicate
        )
        if not ok:
            criterion = f"condition={condition}={status}" if condition else f"jsonpath={jsonpath}"
            raise CommandExecutionError(
                f"Timeout waiting for {kind}/{name} to match {criterion} after {timeout}s"
            )
        return True
    finally:
        _cleanup(**cfg)


def cluster_info(**kwargs):
    """
    Return a summary of the cluster (kubectl-cluster-info / kubectl-version
    equivalent).

    .. versionadded:: 2.1.0

    Returns a dict with:

    * ``server_version`` — the API server's reported version (major,
      minor, gitVersion, platform, etc.)
    * ``healthz`` — string body returned by ``GET /healthz`` (typically
      ``"ok"`` on a healthy cluster).
    * ``api_groups`` — list of available API group names.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.cluster_info
    """
    cfg = _setup_conn(**kwargs)
    try:
        version_api = kubernetes.client.VersionApi()
        version = version_api.get_code()
        server_version = ApiClient().sanitize_for_serialization(version)

        # /healthz isn't modelled in the typed API; call it via the
        # generic api_client. Most clusters return a plain "ok".
        api_client = kubernetes.client.ApiClient()
        try:
            resp = api_client.call_api(
                "/healthz",
                "GET",
                response_type="str",
                _preload_content=True,
                auth_settings=["BearerToken"],
            )
            healthz = resp[0] if isinstance(resp, tuple) else resp
        except (ApiException, HTTPError):
            healthz = "unavailable"

        groups_api = kubernetes.client.ApisApi()
        groups_resp = groups_api.get_api_versions()
        api_groups = [g.name for g in (groups_resp.groups or []) if getattr(g, "name", None)]

        return {
            "server_version": server_version,
            "healthz": healthz,
            "api_groups": sorted(api_groups),
        }
    except (ApiException, HTTPError) as exc:
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# ---------------------------------------------------------------------------
# Node lifecycle operations: cordon, uncordon, drain, taint, untaint
#
# These mirror kubectl's per-node verbs. ``drain`` uses the eviction API
# (``CoreV1Api.create_namespaced_pod_eviction``) to respect PodDisruption
# Budgets — falling through to a direct delete only when ``disable_eviction``
# is set explicitly.
#
# .. versionadded:: 2.1.0
# ---------------------------------------------------------------------------


_VALID_TAINT_EFFECTS = {"NoSchedule", "PreferNoSchedule", "NoExecute"}


def cordon(name, **kwargs):
    """
    Mark a node as unschedulable (kubectl-cordon equivalent).

    .. versionadded:: 2.1.0

    name
        Node name.

    Returns the patched Node object.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.cordon
    """
    cfg = _setup_conn(**kwargs)
    try:
        api = kubernetes.client.CoreV1Api()
        body = {"spec": {"unschedulable": True}}
        result = api.patch_node(name, body)
        return ApiClient().sanitize_for_serialization(result)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Node {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def uncordon(name, **kwargs):
    """
    Mark a node as schedulable again (kubectl-uncordon equivalent).

    .. versionadded:: 2.1.0

    Sends ``spec.unschedulable: null`` so the field is removed via
    strategic-merge patch. Setting ``False`` would leave the field
    present (just falsy), which kubectl avoids for cleanliness.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.uncordon
    """
    cfg = _setup_conn(**kwargs)
    try:
        api = kubernetes.client.CoreV1Api()
        body = {"spec": {"unschedulable": None}}
        result = api.patch_node(name, body)
        return ApiClient().sanitize_for_serialization(result)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Node {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def taint(name, key, effect, value=None, **kwargs):
    """
    Add (or update) a taint on a node (kubectl-taint equivalent).

    .. versionadded:: 2.1.0

    Existing taints with the same ``(key, effect)`` are replaced; other
    taints are preserved. To remove a taint use :py:func:`untaint`.

    name
        Node name.

    key
        Taint key. The standard reserved keys are
        ``node-role.kubernetes.io/control-plane``, ``node.kubernetes.io/*``;
        operator-defined keys are arbitrary strings.

    effect
        One of ``NoSchedule``, ``PreferNoSchedule``, ``NoExecute``.

    value
        Optional taint value.

    Returns the patched Node object.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.taint nodename gpu effect=NoSchedule value=true
    """
    if effect not in _VALID_TAINT_EFFECTS:
        raise CommandExecutionError(
            f"Invalid taint effect '{effect}'. Must be one of: "
            + ", ".join(sorted(_VALID_TAINT_EFFECTS))
        )

    cfg = _setup_conn(**kwargs)
    try:
        api = kubernetes.client.CoreV1Api()
        node = api.read_node(name)
        existing = list(node.spec.taints or [])
        # Replace any taint matching (key, effect); keep the rest.
        kept = [t for t in existing if not (t.key == key and t.effect == effect)]
        kept.append(kubernetes.client.V1Taint(key=key, effect=effect, value=value))
        body = {"spec": {"taints": [ApiClient().sanitize_for_serialization(t) for t in kept]}}
        result = api.patch_node(name, body)
        return ApiClient().sanitize_for_serialization(result)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Node {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def untaint(name, key, effect=None, **kwargs):
    """
    Remove a taint from a node.

    .. versionadded:: 2.1.0

    name
        Node name.

    key
        Taint key to remove.

    effect
        Optional. If given, removes only the taint with matching
        ``(key, effect)``; if omitted, removes every taint with this
        key regardless of effect.

    Returns the patched Node object.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.untaint
    """
    if effect is not None and effect not in _VALID_TAINT_EFFECTS:
        raise CommandExecutionError(
            f"Invalid taint effect '{effect}'. Must be one of: "
            + ", ".join(sorted(_VALID_TAINT_EFFECTS))
        )

    cfg = _setup_conn(**kwargs)
    try:
        api = kubernetes.client.CoreV1Api()
        node = api.read_node(name)
        existing = list(node.spec.taints or [])
        if effect is None:
            kept = [t for t in existing if t.key != key]
        else:
            kept = [t for t in existing if not (t.key == key and t.effect == effect)]
        body = {"spec": {"taints": [ApiClient().sanitize_for_serialization(t) for t in kept]}}
        result = api.patch_node(name, body)
        return ApiClient().sanitize_for_serialization(result)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Node {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


def _is_daemonset_pod(pod):
    """A pod is owned by a DaemonSet if any ownerReference says so."""
    for ref in pod.metadata.owner_references or []:
        if ref.kind == "DaemonSet":
            return True
    return False


def _is_mirror_pod(pod):
    """Mirror pods (kubelet-managed static pods) carry this annotation."""
    annotations = pod.metadata.annotations or {}
    return "kubernetes.io/config.mirror" in annotations


def _has_emptydir_volume(pod):
    """True if any volume on the pod is an emptyDir."""
    for vol in pod.spec.volumes or []:
        if vol.empty_dir is not None:
            return True
    return False


def drain(
    name,
    ignore_daemonsets=True,
    delete_emptydir_data=False,
    disable_eviction=False,
    force=False,
    grace_period_seconds=None,
    timeout=300,
    **kwargs,
):
    """
    Drain a node: cordon it, then evict every (non-DaemonSet, non-mirror)
    pod on it, waiting for the pods to terminate (kubectl-drain equivalent).

    .. versionadded:: 2.1.0

    name
        Node name.

    ignore_daemonsets
        Skip DaemonSet-owned pods (which the DaemonSet controller would
        immediately recreate). Default: ``True`` — matches kubectl's
        default and the only sensible production behaviour.

    delete_emptydir_data
        Allow draining pods that use ``emptyDir`` volumes (the data is
        lost). Without this flag and ``force=True``, the drain refuses
        to remove such pods. Default: ``False``.

    disable_eviction
        Bypass the eviction API and delete pods directly. Skips
        PodDisruptionBudget enforcement. Use only when you understand
        the consequences. Default: ``False``.

    force
        Required to drain pods that are not managed by a controller
        (bare pods). Without it the drain refuses to remove such pods,
        matching kubectl. Default: ``False``.

    grace_period_seconds
        Per-pod termination grace period override. ``None`` means use
        the pod's own ``terminationGracePeriodSeconds``.

    timeout
        Wall-clock cap in seconds for the entire drain (cordon + eviction
        + waiting for terminations). Default: 300.

    Returns a dict::

        {"node": <name>,
         "evicted": [<pod-namespace/pod-name>, ...],
         "skipped": [{"pod": ..., "reason": ...}, ...],
         "errors": [{"pod": ..., "error": ...}]}

    Raises ``CommandExecutionError`` if the timeout elapses before all
    pods terminate, or if any pod could not be evicted at all.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.drain
    """

    cfg = _setup_conn(**kwargs)
    try:
        api = kubernetes.client.CoreV1Api()
        # Verify the node exists before we cordon — gives a clear error
        # if the user mistyped the name.
        api.read_node(name)

        # Step 1: cordon.
        api.patch_node(name, {"spec": {"unschedulable": True}})

        # Step 2: list every pod on the node.
        pods = api.list_pod_for_all_namespaces(field_selector=f"spec.nodeName={name}").items

        evicted = []
        skipped = []
        errors = []
        targets = []  # pods we'll actually evict

        for pod in pods:
            pod_id = f"{pod.metadata.namespace}/{pod.metadata.name}"
            if _is_mirror_pod(pod):
                skipped.append({"pod": pod_id, "reason": "mirror pod"})
                continue
            if _is_daemonset_pod(pod):
                if ignore_daemonsets:
                    skipped.append({"pod": pod_id, "reason": "daemonset"})
                    continue
                # User opted in to draining DS pods; let them proceed.
            if _has_emptydir_volume(pod) and not delete_emptydir_data:
                if not force:
                    raise CommandExecutionError(
                        f"Pod {pod_id} uses emptyDir volumes; "
                        "set delete_emptydir_data=True (data will be lost) "
                        "or force=True to override."
                    )
                # ``force`` alone allows the drain to proceed; the data
                # loss is on the user.
            if not (pod.metadata.owner_references or []) and not force:
                raise CommandExecutionError(
                    f"Pod {pod_id} is not managed by a controller (bare "
                    "pod); set force=True to evict anyway."
                )
            targets.append(pod)

        # Step 3: evict each target.
        delete_options = None
        if grace_period_seconds is not None:
            delete_options = kubernetes.client.V1DeleteOptions(
                grace_period_seconds=grace_period_seconds
            )

        for pod in targets:
            pod_id = f"{pod.metadata.namespace}/{pod.metadata.name}"
            try:
                if disable_eviction:
                    api.delete_namespaced_pod(
                        pod.metadata.name,
                        pod.metadata.namespace,
                        grace_period_seconds=grace_period_seconds,
                    )
                else:
                    eviction = kubernetes.client.V1Eviction(
                        api_version="policy/v1",
                        kind="Eviction",
                        metadata=kubernetes.client.V1ObjectMeta(
                            name=pod.metadata.name,
                            namespace=pod.metadata.namespace,
                        ),
                        delete_options=delete_options,
                    )
                    api.create_namespaced_pod_eviction(
                        pod.metadata.name, pod.metadata.namespace, eviction
                    )
                evicted.append(pod_id)
            except (ApiException, HTTPError) as exc:
                # 429 = PDB blocks the eviction; treat as a soft failure
                # since kubectl drain retries. We surface the error to
                # the caller via ``errors`` rather than raising mid-drain.
                errors.append({"pod": pod_id, "error": str(exc)})

        # Step 4: wait for the targeted pods to terminate (or timeout).
        deadline = time.time() + max(timeout, 1)
        target_ids = {(p.metadata.namespace, p.metadata.name) for p in targets}
        while time.time() < deadline and target_ids:
            time.sleep(2)
            still_present = set()
            for ns, pod_name in target_ids:
                try:
                    api.read_namespaced_pod(pod_name, ns)
                    still_present.add((ns, pod_name))
                except ApiException as exc:
                    if exc.status != 404:
                        # Transient error; consider the pod still present.
                        still_present.add((ns, pod_name))
            target_ids = still_present

        if target_ids:
            still = sorted(f"{ns}/{n}" for ns, n in target_ids)
            errors.append(
                {
                    "pod": ",".join(still),
                    "error": (
                        f"Timeout ({timeout}s) waiting for pods to terminate; "
                        f"still present: {still}"
                    ),
                }
            )

        return {
            "node": name,
            "evicted": evicted,
            "skipped": skipped,
            "errors": errors,
        }
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Node {name} not found") from exc
        raise CommandExecutionError(exc) from exc
    finally:
        _cleanup(**cfg)


# ---------------------------------------------------------------------------
# Generic apply: kubernetes.apply, kubernetes.delete_manifest
#
# Wraps the dynamic-client primitives in saltext.kubernetes.utils._dynamic
# with source-file rendering, multi-document YAML support, namespace
# defaulting, and the ergonomic argument shapes Salt callers expect.
#
# .. versionadded:: 2.1.0
# ---------------------------------------------------------------------------


def _render_yaml_multi(source, template, saltenv, template_context=None):
    """
    Like ``__read_and_render_yaml_file`` but returns a list of every
    document in a multi-doc YAML file (separated by ``---``).
    """
    saltenv = saltenv or __opts__["saltenv"] or "base"
    sfn = __salt__["cp.cache_file"](source, saltenv)
    if not sfn:
        raise CommandExecutionError(f"Source file '{source}' not found")
    with salt.utils.files.fopen(sfn, "r") as src:
        contents = src.read()
    if template:
        if template not in salt.utils.templates.TEMPLATE_REGISTRY:
            raise CommandExecutionError(f"Unknown template specified: {template}")
        if template_context is None:
            template_context = {}
        data = salt.utils.templates.TEMPLATE_REGISTRY[template](
            contents,
            from_str=True,
            to_str=True,
            saltenv=saltenv,
            grains=__grains__,
            pillar=__pillar__,
            salt=__salt__,
            opts=__opts__,
            context=template_context,
        )
        if not data["result"]:
            raise CommandExecutionError(f'Failed to render file path with error: {data["data"]}')
        contents = data["data"]
    # salt.utils.yaml only exposes single-doc safe_load; use PyYAML's
    # safe_load_all directly for multi-document files. PyYAML is a
    # transitive dependency of Salt and the kubernetes-client.

    return [doc for doc in _pyyaml.safe_load_all(contents) if doc]


def _normalise_apply_input(manifest, source, template, saltenv, template_context):
    """
    Coerce ``manifest`` / ``source`` arguments into a list of dict
    manifests ready to feed to ``_dynamic.apply_manifest``.

    Accepts (in priority order):
      * ``source`` — salt:// fileserver path, possibly multi-doc YAML.
      * ``manifest`` — a dict (single doc), a list of dicts (multi-doc),
        or a string (YAML, possibly multi-doc).
    """
    if source:
        return _render_yaml_multi(source, template, saltenv, template_context)
    if manifest is None:
        raise CommandExecutionError("Either 'manifest' or 'source' must be provided")
    if isinstance(manifest, dict):
        return [manifest]
    if isinstance(manifest, list):
        out = []
        for entry in manifest:
            if not isinstance(entry, dict):
                raise CommandExecutionError("Each manifest list entry must be a dictionary")
            out.append(entry)
        return out
    if isinstance(manifest, str):

        return [doc for doc in _pyyaml.safe_load_all(manifest) if doc]
    raise CommandExecutionError(
        f"manifest must be a dict, list, or YAML string, not {type(manifest).__name__}"
    )


def _apply_namespace_default(doc, namespace):
    """If *doc* lacks ``metadata.namespace`` and *namespace* is given, fill it in."""
    if namespace and isinstance(doc, dict):
        meta = doc.setdefault("metadata", {})
        if not meta.get("namespace"):
            meta["namespace"] = namespace


def apply(
    manifest=None,
    source=None,
    namespace=None,
    field_manager="salt",
    force_conflicts=False,
    dry_run=False,
    template=None,
    saltenv=None,
    template_context=None,
    ignore_labels=None,
    ignore_annotations=None,
    ignore_fields=None,
    validate=False,
    **kwargs,
):
    """
    Server-side apply one or more Kubernetes manifests (kubectl-apply
    --server-side equivalent).

    .. versionadded:: 2.1.0

    Accepts a manifest as a Python dict, a list of dicts, a YAML string
    (single- or multi-document), or a ``source`` path to a YAML file
    that may itself contain multiple documents separated by ``---``.
    Source files can be Jinja-templated by setting ``template``.

    Returns a list of applied object dicts when more than one manifest
    is supplied, or a single dict when there's exactly one.

    Unlike the typed CRUD paths (which default missing namespaces to
    ``"default"``), this function deliberately requires an explicit
    namespace for namespaced kinds — either in the manifest's
    ``metadata.namespace`` field or via the ``namespace`` parameter.

    manifest
        A dict, list of dicts, or YAML string. Mutually exclusive with
        ``source``.

    source
        Salt fileserver path (``salt://...``), local path, or anything
        ``cp.cache_file`` can resolve. Mutually exclusive with
        ``manifest``.

    namespace
        Fallback namespace for any document that does not declare its
        own ``metadata.namespace``. Cluster-scoped kinds ignore this.

    field_manager
        SSA fieldManager name. Default: ``"salt"``. Multiple Salt
        masters managing the same cluster should each set a unique
        manager so SSA's conflict tracking can distinguish them.

    force_conflicts
        If ``True``, override fields owned by another manager. Default:
        ``False`` (apply fails if another manager owns a field we're
        trying to set). Use sparingly.

    dry_run
        If ``True``, perform a server-side dry-run apply: the API
        server validates the manifest and returns what *would* be
        written, without persisting changes. Useful for state-mode
        ``test=True`` previews and for catching admission-webhook
        rejections before commit.

    template
        Template engine to render the source file (e.g. ``"jinja"``).

    saltenv
        Salt environment for resolving the source file.

    template_context
        Variables passed to the renderer.

    ignore_labels
        List of label keys to exclude from drift detection. The desired
        manifest's values under these keys are dropped before apply; the
        API server's existing values are preserved.

    ignore_annotations
        List of annotation keys to exclude from drift detection. Same
        semantics as ``ignore_labels``. Note: kubectl bookkeeping
        annotations (``kubectl.kubernetes.io/*`` and
        ``deployment.kubernetes.io/*``) are always excluded.

    ignore_fields
        List of JSON-pointer paths (e.g. ``"/spec/replicas"``) to drop
        from the desired manifest before apply. Useful when another
        controller manages the field (HPA → ``replicas``,
        admission-webhook → ``spec.template.spec.serviceAccountName``).

    validate
        If ``True``, run a server-side dry-run apply first to surface
        validation errors (schema violations, admission-webhook
        rejections, RBAC denials) before the real apply. Cheap to
        enable; matches ``kubernetes.core`` ``validate.fail_on_error``.

    CLI Examples:

    .. code-block:: bash

        salt '*' kubernetes.apply source=salt://manifests/app.yaml
        salt '*' kubernetes.apply manifest='{"apiVersion": "v1", \\
            "kind": "ConfigMap", "metadata": {"name": "x", "namespace": "default"}, \\
            "data": {"k": "v"}}'
    """

    docs = _normalise_apply_input(manifest, source, template, saltenv, template_context)
    if not docs:
        raise CommandExecutionError("No manifests to apply")

    cfg = _setup_conn(**kwargs)
    try:
        results = []
        for doc in docs:
            _apply_namespace_default(doc, namespace)
            doc = _strip_ignored(doc, ignore_labels, ignore_annotations, ignore_fields)
            # When ``validate`` is requested, run a dry-run first. Any
            # API-server-side validation error (schema, admission webhook,
            # RBAC) surfaces as a CommandExecutionError that the caller
            # can catch *before* anything is persisted.
            if validate and not dry_run:
                _dynamic.apply_manifest(
                    doc,
                    field_manager=field_manager,
                    force_conflicts=force_conflicts,
                    dry_run=True,
                )
            results.append(
                _dynamic.apply_manifest(
                    doc,
                    field_manager=field_manager,
                    force_conflicts=force_conflicts,
                    dry_run=dry_run,
                )
            )
        return results[0] if len(results) == 1 else results
    finally:
        _cleanup(**cfg)


def _strip_ignored(doc, ignore_labels, ignore_annotations, ignore_fields):
    """
    Remove drift-suppressed paths from a manifest document before apply.

    Server-side apply records ownership of each field by ``fieldManager``.
    When the caller declares that *we* should not own a label / annotation
    / field, we drop it from the desired document so SSA leaves the live
    value alone. Returns a shallow copy with the requested deletions
    applied; the input dict is not mutated.
    """
    if not (ignore_labels or ignore_annotations or ignore_fields):
        return doc
    out = copy.deepcopy(doc)
    metadata = out.setdefault("metadata", {})
    if ignore_labels:
        labels = metadata.get("labels") or {}
        for key in ignore_labels:
            labels.pop(key, None)
        if labels:
            metadata["labels"] = labels
        else:
            metadata.pop("labels", None)
    if ignore_annotations:
        annotations = metadata.get("annotations") or {}
        for key in ignore_annotations:
            annotations.pop(key, None)
        if annotations:
            metadata["annotations"] = annotations
        else:
            metadata.pop("annotations", None)
    if ignore_fields:
        for pointer in ignore_fields:
            _drop_json_pointer(out, pointer)
    return out


def _drop_json_pointer(target, pointer):
    """
    Drop a JSON-pointer-style path from ``target`` in place.

    Accepts the leading-slash form used in RFC 6901 (e.g. ``/spec/replicas``)
    and the dotted form (e.g. ``spec.replicas``) for convenience. Integer
    path segments index into lists, as RFC 6901 specifies — without this
    a pointer like ``/spec/template/spec/containers/0/image`` could not
    target a specific container's field. Missing intermediate keys and
    out-of-range list indices are no-ops.
    """
    if not pointer:
        return
    if pointer.startswith("/"):
        parts = pointer.strip("/").split("/")
    else:
        parts = pointer.split(".")
    parts = [p for p in parts if p]
    if not parts:
        return
    cur = target
    for part in parts[:-1]:
        if isinstance(cur, list):
            try:
                idx = int(part)
            except ValueError:
                return
            if idx < 0 or idx >= len(cur):
                return
            cur = cur[idx]
        elif isinstance(cur, dict):
            cur = cur.get(part)
            if cur is None:
                return
        else:
            return
    last = parts[-1]
    if isinstance(cur, dict):
        cur.pop(last, None)
    elif isinstance(cur, list):
        try:
            idx = int(last)
        except ValueError:
            return
        if 0 <= idx < len(cur):
            cur.pop(idx)


def get_object(api_version, kind, name, namespace=None, **kwargs):
    """Read a Kubernetes object by GVK, returning ``None`` if absent.

    .. versionadded:: 2.1.0

    The generic read-by-GVK counterpart to ``apply`` and
    ``delete_manifest``. State code (``manifest_present`` /
    ``manifest_absent``) uses this in ``test=True`` mode to detect
    whether a target already exists.

    api_version
        Group/version, e.g. ``"v1"``, ``"apps/v1"``,
        ``"networking.k8s.io/v1"``.

    kind
        Kubernetes kind name, e.g. ``"ConfigMap"``, ``"Deployment"``.

    name
        Object name.

    namespace
        Namespace for namespaced kinds; ignored for cluster-scoped kinds.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.get_object api_version=v1 kind=ConfigMap name=app namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        return _dynamic.get_object(api_version, kind, name=name, namespace=namespace)
    finally:
        _cleanup(**cfg)


def normalise_manifest_input(
    manifest=None,
    source=None,
    template=None,
    saltenv=None,
    template_context=None,
):
    """Return *manifest* / *source* as a list of dicts.

    .. versionadded:: 2.1.0

    Public helper for state code that needs to inspect the manifest
    docs without actually applying or deleting them — for example, to
    decide in ``test=True`` mode whether each doc would change. Accepts
    the same input shapes as :py:func:`apply` / :py:func:`delete_manifest`.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.normalise_manifest_input source=salt://manifests/app.yaml
    """
    return _normalise_apply_input(manifest, source, template, saltenv, template_context)


def delete_manifest(
    manifest=None,
    source=None,
    namespace=None,
    propagation_policy=None,
    grace_period_seconds=None,
    template=None,
    saltenv=None,
    template_context=None,
    **kwargs,
):
    """
    Delete one or more Kubernetes objects identified by their
    manifests (kubectl-delete -f equivalent).

    .. versionadded:: 2.1.0

    Accepts the same manifest / source shapes as :py:func:`apply`.
    Each document's ``apiVersion``, ``kind``, ``metadata.name``, and
    (for namespaced kinds) ``metadata.namespace`` identify the object
    to remove. Returns ``None`` for objects that were already absent
    (404 swallowed, matching the typed ``delete_*`` functions); a list
    of API server responses otherwise.

    propagation_policy
        ``Foreground``, ``Background`` (default), or ``Orphan``.

    grace_period_seconds
        Override the per-object termination grace period.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_manifest source=salt://manifests/app.yaml
    """

    docs = _normalise_apply_input(manifest, source, template, saltenv, template_context)
    if not docs:
        raise CommandExecutionError("No manifests to delete")

    cfg = _setup_conn(**kwargs)
    try:
        results = []
        for doc in docs:
            _apply_namespace_default(doc, namespace)
            api_version = doc.get("apiVersion")
            kind = doc.get("kind")
            name = (doc.get("metadata") or {}).get("name")
            ns = (doc.get("metadata") or {}).get("namespace")
            if not api_version or not kind or not name:
                raise CommandExecutionError(
                    "Each manifest needs apiVersion, kind, and metadata.name"
                )
            results.append(
                _dynamic.delete_object(
                    api_version,
                    kind,
                    name=name,
                    namespace=ns,
                    propagation_policy=propagation_policy,
                    grace_period_seconds=grace_period_seconds,
                )
            )
        return results[0] if len(results) == 1 else results
    finally:
        _cleanup(**cfg)


def __is_base64(value):
    """
    Check if a string is base64 encoded by attempting to decode it.
    Handles whitespace and validates against base64.
    """
    if not isinstance(value, str):
        return False

    # Remove whitespace and newlines
    value = "".join(value.split())
    try:
        # Try decoding with validation
        base64.b64decode(value, validate=True).decode("utf-8")
        return True
    except ValueError:
        return False


def __create_object_body(
    kind,
    obj_class,
    spec_creator,
    name,
    namespace,
    metadata,
    spec,
    source,
    template,
    saltenv,
    template_context=None,
):
    """
    Create a Kubernetes Object body instance.
    """
    if source:
        src_obj = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if not isinstance(src_obj, dict) or "kind" not in src_obj or src_obj["kind"] != kind:
            raise CommandExecutionError(f"The source file should define only a {kind} object")

        if "metadata" in src_obj:
            metadata = src_obj["metadata"]
        if "spec" in src_obj:
            spec = src_obj["spec"]

    if metadata is None:
        metadata = {}
    if spec is None:
        spec = {}

    try:
        created_spec = spec_creator(spec)
    except (ValueError, TypeError) as exc:
        raise CommandExecutionError(f"Invalid {kind} spec: {exc}") from exc

    return obj_class(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        spec=created_spec,
    )


def __read_and_render_yaml_file(source, template, saltenv, template_context=None):
    """
    Read a yaml file and, if needed, renders that using the specified
    templating. Returns the python objects defined inside of the file.
    """
    saltenv = saltenv or __opts__["saltenv"] or "base"
    sfn = __salt__["cp.cache_file"](source, saltenv)
    if not sfn:
        raise CommandExecutionError(f"Source file '{source}' not found")

    with salt.utils.files.fopen(sfn, "r") as src:
        contents = src.read()

        if template:
            if template not in salt.utils.templates.TEMPLATE_REGISTRY:
                raise CommandExecutionError(f"Unknown template specified: {template}")
            # Apply templating with template_context
            if template_context is None:
                template_context = {}

            data = salt.utils.templates.TEMPLATE_REGISTRY[template](
                contents,
                from_str=True,
                to_str=True,
                saltenv=saltenv,
                grains=__grains__,
                pillar=__pillar__,
                salt=__salt__,
                opts=__opts__,
                context=template_context,
            )

            if not data["result"]:
                # Failed to render the template
                raise CommandExecutionError(
                    f'Failed to render file path with error: {data["data"]}'
                )

            contents = data["data"].encode("utf-8")

        return salt.utils.yaml.safe_load(contents)


def __dict_to_object_meta(name, namespace, metadata):
    """
    Converts a dictionary into kubernetes ObjectMetaV1 instance.
    """
    meta_obj = kubernetes.client.V1ObjectMeta()
    meta_obj.namespace = namespace

    if metadata is None:
        metadata = {}

    # Handle nested dictionaries in metadata
    processed_metadata = {}
    for key, value in metadata.items():
        if isinstance(value, dict):
            # Keep nested structure for fields like annotations and labels
            processed_metadata[key] = value
        else:
            # Convert non-dict values to string
            processed_metadata[key] = str(value)

    # Replicate `kubectl [create|replace|apply] --record`
    if "annotations" not in processed_metadata:
        processed_metadata["annotations"] = {}
    if "kubernetes.io/change-cause" not in processed_metadata["annotations"]:
        processed_metadata["annotations"]["kubernetes.io/change-cause"] = " ".join(sys.argv)

    for key, value in processed_metadata.items():
        if hasattr(meta_obj, key):
            setattr(meta_obj, key, value)

    if meta_obj.name != name:
        log.info(
            "The object already has a name attribute, overwriting it with "
            "the one defined inside of salt"
        )
        meta_obj.name = name

    return meta_obj


def __dict_to_deployment_spec(spec):
    """
    Converts a dictionary into kubernetes V1DeploymentSpec instance.
    """
    if not isinstance(spec, dict):
        raise CommandExecutionError(
            f"Deployment spec must be a dictionary, not {type(spec).__name__}"
        )

    processed_spec = spec.copy()

    # Validate required template field
    if "template" not in processed_spec:
        raise CommandExecutionError("Deployment spec must include template with pod specification")

    template = processed_spec["template"]
    template_metadata = template.get("metadata", {})
    template_labels = template_metadata.get("labels", {})

    # Handle selector
    if "selector" not in processed_spec:
        if not template_labels:
            raise CommandExecutionError(
                "Template must include labels when selector is not specified"
            )
        processed_spec["selector"] = {"match_labels": template_labels}
    else:
        selector = processed_spec["selector"]
        if not selector or not selector.get("matchLabels"):
            raise CommandExecutionError("Deployment selector must include matchLabels")
        if not all(template_labels.get(k) == v for k, v in selector["matchLabels"].items()):
            raise CommandExecutionError("selector.matchLabels must match template metadata.labels")

    # Convert selector format
    if "matchLabels" in processed_spec["selector"]:
        processed_spec["selector"] = {"match_labels": processed_spec["selector"]["matchLabels"]}

    # Create pod spec
    try:
        pod_spec = __dict_to_pod_spec(template["spec"])
    except (CommandExecutionError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid pod spec in deployment template: {exc}") from exc

    # Create pod template
    pod_template = kubernetes.client.V1PodTemplateSpec(
        metadata=kubernetes.client.V1ObjectMeta(**template_metadata), spec=pod_spec
    )
    processed_spec["template"] = pod_template

    # Create selector object
    processed_spec["selector"] = kubernetes.client.V1LabelSelector(**processed_spec["selector"])

    # Handle replicas conversion
    if "replicas" in processed_spec:
        try:
            processed_spec["replicas"] = int(processed_spec["replicas"])
        except (TypeError, ValueError) as exc:
            raise CommandExecutionError(f"replicas must be an integer: {exc}") from exc

    # Create final spec
    try:
        return V1DeploymentSpec(**processed_spec)
    except (TypeError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid deployment spec: {exc}") from exc


def __dict_to_pod_spec(spec):
    """
    Converts a dictionary into kubernetes V1PodSpec instance.
    """
    if spec is None:
        raise CommandExecutionError("Pod spec cannot be None")

    # Directly return if already a V1PodSpec
    if isinstance(spec, kubernetes.client.V1PodSpec):
        return spec
    if not isinstance(spec, dict):
        raise CommandExecutionError(f"Pod spec must be a dictionary, not {type(spec).__name__}")

    processed_spec = spec.copy()

    # Validate containers
    if not processed_spec.get("containers"):
        raise CommandExecutionError("Pod spec must include at least one container")

    if not isinstance(processed_spec["containers"], list):
        raise CommandExecutionError(
            f"containers must be a list, not {type(processed_spec['containers']).__name__}"
        )

    # Convert container specs
    containers = []
    for i, container in enumerate(processed_spec["containers"]):
        if not isinstance(container, dict):
            raise CommandExecutionError(
                f"Container {i} must be a dictionary, not {type(container).__name__}"
            )

        container_copy = container.copy()
        if not container_copy.get("name"):
            raise CommandExecutionError(f"Container {i} must specify 'name'")
        if not container_copy.get("image"):
            raise CommandExecutionError(f"Container {i} must specify 'image'")

        # Handle ports
        if "ports" in container_copy:
            ports = container_copy["ports"]
            if not isinstance(ports, list):
                raise CommandExecutionError(
                    f"Container {container_copy['name']} ports must be a list"
                )

            processed_ports = []
            for port in ports:
                if not isinstance(port, dict):
                    raise CommandExecutionError(
                        f"Port in container {container_copy['name']} must be a dictionary"
                    )
                port_copy = port.copy()
                # Handle containerPort conversion
                if "containerPort" in port_copy:
                    try:
                        port_copy["container_port"] = int(port_copy.pop("containerPort"))
                    except (TypeError, ValueError) as exc:
                        raise CommandExecutionError(
                            f"containerPort in container {container_copy['name']} must be an integer: {exc}"
                        ) from exc
                processed_ports.append(kubernetes.client.V1ContainerPort(**port_copy))

        # Translate kubectl/YAML-native camelCase fields (imagePullPolicy,
        # terminationMessagePath, workingDir, etc.) to the snake_case
        # attribute names V1Container expects.
        container_copy = _snake_caseify_keys(container_copy)
        containers.append(kubernetes.client.V1Container(**container_copy))

    processed_spec["containers"] = containers

    # Handle imagePullSecrets field
    if "imagePullSecrets" in processed_spec:
        image_pull_secrets = processed_spec.pop("imagePullSecrets")
        if not isinstance(image_pull_secrets, list):
            raise CommandExecutionError("imagePullSecrets must be a list")

        processed_secrets = []
        for secret in image_pull_secrets:
            if not isinstance(secret, dict):
                raise CommandExecutionError(
                    f"Each imagePullSecret must be a dictionary, not {type(secret).__name__}"
                )
            processed_secrets.append(kubernetes.client.V1LocalObjectReference(**secret))

    # Translate kubectl/YAML-native camelCase fields (restartPolicy,
    # serviceAccountName, terminationGracePeriodSeconds, etc.) to the
    # snake_case attribute names V1PodSpec expects.
    processed_spec = _snake_caseify_keys(processed_spec)
    try:
        return kubernetes.client.V1PodSpec(**processed_spec)
    except (TypeError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid pod spec: {exc}") from exc


def __dict_to_service_spec(spec):
    """
    Converts a dictionary into kubernetes V1ServiceSpec instance.

    Args:
        spec: Service specification dictionary following kubernetes API conventions

    Returns:
        kubernetes.client.V1ServiceSpec: The converted service spec
    """
    if not isinstance(spec, dict):
        raise CommandExecutionError(f"Service spec must be a dictionary, got {type(spec)}")

    # Validate required fields
    if "ports" not in spec:
        raise CommandExecutionError("Service spec must include 'ports'")

    if not isinstance(spec["ports"], list):
        raise CommandExecutionError("Service ports must be a list")

    # Validate service type if specified
    valid_service_types = {"ClusterIP", "ExternalName", "LoadBalancer", "NodePort"}
    if "type" in spec and spec["type"] not in valid_service_types:
        raise CommandExecutionError(
            f"Invalid service type: {spec['type']}. Must be one of: {', '.join(sorted(valid_service_types))}"
        )

    spec_obj = kubernetes.client.V1ServiceSpec()
    for key, value in spec.items():
        if key == "ports":
            spec_obj.ports = []
            # Validate port specifications
            has_multiple_ports = len(value) > 1

            for i, port in enumerate(value):
                if not isinstance(port, dict):
                    try:
                        # Allow simple integer port definitions
                        kube_port = kubernetes.client.V1ServicePort(port=int(port))
                    except (TypeError, ValueError) as exc:
                        raise CommandExecutionError(
                            f"Invalid port specification at index {i}: {exc}"
                        ) from exc
                else:
                    # Verify required fields for port
                    if "port" not in port:
                        raise CommandExecutionError(
                            f"Service port at index {i} must specify 'port' value"
                        )

                    try:
                        port_num = int(port["port"])
                    except (TypeError, ValueError) as exc:
                        raise CommandExecutionError(
                            f"Invalid port number at index {i}: {exc}"
                        ) from exc

                    # Create port object
                    kube_port = kubernetes.client.V1ServicePort(port=port_num)

                    # Validate name requirement for multi-port services
                    if has_multiple_ports and "name" not in port:
                        raise CommandExecutionError(
                            f"Port at index {i} must specify 'name' in multi-port service"
                        )

                    # Validate nodePort range if specified
                    if "nodePort" in port:
                        try:
                            node_port = int(port["nodePort"])
                            if not 30000 <= node_port <= 32767:
                                raise CommandExecutionError(
                                    f"NodePort {node_port} at index {i} must be between 30000-32767"
                                )
                        except (TypeError, ValueError) as exc:
                            raise CommandExecutionError(
                                f"Invalid nodePort value at index {i}: {exc}"
                            ) from exc

                    # Copy remaining port attributes
                    for port_key, port_value in port.items():
                        if port_key != "port":
                            if port_key in ["nodePort", "targetPort"]:
                                try:
                                    if isinstance(port_value, str) and not port_value.isdigit():
                                        # Allow string targetPort for named ports
                                        if port_key != "targetPort":
                                            port_value = int(port_value)
                                    elif isinstance(port_value, (int, str)):
                                        port_value = int(port_value)
                                except (TypeError, ValueError) as exc:
                                    raise CommandExecutionError(
                                        f"Invalid {port_key} value at index {i}: {exc}"
                                    ) from exc
                            if hasattr(kube_port, port_key):
                                setattr(kube_port, port_key, port_value)

                spec_obj.ports.append(kube_port)

        elif hasattr(spec_obj, key):
            setattr(spec_obj, key, value)

    return spec_obj


def __dict_to_statefulset_spec(spec):
    """
    .. versionadded:: 2.1.0

    Converts a dictionary into kubernetes V1StatefulSetSpec instance.
    """
    if not isinstance(spec, dict):
        raise CommandExecutionError(
            f"StatefulSet spec must be a dictionary, not {type(spec).__name__}"
        )

    processed_spec = spec.copy()

    # Validate required fields (accept both camelCase and snake_case input)
    if "serviceName" not in processed_spec and "service_name" not in processed_spec:
        raise CommandExecutionError("StatefulSet spec must include 'serviceName'")

    # Validate required template field
    if "template" not in processed_spec:
        raise CommandExecutionError("StatefulSet spec must include template with pod specification")

    template = processed_spec["template"]
    if not isinstance(template, dict):
        raise CommandExecutionError(f"Template must be a dictionary, not {type(template).__name__}")

    template_metadata = template.get("metadata", {})
    template_spec = template.get("spec", {})

    # Validate template has pod spec
    if not template_spec:
        raise CommandExecutionError("Template must include pod specification")

    # Create pod spec
    try:
        pod_spec = __dict_to_pod_spec(template_spec)
    except (CommandExecutionError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid pod spec in statefulset template: {exc}") from exc

    # Create pod template
    pod_template = kubernetes.client.V1PodTemplateSpec(
        metadata=kubernetes.client.V1ObjectMeta(**template_metadata), spec=pod_spec
    )
    processed_spec["template"] = pod_template

    # Handle selector - optional for StatefulSet but validate if provided
    if "selector" in processed_spec:
        selector = processed_spec["selector"]
        if not isinstance(selector, dict):
            raise CommandExecutionError(
                f"Selector must be a dictionary, not {type(selector).__name__}"
            )
        if "matchLabels" in selector:
            processed_spec["selector"] = {"match_labels": selector["matchLabels"]}
        processed_spec["selector"] = kubernetes.client.V1LabelSelector(**processed_spec["selector"])

    # Handle replicas conversion
    if "replicas" in processed_spec:
        try:
            processed_spec["replicas"] = int(processed_spec["replicas"])
        except (TypeError, ValueError) as exc:
            raise CommandExecutionError(f"replicas must be an integer: {exc}") from exc

    # Normalise the remaining camelCase keys (serviceName,
    # podManagementPolicy, revisionHistoryLimit, ...) to snake_case so
    # they survive the V1StatefulSetSpec constructor. Selector + template
    # are already typed objects at this point and pass through unchanged.
    processed_spec = _normalise_field_map(processed_spec)

    # Create final spec
    try:
        return kubernetes.client.V1StatefulSetSpec(**processed_spec)
    except (TypeError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid statefulset spec: {exc}") from exc


def __dict_to_replicaset_spec(spec):
    """
    .. versionadded:: 2.1.0

    Converts a dictionary into kubernetes V1ReplicaSetSpec instance.
    """
    if not isinstance(spec, dict):
        raise CommandExecutionError(
            f"ReplicaSet spec must be a dictionary, not {type(spec).__name__}"
        )

    processed_spec = spec.copy()

    if "template" not in processed_spec:
        raise CommandExecutionError("ReplicaSet spec must include template with pod specification")

    template = processed_spec["template"]
    template_metadata = template.get("metadata", {})
    template_labels = template_metadata.get("labels", {})

    if "selector" not in processed_spec:
        if not template_labels:
            raise CommandExecutionError(
                "Template must include labels when selector is not specified"
            )
        processed_spec["selector"] = {"match_labels": template_labels}
    else:
        selector = processed_spec["selector"]
        if not selector or not selector.get("matchLabels"):
            raise CommandExecutionError("ReplicaSet selector must include matchLabels")
        if not all(template_labels.get(k) == v for k, v in selector["matchLabels"].items()):
            raise CommandExecutionError("selector.matchLabels must match template metadata.labels")

    if "matchLabels" in processed_spec["selector"]:
        processed_spec["selector"] = {"match_labels": processed_spec["selector"]["matchLabels"]}

    try:
        pod_spec = __dict_to_pod_spec(template["spec"])
    except (CommandExecutionError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid pod spec in replicaset template: {exc}") from exc

    pod_template = kubernetes.client.V1PodTemplateSpec(
        metadata=kubernetes.client.V1ObjectMeta(**template_metadata), spec=pod_spec
    )
    processed_spec["template"] = pod_template

    processed_spec["selector"] = kubernetes.client.V1LabelSelector(**processed_spec["selector"])

    if "replicas" in processed_spec:
        try:
            processed_spec["replicas"] = int(processed_spec["replicas"])
        except (TypeError, ValueError) as exc:
            raise CommandExecutionError(f"replicas must be an integer: {exc}") from exc

    try:
        return kubernetes.client.V1ReplicaSetSpec(**processed_spec)
    except (TypeError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid replicaset spec: {exc}") from exc


def __dict_to_daemonset_spec(spec):
    """
    .. versionadded:: 2.1.0

    Converts a dictionary into kubernetes V1DaemonSetSpec instance.
    """
    if not isinstance(spec, dict):
        raise CommandExecutionError(
            f"DaemonSet spec must be a dictionary, not {type(spec).__name__}"
        )

    processed_spec = spec.copy()

    if "template" not in processed_spec:
        raise CommandExecutionError("DaemonSet spec must include template with pod specification")

    template = processed_spec["template"]
    template_metadata = template.get("metadata", {})
    template_labels = template_metadata.get("labels", {})

    if "selector" not in processed_spec:
        if not template_labels:
            raise CommandExecutionError(
                "Template must include labels when selector is not specified"
            )
        processed_spec["selector"] = {"match_labels": template_labels}
    else:
        selector = processed_spec["selector"]
        if not selector or not selector.get("matchLabels"):
            raise CommandExecutionError("DaemonSet selector must include matchLabels")
        if not all(template_labels.get(k) == v for k, v in selector["matchLabels"].items()):
            raise CommandExecutionError("selector.matchLabels must match template metadata.labels")

    if "matchLabels" in processed_spec["selector"]:
        processed_spec["selector"] = {"match_labels": processed_spec["selector"]["matchLabels"]}

    try:
        pod_spec = __dict_to_pod_spec(template["spec"])
    except (CommandExecutionError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid pod spec in daemonset template: {exc}") from exc

    pod_template = kubernetes.client.V1PodTemplateSpec(
        metadata=kubernetes.client.V1ObjectMeta(**template_metadata), spec=pod_spec
    )
    processed_spec["template"] = pod_template

    processed_spec["selector"] = kubernetes.client.V1LabelSelector(**processed_spec["selector"])

    try:
        return kubernetes.client.V1DaemonSetSpec(**processed_spec)
    except (TypeError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid daemonset spec: {exc}") from exc


def __dict_to_storageclass_spec(spec):
    """
    .. versionadded:: 2.1.0

    Validates and normalizes a dictionary into a V1StorageClass-compatible payload.
    """
    if not isinstance(spec, dict):
        raise CommandExecutionError(
            f"StorageClass spec must be a dictionary, not {type(spec).__name__}"
        )

    processed_spec = _normalise_field_map(spec, _STORAGECLASS_FIELD_MAP)

    if not processed_spec.get("provisioner"):
        raise CommandExecutionError("StorageClass spec must include provisioner")

    mount_options = processed_spec.get("mount_options")
    if mount_options is not None and not isinstance(mount_options, list):
        raise CommandExecutionError("StorageClass mountOptions must be a list")

    if "parameters" in processed_spec:
        parameters = processed_spec["parameters"]
        if not isinstance(parameters, dict):
            raise CommandExecutionError("StorageClass parameters must be a dictionary")
        processed_spec["parameters"] = __enforce_only_strings_dict(parameters)

    allowed_topologies = processed_spec.get("allowed_topologies")
    if allowed_topologies is not None:
        if not isinstance(allowed_topologies, list):
            raise CommandExecutionError("StorageClass allowedTopologies must be a list")
        processed_spec["allowed_topologies"] = [
            kubernetes.client.V1TopologySelectorTerm(**term) for term in allowed_topologies
        ]

    try:
        kubernetes.client.V1StorageClass(**processed_spec)
    except (TypeError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid storageclass spec: {exc}") from exc

    return processed_spec


# Explicit camelCase→snake_case overrides for StorageClass fields. Every
# entry below would translate correctly via the generic ``_camel_to_snake``
# fallback anyway; listing them keeps the per-kind contract documented in
# one place and gives us a single spot to pin any future field whose
# naive translation is wrong (acronyms, plural quirks).
_STORAGECLASS_FIELD_MAP = {
    "reclaimPolicy": "reclaim_policy",
    "allowVolumeExpansion": "allow_volume_expansion",
    "volumeBindingMode": "volume_binding_mode",
    "mountOptions": "mount_options",
    "allowedTopologies": "allowed_topologies",
}


# ---------------------------------------------------------------------------
# RBAC spec builders.
#
# Role and ClusterRole carry a ``rules`` list (and ClusterRole optionally an
# ``aggregation_rule``). RoleBinding and ClusterRoleBinding carry a
# ``subjects`` list and a ``role_ref``. ServiceAccount has no spec block —
# its top-level fields go directly on V1ServiceAccount.
#
# All builders accept either snake_case or camelCase keys at the top level
# and return a dict ready to **kwargs into the corresponding V1 constructor.
# ---------------------------------------------------------------------------


# The kubernetes-client OpenAPI generator maps ``nonResourceURLs`` to the
# awkward ``non_resource_ur_ls`` (the trailing capital sequence becomes its
# own underscore-separated token). We accept both ``non_resource_urls`` and
# ``nonResourceURLs`` from callers and translate to the actual constructor
# kwarg name.
_RULES_FIELD_MAP = {
    "apiGroups": "api_groups",
    "resources": "resources",
    "verbs": "verbs",
    "resourceNames": "resource_names",
    "nonResourceURLs": "non_resource_ur_ls",
    "non_resource_urls": "non_resource_ur_ls",
}


def __dict_to_policy_rule_list(rules):
    """Build a list of V1PolicyRule from a list of rule dicts."""
    if rules is None:
        return []
    if not isinstance(rules, list):
        raise CommandExecutionError("Rules must be a list of rule dicts")
    out = []
    for rule in rules:
        if not isinstance(rule, dict):
            raise CommandExecutionError("Each rule must be a dictionary")
        normalised = {_RULES_FIELD_MAP.get(k, k): v for k, v in rule.items()}
        if "verbs" not in normalised or not normalised["verbs"]:
            raise CommandExecutionError("Each rule must include a non-empty 'verbs' list")
        try:
            out.append(V1PolicyRule(**normalised))
        except (TypeError, ValueError) as exc:
            raise CommandExecutionError(f"Invalid rule {rule}: {exc}") from exc
    return out


def __dict_to_subject_list(subjects):
    """Build a list of V1Subject from a list of subject dicts."""
    if not isinstance(subjects, list):
        raise CommandExecutionError("Subjects must be a list")
    out = []
    for subject in subjects:
        if not isinstance(subject, dict):
            raise CommandExecutionError("Each subject must be a dictionary")
        # Build a fresh dict so we don't mutate the caller's input. Translate
        # camelCase ``apiGroup`` to the snake_case kwarg the V1 class expects.
        normalised = {("api_group" if k == "apiGroup" else k): v for k, v in subject.items()}
        if "kind" not in normalised or "name" not in normalised:
            raise CommandExecutionError("Each subject must include 'kind' and 'name'")
        try:
            out.append(V1Subject(**normalised))
        except (TypeError, ValueError) as exc:
            raise CommandExecutionError(f"Invalid subject {subject}: {exc}") from exc
    return out


def __dict_to_role_ref(role_ref):
    """Build a V1RoleRef from a dict; defaults api_group to rbac.authorization.k8s.io."""
    if not isinstance(role_ref, dict):
        raise CommandExecutionError("roleRef must be a dictionary")
    normalised = {**role_ref}
    if "apiGroup" in normalised:
        normalised["api_group"] = normalised.pop("apiGroup")
    normalised.setdefault("api_group", "rbac.authorization.k8s.io")
    if "kind" not in normalised or "name" not in normalised:
        raise CommandExecutionError("roleRef must include 'kind' and 'name'")
    try:
        return V1RoleRef(**normalised)
    except (TypeError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid roleRef: {exc}") from exc


def __dict_to_role_spec(spec):
    """Validate a dict and return kwargs for V1Role / V1ClusterRole."""
    if not isinstance(spec, dict):
        raise CommandExecutionError(f"Role spec must be a dictionary, not {type(spec).__name__}")
    out = {"rules": __dict_to_policy_rule_list(spec.get("rules"))}
    return out


def __dict_to_cluster_role_spec(spec):
    """Like __dict_to_role_spec but also accepts an optional aggregation_rule."""
    if not isinstance(spec, dict):
        raise CommandExecutionError(
            f"ClusterRole spec must be a dictionary, not {type(spec).__name__}"
        )
    out = {"rules": __dict_to_policy_rule_list(spec.get("rules"))}
    aggregation_rule = spec.get("aggregationRule") or spec.get("aggregation_rule")
    if aggregation_rule is not None:
        if not isinstance(aggregation_rule, dict):
            raise CommandExecutionError("aggregationRule must be a dictionary")
        selectors = aggregation_rule.get("clusterRoleSelectors") or aggregation_rule.get(
            "cluster_role_selectors"
        )
        if not isinstance(selectors, list):
            raise CommandExecutionError("aggregationRule.clusterRoleSelectors must be a list")
        out["aggregation_rule"] = kubernetes.client.V1AggregationRule(
            cluster_role_selectors=[kubernetes.client.V1LabelSelector(**sel) for sel in selectors]
        )
    return out


def __dict_to_role_binding_spec(spec):
    """Validate a dict and return kwargs for V1RoleBinding / V1ClusterRoleBinding."""
    if not isinstance(spec, dict):
        raise CommandExecutionError(
            f"RoleBinding spec must be a dictionary, not {type(spec).__name__}"
        )
    if "subjects" not in spec:
        raise CommandExecutionError("RoleBinding spec must include 'subjects'")
    role_ref_in = spec.get("roleRef") or spec.get("role_ref")
    if role_ref_in is None:
        raise CommandExecutionError("RoleBinding spec must include 'roleRef'")
    return {
        "subjects": __dict_to_subject_list(spec["subjects"]),
        "role_ref": __dict_to_role_ref(role_ref_in),
    }


def __dict_to_service_account_spec(spec):
    """
    Validate a dict and return kwargs for V1ServiceAccount.

    ServiceAccount has no .spec block; the supported fields are
    ``automount_service_account_token``, ``image_pull_secrets`` and
    ``secrets``. We accept either snake_case or camelCase top-level keys.
    """
    if spec is None:
        spec = {}
    if not isinstance(spec, dict):
        raise CommandExecutionError(
            f"ServiceAccount spec must be a dictionary, not {type(spec).__name__}"
        )
    out = {}
    if "automountServiceAccountToken" in spec or "automount_service_account_token" in spec:
        out["automount_service_account_token"] = spec.get(
            "automount_service_account_token", spec.get("automountServiceAccountToken")
        )
    pull_secrets = spec.get("imagePullSecrets") or spec.get("image_pull_secrets")
    if pull_secrets is not None:
        if not isinstance(pull_secrets, list):
            raise CommandExecutionError("imagePullSecrets must be a list of {name: ...} dicts")
        out["image_pull_secrets"] = [
            kubernetes.client.V1LocalObjectReference(**ps) for ps in pull_secrets
        ]
    secrets = spec.get("secrets")
    if secrets is not None:
        if not isinstance(secrets, list):
            raise CommandExecutionError("secrets must be a list of object reference dicts")
        out["secrets"] = [kubernetes.client.V1ObjectReference(**s) for s in secrets]
    return out


# ---------------------------------------------------------------------------
# Batch (Job, CronJob) spec builders.
#
# Both kinds wrap a Pod template. We accept the template as a plain dict
# (which __dict_to_pod_spec already validates) and let the caller supply
# either snake_case or camelCase top-level keys for the Job/CronJob spec
# fields themselves.
# ---------------------------------------------------------------------------


_JOB_FIELD_MAP = {
    "activeDeadlineSeconds": "active_deadline_seconds",
    "backoffLimit": "backoff_limit",
    "completionMode": "completion_mode",
    "ttlSecondsAfterFinished": "ttl_seconds_after_finished",
    "podFailurePolicy": "pod_failure_policy",
    "manualSelector": "manual_selector",
}


_CRONJOB_FIELD_MAP = {
    "concurrencyPolicy": "concurrency_policy",
    "failedJobsHistoryLimit": "failed_jobs_history_limit",
    "jobTemplate": "job_template",
    "startingDeadlineSeconds": "starting_deadline_seconds",
    "successfulJobsHistoryLimit": "successful_jobs_history_limit",
    "timeZone": "time_zone",
}


_VALID_CRONJOB_CONCURRENCY = {"Allow", "Forbid", "Replace"}


def __dict_to_job_spec(spec):
    """Validate and build kwargs for V1JobSpec from a dict."""
    if not isinstance(spec, dict):
        raise CommandExecutionError(f"Job spec must be a dictionary, not {type(spec).__name__}")
    normalised = {_JOB_FIELD_MAP.get(k, k): v for k, v in spec.items()}
    template = normalised.get("template")
    if not isinstance(template, dict):
        raise CommandExecutionError("Job spec must include 'template' (a pod-template dict)")
    pod_meta = template.get("metadata", {}) or {}
    pod_spec_dict = template.get("spec")
    if not isinstance(pod_spec_dict, dict):
        raise CommandExecutionError("Job template must include 'spec'")
    pod_spec_dict = pod_spec_dict.copy()
    # Job pods must have a restartPolicy of OnFailure or Never; default
    # to Never if the user didn't specify, matching kubectl's behaviour
    # for ``kubectl create job``.
    pod_spec_dict.setdefault("restart_policy", pod_spec_dict.pop("restartPolicy", "Never"))
    if pod_spec_dict["restart_policy"] not in ("OnFailure", "Never"):
        raise CommandExecutionError("Job pod template restartPolicy must be 'OnFailure' or 'Never'")
    # __dict_to_pod_spec returns a V1PodSpec instance, not a dict.
    pod_spec = __dict_to_pod_spec(pod_spec_dict)
    normalised["template"] = kubernetes.client.V1PodTemplateSpec(
        metadata=kubernetes.client.V1ObjectMeta(**pod_meta) if pod_meta else None,
        spec=pod_spec,
    )
    try:
        V1JobSpec(**normalised)
    except (TypeError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid job spec: {exc}") from exc
    return normalised


def __dict_to_cron_job_spec(spec):
    """Validate and build kwargs for V1CronJobSpec from a dict."""
    if not isinstance(spec, dict):
        raise CommandExecutionError(f"CronJob spec must be a dictionary, not {type(spec).__name__}")
    normalised = {_CRONJOB_FIELD_MAP.get(k, k): v for k, v in spec.items()}
    if not normalised.get("schedule"):
        raise CommandExecutionError("CronJob spec must include 'schedule'")
    cp = normalised.get("concurrency_policy")
    if cp is not None and cp not in _VALID_CRONJOB_CONCURRENCY:
        raise CommandExecutionError(
            f"Invalid concurrency_policy '{cp}'. Must be one of: "
            + ", ".join(sorted(_VALID_CRONJOB_CONCURRENCY))
        )
    job_template_dict = normalised.get("job_template")
    if not isinstance(job_template_dict, dict):
        raise CommandExecutionError(
            "CronJob spec must include 'job_template' (a {metadata, spec} dict)"
        )
    job_meta = job_template_dict.get("metadata", {}) or {}
    job_spec_dict = job_template_dict.get("spec")
    if not isinstance(job_spec_dict, dict):
        raise CommandExecutionError("CronJob job_template must include 'spec' (a job-spec dict)")
    inner_job_spec_kwargs = __dict_to_job_spec(job_spec_dict)
    normalised["job_template"] = V1JobTemplateSpec(
        metadata=kubernetes.client.V1ObjectMeta(**job_meta) if job_meta else None,
        spec=V1JobSpec(**inner_job_spec_kwargs),
    )
    try:
        V1CronJobSpec(**normalised)
    except (TypeError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid cronjob spec: {exc}") from exc
    return normalised


def __enforce_only_strings_dict(dictionary):
    """
    Returns a dictionary that has string keys and values.
    Only converts non-string values to strings.
    """
    ret = {}

    for key, value in dictionary.items():
        ret[str(key)] = str(value)

    return ret


def _wait_for_resource_status(
    api_instance,
    resource_type,
    name,
    namespace,
    expected_status,
    timeout=60,
    predicate=None,
):
    """
    .. versionadded:: 2.0.0
    .. versionchanged:: 2.1.0

        Internal dispatch routes through
        :py:data:`saltext.kubernetes.utils._kinds._KIND_REGISTRY`. The
        public signature, kwargs, and return semantics are unchanged;
        new typed kinds are added by registering one entry there.

    Helper function to wait for a resource to reach an expected status.

    api_instance
        The kubernetes API instance to use

    resource_type
        Type of resource to wait for (e.g., 'deployment', 'pod', 'service')

    name
        Name of the resource

    namespace
        Namespace of the resource (ignored for cluster-scoped kinds)

    expected_status
        Expected status to wait for ('created', 'deleted', 'ready')

    timeout
        Timeout in seconds (default: 60)

    Returns True if the resource reached the expected status, False otherwise.
    """
    kind = _kinds.get_kind(resource_type)

    try:
        if expected_status == "deleted":
            return _wait_for_deleted(api_instance, kind, name, namespace, timeout)

        w = Watch()
        try:
            return _wait_via_watch(
                w,
                api_instance,
                kind,
                name,
                namespace,
                expected_status,
                timeout,
                predicate=predicate,
            )
        finally:
            w.stop()
    except (ApiException, HTTPError) as exc:
        raise CommandExecutionError(exc) from exc


def _wait_for_deleted(api_instance, kind, name, namespace, timeout):
    """Poll the read endpoint until a 404 is observed or timeout elapses."""
    read = getattr(api_instance, kind.read_method)
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            if kind.namespaced:
                read(name, namespace)
            else:
                read(name)
        except ApiException as exc:
            if exc.status == 404:
                return True
        time.sleep(1)
    return False


def _wait_via_watch(
    w, api_instance, kind, name, namespace, expected_status, timeout, predicate=None
):
    """Stream list events filtered by name; apply the per-kind ready predicate.

    When ``predicate`` is supplied it overrides the per-kind ready predicate
    for ``expected_status == "ready"`` and is the user-driven wait callable
    built by :py:func:`saltext.kubernetes.utils._kinds.build_predicate`.
    """
    list_method = getattr(api_instance, kind.list_method)
    start_time = time.time()
    stream_kwargs = {
        "func": list_method,
        "field_selector": f"metadata.name={name}",
        "timeout_seconds": timeout,
    }
    if kind.namespaced:
        stream_kwargs["namespace"] = namespace

    active_predicate = predicate or kind.ready_predicate
    for event in w.stream(**stream_kwargs):
        obj = event["object"]
        if obj.metadata.name == name:
            if expected_status == "created":
                return True
            if expected_status == "ready" and active_predicate(obj):
                return True
        if time.time() - start_time >= timeout:
            log.warning(
                "Timeout reached while waiting for %s/%s to become %s",
                kind.list_method,
                name,
                expected_status,
            )
            return False

    log.warning(
        "Watch stream ended before %s/%s reached %s status",
        kind.list_method,
        name,
        expected_status,
    )
    return False
