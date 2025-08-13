# pylint: disable=raise-missing-from
"""
Module for handling kubernetes calls.

:optdepends:    - kubernetes Python client >= v19.15.0
                - PyYAML >= 5.3.1
:configuration: The k8s API settings are provided either in a pillar, in
    the minion's config file, or in master's config file::

        kubernetes.kubeconfig: '/path/to/kubeconfig'
        kubernetes.kubeconfig-data: '<base64 encoded kubeconfig content'
        kubernetes.context: 'context'

The data format for `kubernetes.kubeconfig-data` value is the content of
`kubeconfig` base64 encoded in one line.

These settings can be overridden by adding `context and `kubeconfig` or
`kubeconfig_data` parameters when calling a function.

Only `kubeconfig` or `kubeconfig-data` should be provided. In case both are
provided `kubeconfig` entry is preferred.

CLI Example:

.. code-block:: bash

    salt '*' kubernetes.nodes
    salt '*' kubernetes.nodes kubeconfig=/etc/salt/k8s/kubeconfig context=minikube

.. versionadded:: 2017.7.0
.. versionchanged:: 2019.2.0

.. warning::

    Configuration options changed in 2019.2.0. The following configuration options have been removed:

    - kubernetes.user
    - kubernetes.password
    - kubernetes.api_url
    - kubernetes.certificate-authority-data/file
    - kubernetes.client-certificate-data/file
    - kubernetes.client-key-data/file

    Please use now:

    - kubernetes.kubeconfig or kubernetes.kubeconfig-data
    - kubernetes.context

"""
import base64
import errno
import logging
import os.path
import signal
import sys
import tempfile
import time
from contextlib import contextmanager

import salt.utils.files
import salt.utils.platform
import salt.utils.templates
import salt.utils.yaml
from salt.exceptions import CommandExecutionError
from salt.exceptions import TimeoutError

# pylint: disable=import-error,no-name-in-module
try:
    import kubernetes  # pylint: disable=import-self
    import kubernetes.client
    from kubernetes.client import V1Deployment
    from kubernetes.client import V1DeploymentSpec
    from kubernetes.client.rest import ApiException
    from kubernetes.watch import Watch
    from urllib3.exceptions import HTTPError

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


if not salt.utils.platform.is_windows():

    @contextmanager
    def _time_limit(seconds):
        def signal_handler(signum, frame):
            raise TimeoutError

        signal.signal(signal.SIGALRM, signal_handler)
        signal.alarm(seconds)
        try:
            yield
        finally:
            signal.alarm(0)

    POLLING_TIME_LIMIT = 30


def _setup_conn(**kwargs):
    """
    Setup kubernetes API connection singleton
    """
    kubeconfig = kwargs.get("kubeconfig") or __salt__["config.option"]("kubernetes.kubeconfig")
    kubeconfig_data = kwargs.get("kubeconfig_data") or __salt__["config.option"](
        "kubernetes.kubeconfig-data"
    )
    context = kwargs.get("context") or __salt__["config.option"]("kubernetes.context")

    if (kubeconfig_data and not kubeconfig) or (kubeconfig_data and kwargs.get("kubeconfig_data")):
        with tempfile.NamedTemporaryFile(prefix="salt-kubeconfig-", delete=False) as kcfg:
            kcfg.write(base64.b64decode(kubeconfig_data))
            kubeconfig = kcfg.name

    if not (kubeconfig and context):
        raise CommandExecutionError(
            "Invalid kubernetes configuration. Parameter 'kubeconfig' and 'context'"
            " are required."
        )

    kubernetes.config.load_kube_config(config_file=kubeconfig, context=context)

    # The return makes unit testing easier
    return {"kubeconfig": kubeconfig, "context": context}


def _cleanup(**kwargs):
    if "kubeconfig" in kwargs:
        kubeconfig = kwargs.get("kubeconfig")
        if kubeconfig and os.path.basename(kubeconfig).startswith("salt-kubeconfig-"):
            try:
                os.unlink(kubeconfig)
            except OSError as err:
                if err.errno != errno.ENOENT:
                    log.exception(err)


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
        log.exception("Exception when calling CoreV1Api->get_api_resources")
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

        return [k8s_node["metadata"]["name"] for k8s_node in api_response.to_dict().get("items")]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        log.exception("Exception when calling CoreV1Api->list_node")
        raise CommandExecutionError(exc)
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
        log.exception("Exception when calling CoreV1Api->list_node")
        raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)

    for k8s_node in api_response.items:
        if k8s_node.metadata.name == name:
            return k8s_node.to_dict()

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
        log.exception("Exception when calling CoreV1Api->patch_node")
        raise CommandExecutionError(str(exc))
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
        log.exception("Exception when calling CoreV1Api->patch_node")
        raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def namespaces(**kwargs):
    """
    Return the names of the available namespaces

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.namespaces
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.list_namespace()

        return [nms["metadata"]["name"] for nms in api_response.to_dict().get("items")]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        log.exception("Exception when calling CoreV1Api->list_namespace")
        raise CommandExecutionError(exc)
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

        return [dep["metadata"]["name"] for dep in api_response.to_dict().get("items")]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        log.exception("Exception when calling AppsV1Api->list_namespaced_deployment")
        raise CommandExecutionError(exc)
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

        return [srv["metadata"]["name"] for srv in api_response.to_dict().get("items")]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        log.exception("Exception when calling CoreV1Api->list_namespaced_service")
        raise CommandExecutionError(exc)
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
        return [pod["metadata"]["name"] for pod in api_response.to_dict().get("items", [])]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []  # Return empty list for nonexistent namespace
        log.exception("Exception when calling CoreV1Api->list_namespaced_pod")
        raise CommandExecutionError(exc)
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

        return [secret["metadata"]["name"] for secret in api_response.to_dict().get("items")]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []
        log.exception("Exception when calling CoreV1Api->list_namespaced_secret")
        raise CommandExecutionError(exc)
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
            configmap["metadata"]["name"] for configmap in api_response.to_dict().get("items", [])
        ]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return []  # Return empty list for nonexistent namespace
        log.exception("Exception when calling CoreV1Api->list_namespaced_config_map")
        raise CommandExecutionError(exc)
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

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        log.exception("Exception when calling AppsV1Api->read_namespaced_deployment")
        raise CommandExecutionError(exc)
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

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        log.exception("Exception when calling CoreV1Api->read_namespaced_service")
        raise CommandExecutionError(exc)
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

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        log.exception("Exception when calling CoreV1Api->read_namespaced_pod")
        raise CommandExecutionError(exc)
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
        return api_response.to_dict()
    except ApiException as exc:
        if exc.status == 404:
            return None
        log.exception("Exception when calling CoreV1Api->read_namespace")
        raise CommandExecutionError(exc) from exc
    except HTTPError as exc:
        log.exception("HTTP error occurred")
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
        response_dict = api_response.to_dict()

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
        log.exception("Exception when calling CoreV1Api->read_namespaced_secret")
        raise CommandExecutionError(exc)
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

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        log.exception("Exception when calling CoreV1Api->read_namespaced_config_map")
        raise CommandExecutionError(exc)
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

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        log.exception("Exception when calling AppsV1Api->delete_namespaced_deployment")
        raise CommandExecutionError(exc)
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

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->delete_namespaced_service")
            raise CommandExecutionError(exc)
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

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->delete_namespaced_pod")
            raise CommandExecutionError(exc)
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

        return api_response.to_dict()
    except ApiException as exc:
        if exc.status == 404:
            return None
        if exc.status == 403:
            raise CommandExecutionError(f"Cannot delete namespace {name}: {exc.reason}") from exc
        log.exception("Exception when calling CoreV1Api->delete_namespace")
        raise CommandExecutionError(exc) from exc
    except HTTPError as exc:
        log.exception("HTTP error occurred")
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

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        log.exception("Exception when calling CoreV1Api->delete_namespaced_secret")
        raise CommandExecutionError(exc)
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

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->delete_namespaced_config_map")
            raise CommandExecutionError(exc)
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
        api_response = api_instance.create_namespaced_deployment(namespace, body)

        if wait:
            if not _wait_for_resource_status(
                api_instance, "deployment", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(
                    f"Timeout waiting for deployment {name} to become ready"
                )

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException):
            if exc.status == 404:
                raise CommandExecutionError(f"Deployment {namespace}/{name} not found") from exc
            if exc.status == 409:
                raise CommandExecutionError(f"Deployment {name} already exists") from exc
        log.exception("Exception when calling AppsV1Api->create_namespaced_deployment")
        raise CommandExecutionError(exc)
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

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException):
            if exc.status == 404:
                raise CommandExecutionError(f"Pod {namespace}/{name} not found") from exc
            if exc.status == 409:
                raise CommandExecutionError(f"Pod {name} already exists") from exc
        log.exception("Exception when calling CoreV1Api->create_namespaced_pod")
        raise CommandExecutionError(exc)
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
        api_response = api_instance.create_namespaced_service(namespace, body)

        if wait:
            if not _wait_for_resource_status(
                api_instance, "service", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for service {name} to become ready")

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException):
            if exc.status == 404:
                raise CommandExecutionError(f"Service {namespace}/{name} not found") from exc
            if exc.status == 409:
                raise CommandExecutionError(f"Service {name} already exists") from exc
        log.exception("Exception when calling CoreV1Api->create_namespaced_service")
        raise CommandExecutionError(exc)
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
    wait=False,
    timeout=60,
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

    body = kubernetes.client.V1Secret(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        data=encoded_data,
        type=secret_type,
    )

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.create_namespaced_secret(namespace, body)

        if wait:
            if not _wait_for_resource_status(
                api_instance, "secret", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for secret {name} to become ready")

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException):
            if exc.status == 409:
                raise CommandExecutionError(
                    f"Secret {name} already exists in namespace {namespace}. Use replace_secret to update it."
                )
            if exc.status == 404:
                raise CommandExecutionError(f"Secret {namespace}/{name} not found") from exc
            log.exception("Exception when calling CoreV1Api->create_namespaced_secret")
        raise CommandExecutionError(str(exc))
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
    wait=False,
    timeout=60,
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

    body = kubernetes.client.V1ConfigMap(
        metadata=__dict_to_object_meta(name, namespace, {}), data=data
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.create_namespaced_config_map(namespace, body)

        if wait:
            if not _wait_for_resource_status(
                api_instance, "config_map", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for configmap {name} to become ready")

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException):
            if exc.status == 404:
                raise CommandExecutionError(f"ConfigMap {namespace}/{name} not found") from exc
            if exc.status == 409:
                raise CommandExecutionError(f"ConfigMap {name} already exists") from exc
        log.exception("Exception when calling CoreV1Api->create_namespaced_config_map")
        raise CommandExecutionError(exc)
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
        return api_response.to_dict()
    except ApiException as exc:
        if exc.status == 409:
            raise CommandExecutionError(f"Namespace {name} already exists: {exc.reason}") from exc
        if exc.status == 422:
            raise CommandExecutionError(f"Invalid namespace name {name}: {exc.reason}") from exc
        log.exception("Exception when calling CoreV1Api->create_namespace")
        raise CommandExecutionError(exc) from exc
    except HTTPError as exc:
        log.exception("HTTP error occurred")
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

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Deployment {namespace}/{name} not found") from exc
        log.exception("Exception when calling AppsV1Api->replace_namespaced_deployment")
        raise CommandExecutionError(exc)
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
            old_service='{"metadata": {"resource_version": "12345"}, "spec": {"cluster_ip": "10.0.0.1"}}' \
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
    body.spec.cluster_ip = old_service["spec"]["cluster_ip"]
    body.metadata.resource_version = old_service["metadata"]["resource_version"]

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.replace_namespaced_service(name, namespace, body)

        if wait:
            if not _wait_for_resource_status(
                api_instance, "service", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for service {name} to become ready")

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Service {namespace}/{name} not found") from exc
        log.exception("Exception when calling CoreV1Api->replace_namespaced_service")
        raise CommandExecutionError(exc)
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

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"Secret {namespace}/{name} not found") from exc
        log.exception("Exception when calling CoreV1Api->replace_namespaced_secret")
        raise CommandExecutionError(str(exc))
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
                api_instance, "config_map", name, namespace, "ready", timeout
            ):
                raise CommandExecutionError(f"Timeout waiting for configmap {name} to be ready")

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            raise CommandExecutionError(f"ConfigMap {namespace}/{name} not found") from exc
        log.exception("Exception when calling CoreV1Api->replace_namespaced_configmap")
        raise CommandExecutionError(exc)
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
        raise CommandExecutionError(f"Invalid {kind} spec: {exc}")

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
        raise CommandExecutionError(f"Invalid pod spec in deployment template: {exc}")

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
            raise CommandExecutionError(f"replicas must be an integer: {exc}")

    # Create final spec
    try:
        return V1DeploymentSpec(**processed_spec)
    except (TypeError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid deployment spec: {exc}")


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
                        )
                processed_ports.append(kubernetes.client.V1ContainerPort(**port_copy))

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

    try:
        return kubernetes.client.V1PodSpec(**processed_spec)
    except (TypeError, ValueError) as exc:
        raise CommandExecutionError(f"Invalid pod spec: {exc}")


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
                        )
                else:
                    # Verify required fields for port
                    if "port" not in port:
                        raise CommandExecutionError(
                            f"Service port at index {i} must specify 'port' value"
                        )

                    try:
                        port_num = int(port["port"])
                    except (TypeError, ValueError) as exc:
                        raise CommandExecutionError(f"Invalid port number at index {i}: {exc}")

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
                            )

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
                                    )
                            if hasattr(kube_port, port_key):
                                setattr(kube_port, port_key, port_value)

                spec_obj.ports.append(kube_port)

        elif hasattr(spec_obj, key):
            setattr(spec_obj, key, value)

    return spec_obj


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
    api_instance, resource_type, name, namespace, expected_status, timeout=60
):
    """
    .. versionadded:: 2.0.0

    Helper function to wait for a resource to reach an expected status.

    api_instance
        The kubernetes API instance to use

    resource_type
        Type of resource to wait for (e.g., 'deployment', 'pod', 'service')

    name
        Name of the resource

    namespace
        Namespace of the resource

    expected_status
        Expected status to wait for ('created', 'deleted', 'ready')

    timeout
        Timeout in seconds (default: 60)

    Returns True if the resource reached the expected status, False otherwise.
    """
    try:
        w = Watch()
        start_time = time.time()

        if expected_status == "deleted":
            # For deletion, periodically check if the resource still exists until timeout
            while time.time() - start_time < timeout:
                try:
                    if resource_type == "deployment":
                        api_instance.read_namespaced_deployment(name, namespace)
                    elif resource_type == "namespace":
                        api_instance.read_namespace(name)
                    elif resource_type == "service":
                        api_instance.read_namespaced_service(name, namespace)
                    elif resource_type == "pod":
                        api_instance.read_namespaced_pod(name, namespace)
                    elif resource_type == "secret":
                        api_instance.read_namespaced_secret(name, namespace)
                    elif resource_type == "configmap":
                        api_instance.read_namespaced_config_map(name, namespace)
                except ApiException as e:
                    if e.status == 404:
                        # Resource is gone, deletion successful
                        return True
                # Resource still exists, wait before retrying
                time.sleep(1)
            # Timed out waiting for deletion
            return False

        # For creation/ready status watching
        for event in w.stream(
            func=getattr(api_instance, f"list_namespaced_{resource_type}"),
            namespace=namespace,
            field_selector=f"metadata.name={name}",
            timeout_seconds=timeout,
        ):
            if event["object"].metadata.name == name:
                if expected_status == "created":
                    return True
                elif expected_status == "ready":
                    if resource_type == "deployment":
                        if (
                            event["object"].status.available_replicas
                            and event["object"].status.available_replicas
                            == event["object"].spec.replicas
                        ):
                            return True
                    elif resource_type == "pod":
                        # More detailed pod readiness check
                        if event["object"].status.phase == "Running":
                            if not event["object"].status.container_statuses:
                                continue

                            all_containers_ready = True
                            unready_containers = []

                            for container_status in event["object"].status.container_statuses:
                                if not container_status.ready:
                                    all_containers_ready = False
                                    unready_containers.append(container_status.name)

                            if all_containers_ready:
                                return True
                    elif resource_type == "service":
                        # For services, check if endpoints exist
                        endpoints_api = kubernetes.client.CoreV1Api()
                        try:
                            endpoints = endpoints_api.read_namespaced_endpoints(name, namespace)
                            if endpoints and endpoints.subsets:
                                for subset in endpoints.subsets:
                                    if subset.addresses:
                                        return True  # Service has endpoints
                        except ApiException:
                            pass
                        return False  # No endpoints found
                    else:
                        return True  # For other resources, assume ready when created

            if time.time() - start_time >= timeout:
                log.warning(
                    "Timeout reached while waiting for %s/%s to become %s",
                    resource_type,
                    name,
                    expected_status,
                )
                return False

        log.warning(
            "Watch stream ended before %s/%s reached %s status",
            resource_type,
            name,
            expected_status,
        )
        return False

    except (ApiException, HTTPError) as exc:
        log.exception("Exception when waiting for %s", resource_type)
        raise CommandExecutionError(exc)
    finally:
        w.stop()
