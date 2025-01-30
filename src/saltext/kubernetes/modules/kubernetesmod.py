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

Only `kubeconfig` or `kubeconfig-data` should be provided. In case both are
provided `kubeconfig` entry is preferred.

CLI Example:

.. code-block:: bash

    salt '*' kubernetes.nodes

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


def _setup_conn(**_kwargs):
    """
    Setup kubernetes API connection singleton
    """
    kubeconfig = __salt__["config.option"]("kubernetes.kubeconfig")
    kubeconfig_data = __salt__["config.option"]("kubernetes.kubeconfig-data")
    context = __salt__["config.option"]("kubernetes.context")

    if kubeconfig_data and not kubeconfig:
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
            return None
        else:
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
        else:
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
            return None
        else:
            log.exception("Exception when calling CoreV1Api->patch_node")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)

    return None


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
            return None
        else:
            log.exception("Exception when calling CoreV1Api->list_namespace")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def deployments(namespace="default", **kwargs):
    """
    Return a list of kubernetes deployments defined in the namespace

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
            return None
        else:
            log.exception("Exception when calling AppsV1Api->list_namespaced_deployment")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def services(namespace="default", **kwargs):
    """
    Return a list of kubernetes services defined in the namespace

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
            return None
        else:
            log.exception("Exception when calling CoreV1Api->list_namespaced_service")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def pods(namespace="default", **kwargs):
    """
    Return a list of kubernetes pods defined in the namespace

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
        else:
            log.exception("Exception when calling CoreV1Api->list_namespaced_pod")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def secrets(namespace="default", **kwargs):
    """
    Return a list of kubernetes secrets defined in the namespace

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
            return None
        else:
            log.exception("Exception when calling CoreV1Api->list_namespaced_secret")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def configmaps(namespace="default", **kwargs):
    """
    Return a list of kubernetes configmaps defined in the namespace

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
        else:
            log.exception("Exception when calling CoreV1Api->list_namespaced_config_map")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def show_deployment(name, namespace="default", **kwargs):
    """
    Return the kubernetes deployment defined by name and namespace

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
        else:
            log.exception("Exception when calling AppsV1Api->read_namespaced_deployment")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def show_service(name, namespace="default", **kwargs):
    """
    Return the kubernetes service defined by name and namespace

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
        else:
            log.exception("Exception when calling CoreV1Api->read_namespaced_service")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def show_pod(name, namespace="default", **kwargs):
    """
    Return POD information for a given pod name defined in the namespace

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
        else:
            log.exception("Exception when calling CoreV1Api->read_namespaced_pod")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def show_namespace(name, **kwargs):
    """
    Return information for a given namespace defined by the specified name

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_namespace kube-system

    Raises:
        CommandExecutionError: If there is an error retrieving the namespace information
    """
    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.read_namespace(name)
        return api_response.to_dict()
    except ApiException as exc:
        if exc.status == 404:
            return None
        else:
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

        if response_dict.get("data") and (decode or decode == "True"):
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
        else:
            log.exception("Exception when calling CoreV1Api->read_namespaced_secret")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def show_configmap(name, namespace="default", **kwargs):
    """
    Return the kubernetes configmap defined by name and namespace.

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
        else:
            log.exception("Exception when calling CoreV1Api->read_namespaced_config_map")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def delete_deployment(name, namespace="default", **kwargs):
    """
    Deletes the kubernetes deployment defined by name and namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_deployment my-nginx
        salt '*' kubernetes.delete_deployment name=my-nginx namespace=default
    """
    cfg = _setup_conn(**kwargs)
    body = kubernetes.client.V1DeleteOptions(orphan_dependents=True)

    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.delete_namespaced_deployment(
            name=name, namespace=namespace, body=body
        )
        mutable_api_response = api_response.to_dict()
        if not salt.utils.platform.is_windows():
            try:
                with _time_limit(POLLING_TIME_LIMIT):
                    while show_deployment(name, namespace) is not None:
                        time.sleep(1)
                    else:  # pylint: disable=useless-else-on-loop
                        mutable_api_response["code"] = 200
            except TimeoutError:
                pass
        else:
            # Windows has not signal.alarm implementation, so we are just falling
            # back to loop-counting.
            for _ in range(60):
                if show_deployment(name, namespace) is None:
                    mutable_api_response["code"] = 200
                    break
                time.sleep(1)
        if mutable_api_response["code"] != 200:
            log.warning(
                "Reached polling time limit. Deployment is not yet "
                "deleted, but we are backing off. Sorry, but you'll "
                "have to check manually."
            )
        return mutable_api_response
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling AppsV1Api->delete_namespaced_deployment")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def delete_service(name, namespace="default", **kwargs):
    """
    Deletes the kubernetes service defined by name and namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_service my-nginx default
        salt '*' kubernetes.delete_service name=my-nginx namespace=default
    """
    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.delete_namespaced_service(name=name, namespace=namespace)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->delete_namespaced_service")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def delete_pod(name, namespace="default", **kwargs):
    """
    Deletes the kubernetes pod defined by name and namespace

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

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->delete_namespaced_pod")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def delete_namespace(name, **kwargs):
    """
    Deletes the kubernetes namespace defined by name

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_namespace salt
        salt '*' kubernetes.delete_namespace name=salt

    Raises:
        CommandExecutionError: If the namespace deletion fails or is forbidden
    """
    cfg = _setup_conn(**kwargs)
    body = kubernetes.client.V1DeleteOptions(orphan_dependents=True)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.delete_namespace(name=name, body=body)
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


def delete_secret(name, namespace="default", **kwargs):
    """
    Deletes the kubernetes secret defined by name and namespace

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

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->delete_namespaced_secret")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def delete_configmap(name, namespace="default", **kwargs):
    """
    Deletes the kubernetes configmap defined by name and namespace

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
    name, namespace, metadata, spec, source, template, saltenv, context=None, **kwargs
):
    """
    Creates the kubernetes deployment as defined by the user.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_deployment *args
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
        context=context,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.create_namespaced_deployment(namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling AppsV1Api->create_namespaced_deployment")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def create_pod(name, namespace, metadata, spec, source, template, saltenv, context=None, **kwargs):
    """
    Creates a kubernetes pod as defined by the user.

    Args:
        name: The name of the pod
        namespace: The namespace to create the pod in
        metadata: Pod metadata dict
        spec: Pod spec dict following kubernetes API conventions
        source: File path to pod definition
        template: Template engine to use to render the source file
        saltenv: Salt environment to pull the source file from
        context: Variables to make available in templated files
        **kwargs: Extra arguments to pass to the API call

    Pod spec must follow kubernetes API conventions:
        ports:
          - containerPort: 8080
            name: http
            protocol: TCP

    CLI Examples:

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
        context=context,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.create_namespaced_pod(namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->create_namespaced_pod")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def create_service(
    name, namespace, metadata, spec, source, template, saltenv, context=None, **kwargs
):
    """
    Creates the kubernetes service as defined by the user.

    Args:
        name: The name of the service
        namespace: The namespace to create the service in
        metadata: Service metadata dict
        spec: Service spec dict that follows kubernetes API conventions
        source: File path to service definition
        template: Template engine to use to render the source file
        saltenv: Salt environment to pull the source file from
        context: Variables to make available in templated files
        **kwargs: Extra arguments to pass to the API call

    Service spec must follow kubernetes API conventions. Port specifications can be:

    Simple integer for basic port definition: [80, 443]

    Dictionary for advanced configuration:
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
        context=context,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.create_namespaced_service(namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
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
    saltenv="base",
    context=None,
    type=None,
    metadata=None,
    **kwargs,
):
    """
    Creates the kubernetes secret as defined by the user.
    Values that are already base64 encoded will not be re-encoded.

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
        src_obj = __read_and_render_yaml_file(source, template, saltenv, context)
        if isinstance(src_obj, dict):
            if "data" in src_obj:
                data = src_obj["data"]
            type = src_obj.get("type")
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
        type=type,
    )

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.create_namespaced_secret(namespace, body)
        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException):
            if exc.status == 409:
                raise CommandExecutionError(
                    f"Secret {name} already exists in namespace {namespace}. Use replace_secret to update it."
                )
            if exc.status == 404:
                return None
        raise CommandExecutionError(str(exc))
    finally:
        _cleanup(**cfg)


def create_configmap(
    name, namespace, data, source=None, template=None, saltenv="base", context=None, **kwargs
):
    """
    Creates the kubernetes configmap as defined by the user.

    CLI Example:

    .. code-block:: bash

        salt 'minion1' kubernetes.create_configmap \
            settings default '{"example.conf": "# example file"}'

        salt 'minion2' kubernetes.create_configmap \
            name=settings namespace=default data='{"example.conf": "# example file"}'
    """
    if source:
        data = __read_and_render_yaml_file(source, template, saltenv, context)
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

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->create_namespaced_config_map")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def create_namespace(name, **kwargs):
    """
    Creates a namespace with the specified name.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_namespace salt
        salt '*' kubernetes.create_namespace name=salt

    Raises:
        CommandExecutionError: If the namespace creation fails, already exists, or has invalid name
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
    name, metadata, spec, source, template, saltenv, namespace="default", context=None, **kwargs
):
    """
    Replaces an existing deployment with a new one defined by name and
    namespace, having the specificed metadata and spec.

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
        context=context,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.AppsV1Api()
        api_response = api_instance.replace_namespaced_deployment(name, namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling AppsV1Api->replace_namespaced_deployment")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def replace_service(
    name,
    metadata,
    spec,
    source,
    template,
    old_service,
    saltenv,
    namespace="default",
    context=None,
    **kwargs,
):
    """
    Replaces an existing service with a new one defined by name and namespace,
    having the specificed metadata and spec.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replace_service *args
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
        context=context,
    )

    # Some attributes have to be preserved
    # otherwise exceptions will be thrown
    body.spec.cluster_ip = old_service["spec"]["cluster_ip"]
    body.metadata.resource_version = old_service["metadata"]["resource_version"]

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.replace_namespaced_service(name, namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->replace_namespaced_service")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def replace_secret(
    name,
    data,
    source=None,
    template=None,
    saltenv="base",
    namespace="default",
    context=None,
    type=None,
    metadata=None,
    **kwargs,
):
    """
    Replaces an existing secret with a new one defined by name and namespace.
    Values that are already base64 encoded will not be re-encoded.
    If a source file is specified, the secret type will be read from the template.

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
            source=/path/to/docker-secret.yaml

        # For TLS secrets
        salt 'minion4' kubernetes.replace_secret \
            name=tls-secret \
            source=/path/to/tls-secret.yaml
    """
    if source:
        src_obj = __read_and_render_yaml_file(source, template, saltenv, context)
        if isinstance(src_obj, dict):
            if "data" in src_obj:
                data = src_obj["data"]
            type = src_obj.get("type")
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
        type = existing_secret.type

    body = kubernetes.client.V1Secret(
        metadata=__dict_to_object_meta(name, namespace, metadata), data=encoded_data, type=type
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.replace_namespaced_secret(name, namespace, body)
        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        raise CommandExecutionError(str(exc))
    finally:
        _cleanup(**cfg)


def replace_configmap(
    name,
    data,
    source=None,
    template=None,
    saltenv="base",
    namespace="default",
    context=None,
    **kwargs,
):
    """
    Replaces an existing configmap with a new one defined by name and
    namespace with the specified data.

    CLI Example:

    .. code-block:: bash

        salt 'minion1' kubernetes.replace_configmap \
            settings default '{"example.conf": "# example file"}'

        salt 'minion2' kubernetes.replace_configmap \
            name=settings namespace=default data='{"example.conf": "# example file"}'
    """
    if source:
        data = __read_and_render_yaml_file(source, template, saltenv, context)

    data = __enforce_only_strings_dict(data)

    body = kubernetes.client.V1ConfigMap(
        metadata=__dict_to_object_meta(name, namespace, {}), data=data
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.replace_namespaced_config_map(name, namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->replace_namespaced_configmap")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def __is_base64(value):
    """
    Check if a string is base64 encoded by attempting to decode it.
    """
    try:
        if not isinstance(value, str):
            return False
        decoded = base64.b64decode(value)
        # Try encoding back to verify it's legitimate base64
        return base64.b64encode(decoded).decode("utf-8") == value
    except Exception:  # pylint: disable=broad-except
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
    context=None,
):
    """
    Create a Kubernetes Object body instance.
    """
    if source:
        src_obj = __read_and_render_yaml_file(source, template, saltenv, context)
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


def __read_and_render_yaml_file(source, template, saltenv, context=None):
    """
    Read a yaml file and, if needed, renders that using the specified
    templating. Returns the python objects defined inside of the file.
    """
    sfn = __salt__["cp.cache_file"](source, saltenv)
    if not sfn:
        raise CommandExecutionError(f"Source file '{source}' not found")

    with salt.utils.files.fopen(sfn, "r") as src:
        contents = src.read()

        if template:
            if template in salt.utils.templates.TEMPLATE_REGISTRY:
                # Apply templating with context
                if context is None:
                    context = {}

                data = salt.utils.templates.TEMPLATE_REGISTRY[template](
                    contents,
                    from_str=True,
                    to_str=True,
                    saltenv=saltenv,
                    grains=__grains__,
                    pillar=__pillar__,
                    salt=__salt__,
                    opts=__opts__,
                    context=context,
                )

                if not data["result"]:
                    # Failed to render the template
                    raise CommandExecutionError(
                        f'Failed to render file path with error: {data["data"]}'
                    )

                contents = data["data"].encode("utf-8")
            else:
                raise CommandExecutionError(f"Unknown template specified: {template}")

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
                if isinstance(port, dict):
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
                else:
                    raise CommandExecutionError(
                        f"Port in container {container_copy['name']} must be a dictionary"
                    )
            container_copy["ports"] = processed_ports

        containers.append(kubernetes.client.V1Container(**container_copy))

    processed_spec["containers"] = containers

    # Handle imagePullSecrets field
    if "imagePullSecrets" in processed_spec:
        image_pull_secrets = processed_spec.pop("imagePullSecrets")
        if not isinstance(image_pull_secrets, list):
            raise CommandExecutionError("imagePullSecrets must be a list")

        processed_secrets = []
        for secret in image_pull_secrets:
            if isinstance(secret, dict):
                processed_secrets.append(kubernetes.client.V1LocalObjectReference(**secret))
            else:
                raise CommandExecutionError(
                    f"Each imagePullSecret must be a dictionary, not {type(secret).__name__}"
                )
        processed_spec["image_pull_secrets"] = processed_secrets

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

    Raises:
        CommandExecutionError: If the spec is invalid or missing required fields
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
        ret[str(key) if not isinstance(key, str) else key] = (
            str(value) if not isinstance(value, str) else value
        )

    return ret
