"""
Manage kubernetes resources as salt states
==========================================

NOTE: This module requires the proper pillar values set. See
salt.modules.kubernetesmod for more information.

.. warning::

    Configuration options will change in 2019.2.0.

The kubernetes module is used to manage different kubernetes resources.


.. code-block:: yaml

    my-nginx:
      kubernetes.deployment_present:
        - namespace: default
          metadata:
            app: frontend
          spec:
            replicas: 1
            template:
              metadata:
                labels:
                  run: my-nginx
              spec:
                containers:
                - name: my-nginx
                  image: nginx
                  ports:
                  - containerPort: 80

    my-mariadb:
      kubernetes.deployment_absent:
        - namespace: default

    # kubernetes deployment as specified inside of
    # a file containing the definition of the the
    # deployment using the official kubernetes format
    redis-master-deployment:
      kubernetes.deployment_present:
        - name: redis-master
        - source: salt://k8s/redis-master-deployment.yml
      require:
        - pip: kubernetes-python-module

    # kubernetes service as specified inside of
    # a file containing the definition of the the
    # service using the official kubernetes format
    redis-master-service:
      kubernetes.service_present:
        - name: redis-master
        - source: salt://k8s/redis-master-service.yml
      require:
        - kubernetes.deployment_present: redis-master

    # kubernetes deployment as specified inside of
    # a file containing the definition of the the
    # deployment using the official kubernetes format
    # plus some jinja directives
     nginx-source-template:
      kubernetes.deployment_present:
        - source: salt://k8s/nginx.yml.jinja
        - template: jinja
      require:
        - pip: kubernetes-python-module

    # kubernetes deployment using a template with custom template_context variables
    nginx-template-with-template_context:
      kubernetes.deployment_present:
        - name: nginx-template
        - source: salt://k8s/nginx-template.yml.jinja
        - template: jinja
        - template_context:
            replicas: 3
            nginx_version: 1.19
            environment: production
            app_label: frontend

    # kubernetes secret with template_context variables
    cert-secret-with-template_context:
      kubernetes.secret_present:
        - name: tls-cert
        - source: salt://k8s/tls-cert.yml.jinja
        - template: jinja
        - template_context:
            cert_name: myapp.example.com
            cert_data: |
                -----BEGIN CERTIFICATE-----
                ...
                -----END CERTIFICATE-----
        - secret_type: kubernetes.io/tls

    # Kubernetes secret
    k8s-secret:
      kubernetes.secret_present:
        - name: top-secret
          data:
            key1: value1
            key2: value2
            key3: value3

.. versionadded:: 2017.7.0
"""

import copy
import logging

from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)

__virtualname__ = "kubernetes"


def __virtual__():
    """
    Only load if the kubernetes module is available in __salt__
    """
    if "kubernetes.ping" in __salt__:
        return True
    return (False, "kubernetes module could not be loaded")


def _error(ret, err_msg):
    """
    Helper function to propagate errors to
    the end user.
    """
    ret["result"] = False
    ret["comment"] = err_msg
    return ret


def deployment_absent(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    Ensures that the named deployment is absent from the given namespace.

    name
        The name of the deployment

    namespace
        The name of the namespace

    wait
        .. versionadded:: 2.0.0

        If set to True, the function will wait until the deployment is deleted.

    timeout
        .. versionadded:: 2.0.0

        The time in seconds to wait for the deployment to

    Example:

    .. code-block:: yaml

        my-nginx:
          kubernetes.deployment_absent:
            - namespace: default
    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    try:
        deployment = __salt__["kubernetes.show_deployment"](name, namespace, **kwargs)

        if deployment is None:
            ret["result"] = True
            ret["comment"] = "The deployment does not exist"
            return ret

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The deployment is going to be deleted"
            ret["changes"] = {
                "old": "present",
                "new": "absent",
            }
            return ret

        __salt__["kubernetes.delete_deployment"](
            name, namespace, wait=wait, timeout=timeout, **kwargs
        )

        ret["result"] = True
        ret["changes"] = {"old": "present", "new": "absent"}
        ret["comment"] = f"Deployment {name} deleted"

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def deployment_present(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source="",
    template="",
    template_context=None,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    Ensures that the named deployment is present inside of the specified
    namespace with the given metadata and spec.
    If the deployment exists, it will be patched with the desired state.

    name
        The name of the deployment.

    namespace
        The namespace holding the deployment. The 'default' one is going to be
        used unless a different one is specified.

    metadata
        The metadata of the deployment object.

    spec
        The spec of the deployment object.

    source
        A file containing the definition of the deployment (metadata and
        spec) in the official kubernetes format.

    template
        Template engine to be used to render the source file.

    template_context
        .. versionadded:: 2.0.0

        Variables to be passed into the template.

    wait
        .. versionadded:: 2.0.0

        If set to True, the function will wait until the deployment is ready.

    timeout
        .. versionadded:: 2.0.0

        The time in seconds to wait for the deployment to be ready.

    Example:

    .. code-block:: yaml

        my-nginx:
          kubernetes.deployment_present:
            - namespace: default
            - metadata:
                app: frontend
            - spec:
                replicas: 1
                template:
                  metadata:
                    labels:
                      run: my-nginx
                  spec:
                    containers:
                    - name: my-nginx
                      image: nginx
                      ports:
                      - containerPort: 80
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if (metadata or spec) and source:
        return _error(ret, "'source' cannot be used in combination with 'metadata' or 'spec'")

    if metadata is None:
        metadata = {}

    if spec is None:
        spec = {}

    try:
        deployment = __salt__["kubernetes.show_deployment"](name, namespace, **kwargs)

        if deployment is None:
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = "The deployment is going to be created"
                try:
                    dry_run_result = __salt__["kubernetes.create_deployment"](
                        name=name,
                        namespace=namespace,
                        metadata=metadata,
                        spec=spec,
                        source=source,
                        template=template,
                        saltenv=__env__,
                        template_context=template_context,
                        dry_run=True,
                        **kwargs,
                    )
                    ret["changes"] = {"old": {}, "new": dry_run_result}
                except CommandExecutionError as err:
                    ret["result"] = None
                    ret["comment"] = (
                        "The deployment is going to be created. "
                        f"Dry run failed, possibly due to dependencies not created yet: {err}"
                    )
                return ret

            res = __salt__["kubernetes.create_deployment"](
                name=name,
                namespace=namespace,
                metadata=metadata,
                spec=spec,
                source=source,
                template=template,
                saltenv=__env__,
                template_context=template_context,
                wait=wait,
                timeout=timeout,
                **kwargs,
            )
            ret["result"] = True
            ret["changes"] = {"old": {}, "new": res}
            ret["comment"] = "Deployment created"
            return ret

        # Deployment exists — build the patch object
        if source:
            patch_kwargs = {
                "source": source,
                "template": template,
                "template_context": template_context,
            }
        else:
            patch_obj = {}
            if metadata:
                patch_obj["metadata"] = metadata
            if spec:
                patch_obj["spec"] = spec
            patch_kwargs = {"patch": patch_obj}

        if __opts__["test"]:
            try:
                res = __salt__["kubernetes.patch_deployment"](
                    name,
                    namespace,
                    dry_run=True,
                    **patch_kwargs,
                    **kwargs,
                )
            except CommandExecutionError as err:
                ret["result"] = None
                ret["comment"] = (
                    "The deployment is going to be updated. "
                    f"Dry run failed, possibly due to dependencies not created yet: {err}"
                )
                return ret

            if res == deployment:
                ret["result"] = True
                ret["comment"] = "The deployment is already in the desired state"
                return ret

            ret["result"] = None
            ret["comment"] = "The deployment is going to be updated"
            ret["changes"] = {"old": deployment, "new": res}
            return ret

        res = __salt__["kubernetes.patch_deployment"](
            name,
            namespace,
            wait=wait,
            timeout=timeout,
            **patch_kwargs,
            **kwargs,
        )

        if res == deployment:
            ret["result"] = True
            ret["comment"] = "The deployment is already in the desired state"
            return ret

        ret["changes"] = {"old": deployment, "new": res}
        ret["result"] = True
        ret["comment"] = "Deployment updated"

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def service_present(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source="",
    template="",
    template_context=None,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    Ensures that the named service is present inside of the specified namespace
    with the given metadata and spec.
    If the service exists, it will be patched with the desired state.

    name
        The name of the service.

    namespace
        The namespace holding the service. The 'default' one is going to be
        used unless a different one is specified.

    metadata
        The metadata of the service object.

    spec
        The spec of the service object.

    source
        A file containing the definition of the service (metadata and
        spec) in the official kubernetes format.

    template
        Template engine to be used to render the source file.

    template_context
        .. versionadded:: 2.0.0

        Variables to be passed into the template.

    wait
        .. versionadded:: 2.0.0

        If set to True, the function will wait until the service is created.

    timeout
        .. versionadded:: 2.0.0

        The time in seconds to wait for the service to be created.

    Example:

    .. code-block:: yaml

        my-service:
          kubernetes.service_present:
            - namespace: default
            - metadata:
                app: frontend
            - spec:
                ports:
                  - port: 80
                    targetPort: 80
                    protocol: TCP
                selector:
                  app: frontend
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if (metadata or spec) and source:
        return _error(ret, "'source' cannot be used in combination with 'metadata' or 'spec'")

    if metadata is None:
        metadata = {}

    if spec is None:
        spec = {}

    try:
        service = __salt__["kubernetes.show_service"](name, namespace, **kwargs)

        if service is None:
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = "The service is going to be created"
                try:
                    dry_run_result = __salt__["kubernetes.create_service"](
                        name=name,
                        namespace=namespace,
                        metadata=metadata,
                        spec=spec,
                        source=source,
                        template=template,
                        saltenv=__env__,
                        template_context=template_context,
                        dry_run=True,
                        **kwargs,
                    )
                    ret["changes"] = {"old": {}, "new": dry_run_result}
                except CommandExecutionError as err:
                    ret["result"] = None
                    ret["comment"] = (
                        "The service is going to be created. "
                        f"Dry run failed, possibly due to dependencies not created yet: {err}"
                    )
                return ret

            res = __salt__["kubernetes.create_service"](
                name=name,
                namespace=namespace,
                metadata=metadata,
                spec=spec,
                source=source,
                template=template,
                saltenv=__env__,
                template_context=template_context,
                wait=wait,
                timeout=timeout,
                **kwargs,
            )
            ret["result"] = True
            ret["changes"] = {"old": {}, "new": res}
            ret["comment"] = "Service created"
            return ret

        # Service exists — build the patch object
        if source:
            patch_kwargs = {
                "source": source,
                "template": template,
                "template_context": template_context,
            }
        else:
            patch_obj = {}
            if metadata:
                patch_obj["metadata"] = metadata
            if spec:
                patch_obj["spec"] = spec
            patch_kwargs = {"patch": patch_obj}

        if __opts__["test"]:
            try:
                res = __salt__["kubernetes.patch_service"](
                    name,
                    namespace,
                    dry_run=True,
                    **patch_kwargs,
                    **kwargs,
                )
            except CommandExecutionError as err:
                ret["result"] = None
                ret["comment"] = (
                    "The service is going to be updated. "
                    f"Dry run failed, possibly due to dependencies not created yet: {err}"
                )
                return ret

            if res == service:
                ret["result"] = True
                ret["comment"] = "The service is already in the desired state"
                return ret

            ret["result"] = None
            ret["comment"] = "The service is going to be updated"
            ret["changes"] = {"old": service, "new": res}
            return ret

        res = __salt__["kubernetes.patch_service"](
            name,
            namespace,
            wait=wait,
            timeout=timeout,
            **patch_kwargs,
            **kwargs,
        )

        if res == service:
            ret["result"] = True
            ret["comment"] = "The service is already in the desired state"
            return ret

        ret["changes"] = {"old": service, "new": res}
        ret["result"] = True
        ret["comment"] = "Service updated"

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def service_absent(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    Ensures that the named service is absent from the given namespace.

    name
        The name of the service

    namespace
        The name of the namespace

    wait
        .. versionadded:: 2.0.0

        If set to True, the function will wait until the service is deleted.

    timeout
        .. versionadded:: 2.0.0

        The time in seconds to wait for the service to be deleted.

    Example:

    .. code-block:: yaml

        my_service:
          kubernetes.service_absent:
            - namespace: default
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    try:
        service = __salt__["kubernetes.show_service"](name, namespace, **kwargs)

        if service is None:
            ret["result"] = True
            ret["comment"] = "The service does not exist"
            return ret

        if __opts__["test"]:
            ret["comment"] = "The service is going to be deleted"
            ret["result"] = None
            ret["changes"] = {"old": "present", "new": "absent"}
            return ret

        __salt__["kubernetes.delete_service"](name, namespace, wait=wait, timeout=timeout, **kwargs)

        ret["result"] = True
        ret["changes"] = {"old": "present", "new": "absent"}
        ret["comment"] = f"Service {name} deleted"

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def namespace_absent(name, wait=False, timeout=60, **kwargs):
    """
    Ensures that the named namespace is absent.

    name
        The name of the namespace

    wait
        .. versionadded:: 2.0.0

        If set to True, the function will wait until the namespace is deleted.

    timeout
        .. versionadded:: 2.0.0

        The time in seconds to wait for the namespace to be deleted.

    Example:

    .. code-block:: yaml

        my_namespace:
          kubernetes.namespace_absent:
            - namespace: default
    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    try:
        namespace = __salt__["kubernetes.show_namespace"](name, **kwargs)

        if namespace is None:
            ret["result"] = True
            ret["comment"] = "The namespace does not exist"
            return ret

        if __opts__["test"]:
            ret["comment"] = "The namespace is going to be deleted"
            ret["result"] = None
            ret["changes"] = {"old": "present", "new": "absent"}
            return ret

        __salt__["kubernetes.delete_namespace"](name, wait=wait, timeout=timeout, **kwargs)

        ret["result"] = True
        ret["changes"] = {"old": "present", "new": "absent"}
        ret["comment"] = f"Namespace {name} deleted"

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def namespace_present(name, **kwargs):
    """
    Ensures that the named namespace is present.

    name
        The name of the namespace.

    Example:

    .. code-block:: yaml

        my_namespace:
          kubernetes.namespace_present:
            - namespace: default
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    try:
        namespace = __salt__["kubernetes.show_namespace"](name, **kwargs)

        if namespace is None:
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = "The namespace is going to be created"
                ret["changes"] = {"old": {}, "new": {"metadata": {"name": name}}}
                return ret

            res = __salt__["kubernetes.create_namespace"](name, **kwargs)
            ret["result"] = True
            ret["changes"] = {"old": {}, "new": res}
        else:
            ret["result"] = True
            ret["comment"] = "The namespace already exists"

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def secret_absent(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    Ensures that the named secret is absent from the given namespace.

    name
        The name of the secret

    namespace
        The name of the namespace

    wait
        .. versionadded:: 2.0.0

        If set to True, the function will wait until the secret is deleted.

    timeout
        .. versionadded:: 2.0.0

        The time in seconds to wait for the secret to be deleted.

    Example:

    .. code-block:: yaml

        my_secret:
          kubernetes.secret_absent:
            - namespace: default

    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    try:
        secret = __salt__["kubernetes.show_secret"](name, namespace, **kwargs)

        if secret is None:
            ret["result"] = True
            ret["comment"] = "The secret does not exist"
            return ret

        if __opts__["test"]:
            ret["comment"] = "The secret is going to be deleted"
            ret["result"] = None
            ret["changes"] = {"old": "present", "new": "absent"}
            return ret

        __salt__["kubernetes.delete_secret"](name, namespace, wait=wait, timeout=timeout, **kwargs)

        ret["result"] = True
        ret["changes"] = {"old": "present", "new": "absent"}
        ret["comment"] = f"Secret {name} deleted"

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def secret_present(
    name,
    namespace="default",
    data=None,
    source=None,
    template=None,
    template_context=None,
    secret_type=None,
    metadata=None,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    Ensures that the named secret is present inside of the specified namespace
    with the given data.
    If the secret exists, it will be patched with the desired state.

    name
        The name of the secret.

    namespace
        The namespace holding the secret. The 'default' one is going to be
        used unless a different one is specified.

    data
        The dictionary holding the secrets.

    source
        A file containing the data of the secret in plain format.

    template
        Template engine to be used to render the source file.

    template_context
        .. versionadded:: 2.0.0

        Variables to be passed into the template.

    secret_type
        .. versionadded:: 2.0.0

        The type of secret to create. Defaults to ``Opaque``.

    metadata
        .. versionadded:: 2.0.0

        The metadata to include in the secret (annotations, labels, etc).

    wait
        .. versionadded:: 2.0.0

        If set to True, the function will wait until the secret is created.

    timeout
        .. versionadded:: 2.0.0

        The time in seconds to wait for the secret to be created.

    Example:

    .. code-block:: yaml

        my_secret:
          kubernetes.secret_present:
            - namespace: default
            - data:
                key1: value1
                key2: value2
                key3: value3
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if data and source:
        return _error(ret, "'source' cannot be used in combination with 'data'")

    if metadata is None:
        metadata = {}

    try:
        secret = __salt__["kubernetes.show_secret"](name, namespace, **kwargs)

        if secret is None:
            if data is None:
                data = {}

            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = "The secret is going to be created"
                try:
                    dry_run_result = __salt__["kubernetes.create_secret"](
                        name=name,
                        namespace=namespace,
                        data=data,
                        source=source,
                        template=template,
                        saltenv=__env__,
                        template_context=template_context,
                        secret_type=secret_type,
                        metadata=metadata,
                        dry_run=True,
                        **kwargs,
                    )
                    ret["changes"] = {
                        "old": {},
                        "new": {"data": list(dry_run_result.get("data") or [])},
                    }
                except CommandExecutionError as err:
                    ret["result"] = None
                    ret["comment"] = (
                        "The secret is going to be created. "
                        f"Dry run failed, possibly due to dependencies not created yet: {err}"
                    )
                return ret

            res = __salt__["kubernetes.create_secret"](
                name=name,
                namespace=namespace,
                data=data,
                source=source,
                template=template,
                saltenv=__env__,
                template_context=template_context,
                secret_type=secret_type,
                metadata=metadata,
                wait=wait,
                timeout=timeout,
                **kwargs,
            )
            ret["result"] = True
            ret["changes"] = {
                "old": {},
                "new": {"data": list(res.get("data") or [])},
            }
            ret["comment"] = "Secret created"
            return ret

        # Secret exists — build the patch object
        if source:
            patch_kwargs = {
                "source": source,
                "template": template,
                "template_context": template_context,
            }
        else:
            patch_obj = {}
            if metadata:
                patch_obj["metadata"] = metadata
            if data:
                patch_obj["data"] = data
            if secret_type:
                patch_obj["type"] = secret_type
            patch_kwargs = {"patch": patch_obj}

        if __opts__["test"]:
            try:
                res = __salt__["kubernetes.patch_secret"](
                    name,
                    namespace,
                    dry_run=True,
                    **patch_kwargs,
                    **kwargs,
                )
            except CommandExecutionError as err:
                ret["result"] = None
                ret["comment"] = (
                    "The secret is going to be updated. "
                    f"Dry run failed, possibly due to dependencies not created yet: {err}"
                )
                return ret

            if res == secret:
                ret["result"] = True
                ret["comment"] = "The secret is already in the desired state"
                return ret

            ret["result"] = None
            ret["comment"] = "The secret is going to be updated"
            ret["changes"] = {
                "old": {"data": list(secret.get("data") or [])},
                "new": {"data": list(res.get("data") or [])},
            }
            return ret

        res = __salt__["kubernetes.patch_secret"](
            name,
            namespace,
            wait=wait,
            timeout=timeout,
            **patch_kwargs,
            **kwargs,
        )

        if res == secret:
            ret["result"] = True
            ret["comment"] = "The secret is already in the desired state"
            return ret

        ret["changes"] = {
            "old": {"data": list(secret.get("data") or [])},
            "new": {"data": list(res.get("data") or [])},
        }
        ret["result"] = True
        ret["comment"] = "Secret updated"

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def configmap_absent(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    Ensures that the named configmap is absent from the given namespace.

    name
        The name of the configmap

    namespace
        The namespace holding the configmap. The 'default' one is going to be
        used unless a different one is specified.

    wait
        .. versionadded:: 2.0.0

        If set to True, the function will wait until the configmap is deleted.

    timeout
        .. versionadded:: 2.0.0

        The time in seconds to wait for the configmap to be deleted.

    Example:

    .. code-block:: yaml

        my_configmap:
          kubernetes.configmap_absent:
            - namespace: default
    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    try:
        configmap = __salt__["kubernetes.show_configmap"](name, namespace, **kwargs)

        if configmap is None:
            ret["result"] = True
            ret["comment"] = "The configmap does not exist"
            return ret

        if __opts__["test"]:
            ret["comment"] = "The configmap is going to be deleted"
            ret["result"] = None
            ret["changes"] = {"old": "present", "new": "absent"}
            return ret

        __salt__["kubernetes.delete_configmap"](
            name, namespace, wait=wait, timeout=timeout, **kwargs
        )

        ret["result"] = True
        ret["changes"] = {"old": "present", "new": "absent"}
        ret["comment"] = f"ConfigMap {name} deleted"

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def configmap_present(
    name,
    namespace="default",
    data=None,
    source=None,
    template=None,
    template_context=None,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    Ensures that the named configmap is present inside of the specified namespace
    with the given data.
    If the configmap exists, it will be patched with the desired state.

    name
        The name of the configmap.

    namespace
        The namespace holding the configmap. The 'default' one is going to be
        used unless a different one is specified.

    data
        The dictionary holding the configmaps.

    source
        A file containing the data of the configmap in plain format.

        .. versionchanged:: 2.0.0
            The configmap definition must be a proper spec with the configmap data in
            the ``data`` key. In previous versions, the rendered output was used as the
            data directly.

    template
        Template engine to be used to render the source file.

    template_context
        .. versionadded:: 2.0.0

        Variables to be passed into the template.

    wait
        .. versionadded:: 2.0.0

        If set to True, the function will wait until the configmap is created.

    timeout
        .. versionadded:: 2.0.0

        The time in seconds to wait for the configmap to be created.

    Example:

    .. code-block:: yaml

        my_configmap:
            kubernetes.configmap_present:
                - namespace: default
                - data:
                    key1: value1
                    key2: value2
                    key3: value3
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if data and source:
        return _error(ret, "'source' cannot be used in combination with 'data'")
    elif data is None:
        data = {}

    try:
        configmap = __salt__["kubernetes.show_configmap"](name, namespace, **kwargs)

        if configmap is None:
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = "The configmap is going to be created"
                try:
                    dry_run_result = __salt__["kubernetes.create_configmap"](
                        name=name,
                        namespace=namespace,
                        data=data,
                        source=source,
                        template=template,
                        saltenv=__env__,
                        template_context=template_context,
                        dry_run=True,
                        **kwargs,
                    )
                    ret["changes"] = {"old": {}, "new": dry_run_result}
                except CommandExecutionError as err:
                    ret["result"] = None
                    ret["comment"] = (
                        "The configmap is going to be created. "
                        f"Dry run failed, possibly due to dependencies not created yet: {err}"
                    )
                return ret

            res = __salt__["kubernetes.create_configmap"](
                name=name,
                namespace=namespace,
                data=data,
                source=source,
                template=template,
                saltenv=__env__,
                template_context=template_context,
                wait=wait,
                timeout=timeout,
                **kwargs,
            )
            ret["result"] = True
            ret["changes"] = {"old": {}, "new": res}
            ret["comment"] = "ConfigMap created"
            return ret

        # ConfigMap exists — build the patch object
        if source:
            patch_kwargs = {
                "source": source,
                "template": template,
                "template_context": template_context,
            }
        else:
            patch_obj = {}
            if data:
                patch_obj["data"] = data
            patch_kwargs = {"patch": patch_obj}

        if __opts__["test"]:
            try:
                res = __salt__["kubernetes.patch_configmap"](
                    name,
                    namespace,
                    dry_run=True,
                    **patch_kwargs,
                    **kwargs,
                )
            except CommandExecutionError as err:
                ret["result"] = None
                ret["comment"] = (
                    "The configmap is going to be updated. "
                    f"Dry run failed, possibly due to dependencies not created yet: {err}"
                )
                return ret

            if res == configmap:
                ret["result"] = True
                ret["comment"] = "The configmap is already in the desired state"
                return ret

            ret["result"] = None
            ret["comment"] = "The configmap is going to be updated"
            ret["changes"] = {"old": configmap, "new": res}
            return ret

        res = __salt__["kubernetes.patch_configmap"](
            name,
            namespace,
            wait=wait,
            timeout=timeout,
            **patch_kwargs,
            **kwargs,
        )

        if res == configmap:
            ret["result"] = True
            ret["comment"] = "The configmap is already in the desired state"
            return ret

        ret["changes"] = {"old": configmap, "new": res}
        ret["result"] = True
        ret["comment"] = "ConfigMap updated"

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def pod_absent(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    Ensures that the named pod is absent from the given namespace.

    name
        The name of the pod

    namespace
        The name of the namespace

    wait
        .. versionadded:: 2.0.0

        If set to True, the function will wait until the pod is deleted.

    timeout
        .. versionadded:: 2.0.0

        The time in seconds to wait for the pod to be deleted.

    Example:

    .. code-block:: yaml

        my_pod:
          kubernetes.pod_absent:
            - namespace: default
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    try:
        pod = __salt__["kubernetes.show_pod"](name, namespace, **kwargs)

        if pod is None:
            ret["result"] = True
            ret["comment"] = "The pod does not exist"
            return ret

        if __opts__["test"]:
            ret["comment"] = "The pod is going to be deleted"
            ret["result"] = None
            ret["changes"] = {"old": "present", "new": "absent"}
            return ret

        __salt__["kubernetes.delete_pod"](name, namespace, wait=wait, timeout=timeout, **kwargs)

        ret["result"] = True
        ret["changes"] = {"old": "present", "new": "absent"}
        ret["comment"] = f"Pod {name} deleted"

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def pod_present(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source="",
    template="",
    template_context=None,
    wait=False,
    timeout=60,
    **kwargs,
):
    """
    Ensures that the named pod is present inside of the specified
    namespace with the given metadata and spec.

    .. note::
        Pods are immutable once created. If the pod already exists, this state
        will report success without changes. To update a pod, first remove it
        with ``pod_absent`` and then recreate it. For managed workloads,
        consider using ``deployment_present`` instead.

    name
        The name of the pod.

    namespace
        The namespace holding the pod. The 'default' one is going to be
        used unless a different one is specified.

    metadata
        The metadata of the pod object.

    spec
        The spec of the pod object.

    source
        A file containing the definition of the pod (metadata and
        spec) in the official kubernetes format.

    template
        Template engine to be used to render the source file.

    template_context
        .. versionadded:: 2.0.0

        Variables to be passed into the template.

    wait
        .. versionadded:: 2.0.0

        If set to True, the function will wait until the pod is created.

    timeout
        .. versionadded:: 2.0.0

        The time in seconds to wait for the pod to be created.

    Example:

    .. code-block:: yaml

        my_pod:
          kubernetes.pod_present:
            - namespace: default
            - metadata:
                app: frontend
            - spec:
                containers:
                  - name: my-nginx
                    image: nginx
                    ports:
                      - containerPort: 80
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if (metadata or spec) and source:
        return _error(ret, "'source' cannot be used in combination with 'metadata' or 'spec'")

    if metadata is None:
        metadata = {}

    if spec is None:
        spec = {}

    try:
        pod = __salt__["kubernetes.show_pod"](name, namespace, **kwargs)

        if pod is None:
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = "The pod is going to be created"
                return ret

            res = __salt__["kubernetes.create_pod"](
                name=name,
                namespace=namespace,
                metadata=metadata,
                spec=spec,
                source=source,
                template=template,
                saltenv=__env__,
                template_context=template_context,
                wait=wait,
                timeout=timeout,
                **kwargs,
            )
            ret["result"] = True
            ret["changes"] = {"old": {}, "new": res}
            ret["comment"] = "Pod created"
            return ret

        # Pod already exists — pods are immutable, report as already present
        ret["result"] = True
        ret["comment"] = (
            "The pod already exists. Pods are immutable once created. "
            "To update, remove with pod_absent first, then recreate. "
            "For managed workloads, consider using deployment_present instead."
        )

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def node_label_absent(name, node, **kwargs):
    """
    Ensures that the named label is absent from the node.

    name
        The name of the label

    node
        The name of the node

    Example:

    .. code-block:: yaml

        my_label:
          kubernetes.node_label_absent:
            - node: node_name
    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    try:
        labels = __salt__["kubernetes.node_labels"](node, **kwargs)

        if name not in labels:
            ret["result"] = True
            ret["comment"] = "The label does not exist"
            return ret

        if __opts__["test"]:
            ret["comment"] = "The label is going to be deleted"
            ret["result"] = None
            ret["changes"] = {"old": "present", "new": "absent"}
            return ret

        __salt__["kubernetes.node_remove_label"](node_name=node, label_name=name, **kwargs)

        ret["result"] = True
        ret["changes"] = {"old": "present", "new": "absent"}
        ret["comment"] = "Label removed from node"

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def node_label_folder_absent(name, node, **kwargs):
    """
    Ensures the label folder doesn't exist on the specified node.

    name
        The name of label folder

    node
        The name of the node

    Example:

    .. code-block:: yaml

        my_label_folder:
          kubernetes.node_label_folder_absent:
            - node: node_name
    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    try:
        labels = __salt__["kubernetes.node_labels"](node, **kwargs)

        folder = name.strip("/") + "/"
        labels_to_drop = []
        new_labels = []
        for label in labels:
            if label.startswith(folder):
                labels_to_drop.append(label)
            else:
                new_labels.append(label)

        if not labels_to_drop:
            ret["result"] = True
            ret["comment"] = "The label folder does not exist"
            return ret

        if __opts__["test"]:
            ret["comment"] = "The label folder is going to be deleted"
            ret["result"] = None
            ret["changes"] = {"old": list(labels), "new": new_labels}
            return ret

        for label in labels_to_drop:
            __salt__["kubernetes.node_remove_label"](node_name=node, label_name=label, **kwargs)

        ret["result"] = True
        ret["changes"] = {"old": list(labels), "new": new_labels}
        ret["comment"] = "Label folder removed from node"

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def node_label_present(name, node, value, **kwargs):
    """
    Ensures that the named label is set on the named node
    with the given value.
    If the label exists it will be replaced.

    name
        The name of the label.

    value
        Value of the label.

    node
        Node to change.

    Example:

    .. code-block:: yaml

        my_label:
          kubernetes.node_label_present:
            - node: node_name
            - value: my_value
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    try:
        labels = __salt__["kubernetes.node_labels"](node, **kwargs)

        if name not in labels:
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = "The label is going to be set"
                old_labels = copy.copy(labels)
                new_labels = copy.copy(labels)
                new_labels[name] = value
                ret["changes"] = {"old": old_labels, "new": new_labels}
                return ret

            __salt__["kubernetes.node_add_label"](
                label_name=name, label_value=value, node_name=node, **kwargs
            )

        elif labels[name] == value:
            ret["result"] = True
            ret["comment"] = "The label is already set and has the specified value"
            return ret
        else:
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = "The label is going to be updated"
                old_labels = copy.copy(labels)
                new_labels = copy.copy(labels)
                new_labels[name] = value
                ret["changes"] = {"old": old_labels, "new": new_labels}
                return ret

            ret["comment"] = "The label is already set, changing the value"
            __salt__["kubernetes.node_add_label"](
                node_name=node, label_name=name, label_value=value, **kwargs
            )

        old_labels = copy.copy(labels)
        labels[name] = value

        ret["changes"] = {"old": old_labels, "new": labels}
        ret["result"] = True

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret
