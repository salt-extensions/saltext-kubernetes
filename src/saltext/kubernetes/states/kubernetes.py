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
from salt.utils.dictdiffer import RecursiveDictDiffer

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


def _changes(old, new):
    """
    Return a changes dict using RecursiveDictDiffer for concise reporting.
    """
    try:
        # Salt 3007 and earlier: list_dict_matchers does not exist.
        diff = RecursiveDictDiffer(  # pylint: disable=no-value-for-parameter
            old, new, ignore_missing_keys=False
        )
    except TypeError:
        # Salt 3008+: list_dict_matchers is required.
        diff = RecursiveDictDiffer(old, new, False, [])  # pylint: disable=too-many-function-args
    return {"old": diff.old_values, "new": diff.new_values}


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
            try:
                res = __salt__["kubernetes.create_deployment"](
                    name=name,
                    namespace=namespace,
                    metadata=metadata,
                    spec=spec,
                    source=source,
                    template=template,
                    saltenv=__env__,
                    template_context=template_context,
                    dry_run=bool(__opts__["test"]),
                    wait=wait if not __opts__["test"] else False,
                    timeout=timeout,
                    **kwargs,
                )
            except CommandExecutionError as err:
                if not __opts__["test"]:
                    raise
                ret["result"] = None
                ret["comment"] = (
                    "The deployment is going to be created. "
                    f"Dry run failed, possibly due to dependencies not created yet: {err}"
                )
                return ret

            ret["changes"] = {"old": {}, "new": res}
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = "The deployment is going to be created"
            else:
                ret["result"] = True
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

        try:
            res = __salt__["kubernetes.patch_deployment"](
                name,
                namespace,
                dry_run=bool(__opts__["test"]),
                wait=wait,
                timeout=timeout,
                **patch_kwargs,
                **kwargs,
            )
        except CommandExecutionError as err:
            if not __opts__["test"]:
                raise
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

        ret["changes"] = _changes(deployment, res)
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The deployment is going to be updated"
        else:
            ret["result"] = True
            ret["comment"] = "Deployment updated"

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def statefulset_absent(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    .. versionadded:: 2.1.0

    Ensures that the named statefulset is absent from the given namespace.

    name
        The name of the statefulset

    namespace
        The name of the namespace

    wait
        If set to True, the function will wait until the statefulset is deleted.

    timeout
        The time in seconds to wait for the statefulset to be deleted.

    Example:

    .. code-block:: yaml

        my-statefulset:
          kubernetes.statefulset_absent:
            - namespace: default
    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    try:
        statefulset = __salt__["kubernetes.show_statefulset"](name, namespace, **kwargs)

        if statefulset is None:
            ret["result"] = True
            ret["comment"] = "The statefulset does not exist"
            return ret

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The statefulset is going to be deleted"
            ret["changes"] = {
                "old": "present",
                "new": "absent",
            }
            return ret

        __salt__["kubernetes.delete_statefulset"](
            name, namespace, wait=wait, timeout=timeout, **kwargs
        )

        ret["result"] = True
        ret["changes"] = {"old": "present", "new": "absent"}
        ret["comment"] = f"StatefulSet {name} deleted"

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def statefulset_present(
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
    .. versionadded:: 2.1.0

    Ensures that the named statefulset is present inside of the specified
    namespace with the given metadata and spec.
    If the statefulset exists, it will be patched with the desired state.

    name
        The name of the statefulset.

    namespace
        The namespace holding the statefulset. The 'default' one is going to be
        used unless a different one is specified.

    metadata
        The metadata of the statefulset object.

    spec
        The spec of the statefulset object.

    source
        A file containing the definition of the statefulset (metadata and
        spec) in the official kubernetes format.

    template
        Template engine to be used to render the source file.

    template_context
        Variables to be passed into the template.

    wait
        If set to True, the function will wait until the statefulset is ready.

    timeout
        The time in seconds to wait for the statefulset to be ready.

    Example:

    .. code-block:: yaml

        my-statefulset:
          kubernetes.statefulset_present:
            - namespace: default
            - metadata:
                app: myapp
            - spec:
                serviceName: my-service
                replicas: 3
                selector:
                  matchLabels:
                    app: myapp
                template:
                  metadata:
                    labels:
                      app: myapp
                  spec:
                    containers:
                    - name: myapp
                      image: myapp:latest
                      ports:
                      - containerPort: 8080
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if (metadata or spec) and source:
        return _error(ret, "'source' cannot be used in combination with 'metadata' or 'spec'")

    if metadata is None:
        metadata = {}

    if spec is None:
        spec = {}

    try:
        statefulset = __salt__["kubernetes.show_statefulset"](name, namespace, **kwargs)

        if statefulset is None:
            try:
                res = __salt__["kubernetes.create_statefulset"](
                    name=name,
                    namespace=namespace,
                    metadata=metadata,
                    spec=spec,
                    source=source,
                    template=template,
                    saltenv=__env__,
                    template_context=template_context,
                    dry_run=bool(__opts__["test"]),
                    wait=wait if not __opts__["test"] else False,
                    timeout=timeout,
                    **kwargs,
                )
            except CommandExecutionError as err:
                if not __opts__["test"]:
                    raise
                ret["result"] = None
                ret["comment"] = (
                    "The statefulset is going to be created. "
                    f"Dry run failed, possibly due to dependencies not created yet: {err}"
                )
                return ret

            ret["changes"] = {"old": {}, "new": res}
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = "The statefulset is going to be created"
            else:
                ret["result"] = True
                ret["comment"] = "StatefulSet created"
            return ret

        # StatefulSet exists — build the patch object
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

        try:
            res = __salt__["kubernetes.patch_statefulset"](
                name,
                namespace,
                dry_run=bool(__opts__["test"]),
                wait=wait,
                timeout=timeout,
                **patch_kwargs,
                **kwargs,
            )
        except CommandExecutionError as err:
            if not __opts__["test"]:
                raise
            ret["result"] = None
            ret["comment"] = (
                "The statefulset is going to be updated. "
                f"Dry run failed, possibly due to dependencies not created yet: {err}"
            )
            return ret

        if res == statefulset:
            ret["result"] = True
            ret["comment"] = "The statefulset is already in the desired state"
            return ret

        ret["changes"] = _changes(statefulset, res)
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The statefulset is going to be updated"
        else:
            ret["result"] = True
            ret["comment"] = "StatefulSet updated"

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def replicaset_absent(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    .. versionadded:: 2.1.0

    Ensures that the named replicaset is absent from the given namespace.

    name
        The name of the replicaset

    namespace
        The namespace of the replicaset

    wait
        Wait for replicaset to be deleted (default: False)

    timeout
        Timeout in seconds to wait for replicaset deletion (default: 60)

    CLI Example:

    .. code-block:: yaml

        my-replicaset:
          kubernetes.replicaset_absent:
            namespace: default
    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    try:
        replicaset = __salt__["kubernetes.show_replicaset"](name, namespace, **kwargs)

        if replicaset is None:
            ret["result"] = True
            ret["comment"] = "The replicaset does not exist"
            return ret

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The replicaset is going to be deleted"
            ret["changes"] = {
                "old": "present",
                "new": "absent",
            }
            return ret

        __salt__["kubernetes.delete_replicaset"](
            name, namespace, wait=wait, timeout=timeout, **kwargs
        )

        ret["result"] = True
        ret["changes"] = {"old": "present", "new": "absent"}
        ret["comment"] = f"ReplicaSet {name} deleted"

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def replicaset_present(
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
    .. versionadded:: 2.1.0

    Ensures that the named replicaset is present inside of the specified
    namespace with the given metadata and spec.
    If the replicaset exists, it will be patched with the desired state.

    name
        The name of the replicaset

    namespace
        The namespace of the replicaset

    metadata
        A dictionary representing the metadata of the replicaset

    spec
        A dictionary representing the spec of the replicaset

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

    .. code-block:: yaml

        my-replicaset:
          kubernetes.replicaset_present:
            namespace: default
            metadata:
              labels:
                app: my-app
            spec:
              replicas: 3
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if (metadata or spec) and source:
        return _error(ret, "'source' cannot be used in combination with 'metadata' or 'spec'")

    if metadata is None:
        metadata = {}

    if spec is None:
        spec = {}

    try:
        replicaset = __salt__["kubernetes.show_replicaset"](name, namespace, **kwargs)

        if replicaset is None:
            try:
                res = __salt__["kubernetes.create_replicaset"](
                    name=name,
                    namespace=namespace,
                    metadata=metadata,
                    spec=spec,
                    source=source,
                    template=template,
                    saltenv=__env__,
                    template_context=template_context,
                    dry_run=bool(__opts__["test"]),
                    wait=wait if not __opts__["test"] else False,
                    timeout=timeout,
                    **kwargs,
                )
            except CommandExecutionError as err:
                if not __opts__["test"]:
                    raise
                ret["result"] = None
                ret["comment"] = (
                    "The replicaset is going to be created. "
                    f"Dry run failed, possibly due to dependencies not created yet: {err}"
                )
                return ret

            ret["changes"] = {"old": {}, "new": res}
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = "The replicaset is going to be created"
            else:
                ret["result"] = True
                ret["comment"] = "ReplicaSet created"
            return ret

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

        try:
            res = __salt__["kubernetes.patch_replicaset"](
                name,
                namespace,
                dry_run=bool(__opts__["test"]),
                wait=wait,
                timeout=timeout,
                **patch_kwargs,
                **kwargs,
            )
        except CommandExecutionError as err:
            if not __opts__["test"]:
                raise
            ret["result"] = None
            ret["comment"] = (
                "The replicaset is going to be updated. "
                f"Dry run failed, possibly due to dependencies not created yet: {err}"
            )
            return ret

        if res == replicaset:
            ret["result"] = True
            ret["comment"] = "The replicaset is already in the desired state"
            return ret

        ret["changes"] = _changes(replicaset, res)
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The replicaset is going to be updated"
        else:
            ret["result"] = True
            ret["comment"] = "ReplicaSet updated"

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def daemonset_absent(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    .. versionadded:: 2.1.0

    Ensures that the named daemonset is absent from the given namespace.

    name
        The name of the daemonset

    namespace
        The namespace of the daemonset

    wait
        Wait for daemonset to be deleted (default: False)

    timeout
        Timeout in seconds to wait for daemonset deletion (default: 60)

        CLI Example:

    .. code-block:: yaml

        my-daemonset:
          kubernetes.daemonset_absent:
            namespace: default
    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    try:
        daemonset = __salt__["kubernetes.show_daemonset"](name, namespace, **kwargs)

        if daemonset is None:
            ret["result"] = True
            ret["comment"] = "The daemonset does not exist"
            return ret

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The daemonset is going to be deleted"
            ret["changes"] = {
                "old": "present",
                "new": "absent",
            }
            return ret

        __salt__["kubernetes.delete_daemonset"](
            name, namespace, wait=wait, timeout=timeout, **kwargs
        )

        ret["result"] = True
        ret["changes"] = {"old": "present", "new": "absent"}
        ret["comment"] = f"DaemonSet {name} deleted"

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def daemonset_present(
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
    .. versionadded:: 2.1.0

    Ensures that the named daemonset is present inside of the specified
    namespace with the given metadata and spec.
    If the daemonset exists, it will be patched with the desired state.

    name
        The name of the daemonset

    namespace
        The namespace of the daemonset

    metadata
        Metadata for the daemonset

    spec
        Specification for the daemonset

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

    .. code-block:: yaml

        my-daemonset:
          kubernetes.daemonset_present:
            namespace: default
            metadata:
              labels:
                app: my-daemonset
            spec:
              replicas: 3
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if (metadata or spec) and source:
        return _error(ret, "'source' cannot be used in combination with 'metadata' or 'spec'")

    if metadata is None:
        metadata = {}

    if spec is None:
        spec = {}

    try:
        daemonset = __salt__["kubernetes.show_daemonset"](name, namespace, **kwargs)

        if daemonset is None:
            try:
                res = __salt__["kubernetes.create_daemonset"](
                    name=name,
                    namespace=namespace,
                    metadata=metadata,
                    spec=spec,
                    source=source,
                    template=template,
                    saltenv=__env__,
                    template_context=template_context,
                    dry_run=bool(__opts__["test"]),
                    wait=wait if not __opts__["test"] else False,
                    timeout=timeout,
                    **kwargs,
                )
            except CommandExecutionError as err:
                if not __opts__["test"]:
                    raise
                ret["result"] = None
                ret["comment"] = (
                    "The daemonset is going to be created. "
                    f"Dry run failed, possibly due to dependencies not created yet: {err}"
                )
                return ret

            ret["changes"] = {"old": {}, "new": res}
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = "The daemonset is going to be created"
            else:
                ret["result"] = True
                ret["comment"] = "DaemonSet created"
            return ret

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

        try:
            res = __salt__["kubernetes.patch_daemonset"](
                name,
                namespace,
                dry_run=bool(__opts__["test"]),
                wait=wait,
                timeout=timeout,
                **patch_kwargs,
                **kwargs,
            )
        except CommandExecutionError as err:
            if not __opts__["test"]:
                raise
            ret["result"] = None
            ret["comment"] = (
                "The daemonset is going to be updated. "
                f"Dry run failed, possibly due to dependencies not created yet: {err}"
            )
            return ret

        if res == daemonset:
            ret["result"] = True
            ret["comment"] = "The daemonset is already in the desired state"
            return ret

        ret["changes"] = _changes(daemonset, res)
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The daemonset is going to be updated"
        else:
            ret["result"] = True
            ret["comment"] = "DaemonSet updated"

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def storageclass_absent(name, wait=False, timeout=60, **kwargs):
    """
    .. versionadded:: 2.1.0

    Ensures that the named storageclass is absent.

    name
        The name of the storageclass

    wait
        Wait for storageclass to be deleted (default: False)

    timeout
        Timeout in seconds to wait for storageclass deletion (default: 60)

    CLI Example:

    .. code-block:: yaml

        my-storageclass:
          kubernetes.storageclass_absent:
    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    try:
        storageclass = __salt__["kubernetes.show_storageclass"](name, **kwargs)

        if storageclass is None:
            ret["result"] = True
            ret["comment"] = "The storageclass does not exist"
            return ret

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The storageclass is going to be deleted"
            ret["changes"] = {
                "old": "present",
                "new": "absent",
            }
            return ret

        __salt__["kubernetes.delete_storageclass"](name, wait=wait, timeout=timeout, **kwargs)

        ret["result"] = True
        ret["changes"] = {"old": "present", "new": "absent"}
        ret["comment"] = f"StorageClass {name} deleted"

    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def storageclass_present(
    name,
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
    .. versionadded:: 2.1.0

    Ensures that the named storageclass is present with the given metadata and spec.
    If the storageclass exists, it will be patched with the desired state.

    name
        The name of the storageclass

    metadata
        Metadata for the storageclass

    spec
        Specification for the storageclass

    source
        File path to storageclass definition

    template
        Template engine to use to render the source file

    template_context
        Variables to make available in templated files

    wait
        Wait for storageclass to become ready (default: False)

    timeout
        Timeout in seconds to wait for storageclass (default: 60)

    CLI Example:

    .. code-block:: yaml

        my-storageclass:
          kubernetes.storageclass_present:
            metadata:
              labels:
                app: my-storageclass
            spec:
              provisioner: kubernetes.io/no-provisioner
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if (metadata or spec) and source:
        return _error(ret, "'source' cannot be used in combination with 'metadata' or 'spec'")

    if not source and metadata is None:
        metadata = {}

    if not source and spec is None:
        spec = {}

    try:
        storageclass = __salt__["kubernetes.show_storageclass"](name, **kwargs)

        if storageclass is None:
            try:
                res = __salt__["kubernetes.create_storageclass"](
                    name=name,
                    metadata=metadata,
                    spec=spec,
                    source=source,
                    template=template,
                    saltenv=__env__,
                    template_context=template_context,
                    dry_run=bool(__opts__["test"]),
                    wait=wait if not __opts__["test"] else False,
                    timeout=timeout,
                    **kwargs,
                )
            except CommandExecutionError as err:
                if not __opts__["test"]:
                    raise
                ret["result"] = None
                ret["comment"] = (
                    "The storageclass is going to be created. "
                    f"Dry run failed, possibly due to dependencies not created yet: {err}"
                )
                return ret

            ret["changes"] = {"old": {}, "new": res}
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = "The storageclass is going to be created"
            else:
                ret["result"] = True
                ret["comment"] = "StorageClass created"
            return ret

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

        try:
            res = __salt__["kubernetes.patch_storageclass"](
                name,
                dry_run=bool(__opts__["test"]),
                wait=wait,
                timeout=timeout,
                **patch_kwargs,
                **kwargs,
            )
        except CommandExecutionError as err:
            if not __opts__["test"]:
                raise
            ret["result"] = None
            ret["comment"] = (
                "The storageclass is going to be updated. "
                f"Dry run failed, possibly due to dependencies not created yet: {err}"
            )
            return ret

        if res == storageclass:
            ret["result"] = True
            ret["comment"] = "The storageclass is already in the desired state"
            return ret

        ret["changes"] = _changes(storageclass, res)
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The storageclass is going to be updated"
        else:
            ret["result"] = True
            ret["comment"] = "StorageClass updated"

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
            try:
                res = __salt__["kubernetes.create_service"](
                    name=name,
                    namespace=namespace,
                    metadata=metadata,
                    spec=spec,
                    source=source,
                    template=template,
                    saltenv=__env__,
                    template_context=template_context,
                    dry_run=bool(__opts__["test"]),
                    wait=wait if not __opts__["test"] else False,
                    timeout=timeout,
                    **kwargs,
                )
            except CommandExecutionError as err:
                if not __opts__["test"]:
                    raise
                ret["result"] = None
                ret["comment"] = (
                    "The service is going to be created. "
                    f"Dry run failed, possibly due to dependencies not created yet: {err}"
                )
                return ret

            ret["changes"] = {"old": {}, "new": res}
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = "The service is going to be created"
            else:
                ret["result"] = True
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

        try:
            res = __salt__["kubernetes.patch_service"](
                name,
                namespace,
                dry_run=bool(__opts__["test"]),
                wait=wait,
                timeout=timeout,
                **patch_kwargs,
                **kwargs,
            )
        except CommandExecutionError as err:
            if not __opts__["test"]:
                raise
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

        ret["changes"] = _changes(service, res)
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The service is going to be updated"
        else:
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

            try:
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
                    dry_run=bool(__opts__["test"]),
                    wait=wait if not __opts__["test"] else False,
                    timeout=timeout,
                    **kwargs,
                )
            except CommandExecutionError as err:
                if not __opts__["test"]:
                    raise
                ret["result"] = None
                ret["comment"] = (
                    "The secret is going to be created. "
                    f"Dry run failed, possibly due to dependencies not created yet: {err}"
                )
                return ret

            ret["changes"] = {
                "old": {},
                "new": {"data": list(res.get("data") or [])},
            }
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = "The secret is going to be created"
            else:
                ret["result"] = True
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

        try:
            res = __salt__["kubernetes.patch_secret"](
                name,
                namespace,
                dry_run=bool(__opts__["test"]),
                wait=wait,
                timeout=timeout,
                **patch_kwargs,
                **kwargs,
            )
        except CommandExecutionError as err:
            if not __opts__["test"]:
                raise
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

        ret["changes"] = {
            "old": {"data": list(secret.get("data") or [])},
            "new": {"data": list(res.get("data") or [])},
        }
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The secret is going to be updated"
        else:
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
            try:
                res = __salt__["kubernetes.create_configmap"](
                    name=name,
                    namespace=namespace,
                    data=data,
                    source=source,
                    template=template,
                    saltenv=__env__,
                    template_context=template_context,
                    dry_run=bool(__opts__["test"]),
                    wait=wait if not __opts__["test"] else False,
                    timeout=timeout,
                    **kwargs,
                )
            except CommandExecutionError as err:
                if not __opts__["test"]:
                    raise
                ret["result"] = None
                ret["comment"] = (
                    "The configmap is going to be created. "
                    f"Dry run failed, possibly due to dependencies not created yet: {err}"
                )
                return ret

            ret["changes"] = {"old": {}, "new": res}
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = "The configmap is going to be created"
            else:
                ret["result"] = True
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

        try:
            res = __salt__["kubernetes.patch_configmap"](
                name,
                namespace,
                dry_run=bool(__opts__["test"]),
                wait=wait,
                timeout=timeout,
                **patch_kwargs,
                **kwargs,
            )
        except CommandExecutionError as err:
            if not __opts__["test"]:
                raise
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

        ret["changes"] = _changes(configmap, res)
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The configmap is going to be updated"
        else:
            ret["result"] = True
            ret["comment"] = "ConfigMap updated"

    except CommandExecutionError as err:
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


# ---------------------------------------------------------------------------
# RBAC states: Role, RoleBinding, ClusterRole, ClusterRoleBinding,
# ServiceAccount.
#
# .. versionadded:: 2.1.0
#
# All five kinds share a near-identical present/absent pattern, so the
# bulk of the logic lives in :py:func:`_rbac_absent_impl` and
# :py:func:`_rbac_present_impl` — the public ``*_present`` / ``*_absent``
# states are thin per-kind wrappers around those helpers.
# ---------------------------------------------------------------------------


def _rbac_absent_impl(name, kind_lower, kind_pretty, namespaced, namespace, wait, timeout, kwargs):
    """Shared body for the RBAC *_absent state functions."""
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    show_fn = __salt__[f"kubernetes.show_{kind_lower}"]
    delete_fn = __salt__[f"kubernetes.delete_{kind_lower}"]

    show_args = (name, namespace) if namespaced else (name,)
    delete_args = {"wait": wait, "timeout": timeout}
    if namespaced:
        delete_args["namespace"] = namespace

    try:
        existing = show_fn(*show_args, **kwargs)
        if existing is None:
            ret["result"] = True
            ret["comment"] = f"The {kind_pretty} does not exist"
            return ret
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"The {kind_pretty} is going to be deleted"
            ret["changes"] = {"old": "present", "new": "absent"}
            return ret
        delete_fn(name, **delete_args, **kwargs)
        ret["result"] = True
        ret["changes"] = {"old": "present", "new": "absent"}
        ret["comment"] = f"{kind_pretty} {name} deleted"
    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}
    return ret


def _rbac_present_impl(
    name,
    kind_lower,
    kind_pretty,
    namespaced,
    namespace,
    metadata,
    spec,
    source,
    template,
    template_context,
    kwargs,
):
    """Shared body for the RBAC *_present state functions."""
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if (metadata or spec) and source:
        return _error(ret, "'source' cannot be used in combination with 'metadata' or 'spec'")
    if not source and metadata is None:
        metadata = {}
    if not source and spec is None:
        spec = {}

    show_fn = __salt__[f"kubernetes.show_{kind_lower}"]
    create_fn = __salt__[f"kubernetes.create_{kind_lower}"]
    patch_fn = __salt__[f"kubernetes.patch_{kind_lower}"]

    show_args = (name, namespace) if namespaced else (name,)

    create_kwargs = {
        "name": name,
        "metadata": metadata,
        "spec": spec,
        "source": source,
        "template": template,
        "saltenv": __env__,
        "template_context": template_context,
        "dry_run": bool(__opts__["test"]),
    }
    patch_kwargs = {"name": name, "dry_run": bool(__opts__["test"])}
    if namespaced:
        create_kwargs["namespace"] = namespace
        patch_kwargs["namespace"] = namespace

    try:
        existing = show_fn(*show_args, **kwargs)

        if existing is None:
            try:
                res = create_fn(**create_kwargs, **kwargs)
            except CommandExecutionError as err:
                if not __opts__["test"]:
                    raise
                ret["result"] = None
                ret["comment"] = (
                    f"The {kind_pretty} is going to be created. "
                    f"Dry run failed, possibly due to dependencies not created yet: {err}"
                )
                return ret
            ret["changes"] = {"old": {}, "new": res}
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = f"The {kind_pretty} is going to be created"
            else:
                ret["result"] = True
                ret["comment"] = f"{kind_pretty} created"
            return ret

        if source:
            patch_kwargs.update(
                {"source": source, "template": template, "template_context": template_context}
            )
        else:
            patch_obj = {}
            if metadata:
                patch_obj["metadata"] = metadata
            if spec:
                patch_obj["spec"] = spec
            patch_kwargs["patch"] = patch_obj

        try:
            res = patch_fn(**patch_kwargs, **kwargs)
        except CommandExecutionError as err:
            if not __opts__["test"]:
                raise
            ret["result"] = None
            ret["comment"] = (
                f"The {kind_pretty} is going to be updated. "
                f"Dry run failed, possibly due to dependencies not created yet: {err}"
            )
            return ret

        if res == existing:
            ret["result"] = True
            ret["comment"] = f"The {kind_pretty} is already in the desired state"
            return ret

        ret["changes"] = _changes(existing, res)
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"The {kind_pretty} is going to be updated"
        else:
            ret["result"] = True
            ret["comment"] = f"{kind_pretty} updated"
    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}
    return ret


def role_absent(name, namespace="default", wait=False, timeout=60, **kwargs):
    """
    Ensure the named Role is absent from *namespace*.

    .. versionadded:: 2.1.0

    .. code-block:: yaml

        pod-reader:
          kubernetes.role_absent:
            - namespace: default
    """
    return _rbac_absent_impl(name, "role", "Role", True, namespace, wait, timeout, kwargs)


def role_present(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source="",
    template="",
    template_context=None,
    **kwargs,
):
    """
    Ensure the named Role is present with the given rules.

    .. versionadded:: 2.1.0

    .. code-block:: yaml

        pod-reader:
          kubernetes.role_present:
            - namespace: default
            - spec:
                rules:
                  - apiGroups: [""]
                    resources: ["pods"]
                    verbs: ["get", "list", "watch"]
    """
    return _rbac_present_impl(
        name,
        "role",
        "Role",
        True,
        namespace,
        metadata,
        spec,
        source,
        template,
        template_context,
        kwargs,
    )


def role_binding_absent(name, namespace="default", wait=False, timeout=60, **kwargs):
    """Ensure the named RoleBinding is absent from *namespace*. .. versionadded:: 2.1.0"""
    return _rbac_absent_impl(
        name, "role_binding", "RoleBinding", True, namespace, wait, timeout, kwargs
    )


def role_binding_present(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source="",
    template="",
    template_context=None,
    **kwargs,
):
    """
    Ensure the named RoleBinding exists with the given subjects + roleRef.

    .. versionadded:: 2.1.0

    .. note::
        ``roleRef`` is immutable. To change the referenced Role, declare
        ``role_binding_absent`` first and then ``role_binding_present`` with
        the new ``roleRef`` — patching ``roleRef`` will be rejected by the API.

    .. code-block:: yaml

        read-pods:
          kubernetes.role_binding_present:
            - namespace: default
            - spec:
                subjects:
                  - kind: User
                    name: alice
                    apiGroup: rbac.authorization.k8s.io
                roleRef:
                  kind: Role
                  name: pod-reader
                  apiGroup: rbac.authorization.k8s.io
    """
    return _rbac_present_impl(
        name,
        "role_binding",
        "RoleBinding",
        True,
        namespace,
        metadata,
        spec,
        source,
        template,
        template_context,
        kwargs,
    )


def cluster_role_absent(name, wait=False, timeout=60, **kwargs):
    """Ensure the named ClusterRole is absent. .. versionadded:: 2.1.0"""
    return _rbac_absent_impl(
        name, "cluster_role", "ClusterRole", False, None, wait, timeout, kwargs
    )


def cluster_role_present(
    name,
    metadata=None,
    spec=None,
    source="",
    template="",
    template_context=None,
    **kwargs,
):
    """
    Ensure the named ClusterRole is present with the given rules.

    .. versionadded:: 2.1.0

    .. code-block:: yaml

        pod-reader:
          kubernetes.cluster_role_present:
            - spec:
                rules:
                  - apiGroups: [""]
                    resources: ["pods"]
                    verbs: ["get", "list", "watch"]
    """
    return _rbac_present_impl(
        name,
        "cluster_role",
        "ClusterRole",
        False,
        None,
        metadata,
        spec,
        source,
        template,
        template_context,
        kwargs,
    )


def cluster_role_binding_absent(name, wait=False, timeout=60, **kwargs):
    """Ensure the named ClusterRoleBinding is absent. .. versionadded:: 2.1.0"""
    return _rbac_absent_impl(
        name, "cluster_role_binding", "ClusterRoleBinding", False, None, wait, timeout, kwargs
    )


def cluster_role_binding_present(
    name,
    metadata=None,
    spec=None,
    source="",
    template="",
    template_context=None,
    **kwargs,
):
    """
    Ensure the named ClusterRoleBinding is present.

    .. versionadded:: 2.1.0

    .. note::
        ``roleRef`` is immutable; see :py:func:`role_binding_present`.
    """
    return _rbac_present_impl(
        name,
        "cluster_role_binding",
        "ClusterRoleBinding",
        False,
        None,
        metadata,
        spec,
        source,
        template,
        template_context,
        kwargs,
    )


def service_account_absent(name, namespace="default", wait=False, timeout=60, **kwargs):
    """Ensure the named ServiceAccount is absent from *namespace*. .. versionadded:: 2.1.0"""
    return _rbac_absent_impl(
        name, "service_account", "ServiceAccount", True, namespace, wait, timeout, kwargs
    )


def service_account_present(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source="",
    template="",
    template_context=None,
    **kwargs,
):
    """
    Ensure the named ServiceAccount is present in *namespace*.

    .. versionadded:: 2.1.0

    .. code-block:: yaml

        my-sa:
          kubernetes.service_account_present:
            - namespace: default
            - spec:
                automount_service_account_token: false
                image_pull_secrets:
                  - name: my-registry-secret
    """
    return _rbac_present_impl(
        name,
        "service_account",
        "ServiceAccount",
        True,
        namespace,
        metadata,
        spec,
        source,
        template,
        template_context,
        kwargs,
    )


# ---------------------------------------------------------------------------
# Node lifecycle states (cordon, uncordon, taint, untaint).
#
# Drain is intentionally NOT exposed as a state: it's an imperative
# operation that depends on cluster runtime state (which pods are where)
# rather than a desired-state declaration. Use ``kubernetes.drain`` from
# an execution call.
#
# .. versionadded:: 2.1.0
# ---------------------------------------------------------------------------


def node_cordoned(name, **kwargs):
    """
    Ensure the named node is cordoned (unschedulable).

    .. versionadded:: 2.1.0

    .. code-block:: yaml

        my-node:
          kubernetes.node_cordoned: []
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}
    try:
        node = __salt__["kubernetes.node"](name, **kwargs)
        if node is None:
            return _error(ret, f"Node {name} not found")
        currently_unschedulable = bool((node.get("spec") or {}).get("unschedulable", False))
        if currently_unschedulable:
            ret["result"] = True
            ret["comment"] = "Node is already cordoned"
            return ret
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "Node would be cordoned"
            ret["changes"] = {"old": "schedulable", "new": "cordoned"}
            return ret
        __salt__["kubernetes.cordon"](name, **kwargs)
        ret["result"] = True
        ret["comment"] = f"Node {name} cordoned"
        ret["changes"] = {"old": "schedulable", "new": "cordoned"}
    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
    return ret


def node_uncordoned(name, **kwargs):
    """
    Ensure the named node is uncordoned (schedulable).

    .. versionadded:: 2.1.0
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}
    try:
        node = __salt__["kubernetes.node"](name, **kwargs)
        if node is None:
            return _error(ret, f"Node {name} not found")
        currently_unschedulable = bool((node.get("spec") or {}).get("unschedulable", False))
        if not currently_unschedulable:
            ret["result"] = True
            ret["comment"] = "Node is already schedulable"
            return ret
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "Node would be uncordoned"
            ret["changes"] = {"old": "cordoned", "new": "schedulable"}
            return ret
        __salt__["kubernetes.uncordon"](name, **kwargs)
        ret["result"] = True
        ret["comment"] = f"Node {name} uncordoned"
        ret["changes"] = {"old": "cordoned", "new": "schedulable"}
    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
    return ret


def node_tainted(name, key, effect, value=None, **kwargs):
    """
    Ensure the named node has the given taint.

    .. versionadded:: 2.1.0

    .. note::
        State name (``name``) is the node name. ``key`` and ``effect``
        identify the taint within the node's taint list (matching the
        Kubernetes taint identity rule of (key, effect) uniqueness).

    .. code-block:: yaml

        gpu-node:
          kubernetes.node_tainted:
            - key: gpu
            - effect: NoSchedule
            - value: "true"
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}
    try:
        node = __salt__["kubernetes.node"](name, **kwargs)
        if node is None:
            return _error(ret, f"Node {name} not found")
        existing = (node.get("spec") or {}).get("taints") or []
        match = next(
            (t for t in existing if t.get("key") == key and t.get("effect") == effect),
            None,
        )
        if match is not None and match.get("value") == value:
            ret["result"] = True
            ret["comment"] = f"Taint {key}={value}:{effect} already present"
            return ret
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"Taint {key}={value}:{effect} would be applied"
            ret["changes"] = {"old": match, "new": {"key": key, "value": value, "effect": effect}}
            return ret
        __salt__["kubernetes.taint"](name, key=key, effect=effect, value=value, **kwargs)
        ret["result"] = True
        ret["comment"] = f"Taint {key}={value}:{effect} applied"
        ret["changes"] = {"old": match, "new": {"key": key, "value": value, "effect": effect}}
    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
    return ret


def node_untainted(name, key, effect=None, **kwargs):
    """
    Ensure the named node does not carry a taint with the given *key*.

    .. versionadded:: 2.1.0

    If *effect* is given, only the taint with matching ``(key, effect)``
    is removed; otherwise every taint with this key is removed.
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}
    try:
        node = __salt__["kubernetes.node"](name, **kwargs)
        if node is None:
            return _error(ret, f"Node {name} not found")
        existing = (node.get("spec") or {}).get("taints") or []
        if effect is None:
            matches = [t for t in existing if t.get("key") == key]
        else:
            matches = [t for t in existing if t.get("key") == key and t.get("effect") == effect]
        if not matches:
            ret["result"] = True
            ret["comment"] = f"No taint with key '{key}' present"
            return ret
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"{len(matches)} taint(s) with key '{key}' would be removed"
            ret["changes"] = {"old": matches, "new": []}
            return ret
        __salt__["kubernetes.untaint"](name, key=key, effect=effect, **kwargs)
        ret["result"] = True
        ret["comment"] = f"Removed {len(matches)} taint(s) with key '{key}'"
        ret["changes"] = {"old": matches, "new": []}
    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
    return ret


# ---------------------------------------------------------------------------
# Generic manifest states (manifest_present, manifest_absent).
#
# These wrap kubernetes.apply / kubernetes.delete_manifest and provide
# the desired-state semantics Salt callers expect: idempotent reapply
# of the same manifest is a no-op; ``test=True`` produces a dry-run
# preview via the API server's own validation.
#
# .. versionadded:: 2.1.0
# ---------------------------------------------------------------------------


def manifest_present(
    name,
    source=None,
    manifest=None,
    namespace=None,
    field_manager="salt",
    force_conflicts=False,
    template=None,
    template_context=None,
    **kwargs,
):
    """
    Ensure one or more Kubernetes objects described by a manifest are
    present, using server-side apply.

    .. versionadded:: 2.1.0

    The manifest may be a Python dict, a list of dicts, a YAML string,
    or — via ``source`` — a salt:// fileserver path. Multi-document
    YAML files are supported; every document in the file is applied as
    a single state operation.

    name
        The state ID. Used as the ``name`` field of the result; not
        sent to the API. Use whatever identifies the SLS rule for you.

    source
        Salt fileserver path to a YAML manifest. Mutually exclusive
        with ``manifest``.

    manifest
        Inline manifest (dict, list of dicts, or YAML string). Mutually
        exclusive with ``source``.

    namespace
        Fallback namespace for namespaced manifests that don't declare
        their own ``metadata.namespace``. Cluster-scoped kinds ignore.

    field_manager
        SSA fieldManager. Default: ``"salt"``.

    force_conflicts
        Override fields owned by another field manager. Default: off.

    template
        Source-file template engine (e.g. ``"jinja"``).

    template_context
        Variables passed to the renderer.

    .. code-block:: yaml

        my-app-stack:
          kubernetes.manifest_present:
            - source: salt://manifests/my-app.yaml
            - namespace: production
            - template: jinja

        # Or inline:
        my-config:
          kubernetes.manifest_present:
            - manifest:
                apiVersion: v1
                kind: ConfigMap
                metadata:
                  name: app-config
                  namespace: default
                data:
                  greeting: hello
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if source and manifest is not None:
        return _error(ret, "'source' and 'manifest' are mutually exclusive")
    if not source and manifest is None:
        return _error(ret, "Provide either 'source' or 'manifest'")

    apply_kwargs = {
        "manifest": manifest,
        "source": source,
        "namespace": namespace,
        "field_manager": field_manager,
        "force_conflicts": force_conflicts,
        "template": template,
        "saltenv": __env__,
        "template_context": template_context,
    }

    try:
        if __opts__["test"]:
            res = __salt__["kubernetes.apply"](dry_run=True, **apply_kwargs, **kwargs)
            ret["result"] = None
            ret["comment"] = "Manifests would be applied (server-side dry run)"
            ret["changes"] = {"applied": res}
            return ret

        res = __salt__["kubernetes.apply"](**apply_kwargs, **kwargs)
        ret["result"] = True
        ret["comment"] = "Manifests applied via server-side apply"
        ret["changes"] = {"applied": res}
    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}
    return ret


def manifest_absent(
    name,
    source=None,
    manifest=None,
    namespace=None,
    propagation_policy=None,
    grace_period_seconds=None,
    template=None,
    template_context=None,
    **kwargs,
):
    """
    Ensure one or more Kubernetes objects described by a manifest are
    absent.

    .. versionadded:: 2.1.0

    Accepts the same manifest / source shapes as :py:func:`manifest_present`.

    .. code-block:: yaml

        my-app-stack:
          kubernetes.manifest_absent:
            - source: salt://manifests/my-app.yaml
            - propagation_policy: Foreground
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if source and manifest is not None:
        return _error(ret, "'source' and 'manifest' are mutually exclusive")
    if not source and manifest is None:
        return _error(ret, "Provide either 'source' or 'manifest'")

    delete_kwargs = {
        "manifest": manifest,
        "source": source,
        "namespace": namespace,
        "propagation_policy": propagation_policy,
        "grace_period_seconds": grace_period_seconds,
        "template": template,
        "saltenv": __env__,
        "template_context": template_context,
    }

    try:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "Manifests would be deleted"
            ret["changes"] = {"old": "present", "new": "absent"}
            return ret

        res = __salt__["kubernetes.delete_manifest"](**delete_kwargs, **kwargs)
        ret["result"] = True
        ret["comment"] = "Manifests deleted"
        ret["changes"] = {"deleted": res}
    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}
    return ret


# ---------------------------------------------------------------------------
# Batch states (job, cron_job)
#
# Reuses the RBAC present/absent helpers — same pattern: show, create-if-
# absent, patch otherwise; delete on absent. Both kinds are namespaced.
#
# .. versionadded:: 2.1.0
# ---------------------------------------------------------------------------


def job_absent(name, namespace="default", wait=False, timeout=60, **kwargs):
    """Ensure the named Job is absent. .. versionadded:: 2.1.0"""
    return _rbac_absent_impl(name, "job", "Job", True, namespace, wait, timeout, kwargs)


def job_present(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source="",
    template="",
    template_context=None,
    **kwargs,
):
    """
    Ensure the named Job exists with the given pod template.

    .. versionadded:: 2.1.0

    .. note::
        Job ``selector`` and most of ``spec.template`` are immutable
        after creation; if your manifest changes them, the patch will
        be rejected. For mutable changes (labels, ttlSecondsAfterFinished),
        the state behaves normally.

    .. code-block:: yaml

        my-job:
          kubernetes.job_present:
            - namespace: default
            - spec:
                template:
                  spec:
                    restartPolicy: Never
                    containers:
                      - name: hello
                        image: busybox
                        command: ["echo", "hi"]
    """
    return _rbac_present_impl(
        name,
        "job",
        "Job",
        True,
        namespace,
        metadata,
        spec,
        source,
        template,
        template_context,
        kwargs,
    )


def cron_job_absent(name, namespace="default", wait=False, timeout=60, **kwargs):
    """Ensure the named CronJob is absent. .. versionadded:: 2.1.0"""
    return _rbac_absent_impl(name, "cron_job", "CronJob", True, namespace, wait, timeout, kwargs)


def cron_job_present(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source="",
    template="",
    template_context=None,
    **kwargs,
):
    """
    Ensure the named CronJob exists.

    .. versionadded:: 2.1.0

    .. code-block:: yaml

        my-cron:
          kubernetes.cron_job_present:
            - namespace: default
            - spec:
                schedule: "*/5 * * * *"
                concurrencyPolicy: Forbid
                jobTemplate:
                  spec:
                    template:
                      spec:
                        restartPolicy: OnFailure
                        containers:
                          - name: tick
                            image: busybox
                            command: ["echo", "tick"]
    """
    return _rbac_present_impl(
        name,
        "cron_job",
        "CronJob",
        True,
        namespace,
        metadata,
        spec,
        source,
        template,
        template_context,
        kwargs,
    )
