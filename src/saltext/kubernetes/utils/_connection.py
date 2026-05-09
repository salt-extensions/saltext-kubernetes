"""
Internal connection helpers for the saltext-kubernetes extension.

These helpers are extracted from
:py:mod:`saltext.kubernetes.modules.kubernetesmod` to provide a testable
seam for upcoming auth-mode work (in-cluster, bearer token, impersonation,
proxy, etc.). The public Salt-facing API on ``kubernetesmod`` re-exports
these names and preserves its existing signature and return shape for
backwards compatibility.

Direct callers from outside the extension's own internals should not be
relying on this module — use the ``kubernetes`` execution module's
public functions instead.
"""

import base64
import errno
import logging
import os.path
import signal
import tempfile
from contextlib import contextmanager

import salt.utils.platform
from salt.exceptions import CommandExecutionError
from salt.exceptions import TimeoutError  # pylint: disable=redefined-builtin

# pylint: disable=import-error,no-name-in-module
try:
    import kubernetes  # pylint: disable=import-self
    import kubernetes.config

    HAS_LIBS = True
except ImportError:
    HAS_LIBS = False
# pylint: enable=import-error,no-name-in-module

log = logging.getLogger(__name__)

POLLING_TIME_LIMIT = 30


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


def _setup_conn(get_config_option, **kwargs):
    """
    Set up the kubernetes API connection singleton.

    :param get_config_option: a callable that resolves a Salt config / pillar
        key to its value. In the ``kubernetesmod`` path this is
        ``__salt__["config.option"]``. Decoupling from the Salt loader
        allows this helper to be unit-tested without a minion context.
    :param kwargs: ``kubeconfig`` (path), ``kubeconfig_data`` (base64 contents)
        and ``context`` overrides. Behaviour matches the legacy in-line
        implementation.
    :returns: dict ``{"kubeconfig": <path>, "context": <ctx>}`` — the same
        shape ``_cleanup`` expects.
    """
    kubeconfig = kwargs.get("kubeconfig") or get_config_option("kubernetes.kubeconfig")
    kubeconfig_data = kwargs.get("kubeconfig_data") or get_config_option(
        "kubernetes.kubeconfig-data"
    )
    context = kwargs.get("context") or get_config_option("kubernetes.context")

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

    return {"kubeconfig": kubeconfig, "context": context}


def _cleanup(**kwargs):
    """
    Remove a temporary kubeconfig file produced by ``_setup_conn`` from
    inline base64 data. Files not matching the ``salt-kubeconfig-`` prefix
    are left alone (they were user-supplied paths, not Salt-generated).
    """
    if "kubeconfig" in kwargs:
        kubeconfig = kwargs.get("kubeconfig")
        if kubeconfig and os.path.basename(kubeconfig).startswith("salt-kubeconfig-"):
            try:
                os.unlink(kubeconfig)
            except OSError as err:
                if err.errno != errno.ENOENT:
                    log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
