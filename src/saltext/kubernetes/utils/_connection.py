"""
Internal connection helpers for the saltext-kubernetes extension.

This module owns the auth-resolution logic for the extension. The
publicly-exposed seam is :py:func:`_setup_conn`, which is re-exported
through :py:mod:`saltext.kubernetes.modules.kubernetesmod` for
backwards compatibility — its signature, kwargs handling, and
``{"kubeconfig": ..., "context": ...}`` return shape on the kubeconfig
paths are preserved.

Auth precedence (first non-empty wins):
    1. ``kubeconfig`` file path
    2. ``kubeconfig`` inline base64 data
    3. ``host`` + (``api_key`` | ``username`` / ``password`` |
       ``client_cert`` / ``client_key``)
    4. In-cluster ServiceAccount

Within each path, individual values resolve in this order:

    explicit kwarg  >  env var  >  pillar / minion config

The env-var names match the ``K8S_AUTH_*`` convention popularised by
Ansible's ``kubernetes.core`` collection, so users with multi-tool
setups can share a single set of credentials.

Direct callers from outside the extension's own internals should not
be relying on this module — use the ``kubernetes`` execution module's
public functions instead.

.. note::

    Header-based features (HTTP impersonation, custom default headers)
    are deliberately not handled here. They require injection at the
    ``ApiClient`` layer, which the current call-site pattern
    (``kubernetes.client.CoreV1Api()`` with no explicit client)
    bypasses. A follow-up PR will route API instances through a shared
    factory and add impersonation on top.
"""

import base64
import errno
import logging
import os
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
    import kubernetes.client
    import kubernetes.config

    HAS_LIBS = True
except ImportError:
    HAS_LIBS = False
# pylint: enable=import-error,no-name-in-module

log = logging.getLogger(__name__)

POLLING_TIME_LIMIT = 30


# Maps a Salt config key to the env-var fallbacks for that value.
# The order within each list is the precedence (first hit wins).
# The first entry uses the kubernetes-client native ``KUBE_CONFIG_PATH``
# convention; subsequent entries match Ansible ``kubernetes.core``'s
# ``K8S_AUTH_*`` convention.
_ENV_VAR_MAP = {
    "kubernetes.kubeconfig": ["KUBE_CONFIG_PATH", "KUBECONFIG", "K8S_AUTH_KUBECONFIG"],
    "kubernetes.context": ["KUBE_CTX", "K8S_AUTH_CONTEXT"],
    "kubernetes.host": ["K8S_AUTH_HOST"],
    "kubernetes.api_key": ["K8S_AUTH_API_KEY"],
    "kubernetes.api_key_prefix": ["K8S_AUTH_API_KEY_PREFIX"],
    "kubernetes.username": ["K8S_AUTH_USERNAME"],
    "kubernetes.password": ["K8S_AUTH_PASSWORD"],
    "kubernetes.client_cert": ["K8S_AUTH_CERT_FILE"],
    "kubernetes.client_key": ["K8S_AUTH_KEY_FILE"],
    "kubernetes.ca_cert": ["K8S_AUTH_SSL_CA_CERT"],
    "kubernetes.verify_ssl": ["K8S_AUTH_VERIFY_SSL"],
    "kubernetes.proxy": ["K8S_AUTH_PROXY"],
    "kubernetes.no_proxy": ["K8S_AUTH_NO_PROXY"],
    "kubernetes.in_cluster": ["K8S_AUTH_IN_CLUSTER"],
    "kubernetes.persist_config": ["K8S_AUTH_PERSIST_CONFIG"],
}


# Map a Salt config key to the kwarg name that overrides it.
# Most cases follow the trivial "drop the kubernetes. prefix" pattern;
# this dict only lists the exceptions.
_KWARG_OVERRIDES = {
    "kubernetes.kubeconfig-data": "kubeconfig_data",
}


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


def _kwarg_name(key):
    """Resolve which kwarg name overrides a given pillar key."""
    if key in _KWARG_OVERRIDES:
        return _KWARG_OVERRIDES[key]
    return key.split(".", 1)[1]


def _get(key, kwargs, get_config_option, env):
    """
    Resolve a single value via precedence: kwargs > env > pillar.

    Returns ``None`` if no source supplied a non-empty value.
    """
    kwarg_key = _kwarg_name(key)
    if kwargs.get(kwarg_key) is not None:
        return kwargs[kwarg_key]
    for ev in _ENV_VAR_MAP.get(key, []):
        val = env.get(ev)
        if val:
            return val
    return get_config_option(key)


def _coerce_bool(value):
    """Tolerant truthiness for env-var/pillar bool-likes; None means unset."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    return None


def _looks_in_cluster(env):
    """Heuristic match for running inside a Kubernetes pod."""
    return "KUBERNETES_SERVICE_HOST" in env and "KUBERNETES_SERVICE_PORT" in env


def _setup_conn(get_config_option, env=None, **kwargs):
    """
    Set up the kubernetes API connection and install it as the default.

    See module docstring for the full precedence and supported auth modes.
    Existing callers passing only ``kubeconfig`` / ``kubeconfig_data`` /
    ``context`` get the legacy behaviour and the legacy return shape
    ``{"kubeconfig": <path>, "context": <ctx>}``.

    :param get_config_option: callable resolving Salt config / pillar keys.
    :param env: optional env-like mapping (defaults to ``os.environ``);
        injection point for tests.
    :returns: a marker dict whose contents depend on the resolved mode;
        the only stable contract is that ``_cleanup(**result)`` is safe.
    """
    return _resolve_auth(get_config_option, env=env, **kwargs)


def _resolve_auth(get_config_option, env=None, **kwargs):
    env = env if env is not None else os.environ

    kubeconfig = _get("kubernetes.kubeconfig", kwargs, get_config_option, env)
    if kubeconfig:
        return _resolve_kubeconfig_file(kubeconfig, get_config_option, env, kwargs)

    kubeconfig_data = _get("kubernetes.kubeconfig-data", kwargs, get_config_option, env)
    if kubeconfig_data:
        return _resolve_kubeconfig_data(kubeconfig_data, get_config_option, env, kwargs)

    host = _get("kubernetes.host", kwargs, get_config_option, env)
    if host:
        return _resolve_explicit(host, get_config_option, env, kwargs)

    in_cluster_pref = _coerce_bool(_get("kubernetes.in_cluster", kwargs, get_config_option, env))
    if in_cluster_pref is True or (in_cluster_pref is None and _looks_in_cluster(env)):
        return _resolve_in_cluster(get_config_option, env, kwargs)

    raise CommandExecutionError(
        "Invalid kubernetes configuration. Provide one of: "
        "(a) 'kubeconfig' + 'context'; "
        "(b) 'kubeconfig-data' + 'context'; "
        "(c) 'host' plus credentials (api_key, username/password, or client_cert/client_key); "
        "or (d) set 'in_cluster: true' (auto-detected when running in a Kubernetes pod)."
    )


def _resolve_kubeconfig_file(kubeconfig, get_config_option, env, kwargs):
    context = _get("kubernetes.context", kwargs, get_config_option, env)
    if not context:
        raise CommandExecutionError(
            "Invalid kubernetes configuration. Parameter 'kubeconfig' and 'context'"
            " are required."
        )
    config = kubernetes.client.Configuration()
    persist = _coerce_bool(_get("kubernetes.persist_config", kwargs, get_config_option, env))
    loader_kwargs = {
        "config_file": kubeconfig,
        "context": context,
        "client_configuration": config,
    }
    if persist is not None:
        loader_kwargs["persist_config"] = persist
    kubernetes.config.load_kube_config(**loader_kwargs)
    _apply_post_hooks(config, get_config_option, env, kwargs)
    kubernetes.client.Configuration.set_default(config)
    return {"kubeconfig": kubeconfig, "context": context}


def _resolve_kubeconfig_data(kubeconfig_data, get_config_option, env, kwargs):
    context = _get("kubernetes.context", kwargs, get_config_option, env)
    if not context:
        raise CommandExecutionError(
            "Invalid kubernetes configuration. Parameter 'kubeconfig-data' "
            "and 'context' are required."
        )
    with tempfile.NamedTemporaryFile(prefix="salt-kubeconfig-", delete=False) as kcfg:
        kcfg.write(base64.b64decode(kubeconfig_data))
        kubeconfig = kcfg.name
    # Forward through the file path; pass the resolved values explicitly
    # so we don't re-traverse env / pillar lookups for the same keys.
    return _resolve_kubeconfig_file(
        kubeconfig,
        get_config_option,
        env,
        {**kwargs, "kubeconfig": kubeconfig, "context": context},
    )


def _resolve_explicit(host, get_config_option, env, kwargs):
    config = kubernetes.client.Configuration()
    config.host = host

    ca_cert = _get("kubernetes.ca_cert", kwargs, get_config_option, env)
    if ca_cert:
        config.ssl_ca_cert = ca_cert

    api_key = _get("kubernetes.api_key", kwargs, get_config_option, env)
    username = _get("kubernetes.username", kwargs, get_config_option, env)
    client_cert = _get("kubernetes.client_cert", kwargs, get_config_option, env)

    if api_key:
        prefix = _get("kubernetes.api_key_prefix", kwargs, get_config_option, env) or "Bearer"
        config.api_key = {"authorization": api_key}
        config.api_key_prefix = {"authorization": prefix}
    elif username:
        config.username = username
        config.password = _get("kubernetes.password", kwargs, get_config_option, env) or ""
    elif client_cert:
        config.cert_file = client_cert
        client_key = _get("kubernetes.client_key", kwargs, get_config_option, env)
        if client_key:
            config.key_file = client_key
    # No credentials with a host is allowed (e.g. an unauthenticated
    # local kube-apiserver in test harnesses); we rely on the API
    # server to reject if it requires auth.

    _apply_post_hooks(config, get_config_option, env, kwargs)
    kubernetes.client.Configuration.set_default(config)
    return {"host": host}


def _resolve_in_cluster(get_config_option, env, kwargs):
    config = kubernetes.client.Configuration()
    kubernetes.config.load_incluster_config(client_configuration=config)
    _apply_post_hooks(config, get_config_option, env, kwargs)
    kubernetes.client.Configuration.set_default(config)
    return {"in_cluster": True}


def _apply_post_hooks(config, get_config_option, env, kwargs):
    """Mode-agnostic options applied to every resolved Configuration."""
    proxy = _get("kubernetes.proxy", kwargs, get_config_option, env)
    if proxy:
        config.proxy = proxy
    no_proxy = _get("kubernetes.no_proxy", kwargs, get_config_option, env)
    if no_proxy:
        config.no_proxy = no_proxy
    proxy_headers = _get("kubernetes.proxy_headers", kwargs, get_config_option, env)
    if proxy_headers:
        config.proxy_headers = proxy_headers
    verify = _coerce_bool(_get("kubernetes.verify_ssl", kwargs, get_config_option, env))
    if verify is not None:
        config.verify_ssl = verify


def _cleanup(**kwargs):
    """
    Remove a temporary kubeconfig file produced by ``_setup_conn`` from
    inline base64 data. Files not matching the ``salt-kubeconfig-``
    prefix, and result keys other than ``kubeconfig`` (e.g. ``host``,
    ``in_cluster``), are left alone.
    """
    if "kubeconfig" in kwargs:
        kubeconfig = kwargs.get("kubeconfig")
        if kubeconfig and os.path.basename(kubeconfig).startswith("salt-kubeconfig-"):
            try:
                os.unlink(kubeconfig)
            except OSError as err:
                if err.errno != errno.ENOENT:
                    log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
