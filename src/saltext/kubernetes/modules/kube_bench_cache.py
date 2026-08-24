"""
Execution module: kube_bench_cache

Collect kube-bench results and write a validated JSON array to a minion-local
cache file.  Every control SLS calls ``kube_bench_cache.ensure_fresh`` at Jinja
render time before reading the cache.

All cluster interaction goes through this extension's own ``kubernetes``
execution module (``saltext.kubernetes.modules.kubernetesmod``, loaded as
``__salt__["kubernetes.*"]``) rather than shelling out to ``kubectl``. This
means connection/auth handling (kubeconfig file, inline kubeconfig data,
explicit host+credentials, in-cluster ServiceAccount) is inherited for free
from that module's ``_setup_conn`` resolution instead of being reimplemented
here.

Two collection strategies are supported (selected via the ``collection_strategy``
parameter or the ``kube_bench:collection_strategy`` pillar key):

* **job** (default): creates a one-time Kubernetes Job from the suspended
  kube-bench CronJob template, waits for completion, collects JSON output
  from every pod (one per node), then deletes the Job.  Use
  ``run_assessment()`` to trigger this path on demand -- it bypasses the TTL
  cache check and always runs a new Job.  This matches how
  ``helm/kube-bench-job`` actually deploys kube-bench (a suspended CronJob,
  no standing pods), so it's the default that works out of the box without
  any pillar configuration.
* **daemonset** (backward-compatible): reads logs from an existing
  long-running kube-bench DaemonSet. Only useful if you've deployed kube-bench
  that way yourself; set ``collection_strategy: daemonset`` explicitly.

Because ``ensure_fresh`` is invoked via ``salt['kube_bench_cache.ensure_fresh']()``
at Jinja render time it MUST NOT honour ``__opts__['test']`` -- doing so would
silently skip collection during every ``policy.assessment`` run (which uses
``test=True``) and leave all controls reading a stale or missing file.
"""

from __future__ import annotations

import json
import logging
import os
import time
from contextlib import contextmanager

from salt.exceptions import CommandExecutionError
from salt.exceptions import FileLockError
from salt.utils.files import wait_lock

log = logging.getLogger(__name__)

__virtualname__ = "kube_bench_cache"

_DEFAULT_CACHE_PATH = "/var/log/kube-bench.json"
_DEFAULT_NAMESPACE = "kube-system"
_DEFAULT_LABEL = "app=kube-bench"
_DEFAULT_TTL = 900
_LOCK_TIMEOUT = 120
_DEFAULT_CRONJOB = "kube-bench"
_DEFAULT_JOB_TIMEOUT = 600
_JOB_POLL_INTERVAL = 10
_POD_SUCCEEDED_RETRIES = 6
_POD_SUCCEEDED_RETRY_SLEEP = 5

_PILLAR_KEY = "kube_bench"


def __virtual__():
    return __virtualname__


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _pillar_cfg():
    """Return the ``kube_bench`` pillar dict, or an empty dict if absent.

    Checks three sources in order:

    1. ``pillar.get`` execution module -- works when called directly.
    2. ``__pillar__`` dunder -- works in most non-Jinja contexts.
    3. ``__opts__`` (minion config) -- always available, including from Jinja
       rendering context where both pillar sources are empty.  Add a
       ``kube_bench:`` block to ``/etc/salt/minion`` as a reliable fallback.
    """
    try:
        result = __salt__["pillar.get"](_PILLAR_KEY, {})
        if result:
            log.debug("kube_bench_cache: pillar cfg from pillar.get")
            return result
    except Exception:  # pylint: disable=broad-except
        pass

    pillar_val = __pillar__.get(_PILLAR_KEY, {})
    if pillar_val:
        log.debug("kube_bench_cache: pillar cfg from __pillar__")
        return pillar_val

    opts_val = __opts__.get(_PILLAR_KEY, {})
    if opts_val:
        log.debug("kube_bench_cache: pillar cfg from __opts__ (minion config)")
    return opts_val


def ensure_fresh(
    namespace=None,
    label=None,
    cache_path=None,
    ttl_seconds=None,
    kubeconfig=None,
    auth_mode=None,
    collection_strategy=None,
    cronjob_name=None,
    job_timeout=None,
):
    """
    Return *cache_path* after guaranteeing it exists and is no older than
    *ttl_seconds*.  If the file is missing or stale, collect kube-bench results
    using the selected *collection_strategy* and write them atomically to
    *cache_path*.

    Any parameter left as *None* falls back to the ``kube_bench`` pillar key
    of the same name, then to the module-level default constant.  Explicit
    arguments always take precedence over pillar values.

    Parameters
    ----------
    namespace : str or None
        Kubernetes namespace where kube-bench resources live.
    label : str or None
        Label selector for kube-bench pods (DaemonSet strategy only).
    cache_path : str or None
        Absolute path where the JSON array is stored on the minion.
    ttl_seconds : int or None
        Maximum cache age in seconds before re-collection is triggered.
    kubeconfig : str or None
        Path to a kubeconfig file.  *None* falls back to pillar, then to
        ``kubernetes.*``'s own credential auto-detection.
    auth_mode : str or None
        ``"in_cluster"`` or ``"kubeconfig"``.  *None* falls back to pillar,
        then to ``kubernetes.*``'s own auto-detection (kubeconfig file/env,
        then in-cluster ServiceAccount).
    collection_strategy : str or None
        ``"job"`` or ``"daemonset"``.  *None* falls back to pillar, then
        ``"job"``.
    cronjob_name : str or None
        Name of the suspended CronJob used as the Job template (Job strategy).
    job_timeout : int or None
        Seconds to wait for the Job to complete before raising (Job strategy).

    Returns
    -------
    str
        *cache_path* (for use in Jinja ``{%- set _ = salt['...']() %}``).

    CLI Example:

    .. code-block:: bash

        salt '*' kube_bench_cache.ensure_fresh
    """
    cfg = _pillar_cfg()
    log.debug("kube_bench_cache: pillar cfg keys=%s", list(cfg.keys()))
    namespace = namespace if namespace is not None else cfg.get("namespace", _DEFAULT_NAMESPACE)
    label = label if label is not None else cfg.get("label", _DEFAULT_LABEL)
    cache_path = (
        cache_path if cache_path is not None else cfg.get("cache_path", _DEFAULT_CACHE_PATH)
    )
    ttl_seconds = int(
        ttl_seconds if ttl_seconds is not None else cfg.get("ttl_seconds", _DEFAULT_TTL)
    )
    kubeconfig = kubeconfig if kubeconfig is not None else (cfg.get("kubeconfig") or None)
    auth_mode = auth_mode if auth_mode is not None else (cfg.get("auth_mode") or None)
    collection_strategy = (
        collection_strategy
        if collection_strategy is not None
        else cfg.get("collection_strategy", "job")
    )
    cronjob_name = (
        cronjob_name if cronjob_name is not None else cfg.get("cronjob_name", _DEFAULT_CRONJOB)
    )
    job_timeout = int(
        job_timeout if job_timeout is not None else cfg.get("job_timeout", _DEFAULT_JOB_TIMEOUT)
    )
    log.debug(
        "kube_bench_cache: ensure_fresh resolved strategy=%s auth_mode=%s kubeconfig=%s",
        collection_strategy,
        auth_mode,
        kubeconfig,
    )

    if _is_fresh(cache_path, ttl_seconds):
        log.debug("kube_bench_cache: cache is fresh (%s)", cache_path)
        return cache_path

    lock_path = cache_path + ".lock"
    os.makedirs(os.path.dirname(cache_path) or "/var/log", exist_ok=True)

    conn_kwargs = _conn_kwargs(auth_mode, kubeconfig)

    with _lock(lock_path):
        if _is_fresh(cache_path, ttl_seconds):
            log.debug("kube_bench_cache: cache populated by concurrent render (%s)", cache_path)
            return cache_path

        log.info(
            "kube_bench_cache: collecting kube-bench results (ns=%s strategy=%s -> %s)",
            namespace,
            collection_strategy,
            cache_path,
        )
        sections = _collect(
            namespace=namespace,
            label=label,
            conn_kwargs=conn_kwargs,
            collection_strategy=collection_strategy,
            cronjob_name=cronjob_name,
            job_timeout=job_timeout,
        )
        _write_atomic(cache_path, sections)
        log.info("kube_bench_cache: wrote %d section(s) to %s", len(sections), cache_path)

    return cache_path


def run_assessment(
    namespace=None,
    cache_path=None,
    kubeconfig=None,
    auth_mode=None,
    cronjob_name=None,
    job_timeout=None,
):
    """
    Trigger an on-demand kube-bench assessment using the Job strategy.

    Unlike ``ensure_fresh``, this function **always** runs a new Job regardless
    of whether a fresh cache already exists.  Results are written atomically to
    *cache_path* after the Job completes.

    Any parameter left as *None* falls back to the ``kube_bench`` pillar key
    of the same name, then to the module-level default constant.

    Parameters
    ----------
    namespace : str or None
        Kubernetes namespace where the kube-bench CronJob lives.
    cache_path : str or None
        Absolute path where the JSON array is stored on the minion.
    kubeconfig : str or None
        Path to a kubeconfig file.  *None* falls back to pillar, then to
        ``kubernetes.*``'s own credential auto-detection.
    auth_mode : str or None
        ``"in_cluster"`` or ``"kubeconfig"``.  *None* falls back to pillar,
        then to ``kubernetes.*``'s own auto-detection.
    cronjob_name : str or None
        Name of the suspended CronJob used as the Job template.
    job_timeout : int or None
        Seconds to wait for the Job to complete before raising.

    Returns
    -------
    dict
        ``{"result": True, "message": "<cache_path>"}`` on success, or
        ``{"result": False, "message": "<error>"}`` on failure.

    CLI Example:

    .. code-block:: bash

        salt '*' kube_bench_cache.run_assessment
    """
    cfg = _pillar_cfg()
    namespace = namespace if namespace is not None else cfg.get("namespace", _DEFAULT_NAMESPACE)
    cache_path = (
        cache_path if cache_path is not None else cfg.get("cache_path", _DEFAULT_CACHE_PATH)
    )
    kubeconfig = kubeconfig if kubeconfig is not None else (cfg.get("kubeconfig") or None)
    auth_mode = auth_mode if auth_mode is not None else (cfg.get("auth_mode") or None)
    cronjob_name = (
        cronjob_name if cronjob_name is not None else cfg.get("cronjob_name", _DEFAULT_CRONJOB)
    )
    job_timeout = int(
        job_timeout if job_timeout is not None else cfg.get("job_timeout", _DEFAULT_JOB_TIMEOUT)
    )
    conn_kwargs = _conn_kwargs(auth_mode, kubeconfig)
    os.makedirs(os.path.dirname(cache_path) or "/var/log", exist_ok=True)

    try:
        sections = _collect_job(
            namespace=namespace,
            cronjob_name=cronjob_name,
            job_timeout=job_timeout,
            conn_kwargs=conn_kwargs,
        )
        _write_atomic(cache_path, sections)
        log.info(
            "kube_bench_cache: run_assessment wrote %d section(s) to %s",
            len(sections),
            cache_path,
        )
        return {"result": True, "message": cache_path}
    except Exception as exc:  # pylint: disable=broad-except
        log.error("kube_bench_cache: run_assessment failed: %s", exc)
        return {"result": False, "message": str(exc)}


def status_for_check(
    test_number,
    namespace=None,
    label=None,
    cache_path=None,
    ttl_seconds=None,
    kubeconfig=None,
    auth_mode=None,
    collection_strategy=None,
    cronjob_name=None,
    job_timeout=None,
):
    """
    Return an aggregated status/comment for *test_number* across every node
    present in the merged kube-bench cache.

    .. versionadded:: 2.2.0

    kube-bench runs the full CIS check set on every node regardless of its
    actual role (master/worker), so the cache can hold multiple results for
    the same *test_number* -- one per node. Control SLS files that instead
    hand-parse the cache and stop at the first matching result silently
    ignore every other node -- this is the correct replacement for that
    pattern, not just a convenience wrapper.

    Aggregation policy is worst-status-wins: ``FAIL`` if any node FAILs,
    ``WARN`` if none FAIL but any node WARNs/INFOs, ``PASS`` only if every
    node PASSes, ``ERROR`` if no node reports this check at all.

    Parameters mirror :py:func:`ensure_fresh` (which this calls internally
    to guarantee freshness) with one addition:

    test_number : str
        The kube-bench control ID to look up, e.g. ``"1.1.11"``.

    Returns
    -------
    dict
        ``{"status": "PASS"|"WARN"|"FAIL"|"ERROR", "comment": str}``.
        *comment* lists one line per node (via the ``node_name`` tag each
        cached result carries) -- the only place that detail can surface to a
        caller like RaaS, whose compliance-finding model has no per-node
        field of its own, only a single free-text comment per minion per
        check. Each line is ``"<node>: <status> [expected=<...>]
        actual=<...>"``; ``expected`` is omitted when kube-bench doesn't
        populate ``expected_result`` for that check, and ``actual`` falls
        back to kube-bench's ``reason`` (the real audit-command error, e.g.
        "no such file or directory") when ``actual_value`` itself is blank,
        which is common on FAILs where the audit command errored out rather
        than producing comparable output.

    CLI Example:

    .. code-block:: bash

        salt '*' kube_bench_cache.status_for_check test_number=1.1.11
    """
    cache_path = ensure_fresh(
        namespace=namespace,
        label=label,
        cache_path=cache_path,
        ttl_seconds=ttl_seconds,
        kubeconfig=kubeconfig,
        auth_mode=auth_mode,
        collection_strategy=collection_strategy,
        cronjob_name=cronjob_name,
        job_timeout=job_timeout,
    )
    with open(cache_path, encoding="utf-8") as fh:
        sections = json.load(fh)

    matches = [
        (section.get("node_name"), result)
        for section in sections
        for test_group in section.get("tests", [])
        for result in test_group.get("results", [])
        if result.get("test_number") == test_number
    ]
    if not matches:
        return {
            "status": "ERROR",
            "comment": f"control {test_number} not found in {cache_path}",
        }

    statuses = {result.get("status") for _, result in matches}
    if "FAIL" in statuses:
        agg_status = "FAIL"
    elif statuses & {"WARN", "INFO"}:
        agg_status = "WARN"
    else:
        agg_status = "PASS"

    comment = "\n".join(_format_node_result(node_name, result) for node_name, result in matches)
    return {"status": agg_status, "comment": comment}


def _format_node_result(node_name, result):
    """Render one node's result line for :py:func:`status_for_check`'s comment.

    ``actual_value`` is often blank on a FAIL -- kube-bench only populates it
    when its audit command produces comparable output at all; when the audit
    command itself errors out (e.g. checking an etcd-only path on a node with
    no etcd), it leaves ``actual_value`` empty and puts the real diagnostic in
    ``reason`` instead. Falling back to ``reason`` avoids printing a bare
    ``actual=`` with nothing after it, which reads as broken rather than
    "no data". ``expected_result`` is included when kube-bench populates it,
    since it's the counterpart the reader needs to judge ``actual`` against.
    """
    label = node_name or "unknown-node"
    status = result.get("status")
    actual = (result.get("actual_value") or "").strip()
    if not actual:
        actual = (result.get("reason") or "").strip()
    expected = (result.get("expected_result") or "").strip()

    parts = [f"{label}: {status}"]
    if expected:
        parts.append(f"expected={expected[:200]}")
    parts.append("actual={}".format(actual[:300] if actual else "n/a"))
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_fresh(path, ttl_seconds):
    """Return True when *path* exists and its mtime is within *ttl_seconds*."""
    try:
        age = time.time() - os.stat(path).st_mtime
        return age < ttl_seconds
    except FileNotFoundError:
        return False


def _conn_kwargs(auth_mode, kubeconfig):
    """Translate *auth_mode*/*kubeconfig* into kwargs forwarded to every
    ``kubernetes.*`` cross-call below.

    Leaving both unset returns ``{}``, which lets ``kubernetesmod``'s own
    ``_setup_conn`` auto-detect credentials (kubeconfig file/env, then
    in-cluster ServiceAccount) exactly as it does for any other caller --
    no bespoke kubeconfig/env handling needed here any more.
    """
    if auth_mode is None:
        return {"kubeconfig": kubeconfig} if kubeconfig else {}

    if auth_mode == "in_cluster":
        return {"in_cluster": True}

    if auth_mode == "kubeconfig":
        if not kubeconfig:
            raise RuntimeError(
                "kube_bench_cache: auth_mode='kubeconfig' requires a kubeconfig path"
            )
        return {"kubeconfig": kubeconfig}

    log.warning(
        "kube_bench_cache: unknown auth_mode %r, falling back to default credential resolution",
        auth_mode,
    )
    return {"kubeconfig": kubeconfig} if kubeconfig else {}


def _label_matches(labels, selector):
    """Return True when *labels* satisfies every ``key=value`` clause in *selector*.

    ``kubernetes.pods``/``kubernetes.jobs`` have no server-side label-selector
    support, so matching is done client-side against each object's labels.
    Only comma-separated equality clauses are supported (e.g.
    ``app=kube-bench``) -- the only selector syntax this module has ever used.
    """
    labels = labels or {}
    for clause in selector.split(","):
        key, _, value = clause.partition("=")
        if labels.get(key.strip()) != value.strip():
            return False
    return True


def _pod_names(namespace, label, conn_kwargs):
    """Return ``(name, node_name)`` pairs for pods in *namespace* whose
    labels satisfy *label*."""
    names = __salt__["kubernetes.pods"](namespace=namespace, **conn_kwargs)
    matched = []
    for name in names:
        pod = __salt__["kubernetes.show_pod"](name, namespace=namespace, **conn_kwargs)
        if pod and _label_matches(pod.get("metadata", {}).get("labels"), label):
            matched.append((name, (pod.get("spec") or {}).get("nodeName")))
    if not matched:
        raise RuntimeError(f"No pods found in namespace '{namespace}' with label '{label}'")
    return matched


def _tag_sections_with_node(sections, node_name):
    """Annotate each section dict in *sections* with the node it ran on.

    kube-bench's own JSON output carries no node identity at all -- only a
    master/node ``node_type`` classification -- so once results from
    multiple pods are merged into one flat list, there would be no way to
    tell a control-plane FAIL from a specific worker's FAIL without this.
    *node_name* comes from the collecting pod's own ``spec.nodeName``
    (fetched alongside its Succeeded/label check, no extra API call).
    """
    for section in sections:
        section["node_name"] = node_name
    return sections


def _parse_sections(raw_logs):
    """
    Parse *raw_logs* (str) which may contain one or more concatenated JSON
    documents (kube-bench emits one per benchmark section).  Returns a flat
    list of section dicts.

    kube-bench also sometimes wraps everything in a single envelope::

        {"Controls": [...], "Totals": {...}}

    Both formats are handled.
    """
    decoder = json.JSONDecoder()
    pos = 0
    raw = raw_logs.strip()
    docs = []
    while pos < len(raw):
        try:
            obj, end = decoder.raw_decode(raw, pos)
            docs.append(obj)
            pos = end
            while pos < len(raw) and raw[pos] in " \t\n\r":
                pos += 1
        except json.JSONDecodeError:
            # Skip non-JSON noise (prefix/suffix/inter-document text such as
            # entrypoint script warnings printed to stdout) and advance to the
            # next potential JSON start character.  If none remains, pos reaches
            # len(raw) and the outer loop exits cleanly, handling trailing noise
            # as well.
            pos += 1
            while pos < len(raw) and raw[pos] not in "{[":
                pos += 1

    sections = []
    for doc in docs:
        if isinstance(doc, dict) and "Controls" in doc:
            sections.extend(doc["Controls"])
        elif isinstance(doc, dict) and "id" in doc:
            sections.append(doc)

    return sections


def _is_assessment_active(namespace, conn_kwargs):
    """Return ``(True, job_name)`` when a kube-bench assessment Job is currently
    running, ``(False, "")`` otherwise.

    Matches on the ``app=kube-bench-assessment`` label (client-side, see
    ``_label_matches``). Jobs with ``status.active > 0`` are considered
    in-flight.
    """
    try:
        job_names = __salt__["kubernetes.jobs"](namespace=namespace, **conn_kwargs)
    except CommandExecutionError as exc:
        log.debug("kube_bench_cache: _is_assessment_active query failed: %s", exc)
        return False, ""

    for job_name in job_names:
        job = __salt__["kubernetes.show_job"](job_name, namespace=namespace, **conn_kwargs)
        if not job:
            continue
        labels = (job.get("metadata") or {}).get("labels") or {}
        if not _label_matches(labels, "app=kube-bench-assessment"):
            continue
        active = (job.get("status") or {}).get("active") or 0
        if active > 0:
            log.debug("kube_bench_cache: active assessment job found: %s", job_name)
            return True, job_name

    return False, ""


def _create_assessment_job(cronjob_name, namespace, conn_kwargs):
    """Create a kube-bench Job from the suspended CronJob template.

    The Job is named ``kube-bench-assessment-<YYYYMMDD-HHMMSS>`` (UTC), and
    inherits the CronJob's ``jobTemplate`` labels/annotations/spec verbatim --
    the ``app=kube-bench-assessment`` label ``_is_assessment_active`` looks
    for is expected to already be present on that template.  After creation
    the Job's ``parallelism``/``completions`` are patched to the current node
    count so every node runs one kube-bench pod.

    Returns the job name.
    """
    cronjob = __salt__["kubernetes.show_cron_job"](cronjob_name, namespace=namespace, **conn_kwargs)
    if not cronjob:
        raise RuntimeError(
            "kube_bench_cache: CronJob '{}' not found in namespace '{}'".format(
                cronjob_name, namespace
            )
        )
    job_template = (cronjob.get("spec") or {}).get("jobTemplate") or {}
    template_metadata = job_template.get("metadata") or {}
    spec = job_template.get("spec") or {}

    job_name = "kube-bench-assessment-{}".format(time.strftime("%Y%m%d-%H%M%S", time.gmtime()))
    annotations = dict(template_metadata.get("annotations") or {})
    annotations["cronjob.kubernetes.io/instantiate"] = "manual"
    metadata = {
        "labels": dict(template_metadata.get("labels") or {}),
        "annotations": annotations,
    }

    __salt__["kubernetes.create_job"](
        name=job_name, namespace=namespace, metadata=metadata, spec=spec, **conn_kwargs
    )
    log.info("kube_bench_cache: created assessment job %s", job_name)

    node_count = len(__salt__["kubernetes.nodes"](**conn_kwargs)) or 1
    log.debug("kube_bench_cache: cluster has %d node(s)", node_count)

    if node_count > 1:
        __salt__["kubernetes.patch_job"](
            job_name,
            namespace=namespace,
            patch={"spec": {"parallelism": node_count, "completions": node_count}},
            **conn_kwargs,
        )
        log.debug(
            "kube_bench_cache: patched job %s parallelism/completions=%d",
            job_name,
            node_count,
        )

    return job_name


def _wait_for_job(job_name, namespace, timeout_seconds, conn_kwargs):
    """Poll *job_name* until it succeeds, fails, or *timeout_seconds* elapses.

    Raises ``RuntimeError`` on failure or timeout.  Returns ``None`` on success.
    """
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            job = __salt__["kubernetes.show_job"](job_name, namespace=namespace, **conn_kwargs)
        except CommandExecutionError as exc:
            log.warning("kube_bench_cache: _wait_for_job poll error: %s", exc)
            time.sleep(_JOB_POLL_INTERVAL)
            continue

        status = (job or {}).get("status") or {}
        for cond in status.get("conditions") or []:
            if cond.get("type") == "Complete" and cond.get("status") == "True":
                log.info("kube_bench_cache: job %s completed successfully", job_name)
                return
            if cond.get("type") == "Failed" and cond.get("status") == "True":
                raise RuntimeError(
                    "kube_bench_cache: job {} failed: {}".format(
                        job_name, cond.get("message", "no message")
                    )
                )

        log.debug(
            "kube_bench_cache: waiting for job %s (active=%s succeeded=%s failed=%s)",
            job_name,
            status.get("active", 0),
            status.get("succeeded", 0),
            status.get("failed", 0),
        )
        time.sleep(_JOB_POLL_INTERVAL)

    raise RuntimeError(f"kube_bench_cache: job {job_name} timed out after {timeout_seconds}s")


def _succeeded_pods_for_job(job_name, namespace, conn_kwargs):
    """Return ``(name, node_name)`` pairs for Succeeded pods of *job_name*,
    retrying on API timing lag.

    A Job may be marked Complete before every pod's phase is reflected as
    ``Succeeded`` in the API. Retry up to ``_POD_SUCCEEDED_RETRIES`` times
    with a short sleep to let the API catch up. Raises ``RuntimeError`` when
    no Succeeded pods appear after all retries.
    """
    names = __salt__["kubernetes.pods"](namespace=namespace, **conn_kwargs)
    pods = []
    for name in names:
        pod = __salt__["kubernetes.show_pod"](name, namespace=namespace, **conn_kwargs)
        if not pod:
            continue
        labels = (pod.get("metadata") or {}).get("labels")
        if not _label_matches(labels, f"job-name={job_name}"):
            continue
        phase = (pod.get("status") or {}).get("phase")
        if phase == "Succeeded":
            pods.append((name, (pod.get("spec") or {}).get("nodeName")))
        else:
            log.debug("kube_bench_cache: pod %s phase=%s (not yet Succeeded)", name, phase)
    return pods


def _collect_all_pod_logs(job_name, namespace, conn_kwargs):
    """Fetch kube-bench JSON output from every Succeeded pod of *job_name*.

    Returns a merged list of section dicts from all pods.
    """
    pods = []
    for attempt in range(_POD_SUCCEEDED_RETRIES):
        pods = _succeeded_pods_for_job(job_name, namespace, conn_kwargs)
        if pods:
            break
        if attempt < _POD_SUCCEEDED_RETRIES - 1:
            log.debug(
                "kube_bench_cache: no Succeeded pods yet for job %s "
                "(attempt %d/%d), retrying in %ds",
                job_name,
                attempt + 1,
                _POD_SUCCEEDED_RETRIES,
                _POD_SUCCEEDED_RETRY_SLEEP,
            )
            time.sleep(_POD_SUCCEEDED_RETRY_SLEEP)

    if not pods:
        raise RuntimeError(
            "kube_bench_cache: no Succeeded pods found for job {} "
            "after {} attempts".format(job_name, _POD_SUCCEEDED_RETRIES)
        )
    log.debug(
        "kube_bench_cache: collecting logs from %d pod(s) for job %s",
        len(pods),
        job_name,
    )

    all_sections = []
    errors = []
    for pod, node_name in pods:
        try:
            raw_logs = __salt__["kubernetes.logs"](pod, namespace=namespace, **conn_kwargs)
            sections = _parse_sections(raw_logs)
            if not sections:
                log.warning("kube_bench_cache: no sections parsed from pod %s", pod)
            all_sections.extend(_tag_sections_with_node(sections, node_name))
        except Exception as exc:  # pylint: disable=broad-except
            msg = f"pod {pod}: {exc}"
            log.error("kube_bench_cache: %s", msg)
            errors.append(msg)

    if not all_sections:
        raise RuntimeError(
            "kube_bench_cache: no sections collected from any pod for job {}. "
            "Errors: {}".format(job_name, errors)
        )

    return all_sections


def _collect_job(namespace, cronjob_name, job_timeout, conn_kwargs):
    """Orchestrate on-demand Job creation, waiting, log collection, and cleanup.

    Raises ``RuntimeError`` if another assessment Job is already active.
    Always attempts to delete the Job after log collection (or on failure).
    """
    active, active_job = _is_assessment_active(namespace, conn_kwargs)
    if active:
        raise RuntimeError(
            f"kube_bench_cache: concurrent assessment already in progress: {active_job}"
        )

    job_name = _create_assessment_job(cronjob_name, namespace, conn_kwargs)
    try:
        _wait_for_job(job_name, namespace, job_timeout, conn_kwargs)
        sections = _collect_all_pod_logs(job_name, namespace, conn_kwargs)
    finally:
        try:
            __salt__["kubernetes.delete_job"](job_name, namespace=namespace, **conn_kwargs)
            log.debug("kube_bench_cache: deleted assessment job %s", job_name)
        except CommandExecutionError as exc:
            log.warning("kube_bench_cache: failed to delete job %s: %s", job_name, exc)

    return sections


def _collect(
    namespace,
    label,
    conn_kwargs,
    collection_strategy="job",
    cronjob_name=_DEFAULT_CRONJOB,
    job_timeout=_DEFAULT_JOB_TIMEOUT,
):
    """
    Return a list of all kube-bench section dicts.

    Dispatches to ``_collect_job`` when *collection_strategy* is ``"job"``,
    otherwise reads logs from an existing DaemonSet/pods matching *label*.
    """
    if collection_strategy == "job":
        return _collect_job(
            namespace=namespace,
            cronjob_name=cronjob_name,
            job_timeout=int(job_timeout),
            conn_kwargs=conn_kwargs,
        )

    pods = _pod_names(namespace, label, conn_kwargs)
    log.debug("kube_bench_cache: collecting from pods: %s", [name for name, _ in pods])

    all_sections = []
    errors = []
    for pod, node_name in pods:
        try:
            raw = __salt__["kubernetes.logs"](pod, namespace=namespace, **conn_kwargs)
            sections = _parse_sections(raw)
            if not sections:
                log.warning("kube_bench_cache: no sections parsed from pod %s", pod)
            all_sections.extend(_tag_sections_with_node(sections, node_name))
        except Exception as exc:  # pylint: disable=broad-except
            msg = f"pod {pod}: {exc}"
            log.error("kube_bench_cache: %s", msg)
            errors.append(msg)

    if not all_sections:
        raise RuntimeError(
            f"kube_bench_cache: no sections collected from any pod. Errors: {errors}"
        )

    return all_sections


def _write_atomic(path, sections):
    """Write *sections* as JSON to *path* atomically via a temp file."""
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(sections, fh, indent=2)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


@contextmanager
def _lock(path, timeout=_LOCK_TIMEOUT):
    """
    Best-effort exclusive lock on *path*.

    Wraps ``salt.utils.files.wait_lock`` (platform-agnostic: atomic
    ``O_CREAT | O_EXCL`` file creation, no ``fcntl``/``msvcrt`` needed) but,
    unlike that helper, never raises on timeout -- concurrent cache renders
    fall back to proceeding without the lock rather than failing the SLS
    render outright.
    """
    try:
        with wait_lock(path, lock_fn=path, timeout=timeout):
            yield
    except FileLockError:
        log.warning("kube_bench_cache: lock timeout after %ss -- proceeding without lock", timeout)
        yield
