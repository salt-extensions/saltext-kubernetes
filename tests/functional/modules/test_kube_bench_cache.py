"""Functional tests for the kube-bench cache execution module."""

import json
import time

import pytest
from saltfactories.utils import random_string

pytestmark = [
    pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms"),
]


@pytest.fixture(scope="module")
def kubernetes(modules):
    """Return the Kubernetes execution module used to create test resources."""
    return modules.kubernetes


@pytest.fixture
def kube_bench_namespace(kubernetes):
    name = random_string("kube-bench-test-", uppercase=False)
    kubernetes.create_namespace(name)
    try:
        yield name
    finally:
        kubernetes.delete_namespace(name, wait=True)


def _bench_result(test_number, status="PASS"):
    return json.dumps(
        {
            "id": test_number,
            "tests": [
                {
                    "results": [
                        {
                            "test_number": test_number,
                            "status": status,
                            "actual_value": "enabled",
                        }
                    ]
                }
            ],
        }
    )


@pytest.fixture
def kube_bench_daemonset(kubernetes, kube_bench_namespace):
    name = random_string("kube-bench-", uppercase=False)
    result = _bench_result("2.1.1")
    spec = {
        "selector": {"matchLabels": {"app": "kube-bench"}},
        "template": {
            "metadata": {"labels": {"app": "kube-bench"}},
            "spec": {
                "containers": [
                    {
                        "name": "bench",
                        "image": "busybox:1.36",
                        "command": ["sh", "-c", f"printf '%s\\n' '{result}'; sleep 300"],
                    }
                ]
            },
        },
    }
    kubernetes.create_daemonset(
        name=name,
        namespace=kube_bench_namespace,
        metadata={"labels": {"app": "kube-bench"}},
        spec=spec,
        wait=True,
    )
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        pod_names = kubernetes.pods(namespace=kube_bench_namespace)
        ready_pods = []
        for pod_name in pod_names:
            pod = kubernetes.show_pod(pod_name, namespace=kube_bench_namespace)
            labels = (pod or {}).get("metadata", {}).get("labels", {})
            if labels.get("app") != "kube-bench":
                continue
            if (pod.get("status") or {}).get("phase") == "Running":
                ready_pods.append(pod_name)
        if ready_pods:
            break
        time.sleep(1)
    else:
        raise AssertionError("kube-bench DaemonSet did not produce a running pod")
    try:
        yield {"name": name, "namespace": kube_bench_namespace}
    finally:
        kubernetes.delete_daemonset(name, namespace=kube_bench_namespace, wait=True)


@pytest.fixture
def kube_bench_cronjob(kubernetes, kube_bench_namespace):
    name = random_string("kube-bench-", uppercase=False)
    spec = {
        "schedule": "0 0 1 1 *",
        "suspend": True,
        "jobTemplate": {
            "metadata": {"labels": {"app": "kube-bench-assessment"}},
            "spec": {
                "backoffLimit": 0,
                "template": {
                    "metadata": {"labels": {"app": "kube-bench"}},
                    "spec": {
                        "restartPolicy": "Never",
                        "containers": [
                            {
                                "name": "bench",
                                "image": "busybox:1.36",
                                "command": [
                                    "sh",
                                    "-c",
                                    f"printf '%s\\n' '{_bench_result('3.1.1', 'WARN')}'",
                                ],
                            }
                        ],
                    },
                },
            },
        },
    }
    kubernetes.create_cron_job(name, namespace=kube_bench_namespace, spec=spec)
    try:
        yield {"name": name, "namespace": kube_bench_namespace}
    finally:
        kubernetes.delete_cron_job(name, namespace=kube_bench_namespace, wait=True)


@pytest.fixture
def kube_bench_failing_cronjob(kubernetes, kube_bench_namespace):
    name = random_string("kube-bench-failing-", uppercase=False)
    spec = {
        "schedule": "0 0 1 1 *",
        "suspend": True,
        "jobTemplate": {
            "metadata": {"labels": {"app": "kube-bench-assessment"}},
            "spec": {
                "backoffLimit": 0,
                "template": {
                    "spec": {
                        "restartPolicy": "Never",
                        "containers": [
                            {
                                "name": "bench",
                                "image": "busybox:1.36",
                                "command": ["sh", "-c", "exit 1"],
                            }
                        ],
                    }
                },
            },
        },
    }
    kubernetes.create_cron_job(name, namespace=kube_bench_namespace, spec=spec)
    try:
        yield {"name": name, "namespace": kube_bench_namespace}
    finally:
        kubernetes.delete_cron_job(name, namespace=kube_bench_namespace, wait=True)


def _write_cache(path):
    path.write_text(
        json.dumps(
            [
                {
                    "node_name": "node-a",
                    "tests": [
                        {
                            "results": [
                                {
                                    "test_number": "1.1.1",
                                    "status": "PASS",
                                    "actual_value": "enabled",
                                }
                            ]
                        }
                    ],
                },
                {
                    "node_name": "node-b",
                    "tests": [
                        {
                            "results": [
                                {
                                    "test_number": "1.1.1",
                                    "status": "FAIL",
                                    "reason": "disabled",
                                }
                            ]
                        }
                    ],
                },
            ]
        )
    )


def test_kube_bench_cache_ensure_fresh_uses_existing_cache(modules, tmp_path):
    """The module is loaded by Salt and preserves a fresh cache path."""
    cache_path = tmp_path / "kube-bench.json"
    _write_cache(cache_path)

    kube_bench_cache = modules.kube_bench_cache
    result = kube_bench_cache.ensure_fresh(
        cache_path=str(cache_path),
        ttl_seconds=900,
    )

    assert result == str(cache_path)
    assert json.loads(cache_path.read_text())[0]["node_name"] == "node-a"


def test_kube_bench_cache_status_for_check_aggregates_nodes(modules, tmp_path):
    """The loaded module reports the worst status across cached nodes."""
    cache_path = tmp_path / "kube-bench.json"
    _write_cache(cache_path)

    result = modules.kube_bench_cache.status_for_check(
        "1.1.1",
        cache_path=str(cache_path),
        ttl_seconds=900,
    )

    assert result["status"] == "FAIL"
    assert "node-a: PASS actual=enabled" in result["comment"]
    assert "node-b: FAIL actual=disabled" in result["comment"]


def test_kube_bench_cache_collects_from_daemonset(modules, kube_bench_daemonset, tmp_path):
    """DaemonSet collection reads pod logs and tags results with node names."""
    cache_path = tmp_path / "kube-bench-daemonset.json"
    kube_bench_cache = modules.kube_bench_cache

    result = kube_bench_cache.ensure_fresh(
        namespace=kube_bench_daemonset["namespace"],
        label="app=kube-bench",
        cache_path=str(cache_path),
        ttl_seconds=0,
        collection_strategy="daemonset",
    )

    sections = json.loads(cache_path.read_text())
    assert result == str(cache_path)
    assert len(sections) == 1
    assert sections[0]["id"] == "2.1.1"
    assert sections[0]["node_name"]

    status = kube_bench_cache.status_for_check(
        "2.1.1",
        namespace=kube_bench_daemonset["namespace"],
        label="app=kube-bench",
        cache_path=str(cache_path),
        ttl_seconds=900,
        collection_strategy="daemonset",
    )
    assert status["status"] == "PASS"


def test_kube_bench_cache_fails_without_matching_daemonset_pods(
    modules, kube_bench_namespace, tmp_path
):
    """DaemonSet collection reports a useful error when no pods match."""
    cache_path = tmp_path / "kube-bench-no-pods.json"

    with pytest.raises(RuntimeError, match="No pods found"):
        modules.kube_bench_cache.ensure_fresh(
            namespace=kube_bench_namespace,
            label="app=kube-bench",
            cache_path=str(cache_path),
            ttl_seconds=0,
            collection_strategy="daemonset",
        )

    assert not cache_path.exists()


def test_kube_bench_cache_run_assessment_collects_and_cleans_job(
    modules, kubernetes, kube_bench_cronjob, tmp_path
):
    """Job collection writes results and removes its generated assessment Job."""
    cache_path = tmp_path / "kube-bench-job.json"
    kube_bench_cache = modules.kube_bench_cache

    result = kube_bench_cache.run_assessment(
        namespace=kube_bench_cronjob["namespace"],
        cronjob_name=kube_bench_cronjob["name"],
        cache_path=str(cache_path),
        job_timeout=120,
    )

    assert result == {"result": True, "message": str(cache_path)}
    sections = json.loads(cache_path.read_text())
    assert sections
    assert sections[0]["id"] == "3.1.1"
    assert sections[0]["node_name"]
    assert kubernetes.jobs(namespace=kube_bench_cronjob["namespace"]) == []

    status = kube_bench_cache.status_for_check(
        "3.1.1",
        namespace=kube_bench_cronjob["namespace"],
        cache_path=str(cache_path),
        ttl_seconds=900,
    )
    assert status["status"] == "WARN"


def test_kube_bench_cache_refreshes_stale_cache(modules, kube_bench_cronjob, tmp_path):
    """A zero TTL forces Job collection while a later call reuses the cache."""
    cache_path = tmp_path / "kube-bench-refresh.json"
    cache_path.write_text(json.dumps([{"stale": True}]))
    kube_bench_cache = modules.kube_bench_cache

    result = kube_bench_cache.ensure_fresh(
        namespace=kube_bench_cronjob["namespace"],
        cronjob_name=kube_bench_cronjob["name"],
        cache_path=str(cache_path),
        ttl_seconds=0,
        job_timeout=120,
    )
    assert result == str(cache_path)
    assert json.loads(cache_path.read_text())[0]["id"] == "3.1.1"

    cache_path.write_text(json.dumps([{"cached": True}]))
    result = kube_bench_cache.ensure_fresh(
        namespace=kube_bench_cronjob["namespace"],
        cronjob_name=kube_bench_cronjob["name"],
        cache_path=str(cache_path),
        ttl_seconds=900,
        job_timeout=120,
    )
    assert result == str(cache_path)
    assert json.loads(cache_path.read_text()) == [{"cached": True}]


def test_kube_bench_cache_failed_assessment_cleans_up_job(
    modules, kubernetes, kube_bench_failing_cronjob, tmp_path
):
    """A failed assessment returns failure and removes its generated Job."""
    cache_path = tmp_path / "kube-bench-failed.json"

    result = modules.kube_bench_cache.run_assessment(
        namespace=kube_bench_failing_cronjob["namespace"],
        cronjob_name=kube_bench_failing_cronjob["name"],
        cache_path=str(cache_path),
        job_timeout=120,
    )

    assert result["result"] is False
    assert "failed" in result["message"]
    assert kubernetes.jobs(namespace=kube_bench_failing_cronjob["namespace"]) == []
    assert not cache_path.exists()


def test_kube_bench_cache_missing_cronjob_returns_failure(modules, tmp_path):
    """Assessment errors are returned without creating a cache file."""
    cache_path = tmp_path / "kube-bench-missing.json"
    result = modules.kube_bench_cache.run_assessment(
        namespace="default",
        cronjob_name=random_string("missing-kube-bench-", uppercase=False),
        cache_path=str(cache_path),
        job_timeout=30,
    )

    assert result["result"] is False
    assert "not found" in result["message"]
    assert not cache_path.exists()
