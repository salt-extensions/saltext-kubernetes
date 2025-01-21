import logging
import os
import subprocess
import sys
import time

import pytest
from pytest_kind import KindCluster
from saltfactories.utils import random_string

from saltext.kubernetes import PACKAGE_ROOT

# Reset the root logger to its default level(because salt changed it)
logging.root.setLevel(logging.WARNING)

log = logging.getLogger(__name__)

# Supported Kubernetes versions for testing based on v0.25.0 of kind - kind v0.26.0 is latest
K8S_VERSIONS = [
    "v1.26.15",
    "v1.27.16",
    "v1.28.15",
    "v1.29.10",
    "v1.30.6",
    "v1.31.2",
]

# This swallows all logging to stdout.
# To show select logs, set --log-cli-level=<level>
for handler in logging.root.handlers[:]:  # pragma: no cover
    logging.root.removeHandler(handler)
    handler.close()


@pytest.fixture(scope="session")
def salt_factories_config():  # pragma: no cover
    """
    Return a dictionary with the keyword arguments for FactoriesManager
    """
    return {
        "code_dir": str(PACKAGE_ROOT),
        "inject_sitecustomize": "COVERAGE_PROCESS_START" in os.environ,
        "start_timeout": 120 if os.environ.get("CI") else 60,
    }


@pytest.fixture(scope="package")
def master_config():  # pragma: no cover
    """
    Salt master configuration overrides for integration tests.
    """
    return {}


@pytest.fixture(scope="package")
def master(salt_factories, master_config):  # pragma: no cover
    return salt_factories.salt_master_daemon(random_string("master-"), overrides=master_config)


@pytest.fixture(scope="package")
def minion_config():  # pragma: no cover
    """
    Salt minion configuration overrides for integration tests.
    """
    return {}


@pytest.fixture(scope="package")
def minion(master, minion_config):  # pragma: no cover
    return master.salt_minion_daemon(random_string("minion-"), overrides=minion_config)


@pytest.fixture(scope="module", params=K8S_VERSIONS)
@pytest.mark.skipif(sys.platform != "linux", reason="KinD tests only run on Linux platform")
def kind_cluster(request):  # pylint: disable=too-many-statements
    """Create Kind cluster for testing with specified Kubernetes version"""
    cluster = KindCluster(name="salt-test", image=f"kindest/node:{request.param}")
    try:
        cluster.create()

        # Initial wait for cluster to start
        time.sleep(5)

        # Wait for and validate cluster readiness using kubectl
        retries = 6
        context = "kind-salt-test"
        while retries > 0:
            try:
                # Verify cluster is accessible
                kubectl_cmd = [
                    "kubectl",
                    "--context",
                    context,
                    "--kubeconfig",
                    str(cluster.kubeconfig_path),
                ]

                subprocess.run(
                    kubectl_cmd + ["cluster-info"],
                    check=True,
                    capture_output=True,
                    text=True,
                )

                # Check node readiness
                nodes_output = subprocess.run(
                    kubectl_cmd
                    + [
                        "get",
                        "nodes",
                        "-o=jsonpath='{.items[*].status.conditions[?(@.type==\"Ready\")].status}'",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )

                if "True" not in nodes_output.stdout:
                    raise subprocess.CalledProcessError(1, "kubectl", "Nodes not ready")

                # Verify core services are running
                subprocess.run(
                    kubectl_cmd
                    + [
                        "wait",
                        "--for=condition=Ready",
                        "pods",
                        "--all",
                        "-n",
                        "kube-system",
                        "--timeout=60s",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                break
            except subprocess.CalledProcessError as exc:  # pylint: disable=try-except-raise
                retries -= 1
                if retries == 0:
                    log.error("Failed to validate cluster:")
                    log.error("stdout: %s", exc.stdout)
                    log.error("stderr: %s", exc.stderr)
                    raise
                time.sleep(5)

        yield cluster
    finally:
        try:
            cluster.delete()
        except Exception:  # pylint: disable=broad-except
            log.error("Failed to delete cluster", exc_info=True)
