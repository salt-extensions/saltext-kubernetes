import logging
import os
import subprocess

import pytest
from pytest_kind import KindCluster
from saltfactories.utils import random_string

from saltext.kubernetes import PACKAGE_ROOT

# Reset the root logger to its default level(because salt changed it)
logging.root.setLevel(logging.WARNING)

log = logging.getLogger(__name__)

# Kubernetes API server versions exercised by the functional tier. The
# floor is the oldest ``kindest/node`` image the current ``kind``
# release ships; the ceiling is its default. Bracketing these catches
# K8s API surface drift independently of the kubernetes-client Python
# package version range (24+ through 36+) the extension supports via
# the version-compat shims in :py:mod:`saltext.kubernetes.modules.kubernetesmod`.
#
# Bump this list as ``kind`` rolls in newer ``kindest/node`` images
# (kind v0.32.x is expected to add a v1.36 image once K8s 1.36 GAs).
# Lower kubernetes version commented out to reduce test run times
K8S_VERSIONS = [
    # "v1.30.13",
    "v1.35.0",
]  # pragma: no cover

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


@pytest.fixture(scope="module")
def master_config():  # pragma: no cover
    """
    Salt master configuration overrides for integration tests.
    """
    return {}


@pytest.fixture(scope="module")
def master(salt_factories, master_config):  # pragma: no cover
    return salt_factories.salt_master_daemon(random_string("master-"), overrides=master_config)


@pytest.fixture(scope="module")
def minion_config(kind_cluster):  # pragma: no cover
    """
    Salt minion configuration overrides for integration tests.
    """
    return {
        "kubernetes.kubeconfig": str(kind_cluster.kubeconfig_path),
        "kubernetes.context": "kind-salt-test",
    }


@pytest.fixture(scope="module")
def minion(master, minion_config):  # pragma: no cover
    return master.salt_minion_daemon(random_string("minion-"), overrides=minion_config)


@pytest.fixture(scope="session", params=K8S_VERSIONS)
def kind_cluster(request):  # pragma: no cover
    """
    Create Kind cluster for testing with specified Kubernetes version
    """
    cluster = KindCluster(name="salt-test", image=f"kindest/node:{request.param}")
    err = None
    try:
        cluster.create()

        # Wait for and validate cluster readiness using kubectl
        retries = 5
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

                # Wait longer for node readiness
                subprocess.run(
                    kubectl_cmd
                    + ["wait", "--for=condition=ready", "nodes", "--all", "--timeout=120s"],
                    check=True,
                    capture_output=True,
                    text=True,
                )

                # Verify core services are running with longer timeout
                subprocess.run(
                    kubectl_cmd
                    + [
                        "wait",
                        "--for=condition=Ready",
                        "pods",
                        "--all",
                        "-n",
                        "kube-system",
                        "--timeout=120s",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )

                # Install cert-manager so the Ingress+TLS scenario tests
                # (and any future CRD-driven cert-manager tests) have the
                # controllers available. Pinned to a known-good release;
                # bump alongside ``cert-manager`` upstream as needed.
                log.info("Installing cert-manager in kind cluster")
                subprocess.run(
                    kubectl_cmd
                    + [
                        "apply",
                        "-f",
                        "https://github.com/cert-manager/cert-manager/releases/download"
                        "/v1.20.2/cert-manager.yaml",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                subprocess.run(
                    kubectl_cmd
                    + [
                        "wait",
                        "--for=condition=Ready",
                        "pods",
                        "--all",
                        "-n",
                        "cert-manager",
                        "--timeout=180s",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                log.info("cert-manager ready")
                break
            except subprocess.CalledProcessError as exc:  # pylint: disable=try-except-raise
                retries -= 1
                err = exc
        else:
            log.error("Failed to validate cluster:")
            log.error("stdout: %s", err.stdout)
            log.error("stderr: %s", err.stderr)
            raise err

        yield cluster
    finally:
        try:
            cluster.delete()
        except Exception:  # pylint: disable=broad-except
            log.error("Failed to delete cluster", exc_info=True)
