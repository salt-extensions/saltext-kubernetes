import logging
import os
import subprocess
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


@pytest.fixture(scope="package")
def pillar_tree(tmp_path_factory):
    """
    Create a pillar tree in a temporary directory.
    """
    pillar_tree = tmp_path_factory.mktemp("pillar")
    top_file = pillar_tree / "top.sls"
    kubernetes_file = pillar_tree / "kubernetes.sls"

    # Create default top file
    top_file.write_text(
        """
base:
  '*':
    - kubernetes
"""
    )

    # Create empty kubernetes pillar file
    kubernetes_file.write_text("")

    return pillar_tree


@pytest.fixture(scope="session")
def salt_factories_config():
    """Return a dictionary with the keyword arguments for FactoriesManager"""
    return {
        "code_dir": str(PACKAGE_ROOT),
        "start_timeout": 120 if os.environ.get("CI") else 60,
    }


@pytest.fixture(scope="module")
def master_config_defaults(kind_cluster):
    """Default master configuration for kubernetes tests"""
    return {
        "pillar_roots": {"base": []},
        "open_mode": True,
        "timeout": 120,
    }


@pytest.fixture(scope="module")
def master_config_overrides():
    """Override the default configuration per package"""
    return {}


@pytest.fixture(scope="module")
def master(salt_factories, master_config_defaults, master_config_overrides):
    return salt_factories.salt_master_daemon(
        random_string("master-"), defaults=master_config_defaults, overrides=master_config_overrides
    )


@pytest.fixture(scope="module")
def minion_config_defaults(kind_cluster):
    """Default minion configuration for kubernetes tests"""
    return {
        "kubernetes.kubeconfig": str(kind_cluster.kubeconfig_path),
        "kubernetes.context": "kind-salt-test",
        "file_roots": {"base": [str(PACKAGE_ROOT)]},
        "providers": {"pkg": "kubernetes"},
        "open_mode": True,
    }


@pytest.fixture(scope="module")
def minion_config_overrides():
    """Override the default configuration per package"""
    return {}


@pytest.fixture(scope="module")
def minion(master, minion_config_defaults, minion_config_overrides):
    return master.salt_minion_daemon(
        random_string("minion-"), defaults=minion_config_defaults, overrides=minion_config_overrides
    )


@pytest.fixture(scope="session", params=K8S_VERSIONS)
def kind_cluster(request):  # pylint: disable=too-many-statements
    """Create Kind cluster for testing with specified Kubernetes version"""
    cluster = KindCluster(name="salt-test", image=f"kindest/node:{request.param}")
    try:
        cluster.create()

        # Initial wait for cluster to start
        time.sleep(10)

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
                break
            except subprocess.CalledProcessError as exc:  # pylint: disable=try-except-raise
                retries -= 1
                if retries == 0:
                    log.error("Failed to validate cluster:")
                    log.error("stdout: %s", exc.stdout)
                    log.error("stderr: %s", exc.stderr)
                    raise
                time.sleep(10)

        yield cluster
    finally:
        try:
            cluster.delete()
        except Exception:  # pylint: disable=broad-except
            log.error("Failed to delete cluster", exc_info=True)


@pytest.fixture(scope="module")
def base_env_state_tree_root_dir(tmp_path_factory):
    """
    Return the base environment state tree root directory
    """
    state_tree = tmp_path_factory.mktemp("base_state_tree")
    return state_tree
