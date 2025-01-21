import logging
import os

import pytest
from pytest_kind import KindCluster
from saltfactories.utils import random_string

from saltext.kubernetes import PACKAGE_ROOT

# Reset the root logger to its default level(because salt changed it)
logging.root.setLevel(logging.WARNING)

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


@pytest.mark.skip_unless_on_linux
@pytest.fixture(scope="module", params=K8S_VERSIONS)
def kind_cluster(request):
    """Create Kind cluster for testing with specified Kubernetes version"""
    cluster = KindCluster(name="salt-test", image=f"kindest/node:{request.param}")
    try:
        cluster.create()
        yield cluster
    finally:
        cluster.delete()
