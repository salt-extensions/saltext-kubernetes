import logging
import sys
import time

import pytest

log = logging.getLogger(__name__)

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Only run on Linux platforms")


@pytest.fixture(scope="class")
def kubernetes_salt_master(salt_factories, pillar_tree, master_config):
    factory = salt_factories.salt_master_daemon("kube-master", defaults=master_config)
    with factory.started():
        yield factory


@pytest.fixture(scope="class")
def kubernetes_salt_minion(kubernetes_salt_master, minion_config):
    assert kubernetes_salt_master.is_running()
    factory = kubernetes_salt_master.salt_minion_daemon(
        "kube-minion",
        defaults=minion_config,
    )
    with factory.started():
        # Sync All
        salt_call_cli = factory.salt_call_cli()
        ret = salt_call_cli.run("saltutil.sync_all", _timeout=120)
        assert ret.returncode == 0, ret
        yield factory


@pytest.fixture(scope="class")
def salt_call_cli(kubernetes_salt_minion):
    return kubernetes_salt_minion.salt_call_cli()


@pytest.fixture(scope="class")
def kubernetes_pillar(pillar_tree, salt_call_cli, salt_run_cli, kind_cluster):
    """Setup kubernetes pillar data for tests"""
    pillar_data = {
        "kubernetes": {
            "kubeconfig": str(kind_cluster.kubeconfig_path),
            "context": "kind-salt-test",
        }
    }

    pillar_file = pillar_tree / "kubernetes.sls"
    pillar_file.write_text(
        f"""
kubernetes:
  kubeconfig: {pillar_data['kubernetes']['kubeconfig']}
  context: {pillar_data['kubernetes']['context']}
"""
    )

    # Sync and refresh pillar data
    salt_run_cli.run("saltutil.sync_all")
    salt_call_cli.run("saltutil.refresh_pillar")
    ret = salt_call_cli.run("saltutil.sync_all")
    assert ret.returncode == 0

    # Verify kubernetes module
    ret = salt_call_cli.run("sys.list_modules")
    assert ret.returncode == 0
    assert "kubernetes" in ret.data

    ret = salt_call_cli.run("sys.list_functions", "kubernetes")
    assert ret.returncode == 0
    assert ret.data, "No kubernetes functions found"
    assert "kubernetes.ping" in ret.data

    return pillar_data


class TestKubernetesModule:
    """
    Test basic kubernetes module functionality
    """

    def test_ping(self, salt_call_cli):
        """Test basic connectivity to kubernetes cluster"""
        ret = salt_call_cli.run("kubernetes.ping")
        assert ret.returncode == 0
        assert ret.data is True

    def test_list_deployments(self, salt_call_cli):
        """Test listing deployments"""
        ret = salt_call_cli.run("kubernetes.deployments")
        assert ret.returncode == 0
        assert isinstance(ret.data, list)

    def test_deployments(self, salt_call_cli):
        """Test creating and deleting a deployment"""
        deployment = {
            "metadata": {
                "name": "test-nginx",
                "namespace": "default",
                "labels": {"app": "test-nginx"},
            },
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "test-nginx"}},
                "template": {
                    "metadata": {"labels": {"app": "test-nginx"}},
                    "spec": {
                        "containers": [
                            {
                                "name": "nginx",
                                "image": "nginx:latest",
                                "ports": [{"containerPort": 80}],
                            }
                        ]
                    },
                },
            },
        }

        # Create deployment
        ret = salt_call_cli.run(
            "kubernetes.create_deployment",
            name=deployment["metadata"]["name"],
            namespace=deployment["metadata"]["namespace"],
            metadata=deployment["metadata"],
            spec=deployment["spec"],
            source="",
            template="",
            saltenv="base",
        )
        assert ret.returncode == 0
        assert ret.data

        # Verify deployment exists
        ret = salt_call_cli.run(
            "kubernetes.show_deployment",
            name=deployment["metadata"]["name"],
            namespace=deployment["metadata"]["namespace"],
        )
        assert ret.returncode == 0
        assert ret.data["metadata"]["name"] == deployment["metadata"]["name"]

        # Delete deployment
        ret = salt_call_cli.run(
            "kubernetes.delete_deployment",
            name=deployment["metadata"]["name"],
            namespace=deployment["metadata"]["namespace"],
        )
        assert ret.returncode == 0

        # Verify deployment is gone
        ret = salt_call_cli.run(
            "kubernetes.show_deployment",
            name=deployment["metadata"]["name"],
            namespace=deployment["metadata"]["namespace"],
        )
        assert ret.data is None

    def test_namespaces(self, salt_call_cli):
        """Test namespace operations"""
        test_ns = "test-namespace"

        try:
            # List namespaces
            ret = salt_call_cli.run("kubernetes.namespaces")
            assert ret.returncode == 0
            assert isinstance(ret.data, list)
            assert "default" in ret.data

            # Create namespace
            ret = salt_call_cli.run("kubernetes.create_namespace", name=test_ns)
            assert ret.returncode == 0
            # Verify namespace creation response
            assert isinstance(ret.data, dict)
            assert ret.data.get("metadata", {}).get("name") == test_ns
            assert ret.data.get("kind") == "Namespace"

            # Give the namespace time to be fully created
            time.sleep(5)  # Increased wait time

            # Show namespace
            ret = salt_call_cli.run("kubernetes.show_namespace", name=test_ns)
            assert ret.returncode == 0
            # Verify namespace details
            assert isinstance(ret.data, dict)
            assert ret.data.get("metadata", {}).get("name") == test_ns
            assert ret.data.get("kind") == "Namespace"
            assert ret.data.get("status", {}).get("phase") == "Active"

        finally:
            # Cleanup - delete namespace
            ret = salt_call_cli.run("kubernetes.delete_namespace", name=test_ns)
            assert ret.returncode == 0

            # Wait longer for deletion to complete
            time.sleep(10)  # Increased wait time

            # Verify namespace is gone
            ret = salt_call_cli.run("kubernetes.show_namespace", name=test_ns)
            assert ret.data is None

    def test_pods(self, salt_call_cli):
        """Test pod operations"""
        pod = {
            "metadata": {"name": "test-pod", "namespace": "default", "labels": {"app": "test"}},
            "spec": {
                "containers": [
                    {"name": "nginx", "image": "nginx:latest", "ports": [{"containerPort": 80}]}
                ]
            },
        }

        # List pods
        ret = salt_call_cli.run("kubernetes.pods")
        assert ret.returncode == 0
        assert isinstance(ret.data, list)

        # Create pod
        ret = salt_call_cli.run(
            "kubernetes.create_pod",
            name=pod["metadata"]["name"],
            namespace=pod["metadata"]["namespace"],
            metadata=pod["metadata"],
            spec=pod["spec"],
            source="",
            template="",
            saltenv="base",
        )
        assert ret.returncode == 0
        assert ret.data["metadata"]["name"] == pod["metadata"]["name"]

        # Allow pod to start
        time.sleep(5)

        # Show pod
        ret = salt_call_cli.run(
            "kubernetes.show_pod",
            name=pod["metadata"]["name"],
            namespace=pod["metadata"]["namespace"],
        )
        assert ret.returncode == 0
        assert ret.data["metadata"]["name"] == pod["metadata"]["name"]

        # Delete pod
        ret = salt_call_cli.run(
            "kubernetes.delete_pod",
            name=pod["metadata"]["name"],
            namespace=pod["metadata"]["namespace"],
        )
        assert ret.returncode == 0

        # Verify pod is gone
        time.sleep(5)
        ret = salt_call_cli.run(
            "kubernetes.show_pod",
            name=pod["metadata"]["name"],
            namespace=pod["metadata"]["namespace"],
        )
        assert ret.data is None

    def test_services(self, salt_call_cli):
        """Test service operations"""
        service = {
            "metadata": {"name": "test-service", "namespace": "default", "labels": {"app": "test"}},
            "spec": {
                "ports": [{"port": 80, "targetPort": 80, "name": "http"}],
                "selector": {"app": "test"},
                "type": "ClusterIP",
            },
        }

        # List services
        ret = salt_call_cli.run("kubernetes.services")
        assert ret.returncode == 0
        assert isinstance(ret.data, list)

        # Create service
        ret = salt_call_cli.run(
            "kubernetes.create_service",
            name=service["metadata"]["name"],
            namespace=service["metadata"]["namespace"],
            metadata=service["metadata"],
            spec=service["spec"],
            source="",
            template="",
            saltenv="base",
        )
        assert ret.returncode == 0
        assert ret.data["metadata"]["name"] == service["metadata"]["name"]

        # Show service
        ret = salt_call_cli.run(
            "kubernetes.show_service",
            name=service["metadata"]["name"],
            namespace=service["metadata"]["namespace"],
        )
        assert ret.returncode == 0
        assert ret.data["metadata"]["name"] == service["metadata"]["name"]

        # Delete service
        ret = salt_call_cli.run(
            "kubernetes.delete_service",
            name=service["metadata"]["name"],
            namespace=service["metadata"]["namespace"],
        )
        assert ret.returncode == 0

        # Verify service is gone
        ret = salt_call_cli.run(
            "kubernetes.show_service",
            name=service["metadata"]["name"],
            namespace=service["metadata"]["namespace"],
        )
        assert ret.data is None

    def test_configmaps(self, salt_call_cli):
        """Test configmap operations"""
        configmap_data = {
            "config.txt": "some configuration data",
            "other-file.txt": "other configuration data",
        }

        # List configmaps
        ret = salt_call_cli.run("kubernetes.configmaps")
        assert ret.returncode == 0
        assert isinstance(ret.data, list)

        # Create configmap
        ret = salt_call_cli.run(
            "kubernetes.create_configmap",
            name="test-config",
            namespace="default",
            data=configmap_data,
        )
        assert ret.returncode == 0
        assert ret.data["metadata"]["name"] == "test-config"

        # Show configmap
        ret = salt_call_cli.run(
            "kubernetes.show_configmap", name="test-config", namespace="default"
        )
        assert ret.returncode == 0
        assert ret.data["data"] == configmap_data

        # Delete configmap
        ret = salt_call_cli.run(
            "kubernetes.delete_configmap", name="test-config", namespace="default"
        )
        assert ret.returncode == 0

        # Verify configmap is gone
        ret = salt_call_cli.run(
            "kubernetes.show_configmap", name="test-config", namespace="default"
        )
        assert ret.data is None

    def test_secrets(self, salt_call_cli):
        """Test secret operations"""
        secret = {
            "metadata": {"name": "test-secret", "namespace": "default", "labels": {"app": "test"}},
            "type": "Opaque",
            "data": {"username": "admin", "password": "YWRtaW4xMjM="},  # base64 encoded "admin123"
        }

        # List secrets
        ret = salt_call_cli.run("kubernetes.secrets")
        assert ret.returncode == 0
        assert isinstance(ret.data, list)

        # Create secret
        ret = salt_call_cli.run(
            "kubernetes.create_secret",
            name=secret["metadata"]["name"],
            namespace=secret["metadata"]["namespace"],
            data=secret["data"],
            type=secret["type"],
        )
        assert ret.returncode == 0
        assert ret.data["metadata"]["name"] == secret["metadata"]["name"]

        # Show secret without decode
        ret = salt_call_cli.run(
            "kubernetes.show_secret",
            name=secret["metadata"]["name"],
            namespace=secret["metadata"]["namespace"],
            decode=False,
        )
        assert ret.returncode == 0
        assert ret.data["metadata"]["name"] == secret["metadata"]["name"]
        assert ret.data["data"]["password"] == secret["data"]["password"]

        # Show secret with decode
        ret = salt_call_cli.run(
            "kubernetes.show_secret",
            name=secret["metadata"]["name"],
            namespace=secret["metadata"]["namespace"],
            decode=True,
        )
        assert ret.returncode == 0
        assert ret.data["data"]["username"] == "admin"
        assert ret.data["data"]["password"] == "admin123"

        # Delete secret
        ret = salt_call_cli.run(
            "kubernetes.delete_secret",
            name=secret["metadata"]["name"],
            namespace=secret["metadata"]["namespace"],
        )
        assert ret.returncode == 0

        # Verify secret is gone
        ret = salt_call_cli.run(
            "kubernetes.show_secret",
            name=secret["metadata"]["name"],
            namespace=secret["metadata"]["namespace"],
        )
        assert ret.data is None
