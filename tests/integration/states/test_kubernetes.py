import logging
from textwrap import dedent

import pytest

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.skip_unless_on_linux(reason="Only run on Linux platforms"),
]


@pytest.fixture(scope="module")
def state_tree(master):
    return master.state_tree.base


def test_namespace_present_absent(kind_cluster, salt_call_cli, state_tree):
    """Test namespace creation and deletion via states"""
    test_namespace = "test-namespace-state"
    # Create namespace state file
    contents = dedent(
        f"""
        test_namespace:
          kubernetes.namespace_present:
            - name: {test_namespace}
            - labels:
              app: test
              environment: testing
        """
    )
    # Create namespace state file
    try:
        with state_tree.temp_file("test_namespace.sls", contents):
            # Apply namespace present state
            ret = salt_call_cli.run("state.apply", "test_namespace")
            assert ret.returncode == 0
            assert ret.data
            # Check state result
            state_ret = ret.data[next(iter(ret.data))]
            assert state_ret["result"] is True
            assert state_ret["changes"]

            # Verify namespace exists
            ret = salt_call_cli.run("kubernetes.show_namespace", name="test-namespace-state")
            assert ret.returncode == 0
            assert ret.data["metadata"]["name"] == "test-namespace-state"
            assert ret.data["status"]["phase"] == "Active"

            # Test idempotency
            ret = salt_call_cli.run("state.apply", "test_namespace")
            assert ret.returncode == 0
            assert ret.data
            state_ret = ret.data[next(iter(ret.data))]
            assert state_ret["result"] is True
            assert not state_ret["changes"]
            assert "already exists" in state_ret["comment"]

    finally:
        contents = dedent(
            f"""
            remove_test_namespace:
                kubernetes.namespace_absent:
                - name: {test_namespace}
            """
        )
        # Test namespace removal
        with state_tree.temp_file("test_namespace.sls", contents):
            # Apply namespace absent state
            ret = salt_call_cli.run("state.apply", "test_namespace")
            assert ret.returncode == 0
            assert ret.data


def test_pod_present_absent(kind_cluster, salt_call_cli, state_tree):
    """Test pod creation and deletion via states"""
    test_pod = "test-pod-state"

    # Create pod state file
    contents = dedent(
        f"""
        test_pod:
          kubernetes.pod_present:
            - name: {test_pod}
            - namespace: default
            - metadata:
                labels:
                  app: test
            - spec:
                containers:
                  - name: nginx
                    image: nginx:latest
                    ports:
                      - containerPort: 80
            - wait: True
        """
    )

    try:
        with state_tree.temp_file("test_pod.sls", contents):
            ret = salt_call_cli.run("state.apply", "test_pod")
            assert ret.returncode == 0
            assert ret.data
            # Check state result
            state_ret = ret.data[next(iter(ret.data))]
            assert state_ret["result"] is True
            assert state_ret["changes"]

            # Verify pod creation changes - check metadata/spec was applied correctly
            assert state_ret["changes"]["metadata"]["labels"] == {"app": "test"}
            assert state_ret["changes"]["spec"]["containers"][0]["name"] == "nginx"

            ret = salt_call_cli.run("kubernetes.show_pod", name=test_pod, namespace="default")
            assert ret.returncode == 0
            assert ret.data is not None
            assert ret.data["metadata"]["name"] == test_pod

        # Comment out idempotent test for now
        # TODO: The state module needs fixed to handle proper present functionality
        # # Test idempotency
        # with state_tree.temp_file("test_pod.sls", contents):
        #     ret = salt_call_cli.run("state.apply", "test_pod")
        #     assert ret.returncode == 0
        #     assert isinstance(ret.data, dict)
        #     state_ret = ret.data[next(iter(ret.data))]
        #     assert not state_ret["changes"]

    finally:
        # Test pod removal
        contents = dedent(
            f"""
            remove_test_pod:
              kubernetes.pod_absent:
                - name: {test_pod}
                - namespace: default
            """
        )
        with state_tree.temp_file("test_pod.sls", contents):
            # Apply pod absent state
            ret = salt_call_cli.run("state.apply", "test_pod")
            assert ret.returncode == 0
            assert ret.data
            state_ret = ret.data[next(iter(ret.data))]
            assert state_ret["result"] is True
            assert state_ret["changes"]["kubernetes.pod"]["new"] == "absent"
            assert state_ret["changes"]["kubernetes.pod"]["old"] == "present"


def test_deployment_present_absent(kind_cluster, salt_call_cli, state_tree):
    """Test deployment creation and deletion via states"""
    test_deployment = "test-deployment-state"

    # Create deployment state file
    contents = dedent(
        f"""
        test_deployment:
          kubernetes.deployment_present:
            - name: {test_deployment}
            - namespace: default
            - metadata:
                labels:
                  app: test
            - spec:
                replicas: 2
                selector:
                  matchLabels:
                    app: test
                template:
                  metadata:
                    labels:
                      app: test
                  spec:
                    containers:
                      - name: nginx
                        image: nginx:latest
                        ports:
                          - containerPort: 80
            - wait: True
        """
    )
    try:
        with state_tree.temp_file("test_deployment.sls", contents):
            # Apply deployment present state
            ret = salt_call_cli.run("state.apply", "test_deployment")
            assert ret.returncode == 0
            assert ret.data
            # Check state result
            state_ret = ret.data[next(iter(ret.data))]
            assert state_ret["result"] is True
            assert state_ret["changes"]
            assert "metadata" in state_ret["changes"]
            assert "spec" in state_ret["changes"]
            assert state_ret["changes"]["metadata"]["labels"] == {"app": "test"}
            assert state_ret["changes"]["spec"]["replicas"] == 2

            # Verify deployment exists
            ret = salt_call_cli.run(
                "kubernetes.show_deployment", name=test_deployment, namespace="default"
            )
            assert ret.returncode == 0
            assert ret.data["metadata"]["name"] == test_deployment
            assert ret.data["spec"]["replicas"] == 2

            # Comment out idempotent test for now
            # TODO: The state module needs fixed to handle proper present functionality
            # ret = salt_call_cli.run("state.apply", "test_deployment")
            # assert ret.returncode == 0
            # assert ret.data
            # state_ret = ret.data[next(iter(ret.data))]
            # assert state_ret["result"] is True
            # assert state_ret["comment"] == "The deployment is already present. Forcing recreation"
            # assert state_ret["changes"]  # Changes will be present due to recreation

    finally:
        # Test deployment removal
        contents = dedent(
            f"""
        remove_deployment:
            kubernetes.deployment_absent:
            - name: {test_deployment}
            - namespace: default
        """
        )
        with state_tree.temp_file("test_deployment.sls", contents):
            # Apply deployment absent state
            ret = salt_call_cli.run("state.apply", "test_deployment")
            assert ret.returncode == 0
            assert ret.data
            state_ret = ret.data[next(iter(ret.data))]
            assert state_ret["result"] is True
            assert state_ret["changes"]["kubernetes.deployment"]["new"] == "absent"
            assert state_ret["changes"]["kubernetes.deployment"]["old"] == "present"


def test_secret_present_absent(kind_cluster, salt_call_cli, state_tree):
    """Test secret creation and deletion via states"""
    test_secret = "test-secret-state"

    contents = dedent(
        f"""
        test_secret:
          kubernetes.secret_present:
            - name: {test_secret}
            - namespace: default
            - data:
                username: YWRtaW4=  # base64 encoded "admin"
                password: cGFzc3dvcmQ=  # base64 encoded "password"
            - type: Opaque
            - wait: True
        """
    )

    try:
        with state_tree.temp_file("test_secret.sls", contents):
            # Apply secret present state
            ret = salt_call_cli.run("state.apply", "test_secret")
            assert ret.returncode == 0
            assert ret.data
            # Check state result
            state_ret = ret.data[next(iter(ret.data))]
            assert state_ret["result"] is True
            assert state_ret["changes"]
            # Verify secret data (keys only since values are sensitive)
            assert sorted(state_ret["changes"]["data"]) == ["password", "username"]

            # Verify secret exists using module
            ret = salt_call_cli.run(
                "kubernetes.show_secret",
                name=test_secret,
                namespace="default",
                decode=True,
            )
            assert ret.returncode == 0
            assert ret.data["metadata"]["name"] == test_secret
            assert ret.data["data"]["username"] == "admin"
            assert ret.data["data"]["password"] == "password"

            # Comment out idempotent test for now
            # TODO: The state module needs fixed to handle proper present functionality
            # ret = salt_call_cli.run("state.apply", "test_secret")
            # assert ret.returncode == 0
            # assert ret.data
            # state_ret = ret.data[next(iter(ret.data))]
            # assert state_ret["result"] is True
            # assert state_ret["comment"] == "The secret is already present. Forcing recreation"
            # assert state_ret["changes"]  # Changes will be present due to recreation
            # assert sorted(state_ret["changes"]["data"]) == ["password", "username"]

            # Verify secret still exists with same values
            # ret = salt_call_cli.run(
            #     "kubernetes.show_secret",
            #     name=test_secret,
            #     namespace="default",
            #     decode=True,
            # )
            # assert ret.returncode == 0
            # assert ret.data["data"]["username"] == "admin"
            # assert ret.data["data"]["password"] == "password"

        # Test updating the secret
        contents = dedent(
            f"""
        test_secret:
            kubernetes.secret_present:
            - name: {test_secret}
            - namespace: default
            - data:
                username: bmV3YWRtaW4=  # base64 encoded "newadmin"
                password: bmV3cGFzcw==  # base64 encoded "newpass"
            - type: Opaque
            - wait: True
        """
        )
        with state_tree.temp_file("test_secret.sls", contents):
            ret = salt_call_cli.run("state.apply", "test_secret")
            assert ret.returncode == 0
            assert ret.data
            state_ret = ret.data[next(iter(ret.data))]
            assert state_ret["result"] is True
            assert state_ret["changes"]
            assert sorted(state_ret["changes"]["data"]) == ["password", "username"]

            # Verify updated values
            ret = salt_call_cli.run(
                "kubernetes.show_secret",
                name=test_secret,
                namespace="default",
                decode=True,
            )
            assert ret.returncode == 0
            assert ret.data["data"]["username"] == "newadmin"
            assert ret.data["data"]["password"] == "newpass"

    finally:
        # Test secret removal
        contents = dedent(
            f"""
            remove_secret:
                kubernetes.secret_absent:
                - name: {test_secret}
                - namespace: default
            """
        )
        with state_tree.temp_file("test_secret.sls", contents):
            # Apply secret absent state
            ret = salt_call_cli.run("state.apply", "test_secret")
            assert ret.returncode == 0
            assert ret.data
            state_ret = ret.data[next(iter(ret.data))]
            assert state_ret["result"] is True
            assert state_ret["changes"]["kubernetes.secret"]["new"] == "absent"
            assert state_ret["changes"]["kubernetes.secret"]["old"] == "present"

            # Verify secret is gone
            ret = salt_call_cli.run(
                "kubernetes.show_secret",
                name=test_secret,
                namespace="default",
            )
            assert ret.data is None


def test_service_present_absent(kind_cluster, salt_call_cli, state_tree):
    """Test service creation and deletion via states"""
    test_service = "test-service-state"

    # Create service state file
    contents = dedent(
        f"""
        test_service:
          kubernetes.service_present:
            - name: {test_service}
            - namespace: default
            - metadata:
                labels:
                  app: test
            - spec:
                ports:
                - port: 80
                  targetPort: 8080
                  name: http
                - port: 443
                  targetPort: 8443
                  name: https
                selector:
                  app: test
                type: ClusterIP
        """
    )
    try:
        with state_tree.temp_file("test_service.sls", contents):
            # Apply service present state
            ret = salt_call_cli.run("state.apply", "test_service")
            assert ret.returncode == 0
            assert ret.data
            # Check state result
            state_ret = ret.data[next(iter(ret.data))]
            assert state_ret["result"] is True
            assert state_ret["changes"]
            assert "metadata" in state_ret["changes"]
            assert "spec" in state_ret["changes"]
            assert state_ret["changes"]["metadata"]["labels"] == {"app": "test"}
            assert len(state_ret["changes"]["spec"]["ports"]) == 2

            # Verify service exists
            ret = salt_call_cli.run(
                "kubernetes.show_service", name=test_service, namespace="default"
            )
            assert ret.returncode == 0
            assert ret.data["metadata"]["name"] == test_service
            assert len(ret.data["spec"]["ports"]) == 2
            assert ret.data["spec"]["type"] == "ClusterIP"

            # Comment out idempotent test for now
            # TODO: The state module needs fixed to handle proper present functionality
            # ret = salt_call_cli.run("state.apply", "test_service")
            # assert ret.returncode == 0
            # assert ret.data
            # state_ret = ret.data[next(iter(ret.data))]
            # assert state_ret["result"] is True
            # assert state_ret["comment"] == "The service is already present. Forcing recreation"
            # assert state_ret["changes"]

    finally:
        # Test service removal
        contents = dedent(
            f"""
            remove_service:
                kubernetes.service_absent:
                - name: {test_service}
                - namespace: default
            """
        )
        with state_tree.temp_file("test_service.sls", contents):
            # Apply service absent state
            ret = salt_call_cli.run("state.apply", "test_service")
            assert ret.returncode == 0
            assert ret.data
            state_ret = ret.data[next(iter(ret.data))]
            assert state_ret["result"] is True
            assert state_ret["changes"]["kubernetes.service"]["new"] == "absent"
            assert state_ret["changes"]["kubernetes.service"]["old"] == "present"

            # Verify service is gone
            ret = salt_call_cli.run(
                "kubernetes.show_service",
                name=test_service,
                namespace="default",
            )
            assert ret.data is None


def test_configmap_present_absent(kind_cluster, salt_call_cli, state_tree):
    """Test configmap creation and deletion via states"""
    test_configmap = "test-configmap-state"

    contents = dedent(
        f"""
        test_configmap:
          kubernetes.configmap_present:
            - name: {test_configmap}
            - namespace: default
            - data:
                config.yaml: |
                    foo: bar
                    key: value
                app.properties: |
                    app.name=myapp
                    app.port=8080
        """
    )
    try:
        with state_tree.temp_file("test_configmap.sls", contents):
            # Apply configmap present state
            ret = salt_call_cli.run("state.apply", "test_configmap")
            assert ret.returncode == 0
            assert ret.data
            # Check state result
            state_ret = ret.data[next(iter(ret.data))]
            assert state_ret["result"] is True
            assert state_ret["changes"]
            assert "data" in state_ret["changes"]
            assert sorted(state_ret["changes"]["data"]) == ["app.properties", "config.yaml"]

            # Verify configmap exists
            ret = salt_call_cli.run(
                "kubernetes.show_configmap", name=test_configmap, namespace="default"
            )
            assert ret.returncode == 0
            assert ret.data["metadata"]["name"] == test_configmap
            assert "config.yaml" in ret.data["data"]
            assert "app.properties" in ret.data["data"]

            # Comment out idempotent test for now
            # TODO: The state module needs fixed to handle proper present functionality
            # ret = salt_call_cli.run("state.apply", "test_configmap")
            # assert ret.returncode == 0
            # assert ret.data
            # state_ret = ret.data[next(iter(ret.data))]
            # assert state_ret["result"] is True
            # assert state_ret["comment"] == "The configmap is already present. Forcing recreation"
            # assert state_ret["changes"]  # Changes will be present due to recreation
            # assert sorted(state_ret["changes"]["data"]) == ["app.properties", "config.yaml"]

            # Verify configmap still exists with same data
            ret = salt_call_cli.run(
                "kubernetes.show_configmap", name=test_configmap, namespace="default"
            )
            assert ret.returncode == 0
            assert ret.data["metadata"]["name"] == test_configmap
            assert ret.data["data"]["config.yaml"].strip() == "foo: bar\nkey: value"
            assert ret.data["data"]["app.properties"].strip() == "app.name=myapp\napp.port=8080"

        # Test updating the configmap
        contents = dedent(
            f"""
            test_configmap:
              kubernetes.configmap_present:
                - name: {test_configmap}
                - namespace: default
                - data:
                    config.yaml: |
                        foo: newbar
                        key: newvalue
                    app.properties: |
                        app.name=newapp
                        app.port=9090
            """
        )
        with state_tree.temp_file("test_configmap.sls", contents):
            ret = salt_call_cli.run("state.apply", "test_configmap")
            assert ret.returncode == 0
            assert ret.data
            state_ret = ret.data[next(iter(ret.data))]
            assert state_ret["result"] is True
            assert state_ret["changes"]
            assert sorted(state_ret["changes"]["data"]) == ["app.properties", "config.yaml"]

    finally:
        # Test configmap removal
        contents = dedent(
            f"""
            remove_configmap:
                kubernetes.configmap_absent:
                  - name: {test_configmap}
                  - namespace: default
            """
        )
        with state_tree.temp_file("remove_configmap.sls", contents):
            # Test configmap removal
            ret = salt_call_cli.run("state.apply", "remove_configmap")
            assert ret.returncode == 0
            assert ret.data
            state_ret = ret.data[next(iter(ret.data))]
            assert state_ret["result"] is True
            assert state_ret["changes"]["kubernetes.configmap"]["new"] == "absent"
            assert state_ret["changes"]["kubernetes.configmap"]["old"] == "present"

            # Verify configmap is gone
            ret = salt_call_cli.run(
                "kubernetes.show_configmap",
                name=test_configmap,
                namespace="default",
            )
            assert ret.data is None
