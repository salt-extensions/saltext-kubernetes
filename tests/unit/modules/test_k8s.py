"""
Unit Tests for the k8s execution module.
"""

import base64
import hashlib
import time
from subprocess import PIPE
from subprocess import Popen
from subprocess import run

import pytest
import salt.utils.files
import salt.utils.json

from saltext.kubernetes.modules import k8s

pytestmark = [
    pytest.mark.skip_if_binaries_missing("kubectl"),
]

pytest.skip(reason="Broken tests. Overhaul required.", allow_module_level=True)


def test_get_namespaces():
    res = k8s.get_namespaces(apiserver_url="http://127.0.0.1:8080")
    a = len(res.get("items", []))
    with Popen(["kubectl", "get", "namespaces", "-o", "json"], stdout=PIPE) as proc:
        kubectl_out = salt.utils.json.loads(proc.communicate()[0])
    b = len(kubectl_out.get("items", []))
    assert a == b


def test_get_one_namespace():
    res = k8s.get_namespaces("default", apiserver_url="http://127.0.0.1:8080")
    a = res.get("metadata", {}).get("name", "a")
    with Popen(["kubectl", "get", "namespaces", "default", "-o", "json"], stdout=PIPE) as proc:
        kubectl_out = salt.utils.json.loads(proc.communicate()[0])
    b = kubectl_out.get("metadata", {}).get("name", "b")
    assert a == b


def test_create_namespace():
    hsh = hashlib.sha1()  # nosec
    hsh.update(str(time.time()).encode())
    nsname = hsh.hexdigest()[:16]
    k8s.create_namespace(nsname, apiserver_url="http://127.0.0.1:8080")
    with Popen(["kubectl", "get", "namespaces", nsname, "-o", "json"], stdout=PIPE) as proc:
        kubectl_out = salt.utils.json.loads(proc.communicate()[0])
    # if creation is failed, kubernetes return non json error message
    assert isinstance(kubectl_out, dict)


def test_get_secrets():
    res = k8s.get_secrets("default", apiserver_url="http://127.0.0.1:8080")
    a = len(res.get("items", []))
    with Popen(
        ["kubectl", "--namespace=default", "get", "secrets", "-o", "json"],
        stdout=PIPE,
    ) as proc:
        kubectl_out = salt.utils.json.loads(proc.communicate()[0])
    b = len(kubectl_out.get("items", []))
    assert a == b


@pytest.fixture()
def secret_name():
    hsh = hashlib.sha1()  # nosec
    hsh.update(str(time.time()).encode())
    return hsh.hexdigest()[:16]


@pytest.fixture()
def secret(secret_name):
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": secret_name, "namespace": "default"},
        "data": {"testsecret": str(base64.encodebytes(b"teststring"))},
    }


def test_get_one_secret(secret_name, secret):
    name = secret_name
    filename = f"/tmp/{name}.json"
    with salt.utils.files.fopen(filename, "w") as f:
        salt.utils.json.dump(secret, f)

    run(["kubectl", "--namespace=default", "create", "-f", filename], check=True)
    # we need to give kubernetes time save data in etcd
    time.sleep(0.1)
    res = k8s.get_secrets("default", name, apiserver_url="http://127.0.0.1:8080")
    a = res.get("metadata", {}).get("name", "a")
    with Popen(
        ["kubectl", "--namespace=default", "get", "secrets", name, "-o", "json"],
        stdout=PIPE,
    ) as proc:
        kubectl_out = salt.utils.json.loads(proc.communicate()[0])
    b = kubectl_out.get("metadata", {}).get("name", "b")
    assert a == b


def test_get_decoded_secret(secret_name, secret):
    name = secret_name
    filename = f"/tmp/{name}.json"
    with salt.utils.files.fopen(filename, "w") as f:
        salt.utils.json.dump(secret, f)

    run(["kubectl", "--namespace=default", "create", "-f", filename], check=True)
    # we need to give etcd to populate data on all nodes
    time.sleep(0.1)
    res = k8s.get_secrets("default", name, apiserver_url="http://127.0.0.1:8080", decode=True)
    a = res.get("data", {}).get(
        "testsecret",
    )
    assert a == "teststring"


def test_create_secret(secret_name):
    name = secret_name
    names = []
    expected_data = {}
    for i in range(2):
        names.append(f"/tmp/{name}-{i}")
        with salt.utils.files.fopen(f"/tmp/{name}-{i}", "w") as f:
            expected_data[f"{name}-{i}"] = base64.b64encode(f"{name}{i}")
            f.write(salt.utils.stringutils.to_str(f"{name}{i}"))
    k8s.create_secret("default", name, names, apiserver_url="http://127.0.0.1:8080")
    with Popen(
        ["kubectl", "--namespace=default", "get", "secrets", name, "-o", "json"],
        stdout=PIPE,
    ) as proc:
        kubectl_out = salt.utils.json.loads(proc.communicate()[0])
    # if creation is failed, kubernetes return non json error message
    b = kubectl_out.get("data", {})
    assert isinstance(kubectl_out, dict)
    assert b == expected_data


def test_update_secret(secret_name, secret):
    name = secret_name
    filename = f"/tmp/{name}.json"
    with salt.utils.files.fopen(filename, "w") as f:
        salt.utils.json.dump(secret, f)

    run(["kubectl", "--namespace=default", "create", "-f", filename], check=True)
    # wee need to give kubernetes time save data in etcd
    time.sleep(0.1)
    expected_data = {}
    names = []
    for i in range(3):
        names.append(f"/tmp/{name}-{i}-updated")
        with salt.utils.files.fopen(f"/tmp/{name}-{i}-updated", "w") as f:
            expected_data[f"{name}-{i}-updated"] = base64.b64encode(f"{name}{i}-updated")
            f.write(f"{name}{i}-updated")

    k8s.update_secret("default", name, names, apiserver_url="http://127.0.0.1:8080")
    # if creation is failed, kubernetes return non json error message
    with Popen(
        ["kubectl", "--namespace=default", "get", "secrets", name, "-o", "json"],
        stdout=PIPE,
    ) as proc:
        kubectl_out = salt.utils.json.loads(proc.communicate()[0])
    # if creation is failed, kubernetes return non json error message
    b = kubectl_out.get("data", {})
    assert isinstance(kubectl_out, dict)
    assert b == expected_data


def test_delete_secret(secret_name, secret):
    name = secret_name
    filename = f"/tmp/{name}.json"
    with salt.utils.files.fopen(filename, "w") as f:
        salt.utils.json.dump(secret, f)

    run(["kubectl", "--namespace=default", "create", "-f", filename], check=True)
    # wee need to give kubernetes time save data in etcd
    time.sleep(0.1)
    k8s.delete_secret("default", name, apiserver_url="http://127.0.0.1:8080")
    time.sleep(0.1)
    with Popen(
        ["kubectl", "--namespace=default", "get", "secrets", name, "-o", "json"],
        stdout=PIPE,
        stderr=PIPE,
    ) as proc:
        kubectl_out, err = proc.communicate()
    # stdout is empty, stderr is showing something like "not found"
    assert kubectl_out == b""
    assert err == f'Error from server: secrets "{name}" not found\n'
