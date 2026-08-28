"""Regression test for: sourced Secrets silently lose their ``type``.

DEFECT
------
``kubernetes.create_secret`` and ``kubernetes.replace_secret`` both do this when
``source=`` is supplied (``modules/kubernetesmod.py``)::

    if source:
        src_obj = __read_and_render_yaml_file(source, template, saltenv, template_context)
        if "data" in src_obj:
            data = src_obj["data"]
        secret_type = src_obj.get("secret_type")   # <-- unconditional overwrite

A real Kubernetes Secret manifest declares its type under the ``type`` key, not
``secret_type``. So ``src_obj.get("secret_type")`` is ``None`` for every valid
manifest, and two things go wrong:

1. The manifest's own ``type:`` is ignored.
2. A ``secret_type=`` argument passed explicitly to the state is discarded,
   because the assignment is unconditional rather than a fallback.

Either way the secret is created as ``Opaque``.

IMPACT
------
``kubernetes.io/tls`` and ``kubernetes.io/dockerconfigjson`` secrets cannot be
managed from a manifest at all. A TLS secret that lands as ``Opaque`` is not
rejected by the API, so the failure is silent: ingress controllers and kubelet
volume projection simply do not find the cert material where they expect it.

WHY IT WAS NOT CAUGHT
---------------------
The existing ``test_secret_present_template_context`` renders ``type:
{{ secret_type }}`` and asserts ``secret_state["type"] == "Opaque"``. Opaque is
the default, so the assertion passes whether or not the type is honoured.

SUGGESTED FIX
-------------
Read the Kubernetes field, and only fall back when the caller gave nothing::

    if "type" in src_obj:
        secret_type = src_obj["type"]
    elif secret_type is None:
        secret_type = src_obj.get("secret_type")

Accepting ``secret_type`` as well keeps backwards compatibility for anyone who
relied on the old key.
"""

from textwrap import dedent

import pytest


@pytest.fixture
def tls_secret_template(state_tree):
    """A well-formed TLS Secret manifest, using the real ``type`` field."""
    sls = "k8s/secret-tls-typed"
    contents = dedent("""
        apiVersion: v1
        kind: Secret
        metadata:
          name: {{ name }}
          namespace: {{ namespace }}
        type: kubernetes.io/tls
        data:
          tls.crt: {{ tls_crt }}
          tls.key: {{ tls_key }}
        """).strip()

    with pytest.helpers.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        yield f"salt://{sls}.yml.jinja"


@pytest.mark.xfail(reason="defect: sourced secrets are forced to Opaque", strict=True)
@pytest.mark.parametrize("secret", [False], indirect=True)
def test_secret_present_source_preserves_declared_type(
    kubernetes, secret, tls_secret_template, kubernetes_exe
):
    """A manifest declaring ``type: kubernetes.io/tls`` must produce a TLS secret."""
    ret = kubernetes.secret_present(
        name=secret["name"],
        namespace=secret["namespace"],
        source=tls_secret_template,
        template="jinja",
        template_context={
            "name": secret["name"],
            "namespace": secret["namespace"],
            # Minimal PEM-shaped values; the API only validates the key names.
            "tls_crt": "dGxzLWNlcnQ=",
            "tls_key": "dGxzLWtleQ==",
        },
        wait=True,
    )
    assert ret.result is True

    secret_state = kubernetes_exe.show_secret(name=secret["name"], namespace=secret["namespace"])
    assert secret_state["type"] == "kubernetes.io/tls"


@pytest.mark.xfail(reason="defect: source= discards the secret_type argument", strict=True)
@pytest.mark.parametrize("secret", [False], indirect=True)
def test_secret_present_source_honours_secret_type_argument(
    kubernetes, secret, state_tree, kubernetes_exe
):
    """An explicit ``secret_type`` must survive being combined with ``source``."""
    sls = "k8s/secret-untyped"
    contents = dedent("""
        apiVersion: v1
        kind: Secret
        metadata:
          name: {{ name }}
          namespace: {{ namespace }}
        data:
          .dockerconfigjson: e30=
        """).strip()

    with pytest.helpers.temp_file(f"{sls}.yml.jinja", contents, state_tree):
        ret = kubernetes.secret_present(
            name=secret["name"],
            namespace=secret["namespace"],
            source=f"salt://{sls}.yml.jinja",
            template="jinja",
            template_context={"name": secret["name"], "namespace": secret["namespace"]},
            secret_type="kubernetes.io/dockerconfigjson",
            wait=True,
        )
    assert ret.result is True

    secret_state = kubernetes_exe.show_secret(name=secret["name"], namespace=secret["namespace"])
    assert secret_state["type"] == "kubernetes.io/dockerconfigjson"
