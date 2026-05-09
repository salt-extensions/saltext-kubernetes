# Authentication

The `kubernetes` module supports four authentication modes. They are tried in
the order shown; the first one whose required values are present wins.

## 1. Kubeconfig file (default, legacy)

The original auth mode. Provide a path to a kubeconfig file plus the context
inside it to use:

```yaml
kubernetes.kubeconfig: /etc/salt/kube/admin.kubeconfig
kubernetes.context: my-cluster
```

## 2. Inline kubeconfig data

The same kubeconfig as above, but provided as base64-encoded inline data —
useful when the file lives in a Salt pillar or vault:

```yaml
kubernetes.kubeconfig-data: |
  YXBpVmVyc2lvbjogdjEKa2luZDogQ29uZmlnCi4uLg==
kubernetes.context: my-cluster
```

The minion writes a temporary file (named `salt-kubeconfig-*`) and removes it
after the call completes.

## 3. Explicit credentials

Specify the API server URL and one credential type. The credentials are
mutually exclusive and tried in the order **bearer token → basic auth →
client certificate**:

:::{tab} Bearer token
```yaml
kubernetes.host: https://my-cluster.example.com
kubernetes.api_key: "<service-account-token>"
# Optional. Defaults to "Bearer".
kubernetes.api_key_prefix: Bearer
```
:::

:::{tab} Basic auth
```yaml
kubernetes.host: https://my-cluster.example.com
kubernetes.username: alice
kubernetes.password: s3cret
```
:::

:::{tab} Client certificate
```yaml
kubernetes.host: https://my-cluster.example.com
kubernetes.client_cert: /etc/salt/kube/client.crt
kubernetes.client_key: /etc/salt/kube/client.key
kubernetes.ca_cert: /etc/salt/kube/ca.crt
```
:::

TLS validation is on by default. To disable it (for self-signed local
clusters), set `kubernetes.verify_ssl: false`.

## 4. In-cluster service account

When the salt-minion runs inside a Kubernetes pod, it can authenticate using
the mounted ServiceAccount token. This is auto-detected from the
`KUBERNETES_SERVICE_HOST` and `KUBERNETES_SERVICE_PORT` environment variables
that Kubernetes injects into every pod, but you can opt in (or out)
explicitly:

```yaml
# Force in-cluster auth even when running outside a pod (rare; useful for testing).
kubernetes.in_cluster: true

# Disable in-cluster autodetect; require one of the modes above.
kubernetes.in_cluster: false
```

## Proxy settings

All four auth modes pick up proxy configuration from the same options:

```yaml
kubernetes.proxy: http://proxy.internal:3128
kubernetes.no_proxy: ".cluster.local,10.0.0.0/8"
kubernetes.proxy_headers:
  Proxy-Authorization: Bearer abc123
```

## Environment variables

Every option above can be supplied as an environment variable, which takes
precedence over the pillar/minion-config value. The names match Ansible's
`kubernetes.core` collection so multi-tool installations can share a single
set of credentials:

| Salt option | Env var(s) (first hit wins) |
| --- | --- |
| `kubernetes.kubeconfig` | `KUBE_CONFIG_PATH`, `KUBECONFIG`, `K8S_AUTH_KUBECONFIG` |
| `kubernetes.context` | `KUBE_CTX`, `K8S_AUTH_CONTEXT` |
| `kubernetes.host` | `K8S_AUTH_HOST` |
| `kubernetes.api_key` | `K8S_AUTH_API_KEY` |
| `kubernetes.api_key_prefix` | `K8S_AUTH_API_KEY_PREFIX` |
| `kubernetes.username` | `K8S_AUTH_USERNAME` |
| `kubernetes.password` | `K8S_AUTH_PASSWORD` |
| `kubernetes.client_cert` | `K8S_AUTH_CERT_FILE` |
| `kubernetes.client_key` | `K8S_AUTH_KEY_FILE` |
| `kubernetes.ca_cert` | `K8S_AUTH_SSL_CA_CERT` |
| `kubernetes.verify_ssl` | `K8S_AUTH_VERIFY_SSL` |
| `kubernetes.proxy` | `K8S_AUTH_PROXY` |
| `kubernetes.no_proxy` | `K8S_AUTH_NO_PROXY` |
| `kubernetes.in_cluster` | `K8S_AUTH_IN_CLUSTER` |

## Per-call overrides

All of the options above can also be passed as keyword arguments to a single
function call. Per-call kwargs take precedence over env vars and pillar:

```bash
salt '*' kubernetes.nodes \
    host=https://my-cluster.example.com \
    api_key=$(cat ~/sa-token)
```

## Precedence summary

```
explicit kwargs  >  env vars  >  pillar / minion config
```

Within those layers, the auth-mode resolver tries the four modes above in the
order they're listed.
