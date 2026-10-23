# Kubernetes API overview

The extension provides Salt execution functions and states for Kubernetes and Helm. Use states for resources that should converge to a declared configuration, and execution functions for queries or one-time operations. API calls run on the minion, so manifests and local tools must be available there.

## Resource management

| Salt API | Purpose |
| --- | --- |
| `k8s.present` / `k8s.absent` | Apply or remove Kubernetes manifests. |
| `k8s.patched` | Patch existing objects with strategic-merge or JSON merge data. |
| `k8s.info` / `k8s.cluster_info` | Read resources, lists, API discovery, and cluster details. |
| `k8s.json_patch` | Apply RFC 6902 JSON Patch operations. |
| `kubernetes.manifest_present` / `kubernetes.manifest_absent` | Generic server-side apply states for built-in and custom resources. |
| `kubernetes.manifest_patched` | Patch existing objects; missing objects are skipped. |
| `kubernetes.deployment_present`, `kubernetes.service_present`, and node states | Reconcile common workload, service, scheduling, and taint settings. |

## Helm and configuration

| Salt API | Purpose |
| --- | --- |
| `helm.release_present` / `helm.release_absent` | Install, upgrade, or remove a release. Pin chart versions for predictable results. |
| `helm_repo.present` / `helm_repo.absent` | Manage Helm chart repositories. |
| `helm_plugin.present` / `helm_plugin.absent` / `helm_plugin.latest` | Install, remove, or update Helm plugins. |
| `helm_info.release`, `helm_info.releases`, and `helm_info.plugins` | Read release and plugin information. |
| `helm_template.render` | Render a chart to YAML or an output directory. |
| `kubeconfig.managed` | Merge named kubeconfig entries atomically, default to mode `0600`, and hide credentials in state changes. |

Helm operations require the `helm` binary on the minion. `k8s.kustomize_build` requires `kustomize`. Helm state output reports resource identifiers and actions rather than rendered values or manifests. Registry passwords are sent over stdin; do not place tokens in pillar output, state arguments, logs, or command-line flags.

## Examples

Apply an application manifest:

```yaml
web:
  k8s.present:
    - source: salt://apps/web.yaml
    - namespace: production
```

Install a pinned Helm chart:

```yaml
metrics-server:
  helm.release_present:
    - chart: metrics-server/metrics-server
    - version: 3.12.2
    - namespace: kube-system
    - values:
        replicas: 2
    - wait: true
```

Manage kubeconfig entries without returning token values in state changes:

```yaml
workstation-kubeconfig:
  kubeconfig.managed:
    - path: /home/salt/.kube/config
    - clusters:
      - name: dev
        cluster:
          server: https://k8s.example.test:6443
          certificate-authority-data: {{ pillar['k8s_ca_data'] }}
    - users:
      - name: automation
        user:
          token: {{ pillar['k8s_token'] }}
    - contexts:
      - name: dev-automation
        context:
          cluster: dev
          user: automation
          namespace: default
    - current_context: dev-automation
```

The Kubernetes client configuration used by `kubernetes.*` is separate from a kubeconfig managed by this state. Configure API credentials through the extension's [authentication settings](auth.md).

## Behavior and limitations

`kubernetes.manifest_present` uses server-side apply, which has field-ownership semantics that can differ from create or patch workflows. It can wait for registered readiness or an explicit status condition; `k8s.info` can poll for a named resource. `manifest_patched` skips missing resources and supports strategic or JSON merge patches; use `k8s.json_patch` for RFC 6902. Helm release states support typed `set_values` and additional Helm CLI controls. When `values_files` or `set_values` are supplied, Salt conservatively upgrades because it cannot reliably compare effective values with chart defaults. Review each Salt API reference for exact options and limitations before applying states in production.
