# Converting `kubernetes.core` automation

This guide maps the public plugins in `kubernetes.core` 6.6.0 to Salt Extension APIs. The Kubernetes collection is not a drop-in Salt provider: Ansible controller action plugins, lookups, filters, and connection plugins run in different execution contexts. Use the Salt API that matches the operation and move controller-local files into Salt fileserver sources or onto the minion that runs the command.

## Module mapping

| Ansible module | Salt equivalent | Notes |
| --- | --- | --- |
| `helm` | `helm.release_present` / `helm.release_absent` | Release lifecycle; pin `version` for predictable reconciliation. |
| `helm_info` | `helm_info.release` / `helm_info.releases` | Values, manifests, hooks, and notes are opt-in because they may contain secrets. |
| `helm_plugin` | `helm_plugin.present` / `.absent` / `.latest` | Plugin install, remove, and update. |
| `helm_plugin_info` | `helm_info.plugins` | Lists plugin name, version, and description. |
| `helm_pull` | `helm.pull` | Downloads chart archives to the minion. |
| `helm_registry_auth` | `helm.registry_auth` | Password travels on stdin; login state is inherently imperative. |
| `helm_repository` | `helm_repo.present` / `.absent`; `helm.repository_update` | Public repository lifecycle. Password-authenticated repo configuration is not accepted by the state. |
| `helm_template` | `helm_template.render` | Renders YAML or writes Helm's output directory. |
| `k8s` | `k8s.present` / `.absent` / `.patched` | Uses the generic manifest states and their documented SSA/patch differences. |
| `k8s_cluster_info` | `k8s.cluster_info` | API discovery and cluster information. |
| `k8s_cp` | `k8s.copy_to` / `.copy_from` | Copy runs through the Kubernetes API; the target container needs `tar`. |
| `k8s_drain` | `k8s.drain` | Imperative node operation; review eviction and disruption-budget behavior. |
| `k8s_exec` | `k8s.execute` | Executes inside a pod. |
| `k8s_info` | `k8s.info` | Reads one object or lists by GVK and selectors. |
| `k8s_json_patch` | `k8s.json_patch` | RFC 6902 patch operations. |
| `k8s_log` | `k8s.logs` | Fetches pod logs. |
| `k8s_rollback` | `k8s.rollback` | Rolls a Deployment back to a revision. |
| `k8s_scale` | `k8s.scale`; declarative workloads can use `kubernetes.deployment_present` | Scaling is imperative; use a state when the replica count is the desired configuration. |
| `k8s_service` | `kubernetes.service_present` / `kubernetes.service_absent` or generic manifest states | Salt test mode and state change reporting apply. |
| `k8s_taint` | `k8s.taint` / `.untaint`; `kubernetes.node_tainted` / `.node_untainted` | Choose execution functions for a one-time action and states for a persistent taint. |
| `kubeconfig` | `kubeconfig.managed` | Merges named entries atomically, writes mode `0600` by default, and hides credentials in state output. |

## Plugin mapping

| Ansible plugin | Salt equivalent | Difference |
| --- | --- | --- |
| `kubectl` connection | `k8s.execute`, `k8s.copy_to`, `k8s.copy_from` | Salt does not transparently replace Ansible's task connection transport. |
| `k8s_config_resource_name` filter | `salt['k8s.config_resource_name'](resource)` | Call the execution helper from a Salt Jinja template. |
| `k8s` lookup | `k8s.info` | API calls run on the minion rather than during controller-side templating. |
| `kustomize` lookup | `k8s.kustomize_build` | Requires the `kustomize` binary and source files on the minion. |
| `k8s_info` action plugin | `k8s.info` | Internal Ansible orchestration is represented by a Salt execution function. |

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

## Behavior and security limits

`kubernetes.manifest_present` uses server-side apply, which can differ from Ansible's default create/patch behavior and field ownership. It can wait for registered readiness or an explicit status condition; `k8s.info` can poll for a named resource to appear. `manifest_patched` skips missing resources and supports strategic or JSON merge patches; use `k8s.json_patch` for RFC 6902. Helm release states support typed `set_values` and additional Helm CLI controls, but compare resulting values carefully: Salt conservatively upgrades when `values_files` or `set_values` are supplied because it cannot reliably compare their effective values with chart defaults. The extension does not reproduce every Ansible option; in particular, Ansible controller-local lookup paths, `kubectl` connection task transport, and Helm repository basic-auth secrets do not have identical Salt behavior. Review each Salt API reference before converting production states.

Helm commands require the `helm` binary on the minion. `k8s.kustomize_build` requires `kustomize`. Helm state output reports resource identifiers and actions rather than rendered values or manifests. Registry passwords are sent over stdin. Do not put tokens in pillar output, state arguments, logs, or command-line flags.

See the [Ansible collection source](https://github.com/ansible-collections/kubernetes.core/tree/6.6.0) and the generated Salt module and state references for option details and limitations.
