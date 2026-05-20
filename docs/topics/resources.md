# Salt Resources subsystem

The `saltext.kubernetes` extension ships a *resource plug-in* —
`saltext/kubernetes/resources/kubernetes.py` — that publishes Kubernetes
objects to Salt's resources subsystem. Once published, every object
(`pod:default/nginx-abc`, `node:gke-prod-1`, `deployment:prod/web`, …)
becomes a first-class targeting surface:

```bash
# Drain a node by bare resource ID
salt 'node:worker-3' kuberesource_node.drain

# Run a command in every pod with label app=web
salt -G 'label:app=web' kuberesource_cmd.run -- ls /etc

# Apply a state to every deployment in production
salt 'deployment:prod/*' state.apply restart
```

:::{important}
The Salt resources subsystem is **available in Salt 3008.0 and newer**.
On older Salt versions this plug-in stays dormant — its `__virtual__`
returns `False` unless `salt.utils.resources` is importable, and that
module is only present in 3008+. On 3006 or 3007 the configuration
documented here is harmless but inert; the minion does not load the
plug-in and no resource IDs are published.
:::

## How discovery is configured

Configuration lives under the `resources.kubernetes` pillar block. Three
*modes* are supported, controlled by the `mode:` key. When `mode:` is
omitted, it's inferred from the pillar shape:

| `mode:` | Inferred when | What `discover()` returns |
| --- | --- | --- |
| `discover` | `resources:` is absent | Live API enumeration filtered by `kinds:` / `namespaces:` / `label_selector:` |
| `pillar` | `resources:` is present | Exactly the entries declared in pillar — **no API call** |
| `merge` | (never inferred; opt-in) | Declared entries plus API-discovered entries not already in the declared set |

The three sections below cover each mode in turn.

## Mode 1 — `discover` (default)

The plug-in connects to the cluster using the same auth path the typed
`kubernetes` execution module uses ([Authentication](auth.md)) and lists
every API object that matches the configured filters.

```yaml
kubernetes:
  kubeconfig: /etc/salt/kubeconfig
  context: production

resources:
  kubernetes:
    mode: discover                        # optional; the default
    kinds:                                # which kinds to enumerate
      - deployment
      - statefulset
      - service
      - namespace
      - node
      - configmap
    namespaces:                           # optional — scope namespaced kinds
      - production
      - staging
    label_selector: "managed-by=salt"     # optional — Kubernetes label
                                          #            selector applied to
                                          #            every list call
```

**Filter semantics:**

- `kinds:` defaults to a conservative built-in set (workload controllers,
  cluster-scoped infrastructure, NOT individual Pods — Pods are too
  numerous and short-lived to enumerate by default). Set explicitly to
  include or exclude kinds.
- `namespaces:` constrains the scope of *namespaced* kinds. If omitted,
  each namespaced kind uses its `*_for_all_namespaces` variant. Cluster-
  scoped kinds (`node`, `namespace`, `priority_class`, …) ignore this.
- `label_selector:` is passed straight to every list call. Kubernetes
  label-selector grammar: `key=value`, `key!=value`, `key in (a,b)`,
  `key`, `!key`.

**When to use it:**

- The cluster inventory changes frequently (autoscaling, GitOps churn).
- The salt-minion has full `list` permission on the kinds it cares about.
- You want every matching object to become a target without explicit
  pillar entries.

**Costs:**

- Every `saltutil.refresh_resources` triggers a `list` for each
  configured `(kind, namespace)` tuple. On a cluster with thousands of
  objects this is noticeable.
- Discovery fails if the salt-minion lacks RBAC `list` permission on any
  configured kind — including kinds the user doesn't actually care about
  but left in the default set.

## Mode 2 — `pillar` (declarative inventory, no API call)

`mode: pillar` makes the pillar block itself the authoritative inventory.
`discover()` returns exactly the IDs derived from the `resources:` list
and skips the API call entirely.

```yaml
resources:
  kubernetes:
    mode: pillar                          # optional; inferred from ``resources:``
    resources:
      - {kind: deployment, namespace: prod, name: web}
      - {kind: deployment, namespace: prod, name: api}
      - {kind: deployment, namespace: prod, name: worker}
      - {kind: namespace, name: prod}
      - {kind: node, name: gke-prod-pool-1-abc}
      - {kind: priority_class, name: high}
```

Each entry is a dict with:

- `kind` (required) — must be a key in the kind registry (see
  the *Discoverable kinds* section below).
- `name` (required) — the Kubernetes object name.
- `namespace` (required for namespaced kinds; omitted or `null` for
  cluster-scoped kinds).

Validation errors raise `CommandExecutionError` with an actionable
message at `init()` time:

```
kubernetes resource pillar 'resources[2]' kind='deployment' is namespaced and requires 'namespace'
kubernetes resource pillar 'resources[5]' has unknown kind 'depolyment': Unsupported resource type for wait operation: depolyment
kubernetes resource pillar 'resources[7]' missing 'kind' or 'name'
```

**When to use it:**

- Air-gapped clusters where the salt-minion can't reach the API server
  during normal operation (but you still want to manage the target set
  declaratively).
- Strict RBAC: the discovery user lacks `list` permission on some kinds,
  but you want those kinds addressable anyway.
- Bootstrap: declare resources before they exist in the cluster so a
  state run can reference them by ID.
- Stable inventories that should NOT drift with cluster state — a fixed
  set of "managed" objects that doesn't auto-include new ones.
- Performance — discovery on busy clusters is expensive; declaring the
  ~50 objects you actually target sidesteps the cost.
- Testing — exercise the plug-in without a live cluster.

**Limitations:**

- New objects created in the cluster aren't auto-targeted; the pillar
  must be updated.
- `kinds:`, `namespaces:`, and `label_selector:` are *ignored* in this
  mode. Use `merge` mode if you want both.

## Mode 3 — `merge` (declared + discovered)

`merge` returns the union of the declared inventory and the live API
enumeration. The declared list is always included; API discovery adds
any IDs not already in the declared set.

```yaml
resources:
  kubernetes:
    mode: merge
    resources:                            # always included
      - {kind: namespace, name: bootstrap-only}
      - {kind: priority_class, name: pinned}
    kinds: [deployment, namespace]        # also discovered live
    namespaces: [prod]
    label_selector: "managed-by=salt"
```

**When to use it:**

- You want most of the inventory to track cluster state (discovery
  mode) but pin a small set of "always-targeted" IDs explicitly.
- You're declaring resources that don't exist yet AND want live-cluster
  state for everything else.
- A hybrid air-gapped/connected setup: declare the must-have set for
  offline operation, augment with discovery when the API is reachable.

## Resource ID schema

Bare resource IDs follow:

| Scope | Format | Example |
| --- | --- | --- |
| Cluster-scoped | `<kind>:<name>` | `node:gke-prod-1`, `namespace:kube-system` |
| Namespaced | `<kind>:<namespace>/<name>` | `pod:default/nginx-abc`, `deployment:prod/web` |

The resources subsystem prefixes the resource type itself, so the full
Salt Resource Name (SRN) on the wire looks like
`kubernetes:pod:default/nginx-abc`. `parse_srn` uses `str.partition(":")`
— first colon only — so the embedded `:` in our bare IDs is unambiguous.

## Discoverable kinds

The plug-in only discovers kinds registered in
`saltext.kubernetes.utils._kinds._KIND_REGISTRY`. As of `2.1.0` the
registered kinds are:

| Workload | RBAC | Networking | Policy / scheduling | Storage | Cluster-scoped |
| --- | --- | --- | --- | --- | --- |
| `deployment` | `role` | `service` | `pod_disruption_budget` | `persistent_volume` | `namespace` |
| `statefulset` | `role_binding` | `ingress` | `priority_class` | `persistent_volume_claim` | `node` |
| `daemonset` | `cluster_role` | `network_policy` | `resource_quota` | `storageclass` | `custom_resource_definition` |
| `replicaset` | `cluster_role_binding` | `horizontal_pod_autoscaler` | `limit_range` | | |
| `pod` | `service_account` | | | | |
| `job` | | | | | |
| `cron_job` | | | | | |
| `configmap` | | | | | |
| `secret` | | | | | |

A kind name listed in pillar but not in the registry is **skipped with a
warning** in `discover` / `merge` mode (so a single bad entry doesn't
break the whole refresh) and **raises** in `pillar` mode (so a typo in
your declarative inventory is fatal at config-validation time, not
later).

## Default `kinds:` set

When `kinds:` is omitted, the plug-in uses a conservative default:

```python
("deployment", "statefulset", "daemonset", "replicaset",
 "node", "namespace", "service", "configmap", "secret",
 "persistent_volume", "persistent_volume_claim", "ingress",
 "network_policy", "resource_quota", "priority_class",
 "custom_resource_definition")
```

Notable exclusions:

- **`pod`** — too many, too short-lived. Opt in via `kinds: [..., pod]`.
- **`job` / `cron_job`** — typically managed via their parent
  controllers; opt in if you target individual jobs.

## Targeting examples

Once published to the master's registry, targeting works the same as
any Salt resource:

```bash
# List every Kubernetes resource this minion manages
salt 'minion-1' resource.list_managed kubernetes

# Run a command in a specific pod
salt 'pod:default/nginx-abc' kuberesource_cmd.run -- env

# Fetch logs from a specific pod
salt 'pod:prod/api-7d8' kuberesource_logs.tail --tail-lines 100

# Cordon a node
salt 'node:worker-3' kuberesource_node.cordon

# Apply state to every PriorityClass
salt 'priority_class:*' state.apply

# Compound: every namespaced object in production
salt -C 'kubernetes:* and G@namespace:production' test.ping
```

Grain-based selectors work because the plug-in's `grains()` function
projects each object's labels and key metadata as resource-scoped
grains:

```bash
salt -G 'label:tier=frontend' kuberesource_cmd.run -- nginx -s reload
salt -G 'phase:Pending' kubernetes.show_pod
```

## Pitfalls and edge cases

- **`mode:` only validated at init time.** A typo (`mode: dicsover`) is
  caught early with a clear error rather than fingerprinting at every
  `discover()` call.
- **Discovery RBAC.** In `discover` / `merge` mode the salt-minion's
  Kubernetes identity must have `list` permission on every kind in
  `kinds:` (filtered by `namespaces:` if set). Use `pillar` mode if the
  identity is intentionally restricted.
- **`label_selector:` does not apply to declared entries.** Even in
  `merge` mode, the `resources:` list is taken verbatim regardless of
  labels.
- **Refresh cadence.** Resources are re-discovered by
  `saltutil.refresh_resources`. There's no automatic watcher; you must
  trigger refresh after creating/deleting K8s objects you want
  reflected in the registry.
