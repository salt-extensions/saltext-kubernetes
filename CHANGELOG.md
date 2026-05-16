The changelog format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

This project uses [Semantic Versioning](https://semver.org/) - MAJOR.MINOR.PATCH

# Changelog

## 2.1.0 (2026-05-16)


### Deprecated

- The legacy `k8s` execution module (`saltext.kubernetes.modules.k8s`) is deprecated and emits a `DeprecationWarning` at import time. It will be removed in saltext-kubernetes 3.0.0. Use the modern `kubernetes` execution module (`kubernetesmod`) instead, which is built on the official Kubernetes Python client and supports all current resource types.


### Changed

- Internal plumbing for the upcoming generic-apply path. New `saltext.kubernetes.utils._dynamic` module wraps `kubernetes.dynamic.DynamicClient` with a per-Configuration cache, an in-process resource-discovery cache (so repeated apply calls against the same kind don't re-query OpenAPI), and helpers `apply_manifest`, `get_object`, `list_resource`, `delete_object` that surface clear `CommandExecutionError` messages for missing GVKs, missing `metadata.namespace` on namespaced kinds, and missing `metadata.name`. The `kubernetes` runtime dependency floor is bumped to `>=24.2.0` (required for reliable `Resource.server_side_apply` semantics). The user-visible `kubernetes.apply` execution-module function and `manifest_present`/`manifest_absent` states that build on these primitives ship in a follow-up.
- Internal refactor: the per-kind metadata used by the resource-wait subsystem (`_wait_for_resource_status`) is now centralised in `saltext.kubernetes.utils._kinds._KIND_REGISTRY`. The `kubernetesmod._wait_for_resource_status` function dispatches through this registry instead of carrying duplicated `resource_type → method_name` literal dicts. Adding a new typed kind now requires one registry entry rather than two parallel dict updates. Public signature, kwargs, and return semantics of `_wait_for_resource_status` are unchanged.


### Fixed

- Improved Kubernetes resource wait handling by making compound resource name resolution more consistent and normalizing configmap wait references. [#25](https://github.com/salt-extensions/saltext-kubernetes/issues/25)


### Added

- Added support to manage statefulset resources in kubernetes clusters. [#23](https://github.com/salt-extensions/saltext-kubernetes/issues/23)
- Added support to manage replicaset resources in kubernetes clusters. [#25](https://github.com/salt-extensions/saltext-kubernetes/issues/25)
- Added support to manage daemonset resources in kubernetes clusters. [#27](https://github.com/salt-extensions/saltext-kubernetes/issues/27)
- Added support to manage storageclass resources in kubernetes clusters. [#30](https://github.com/salt-extensions/saltext-kubernetes/issues/30)
- Added node lifecycle operations: `kubernetes.cordon` / `kubernetes.uncordon` (mark a node un/schedulable), `kubernetes.taint` / `kubernetes.untaint` (manage node taints with `(key, effect)` identity), and `kubernetes.drain` (cordon + evict managed pods via the eviction API, respecting PodDisruption Budgets). Drain skips DaemonSet-owned pods by default (`ignore_daemonsets=True`), refuses pods with `emptyDir` volumes unless `delete_emptydir_data=True` or `force=True`, refuses bare (uncontrolled) pods unless `force=True`, and supports `disable_eviction=True` to fall back to direct DELETE bypassing PDBs. Returns a structured report with `evicted` / `skipped` / `errors` lists. Companion idempotent state functions: `kubernetes.node_cordoned`, `kubernetes.node_uncordoned`, `kubernetes.node_tainted`, `kubernetes.node_untainted`. Drain itself is intentionally not exposed as a state — it's an imperative operation, not a desired-state declaration.
- Added pod operations modules: `kubernetes.exec` (run commands inside a Pod and capture stdout/stderr/retcode), `kubernetes.logs` (fetch logs with `container`, `previous`, `since_seconds`, `tail_lines`, `timestamps` filters), `kubernetes.cp_to` and `kubernetes.cp_from` (copy files into and out of a Pod via tar pipe through the exec subresource). All four are namespace-aware and honour `container` for multi-container Pods. The exec subresource websocket has no portable way to signal stdin EOF, so commands that wait for EOF (`cat`, `tee`) are bounded by a wall-clock `timeout` and surface `retcode=-1` if exceeded; the recommended idiom for stdin-bearing exec is a byte-bounded reader like `head -c N`. Linux-only; Windows is unsupported because the cp path depends on POSIX tar semantics.
- Added rich authentication modes to the `kubernetes` execution module: in-cluster ServiceAccount (auto-detected when running in a pod), bearer token (`kubernetes.api_key`), basic auth (`kubernetes.username` / `kubernetes.password`), and explicit client certificate (`kubernetes.client_cert` / `kubernetes.client_key` / `kubernetes.ca_cert`). Proxy support added via `kubernetes.proxy`, `kubernetes.no_proxy`, `kubernetes.proxy_headers`. TLS verification toggled with `kubernetes.verify_ssl`. All options can also be provided via `K8S_AUTH_*` environment variables (matching Ansible's `kubernetes.core` collection) or as per-call kwargs. The legacy kubeconfig path is unchanged and remains the default. See the auth guide (`docs/topics/auth.md`) for details.
- Added six `kuberesource_*` companion execution modules that ride on Salt's resources subsystem to dispatch operations against individual Kubernetes resources by their bare ID. `kuberesource_cmd` (run, run_all, run_stdout — Pod-only), `kuberesource_logs` (fetch, tail — Pod-only), `kuberesource_cp` (to_pod, from_pod — Pod-only), `kuberesource_node` (cordon, uncordon, drain, taint, untaint — Node-only), `kuberesource_workload` (scale, restart, rollback — Deployment/StatefulSet/ReplicaSet/DaemonSet), and `kuberesource_state` (apply with the active resource's identity exposed to the manifest's Jinja template context). All six are dormant on stock Salt — `__virtual__` returns False unless `salt.utils.resources` is importable. They light up automatically on a Salt build that includes the resources branch, at which point dispatches like `salt 'pod:default/nginx-abc' kuberesource_cmd.run "echo hi"` route to the correct typed `kubernetes.*` execution.
- Added support for RBAC resources: Role, RoleBinding, ClusterRole, ClusterRoleBinding, and ServiceAccount. Each gets the standard six-verb execution-module surface (`list_*`, `show_*`, `create_*`, `replace_*`, `patch_*`, `delete_*`) and matching state functions (`*_present`, `*_absent`). Specs accept either snake_case or camelCase keys; `roleRef.apiGroup` defaults to `rbac.authorization.k8s.io`. Replace and patch surface a clear error when the operation would change a binding's immutable `roleRef`, matching kubectl behaviour. ClusterRole supports `aggregationRule` for aggregated roles. ServiceAccount supports `automountServiceAccountToken`, `imagePullSecrets`, and `secrets`.
- Added the Kubernetes resource type for Salt's in-flight `resources` subsystem (`saltext.kubernetes.resource.kubernetes`). The module ships dormant on stock Salt — its `__virtual__` returns False when `salt.utils.resources` isn't importable — and "lights up" automatically once a Salt build that includes the resources branch is in use. Implements the full lifecycle contract: `init`, `initialized`, `discover`, `grains`, `grains_refresh`, `shutdown`. On enabled clusters, declaring a `resources.kubernetes` block in pillar publishes pods/deployments/nodes/etc. into the master's resource registry, where they become first-class targets for grain-based and bare-ID targeting (e.g. `salt -G 'app:nginx' kubernetes.show_pod`).
- Added the user-visible generic-apply surface: `kubernetes.apply` (server-side apply one or more manifests; accepts a dict, list of dicts, YAML string, or salt:// `source` path; supports Jinja templating, multi-document YAML, fieldManager, force_conflicts, dry_run, and per-namespace defaulting), and `kubernetes.delete_manifest` (the symmetric deletion path). Companion idempotent state functions: `kubernetes.manifest_present` and `kubernetes.manifest_absent`. The state functions honour Salt's `test=True` mode by issuing a server-side dry-run apply through the API server's own validation — admission webhook rejections surface during `state.apply test=True` rather than at commit time. Unlike the typed CRUD path which silently scopes namespaced resources to `"default"`, the apply path requires an explicit namespace (either in `metadata.namespace` or via the `namespace` parameter) and fails loudly otherwise.
- Added typed support for `PersistentVolume` (cluster-scoped) and `PersistentVolumeClaim` (namespaced): 12 module functions and 4 state functions. Spec helpers validate the required `accessModes` and (for PV) `capacity` / (for PVC) `resources`. Replace and patch surface immutability errors clearly — most PV fields are immutable after binding, and PVC `accessModes`, `selector`, `volumeName`, and `storageClassName` are immutable after binding. Spec helpers now do generic camelCase→snake_case translation for unmapped keys, so volume-backend fields like `hostPath`, `nfs`, `csi`, `awsElasticBlockStore` work without per-field map entries.

  Four additional kinds (`NetworkPolicy`, `ResourceQuota`, `LimitRange`, `PriorityClass`) get registry entries — so the wait subsystem and `_dynamic.get_object` recognise them — but no typed CRUD wrappers. The recommended path for these is `kubernetes.apply` / `kubernetes.manifest_present`. See the new "Apply-only kinds" docs page.
- Added typed support for the batch kinds: `kubernetes.{jobs, show_job, create_job, replace_job, patch_job, delete_job}` and the matching `cron_job` set, plus the `kubernetes.{job,cron_job}_{present,absent}` states. `create_job` accepts `wait_for_completion=True` to block until `status.conditions` reports `Complete=True` (or fail on `Failed=True` / wall-clock `timeout` elapsed). CronJob spec validates `concurrencyPolicy` (Allow / Forbid / Replace) and requires `schedule`. Job pod templates default `restartPolicy` to `Never` and reject `Always` (matching kubectl-create-job). Patch on these kinds passes the body through verbatim — unlike RBAC where the patch helper flattens `spec:` because those kinds have no real `.spec`, batch kinds have a genuine nested `.spec` (e.g. `spec.suspend`, `spec.schedule`) that must be preserved.
- Added typed support for three more kinds: `Ingress` (NetworkingV1Api), `HorizontalPodAutoscaler` (autoscaling/v2 — modern), and `PodDisruptionBudget` (PolicyV1Api). 18 module functions and 6 state functions follow the same pattern as the other typed kinds. PDB validates that exactly one of `minAvailable` / `maxUnavailable` is set (matching kubectl) and requires a `selector`. HPA spec validates the required `scaleTargetRef` and `maxReplicas`. Spec helpers translate top-level camelCase keys (`ingressClassName`, `scaleTargetRef`, `minReplicas`, `minAvailable`, etc.) to the snake_case kwargs the V1*Spec constructors expect; nested fields in user-supplied dicts (e.g. `pathType` inside ingress rules, `averageUtilization` inside HPA targets) must use the wire camelCase names.
- Added workload + cluster operations: `kubernetes.scale` (set replica counts on Deployment / StatefulSet / ReplicaSet via the `/scale` subresource), `kubernetes.restart` (rolling restart of Deployment / StatefulSet / DaemonSet / ReplicaSet via the `kubectl.kubernetes.io/restartedAt` pod-template annotation), `kubernetes.rollback` (revert a Deployment to a previous revision by patching the pod template from the target ReplicaSet — works on all current K8s versions, doesn't depend on the deprecated `/rollback` subresource), and `kubernetes.cluster_info` (server version, healthz, and available API groups). Scale uses PATCH rather than read-modify-write to avoid 409 conflicts from concurrent reconciliation by the deployment controller.

## 2.0.0 (2026-04-20)


### Breaking changes

- Dropped legacy connection setup. Either `kubeconfig` or `kubeconfig-data` and (always) `context` configuration is required now. This change affects backwards compatibility and may not work on very old versions of kubernetes.
- `kubernetes.create_configmap` with `source` parameter now expects to receive a properly formatted spec with the configmap data in the `data` key. Previously, the loaded data was used as the data directly.


### Changed

- API responses now return ``camelCase`` keys matching Kubernetes YAML manifests instead of ``snake_case``, and ``_present`` state functions use ``patch`` instead of delete-and-recreate (the ``replace`` parameter has been removed). [#16](https://github.com/salt-extensions/saltext-kubernetes/issues/16)


### Fixed

- Added Kubernetes patch functionality to the execution module for applying patch operations to cluster resources during runtime. Also fixed general idempotency issues in absent functions by checking resource existence before modifications. [#16](https://github.com/salt-extensions/saltext-kubernetes/issues/16)


### Added

- Added enhanced functionality including Jinja2 templating via `template_context` parameter, `wait` and `timeout` parameters for resource operations, `secret_type` and `metadata` parameters for secrets, and improved parameter validation across resource types. [#10](https://github.com/salt-extensions/saltext-kubernetes/issues/10)
- Added Kubernetes patch functionality to the execution module for applying patch operations to cluster resources during runtime. [#16](https://github.com/salt-extensions/saltext-kubernetes/issues/16)

## 1.1.0 (2025-01-14)


### Changed

- Updated `kubernetesmod` to work with newer versions of the Kubernetes Python client. [#1](https://github.com/salt-extensions/saltext-kubernetes/pull/1)


## 1.0.1 (2023-12-29)

Initial release of `saltext-kubernetes`. This release tracks the functionality in the core Salt code base at this point.
