# Apply-only kinds

Some Kubernetes kinds get a registry entry in this extension (so the
wait subsystem and resource discovery work) but do **not** get typed
CRUD wrappers. The recommended way to manage them is through
`kubernetes.apply` / `kubernetes.manifest_present`.

## Which kinds?

The current apply-only kinds are:

| Kind | Why apply-only |
| --- | --- |
| `NetworkPolicy` | The spec is essentially configuration with no field-by-field churn — operators write it once and barely touch it. |
| `ResourceQuota` | Same — namespace-scoped quotas are written and forgotten, occasionally edited wholesale. |
| `LimitRange` | Same. |
| `PriorityClass` | Cluster-scoped, set once at install time. |

These kinds have a single design pattern in production: write the
manifest, apply it, and let it sit. Typed wrappers would impose a
spec-builder helper (one per kind) plus six CRUD functions plus two
state functions — ~300 LoC each — for ergonomic gain that doesn't
exist in the day-to-day workflow.

## Recommended pattern

Use `kubernetes.manifest_present` with a YAML source:

```yaml
my-namespace-quota:
  kubernetes.manifest_present:
    - source: salt://kubernetes/quotas/my-namespace.yaml
```

Or inline:

```yaml
backend-network-policy:
  kubernetes.manifest_present:
    - manifest:
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: backend-deny-all
          namespace: backend
        spec:
          podSelector: {}
          policyTypes: [Ingress]
```

## What you still get

Even without typed CRUD, these kinds participate in:

- **The kind registry** — `kubernetes.apply` knows about them, the
  wait subsystem can wait on them being created/deleted, and they
  show up in resource discovery.
- **`manifest_present` / `manifest_absent`** — full SSA semantics,
  diff reporting, dry-run, all the same as the typed kinds.
- **The deletion path** — `kubernetes.delete_manifest` with the same
  manifest deletes the resource cleanly.

## Promoting a kind to typed in the future

If a real use case appears for a typed wrapper on one of these kinds
(e.g. a state that builds a NetworkPolicy by composing rules
programmatically), promote it: add a spec helper, a registry entry
becomes a `KindOps` with whatever ready predicate is appropriate, and
add the six-verb CRUD functions. The promotion is purely additive —
existing `manifest_present` declarations continue to work because the
generic apply path is unchanged.
