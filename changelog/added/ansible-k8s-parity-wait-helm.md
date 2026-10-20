Add polling and readiness options to the Ansible-compatible Kubernetes APIs. ``k8s.info`` can wait for a named resource to appear, and ``k8s.present`` can wait for registered readiness or an explicit status condition after reconciliation.

Add typed Helm ``set_values`` overrides and CLI controls for schema validation, release ownership, hooks, post-renderers, and reset-then-reuse values. Helm releases with ``values_files`` or ``set_values`` continue to use conservative upgrade checks because effective values cannot be compared reliably.
