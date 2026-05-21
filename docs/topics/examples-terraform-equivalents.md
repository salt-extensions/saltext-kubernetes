# Common Terraform patterns, expressed in Salt

This page walks through the most common Kubernetes orchestration
patterns that teams set up with HashiCorp's
[`hashicorp/kubernetes`](https://registry.terraform.io/providers/hashicorp/kubernetes/latest)
Terraform provider, and shows the equivalent Salt SLS state for each.
Patterns are drawn from real production examples on the Terraform
Registry, the OneUptime tutorial series, the Container Solutions
examples repo, and the multi-tenancy guides from Gruntwork and
HashiCorp's own learn-tutorials.

The Salt versions use the typed state functions shipped in
`saltext-kubernetes >= 2.1.0`. Where a kind has no typed wrapper, the
generic `kubernetes.manifest_present` / `manifest_absent` states
accept any Kubernetes manifest — those work for everything, including
CRDs and arbitrary custom resources.

## 1. App deploy: Namespace + ConfigMap + Secret + Deployment + Service

The "hello world" of every Terraform Kubernetes tutorial. Five
resources, declared in one config, applied as a unit.

:::{tab} Terraform

```hcl
resource "kubernetes_namespace" "app" {
  metadata { name = "myapp" }
}

resource "kubernetes_config_map" "app" {
  metadata {
    name      = "app-config"
    namespace = kubernetes_namespace.app.metadata[0].name
  }
  data = {
    LOG_LEVEL = "INFO"
    REGION    = "us-east-1"
  }
}

resource "kubernetes_secret" "app" {
  metadata {
    name      = "app-secret"
    namespace = kubernetes_namespace.app.metadata[0].name
  }
  data = { API_TOKEN = "deadbeef" }
}

resource "kubernetes_deployment" "app" {
  metadata {
    name      = "app"
    namespace = kubernetes_namespace.app.metadata[0].name
  }
  spec {
    replicas = 3
    selector { match_labels = { app = "app" } }
    template {
      metadata { labels = { app = "app" } }
      spec {
        container {
          name  = "app"
          image = "myorg/app:1.2.3"
          env_from {
            config_map_ref { name = kubernetes_config_map.app.metadata[0].name }
          }
          env_from {
            secret_ref { name = kubernetes_secret.app.metadata[0].name }
          }
          port { container_port = 8080 }
        }
      }
    }
  }
}

resource "kubernetes_service" "app" {
  metadata {
    name      = "app"
    namespace = kubernetes_namespace.app.metadata[0].name
  }
  spec {
    selector = { app = "app" }
    port {
      port        = 80
      target_port = 8080
    }
  }
}
```
:::

:::{tab} Salt SLS

```yaml
myapp-namespace:
  kubernetes.namespace_present:
    - name: myapp

app-config:
  kubernetes.configmap_present:
    - namespace: myapp
    - data:
        LOG_LEVEL: INFO
        REGION: us-east-1
    - require:
      - kubernetes: myapp-namespace

app-secret:
  kubernetes.secret_present:
    - namespace: myapp
    - data:
        API_TOKEN: deadbeef
    - require:
      - kubernetes: myapp-namespace

app-deployment:
  kubernetes.deployment_present:
    - name: app
    - namespace: myapp
    - spec:
        replicas: 3
        selector:
          matchLabels: {app: app}
        template:
          metadata:
            labels: {app: app}
          spec:
            containers:
              - name: app
                image: myorg/app:1.2.3
                envFrom:
                  - configMapRef: {name: app-config}
                  - secretRef: {name: app-secret}
                ports:
                  - containerPort: 8080
    - require:
      - kubernetes: app-config
      - kubernetes: app-secret

app-service:
  kubernetes.service_present:
    - name: app
    - namespace: myapp
    - spec:
        selector: {app: app}
        ports:
          - port: 80
            targetPort: 8080
    - require:
      - kubernetes: app-deployment
```
:::

**Notable differences:**

- Salt's `require:` clause replaces Terraform's implicit
  attribute-reference dependency graph. The semantics are equivalent;
  Salt is explicit.
- Salt accepts the kubectl-native camelCase spelling (`matchLabels`,
  `containerPort`, `targetPort`) directly. Terraform requires
  snake_case (`match_labels`, `container_port`, `target_port`).
- For larger manifests, use `kubernetes.manifest_present` with a
  `source: salt://...yaml` pointing at a vanilla Kubernetes YAML
  file — the same YAML you'd `kubectl apply -f`.

## 2. RBAC: ServiceAccount + Role + RoleBinding

The "give a workload least-privilege" pattern. Common Terraform
modules: `gruntwork-io/terraform-kubernetes-namespace`,
`aidanmelen/rbac/kubernetes`.

:::{tab} Terraform

```hcl
resource "kubernetes_service_account" "reader" {
  metadata {
    name      = "pod-reader"
    namespace = "production"
  }
}

resource "kubernetes_role" "reader" {
  metadata {
    name      = "pod-reader"
    namespace = "production"
  }
  rule {
    api_groups = [""]
    resources  = ["pods"]
    verbs      = ["get", "list", "watch"]
  }
}

resource "kubernetes_role_binding" "reader" {
  metadata {
    name      = "pod-reader"
    namespace = "production"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role.reader.metadata[0].name
  }
  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.reader.metadata[0].name
    namespace = "production"
  }
}
```
:::

:::{tab} Salt SLS

```yaml
pod-reader-sa:
  kubernetes.service_account_present:
    - name: pod-reader
    - namespace: production

pod-reader-role:
  kubernetes.role_present:
    - name: pod-reader
    - namespace: production
    - spec:
        rules:
          - apiGroups: [""]
            resources: [pods]
            verbs: [get, list, watch]

pod-reader-binding:
  kubernetes.role_binding_present:
    - name: pod-reader
    - namespace: production
    - spec:
        subjects:
          - kind: ServiceAccount
            name: pod-reader
            namespace: production
        roleRef:
          apiGroup: rbac.authorization.k8s.io
          kind: Role
          name: pod-reader
    - require:
      - kubernetes: pod-reader-sa
      - kubernetes: pod-reader-role
```
:::

ClusterRole / ClusterRoleBinding work the same way — replace
`role_present` with `cluster_role_present` and drop the `namespace:`
field (they are cluster-scoped).

## 3. Ingress with TLS via cert-manager

The standard production HTTPS pattern: cert-manager auto-issues a
Let's Encrypt cert, the Ingress references it via an annotation. Real
Terraform modules: `terraform-iaac/cert-manager/kubernetes`,
`sculley/terraform-kubernetes-cert-manager`.

:::{tab} Terraform

```hcl
resource "kubernetes_ingress_v1" "site" {
  metadata {
    name      = "site"
    namespace = "production"
    annotations = {
      "cert-manager.io/cluster-issuer" = "letsencrypt-prod"
    }
  }
  spec {
    ingress_class_name = "nginx"
    tls {
      hosts       = ["www.example.com"]
      secret_name = "site-tls"
    }
    rule {
      host = "www.example.com"
      http {
        path {
          path      = "/"
          path_type = "Prefix"
          backend {
            service {
              name = "site"
              port { number = 80 }
            }
          }
        }
      }
    }
  }
}
```
:::

:::{tab} Salt SLS

```yaml
site-ingress:
  kubernetes.ingress_present:
    - name: site
    - namespace: production
    - metadata:
        annotations:
          cert-manager.io/cluster-issuer: letsencrypt-prod
    - spec:
        ingressClassName: nginx
        tls:
          - hosts: [www.example.com]
            secretName: site-tls
        rules:
          - host: www.example.com
            http:
              paths:
                - path: /
                  pathType: Prefix
                  backend:
                    service:
                      name: site
                      port: {number: 80}
```
:::

cert-manager itself is typically installed once per cluster via its
upstream Helm chart. With Salt, install the CRDs declaratively and
target the controller deployment with `manifest_present`:

```yaml
cert-manager-crds:
  kubernetes.manifest_present:
    - source: salt://cert-manager/crds.yaml

letsencrypt-prod-issuer:
  kubernetes.manifest_present:
    - manifest:
        apiVersion: cert-manager.io/v1
        kind: ClusterIssuer
        metadata: {name: letsencrypt-prod}
        spec:
          acme:
            server: https://acme-v02.api.letsencrypt.org/directory
            email: ops@example.com
            privateKeySecretRef: {name: letsencrypt-prod-key}
            solvers:
              - http01:
                  ingress: {class: nginx}
    - require:
      - kubernetes: cert-manager-crds
```

## 4. Stateful workload with PVC + StorageClass

Postgres-style: a StatefulSet with a `volumeClaimTemplates` block that
provisions a fresh PVC per replica.

:::{tab} Terraform

```hcl
resource "kubernetes_storage_class" "fast" {
  metadata { name = "fast-ssd" }
  storage_provisioner    = "ebs.csi.aws.com"
  reclaim_policy         = "Retain"
  volume_binding_mode    = "WaitForFirstConsumer"
  allow_volume_expansion = true
  parameters             = { type = "gp3", encrypted = "true" }
}

resource "kubernetes_stateful_set_v1" "pg" {
  metadata {
    name      = "postgres"
    namespace = "production"
  }
  spec {
    service_name = "postgres-headless"
    replicas     = 3
    selector { match_labels = { app = "postgres" } }
    template {
      metadata { labels = { app = "postgres" } }
      spec {
        container {
          name  = "postgres"
          image = "postgres:16-alpine"
          port { container_port = 5432 }
          volume_mount {
            name       = "data"
            mount_path = "/var/lib/postgresql/data"
          }
        }
      }
    }
    volume_claim_template {
      metadata { name = "data" }
      spec {
        access_modes       = ["ReadWriteOnce"]
        storage_class_name = "fast-ssd"
        resources { requests = { storage = "20Gi" } }
      }
    }
  }
}
```
:::

:::{tab} Salt SLS

```yaml
fast-ssd-sc:
  kubernetes.storageclass_present:
    - name: fast-ssd
    - spec:
        provisioner: ebs.csi.aws.com
        reclaimPolicy: Retain
        volumeBindingMode: WaitForFirstConsumer
        allowVolumeExpansion: true
        parameters:
          type: gp3
          encrypted: "true"

postgres-statefulset:
  kubernetes.statefulset_present:
    - name: postgres
    - namespace: production
    - spec:
        serviceName: postgres-headless
        replicas: 3
        selector:
          matchLabels: {app: postgres}
        template:
          metadata:
            labels: {app: postgres}
          spec:
            containers:
              - name: postgres
                image: postgres:16-alpine
                ports:
                  - containerPort: 5432
                volumeMounts:
                  - name: data
                    mountPath: /var/lib/postgresql/data
        volumeClaimTemplates:
          - metadata: {name: data}
            spec:
              accessModes: [ReadWriteOnce]
              storageClassName: fast-ssd
              resources:
                requests: {storage: 20Gi}
    - require:
      - kubernetes: fast-ssd-sc
```
:::

PVCs created outside of `volumeClaimTemplates` (e.g. for a standalone
shared volume) use the `kubernetes.persistent_volume_claim_present`
state — same arg shape.

## 5. Multi-tenant namespace: Quota + LimitRange + NetworkPolicy + RBAC

The pattern teams use when carving up a shared cluster for multiple
teams or environments. Every namespace gets the same scaffolding:
hard resource ceilings, default container limits, default-deny
network isolation, and a baseline RBAC binding.

The Terraform community standardises this as a reusable module
(see `gruntwork-io/terraform-kubernetes-namespace`). Salt's
equivalent is one SLS file you `include:` or `extend:` per namespace.

:::{tab} Terraform module call

```hcl
module "team_a" {
  source        = "gruntwork-io/namespace/kubernetes"
  namespace     = "team-a"
  admin_group   = "team-a-admins"
  reader_group  = "team-a-readers"

  cpu_limit     = "10"
  memory_limit  = "16Gi"
  pod_limit     = 100
}
```
:::

:::{tab} Salt SLS template

```jinja
{% set ns = pillar['team_namespace']['name'] %}
{% set admin_group = pillar['team_namespace']['admin_group'] %}

namespace-{{ ns }}:
  kubernetes.namespace_present:
    - name: {{ ns }}
    - metadata:
        labels:
          managed-by: salt
          tenant: {{ ns }}

quota-{{ ns }}:
  kubernetes.resource_quota_present:
    - name: tenant-quota
    - namespace: {{ ns }}
    - spec:
        hard:
          requests.cpu: "{{ pillar['team_namespace']['cpu_limit'] }}"
          requests.memory: "{{ pillar['team_namespace']['memory_limit'] }}"
          pods: "{{ pillar['team_namespace']['pod_limit'] }}"

limit-range-{{ ns }}:
  kubernetes.limit_range_present:
    - name: container-defaults
    - namespace: {{ ns }}
    - spec:
        limits:
          - type: Container
            default:
              cpu: 500m
              memory: 512Mi
            defaultRequest:
              cpu: 100m
              memory: 128Mi
            max:
              cpu: 2
              memory: 4Gi

netpol-default-deny-{{ ns }}:
  kubernetes.network_policy_present:
    - name: default-deny
    - namespace: {{ ns }}
    - spec:
        podSelector: {}
        policyTypes: [Ingress, Egress]

admin-binding-{{ ns }}:
  kubernetes.role_binding_present:
    - name: tenant-admin
    - namespace: {{ ns }}
    - spec:
        roleRef:
          apiGroup: rbac.authorization.k8s.io
          kind: ClusterRole
          name: admin
        subjects:
          - kind: Group
            name: {{ admin_group }}
            apiGroup: rbac.authorization.k8s.io
```
:::

Drop that SLS file into your tree (say `salt/k8s/tenant/init.sls`),
parameterise via pillar, and `state.apply` per team:

```yaml
# pillar/teams/a.sls
team_namespace:
  name: team-a
  admin_group: team-a-admins
  cpu_limit: "10"
  memory_limit: "16Gi"
  pod_limit: 100
```

```bash
salt-call state.apply k8s.tenant pillar='{"team_namespace": {"name": "team-a", ...}}'
```

## 6. HorizontalPodAutoscaler + PodDisruptionBudget

The "available under load" pair: HPA scales replicas up under CPU
pressure, PDB guarantees a minimum during voluntary disruption
(rolling updates, node drains).

:::{tab} Terraform

```hcl
resource "kubernetes_horizontal_pod_autoscaler_v2" "web" {
  metadata {
    name      = "web"
    namespace = "production"
  }
  spec {
    scale_target_ref {
      api_version = "apps/v1"
      kind        = "Deployment"
      name        = "web"
    }
    min_replicas = 3
    max_replicas = 20
    metric {
      type = "Resource"
      resource {
        name = "cpu"
        target {
          type                = "Utilization"
          average_utilization = 70
        }
      }
    }
  }
}

resource "kubernetes_pod_disruption_budget_v1" "web" {
  metadata {
    name      = "web"
    namespace = "production"
  }
  spec {
    min_available = "50%"
    selector {
      match_labels = { app = "web" }
    }
  }
}
```
:::

:::{tab} Salt SLS

```yaml
web-hpa:
  kubernetes.horizontal_pod_autoscaler_present:
    - name: web
    - namespace: production
    - spec:
        scaleTargetRef:
          apiVersion: apps/v1
          kind: Deployment
          name: web
        minReplicas: 3
        maxReplicas: 20
        metrics:
          - type: Resource
            resource:
              name: cpu
              target:
                type: Utilization
                averageUtilization: 70

web-pdb:
  kubernetes.pod_disruption_budget_present:
    - name: web
    - namespace: production
    - spec:
        minAvailable: "50%"
        selector:
          matchLabels: {app: web}
```
:::

## 7. Custom Resource Definition + Custom Resource

For operator-style workflows: install a CRD, then declare an instance
of the custom type.

:::{tab} Terraform

Terraform's `kubernetes_manifest` resource is the usual choice for
CRDs because the typed provider doesn't ship custom types:

```hcl
resource "kubernetes_manifest" "widget_crd" {
  manifest = yamldecode(file("${path.module}/crds/widgets.example.io.yaml"))
}

resource "kubernetes_manifest" "widget_demo" {
  manifest = {
    apiVersion = "example.io/v1"
    kind       = "Widget"
    metadata   = { name = "demo", namespace = "production" }
    spec       = { size = "large", color = "blue" }
  }
  depends_on = [kubernetes_manifest.widget_crd]
}
```
:::

:::{tab} Salt SLS

```yaml
widget-crd:
  kubernetes.custom_resource_definition_present:
    - name: widgets.example.io
    - spec:
        group: example.io
        scope: Namespaced
        names:
          plural: widgets
          singular: widget
          kind: Widget
          shortNames: [wg]
        versions:
          - name: v1
            served: true
            storage: true
            schema:
              openAPIV3Schema:
                type: object
                properties:
                  spec:
                    type: object
                    properties:
                      size: {type: string}
                      color: {type: string}

widget-demo:
  kubernetes.manifest_present:
    - manifest:
        apiVersion: example.io/v1
        kind: Widget
        metadata: {name: demo, namespace: production}
        spec: {size: large, color: blue}
    - require:
      - kubernetes: widget-crd
```
:::

`manifest_present` works for any kind, registered or not — it goes
through the dynamic-client server-side-apply path that mirrors
`kubectl apply`. For typed CRDs the dedicated
`custom_resource_definition_present` state gives clearer SLS-level
identity and idempotency tracking.

## 8. Conditional apply with `test=True` (Terraform's `plan`)

Terraform's `terraform plan` shows what would change without applying.
Salt has the same affordance via `test=True` on any state run:

```bash
# Show changes the SLS would make, without applying them
salt-call state.apply k8s.tenant test=True

# Apply for real
salt-call state.apply k8s.tenant
```

Every typed `*_present` / `*_absent` state and the generic
`manifest_present` / `manifest_absent` honour `test=True`. Under the
hood they call the API with `dry_run=All` so server-side admission
webhooks and validation rules fire — the same way Terraform's plan
catches what apply would.

## What doesn't translate yet

- **Helm releases.** Terraform's `helm_release` resource is the
  canonical way to install third-party charts. Salt's
  `saltext-helm` (separate extension) is the equivalent and is
  recommended for chart-driven deployments.
- **Cloud-managed cluster provisioning** (EKS, GKE, AKS). Use Salt's
  cloud-provider modules (`saltext-vmware`, `boto3`-backed states, …)
  alongside this extension. Cluster provisioning is out of scope for
  the K8s API surface.
- **Provider-side authentication via exec plugins** (`aws-iam-authenticator`,
  `gke-gcloud-auth-plugin`, …) is supported via the `kubernetes.exec:`
  pillar key — see [Authentication](auth.md).
