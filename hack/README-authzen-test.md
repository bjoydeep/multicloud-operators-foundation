# AuthZen Endpoint Test Setup

This directory contains scripts to set up and test the AuthZen Authorization API 1.0
endpoints added to `ocm-proxyserver` as part of DDR-083 Phase 3.

---

## Scripts

| Script | Purpose | When |
|--------|---------|------|
| `setup-authzen-users.sh` | HTPasswd IDP + alice/bob/carol User objects | Once per cluster |
| `setup-authzen-rbac.sh` | RoleBindings + discoverable ClusterRoles + MCRAs | Once per cluster |
| `test-authzen.sh` | Smoke tests for all AuthZen endpoints | Each dev session |

---

## Step 1 — Prerequisites

The `fine-grained-rbac` feature gate must be enabled in MultiClusterHub. This deploys
the MCRA controller (`multicluster-role-assignment-controller`) — without it, MCRAs
exist as objects but nothing reconciles them into ClusterPermissions.

```bash
# Check current state
kubectl get multiclusterhub multiclusterhub -n open-cluster-management \
  -o jsonpath='{.spec.overrides.components[?(@.name=="fine-grained-rbac")].enabled}'

# Enable if false
kubectl get multiclusterhub multiclusterhub -n open-cluster-management -o json | python3 -c "
import json,sys
mch=json.load(sys.stdin)
for c in mch['spec']['overrides']['components']:
    if c['name'] == 'fine-grained-rbac':
        c['enabled'] = True
print(json.dumps(mch))
" | kubectl apply -f -
```

Wait for MCH to return to `Running` phase before proceeding to Step 2.

---

## Step 2 — One-time cluster setup

Run these once. Both scripts are idempotent — safe to re-run.

```bash
# Create HTPasswd IDP and test users (alice, bob, carol)
./hack/setup-authzen-users.sh

# Create RBAC, discoverable ClusterRoles, and MCRAs
./hack/setup-authzen-rbac.sh
```

After `setup-authzen-rbac.sh` completes, verify the cache has warmed up:

```bash
kubectl get userpermissions --as=alice
kubectl get userpermissions --as=bob
kubectl get userpermissions --as=carol
```

If results are empty, wait 30 seconds and retry.

---

## Step 3 — Dev session workflow

```bash
# 1. Build (you changed the code — always start here)
IMAGE_REGISTRY=quay.io/bjoydeep IMAGE_TAG=dev make images-amd64

# 2. Push
podman push quay.io/bjoydeep/multicloud-manager:dev

# 3. Pause MCE operator (ONCE per cluster session — skip if already paused)
kubectl annotate multiclusterengine multiclusterengine \
  installer.multicluster.openshift.io/pause=true --overwrite

# 4. RBAC patch — check first, apply if MISSING (ONCE per cluster session)
kubectl get clusterrole open-cluster-management:backplane:foundation -o json | \
  python3 -c "import json,sys; rules=json.load(sys.stdin)['rules']; \
  print('PRESENT' if any('config.openshift.io' in r.get('apiGroups',[]) for r in rules) else 'MISSING')"
# Apply if MISSING:
kubectl patch clusterrole open-cluster-management:backplane:foundation \
  --type=json \
  -p='[{"op":"add","path":"/rules/-","value":{"apiGroups":["config.openshift.io"],"resources":["apiservers"],"verbs":["get","list","watch"]}}]'

# 5. Verify push landed before restarting (avoids CDN propagation race)
podman pull quay.io/bjoydeep/multicloud-manager:dev

# 6. Restart — imagePullPolicy:Always guarantees fresh pull of :dev tag
kubectl rollout restart deployment/ocm-proxyserver -n multicluster-engine
kubectl rollout status deployment/ocm-proxyserver -n multicluster-engine --timeout=120s

# 7. Test
./hack/test-authzen.sh

# --- End of dev session ---
kubectl annotate multiclusterengine multiclusterengine installer.multicluster.openshift.io/pause-
```

---

## Reference — Permission matrix

### Why hub-only?

Users only need to exist on the hub cluster. The entire authorization pipeline runs
on the hub:
- UserPermission cache (`ocm-proxyserver`)
- RBAC bindings (hub kube-apiserver)
- MCRAs → ClusterPermissions (hub, distributed to managed clusters)
- AuthZen PDP (`ocm-proxyserver`)

Managed clusters do not need these users to exist.

### Two permission sources

The UserPermission cache has two processors that both contribute to what the AuthZen
PDP sees:

```
adminViewPermissionProcessor  — scans hub RoleBindings/ClusterRoleBindings
  admin binding  →  managedcluster:admin  (all verbs, all resources, all namespaces)
  edit binding   →  managedcluster:view   (read verbs only)
  view binding   →  managedcluster:view   (read verbs only)

discoverablePermissionProcessor  — scans ClusterPermissions created by MCRA controller
  MCRA → ClusterPermission → fine-grained rules (specific namespaces, specific resources)
  Requires ClusterRole to have label: clusterview.open-cluster-management.io/discoverable=true
```

Both results are additive — a user can have coarse AND fine-grained permissions
simultaneously.

### User × cluster matrix

| User | `dsf-mc` | `dsf-mc-02` | `local-cluster` | Processor |
|------|----------|------------|----------------|-----------|
| **alice** | admin RoleBinding | view RoleBinding | no access | adminView only |
| **bob** | MCRA → `app-frontend`, `app-backend` (write) | MCRA → `openshift-monitoring` (read) | no access | discoverable only |
| **carol** | no access | admin RoleBinding | MCRA → `app-frontend`, `openshift-monitoring` (write) | **both** |

Carol deliberately exercises both processors on different clusters — the most complete
coverage case.

### Namespace rationale

| Namespace | Exists on clusters? | Purpose |
|-----------|---------------------|---------|
| `app-frontend` | No (fake) | Tests that permission evaluation is based on the permission record, not namespace existence |
| `app-backend` | No (fake) | Same as above |
| `openshift-monitoring` | Yes (real, all clusters) | Tests the realistic case; also verifies that out-of-scope real namespaces are correctly denied |

---

## Reference — Expected AuthZen decisions

### alice

| Verb | Resource | Cluster | Namespace | Decision | Reason |
|------|----------|---------|-----------|----------|--------|
| get | pods | dsf-mc | default | ✅ true | admin (wildcard) |
| create | pods | dsf-mc | default | ✅ true | admin (wildcard) |
| get | pods | dsf-mc-02 | default | ✅ true | view (read allowed) |
| create | pods | dsf-mc-02 | default | ❌ false | view (no write) |
| get | pods | local-cluster | default | ❌ false | no access |
| search/resource pods | — | — | — | dsf-mc/\*, dsf-mc-02/\* | local-cluster not in results |

### bob

| Verb | Resource | Cluster | Namespace | Decision | Reason |
|------|----------|---------|-----------|----------|--------|
| get | pods | dsf-mc | app-frontend | ✅ true | MCRA in-scope (fake ns) |
| get | pods | dsf-mc | app-backend | ✅ true | MCRA in-scope (fake ns) |
| create | pods | dsf-mc | app-frontend | ✅ true | workload-admin (write) |
| get | pods | dsf-mc | kube-system | ❌ false | out of MCRA scope |
| get | pods | dsf-mc | openshift-monitoring | ❌ false | not in bob's dsf-mc MCRA |
| get | pods | dsf-mc-02 | openshift-monitoring | ✅ true | MCRA in-scope (real ns) |
| create | pods | dsf-mc-02 | openshift-monitoring | ❌ false | workload-view (no write) |
| get | pods | local-cluster | default | ❌ false | no access |
| search/resource pods | — | — | — | dsf-mc/app-frontend, dsf-mc/app-backend, dsf-mc-02/openshift-monitoring | 3 scopes total |

### carol

| Verb | Resource | Cluster | Namespace | Decision | Reason |
|------|----------|---------|-----------|----------|--------|
| get | pods | dsf-mc | default | ❌ false | no access |
| get | pods | dsf-mc-02 | default | ✅ true | admin (wildcard) |
| create | pods | dsf-mc-02 | default | ✅ true | admin (wildcard) |
| get | pods | local-cluster | app-frontend | ✅ true | MCRA in-scope (fake ns) |
| create | pods | local-cluster | app-frontend | ✅ true | workload-admin (write) |
| get | pods | local-cluster | openshift-monitoring | ✅ true | MCRA in-scope (real ns) |
| get | pods | local-cluster | default | ❌ false | out of MCRA scope |
| get | pods | local-cluster | kube-system | ❌ false | out of MCRA scope |
| search/resource pods | — | — | — | dsf-mc-02/\*, local-cluster/app-frontend, local-cluster/openshift-monitoring | 3 scopes total |

---

## Reference — Discoverable ClusterRoles

Two custom ClusterRoles are created by `setup-authzen-rbac.sh`:

**`acm-test:workload-admin`** — read + write on common workload resources
```yaml
rules:
- apiGroups: ["", "apps", "batch"]
  resources: [pods, deployments, services, jobs, configmaps]
  verbs: [get, list, watch, create, update, patch, delete]
label: clusterview.open-cluster-management.io/discoverable: "true"
```

**`acm-test:workload-view`** — read-only on common workload resources
```yaml
rules:
- apiGroups: ["", "apps", "batch"]
  resources: [pods, deployments, services, jobs, configmaps]
  verbs: [get, list, watch]
label: clusterview.open-cluster-management.io/discoverable: "true"
```

The `discoverable` label is required for the `discoverablePermissionProcessor` to
pick up these roles from ClusterPermission resources. Without it, MCRA grants would
not appear in the UserPermission cache and AuthZen would return false.

---

## Gotcha — after an ACM/MCE upgrade

An upgrade un-pauses the MCE operator and resets the `ocm-proxyserver` deployment back
to the release image. After an upgrade, run the full restore sequence:

```bash
# 1. Re-pause MCE operator
kubectl annotate multiclusterengine multiclusterengine \
  installer.multicluster.openshift.io/pause=true --overwrite

# 2. Re-apply RBAC patch (upgrade reverts it)
kubectl get clusterrole open-cluster-management:backplane:foundation -o json | \
  python3 -c "import json,sys; rules=json.load(sys.stdin)['rules']; \
  print('PRESENT' if any('config.openshift.io' in r.get('apiGroups',[]) for r in rules) else 'MISSING')"
# Apply if MISSING:
kubectl patch clusterrole open-cluster-management:backplane:foundation \
  --type=json \
  -p='[{"op":"add","path":"/rules/-","value":{"apiGroups":["config.openshift.io"],"resources":["apiservers"],"verbs":["get","list","watch"]}}]'

# 3. Reset deployment image (rollout restart alone is not enough — spec was reset too)
kubectl set image deployment/ocm-proxyserver \
  -n multicluster-engine \
  ocm-proxyserver=quay.io/bjoydeep/multicloud-manager:dev
kubectl patch deployment ocm-proxyserver -n multicluster-engine \
  --type=json \
  -p='[{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"Always"}]'
kubectl rollout status deployment/ocm-proxyserver -n multicluster-engine --timeout=120s
```

A `rollout restart` alone is not sufficient after an upgrade — the deployment spec has
already been reset to the release image, so restarting just re-pulls the release image.

---

## Implementation notes

### Group-based permissions must use the caller's full user.Info

The AuthZen `Decider` interface accepts `user.Info` (not a reconstructed Subject string)
so that group-based permissions are correctly resolved. For users like `kube:admin` whose
permissions come entirely via group bindings (e.g. `system:cluster-admins`), passing only
the username with no groups would cause the cache lookup to return empty — resulting in
incorrect `{"decision":false}` responses.

### Fake namespaces in MCRA scope work correctly

MCRA/ClusterPermission records namespace names in the hub-side cache regardless of whether
those namespaces exist on the managed cluster. The AuthZen decision engine evaluates against
the cache — it has no knowledge of actual namespace existence on managed clusters.

The MCRA controller will fail to create the RoleBinding on the managed cluster (namespace
not found), but the hub-side ClusterPermission is created and the `discoverablePermissionProcessor`
picks it up. The `{"decision":true}` response for `app-frontend` and `app-backend` confirms
this is working as designed.
