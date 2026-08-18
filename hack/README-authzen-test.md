# AuthZen Endpoint Test Setup

This directory contains scripts to set up and test the AuthZen Authorization API 1.0
endpoints added to `ocm-proxyserver` as part of DDR-083 Phase 3.

**Related:** `~/code/acm-discovery/userpermission/implementation-plan-authzen.md`

---

## Scripts

| Script | Purpose | Run |
|--------|---------|-----|
| `setup-authzen-users.sh` | HTPasswd IDP + alice/bob/carol User objects | Once per cluster |
| `setup-authzen-rbac.sh` | RoleBindings + discoverable ClusterRoles + MCRAs | Once per cluster |
| `test-authzen.sh` | Smoke tests for all AuthZen endpoints | Each dev session |

---

## Dev session workflow

The MCE operator continuously reconciles the `MultiClusterEngine` CR and reverts any
manual changes to the `ocm-proxyserver` deployment. Pause it via annotation — cleaner
than scaling to 0 because the operator keeps running and manages all other MCE components
normally. See `implementation-plan-authzen.md` for the full explanation.

```bash
# --- Start of dev session ---

# 1. Pause MCE operator reconciliation (operator stays running, just stops reconciling MCE CR)
#    Cleaner than scaling to 0 — other MCE components continue to be managed normally.
kubectl annotate multiclusterengine multiclusterengine \
  installer.multicluster.openshift.io/pause=true --overwrite

# 2. RBAC patch for TLS profile watcher (check first, apply if MISSING)
kubectl get clusterrole open-cluster-management:backplane:foundation -o json | \
  python3 -c "import json,sys; rules=json.load(sys.stdin)['rules']; \
  print('PRESENT' if any('config.openshift.io' in r.get('apiGroups',[]) for r in rules) else 'MISSING')"

kubectl patch clusterrole open-cluster-management:backplane:foundation \
  --type=json \
  -p='[{"op":"add","path":"/rules/-","value":{"apiGroups":["config.openshift.io"],"resources":["apiservers"],"verbs":["get","list","watch"]}}]'

# 3. Deploy dev image (imagePullPolicy: Always is already set)
kubectl set image deployment/ocm-proxyserver \
  -n multicluster-engine \
  ocm-proxyserver=quay.io/bjoydeep/multicloud-manager:dev
kubectl rollout status deployment/ocm-proxyserver -n multicluster-engine --timeout=120s

# 4. Run tests
./hack/test-authzen.sh

# --- End of dev session ---
kubectl annotate multiclusterengine multiclusterengine installer.multicluster.openshift.io/pause-
```

---

## Prerequisites

### 1. `fine-grained-rbac` feature gate must be enabled in MultiClusterHub

The MCRA controller (`multicluster-role-assignment-controller`) is only deployed when
this feature gate is on. The CRD ships regardless, so MCRAs can be created but nothing
reconciles them until the feature is enabled.

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

Wait for MCH to return to `Running` phase after enabling.

### 2. MCRAs use Placements for cluster selection

`MulticlusterRoleAssignment.spec.roleAssignments[].clusterSelection` only supports
`type: placements` — it cannot name clusters directly. The setup script creates:

- A `ManagedClusterSetBinding` in each cluster namespace (binds `global` clusterset)
- A `Placement` per cluster (selects by `name: <cluster>` label)

The `global` ManagedClusterSet automatically includes all clusters.

### 3. Test users need access to the userpermissions API and AuthZen endpoints

The `ocm-proxyserver` uses `DelegatingAuthorizationOptions`, which enforces authorization
for **all** paths including non-resource URLs like `/access/v1/evaluation`. Without a
ClusterRole granting this, test user requests are rejected with 403 before reaching the
AuthZen handler.

`setup-authzen-rbac.sh` creates `authzen-test:client` ClusterRole covering:
- `clusterview.open-cluster-management.io/userpermissions` get/list
- `/access/v1/*` and `/.well-known/authzen-configuration` non-resource URLs

---

## Permission matrix

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

Three namespaces are used for MCRA scoping:

| Namespace | Exists on clusters? | Purpose |
|-----------|---------------------|---------|
| `app-frontend` | No (fake) | Tests that permission evaluation is based on the permission record, not namespace existence |
| `app-backend` | No (fake) | Same as above |
| `openshift-monitoring` | Yes (real, all clusters) | Tests the realistic case; also verifies that out-of-scope real namespaces are correctly denied |

This mix is intentional: a real namespace that's in-scope (allowed) sits alongside
real namespaces that are out-of-scope (denied), which catches any "namespace exists
therefore allow" bug in the decision engine.

---

## Expected AuthZen decisions

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
| get | pods | dsf-mc-02 | app-frontend | ❌ false | out of MCRA scope |
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

## Discoverable ClusterRoles created

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

## Known cluster-specific notes (this cluster)

- `local-cluster` is the hub, self-imported as a managed cluster — appears in
  userpermissions alongside dsf-mc and dsf-mc-02
- `imagePullPolicy: Always` is set on ocm-proxyserver deployment (prevents stale
  image caching when reusing the `:dev` tag)
- RBAC patch for TLS profile watcher is needed each session: the MCE 2.11.4 ClusterRole
  predates the `config.openshift.io/apiservers` rule added in PR #1236

## Implementation notes relevant to DDR-083 review

### Group-based permissions must use the caller's full user.Info

The AuthZen `Decider` interface accepts `user.Info` (not a reconstructed Subject string)
so that group-based permissions are correctly resolved. For users like `kube:admin` whose
permissions come entirely via group bindings (e.g. `system:cluster-admins`), passing only
the username with no groups would cause the cache lookup to return empty — resulting in
incorrect `{"decision":false}` responses.

The handler extracts the caller's full `user.Info` from the request context (populated by
the DelegatingAuthenticationOptions middleware, which includes all groups from TokenReview)
and passes it to the Decider. This is covered by `TestEvaluate_GroupBasedPermission` in
`pkg/proxyserver/authzen/decider_test.go`.

### Fake namespaces in MCRA scope work correctly

MCRA/ClusterPermission records namespace names in the hub-side cache regardless of whether
those namespaces exist on the managed cluster. The AuthZen decision engine evaluates against
the cache — it has no knowledge of actual namespace existence on managed clusters. This is
correct behaviour: the permission grant is what matters, not namespace existence.

The MCRA controller will fail to create the RoleBinding on the managed cluster (namespace
not found), but the hub-side ClusterPermission is created and the `discoverablePermissionProcessor`
picks it up. The `{"decision":true}` response for `app-frontend` and `app-backend` confirms
this is working as designed.
