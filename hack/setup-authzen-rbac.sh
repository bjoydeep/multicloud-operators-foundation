#!/usr/bin/env bash
# setup-authzen-rbac.sh — creates RBAC bindings, discoverable ClusterRoles,
# and MCRAs for alice, bob, carol to test AuthZen endpoints.
#
# Permission matrix:
#
#   alice:
#     dsf-mc       → admin RoleBinding (managedcluster:admin via adminViewProcessor)
#     dsf-mc-02    → view  RoleBinding (managedcluster:view  via adminViewProcessor)
#     local-cluster→ no access
#
#   bob:
#     dsf-mc       → MCRA → ns app-frontend, app-backend  (acm-test:workload-admin, write)
#     dsf-mc-02    → MCRA → ns openshift-monitoring        (acm-test:workload-view,  read)
#     local-cluster→ no access
#
#   carol:
#     dsf-mc       → no access
#     dsf-mc-02    → admin RoleBinding (managedcluster:admin via adminViewProcessor)
#     local-cluster→ MCRA → ns app-frontend, openshift-monitoring (acm-test:workload-admin, write)
#
# Namespace legend:
#   app-frontend        — does NOT exist on any cluster (tests permission-only scoping)
#   app-backend         — does NOT exist on any cluster (tests permission-only scoping)
#   openshift-monitoring— EXISTS on all clusters
#
# Safe to run multiple times (idempotent via apply).
# Prerequisites: setup-authzen-users.sh must have run first.

set -euo pipefail

CLUSTERS_MANAGED=("dsf-mc" "dsf-mc-02")
CLUSTER_HUB="local-cluster"
NS_FAKE_1="app-frontend"
NS_FAKE_2="app-backend"
NS_REAL="openshift-monitoring"

green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
info()  { printf '  %s\n' "$*"; }

bold "=== AuthZen RBAC + MCRA setup ==="
echo ""

# ---------------------------------------------------------------------------
# 1. Discoverable ClusterRoles (required for discoverablePermissionProcessor)
# ---------------------------------------------------------------------------
bold "Step 1: Creating discoverable ClusterRoles"

kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: acm-test:workload-admin
  labels:
    clusterview.open-cluster-management.io/discoverable: "true"
rules:
- apiGroups: ["", "apps", "batch"]
  resources: ["pods", "deployments", "services", "jobs", "configmaps"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
EOF
info "Created acm-test:workload-admin (discoverable, read+write)"

kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: acm-test:workload-view
  labels:
    clusterview.open-cluster-management.io/discoverable: "true"
rules:
- apiGroups: ["", "apps", "batch"]
  resources: ["pods", "deployments", "services", "jobs", "configmaps"]
  verbs: ["get", "list", "watch"]
EOF
info "Created acm-test:workload-view (discoverable, read-only)"

# ---------------------------------------------------------------------------
# 2. Grant test users access to userpermissions API + AuthZen endpoints
# The proxyserver's DelegatingAuthorizationOptions enforces authorization for
# all paths including non-resource URLs like /access/v1/*.
# ---------------------------------------------------------------------------
bold "Step 2: Granting test users access to userpermissions API and AuthZen endpoints"

kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: authzen-test:client
rules:
- apiGroups: ["clusterview.open-cluster-management.io"]
  resources: ["userpermissions"]
  verbs: ["get", "list"]
- nonResourceURLs:
  - "/access/v1/evaluation"
  - "/access/v1/evaluations"
  - "/access/v1/search/resource"
  - "/access/v1/search/action"
  - "/.well-known/authzen-configuration"
  verbs: ["get", "post"]
EOF
info "Created ClusterRole authzen-test:client"

kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: authzen-test:client
subjects:
- kind: User
  name: alice
  apiGroup: rbac.authorization.k8s.io
- kind: User
  name: bob
  apiGroup: rbac.authorization.k8s.io
- kind: User
  name: carol
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: authzen-test:client
  apiGroup: rbac.authorization.k8s.io
EOF
info "Bound alice, bob, carol to authzen-test:client"

# ---------------------------------------------------------------------------
# 3. alice — coarse bindings (adminViewPermissionProcessor)
# ---------------------------------------------------------------------------
bold "Step 3: alice — admin on dsf-mc, view on dsf-mc-02"

kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: authzen-test-alice-admin
  namespace: dsf-mc
subjects:
- kind: User
  name: alice
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: admin
  apiGroup: rbac.authorization.k8s.io
EOF
info "alice: admin RoleBinding in dsf-mc namespace"

kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: authzen-test-alice-view
  namespace: dsf-mc-02
subjects:
- kind: User
  name: alice
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
EOF
info "alice: view RoleBinding in dsf-mc-02 namespace"

# ---------------------------------------------------------------------------
# 3. carol — coarse bindings (adminViewPermissionProcessor)
# ---------------------------------------------------------------------------
bold "Step 4: carol — admin on dsf-mc-02"

kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: authzen-test-carol-admin
  namespace: dsf-mc-02
subjects:
- kind: User
  name: carol
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: admin
  apiGroup: rbac.authorization.k8s.io
EOF
info "carol: admin RoleBinding in dsf-mc-02 namespace"

# ---------------------------------------------------------------------------
# 4. Placements + ManagedClusterSetBindings (required by MCRA clusterSelection)
# Each Placement uses the global clusterset and selects one cluster by name label.
# ---------------------------------------------------------------------------
bold "Step 5: Creating Placements (global clusterset, select by name label)"

for ns_cluster in "dsf-mc:dsf-mc" "dsf-mc-02:dsf-mc-02" "local-cluster:local-cluster"; do
  ns="${ns_cluster%%:*}"
  cluster="${ns_cluster##*:}"

  # ManagedClusterSetBinding — allows this namespace to use the global clusterset
  kubectl apply -f - <<EOF
apiVersion: cluster.open-cluster-management.io/v1beta2
kind: ManagedClusterSetBinding
metadata:
  name: global
  namespace: ${ns}
spec:
  clusterSet: global
EOF

  # Placement — selects the specific cluster by name label
  kubectl apply -f - <<EOF
apiVersion: cluster.open-cluster-management.io/v1beta1
kind: Placement
metadata:
  name: authzen-test-${cluster}
  namespace: ${ns}
spec:
  clusterSets:
  - global
  predicates:
  - requiredClusterSelector:
      labelSelector:
        matchLabels:
          name: ${cluster}
EOF
  info "Placement authzen-test-${cluster} in namespace ${ns} → selects cluster ${cluster}"
done

# ---------------------------------------------------------------------------
# 5. bob — MCRA on dsf-mc (app-frontend, app-backend, workload-admin)
# ---------------------------------------------------------------------------
bold "Step 6: bob — MCRA on dsf-mc (app-frontend + app-backend, write)"

kubectl apply -f - <<EOF
apiVersion: rbac.open-cluster-management.io/v1beta1
kind: MulticlusterRoleAssignment
metadata:
  name: authzen-test-bob-dsf-mc
  namespace: dsf-mc
spec:
  subject:
    kind: User
    name: bob
    apiGroup: rbac.authorization.k8s.io
  roleAssignments:
  - name: bob-workload-admin-dsf-mc
    clusterRole: acm-test:workload-admin
    clusterSelection:
      type: placements
      placements:
      - name: authzen-test-dsf-mc
        namespace: dsf-mc
    targetNamespaces:
    - ${NS_FAKE_1}
    - ${NS_FAKE_2}
EOF
info "bob: MCRA workload-admin on dsf-mc → ns $NS_FAKE_1, $NS_FAKE_2"

# ---------------------------------------------------------------------------
# 6. bob — MCRA on dsf-mc-02 (openshift-monitoring, workload-view)
# ---------------------------------------------------------------------------
bold "Step 7: bob — MCRA on dsf-mc-02 (openshift-monitoring, read-only)"

kubectl apply -f - <<EOF
apiVersion: rbac.open-cluster-management.io/v1beta1
kind: MulticlusterRoleAssignment
metadata:
  name: authzen-test-bob-dsf-mc-02
  namespace: dsf-mc-02
spec:
  subject:
    kind: User
    name: bob
    apiGroup: rbac.authorization.k8s.io
  roleAssignments:
  - name: bob-workload-view-dsf-mc-02
    clusterRole: acm-test:workload-view
    clusterSelection:
      type: placements
      placements:
      - name: authzen-test-dsf-mc-02
        namespace: dsf-mc-02
    targetNamespaces:
    - ${NS_REAL}
EOF
info "bob: MCRA workload-view on dsf-mc-02 → ns $NS_REAL"

# ---------------------------------------------------------------------------
# 7. carol — MCRA on local-cluster (app-frontend + openshift-monitoring, workload-admin)
# ---------------------------------------------------------------------------
bold "Step 8: carol — MCRA on local-cluster (app-frontend + openshift-monitoring, write)"

kubectl apply -f - <<EOF
apiVersion: rbac.open-cluster-management.io/v1beta1
kind: MulticlusterRoleAssignment
metadata:
  name: authzen-test-carol-local-cluster
  namespace: local-cluster
spec:
  subject:
    kind: User
    name: carol
    apiGroup: rbac.authorization.k8s.io
  roleAssignments:
  - name: carol-workload-admin-local-cluster
    clusterRole: acm-test:workload-admin
    clusterSelection:
      type: placements
      placements:
      - name: authzen-test-local-cluster
        namespace: local-cluster
    targetNamespaces:
    - ${NS_FAKE_1}
    - ${NS_REAL}
EOF
info "carol: MCRA workload-admin on local-cluster → ns $NS_FAKE_1, $NS_REAL"

# ---------------------------------------------------------------------------
# 8. Service accounts for impersonation testing
#
# authzen-search-sa  — has impersonate rights on users/groups, simulates Search/MCP
# authzen-unauth-sa  — has AuthZen endpoint access but NO impersonate rights
# ---------------------------------------------------------------------------
bold "Step 9: Creating service accounts for impersonation tests"

kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: authzen-search-sa
  namespace: open-cluster-management
EOF
info "Created authzen-search-sa (simulates Search / MCP server)"

kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: authzen-unauth-sa
  namespace: open-cluster-management
EOF
info "Created authzen-unauth-sa (no impersonate rights — should get 403)"

# ClusterRole: AuthZen endpoint access + impersonate on users and groups
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: authzen-test:impersonator
rules:
- apiGroups: [""]
  resources: ["users", "groups"]
  verbs: ["impersonate"]
- nonResourceURLs:
  - "/access/v1/evaluation"
  - "/access/v1/evaluations"
  - "/access/v1/search/resource"
  - "/access/v1/search/action"
  - "/.well-known/authzen-configuration"
  verbs: ["get", "post"]
EOF
info "Created ClusterRole authzen-test:impersonator"

kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: authzen-test:impersonator
subjects:
- kind: ServiceAccount
  name: authzen-search-sa
  namespace: open-cluster-management
roleRef:
  kind: ClusterRole
  name: authzen-test:impersonator
  apiGroup: rbac.authorization.k8s.io
EOF
info "Bound authzen-search-sa to authzen-test:impersonator"

# authzen-unauth-sa gets AuthZen endpoint access only — no impersonate
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: authzen-test:unauth
subjects:
- kind: ServiceAccount
  name: authzen-unauth-sa
  namespace: open-cluster-management
roleRef:
  kind: ClusterRole
  name: authzen-test:client
  apiGroup: rbac.authorization.k8s.io
EOF
info "Bound authzen-unauth-sa to authzen-test:client (endpoints only, no impersonate)"

# ---------------------------------------------------------------------------
# 9. Wait for cache to sync
# ---------------------------------------------------------------------------
bold "Step 10: Waiting 10s for UserPermission cache to sync"
sleep 10

echo ""
bold "=== Verifying cache (kubectl get userpermissions --as=<user>) ==="
for user in alice bob carol; do
  echo ""
  info "--- $user ---"
  kubectl get userpermissions --as="$user" -o json 2>/dev/null | python3 -c "
import json,sys
data=json.load(sys.stdin)
if not data['items']:
    print('  WARNING: no userpermissions found — cache may still be warming')
for item in data['items']:
    role=item['metadata']['name']
    bindings=item['status'].get('bindings',[])
    for b in bindings:
        ns=','.join(b.get('namespaces',[]))
        print(f'  role={role}  cluster={b[\"cluster\"]}  ns={ns}')
" 2>/dev/null || info "Could not verify (user may not have permissions to list)"
done

echo ""
bold "=== Done ==="
green "RBAC + MCRAs created for alice, bob, carol"
info "If userpermissions are empty above, wait 30s and re-run:"
info "  kubectl get userpermissions --as=alice"
info "  kubectl get userpermissions --as=bob"
info "  kubectl get userpermissions --as=carol"
