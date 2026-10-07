#!/usr/bin/env bash
# setup-authzen-fake-clusters.sh — creates fake ManagedCluster objects for clusters
# that the AuthZen test setup references but do not exist on this hub.
#
# Safe to run on any cluster — checks before acting:
#   - If a ManagedCluster already exists (real or fake), it is NOT touched.
#   - If a Placement already has tolerations, it is NOT patched.
#
# When to run:
#   Run AFTER setup-authzen-rbac.sh if kubectl get managedcluster shows that
#   dsf-mc or dsf-mc-02 are missing. Single-hub-only clusters (no managed clusters
#   registered) need this to simulate the multi-cluster permission model.
#
# Reverting:
#   kubectl delete managedcluster dsf-mc dsf-mc-02 --ignore-not-found
#   (Placement toleration patches are removed automatically when the ManagedCluster
#   is deleted — or patch manually: see REVERSE COMMANDS printed at end of run)

set -euo pipefail

# Clusters the AuthZen test setup targets
TARGET_CLUSTERS=("dsf-mc" "dsf-mc-02")
CLUSTERSET="default"

green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
info()  { printf '  %s\n' "$*"; }

CREATED_CLUSTERS=()
PATCHED_PLACEMENTS=()

bold "=== AuthZen fake managed cluster setup ==="
echo ""

for cluster in "${TARGET_CLUSTERS[@]}"; do

  bold "--- Cluster: $cluster ---"

  # -------------------------------------------------------------------------
  # Step 1: Create ManagedCluster if it doesn't exist
  # -------------------------------------------------------------------------
  if kubectl get managedcluster "$cluster" &>/dev/null 2>&1; then
    green "  ManagedCluster/$cluster already exists — skipping creation"
  else
    kubectl apply -f - <<EOF
apiVersion: cluster.open-cluster-management.io/v1
kind: ManagedCluster
metadata:
  name: ${cluster}
  labels:
    name: ${cluster}
    cluster.open-cluster-management.io/clusterset: ${CLUSTERSET}
    authzen-test/fake: "true"
spec:
  hubAcceptsClient: true
EOF
    green "  ManagedCluster/$cluster created (fake — no real cluster behind it)"
    CREATED_CLUSTERS+=("$cluster")
  fi

  # -------------------------------------------------------------------------
  # Step 2: Patch the Placement with tolerations if not already present
  # Placements default to excluding unavailable/unreachable clusters.
  # Fake clusters get the 'unreachable' taint immediately — tolerations needed.
  # -------------------------------------------------------------------------
  if kubectl get placement "authzen-test-${cluster}" -n "$cluster" &>/dev/null 2>&1; then
    HAS_TOLERATION=$(kubectl get placement "authzen-test-${cluster}" -n "$cluster" \
      -o jsonpath='{.spec.tolerations}' 2>/dev/null)
    if [ -n "$HAS_TOLERATION" ] && [ "$HAS_TOLERATION" != "null" ]; then
      green "  Placement/authzen-test-${cluster} already has tolerations — skipping patch"
    else
      kubectl patch placement "authzen-test-${cluster}" -n "$cluster" \
        --type=merge \
        -p='{"spec":{"tolerations":[
          {"key":"cluster.open-cluster-management.io/unreachable","operator":"Exists"},
          {"key":"cluster.open-cluster-management.io/unavailable","operator":"Exists"}
        ]}}'
      green "  Placement/authzen-test-${cluster} patched with tolerations"
      PATCHED_PLACEMENTS+=("authzen-test-${cluster}:${cluster}")
    fi
  else
    yellow "  Placement/authzen-test-${cluster} not found in namespace ${cluster} — run setup-authzen-rbac.sh first"
  fi

  echo ""
done

# -------------------------------------------------------------------------
# Step 3: Wait for PlacementDecisions to resolve
# -------------------------------------------------------------------------
bold "Waiting for Placements to resolve (up to 30s)..."
for i in $(seq 1 6); do
  sleep 5
  ALL_SCHEDULED=true
  for cluster in "${TARGET_CLUSTERS[@]}"; do
    STATUS=$(kubectl get placement "authzen-test-${cluster}" -n "$cluster" \
      -o jsonpath='{.status.conditions[?(@.type=="PlacementSatisfied")].status}' 2>/dev/null || echo "")
    if [ "$STATUS" != "True" ]; then
      ALL_SCHEDULED=false
    fi
  done
  $ALL_SCHEDULED && break
  printf "."
done
echo ""

# -------------------------------------------------------------------------
# Step 4: Verify userpermissions populated
# -------------------------------------------------------------------------
bold "Verifying userpermissions cache (waiting up to 15s)..."
sleep 15
echo ""
for user in alice bob carol; do
  echo "  --- $user ---"
  kubectl get userpermissions --as="$user" -o json 2>/dev/null | python3 -c "
import json,sys
data=json.load(sys.stdin)
if not data['items']:
    print('  WARNING: empty — cache may still be warming, retry in 30s')
for item in data['items']:
    role=item['metadata']['name']
    bindings=item['status'].get('bindings',[])
    for b in bindings:
        ns=','.join(b.get('namespaces',[]))
        print(f'    role={role}  cluster={b[\"cluster\"]}  ns={ns}')
" 2>/dev/null || info "Could not verify"
done

# -------------------------------------------------------------------------
# Summary and reverse commands
# -------------------------------------------------------------------------
echo ""
bold "=== Summary ==="

if [ ${#CREATED_CLUSTERS[@]} -eq 0 ] && [ ${#PATCHED_PLACEMENTS[@]} -eq 0 ]; then
  green "Nothing to do — all clusters already existed."
else
  if [ ${#CREATED_CLUSTERS[@]} -gt 0 ]; then
    green "Created fake ManagedClusters: ${CREATED_CLUSTERS[*]}"
  fi
  if [ ${#PATCHED_PLACEMENTS[@]} -gt 0 ]; then
    green "Patched Placements: ${PATCHED_PLACEMENTS[*]}"
  fi

  echo ""
  bold "=== Reverse commands (to undo everything) ==="
  for cluster in "${CREATED_CLUSTERS[@]}"; do
    echo "  kubectl delete managedcluster ${cluster}"
  done
  for entry in "${PATCHED_PLACEMENTS[@]}"; do
    name="${entry%%:*}"
    ns="${entry##*:}"
    echo "  kubectl patch placement ${name} -n ${ns} --type=json -p='[{\"op\":\"remove\",\"path\":\"/spec/tolerations\"}]'"
  done
fi
