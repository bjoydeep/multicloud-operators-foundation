#!/usr/bin/env bash
# setup-authzen-users.sh — creates HTPasswd IDP and test users alice, bob, carol
# on the hub cluster for AuthZen endpoint testing.
#
# Safe to run multiple times (idempotent).
#
# Creates:
#   - HTPasswd secret in openshift-config
#   - OAuth HTPasswd identity provider named "authzen-test"
#   - OpenShift User objects for alice, bob, carol
#
# Run ONCE before setup-authzen-rbac.sh.
# Cleanup: hack/teardown-authzen-test.sh

set -euo pipefail

HTPASSWD_SECRET="authzen-test-htpasswd"
IDP_NAME="authzen-test"
USERS=(alice bob carol)
PASSWORD="Authzen-Test-2026!"   # same password for all test users

green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
info()  { printf '  %s\n' "$*"; }

bold "=== AuthZen test user setup ==="
echo ""

# ---------------------------------------------------------------------------
# 1. Create htpasswd file
# ---------------------------------------------------------------------------
bold "Step 1: Creating htpasswd credentials"
HTPASSWD_FILE=$(mktemp)
trap "rm -f $HTPASSWD_FILE" EXIT

for user in "${USERS[@]}"; do
  htpasswd -bB "$HTPASSWD_FILE" "$user" "$PASSWORD" 2>/dev/null
  info "  $user — password set"
done

# ---------------------------------------------------------------------------
# 2. Create or update the secret in openshift-config
# ---------------------------------------------------------------------------
bold "Step 2: Creating HTPasswd secret in openshift-config"
if kubectl get secret "$HTPASSWD_SECRET" -n openshift-config &>/dev/null; then
  kubectl create secret generic "$HTPASSWD_SECRET" \
    --from-file=htpasswd="$HTPASSWD_FILE" \
    -n openshift-config \
    --dry-run=client -o yaml | kubectl apply -f -
  info "Updated existing secret $HTPASSWD_SECRET"
else
  kubectl create secret generic "$HTPASSWD_SECRET" \
    --from-file=htpasswd="$HTPASSWD_FILE" \
    -n openshift-config
  info "Created secret $HTPASSWD_SECRET"
fi

# ---------------------------------------------------------------------------
# 3. Add HTPasswd IDP to OAuth cluster object (non-destructive patch)
# ---------------------------------------------------------------------------
bold "Step 3: Configuring OAuth HTPasswd identity provider"

# Check if IDP already exists
EXISTING=$(kubectl get oauth cluster -o json | \
  python3 -c "
import json,sys
o=json.load(sys.stdin)
idps=o.get('spec',{}).get('identityProviders') or []
print(next((i['name'] for i in idps if i['name']=='${IDP_NAME}'),''))
" 2>/dev/null)

if [ "$EXISTING" = "$IDP_NAME" ]; then
  info "IDP '$IDP_NAME' already configured — skipping"
else
  # Append the new IDP to existing providers (preserves any existing IDPs)
  kubectl get oauth cluster -o json | python3 -c "
import json,sys
o=json.load(sys.stdin)
if 'spec' not in o: o['spec']={}
if not o['spec'].get('identityProviders'): o['spec']['identityProviders']=[]
o['spec']['identityProviders'].append({
  'name': '${IDP_NAME}',
  'type': 'HTPasswd',
  'htpasswd': {'fileData': {'name': '${HTPASSWD_SECRET}'}}
})
print(json.dumps(o))
" | kubectl apply -f -
  info "Added IDP '$IDP_NAME' to OAuth cluster config"
fi

# ---------------------------------------------------------------------------
# 4. Wait for OAuth operator to roll out
# ---------------------------------------------------------------------------
bold "Step 4: Waiting for OAuth server to roll out"
kubectl rollout status deployment/oauth-openshift -n openshift-authentication \
  --timeout=120s 2>/dev/null || \
kubectl rollout status deployment/oauth-openshift -n openshift-authentication \
  --timeout=120s 2>/dev/null || \
info "OAuth rollout check skipped (may take a moment to propagate)"

# ---------------------------------------------------------------------------
# 5. Pre-create User objects so RBAC bindings can reference them immediately
# ---------------------------------------------------------------------------
bold "Step 5: Creating OpenShift User objects"
for user in "${USERS[@]}"; do
  if kubectl get user "$user" &>/dev/null; then
    info "User $user already exists"
  else
    kubectl create -f - <<EOF
apiVersion: user.openshift.io/v1
kind: User
metadata:
  name: $user
EOF
    info "Created User $user"
  fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
bold "=== Done ==="
green "Users created: ${USERS[*]}"
green "Password for all: $PASSWORD"
echo ""
info "Next: run hack/setup-authzen-rbac.sh to create bindings and MCRAs"
info "Then: oc login --username alice --password '$PASSWORD'"
