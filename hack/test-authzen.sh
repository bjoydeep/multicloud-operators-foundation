#!/usr/bin/env bash
# test-authzen.sh — smoke tests for the AuthZen Authorization API endpoints
# on ocm-proxyserver. Tests the calling user AND alice/bob/carol if they exist.
#
# Usage:
#   ./hack/test-authzen.sh              # uses default port 9443
#   AUTHZEN_PORT=9444 ./hack/test-authzen.sh
#
# Prerequisites:
#   - ocm-proxyserver running (MCE operator scaled to 0, dev image deployed)
#   - oc whoami -t returns a valid token
#   - Optionally: hack/setup-authzen-users.sh + hack/setup-authzen-rbac.sh run

set -euo pipefail

LOCAL_PORT="${AUTHZEN_PORT:-9443}"
NAMESPACE="multicluster-engine"
SVC="ocm-proxyserver"
BASE="https://localhost:${LOCAL_PORT}"
PASSWORD="Authzen-Test-2026!"

# Namespace constants — must match setup-authzen-rbac.sh
NS_FAKE_1="app-frontend"
NS_FAKE_2="app-backend"
NS_REAL="openshift-monitoring"

PF_PID=""
PASS=0
FAIL=0

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }
dim()    { printf '\033[2m%s\033[0m\n' "$*"; }

pass() { PASS=$((PASS+1)); green "  PASS  $1"; }
fail() { FAIL=$((FAIL+1)); red   "  FAIL  $1"; [ -n "${2:-}" ] && dim "         $2"; }
skip() { yellow "  SKIP  $1"; }

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
authzen_post() {
  local token="$1" path="$2" body="$3"
  curl -sk -H "Authorization: Bearer $token" \
       -H "Content-Type: application/json" \
       -d "$body" "${BASE}${path}"
}

authzen_get() {
  local token="$1" path="$2"
  curl -sk -H "Authorization: Bearer $token" "${BASE}${path}"
}

authzen_post_code() {
  local token="$1" path="$2" body="$3"
  curl -sk -o /dev/null -w "%{http_code}" \
       -H "Authorization: Bearer $token" \
       -H "Content-Type: application/json" \
       -d "$body" "${BASE}${path}"
}

get_decision() {
  local json="$1"
  echo "$json" | python3 -c "import json,sys; print(json.load(sys.stdin).get('decision','PARSE_ERROR'))" 2>/dev/null
}

get_result_count() {
  local json="$1"
  echo "$json" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('results',[])))" 2>/dev/null || echo "0"
}

get_result_clusters() {
  local json="${1:-}"
  [ -z "$json" ] && echo "" && return
  echo "$json" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(' '.join(sorted(set(r['properties']['cluster'] for r in d.get('results',[])))))" 2>/dev/null
}

assert_decision() {
  local label="$1" token="$2" subject_id="$3" subject_type="$4" \
        verb="$5" resource="$6" cluster="$7" namespace="$8" apigroup="${9:-}" expected="${10}"
  local body resp decision
  body="{\"subject\":{\"type\":\"$subject_type\",\"id\":\"$subject_id\"},\
\"action\":{\"name\":\"$verb\"},\
\"resource\":{\"type\":\"$resource\",\"properties\":{\"cluster\":\"$cluster\",\"namespace\":\"$namespace\",\"apiGroup\":\"$apigroup\"}}}"
  resp=$(authzen_post "$token" "/access/v1/evaluation" "$body")
  decision=$(get_decision "$resp")
  if [ "$decision" = "$expected" ]; then
    pass "$label"
  else
    fail "$label" "expected=$expected actual=$decision  resp=$resp"
  fi
}

# ---------------------------------------------------------------------------
# Port-forward lifecycle
# ---------------------------------------------------------------------------
setup() {
  pkill -f "port-forward.*${SVC}" 2>/dev/null || true
  sleep 1
  kubectl port-forward "svc/${SVC}" -n "$NAMESPACE" "${LOCAL_PORT}:443" &>/dev/null &
  PF_PID=$!
  sleep 2
  if ! kill -0 "$PF_PID" 2>/dev/null; then
    red "ERROR: port-forward failed — is $SVC running in $NAMESPACE?"
    exit 1
  fi
}

teardown() { [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null || true; }
trap teardown EXIT

# ---------------------------------------------------------------------------
# Pre-flight: discover ground truth
# ---------------------------------------------------------------------------
preflight() {
  ADMIN_TOKEN=$(oc whoami -t 2>/dev/null || { red "ERROR: oc whoami -t failed"; exit 1; })
  ADMIN_USER=$(oc whoami 2>/dev/null || echo "unknown")

  bold "Ground truth from userpermissions API"
  bold "--------------------------------------"

  UP_JSON=$(kubectl get userpermissions -o json 2>/dev/null)
  ADMIN_CLUSTERS=$(echo "$UP_JSON" | python3 -c "
import json,sys
data=json.load(sys.stdin)
for item in data['items']:
    if item['metadata']['name'] == 'managedcluster:admin':
        for b in item['status'].get('bindings',[]):
            print(b['cluster'])
" 2>/dev/null)

  if [ -z "$ADMIN_CLUSTERS" ]; then
    red "ERROR: no userpermissions found — is the proxyserver cache warm?"
    exit 1
  fi

  FIRST_CLUSTER=$(echo "$ADMIN_CLUSTERS" | head -1)
  SECOND_CLUSTER=$(echo "$ADMIN_CLUSTERS" | sed -n '2p')
  CLUSTER_COUNT=$(echo "$ADMIN_CLUSTERS" | wc -l | tr -d ' ')

  printf "  %-22s %s\n" "Admin user:" "$ADMIN_USER"
  printf "  %-22s %s\n" "Proxyserver port:" "$LOCAL_PORT"
  printf "  %-22s\n"    "Admin clusters:"
  while IFS= read -r cluster; do
    tag=""; [ "$cluster" = "local-cluster" ] && tag=" (hub)"
    printf "    - %s%s\n" "$cluster" "$tag"
  done <<< "$ADMIN_CLUSTERS"
  echo ""

  # Check if test users exist
  ALICE_TOKEN=""
  BOB_TOKEN=""
  CAROL_TOKEN=""
  HAVE_TEST_USERS=false

  for user in alice bob carol; do
    if kubectl get user "$user" &>/dev/null 2>&1; then
      HAVE_TEST_USERS=true
      break
    fi
  done

  if $HAVE_TEST_USERS; then
    bold "Test user tokens"
    bold "----------------"
    # Get the API server URL from the current context — required for non-interactive oc login
    SERVER=$(oc whoami --show-server 2>/dev/null)

    get_token() {
      local user="$1"
      oc login "$SERVER" \
        --username="$user" --password="$PASSWORD" \
        --kubeconfig=/tmp/authzen-test-kubeconfig \
        --insecure-skip-tls-verify \
        &>/dev/null && \
      oc whoami -t --kubeconfig=/tmp/authzen-test-kubeconfig 2>/dev/null || echo ""
    }

    ALICE_TOKEN=$(get_token alice)
    BOB_TOKEN=$(get_token bob)
    CAROL_TOKEN=$(get_token carol)

    # Restore original login
    oc login --token="$ADMIN_TOKEN" --server="$SERVER" &>/dev/null 2>&1 || true
    rm -f /tmp/authzen-test-kubeconfig

    printf "  %-10s %s\n" "alice:" "$([ -n "$ALICE_TOKEN" ] && echo 'token acquired' || echo 'FAILED — run setup-authzen-users.sh')"
    printf "  %-10s %s\n" "bob:"   "$([ -n "$BOB_TOKEN"   ] && echo 'token acquired' || echo 'FAILED — run setup-authzen-users.sh')"
    printf "  %-10s %s\n" "carol:" "$([ -n "$CAROL_TOKEN" ] && echo 'token acquired' || echo 'FAILED — run setup-authzen-users.sh')"
    echo ""
  else
    dim "  Test users (alice/bob/carol) not found — run setup-authzen-users.sh + setup-authzen-rbac.sh"
    dim "  Only admin user tests will run."
    echo ""
  fi

  # Service account tokens for impersonation tests (from kubectl create token — no login needed)
  SEARCH_SA_TOKEN=""
  UNAUTH_SA_TOKEN=""
  if kubectl get serviceaccount authzen-search-sa -n open-cluster-management &>/dev/null; then
    SEARCH_SA_TOKEN=$(kubectl create token authzen-search-sa -n open-cluster-management --duration=1h 2>/dev/null || echo "")
    UNAUTH_SA_TOKEN=$(kubectl create token authzen-unauth-sa -n open-cluster-management --duration=1h 2>/dev/null || echo "")
    bold "Service account tokens"
    bold "----------------------"
    printf "  %-22s %s\n" "authzen-search-sa:" "$([ -n "$SEARCH_SA_TOKEN" ] && echo 'token acquired' || echo 'FAILED')"
    printf "  %-22s %s\n" "authzen-unauth-sa:" "$([ -n "$UNAUTH_SA_TOKEN" ] && echo 'token acquired' || echo 'FAILED')"
    echo ""
  fi
}

# ---------------------------------------------------------------------------
# Test suites
# ---------------------------------------------------------------------------

suite_discovery() {
  bold "=== Suite: Discovery ==="
  local resp
  resp=$(authzen_get "$ADMIN_TOKEN" "/.well-known/authzen-configuration")

  # Spec-compliant field names
  local pdp eval_ep eval_batch_ep search_ep
  pdp=$(echo "$resp"         | python3 -c "import json,sys; print(json.load(sys.stdin).get('policy_decision_point',''))" 2>/dev/null)
  eval_ep=$(echo "$resp"     | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_evaluation_endpoint',''))" 2>/dev/null)
  eval_batch_ep=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_evaluations_endpoint',''))" 2>/dev/null)
  search_ep=$(echo "$resp"   | python3 -c "import json,sys; print(json.load(sys.stdin).get('search_resource_endpoint',''))" 2>/dev/null)

  [ -n "$pdp" ] && pass "discovery: policy_decision_point present ($pdp)" || fail "discovery: policy_decision_point missing" "resp=$resp"
  [[ "$eval_ep" == https://* ]] && pass "discovery: access_evaluation_endpoint is absolute URL" || fail "discovery: access_evaluation_endpoint not absolute URL" "got=$eval_ep"
  [[ "$eval_batch_ep" == https://* ]] && pass "discovery: access_evaluations_endpoint is absolute URL" || fail "discovery: access_evaluations_endpoint not absolute URL" "got=$eval_batch_ep"
  [[ "$search_ep" == https://* ]] && pass "discovery: search_resource_endpoint is absolute URL" || fail "discovery: search_resource_endpoint not absolute URL" "got=$search_ep"

  # Old non-spec keys must NOT appear
  local old_key
  old_key=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_evaluation_v1_endpoint','ABSENT'))" 2>/dev/null)
  [ "$old_key" = "ABSENT" ] && pass "discovery: old non-spec key absent" || fail "discovery: old non-spec key still present" "got=$old_key"

  # Resource type convention advertised
  local convention
  convention=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('resource_type_convention',''))" 2>/dev/null)
  [ "$convention" = "resource_name_only" ] && pass "discovery: resource_type_convention=resource_name_only" || fail "discovery: resource_type_convention missing" "got=$convention"

  # search/action endpoint advertised
  local action_ep
  action_ep=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('search_action_endpoint',''))" 2>/dev/null)
  [[ "$action_ep" == https://* ]] && pass "discovery: search_action_endpoint is absolute URL" || fail "discovery: search_action_endpoint missing or not absolute" "got=$action_ep"
}

suite_auth_enforcement() {
  bold "=== Suite: Auth enforcement ==="

  # Use alice's token — alice has endpoint access but no impersonate rights,
  # so cross-subject queries must return 403.
  # (kube:admin is cluster-admin and CAN impersonate anyone — wrong caller for this test)
  local caller_token="$ALICE_TOKEN"
  local caller_label="alice"
  if [ -z "$caller_token" ]; then
    caller_token="$UNAUTH_SA_TOKEN"
    caller_label="unauth-sa"
  fi
  if [ -z "$caller_token" ]; then
    skip "auth enforcement tests (need alice or unauth-sa token)"
    return
  fi

  local code
  code=$(authzen_post_code "$caller_token" "/access/v1/evaluation" \
    "{\"subject\":{\"type\":\"user\",\"id\":\"someone-else\"},\"action\":{\"name\":\"get\"},\"resource\":{\"type\":\"pods\",\"properties\":{\"cluster\":\"$FIRST_CLUSTER\",\"namespace\":\"default\"}}}")
  assert_http "403 when $caller_label queries someone-else (no impersonate rights)" "$code" "403"

  code=$(authzen_post_code "$caller_token" "/access/v1/evaluation" \
    "{\"subject\":{\"type\":\"group\",\"id\":\"not-my-group\"},\"action\":{\"name\":\"get\"},\"resource\":{\"type\":\"pods\",\"properties\":{\"cluster\":\"$FIRST_CLUSTER\",\"namespace\":\"default\"}}}")
  assert_http "403 when $caller_label queries non-member group (no impersonate rights)" "$code" "403"
}

assert_http() {
  local label="$1" got="$2" expected="$3"
  [ "$got" = "$expected" ] && pass "$label (HTTP $got)" || fail "$label" "expected HTTP $expected got HTTP $got"
}

suite_admin_user() {
  bold "=== Suite: Admin user ($ADMIN_USER) ==="

  # Every known cluster → true
  while IFS= read -r cluster; do
    assert_decision "get pods on $cluster → true" \
      "$ADMIN_TOKEN" "$ADMIN_USER" "user" "get" "pods" "$cluster" "default" "" "True"
  done <<< "$ADMIN_CLUSTERS"

  # Unknown cluster → false
  assert_decision "get pods on ghost-cluster → false" \
    "$ADMIN_TOKEN" "$ADMIN_USER" "user" "get" "pods" "ghost-cluster" "default" "" "False"

  # Write verb on known cluster → true (admin)
  assert_decision "create deployment on $FIRST_CLUSTER → true" \
    "$ADMIN_TOKEN" "$ADMIN_USER" "user" "create" "deployments" "$FIRST_CLUSTER" "default" "apps" "True"

  # Batch: known / ghost / known  →  true / false / true
  local resp batch_body
  batch_body="{\"subject\":{\"type\":\"user\",\"id\":\"$ADMIN_USER\"},\"action\":{\"name\":\"get\"},\
\"evaluations\":[\
{\"type\":\"pods\",\"properties\":{\"cluster\":\"$FIRST_CLUSTER\",\"namespace\":\"default\"}},\
{\"type\":\"pods\",\"properties\":{\"cluster\":\"ghost-cluster\",\"namespace\":\"default\"}},\
{\"type\":\"pods\",\"properties\":{\"cluster\":\"$SECOND_CLUSTER\",\"namespace\":\"default\"}}]}"
  resp=$(authzen_post "$ADMIN_TOKEN" "/access/v1/evaluations" "$batch_body")
  local d0 d1 d2
  d0=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin)['evaluations'][0]['decision'])" 2>/dev/null)
  d1=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin)['evaluations'][1]['decision'])" 2>/dev/null)
  d2=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin)['evaluations'][2]['decision'])" 2>/dev/null)
  [ "$d0" = "True" ]  && pass "batch[0] $FIRST_CLUSTER → true"  || fail "batch[0] $FIRST_CLUSTER → true"  "got $d0"
  [ "$d1" = "False" ] && pass "batch[1] ghost-cluster → false" || fail "batch[1] ghost-cluster → false" "got $d1"
  [ "$d2" = "True" ]  && pass "batch[2] $SECOND_CLUSTER → true"  || fail "batch[2] $SECOND_CLUSTER → true"  "got $d2"

  # search/resource: result count matches cluster count
  resp=$(authzen_post "$ADMIN_TOKEN" "/access/v1/search/resource" \
    "{\"subject\":{\"type\":\"user\",\"id\":\"$ADMIN_USER\"},\"action\":{\"name\":\"get\"},\"resource\":{\"type\":\"pods\"}}")
  local cnt
  cnt=$(get_result_count "$resp")
  [ "$cnt" = "$CLUSTER_COUNT" ] \
    && pass "search/resource returns $cnt scopes (= $CLUSTER_COUNT clusters)" \
    || fail "search/resource count" "expected $CLUSTER_COUNT got $cnt"
}

suite_alice() {
  [ -z "$ALICE_TOKEN" ] && skip "alice tests (no token)" && return
  bold "=== Suite: alice — admin on dsf-mc, view on dsf-mc-02, no access on local-cluster ==="

  # dsf-mc: admin → get and create both true
  assert_decision "alice: get pods on dsf-mc → true" \
    "$ALICE_TOKEN" "alice" "user" "get" "pods" "dsf-mc" "default" "" "True"
  assert_decision "alice: create pods on dsf-mc → true (admin)" \
    "$ALICE_TOKEN" "alice" "user" "create" "pods" "dsf-mc" "default" "" "True"

  # dsf-mc-02: view → get true, create false
  assert_decision "alice: get pods on dsf-mc-02 → true (view)" \
    "$ALICE_TOKEN" "alice" "user" "get" "pods" "dsf-mc-02" "default" "" "True"
  assert_decision "alice: create pods on dsf-mc-02 → false (view only)" \
    "$ALICE_TOKEN" "alice" "user" "create" "pods" "dsf-mc-02" "default" "" "False"

  # local-cluster: no access
  assert_decision "alice: get pods on local-cluster → false (no access)" \
    "$ALICE_TOKEN" "alice" "user" "get" "pods" "local-cluster" "default" "" "False"

  # search/resource: dsf-mc and dsf-mc-02 only (not local-cluster)
  local resp clusters
  resp=$(authzen_post "$ALICE_TOKEN" "/access/v1/search/resource" \
    '{"subject":{"type":"user","id":"alice"},"action":{"name":"get"},"resource":{"type":"pods"}}')
  clusters=$(get_result_clusters "$resp")
  [[ "$clusters" == *"dsf-mc"*    ]] && pass "alice: search includes dsf-mc"       || fail "alice: search includes dsf-mc"       "got: $clusters"
  [[ "$clusters" == *"dsf-mc-02"* ]] && pass "alice: search includes dsf-mc-02"    || fail "alice: search includes dsf-mc-02"    "got: $clusters"
  [[ "$clusters" != *"local-cluster"* ]] && pass "alice: search excludes local-cluster" || fail "alice: search excludes local-cluster" "got: $clusters"
}

suite_bob() {
  [ -z "$BOB_TOKEN" ] && skip "bob tests (no token)" && return
  bold "=== Suite: bob — MCRA on dsf-mc (app-frontend/app-backend), dsf-mc-02 (openshift-monitoring read), no access on local-cluster ==="

  # dsf-mc, in-scope ns: true for both fake namespaces
  assert_decision "bob: get pods on dsf-mc ns=$NS_FAKE_1 → true (MCRA in-scope)" \
    "$BOB_TOKEN" "bob" "user" "get" "pods" "dsf-mc" "$NS_FAKE_1" "" "True"
  assert_decision "bob: get pods on dsf-mc ns=$NS_FAKE_2 → true (MCRA in-scope)" \
    "$BOB_TOKEN" "bob" "user" "get" "pods" "dsf-mc" "$NS_FAKE_2" "" "True"

  # dsf-mc, write in-scope ns: true (workload-admin)
  assert_decision "bob: create pods on dsf-mc ns=$NS_FAKE_1 → true (workload-admin)" \
    "$BOB_TOKEN" "bob" "user" "create" "pods" "dsf-mc" "$NS_FAKE_1" "" "True"

  # dsf-mc, out-of-scope ns: false
  assert_decision "bob: get pods on dsf-mc ns=kube-system → false (out of MCRA scope)" \
    "$BOB_TOKEN" "bob" "user" "get" "pods" "dsf-mc" "kube-system" "" "False"
  assert_decision "bob: get pods on dsf-mc ns=$NS_REAL → false (not in MCRA for dsf-mc)" \
    "$BOB_TOKEN" "bob" "user" "get" "pods" "dsf-mc" "$NS_REAL" "" "False"

  # dsf-mc-02, real ns: get true, create false (workload-view)
  assert_decision "bob: get pods on dsf-mc-02 ns=$NS_REAL → true (MCRA view in-scope)" \
    "$BOB_TOKEN" "bob" "user" "get" "pods" "dsf-mc-02" "$NS_REAL" "" "True"
  assert_decision "bob: create pods on dsf-mc-02 ns=$NS_REAL → false (view only)" \
    "$BOB_TOKEN" "bob" "user" "create" "pods" "dsf-mc-02" "$NS_REAL" "" "False"

  # dsf-mc-02, out-of-scope ns: false
  assert_decision "bob: get pods on dsf-mc-02 ns=$NS_FAKE_1 → false (out of MCRA scope)" \
    "$BOB_TOKEN" "bob" "user" "get" "pods" "dsf-mc-02" "$NS_FAKE_1" "" "False"

  # local-cluster: no access
  assert_decision "bob: get pods on local-cluster → false (no access)" \
    "$BOB_TOKEN" "bob" "user" "get" "pods" "local-cluster" "default" "" "False"

  # search/resource: dsf-mc (2 ns) + dsf-mc-02 (1 ns)
  local resp cnt
  resp=$(authzen_post "$BOB_TOKEN" "/access/v1/search/resource" \
    '{"subject":{"type":"user","id":"bob"},"action":{"name":"get"},"resource":{"type":"pods"}}')
  cnt=$(get_result_count "$resp")
  [ "$cnt" = "3" ] \
    && pass "bob: search returns 3 scopes ($NS_FAKE_1, $NS_FAKE_2 on dsf-mc + $NS_REAL on dsf-mc-02)" \
    || fail "bob: search scope count" "expected 3 got $cnt  resp=$resp"
}

suite_carol() {
  [ -z "$CAROL_TOKEN" ] && skip "carol tests (no token)" && return
  bold "=== Suite: carol — no access on dsf-mc, admin on dsf-mc-02, MCRA on local-cluster (app-frontend + openshift-monitoring) ==="

  # dsf-mc: no access
  assert_decision "carol: get pods on dsf-mc → false (no access)" \
    "$CAROL_TOKEN" "carol" "user" "get" "pods" "dsf-mc" "default" "" "False"

  # dsf-mc-02: admin → get and create both true
  assert_decision "carol: get pods on dsf-mc-02 → true (admin)" \
    "$CAROL_TOKEN" "carol" "user" "get" "pods" "dsf-mc-02" "default" "" "True"
  assert_decision "carol: create pods on dsf-mc-02 → true (admin)" \
    "$CAROL_TOKEN" "carol" "user" "create" "pods" "dsf-mc-02" "default" "" "True"

  # local-cluster: MCRA — fake ns true, real ns true, out-of-scope ns false
  assert_decision "carol: get pods on local-cluster ns=$NS_FAKE_1 → true (MCRA in-scope fake ns)" \
    "$CAROL_TOKEN" "carol" "user" "get" "pods" "local-cluster" "$NS_FAKE_1" "" "True"
  assert_decision "carol: create pods on local-cluster ns=$NS_FAKE_1 → true (workload-admin)" \
    "$CAROL_TOKEN" "carol" "user" "create" "pods" "local-cluster" "$NS_FAKE_1" "" "True"
  assert_decision "carol: get pods on local-cluster ns=$NS_REAL → true (MCRA in-scope real ns)" \
    "$CAROL_TOKEN" "carol" "user" "get" "pods" "local-cluster" "$NS_REAL" "" "True"
  assert_decision "carol: get pods on local-cluster ns=default → false (out of MCRA scope)" \
    "$CAROL_TOKEN" "carol" "user" "get" "pods" "local-cluster" "default" "" "False"
  assert_decision "carol: get pods on local-cluster ns=kube-system → false (out of MCRA scope)" \
    "$CAROL_TOKEN" "carol" "user" "get" "pods" "local-cluster" "kube-system" "" "False"

  # search/resource: dsf-mc-02 + local-cluster (2 ns)
  local resp cnt clusters
  resp=$(authzen_post "$CAROL_TOKEN" "/access/v1/search/resource" \
    '{"subject":{"type":"user","id":"carol"},"action":{"name":"get"},"resource":{"type":"pods"}}')
  cnt=$(get_result_count "$resp")
  clusters=$(get_result_clusters "$resp")
  [[ "$clusters" != *"dsf-mc "* && "$clusters" != "dsf-mc" ]] \
    && pass "carol: search excludes dsf-mc" \
    || fail "carol: search excludes dsf-mc" "got clusters: $clusters"
  [[ "$clusters" == *"dsf-mc-02"* ]] \
    && pass "carol: search includes dsf-mc-02" \
    || fail "carol: search includes dsf-mc-02" "got clusters: $clusters"
  [[ "$clusters" == *"local-cluster"* ]] \
    && pass "carol: search includes local-cluster" \
    || fail "carol: search includes local-cluster" "got clusters: $clusters"
  # dsf-mc-02 = 1 scope (*), local-cluster = 2 scopes (app-frontend + openshift-monitoring) = 3 total
  [ "$cnt" = "3" ] \
    && pass "carol: search returns 3 scopes (1 on dsf-mc-02, 2 on local-cluster)" \
    || fail "carol: search scope count" "expected 3 got $cnt"
}

suite_search_action() {
  bold "=== Suite: search/action (what verbs can subject do on resource?) ==="

  [ -z "$ALICE_TOKEN" ] && skip "search/action tests (alice not set up)" && return

  local resp verbs cnt
  # alice has admin on dsf-mc → ≥7 verbs (wildcard expanded)
  resp=$(authzen_post "$ALICE_TOKEN" "/access/v1/search/action" \
    '{"subject":{"type":"user","id":"alice"},"resource":{"type":"pods","properties":{"cluster":"dsf-mc","namespace":"default","apiGroup":""}}}')
  verbs=$(echo "$resp" | python3 -c "import json,sys; print(sorted([a['name'] for a in json.load(sys.stdin).get('actions',[])]))" 2>/dev/null)
  cnt=$(echo "$resp"   | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('actions',[])))" 2>/dev/null)
  [ "$cnt" -ge 7 ] \
    && pass "search/action: alice admin on dsf-mc returns $cnt verbs: $verbs" \
    || fail "search/action: alice admin on dsf-mc expected ≥7 verbs, got $cnt — $verbs"

  # alice has VIEW on dsf-mc-02 → only get/list/watch
  resp=$(authzen_post "$ALICE_TOKEN" "/access/v1/search/action" \
    '{"subject":{"type":"user","id":"alice"},"resource":{"type":"pods","properties":{"cluster":"dsf-mc-02","namespace":"default","apiGroup":""}}}')
  cnt=$(echo "$resp"   | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('actions',[])))" 2>/dev/null)
  verbs=$(echo "$resp" | python3 -c "import json,sys; print(sorted([a['name'] for a in json.load(sys.stdin).get('actions',[])]))" 2>/dev/null)
  [ "$cnt" = "3" ] \
    && pass "search/action: alice view on dsf-mc-02 returns 3 verbs: $verbs" \
    || fail "search/action: alice view on dsf-mc-02 expected 3 verbs (get/list/watch), got $cnt — $verbs"

  # no-access cluster → empty list
  resp=$(authzen_post "$ALICE_TOKEN" "/access/v1/search/action" \
    "{\"subject\":{\"type\":\"user\",\"id\":\"alice\"},\
\"resource\":{\"type\":\"pods\",\"properties\":{\"cluster\":\"ghost-cluster\",\"namespace\":\"default\",\"apiGroup\":\"\"}}}")
  cnt=$(echo "$resp" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('actions',[])))" 2>/dev/null)
  [ "$cnt" = "0" ] \
    && pass "search/action: ghost-cluster returns empty list" \
    || fail "search/action: ghost-cluster should return empty, got $cnt"

  # bob MCRA (workload-admin) on dsf-mc/app-frontend → create allowed
  [ -z "$BOB_TOKEN" ] && return
  resp=$(authzen_post "$BOB_TOKEN" "/access/v1/search/action" \
    "{\"subject\":{\"type\":\"user\",\"id\":\"bob\"},\
\"resource\":{\"type\":\"pods\",\"properties\":{\"cluster\":\"dsf-mc\",\"namespace\":\"$NS_FAKE_1\",\"apiGroup\":\"\"}}}")
  verbs=$(echo "$resp" | python3 -c "import json,sys; print(sorted([a['name'] for a in json.load(sys.stdin).get('actions',[])]))" 2>/dev/null)
  has_create=$(echo "$resp" | python3 -c "import json,sys; print('create' in [a['name'] for a in json.load(sys.stdin).get('actions',[])])" 2>/dev/null)
  [ "$has_create" = "True" ] \
    && pass "search/action: bob workload-admin on $NS_FAKE_1 includes create: $verbs" \
    || fail "search/action: bob workload-admin should include create, got $verbs"

  # bob MCRA (workload-view) on dsf-mc-02/openshift-monitoring → create NOT allowed
  resp=$(authzen_post "$BOB_TOKEN" "/access/v1/search/action" \
    "{\"subject\":{\"type\":\"user\",\"id\":\"bob\"},\
\"resource\":{\"type\":\"pods\",\"properties\":{\"cluster\":\"dsf-mc-02\",\"namespace\":\"$NS_REAL\",\"apiGroup\":\"\"}}}")
  has_create=$(echo "$resp" | python3 -c "import json,sys; print('create' in [a['name'] for a in json.load(sys.stdin).get('actions',[])])" 2>/dev/null)
  has_get=$(echo "$resp"    | python3 -c "import json,sys; print('get' in [a['name'] for a in json.load(sys.stdin).get('actions',[])])" 2>/dev/null)
  [ "$has_create" = "False" ] && [ "$has_get" = "True" ] \
    && pass "search/action: bob workload-view on $NS_REAL has get but not create" \
    || fail "search/action: bob view expected get=True create=False, got get=$has_get create=$has_create"
}

suite_search_resources() {
  bold "=== Suite: search/resources — bulk + wildcard ==="
  [ -z "$ALICE_TOKEN" ] && skip "search/resources tests (alice not set up)" && return

  local resp cnt

  # --- Explicit list mode ---
  # alice has admin on dsf-mc and view on dsf-mc-02 — both should appear for pods
  resp=$(authzen_post "$ALICE_TOKEN" "/access/v1/search/resources" \
    '{"subject":{"type":"user","id":"alice"},"action":{"name":"get"},
"resources":[
  {"type":"pods","properties":{"apiGroup":""}},
  {"type":"deployments","properties":{"apiGroup":"apps"}}
]}')
  cnt=$(echo "$resp" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('results',[])))" 2>/dev/null)
  [ "$cnt" = "2" ] \
    && pass "search/resources explicit: 2 types returned (pods, deployments)" \
    || fail "search/resources explicit: expected 2 results, got $cnt — resp=$resp"

  # apiGroup precision — bob has acm-test:workload-admin (apiGroups: ["","apps","batch"])
  # asking for pods.kubevirt.io should return empty (bob has no kubevirt.io access)
  # Note: alice (admin/wildcard) would match anything — wrong subject for this check
  [ -n "$BOB_TOKEN" ] && {
    resp=$(authzen_post "$BOB_TOKEN" "/access/v1/search/resources" \
      '{"subject":{"type":"user","id":"bob"},"action":{"name":"get"},
"resources":[
  {"type":"pods","properties":{"apiGroup":"kubevirt.io"}}
]}')
    cnt=$(echo "$resp" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('results',[])))" 2>/dev/null)
    [ "$cnt" = "0" ] \
      && pass "search/resources explicit: apiGroup precision — bob has no kubevirt.io access, returns empty" \
      || fail "search/resources explicit: apiGroup precision failed, got $cnt results (bob should not match kubevirt.io)"
  }

  # --- Wildcard mode ---
  resp=$(authzen_post "$ALICE_TOKEN" "/access/v1/search/resources" \
    '{"subject":{"type":"user","id":"alice"},"action":{"name":"get"},"all_resource_types":true}')
  # alice has managedcluster:admin (resources:["*"]) on dsf-mc and managedcluster:view on dsf-mc-02
  # wildcard mode should emit type="*" entries
  local has_wildcard
  has_wildcard=$(echo "$resp" | python3 -c "
import json,sys
results=json.load(sys.stdin).get('results',[])
print('yes' if any(r.get('type')=='*' for r in results) else 'no')
" 2>/dev/null)
  [ "$has_wildcard" = "yes" ] \
    && pass "search/resources wildcard: type='*' entries present for admin grants" \
    || fail "search/resources wildcard: expected type='*' entries for alice's admin grant" "resp=$resp"

  # wildcard mode — no access on local-cluster means no local-cluster scopes under type="*"
  local clusters_in_wildcard
  clusters_in_wildcard=$(echo "$resp" | python3 -c "
import json,sys
results=json.load(sys.stdin).get('results',[])
clusters=set()
for r in results:
    for s in r.get('scopes',[]):
        clusters.add(s.get('cluster',''))
print(' '.join(sorted(clusters)))
" 2>/dev/null)
  [[ "$clusters_in_wildcard" != *"local-cluster"* ]] \
    && pass "search/resources wildcard: local-cluster absent (alice has no access)" \
    || fail "search/resources wildcard: local-cluster should not appear" "clusters=$clusters_in_wildcard"

  # --- Bad request — neither mode set ---
  local code
  code=$(authzen_post_code "$ALICE_TOKEN" "/access/v1/search/resources" \
    '{"subject":{"type":"user","id":"alice"},"action":{"name":"get"}}')
  assert_http "search/resources: 400 when neither mode set" "$code" "400"

  # --- Bob wildcard mode — MCRA grants should appear as specific types ---
  [ -z "$BOB_TOKEN" ] && return
  resp=$(authzen_post "$BOB_TOKEN" "/access/v1/search/resources" \
    '{"subject":{"type":"user","id":"bob"},"action":{"name":"get"},"all_resource_types":true}')
  # bob has acm-test:workload-admin (pods/deployments/etc, NOT wildcard resources)
  # so results should be specific types, NOT type="*"
  has_wildcard=$(echo "$resp" | python3 -c "
import json,sys
results=json.load(sys.stdin).get('results',[])
print('yes' if any(r.get('type')=='*' for r in results) else 'no')
" 2>/dev/null)
  [ "$has_wildcard" = "no" ] \
    && pass "search/resources wildcard: bob MCRA returns specific types (not wildcard)" \
    || fail "search/resources wildcard: bob MCRA should not emit type='*'" "resp=$resp"
}

suite_namespace_security() {
  # Tests the namespace=="" fix: omitting namespace must not grant access.
  # bob has namespace-scoped MCRA access (app-frontend, app-backend on dsf-mc) — ideal test subject.
  [ -z "$BOB_TOKEN" ] && skip "namespace security tests (bob not set up)" && return
  bold "=== Suite: Namespace security (namespace==\"\" no longer false-allows) ==="

  # empty namespace → denied, even though bob has access to specific namespaces on dsf-mc
  assert_decision "bob: empty namespace on dsf-mc → false (must not wildcard-match)" \
    "$BOB_TOKEN" "bob" "user" "get" "pods" "dsf-mc" "" "" "False"

  # explicit in-scope namespace → allowed (baseline still works)
  assert_decision "bob: ns=app-frontend on dsf-mc → true (in-scope MCRA)" \
    "$BOB_TOKEN" "bob" "user" "get" "pods" "dsf-mc" "app-frontend" "" "True"

  # explicit out-of-scope namespace → denied (not a regression from the fix)
  assert_decision "bob: ns=kube-system on dsf-mc → false (out-of-scope MCRA)" \
    "$BOB_TOKEN" "bob" "user" "get" "pods" "dsf-mc" "kube-system" "" "False"
}

suite_batch_semantics() {
  # Tests options.evaluations_semantic short-circuit behaviour.
  # Uses alice: FIRST_CLUSTER=allowed, ghost-cluster=denied, SECOND_CLUSTER=allowed.
  [ -z "$ALICE_TOKEN" ] && skip "batch semantics tests (alice not set up)" && return
  bold "=== Suite: Batch semantics (options.evaluations_semantic) ==="

  # execute_all (default) — all 3 items returned
  local resp cnt
  resp=$(authzen_post "$ALICE_TOKEN" "/access/v1/evaluations" \
    "{\"subject\":{\"type\":\"user\",\"id\":\"alice\"},\"action\":{\"name\":\"get\"},\
\"evaluations\":[\
{\"type\":\"pods\",\"properties\":{\"cluster\":\"$FIRST_CLUSTER\",\"namespace\":\"default\"}},\
{\"type\":\"pods\",\"properties\":{\"cluster\":\"ghost-cluster\",\"namespace\":\"default\"}},\
{\"type\":\"pods\",\"properties\":{\"cluster\":\"$SECOND_CLUSTER\",\"namespace\":\"default\"}}]}")
  cnt=$(echo "$resp" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('evaluations',[])))" 2>/dev/null)
  [ "$cnt" = "3" ] \
    && pass "execute_all (default): all 3 items returned" \
    || fail "execute_all: expected 3 items, got $cnt"

  # deny_on_first_deny — true, false, true → stops after item 2 (first deny)
  resp=$(authzen_post "$ALICE_TOKEN" "/access/v1/evaluations" \
    "{\"subject\":{\"type\":\"user\",\"id\":\"alice\"},\"action\":{\"name\":\"get\"},\
\"options\":{\"evaluations_semantic\":\"deny_on_first_deny\"},\
\"evaluations\":[\
{\"type\":\"pods\",\"properties\":{\"cluster\":\"$FIRST_CLUSTER\",\"namespace\":\"default\"}},\
{\"type\":\"pods\",\"properties\":{\"cluster\":\"ghost-cluster\",\"namespace\":\"default\"}},\
{\"type\":\"pods\",\"properties\":{\"cluster\":\"$SECOND_CLUSTER\",\"namespace\":\"default\"}}]}")
  cnt=$(echo "$resp" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('evaluations',[])))" 2>/dev/null)
  [ "$cnt" = "2" ] \
    && pass "deny_on_first_deny: stopped at 2 items (first deny was item 2)" \
    || fail "deny_on_first_deny: expected 2 items, got $cnt — resp=$resp"

  # permit_on_first_permit — false, true, true → stops after item 2 (first permit)
  resp=$(authzen_post "$ALICE_TOKEN" "/access/v1/evaluations" \
    "{\"subject\":{\"type\":\"user\",\"id\":\"alice\"},\"action\":{\"name\":\"get\"},\
\"options\":{\"evaluations_semantic\":\"permit_on_first_permit\"},\
\"evaluations\":[\
{\"type\":\"pods\",\"properties\":{\"cluster\":\"ghost-cluster\",\"namespace\":\"default\"}},\
{\"type\":\"pods\",\"properties\":{\"cluster\":\"$FIRST_CLUSTER\",\"namespace\":\"default\"}},\
{\"type\":\"pods\",\"properties\":{\"cluster\":\"$SECOND_CLUSTER\",\"namespace\":\"default\"}}]}")
  cnt=$(echo "$resp" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('evaluations',[])))" 2>/dev/null)
  [ "$cnt" = "2" ] \
    && pass "permit_on_first_permit: stopped at 2 items (first permit was item 2)" \
    || fail "permit_on_first_permit: expected 2 items, got $cnt — resp=$resp"
}

suite_impersonation() {
  [ -z "$SEARCH_SA_TOKEN" ] && skip "impersonation tests (authzen-search-sa not found — run setup-authzen-rbac.sh)" && return
  [ -z "$ALICE_TOKEN" ]     && skip "impersonation tests (alice not set up — run setup-authzen-users.sh)" && return

  bold "=== Suite: Impersonation — search-sa queries on behalf of alice ==="

  # search-sa can reach the endpoint (not 403)
  local code
  code=$(authzen_post_code "$SEARCH_SA_TOKEN" "/access/v1/evaluation" \
    "{\"subject\":{\"type\":\"user\",\"id\":\"alice\"},\"action\":{\"name\":\"get\"},\"resource\":{\"type\":\"pods\",\"properties\":{\"cluster\":\"dsf-mc\",\"namespace\":\"default\"}}}")
  assert_http "search-sa can query alice (not 403)" "$code" "200"

  # decision consistency — search-sa and alice must get the same answer
  local search_dec alice_dec
  search_dec=$(get_decision "$(authzen_post "$SEARCH_SA_TOKEN" "/access/v1/evaluation" \
    "{\"subject\":{\"type\":\"user\",\"id\":\"alice\"},\"action\":{\"name\":\"get\"},\"resource\":{\"type\":\"pods\",\"properties\":{\"cluster\":\"dsf-mc\",\"namespace\":\"default\"}}}")")
  alice_dec=$(get_decision "$(authzen_post "$ALICE_TOKEN" "/access/v1/evaluation" \
    "{\"subject\":{\"type\":\"user\",\"id\":\"alice\"},\"action\":{\"name\":\"get\"},\"resource\":{\"type\":\"pods\",\"properties\":{\"cluster\":\"dsf-mc\",\"namespace\":\"default\"}}}")")
  [ "$search_dec" = "$alice_dec" ] \
    && pass "decision consistency: search-sa and alice agree (both=$alice_dec)" \
    || fail "decision mismatch: search-sa=$search_dec alice=$alice_dec"

  # spot-check decisions through impersonation
  assert_decision "search-sa querying alice: get pods dsf-mc → true (admin)" \
    "$SEARCH_SA_TOKEN" "alice" "user" "get" "pods" "dsf-mc" "default" "" "True"
  assert_decision "search-sa querying alice: create pods dsf-mc-02 → false (view only)" \
    "$SEARCH_SA_TOKEN" "alice" "user" "create" "pods" "dsf-mc-02" "default" "" "False"
  assert_decision "search-sa querying alice: get pods local-cluster → false (no access)" \
    "$SEARCH_SA_TOKEN" "alice" "user" "get" "pods" "local-cluster" "default" "" "False"

  # search/resource consistency — same scopes via impersonation as alice's own query
  local search_scopes alice_scopes
  search_scopes=$(authzen_post "$SEARCH_SA_TOKEN" "/access/v1/search/resource" \
    '{"subject":{"type":"user","id":"alice"},"action":{"name":"get"},"resource":{"type":"pods"}}' | get_result_clusters)
  alice_scopes=$(authzen_post "$ALICE_TOKEN" "/access/v1/search/resource" \
    '{"subject":{"type":"user","id":"alice"},"action":{"name":"get"},"resource":{"type":"pods"}}' | get_result_clusters)
  [ "$search_scopes" = "$alice_scopes" ] \
    && pass "search/resource consistency: same scopes via impersonation (clusters: $alice_scopes)" \
    || fail "search/resource mismatch" "search-sa=$search_scopes alice=$alice_scopes"

  bold ""
  bold "=== Suite: subject.properties.groups (cross-subject group resolution) ==="

  # search-sa queries alice passing her groups explicitly in subject.properties
  # alice has direct user bindings so this produces the same result either way —
  # what we're testing is that the groups field is accepted and parsed correctly.
  local with_groups_dec without_groups_dec
  with_groups_dec=$(get_decision "$(authzen_post "$SEARCH_SA_TOKEN" "/access/v1/evaluation" \
    "{\"subject\":{\"type\":\"user\",\"id\":\"alice\",\"properties\":{\"groups\":\"system:authenticated\"}},\
\"action\":{\"name\":\"get\"},\"resource\":{\"type\":\"pods\",\"properties\":{\"cluster\":\"dsf-mc\",\"namespace\":\"default\"}}}")")
  without_groups_dec=$(get_decision "$(authzen_post "$SEARCH_SA_TOKEN" "/access/v1/evaluation" \
    "{\"subject\":{\"type\":\"user\",\"id\":\"alice\"},\
\"action\":{\"name\":\"get\"},\"resource\":{\"type\":\"pods\",\"properties\":{\"cluster\":\"dsf-mc\",\"namespace\":\"default\"}}}")")
  [ "$with_groups_dec" = "$without_groups_dec" ] \
    && pass "subject.properties.groups accepted and parsed (decision=$with_groups_dec, consistent with/without groups)" \
    || fail "subject.properties.groups: inconsistent result" "with=$with_groups_dec without=$without_groups_dec"

  bold ""
  bold "=== Suite: Impersonation — authzen-unauth-sa is denied ==="

  code=$(authzen_post_code "$UNAUTH_SA_TOKEN" "/access/v1/evaluation" \
    "{\"subject\":{\"type\":\"user\",\"id\":\"alice\"},\"action\":{\"name\":\"get\"},\"resource\":{\"type\":\"pods\",\"properties\":{\"cluster\":\"dsf-mc\",\"namespace\":\"default\"}}}")
  assert_http "unauth-sa querying alice → 403 (no impersonate rights)" "$code" "403"

  code=$(authzen_post_code "$UNAUTH_SA_TOKEN" "/access/v1/search/resource" \
    '{"subject":{"type":"user","id":"alice"},"action":{"name":"get"},"resource":{"type":"pods"}}')
  assert_http "unauth-sa search for alice → 403 (no impersonate rights)" "$code" "403"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
bold "AuthZen endpoint smoke tests"
bold "=============================="
setup
preflight

suite_discovery
echo ""
suite_auth_enforcement
echo ""
suite_admin_user
echo ""
suite_alice
echo ""
suite_bob
echo ""
suite_carol
echo ""
suite_namespace_security
echo ""
suite_search_resources
echo ""
suite_search_action
echo ""
suite_batch_semantics
echo ""
suite_impersonation

echo ""
bold "=============================="
TOTAL=$((PASS+FAIL))
if [ "$FAIL" -eq 0 ]; then
  green "Result: $PASS/$TOTAL passed"
else
  red "Result: $PASS/$TOTAL passed, $FAIL FAILED"
  exit 1
fi
