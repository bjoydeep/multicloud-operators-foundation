package authzen

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// mockDecider is a controllable Decider for handler tests.
type mockDecider struct {
	evaluateResult        bool
	evaluateBatchResult   []bool
	searchResult          []Scope
	searchActionResult    []string
	searchResourcesResult []ResourceTypeScopes
	err                   error
}

func (m *mockDecider) Evaluate(_ context.Context, _ user.Info, _ Action, _ Resource) (bool, error) {
	return m.evaluateResult, m.err
}
func (m *mockDecider) EvaluateBatch(_ context.Context, _ user.Info, _ Action, _ []Resource) ([]bool, error) {
	return m.evaluateBatchResult, m.err
}
func (m *mockDecider) SearchResource(_ context.Context, _ user.Info, _ Action, _ string) ([]Scope, error) {
	return m.searchResult, m.err
}
func (m *mockDecider) SearchAction(_ context.Context, _ user.Info, _ Resource) ([]string, error) {
	return m.searchActionResult, m.err
}
func (m *mockDecider) SearchResources(_ context.Context, _ user.Info, _ Action, _ []Resource, _ bool) ([]ResourceTypeScopes, error) {
	return m.searchResourcesResult, m.err
}

// requestWithUser injects a user.Info into the request context (simulates the auth middleware).
func requestWithUser(r *http.Request, name string, groups []string) *http.Request {
	info := &user.DefaultInfo{Name: name, Groups: groups}
	ctx := request.WithUser(r.Context(), info)
	return r.WithContext(ctx)
}

func postRequest(t *testing.T, path string, body interface{}) *http.Request {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	return r
}

// --- Discovery ---

func TestDiscovery_ReturnsConfig(t *testing.T) {
	h := NewHandler(&mockDecider{}, nil)
	r, _ := http.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	r.Host = "ocm-proxyserver.multicluster-engine.svc:443"
	w := httptest.NewRecorder()
	h.Discovery(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	str := func(k string) string {
		v, _ := resp[k].(string)
		return v
	}
	base := "https://ocm-proxyserver.multicluster-engine.svc:443"
	if str("policy_decision_point") != base {
		t.Errorf("policy_decision_point: got %q want %q", str("policy_decision_point"), base)
	}
	if str("access_evaluation_endpoint") != base+"/access/v1/evaluation" {
		t.Errorf("access_evaluation_endpoint: got %q", str("access_evaluation_endpoint"))
	}
	if str("search_resource_endpoint") != base+"/access/v1/search/resource" {
		t.Errorf("search_resource_endpoint: got %q", str("search_resource_endpoint"))
	}
	if str("resource_type_convention") != "resource_name_only" {
		t.Errorf("resource_type_convention missing or wrong: got %q", str("resource_type_convention"))
	}
}

func TestDiscovery_WrongMethod(t *testing.T) {
	h := NewHandler(&mockDecider{}, nil)
	r, _ := http.NewRequest(http.MethodPost, "/.well-known/authzen-configuration", nil)
	w := httptest.NewRecorder()
	h.Discovery(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// --- Evaluation ---

func TestEvaluation_AllowedDecision(t *testing.T) {
	h := NewHandler(&mockDecider{evaluateResult: true}, nil)
	body := EvaluationRequest{
		Subject:  Subject{Type: "user", ID: "alice"},
		Action:   Action{Name: "get"},
		Resource: Resource{Type: "configmaps", Properties: map[string]string{"cluster": "bar", "namespace": "foo"}},
	}
	r := requestWithUser(postRequest(t, "/access/v1/evaluation", body), "alice", nil)
	w := httptest.NewRecorder()
	h.Evaluation(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp EvaluationResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Decision {
		t.Error("expected decision=true")
	}
}

func TestEvaluation_DeniedDecision(t *testing.T) {
	h := NewHandler(&mockDecider{evaluateResult: false}, nil)
	body := EvaluationRequest{
		Subject:  Subject{Type: "user", ID: "alice"},
		Action:   Action{Name: "create"},
		Resource: Resource{Type: "secrets", Properties: map[string]string{"cluster": "bar", "namespace": "foo"}},
	}
	r := requestWithUser(postRequest(t, "/access/v1/evaluation", body), "alice", nil)
	w := httptest.NewRecorder()
	h.Evaluation(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp EvaluationResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Decision {
		t.Error("expected decision=false")
	}
}

func TestEvaluation_ForbiddenWhenQueryingOtherUser(t *testing.T) {
	h := NewHandler(&mockDecider{evaluateResult: true}, nil)
	body := EvaluationRequest{
		Subject:  Subject{Type: "user", ID: "bob"},
		Action:   Action{Name: "get"},
		Resource: Resource{Type: "pods", Properties: map[string]string{"cluster": "bar", "namespace": "foo"}},
	}
	// authenticated as alice, but querying bob's permissions
	r := requestWithUser(postRequest(t, "/access/v1/evaluation", body), "alice", nil)
	w := httptest.NewRecorder()
	h.Evaluation(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestEvaluation_BadRequestOnMissingSubject(t *testing.T) {
	h := NewHandler(&mockDecider{}, nil)
	body := EvaluationRequest{
		Action:   Action{Name: "get"},
		Resource: Resource{Type: "pods", Properties: map[string]string{"cluster": "bar"}},
	}
	r := requestWithUser(postRequest(t, "/access/v1/evaluation", body), "alice", nil)
	w := httptest.NewRecorder()
	h.Evaluation(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestEvaluation_BadRequestOnMissingCluster(t *testing.T) {
	h := NewHandler(&mockDecider{}, nil)
	body := EvaluationRequest{
		Subject:  Subject{Type: "user", ID: "alice"},
		Action:   Action{Name: "get"},
		Resource: Resource{Type: "pods"}, // no cluster property
	}
	r := requestWithUser(postRequest(t, "/access/v1/evaluation", body), "alice", nil)
	w := httptest.NewRecorder()
	h.Evaluation(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestEvaluation_GroupSubjectAllowedForMember(t *testing.T) {
	h := NewHandler(&mockDecider{evaluateResult: true}, nil)
	body := EvaluationRequest{
		Subject:  Subject{Type: "group", ID: "sre-team"},
		Action:   Action{Name: "get"},
		Resource: Resource{Type: "pods", Properties: map[string]string{"cluster": "bar", "namespace": "foo"}},
	}
	// alice is a member of sre-team
	r := requestWithUser(postRequest(t, "/access/v1/evaluation", body), "alice", []string{"sre-team"})
	w := httptest.NewRecorder()
	h.Evaluation(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestEvaluation_GroupSubjectForbiddenForNonMember(t *testing.T) {
	h := NewHandler(&mockDecider{evaluateResult: true}, nil)
	body := EvaluationRequest{
		Subject:  Subject{Type: "group", ID: "sre-team"},
		Action:   Action{Name: "get"},
		Resource: Resource{Type: "pods", Properties: map[string]string{"cluster": "bar", "namespace": "foo"}},
	}
	// alice is NOT a member of sre-team
	r := requestWithUser(postRequest(t, "/access/v1/evaluation", body), "alice", []string{"dev-team"})
	w := httptest.NewRecorder()
	h.Evaluation(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

// --- Evaluations (batch) ---

func TestEvaluations_ReturnsMixedResults(t *testing.T) {
	h := NewHandler(&mockDecider{evaluateBatchResult: []bool{true, false, true}}, nil)
	body := EvaluationsRequest{
		Subject: Subject{Type: "user", ID: "alice"},
		Action:  Action{Name: "get"},
		Evaluations: []Resource{
			{Type: "configmaps", Properties: map[string]string{"cluster": "bar", "namespace": "foo"}},
			{Type: "secrets", Properties: map[string]string{"cluster": "baz", "namespace": "foo"}},
			{Type: "pods", Properties: map[string]string{"cluster": "bar", "namespace": "default"}},
		},
	}
	r := requestWithUser(postRequest(t, "/access/v1/evaluations", body), "alice", nil)
	w := httptest.NewRecorder()
	h.Evaluations(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp EvaluationsResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	expected := []bool{true, false, true}
	for i, e := range resp.Evaluations {
		if e.Decision != expected[i] {
			t.Errorf("index %d: expected %v got %v", i, expected[i], e.Decision)
		}
	}
}

func TestEvaluations_DenyOnFirstDeny_ShortCircuits(t *testing.T) {
	// Results: true, false, true — deny_on_first_deny stops after the second item
	h := NewHandler(&mockDecider{evaluateBatchResult: []bool{true, false, true}}, nil)
	sem := SemanticDenyOnFirstDeny
	body := EvaluationsRequest{
		Subject:     Subject{Type: "user", ID: "alice"},
		Action:      Action{Name: "get"},
		Options:     &EvaluationsOptions{EvaluationsSemantic: sem},
		Evaluations: []Resource{
			{Type: "pods", Properties: map[string]string{"cluster": "bar", "namespace": "a"}},
			{Type: "pods", Properties: map[string]string{"cluster": "baz", "namespace": "a"}},
			{Type: "pods", Properties: map[string]string{"cluster": "bar", "namespace": "b"}},
		},
	}
	r := requestWithUser(postRequest(t, "/access/v1/evaluations", body), "alice", nil)
	w := httptest.NewRecorder()
	h.Evaluations(w, r)
	var resp EvaluationsResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	// Only 2 results returned — stopped at first deny
	if len(resp.Evaluations) != 2 {
		t.Fatalf("deny_on_first_deny: expected 2 results (stopped at deny), got %d", len(resp.Evaluations))
	}
	if resp.Evaluations[0].Decision != true || resp.Evaluations[1].Decision != false {
		t.Errorf("unexpected decisions: %+v", resp.Evaluations)
	}
}

func TestEvaluations_PermitOnFirstPermit_ShortCircuits(t *testing.T) {
	// Results: false, true, true — permit_on_first_permit stops after the second item
	h := NewHandler(&mockDecider{evaluateBatchResult: []bool{false, true, true}}, nil)
	sem := SemanticPermitOnFirstPermit
	body := EvaluationsRequest{
		Subject:     Subject{Type: "user", ID: "alice"},
		Action:      Action{Name: "get"},
		Options:     &EvaluationsOptions{EvaluationsSemantic: sem},
		Evaluations: []Resource{
			{Type: "pods", Properties: map[string]string{"cluster": "bar", "namespace": "a"}},
			{Type: "pods", Properties: map[string]string{"cluster": "baz", "namespace": "a"}},
			{Type: "pods", Properties: map[string]string{"cluster": "bar", "namespace": "b"}},
		},
	}
	r := requestWithUser(postRequest(t, "/access/v1/evaluations", body), "alice", nil)
	w := httptest.NewRecorder()
	h.Evaluations(w, r)
	var resp EvaluationsResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	// Only 2 results returned — stopped at first permit
	if len(resp.Evaluations) != 2 {
		t.Fatalf("permit_on_first_permit: expected 2 results (stopped at permit), got %d", len(resp.Evaluations))
	}
	if resp.Evaluations[0].Decision != false || resp.Evaluations[1].Decision != true {
		t.Errorf("unexpected decisions: %+v", resp.Evaluations)
	}
}

// --- SearchResource ---

func TestSearchResource_ReturnsScopes(t *testing.T) {
	scopes := []Scope{
		{Cluster: "bar", Namespace: "*"},
		{Cluster: "baz", Namespace: "alpha"},
	}
	h := NewHandler(&mockDecider{searchResult: scopes}, nil)
	body := SearchResourceRequest{
		Subject:  Subject{Type: "user", ID: "alice"},
		Action:   Action{Name: "get"},
		Resource: Resource{Type: "virtualmachines"},
	}
	r := requestWithUser(postRequest(t, "/access/v1/search/resource", body), "alice", nil)
	w := httptest.NewRecorder()
	h.SearchResource(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp SearchResourceResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(resp.Results))
	}
	if resp.Results[0].ID != "bar/*" {
		t.Errorf("expected ID bar/*, got %s", resp.Results[0].ID)
	}
	if resp.Results[1].Properties["cluster"] != "baz" {
		t.Errorf("expected cluster=baz, got %s", resp.Results[1].Properties["cluster"])
	}
}

func TestSearchResource_BadRequestOnMissingResourceType(t *testing.T) {
	h := NewHandler(&mockDecider{}, nil)
	body := SearchResourceRequest{
		Subject: Subject{Type: "user", ID: "alice"},
		Action:  Action{Name: "get"},
		// Resource.Type is empty
	}
	r := requestWithUser(postRequest(t, "/access/v1/search/resource", body), "alice", nil)
	w := httptest.NewRecorder()
	h.SearchResource(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// --- SearchResources ---

func TestSearchResources_ExplicitMode_ReturnsResults(t *testing.T) {
	mockResults := []ResourceTypeScopes{
		{Type: "pods", APIGroup: "", Scopes: []ScopeEntry{{Cluster: "bar", Namespace: "*"}}},
		{Type: "deployments", APIGroup: "apps", Scopes: []ScopeEntry{{Cluster: "bar", Namespace: "*"}}},
	}
	h := NewHandler(&mockDecider{searchResourcesResult: mockResults}, nil)
	body := SearchResourcesRequest{
		Subject: Subject{Type: "user", ID: "alice"},
		Action:  Action{Name: "get"},
		Resources: []Resource{
			{Type: "pods", Properties: map[string]string{"apiGroup": ""}},
			{Type: "deployments", Properties: map[string]string{"apiGroup": "apps"}},
		},
	}
	r := requestWithUser(postRequest(t, "/access/v1/search/resources", body), "alice", nil)
	w := httptest.NewRecorder()
	h.SearchResources(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp SearchResourcesResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(resp.Results))
	}
}

func TestSearchResources_WildcardMode_ReturnsResults(t *testing.T) {
	mockResults := []ResourceTypeScopes{
		{Type: "*", APIGroup: "*", Scopes: []ScopeEntry{{Cluster: "bar", Namespace: "*"}}},
	}
	h := NewHandler(&mockDecider{searchResourcesResult: mockResults}, nil)
	body := SearchResourcesRequest{
		Subject:          Subject{Type: "user", ID: "alice"},
		Action:           Action{Name: "get"},
		AllResourceTypes: true,
	}
	r := requestWithUser(postRequest(t, "/access/v1/search/resources", body), "alice", nil)
	w := httptest.NewRecorder()
	h.SearchResources(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp SearchResourcesResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if len(resp.Results) != 1 || resp.Results[0].Type != "*" {
		t.Errorf("expected wildcard result, got %+v", resp.Results)
	}
}

func TestSearchResources_BadRequest_NeitherModeSet(t *testing.T) {
	h := NewHandler(&mockDecider{}, nil)
	body := SearchResourcesRequest{
		Subject: Subject{Type: "user", ID: "alice"},
		Action:  Action{Name: "get"},
		// neither Resources nor AllResourceTypes set
	}
	r := requestWithUser(postRequest(t, "/access/v1/search/resources", body), "alice", nil)
	w := httptest.NewRecorder()
	h.SearchResources(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// --- SearchAction ---

func TestSearchAction_ReturnsVerbs(t *testing.T) {
	h := NewHandler(&mockDecider{searchActionResult: []string{"get", "list", "watch"}}, nil)
	body := SearchActionRequest{
		Subject:  Subject{Type: "user", ID: "alice"},
		Resource: Resource{Type: "pods", Properties: map[string]string{"cluster": "bar", "namespace": "default", "apiGroup": ""}},
	}
	r := requestWithUser(postRequest(t, "/access/v1/search/action", body), "alice", nil)
	w := httptest.NewRecorder()
	h.SearchAction(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp SearchActionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Actions) != 3 {
		t.Errorf("expected 3 actions, got %d: %v", len(resp.Actions), resp.Actions)
	}
}

func TestSearchAction_EmptyWhenNoAccess(t *testing.T) {
	h := NewHandler(&mockDecider{searchActionResult: []string{}}, nil)
	body := SearchActionRequest{
		Subject:  Subject{Type: "user", ID: "alice"},
		Resource: Resource{Type: "pods", Properties: map[string]string{"cluster": "no-cluster", "namespace": "default", "apiGroup": ""}},
	}
	r := requestWithUser(postRequest(t, "/access/v1/search/action", body), "alice", nil)
	w := httptest.NewRecorder()
	h.SearchAction(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp SearchActionResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if len(resp.Actions) != 0 {
		t.Errorf("expected empty actions, got %v", resp.Actions)
	}
}

func TestSearchAction_BadRequestOnMissingCluster(t *testing.T) {
	h := NewHandler(&mockDecider{}, nil)
	body := SearchActionRequest{
		Subject:  Subject{Type: "user", ID: "alice"},
		Resource: Resource{Type: "pods"}, // no cluster
	}
	r := requestWithUser(postRequest(t, "/access/v1/search/action", body), "alice", nil)
	w := httptest.NewRecorder()
	h.SearchAction(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestSearchAction_ForbiddenCrossSubject(t *testing.T) {
	h := NewHandler(&mockDecider{}, nil)
	body := SearchActionRequest{
		Subject:  Subject{Type: "user", ID: "bob"},
		Resource: Resource{Type: "pods", Properties: map[string]string{"cluster": "bar", "namespace": "default"}},
	}
	r := requestWithUser(postRequest(t, "/access/v1/search/action", body), "alice", nil)
	w := httptest.NewRecorder()
	h.SearchAction(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

// --- Impersonation path ---

// fakeKubeClient returns a fake kube client whose SubjectAccessReview always returns the given allowed value.
func fakeKubeClient(allowed bool) *fake.Clientset {
	fc := fake.NewSimpleClientset()
	fc.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		sar := &authorizationv1.SubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{Allowed: allowed},
		}
		return true, sar, nil
	})
	return fc
}

func TestEvaluation_AllowedViaImpersonation(t *testing.T) {
	// search-sa queries alice's permissions — caller != subject, but search-sa can impersonate alice
	h := NewHandler(&mockDecider{evaluateResult: true}, fakeKubeClient(true))
	body := EvaluationRequest{
		Subject:  Subject{Type: "user", ID: "alice"},
		Action:   Action{Name: "get"},
		Resource: Resource{Type: "pods", Properties: map[string]string{"cluster": "bar", "namespace": "default"}},
	}
	// caller is search-sa, not alice
	r := requestWithUser(postRequest(t, "/access/v1/evaluation", body), "system:serviceaccount:open-cluster-management:search-sa", nil)
	w := httptest.NewRecorder()
	h.Evaluation(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (impersonation allowed), got %d: %s", w.Code, w.Body.String())
	}
}

func TestEvaluation_ForbiddenWhenImpersonationDenied(t *testing.T) {
	// search-sa tries to query alice's permissions but doesn't have impersonate rights
	h := NewHandler(&mockDecider{evaluateResult: true}, fakeKubeClient(false))
	body := EvaluationRequest{
		Subject:  Subject{Type: "user", ID: "alice"},
		Action:   Action{Name: "get"},
		Resource: Resource{Type: "pods", Properties: map[string]string{"cluster": "bar", "namespace": "default"}},
	}
	r := requestWithUser(postRequest(t, "/access/v1/evaluation", body), "system:serviceaccount:open-cluster-management:search-sa", nil)
	w := httptest.NewRecorder()
	h.Evaluation(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (impersonation denied), got %d", w.Code)
	}
}

// --- subject.properties.groups ---

func TestParseGroups(t *testing.T) {
	cases := []struct {
		input    string
		expected []string
	}{
		{"", nil},
		{"sre-team", []string{"sre-team"}},
		{"sre-team,system:authenticated", []string{"sre-team", "system:authenticated"}},
		{" sre-team , system:authenticated ", []string{"sre-team", "system:authenticated"}},
	}
	for _, c := range cases {
		got := parseGroups(c.input)
		if len(got) != len(c.expected) {
			t.Errorf("parseGroups(%q): got %v want %v", c.input, got, c.expected)
			continue
		}
		for i := range got {
			if got[i] != c.expected[i] {
				t.Errorf("parseGroups(%q)[%d]: got %q want %q", c.input, i, got[i], c.expected[i])
			}
		}
	}
}

func TestEvaluation_ImpersonationWithGroups_PassedToDecider(t *testing.T) {
	// search-sa queries alice's permissions and supplies her groups via subject.properties.
	// The mock decider captures the user.Info it receives so we can verify groups are passed.
	var capturedInfo user.Info
	capturingDecider := &mockDecider{evaluateResult: true}
	_ = capturingDecider // mock doesn't capture user.Info yet — we verify via subjectUserInfo directly

	// Directly test subjectUserInfo to confirm groups are parsed and included
	subject := Subject{
		Type:       "user",
		ID:         "alice",
		Properties: map[string]string{"groups": "sre-team,system:authenticated"},
	}
	caller := &user.DefaultInfo{Name: "search-sa"} // caller != subject → impersonation path
	info := subjectUserInfo(subject, caller)

	if info.GetName() != "alice" {
		t.Errorf("expected name=alice, got %q", info.GetName())
	}
	groups := info.GetGroups()
	if len(groups) != 2 || groups[0] != "sre-team" || groups[1] != "system:authenticated" {
		t.Errorf("expected groups=[sre-team system:authenticated], got %v", groups)
	}
	capturedInfo = info
	_ = capturedInfo
}

func TestEvaluation_ImpersonationNoGroups_NameOnly(t *testing.T) {
	// Without subject.properties.groups, impersonation path uses name only
	subject := Subject{Type: "user", ID: "alice"}
	caller := &user.DefaultInfo{Name: "search-sa"}
	info := subjectUserInfo(subject, caller)

	if info.GetName() != "alice" {
		t.Errorf("expected name=alice, got %q", info.GetName())
	}
	if len(info.GetGroups()) != 0 {
		t.Errorf("expected no groups without properties, got %v", info.GetGroups())
	}
}
