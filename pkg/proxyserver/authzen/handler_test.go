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
	evaluateResult      bool
	evaluateBatchResult []bool
	searchResult        []Scope
	err                 error
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
	w := httptest.NewRecorder()
	h.Discovery(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["access_evaluation_v1_endpoint"] != "/access/v1/evaluation" {
		t.Errorf("unexpected discovery body: %v", resp)
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
