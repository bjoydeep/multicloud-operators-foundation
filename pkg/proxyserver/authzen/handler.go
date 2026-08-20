package authzen

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// Handler serves the AuthZen Authorization API 1.0 endpoints on the ocm-proxyserver.
type Handler struct {
	decider    Decider
	kubeClient kubernetes.Interface
}

// NewHandler creates a Handler backed by the given Decider and kube client.
// The kube client is used to check impersonation rights for cross-subject queries.
func NewHandler(decider Decider, kubeClient kubernetes.Interface) *Handler {
	return &Handler{decider: decider, kubeClient: kubeClient}
}

// Discovery serves GET /.well-known/authzen-configuration.
// Returns absolute HTTPS URLs per the AuthZen Authorization API 1.0 spec.
func (h *Handler) Discovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	base := "https://" + r.Host
	writeJSON(w, map[string]interface{}{
		"policy_decision_point":       base,
		"access_evaluation_endpoint":  base + "/access/v1/evaluation",
		"access_evaluations_endpoint": base + "/access/v1/evaluations",
		"search_resource_endpoint":    base + "/access/v1/search/resource",
		"search_action_endpoint":      base + "/access/v1/search/action",
		"resource_type_convention":    "resource_name_only",
		"resource_type_description":   "resource.type is the plural resource name (e.g. pods, deployments, virtualmachines). API group is carried in resource.properties.apiGroup.",
	})
}

// Evaluation serves POST /access/v1/evaluation.
func (h *Handler) Evaluation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req EvaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Subject.ID == "" {
		http.Error(w, "subject.id is required", http.StatusBadRequest)
		return
	}
	if req.Resource.Properties["cluster"] == "" {
		http.Error(w, "resource.properties.cluster is required", http.StatusBadRequest)
		return
	}
	callerInfo, ok := request.UserFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !h.callerCanQuerySubject(r.Context(), callerInfo, req.Subject) {
		http.Error(w, "forbidden: caller may only query their own permissions", http.StatusForbidden)
		return
	}
	decision, err := h.decider.Evaluate(r.Context(), subjectUserInfo(req.Subject, callerInfo), req.Action, req.Resource)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, EvaluationResponse{Decision: decision})
}

// Evaluations serves POST /access/v1/evaluations (batch).
func (h *Handler) Evaluations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req EvaluationsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Subject.ID == "" {
		http.Error(w, "subject.id is required", http.StatusBadRequest)
		return
	}
	callerInfo, ok := request.UserFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !h.callerCanQuerySubject(r.Context(), callerInfo, req.Subject) {
		http.Error(w, "forbidden: caller may only query their own permissions", http.StatusForbidden)
		return
	}
	semantic := SemanticExecuteAll
	if req.Options != nil && req.Options.EvaluationsSemantic != "" {
		semantic = req.Options.EvaluationsSemantic
	}

	decisions, err := h.decider.EvaluateBatch(r.Context(), subjectUserInfo(req.Subject, callerInfo), req.Action, req.Evaluations)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	resp := EvaluationsResponse{Evaluations: make([]EvaluationResponse, 0, len(decisions))}
	for _, d := range decisions {
		resp.Evaluations = append(resp.Evaluations, EvaluationResponse{Decision: d})
		if semantic == SemanticDenyOnFirstDeny && !d {
			break // logical AND: stop on first false
		}
		if semantic == SemanticPermitOnFirstPermit && d {
			break // logical OR: stop on first true
		}
	}
	writeJSON(w, resp)
}

// SearchResource serves POST /access/v1/search/resource.
func (h *Handler) SearchResource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req SearchResourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Subject.ID == "" {
		http.Error(w, "subject.id is required", http.StatusBadRequest)
		return
	}
	if req.Resource.Type == "" {
		http.Error(w, "resource.type is required", http.StatusBadRequest)
		return
	}
	callerInfo, ok := request.UserFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !h.callerCanQuerySubject(r.Context(), callerInfo, req.Subject) {
		http.Error(w, "forbidden: caller may only query their own permissions", http.StatusForbidden)
		return
	}
	scopes, err := h.decider.SearchResource(r.Context(), subjectUserInfo(req.Subject, callerInfo), req.Action, req.Resource.Type)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	resp := SearchResourceResponse{Results: make([]SearchResult, 0, len(scopes))}
	for _, s := range scopes {
		resp.Results = append(resp.Results, SearchResult{
			Type:       req.Resource.Type,
			ID:         fmt.Sprintf("%s/%s", s.Cluster, s.Namespace),
			Properties: map[string]string{"cluster": s.Cluster, "namespace": s.Namespace},
		})
	}
	writeJSON(w, resp)
}

// SearchAction serves POST /access/v1/search/action.
func (h *Handler) SearchAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req SearchActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Subject.ID == "" {
		http.Error(w, "subject.id is required", http.StatusBadRequest)
		return
	}
	if req.Resource.Properties["cluster"] == "" {
		http.Error(w, "resource.properties.cluster is required", http.StatusBadRequest)
		return
	}
	callerInfo, ok := request.UserFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !h.callerCanQuerySubject(r.Context(), callerInfo, req.Subject) {
		http.Error(w, "forbidden: caller may only query their own permissions", http.StatusForbidden)
		return
	}
	verbs, err := h.decider.SearchAction(r.Context(), subjectUserInfo(req.Subject, callerInfo), req.Resource)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	actions := make([]Action, 0, len(verbs))
	for _, v := range verbs {
		actions = append(actions, Action{Name: v})
	}
	writeJSON(w, SearchActionResponse{Actions: actions})
}

// callerCanQuerySubject enforces authorization for cross-subject queries.
//
// Two-path check:
//  1. Self-query: caller IS the subject → always allowed, no RBAC required
//     - user subject: caller name matches subject.id
//     - group subject: caller is a member of subject.id
//  2. Impersonation: caller has Kubernetes impersonate rights on the subject → allowed
//     This enables elevated service accounts (Search, MCP server, console) to query
//     permissions on behalf of a logged-in user.
func (h *Handler) callerCanQuerySubject(ctx context.Context, caller user.Info, subject Subject) bool {
	// Path 1: self-query — no RBAC check needed
	if subject.Type == "group" {
		for _, g := range caller.GetGroups() {
			if g == subject.ID {
				return true
			}
		}
	} else if caller.GetName() == subject.ID {
		return true
	}

	// Path 2: impersonation check via SubjectAccessReview
	// "Can this caller impersonate the subject?" uses standard Kubernetes RBAC
	// as the authorization gate for cross-subject queries.
	if h.kubeClient == nil {
		klog.Errorf("[authzen] kubeClient is nil — impersonation check skipped, returning false")
		return false
	}
	resource := "users"
	if subject.Type == "group" {
		resource = "groups"
	}
	klog.V(4).Infof("[authzen] impersonation SAR: caller=%q checking impersonate %s/%s", caller.GetName(), resource, subject.ID)
	sar, err := h.kubeClient.AuthorizationV1().SubjectAccessReviews().Create(
		ctx,
		&authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   caller.GetName(),
				Groups: caller.GetGroups(),
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Verb:     "impersonate",
					Resource: resource,
					Name:     subject.ID,
				},
			},
		},
		metav1.CreateOptions{},
	)
	if err != nil {
		klog.Errorf("[authzen] impersonation SAR error: %v", err)
		return false
	}
	klog.V(4).Infof("[authzen] impersonation SAR result: allowed=%v reason=%q", sar.Status.Allowed, sar.Status.Reason)
	return sar.Status.Allowed
}

// subjectUserInfo returns the user.Info to use for cache lookups.
//
// Three cases:
//   - group subject: scoped user.Info with only that group.
//   - user subject, self-query (caller IS the subject): use the caller's full user.Info
//     (name + groups) so group-based permissions are correctly resolved.
//   - user subject, impersonation (caller != subject): use the subject's name plus any
//     groups supplied in subject.Properties["groups"] (comma-separated). Elevated callers
//     (Search, MCP server) obtain group membership via a single TokenReview and pass it
//     here so the PDP resolves group-inherited permissions correctly. Without groups, only
//     direct user-level bindings are resolved.
func subjectUserInfo(subject Subject, caller user.Info) user.Info {
	if subject.Type == "group" {
		return &user.DefaultInfo{Groups: []string{subject.ID}}
	}
	if caller.GetName() == subject.ID {
		return caller // self-query: full user.Info including groups
	}
	// impersonation path: build user.Info from subject.id + optional groups
	groups := parseGroups(subject.Properties["groups"])
	return &user.DefaultInfo{Name: subject.ID, Groups: groups}
}

// parseGroups splits a comma-separated group string into a slice.
// Returns nil (not an empty slice) when the input is empty so callers can
// distinguish "no groups provided" from "empty groups list".
func parseGroups(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	groups := make([]string, 0, len(parts))
	for _, g := range parts {
		if g = strings.TrimSpace(g); g != "" {
			groups = append(groups, g)
		}
	}
	return groups
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
