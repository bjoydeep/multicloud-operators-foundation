package authzen

// Subject identifies who is making the access request.
type Subject struct {
	Type string `json:"type"` // "user" or "group"
	ID   string `json:"id"`

	// Properties carries optional subject attributes.
	// ACM extension: elevated callers (Search, MCP server) may pass the target user's
	// group memberships under the key "groups" (comma-separated) so the PDP can resolve
	// group-inherited permissions when evaluating on behalf of another user:
	//   "properties": { "groups": "sre-team,system:authenticated" }
	// Callers obtain group membership via a single TokenReview against the hub kube-apiserver.
	// This is a spec-compliant use of AuthZen's subject.properties extensibility mechanism.
	Properties map[string]string `json:"properties,omitempty"`
}

// Action is the operation being requested — a Kubernetes verb.
type Action struct {
	Name string `json:"name"` // e.g. "get", "list", "create", "delete", "update", "patch", "watch"
}

// Resource describes what is being accessed.
//
// Convention (Option A — resource type taxonomy):
//   - Type is the plural resource name ONLY: "pods", "deployments", "virtualmachines".
//     It never includes the API group.
//   - Properties["apiGroup"] carries the API group: "" for core, "apps", "kubevirt.io".
//   - Together, Type + Properties["apiGroup"] uniquely identify the Kubernetes resource.
//
// Examples:
//   pods (core)           → Type: "pods",            apiGroup: ""
//   deployments (apps)    → Type: "deployments",     apiGroup: "apps"
//   VMs (kubevirt)        → Type: "virtualmachines", apiGroup: "kubevirt.io"
type Resource struct {
	Type       string            `json:"type"`
	ID         string            `json:"id,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

// Scope is a (cluster, namespace) pair used internally by the Decider.
// Namespace "*" means cluster-wide access.
type Scope struct {
	Cluster   string
	Namespace string
}

// EvaluationRequest is the body of POST /access/v1/evaluation.
type EvaluationRequest struct {
	Subject  Subject  `json:"subject"`
	Action   Action   `json:"action"`
	Resource Resource `json:"resource"`
}

// EvaluationResponse is returned by the evaluation endpoint.
type EvaluationResponse struct {
	Decision bool `json:"decision"`
}

// EvaluationsRequest is the body of POST /access/v1/evaluations (batch).
// Each element of Evaluations is a Resource to check; Subject and Action apply to all.
//
// ACM deviation from AuthZen spec: a single Action applies to all Evaluations items.
// The spec allows per-item actions; ACM's batch use case is always homogeneous.
type EvaluationsRequest struct {
	Subject     Subject             `json:"subject"`
	Action      Action              `json:"action"`
	Evaluations []Resource          `json:"evaluations"`
	Options     *EvaluationsOptions `json:"options,omitempty"`
}

// EvaluationsResponse is returned by the batch evaluation endpoint.
// Results are in the same order as the request Evaluations slice.
type EvaluationsResponse struct {
	Evaluations []EvaluationResponse `json:"evaluations"`
}

// SearchResourceRequest is the body of POST /access/v1/search/resource.
// Resource.ID is omitted; Resource.Type narrows which resource kind to search.
type SearchResourceRequest struct {
	Subject  Subject  `json:"subject"`
	Action   Action   `json:"action"`
	Resource Resource `json:"resource"`
}

// SearchResourceResponse is returned by the search/resource endpoint.
type SearchResourceResponse struct {
	Results []SearchResult `json:"results"`
}

// SearchResult is a single (cluster, namespace) scope the subject can access.
// ID is the synthetic scope identifier "cluster/namespace".
// Properties carries "cluster" and "namespace" for structured access.
type SearchResult struct {
	Type       string            `json:"type"`
	ID         string            `json:"id"`
	Properties map[string]string `json:"properties"`
}

// ScopeEntry is a (cluster, namespace) pair used in bulk resource responses.
// Namespace "*" means cluster-wide access.
type ScopeEntry struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
}

// ResourceTypeScopes is a single resource type's permission scopes in a bulk response.
type ResourceTypeScopes struct {
	Type     string       `json:"type"`     // plural resource name, or "*" for wildcard
	APIGroup string       `json:"api_group"` // "" = core, "*" = wildcard
	Scopes   []ScopeEntry `json:"scopes"`
}

// SearchResourcesRequest is the body of POST /access/v1/search/resources (bulk).
// Two modes — set exactly one:
//   - Resources: explicit list of (type, apiGroup) pairs to check
//   - AllResourceTypes: wildcard — return scopes for everything the subject can access
type SearchResourcesRequest struct {
	Subject          Subject    `json:"subject"`
	Action           Action     `json:"action"`
	Resources        []Resource `json:"resources,omitempty"`
	AllResourceTypes bool       `json:"all_resource_types,omitempty"`
}

// SearchResourcesResponse is returned by the search/resources endpoint.
type SearchResourcesResponse struct {
	Results []ResourceTypeScopes `json:"results"`
}

// SearchActionRequest is the body of POST /access/v1/search/action.
// Answers: what actions can subject perform on this specific resource?
// resource.properties.cluster, namespace, and apiGroup are all required.
type SearchActionRequest struct {
	Subject  Subject  `json:"subject"`
	Resource Resource `json:"resource"`
}

// SearchActionResponse is returned by the search/action endpoint.
type SearchActionResponse struct {
	Actions []Action `json:"actions"`
}

// EvaluationsSemantic controls short-circuit behaviour in batch evaluation.
type EvaluationsSemantic string

const (
	// SemanticExecuteAll runs all evaluations and returns all results (default).
	SemanticExecuteAll EvaluationsSemantic = "execute_all"
	// SemanticDenyOnFirstDeny stops at the first false decision (logical AND).
	SemanticDenyOnFirstDeny EvaluationsSemantic = "deny_on_first_deny"
	// SemanticPermitOnFirstPermit stops at the first true decision (logical OR).
	SemanticPermitOnFirstPermit EvaluationsSemantic = "permit_on_first_permit"
)

// EvaluationsOptions carries evaluation execution options.
type EvaluationsOptions struct {
	// EvaluationsSemantic controls short-circuit behaviour.
	// Defaults to execute_all if omitted.
	EvaluationsSemantic EvaluationsSemantic `json:"evaluations_semantic,omitempty"`
}
