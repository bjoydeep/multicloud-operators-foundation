package authzen

// Subject identifies who is making the access request.
type Subject struct {
	Type string `json:"type"` // "user" or "group"
	ID   string `json:"id"`
}

// Action is the operation being requested — a Kubernetes verb.
type Action struct {
	Name string `json:"name"` // e.g. "get", "list", "create", "delete", "update", "patch", "watch"
}

// Resource describes what is being accessed.
// Type is the plural resource name (e.g. "configmaps", "virtualmachines.kubevirt.io").
// ID is the specific resource name; omit for search queries.
// Properties carries "cluster", "namespace", and "apiGroup".
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
type EvaluationsRequest struct {
	Subject     Subject    `json:"subject"`
	Action      Action     `json:"action"`
	Evaluations []Resource `json:"evaluations"`
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
