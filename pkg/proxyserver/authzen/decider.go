package authzen

import (
	"context"
	"fmt"

	clusterviewv1alpha1 "github.com/stolostron/cluster-lifecycle-api/clusterview/v1alpha1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/stolostron/multicloud-operators-foundation/pkg/cache/userpermission"
)

// Decider evaluates authorization questions against the unified UserPermission cache.
// Methods accept user.Info rather than Subject so the cache lookup always uses the
// full identity (name + groups) — not a reconstructed Subject that may lack groups.
type Decider interface {
	// Evaluate answers: can userInfo perform action on resource?
	Evaluate(ctx context.Context, userInfo user.Info, action Action, resource Resource) (bool, error)
	// EvaluateBatch answers the same for multiple resources in one call.
	// Results are in the same order as the input slice.
	EvaluateBatch(ctx context.Context, userInfo user.Info, action Action, resources []Resource) ([]bool, error)
	// SearchResource answers: in which (cluster, namespace) scopes can userInfo perform action on resourceType?
	SearchResource(ctx context.Context, userInfo user.Info, action Action, resourceType string) ([]Scope, error)
}

// UserPermissionDecider implements Decider by reading from the UserPermission cache via Lister.
type UserPermissionDecider struct {
	lister userpermission.Lister
}

// NewUserPermissionDecider creates a Decider backed by the given Lister.
func NewUserPermissionDecider(lister userpermission.Lister) *UserPermissionDecider {
	return &UserPermissionDecider{lister: lister}
}

func (d *UserPermissionDecider) Evaluate(_ context.Context, userInfo user.Info, action Action, resource Resource) (bool, error) {
	perms, err := d.lister.List(userInfo, labels.Everything())
	if err != nil {
		return false, err
	}
	cluster := resource.Properties["cluster"]
	namespace := resource.Properties["namespace"]
	apiGroup := resource.Properties["apiGroup"]
	for i := range perms.Items {
		if permAllows(&perms.Items[i], cluster, namespace, resource.Type, apiGroup, action.Name) {
			return true, nil
		}
	}
	return false, nil
}

func (d *UserPermissionDecider) EvaluateBatch(_ context.Context, userInfo user.Info, action Action, resources []Resource) ([]bool, error) {
	perms, err := d.lister.List(userInfo, labels.Everything())
	if err != nil {
		return nil, err
	}
	results := make([]bool, len(resources))
	for i, res := range resources {
		cluster := res.Properties["cluster"]
		namespace := res.Properties["namespace"]
		apiGroup := res.Properties["apiGroup"]
		for j := range perms.Items {
			if permAllows(&perms.Items[j], cluster, namespace, res.Type, apiGroup, action.Name) {
				results[i] = true
				break
			}
		}
	}
	return results, nil
}

func (d *UserPermissionDecider) SearchResource(_ context.Context, userInfo user.Info, action Action, resourceType string) ([]Scope, error) {
	perms, err := d.lister.List(userInfo, labels.Everything())
	if err != nil {
		return nil, err
	}
	var scopes []Scope
	for i := range perms.Items {
		perm := &perms.Items[i]
		// apiGroup is intentionally not filtered here: search asks "where can I access
		// this resource type?" across all apiGroups that grant it.
		if !rulesAllowResourceVerb(perm.Status.ClusterRoleDefinition.Rules, resourceType, action.Name) {
			continue
		}
		for _, binding := range perm.Status.Bindings {
			for _, ns := range binding.Namespaces {
				scopes = append(scopes, Scope{Cluster: binding.Cluster, Namespace: ns})
			}
		}
	}
	return deduplicateScopes(scopes), nil
}

// permAllows returns true if perm grants verb on (resourceType, apiGroup) within (cluster, namespace).
func permAllows(perm *clusterviewv1alpha1.UserPermission, cluster, namespace, resourceType, apiGroup, verb string) bool {
	if !bindingCovers(perm.Status.Bindings, cluster, namespace) {
		return false
	}
	return rulesAllowResourceAction(perm.Status.ClusterRoleDefinition.Rules, resourceType, apiGroup, verb)
}

// bindingCovers returns true if any binding matches the cluster and namespace.
// namespace="" is treated as matching any namespace (useful for cluster-scoped resources).
func bindingCovers(bindings []clusterviewv1alpha1.ClusterBinding, cluster, namespace string) bool {
	for _, b := range bindings {
		if b.Cluster != cluster {
			continue
		}
		for _, ns := range b.Namespaces {
			if ns == "*" || ns == namespace || namespace == "" {
				return true
			}
		}
	}
	return false
}

// rulesAllowResourceAction returns true if any rule grants verb on resourceType/apiGroup.
// Used by Evaluate where apiGroup precision matters.
func rulesAllowResourceAction(rules []rbacv1.PolicyRule, resourceType, apiGroup, verb string) bool {
	for _, rule := range rules {
		if coversVerb(rule.Verbs, verb) &&
			coversResource(rule.Resources, resourceType) &&
			coversAPIGroup(rule.APIGroups, apiGroup) {
			return true
		}
	}
	return false
}

// rulesAllowResourceVerb returns true if any rule grants verb on resourceType across any apiGroup.
// Used by SearchResource where the caller specifies a resource type but not an apiGroup.
func rulesAllowResourceVerb(rules []rbacv1.PolicyRule, resourceType, verb string) bool {
	for _, rule := range rules {
		if coversVerb(rule.Verbs, verb) && coversResource(rule.Resources, resourceType) {
			return true
		}
	}
	return false
}

func coversVerb(verbs []string, verb string) bool {
	for _, v := range verbs {
		if v == "*" || v == verb {
			return true
		}
	}
	return false
}

func coversResource(resources []string, resource string) bool {
	for _, r := range resources {
		if r == "*" || r == resource {
			return true
		}
	}
	return false
}

func coversAPIGroup(apiGroups []string, apiGroup string) bool {
	for _, g := range apiGroups {
		if g == "*" || g == apiGroup {
			return true
		}
	}
	return false
}

func deduplicateScopes(scopes []Scope) []Scope {
	seen := make(map[string]struct{}, len(scopes))
	out := make([]Scope, 0, len(scopes))
	for _, s := range scopes {
		key := fmt.Sprintf("%s/%s", s.Cluster, s.Namespace)
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
