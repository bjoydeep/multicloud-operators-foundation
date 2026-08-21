package authzen

import (
	"context"
	"fmt"
	"sort"

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
	// SearchAction answers: what actions can userInfo perform on this specific resource?
	// resource.Properties must include cluster, namespace, and apiGroup.
	SearchAction(ctx context.Context, userInfo user.Info, resource Resource) ([]string, error)
	// SearchResources is a bulk version of SearchResource supporting two modes:
	//   - Explicit list: resources contains specific (type, apiGroup) pairs to check.
	//   - Wildcard (allTypes=true): returns all (type, apiGroup) → scopes the user has,
	//     emitting type="*" / apiGroup="*" entries for wildcard rule grants.
	// includeBindingNamespaceScopes adds Namespace entries for every bound (cluster, namespace)
	// regardless of rules — implements the OCP namespace visibility workaround.
	SearchResources(ctx context.Context, userInfo user.Info, action Action, resources []Resource, allTypes bool, includeBindingNamespaceScopes bool) ([]ResourceTypeScopes, error)
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

func (d *UserPermissionDecider) SearchResources(_ context.Context, userInfo user.Info, action Action, resources []Resource, allTypes bool, includeBindingNamespaceScopes bool) ([]ResourceTypeScopes, error) {
	perms, err := d.lister.List(userInfo, labels.Everything())
	if err != nil {
		return nil, err
	}

	// resKey → scopeKey → ScopeEntry (deduplicated)
	type resKey struct{ typ, apiGroup string }
	scopeMap := map[resKey]map[string]ScopeEntry{}

	addScope := func(k resKey, cluster, namespace string) {
		if scopeMap[k] == nil {
			scopeMap[k] = map[string]ScopeEntry{}
		}
		id := cluster + "/" + namespace
		scopeMap[k][id] = ScopeEntry{Cluster: cluster, Namespace: namespace}
	}

	for i := range perms.Items {
		perm := &perms.Items[i]
		for _, binding := range perm.Status.Bindings {
			for _, ns := range binding.Namespaces {
				for _, rule := range perm.Status.ClusterRoleDefinition.Rules {
					if !coversVerb(rule.Verbs, action.Name) {
						continue
					}
					if allTypes {
						// Wildcard mode: emit rules as-is — "*" stays as "*"
						for _, res := range rule.Resources {
							for _, ag := range rule.APIGroups {
								addScope(resKey{res, ag}, binding.Cluster, ns)
							}
						}
					} else {
						// Explicit list mode: match only caller-requested types
						for _, req := range resources {
							reqAPIGroup := req.Properties["apiGroup"]
							if coversResource(rule.Resources, req.Type) &&
								coversAPIGroup(rule.APIGroups, reqAPIGroup) {
								addScope(resKey{req.Type, reqAPIGroup}, binding.Cluster, ns)
							}
						}
					}
				}
			}
		}
	}

	// OCP namespace visibility workaround: in OpenShift, namespaces are "all or none"
	// at the RBAC level — no native way to list only namespaces a user has partial access to.
	// When requested, emit Namespace scopes for every bound (cluster, namespace) regardless
	// of whether any rule explicitly covers the namespaces resource.
	if includeBindingNamespaceScopes {
		nsKey := resKey{"namespaces", ""}
		if scopeMap[nsKey] == nil {
			scopeMap[nsKey] = map[string]ScopeEntry{}
		}
		for i := range perms.Items {
			for _, binding := range perms.Items[i].Status.Bindings {
				for _, ns := range binding.Namespaces {
					if ns != "*" { // only named namespaces — cluster-wide bindings don't imply a specific ns
						id := binding.Cluster + "/" + ns
						scopeMap[nsKey][id] = ScopeEntry{Cluster: binding.Cluster, Namespace: ns}
					}
				}
			}
		}
	}

	results := make([]ResourceTypeScopes, 0, len(scopeMap))
	for k, scopes := range scopeMap {
		scopeList := make([]ScopeEntry, 0, len(scopes))
		for _, s := range scopes {
			scopeList = append(scopeList, s)
		}
		// Sort scopes deterministically: cluster asc, namespace asc
		sort.Slice(scopeList, func(i, j int) bool {
			if scopeList[i].Cluster != scopeList[j].Cluster {
				return scopeList[i].Cluster < scopeList[j].Cluster
			}
			return scopeList[i].Namespace < scopeList[j].Namespace
		})
		results = append(results, ResourceTypeScopes{
			Type:     k.typ,
			APIGroup: k.apiGroup,
			Scopes:   scopeList,
		})
	}
	// Sort results deterministically: type asc, api_group asc
	sort.Slice(results, func(i, j int) bool {
		if results[i].Type != results[j].Type {
			return results[i].Type < results[j].Type
		}
		return results[i].APIGroup < results[j].APIGroup
	})
	return results, nil
}

func (d *UserPermissionDecider) SearchAction(_ context.Context, userInfo user.Info, resource Resource) ([]string, error) {
	perms, err := d.lister.List(userInfo, labels.Everything())
	if err != nil {
		return nil, err
	}
	cluster := resource.Properties["cluster"]
	namespace := resource.Properties["namespace"]
	apiGroup := resource.Properties["apiGroup"]

	verbSet := make(map[string]struct{})
	for i := range perms.Items {
		perm := &perms.Items[i]
		if !bindingCovers(perm.Status.Bindings, cluster, namespace) {
			continue
		}
		for _, rule := range perm.Status.ClusterRoleDefinition.Rules {
			if !coversResource(rule.Resources, resource.Type) || !coversAPIGroup(rule.APIGroups, apiGroup) {
				continue
			}
			for _, verb := range rule.Verbs {
				if verb == "*" {
					for _, v := range []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"} {
						verbSet[v] = struct{}{}
					}
				} else {
					verbSet[verb] = struct{}{}
				}
			}
		}
	}

	verbs := make([]string, 0, len(verbSet))
	for v := range verbSet {
		verbs = append(verbs, v)
	}
	sort.Strings(verbs)
	return verbs, nil
}

// permAllows returns true if perm grants verb on (resourceType, apiGroup) within (cluster, namespace).
func permAllows(perm *clusterviewv1alpha1.UserPermission, cluster, namespace, resourceType, apiGroup, verb string) bool {
	if !bindingCovers(perm.Status.Bindings, cluster, namespace) {
		return false
	}
	return rulesAllowResourceAction(perm.Status.ClusterRoleDefinition.Rules, resourceType, apiGroup, verb)
}

// bindingCovers returns true if any binding matches the cluster and namespace.
// Callers must pass "*" explicitly for cluster-scoped intent — empty string is not
// treated as a wildcard to prevent false allows when namespace is omitted from the request.
func bindingCovers(bindings []clusterviewv1alpha1.ClusterBinding, cluster, namespace string) bool {
	for _, b := range bindings {
		if b.Cluster != cluster {
			continue
		}
		for _, ns := range b.Namespaces {
			if ns == "*" || ns == namespace {
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
