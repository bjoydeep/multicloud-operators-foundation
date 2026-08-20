package authzen

import (
	"context"
	"testing"

	clusterviewv1alpha1 "github.com/stolostron/cluster-lifecycle-api/clusterview/v1alpha1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apiserver/pkg/authentication/user"
)

// mockLister returns a fixed UserPermissionList for any user.
type mockLister struct {
	perms *clusterviewv1alpha1.UserPermissionList
	err   error
}

func (m *mockLister) List(_ user.Info, _ labels.Selector) (*clusterviewv1alpha1.UserPermissionList, error) {
	return m.perms, m.err
}
func (m *mockLister) Get(_ user.Info, _ string) (*clusterviewv1alpha1.UserPermission, error) {
	return nil, nil
}

// helpers to build test fixtures

func adminPermission(cluster string) clusterviewv1alpha1.UserPermission {
	return clusterviewv1alpha1.UserPermission{
		ObjectMeta: metav1.ObjectMeta{Name: clusterviewv1alpha1.ManagedClusterAdminRole},
		Status: clusterviewv1alpha1.UserPermissionStatus{
			Bindings: []clusterviewv1alpha1.ClusterBinding{
				{Cluster: cluster, Scope: clusterviewv1alpha1.BindingScopeCluster, Namespaces: []string{"*"}},
			},
			ClusterRoleDefinition: clusterviewv1alpha1.ClusterRoleDefinition{
				Rules: []rbacv1.PolicyRule{
					{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
				},
			},
		},
	}
}

func viewPermission(cluster string) clusterviewv1alpha1.UserPermission {
	return clusterviewv1alpha1.UserPermission{
		ObjectMeta: metav1.ObjectMeta{Name: clusterviewv1alpha1.ManagedClusterViewRole},
		Status: clusterviewv1alpha1.UserPermissionStatus{
			Bindings: []clusterviewv1alpha1.ClusterBinding{
				{Cluster: cluster, Scope: clusterviewv1alpha1.BindingScopeCluster, Namespaces: []string{"*"}},
			},
			ClusterRoleDefinition: clusterviewv1alpha1.ClusterRoleDefinition{
				Rules: []rbacv1.PolicyRule{
					{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"get", "list", "watch"}},
				},
			},
		},
	}
}

func namespacedPermission(cluster string, namespaces []string, rules []rbacv1.PolicyRule) clusterviewv1alpha1.UserPermission {
	return clusterviewv1alpha1.UserPermission{
		ObjectMeta: metav1.ObjectMeta{Name: "kubevirt.io:admin"},
		Status: clusterviewv1alpha1.UserPermissionStatus{
			Bindings: []clusterviewv1alpha1.ClusterBinding{
				{Cluster: cluster, Scope: clusterviewv1alpha1.BindingScopeNamespace, Namespaces: namespaces},
			},
			ClusterRoleDefinition: clusterviewv1alpha1.ClusterRoleDefinition{Rules: rules},
		},
	}
}

var (
	ctx   = context.Background()
	alice = &user.DefaultInfo{Name: "alice"}
	// aliceWithGroups simulates a user whose permissions come via group bindings (like kube:admin via system:masters)
	aliceWithGroups = &user.DefaultInfo{Name: "alice", Groups: []string{"sre-team", "system:authenticated"}}
	sreTeamGroup    = &user.DefaultInfo{Groups: []string{"sre-team"}}
)

// --- Evaluate ---

func TestEvaluate_AdminAllowsAnyVerb(t *testing.T) {
	d := NewUserPermissionDecider(&mockLister{perms: &clusterviewv1alpha1.UserPermissionList{
		Items: []clusterviewv1alpha1.UserPermission{adminPermission("bar")},
	}})

	for _, verb := range []string{"get", "list", "create", "delete", "patch", "update"} {
		got, err := d.Evaluate(ctx, alice, Action{Name: verb},
			Resource{Type: "configmaps", Properties: map[string]string{"cluster": "bar", "namespace": "foo", "apiGroup": ""}},
		)
		if err != nil {
			t.Fatalf("verb=%s: unexpected error: %v", verb, err)
		}
		if !got {
			t.Errorf("verb=%s: admin should allow all verbs, got false", verb)
		}
	}
}

func TestEvaluate_ViewAllowsReadDeniesWrite(t *testing.T) {
	d := NewUserPermissionDecider(&mockLister{perms: &clusterviewv1alpha1.UserPermissionList{
		Items: []clusterviewv1alpha1.UserPermission{viewPermission("bar")},
	}})

	res := Resource{Type: "pods", Properties: map[string]string{"cluster": "bar", "namespace": "default", "apiGroup": ""}}

	for _, verb := range []string{"get", "list", "watch"} {
		got, err := d.Evaluate(ctx, alice, Action{Name: verb}, res)
		if err != nil || !got {
			t.Errorf("verb=%s: view should allow reads, got %v err %v", verb, got, err)
		}
	}
	for _, verb := range []string{"create", "delete", "update", "patch"} {
		got, err := d.Evaluate(ctx, alice, Action{Name: verb}, res)
		if err != nil || got {
			t.Errorf("verb=%s: view should deny writes, got %v err %v", verb, got, err)
		}
	}
}

func TestEvaluate_WrongClusterDenied(t *testing.T) {
	d := NewUserPermissionDecider(&mockLister{perms: &clusterviewv1alpha1.UserPermissionList{
		Items: []clusterviewv1alpha1.UserPermission{adminPermission("bar")},
	}})
	got, err := d.Evaluate(ctx, alice, Action{Name: "get"},
		Resource{Type: "configmaps", Properties: map[string]string{"cluster": "baz", "namespace": "foo"}},
	)
	if err != nil || got {
		t.Errorf("expected denied for wrong cluster, got %v err %v", got, err)
	}
}

func TestEvaluate_NamespaceScopedBinding_OutOfScopeDenied(t *testing.T) {
	rules := []rbacv1.PolicyRule{
		{APIGroups: []string{"kubevirt.io"}, Resources: []string{"virtualmachines"}, Verbs: []string{"get", "list"}},
	}
	d := NewUserPermissionDecider(&mockLister{perms: &clusterviewv1alpha1.UserPermissionList{
		Items: []clusterviewv1alpha1.UserPermission{namespacedPermission("bar", []string{"alpha", "beta"}, rules)},
	}})

	// in-scope namespace — allowed
	got, err := d.Evaluate(ctx, alice, Action{Name: "get"},
		Resource{Type: "virtualmachines", Properties: map[string]string{"cluster": "bar", "namespace": "alpha", "apiGroup": "kubevirt.io"}},
	)
	if err != nil || !got {
		t.Errorf("expected allowed for in-scope namespace, got %v err %v", got, err)
	}

	// out-of-scope namespace — denied
	got, err = d.Evaluate(ctx, alice, Action{Name: "get"},
		Resource{Type: "virtualmachines", Properties: map[string]string{"cluster": "bar", "namespace": "gamma", "apiGroup": "kubevirt.io"}},
	)
	if err != nil || got {
		t.Errorf("expected denied for out-of-scope namespace, got %v err %v", got, err)
	}
}

// TestEvaluate_EmptyNamespaceIsDenied verifies that omitting namespace from the request
// does NOT produce a false allow — callers must pass "*" explicitly for cluster-scoped intent.
func TestEvaluate_EmptyNamespaceIsDenied(t *testing.T) {
	rules := []rbacv1.PolicyRule{
		{APIGroups: []string{"kubevirt.io"}, Resources: []string{"virtualmachines"}, Verbs: []string{"get"}},
	}
	d := NewUserPermissionDecider(&mockLister{perms: &clusterviewv1alpha1.UserPermissionList{
		Items: []clusterviewv1alpha1.UserPermission{namespacedPermission("bar", []string{"alpha"}, rules)},
	}})

	// empty namespace must NOT match namespace-scoped binding for "alpha"
	got, err := d.Evaluate(ctx, alice, Action{Name: "get"},
		Resource{Type: "virtualmachines", Properties: map[string]string{"cluster": "bar", "namespace": "", "apiGroup": "kubevirt.io"}},
	)
	if err != nil || got {
		t.Errorf("empty namespace should be denied, not treated as wildcard; got %v err %v", got, err)
	}

	// "*" namespace must NOT match namespace-scoped binding either (user has no cluster-wide grant)
	got, err = d.Evaluate(ctx, alice, Action{Name: "get"},
		Resource{Type: "virtualmachines", Properties: map[string]string{"cluster": "bar", "namespace": "*", "apiGroup": "kubevirt.io"}},
	)
	if err != nil || got {
		t.Errorf("wildcard namespace request should not match a namespace-scoped binding; got %v err %v", got, err)
	}

	// explicit in-scope namespace must still work
	got, err = d.Evaluate(ctx, alice, Action{Name: "get"},
		Resource{Type: "virtualmachines", Properties: map[string]string{"cluster": "bar", "namespace": "alpha", "apiGroup": "kubevirt.io"}},
	)
	if err != nil || !got {
		t.Errorf("explicit in-scope namespace should be allowed; got %v err %v", got, err)
	}
}

func TestEvaluate_NoPermissions_Denied(t *testing.T) {
	d := NewUserPermissionDecider(&mockLister{perms: &clusterviewv1alpha1.UserPermissionList{}})
	got, err := d.Evaluate(ctx, alice, Action{Name: "get"},
		Resource{Type: "configmaps", Properties: map[string]string{"cluster": "bar", "namespace": "foo"}},
	)
	if err != nil || got {
		t.Errorf("expected denied with no permissions, got %v err %v", got, err)
	}
}

// TestEvaluate_GroupBasedPermission verifies that permissions granted via a group binding
// are found when the user.Info includes that group — the key case for users like kube:admin
// whose permissions come via system:masters rather than a direct user binding.
func TestEvaluate_GroupBasedPermission(t *testing.T) {
	d := NewUserPermissionDecider(&mockLister{perms: &clusterviewv1alpha1.UserPermissionList{
		Items: []clusterviewv1alpha1.UserPermission{adminPermission("bar")},
	}})

	// aliceWithGroups has permissions via group — must be found
	got, err := d.Evaluate(ctx, aliceWithGroups, Action{Name: "get"},
		Resource{Type: "pods", Properties: map[string]string{"cluster": "bar", "namespace": "default"}},
	)
	if err != nil || !got {
		t.Errorf("expected allowed when permission comes via group, got %v err %v", got, err)
	}
}

// --- EvaluateBatch ---

func TestEvaluateBatch_MixedResults(t *testing.T) {
	d := NewUserPermissionDecider(&mockLister{perms: &clusterviewv1alpha1.UserPermissionList{
		Items: []clusterviewv1alpha1.UserPermission{adminPermission("bar")},
	}})
	resources := []Resource{
		{Type: "configmaps", Properties: map[string]string{"cluster": "bar", "namespace": "foo"}},  // allowed
		{Type: "secrets", Properties: map[string]string{"cluster": "baz", "namespace": "foo"}},     // denied — wrong cluster
		{Type: "pods", Properties: map[string]string{"cluster": "bar", "namespace": "default"}},    // allowed
	}
	results, err := d.EvaluateBatch(ctx, alice, Action{Name: "get"}, resources)
	if err != nil {
		t.Fatal(err)
	}
	expected := []bool{true, false, true}
	for i, got := range results {
		if got != expected[i] {
			t.Errorf("index %d: expected %v got %v", i, expected[i], got)
		}
	}
}

// --- SearchResource ---

func TestSearchResource_AdminReturnsAllBindingScopes(t *testing.T) {
	perms := &clusterviewv1alpha1.UserPermissionList{
		Items: []clusterviewv1alpha1.UserPermission{
			{
				ObjectMeta: metav1.ObjectMeta{Name: clusterviewv1alpha1.ManagedClusterAdminRole},
				Status: clusterviewv1alpha1.UserPermissionStatus{
					Bindings: []clusterviewv1alpha1.ClusterBinding{
						{Cluster: "bar", Scope: clusterviewv1alpha1.BindingScopeCluster, Namespaces: []string{"*"}},
						{Cluster: "baz", Scope: clusterviewv1alpha1.BindingScopeCluster, Namespaces: []string{"*"}},
					},
					ClusterRoleDefinition: clusterviewv1alpha1.ClusterRoleDefinition{
						Rules: []rbacv1.PolicyRule{
							{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
						},
					},
				},
			},
		},
	}
	d := NewUserPermissionDecider(&mockLister{perms: perms})
	scopes, err := d.SearchResource(ctx, alice, Action{Name: "get"}, "configmaps")
	if err != nil {
		t.Fatal(err)
	}
	if len(scopes) != 2 {
		t.Errorf("expected 2 scopes (bar and baz), got %d: %+v", len(scopes), scopes)
	}
}

func TestSearchResource_NamespacedBindingFilteredByResourceType(t *testing.T) {
	vmRules := []rbacv1.PolicyRule{
		{APIGroups: []string{"kubevirt.io"}, Resources: []string{"virtualmachines"}, Verbs: []string{"get", "list"}},
	}
	d := NewUserPermissionDecider(&mockLister{perms: &clusterviewv1alpha1.UserPermissionList{
		Items: []clusterviewv1alpha1.UserPermission{namespacedPermission("bar", []string{"alpha", "beta"}, vmRules)},
	}})

	// virtualmachines — should return alpha and beta on bar
	scopes, err := d.SearchResource(ctx, alice, Action{Name: "get"}, "virtualmachines")
	if err != nil {
		t.Fatal(err)
	}
	if len(scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d: %+v", len(scopes), scopes)
	}

	// configmaps — rule doesn't cover configmaps, should return empty
	scopes, err = d.SearchResource(ctx, alice, Action{Name: "get"}, "configmaps")
	if err != nil {
		t.Fatal(err)
	}
	if len(scopes) != 0 {
		t.Errorf("expected 0 scopes for configmaps, got %d", len(scopes))
	}
}

// --- SearchAction ---

func TestSearchAction_AdminReturnsAllVerbs(t *testing.T) {
	d := NewUserPermissionDecider(&mockLister{perms: &clusterviewv1alpha1.UserPermissionList{
		Items: []clusterviewv1alpha1.UserPermission{adminPermission("bar")},
	}})
	verbs, err := d.SearchAction(ctx, alice,
		Resource{Type: "pods", Properties: map[string]string{"cluster": "bar", "namespace": "default", "apiGroup": ""}},
	)
	if err != nil {
		t.Fatal(err)
	}
	// admin wildcard (*) should expand to all standard verbs
	verbSet := make(map[string]struct{})
	for _, v := range verbs {
		verbSet[v] = struct{}{}
	}
	for _, expected := range []string{"get", "list", "watch", "create", "update", "patch", "delete"} {
		if _, ok := verbSet[expected]; !ok {
			t.Errorf("expected verb %q in admin result, got %v", expected, verbs)
		}
	}
}

func TestSearchAction_ViewReturnsReadOnlyVerbs(t *testing.T) {
	d := NewUserPermissionDecider(&mockLister{perms: &clusterviewv1alpha1.UserPermissionList{
		Items: []clusterviewv1alpha1.UserPermission{viewPermission("bar")},
	}})
	verbs, err := d.SearchAction(ctx, alice,
		Resource{Type: "pods", Properties: map[string]string{"cluster": "bar", "namespace": "default", "apiGroup": ""}},
	)
	if err != nil {
		t.Fatal(err)
	}
	verbSet := make(map[string]struct{})
	for _, v := range verbs {
		verbSet[v] = struct{}{}
	}
	for _, expected := range []string{"get", "list", "watch"} {
		if _, ok := verbSet[expected]; !ok {
			t.Errorf("view: expected verb %q, got %v", expected, verbs)
		}
	}
	for _, denied := range []string{"create", "delete", "update", "patch"} {
		if _, ok := verbSet[denied]; ok {
			t.Errorf("view: should not have verb %q, got %v", denied, verbs)
		}
	}
}

func TestSearchAction_WrongClusterReturnsEmpty(t *testing.T) {
	d := NewUserPermissionDecider(&mockLister{perms: &clusterviewv1alpha1.UserPermissionList{
		Items: []clusterviewv1alpha1.UserPermission{adminPermission("bar")},
	}})
	verbs, err := d.SearchAction(ctx, alice,
		Resource{Type: "pods", Properties: map[string]string{"cluster": "baz", "namespace": "default", "apiGroup": ""}},
	)
	if err != nil || len(verbs) != 0 {
		t.Errorf("expected empty verbs for wrong cluster, got %v err %v", verbs, err)
	}
}

func TestSearchAction_NamespacedMCRAReturnsVerbs(t *testing.T) {
	rules := []rbacv1.PolicyRule{
		{APIGroups: []string{"kubevirt.io"}, Resources: []string{"virtualmachines"}, Verbs: []string{"get", "list", "create"}},
	}
	d := NewUserPermissionDecider(&mockLister{perms: &clusterviewv1alpha1.UserPermissionList{
		Items: []clusterviewv1alpha1.UserPermission{namespacedPermission("bar", []string{"alpha"}, rules)},
	}})

	// in-scope namespace, correct resource → returns verbs
	verbs, err := d.SearchAction(ctx, alice,
		Resource{Type: "virtualmachines", Properties: map[string]string{"cluster": "bar", "namespace": "alpha", "apiGroup": "kubevirt.io"}},
	)
	if err != nil || len(verbs) != 3 {
		t.Errorf("expected 3 verbs for in-scope MCRA, got %v err %v", verbs, err)
	}

	// out-of-scope namespace → empty
	verbs, err = d.SearchAction(ctx, alice,
		Resource{Type: "virtualmachines", Properties: map[string]string{"cluster": "bar", "namespace": "beta", "apiGroup": "kubevirt.io"}},
	)
	if err != nil || len(verbs) != 0 {
		t.Errorf("expected empty verbs for out-of-scope namespace, got %v err %v", verbs, err)
	}
}

func TestSearchResource_DeduplicatesScopes(t *testing.T) {
	// Two permissions that both grant access to the same cluster/namespace
	d := NewUserPermissionDecider(&mockLister{perms: &clusterviewv1alpha1.UserPermissionList{
		Items: []clusterviewv1alpha1.UserPermission{adminPermission("bar"), viewPermission("bar")},
	}})
	scopes, err := d.SearchResource(ctx, alice, Action{Name: "get"}, "configmaps")
	if err != nil {
		t.Fatal(err)
	}
	if len(scopes) != 1 {
		t.Errorf("expected 1 deduplicated scope, got %d: %+v", len(scopes), scopes)
	}
}
