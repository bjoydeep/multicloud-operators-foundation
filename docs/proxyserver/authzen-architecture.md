# AuthZen PDP Architecture: From PIP to Decision API

This document explains how the AuthZen authorization endpoints in `ocm-proxyserver` are
architected, why they are structured the way they are, and what that structure makes easy
to change in the future.

**Relevant code:**
- `pkg/proxyserver/authzen/` — all AuthZen logic
- `pkg/proxyserver/api/register.go` — wiring point
- `pkg/cache/userpermission/` — the underlying permission store

**Parent design:** ACM-DDR-083, Phase 3.

---

## The Core Idea: PIP vs PDP

Two concepts from the ABAC reference architecture (OASIS / NIST SP 800-207) are central
to understanding this code.

**PIP — Policy Information Point**

A store of permission data. It answers: *"What permissions does this user have?"*
It returns raw data — roles, bindings, rules. It does not make decisions.

**PDP — Policy Decision Point**

An evaluator. It answers: *"Can this user do this thing?"*
It takes a specific question, consults the PIP for raw data, applies decision logic,
and returns a binary: **allow** or **deny**.

Before Phase 3, ACM had a PIP: the `UserPermission` cache, exposed at
`/apis/clusterview.open-cluster-management.io/v1alpha1/userpermissions`.
Consumers (Search, Console, Observability) fetched raw permission data from that endpoint
and each built their own allow/deny logic. Three consumers, three interpretations.

Phase 3 promotes the PIP into a PDP. Instead of fetching data and deciding, consumers
ask a question and get a decision.

```
Before Phase 3                        After Phase 3

UserPermission Cache (PIP)            UserPermission Cache (PIP)
        │                                      │
        │  raw data                            │  raw data
        ▼                                      ▼
  Search  Console  Observability        UserPermissionDecider  (PDP logic)
  (each builds its own allow/deny)             │
                                               │  allow / deny / scopes
                                               ▼
                                        AuthZen HTTP endpoints
                                        (one shared decision API)
```

The raw PIP endpoint remains available and unchanged. The PDP is an additional layer
on top, not a replacement.

---

## The Architectural Layers

```
┌─────────────────────────────────────────────────────────────┐
│  HTTP Transport Layer  (handler.go)                         │
│                                                             │
│  Knows: HTTP, JSON, status codes, authentication            │
│  Does NOT know: ClusterBinding, PolicyRule, cache structure  │
└────────────────────────────┬────────────────────────────────┘
                             │
                    [ Decider interface ]   ← the seam
                             │
┌────────────────────────────▼────────────────────────────────┐
│  Decision Logic Layer  (UserPermissionDecider in decider.go) │
│                                                             │
│  Knows: RBAC matching, ClusterBinding, PolicyRule           │
│  Does NOT know: HTTP, JSON, status codes                    │
└────────────────────────────┬────────────────────────────────┘
                             │
                    lister.List(userInfo)
                             │
┌────────────────────────────▼────────────────────────────────┐
│  Data Layer  (userpermission.Cache)                         │
│                                                             │
│  The PIP. In-memory store of all user permissions,          │
│  rebuilt every 2 seconds from RBAC informers.               │
└─────────────────────────────────────────────────────────────┘
```

Each layer knows only its own concerns. The `Decider` interface is the explicit boundary
between HTTP and RBAC. Neither side crosses it.

---

## The Decider Interface

```go
// pkg/proxyserver/authzen/decider.go

type Decider interface {
    Evaluate(ctx context.Context, userInfo user.Info, action Action, resource Resource) (bool, error)
    EvaluateBatch(ctx context.Context, userInfo user.Info, action Action, resources []Resource) ([]bool, error)
    SearchResource(ctx context.Context, userInfo user.Info, action Action, resourceType string) ([]Scope, error)
}
```

Three methods, each corresponding to one AuthZen endpoint:

| Method | AuthZen endpoint | Question answered |
|---|---|---|
| `Evaluate` | `POST /access/v1/evaluation` | Can this user do X on this resource? → bool |
| `EvaluateBatch` | `POST /access/v1/evaluations` | Can this user do X on each of these resources? → []bool |
| `SearchResource` | `POST /access/v1/search/resource` | Which (cluster, namespace) scopes can this user access? → []Scope |

The interface accepts `user.Info` rather than `Subject` (the wire type from the HTTP
request). This is intentional: `user.Info` carries the full identity — name plus group
memberships. `Subject` is a protocol concept; by the time it reaches the Decider it has
been resolved into a real identity. This matters because permissions are often granted
via group bindings, not user-level bindings directly.

---

## The Real Implementation: UserPermissionDecider

`UserPermissionDecider` is the concrete struct that implements `Decider`. It holds a
reference to the `userpermission.Lister` — the read interface into the UserPermission
cache.

```go
// pkg/proxyserver/authzen/decider.go

type UserPermissionDecider struct {
    lister userpermission.Lister
}
```

### How `Evaluate` works

```
Question: "Can alice GET configmaps in namespace foo on cluster bar?"

1. d.lister.List(aliceUserInfo)
   → returns all UserPermissions for alice
     (union of user-level bindings and group-level bindings)

2. For each UserPermission:
   a. bindingCovers(bindings, cluster="bar", namespace="foo")
      → does this permission apply to cluster bar / namespace foo?
   b. rulesAllowResourceAction(rules, "configmaps", apiGroup="", verb="get")
      → do the RBAC rules allow GET on configmaps?

3. If ANY permission passes both checks → return true (allow)
   If none pass → return false (deny)
```

The two-check structure mirrors Kubernetes RBAC semantics exactly: a binding scopes
WHERE a permission applies (cluster, namespace); the rules define WHAT is permitted
(verbs, resources, apiGroups). Both must match for access to be granted.

### How `EvaluateBatch` works

Same as `Evaluate`, but the cache is consulted **once** and the result is reused for
all resources in the batch. This is the primary reason the batch endpoint exists: one
cache lookup for N permission checks instead of N cache lookups.

Results are returned in the same order as the input slice. Position 0 in the result
corresponds to position 0 in the request.

### How `SearchResource` works

Instead of checking a specific (cluster, namespace) pair, `SearchResource` collects
all scopes where the user's permissions allow the requested action on the given resource
type. It omits the apiGroup filter intentionally — when searching, the caller names a
resource type but not a specific apiGroup, and the result should include all bindings
where that resource type is accessible under any apiGroup.

Duplicate scopes (two permissions covering the same cluster/namespace) are deduplicated
before returning.

### Wildcard handling

All three matching functions support the Kubernetes RBAC `*` wildcard:

- Verb `"*"` covers any verb
- Resource `"*"` covers any resource
- APIGroup `"*"` covers any apiGroup
- Namespace `"*"` in a binding means cluster-wide access (all namespaces)

`managedcluster:admin` uses `["*"]` for all three rule fields, which is why it allows
any action on any resource.

---

## Full Data Flow: Single Evaluation

```
POST /access/v1/evaluation
{ "subject": {"type":"user","id":"alice"},
  "action":  {"name":"get"},
  "resource": {"type":"configmaps","properties":{"cluster":"bar","namespace":"foo"}} }

  │
  ▼ handler.go: Evaluation()

  1. json.Decode(r.Body) → EvaluationRequest
  2. request.UserFrom(r.Context()) → callerInfo  (set by auth middleware)
  3. callerCanQuerySubject(callerInfo, req.Subject)
     → Path 1: caller name == subject.id (self-query) → allowed
     → Path 2: SAR "can caller impersonate users/alice?" → allowed/denied
  4. subjectUserInfo(req.Subject, callerInfo)
     → self-query: return callerInfo (full user.Info with groups)
     → impersonation: return DefaultInfo{Name:"alice"} (name only)

  │  h.decider.Evaluate(ctx, subjectUserInfo, action, resource)
  │
  ▼ ─── Decider interface boundary ───

  ▼ decider.go: UserPermissionDecider.Evaluate()

  5. d.lister.List(userInfo) → []UserPermission
     (from in-memory cache; rebuilt every 2s from RBAC informers)

  6. For each UserPermission:
     permAllows(perm, "bar", "foo", "configmaps", "", "get")
       bindingCovers: does perm cover cluster=bar, ns=foo?  → yes/no
       rulesAllowResourceAction: does perm allow GET configmaps?  → yes/no

  7. return true (first match) or false (no match)

  ▼ ─── back in handler ───

  8. writeJSON(w, EvaluationResponse{Decision: true})

HTTP 200 { "decision": true }
```

---

## Why the Interface Exists: Three Concrete Benefits

### 1. Independent testability

The handler can be tested without a live cache. The decider can be tested without HTTP.
Each layer uses a mock of the other side of the interface.

**Testing the handler** — inject a `mockDecider` that returns whatever you need:

```go
// handler_test.go
h := NewHandler(&mockDecider{evaluateResult: true}, nil)
// now test HTTP parsing, auth enforcement, response marshaling
// without any cache or Kubernetes cluster
```

**Testing the decider** — inject a `mockLister` that returns fixed permissions:

```go
// decider_test.go
d := NewUserPermissionDecider(&mockLister{perms: &UserPermissionList{
    Items: []UserPermission{adminPermission("bar")},
}})
// now test RBAC matching logic with precise, controlled input
// without any running cache
```

Neither test requires a Kubernetes cluster or a running cache.

### 2. Clean separation of concerns

The handler knows HTTP. It parses JSON, enforces authentication, sets status codes.
It does not know what `ClusterBinding` or `PolicyRule` is.

The decider knows RBAC. It applies binding and rule matching logic.
It does not know what HTTP status codes are.

If the cache internal structure changes — say `ClusterBinding` grows a new field — only
`decider.go` needs updating. `handler.go` is unaffected.

If the HTTP contract changes — say a new query parameter is added — only `handler.go`
changes. `decider.go` is unaffected.

### 3. The implementation is swappable at one point

The interface is injected at construction time in a single place:

```go
// pkg/proxyserver/api/register.go

func installAuthZen(server *genericapiserver.GenericAPIServer, lister userpermission.Lister, kubeClient kubernetes.Interface) {
    h := authzen.NewHandler(authzen.NewUserPermissionDecider(lister), kubeClient)
    // ...
}
```

The handler receives a `Decider`. It never sees the concrete type. Swapping the
implementation means changing this one line — nothing else.

---

## What This Makes Easy to Change

### Phase 2: Adding hub functional permissions (CompositeDecider)

Phase 2 adds `hubpermissions` — a second data source covering hub functional roles
(policy admin, app deployer) that are not in the UserPermission cache.

The handlers do not change. A new struct satisfies the `Decider` interface and merges
both sources:

```go
type CompositeDecider struct {
    clusterDecider Decider  // reads UserPermission cache (managed-cluster permissions)
    hubDecider     Decider  // reads hubpermissions cache (hub functional roles)
}

func (c *CompositeDecider) Evaluate(ctx context.Context, userInfo user.Info, action Action, resource Resource) (bool, error) {
    // ask the cluster decider first
    if allowed, err := c.clusterDecider.Evaluate(ctx, userInfo, action, resource); allowed || err != nil {
        return allowed, err
    }
    // fall through to hub permissions
    return c.hubDecider.Evaluate(ctx, userInfo, action, resource)
}
```

Wire it in at the single injection point:

```go
// register.go — Phase 2 change
h := authzen.NewHandler(
    authzen.NewCompositeDecider(
        authzen.NewUserPermissionDecider(clusterLister),
        authzen.NewHubPermissionDecider(hubLister),
    ),
    kubeClient,
)
```

Handlers, handler tests, and decider tests are all unchanged.

### External PDP (OPA, Cerbos, OpenFGA)

An external PDP bridge satisfies the `Decider` interface by forwarding questions to an
external engine and translating the response:

```go
type OPADecider struct {
    endpoint string
    client   *http.Client
}

func (o *OPADecider) Evaluate(ctx context.Context, userInfo user.Info, action Action, resource Resource) (bool, error) {
    // translate to OPA input, POST to OPA endpoint, parse result
}
```

Same single-line swap in `register.go`. The AuthZen HTTP surface, the handler logic, and
the auth enforcement are all reused without change.

### Richer decision logic

The current `UserPermissionDecider` does pattern matching against the cache. If the
decision logic needs to grow — time-of-day constraints, risk-based access, contextual
conditions from the AuthZen `context` field — those changes live entirely in
`decider.go`. The handlers, the cache, and the wiring point are not touched.

---

## Where Everything Is Wired Together

```
cmd/proxyserver/app/start.go
    └── NewProxyServer(kubeClient, clusterClient, ...)
            └── api.Install(...)
                    └── installAuthZen(server, upCache, kubeClient)
                            │
                            ├── authzen.NewUserPermissionDecider(lister)   ← PIP wrapped as PDP
                            ├── authzen.NewHandler(decider, kubeClient)    ← PDP wrapped as HTTP
                            │
                            └── server.Handler.NonGoRestfulMux.HandleFunc(...)
                                    /.well-known/authzen-configuration  → h.Discovery
                                    /access/v1/evaluation               → h.Evaluation
                                    /access/v1/evaluations              → h.Evaluations
                                    /access/v1/search/resource          → h.SearchResource
```

`upCache` (the UserPermission cache) is created in `installClusterViewGroup` and passed
through. The same cache instance backs both the existing PIP endpoint
(`/apis/clusterview.../userpermissions`) and the new PDP endpoints. No new data is
stored; only the decision layer is new.

---

## Summary

| Concept | Where it lives | What it does |
|---|---|---|
| PIP (raw permission data) | `pkg/cache/userpermission/` | Stores aggregated user permissions; rebuilt from RBAC informers |
| `Lister` interface | `pkg/cache/userpermission/lister.go` | Read interface into the PIP; the only thing the Decider needs |
| `Decider` interface | `pkg/proxyserver/authzen/decider.go` | The seam between HTTP and RBAC; makes the PDP swappable and testable |
| `UserPermissionDecider` | `pkg/proxyserver/authzen/decider.go` | The PDP: wraps the Lister, applies RBAC matching, returns allow/deny |
| `Handler` | `pkg/proxyserver/authzen/handler.go` | The HTTP face of the PDP; knows nothing about RBAC internals |
| Wiring | `pkg/proxyserver/api/register.go` | The one place where PIP → Decider → Handler are composed |

The `Decider` interface is the architectural seam that keeps the HTTP transport, the
decision logic, and the data store independently changeable. Adding a new data source,
replacing the decision engine, or testing any layer in isolation all reduce to the same
operation: satisfy the `Decider` interface and inject at the single wiring point.
