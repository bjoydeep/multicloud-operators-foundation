# AuthZen Implementation Review

| Field | Value |
|---|---|
| **Last reviewed** | 2026-08-18 16:38 PDT |
| **Reviewer** | Joydeep Banerjee |
| **Scope** | Phase 3 MVP — AuthZen endpoints in `ocm-proxyserver` |
| **Parent DDR** | ACM-DDR-083 |
| **Code reviewed** | `pkg/proxyserver/authzen/`, `pkg/proxyserver/api/register.go`, `cmd/proxyserver/app/server.go` |
| **API spec reviewed** | `docs/proxyserver/authzen-api.yaml` |
| **Status** | All items resolved. Verb sort finding fixed. 3 production adoption concerns documented (RBAC rollout — easy; network dependency — needs debate; Go client — easy). Ready for external review. |

---

## Verification Log

Code was read directly to confirm each claimed fix. Results:

| # | Claimed fix | Verified? | Notes |
|---|---|---|---|
| #2 | Discovery — spec-compliant field names, absolute HTTPS URLs | ✓ | F1 flagged in prior review was already fixed in the YAML — reviewer was checking an older version. Field names match. |
| #3 | Batch `options.evaluations_semantic` with short-circuit | ✓ | Short-circuit truncates the **response** correctly. `EvaluateBatch` in `decider.go` still evaluates all items — API semantics are correct, this is a performance gap only. Folded into deferred item #8. |
| #4 | `namespace == ""` false positive removed from `bindingCovers` | ✓ | Clean fix; comment added. |
| #5 | Group resolution limitation documented | ✓ | Superseded by #9. F2 (stale description in `/evaluation` endpoint description) is now fixed. The `Action` schema correctly notes `action.properties` is not supported — accurate, stays as-is. |
| #6 | `klog.Infof` → `klog.V(4).Infof` on SAR logs | ✓ | Both log lines downgraded. |
| #9 | `subject.properties.groups` extension implemented | ✓ | `Subject.Properties`, `parseGroups`, and `subjectUserInfo` all verified. |
| #1 | Resource type taxonomy — "resource name only" convention | ✓ | Documented in `types.go` comment with examples, encoded in discovery as `resource_type_convention: "resource_name_only"`, consistently applied across all tests. |
| #7 | `search/action` endpoint | ✓ | Complete: types, `Decider` interface, `UserPermissionDecider.SearchAction`, handler, route registered in `register.go`, advertised in discovery, 4 decider tests + 4 handler tests. **New finding — see below.** |

**New finding this round — `SearchAction` verb order is non-deterministic. FIXED.**

`SearchAction` collected verbs into a `map[string]struct{}` then iterated the map to build
the response slice. Go map iteration order is randomised per run. Not a correctness issue
but a consumer diffing raw responses would see spurious differences.

**Fixed:** `sort.Strings(verbs)` added before return in `decider.go`. Same fix applied to
`SearchResources` — both `ResourceTypeScopes` results and `ScopeEntry` slices within each
result are now sorted deterministically (type/apiGroup asc, cluster/namespace asc).

---

## Overall Assessment

The design is architecturally sound. The phasing (PIP unification first, PDP on top) is
correct: a decision service built on fragmented data would just centralize the
inconsistency. Phase 3 as implemented is a solid POC. The Decider interface boundary is
clean. The test coverage is good for a first pass.

All Must-priority items are resolved. All pre-review blockers are closed. The one new
finding (verb order) is low priority. This implementation is ready for external review.

---

## What Is Strong

**Correct ABAC layer decomposition.** The PIP → PDP promotion follows the standard
architecture (OASIS / NIST SP 800-207) correctly. The decision to unify the PIP in
Phases 1-2 before building the PDP in Phase 3 is the right sequencing.

**Clean Decider interface boundary.** The HTTP transport layer (`handler.go`) and the
RBAC decision logic (`decider.go`) are properly separated. Neither leaks into the other.
Adding a `CompositeDecider` for Phase 2 hub permissions requires changing one line in
`register.go` and nothing else.

**Building on `Lister`, not cache internals.** The `UserPermissionDecider` reads from the
public `Lister` interface only. Zero regression risk to the existing `userpermissions` PIP
endpoint or to the cache internals.

**kube:admin group bug was caught and fixed.** The `toUserInfo` → `subjectUserInfo` fix
(using the caller's real `user.Info` for self-queries, preserving group memberships) was
the right solution. Without it, the most common admin role would have returned `false` for
every evaluation — a silent production correctness failure.

**Impersonation via SAR is the right mechanism.** Using standard Kubernetes
`SubjectAccessReview` as the gate for cross-subject queries reuses existing, auditable RBAC
rather than inventing a new authorization mechanism.

---

## Relationship to AuthZen Authorization API 1.0

This implementation is a **multicluster profile** of AuthZen Authorization API 1.0
(OpenID Foundation, July 2026) — not a full conformant implementation. The profile
name is deliberate: the deviations and extensions here are not ACM-specific quirks,
they are the changes any AuthZen implementation requires when the resource model spans
multiple Kubernetes clusters. The relationship falls into four distinct categories,
which a reviewer should read in order.

| Category | Items | Reviewer posture |
|---|---|---|
| [A. Spec-compliant uses](#a-spec-compliant-uses) | 2 | Strengths — lead with these |
| [B. Intentional architectural deviations](#b-intentional-architectural-deviations) | 3 | Design choices we own and can defend |
| [C. Where AuthZen is inadequate for multicluster Kubernetes](#c-where-authzen-is-inadequate-for-multicluster-kubernetes) | 2 | Spec gaps, not our gaps |
| [D. Spec features not yet implemented](#d-spec-features-not-yet-implemented) | 2 | Gaps to close or explicitly deferred |

---

### A. Spec-Compliant Uses

These look like they might be deviations but are not. Lead with them in any review.

**`resource.properties` — intended use of the spec's extension mechanism.**

AuthZen's spec defines `properties` on the Resource object as:

> *"OPTIONAL. An object which can be used to express additional attributes of a Resource.
> Such attributes can include, **but are not limited to**, attributes of the resource
> used in access evaluations or metadata about the resource."*

The phrase "but are not limited to" is deliberate — the spec enumerates no specific
property names. Implementations define whatever their authorization policy requires.
ACM's use of `properties.cluster`, `properties.namespace`, and `properties.apiGroup`
is exactly what `properties` is designed for.

*Posture:* "We use `properties` as the spec intends — to carry the authorization context
our policy requires. Cluster and namespace are the dimensions ACM policy evaluates against.
They belong in `properties` by design."

**`subject.properties.groups` — spec-compliant extension for cross-subject group resolution.**

The same extensibility pattern applies to `Subject`. The spec defines `subject.properties`
as an optional map. ACM uses it to carry the target user's group memberships in
cross-subject (impersonation) queries, so the PDP can resolve group-inherited permissions
correctly without an IDP integration:

```json
{
  "subject": {
    "type": "user",
    "id": "alice",
    "properties": { "groups": "sre-team,system:authenticated" }
  }
}
```

Callers obtain group memberships via a single `TokenReview` against the hub
kube-apiserver — they already hold the user's bearer token because requests in ACM's
architecture flow through the authenticated caller.

---

### B. Intentional Architectural Deviations

These are places where we understand the spec and chose differently. Each has a
defensible rationale rooted in the multicluster architecture.

**`search/resource` returns permission scopes, not resource instances.**

The AuthZen spec envisions a PDP that also serves as a resource catalog — it returns
individual resource instances the subject can access. ACM's PDP knows about permissions,
not about which VMs or ConfigMaps exist (that is Search's index). Returning
`(cluster, namespace)` scope pairs and having Search intersect them with its own index
is the only design that is O(1) at fleet scale. Returning instances would require the
PDP to enumerate every resource across every managed cluster on every query.

*Defense:* "Our PDP is a permission-scope server, not a resource catalog. Resource
inventory belongs to Search — it already indexes every resource across every managed
cluster. Coupling the PDP to that inventory would create a circular dependency: Search
needs the PDP to scope what to show, and the PDP would need Search's data to know what
exists. The PDP returns permission scope; Search intersects that scope against its index.
This is the only design that is O(1) at fleet scale."

**`resource.id` omitted on search requests.**

The AuthZen spec marks `id` as REQUIRED on the Resource object. ACM omits it on
`/access/v1/search/resource` requests because the search endpoint asks "in which scopes
can alice access this resource type?" — the specific resource instance is unknown and
irrelevant. The spec's schema was designed with evaluation (checking a known instance)
in mind; the schema and the search endpoint's own semantics are in tension.

*Defense:* "Requiring `id` on a search request contradicts the purpose of the search
endpoint, which the spec itself defines as discovering what a subject can access. We
follow the endpoint's stated purpose over its schema constraint."

**Batch `action` is shared across all items, not per-item.**

The AuthZen spec defines `evaluations` as a list of `{action, resource}` pairs, allowing
a different action per resource. ACM uses a single top-level `action` that applies to
all resources in the batch. ACM's batch use case is always the same operation across
multiple resources ("can alice GET each of these?"). Per-item actions add schema
complexity with no current consumer benefit.

*Defense:* "Our batch use case is homogeneous by design. Per-item actions can be added
when a consumer needs them without a breaking change — the simplification is additive."

---

### C. Where AuthZen Is Inadequate for Multicluster Kubernetes

These are not our gaps — they are places where the AuthZen spec does not address the
problem domain. Document them as spec limitations, not implementation limitations.

**The cluster dimension has no AuthZen equivalent.**

AuthZen's resource model (`type`, `id`, `properties`) has no concept of a cluster
boundary. In a multicluster system, "can alice GET pods in namespace foo?" is
meaningless without specifying which cluster. The spec's `properties` extension fills
this gap (see section A), but the absence of cluster as a first-class dimension means
the spec cannot validate or reason about multicluster scope at the protocol level.

*Implication:* Any AuthZen implementation targeting a multicluster system will need
this extension. This is a gap in the spec for distributed Kubernetes environments.

**AuthZen has no answer for cross-subject group resolution.**

Search does not yet call these endpoints — it currently uses the `userpermissions` API
directly. This gap will surface when Search or Console integrates with the PDP.

Alice is a member of the `sre-team` group. An admin granted `sre-team` admin access on
cluster `bar`. There is no direct binding to alice — her access flows entirely through
the group.

Alice queries the PDP herself: the PDP extracts her full identity from her bearer token
(name `alice`, groups `[sre-team, system:authenticated]`), looks up both alice's direct
permissions and `sre-team`'s permissions, and correctly returns `decision: true`.

When Search integrates with the PDP, it will call on alice's behalf as a service account.
Without group context it only has alice's name — no direct binding exists — and returns
`decision: false`. The wrong answer.

AuthZen's subject model (`type` + `id`) provides no mechanism for a caller to supply a
subject's group memberships. The spec says "here is the subject, go decide" — it does
not address that the information needed to decide may live in a separate system.

**This is addressed by the `subject.properties.groups` extension (section A).** Callers
do a `TokenReview` on the user's bearer token, get full group membership, and pass it
alongside the subject ID. The PDP resolves everything correctly. The spec's own
`subject.properties` extensibility makes this compliant — no deviation.

---

### D. Spec Features Not Yet Implemented

Only two remain. Everything else from the original list has been implemented or resolved.

**`search/action` endpoint — not yet implemented.**

AuthZen defines this as "what actions can this subject perform on this resource?" It is
the simplest of the unimplemented endpoints: collect all verbs the subject has on the
given cluster. Without it, the implementation covers 3 of 5 AuthZen endpoint types.
*Recommended for MVP — see action items.*

**`search/subject` (inverse query) — explicitly deferred.**

"Who can access cluster bar?" Requires iterating all subjects in the `permissionStore`,
which has no public enumeration method today. The least-demanded endpoint for immediate
consumers. *Deferred until `evaluation` and `search/resource` are proven in production.*

---

## MVP Action Items

| # | Status | Priority | Action | Notes |
|---|---|---|---|---|
| 1 | **DONE** | ~~Must~~ | Resource type taxonomy — "resource name only" convention | ✓ Documented in `types.go`, encoded in discovery response, consistently applied in tests. |
| 2 | **DONE** | ~~Must~~ | Discovery — spec-compliant field names, absolute HTTPS URLs | ✓ F1 (field name mismatch) was already fixed in the YAML — reviewer was on an older version. |
| 3 | **DONE** | ~~Must~~ | Batch `options.evaluations_semantic` short-circuit semantics | ✓ API contract is correct. Performance optimization (stopping evaluation early in the decider) is a separate concern folded into #8. |
| 4 | **DONE** | ~~Must~~ | Fix `namespace == ""` false positive in `bindingCovers` | ✓ |
| 5 | **DONE** | ~~Must~~ | Document group resolution limitation | ✓ Superseded by #9. F2 (stale endpoint description) now fixed. |
| 6 | **DONE** | ~~Must~~ | `klog.Infof` → `klog.V(4).Infof` on SAR logs | ✓ |
| 7 | **DONE** | ~~Argue for~~ | `search/action` endpoint | ✓ Full implementation verified. **Minor:** verb results non-deterministic (map iteration) — add sort before returning. |
| 8 | **DEFER** | Defer | `EvaluateBatch` full short-circuit in decider + O(P×R) optimization | Performance only — API semantics are correct. Revisit under real Search load. |
| 9 | **DONE** | ~~Must~~ | `subject.properties.groups` for cross-subject group resolution | ✓ |
| 10 | **DEFER** | Defer | Rate limiting on AuthZen paths | GenericAPIServer covers it; have the answer ready. |
| 11 | **DEFER** | Defer | Cache readiness signal in discovery | Nice-to-have operationally. |
| 12 | **DEFER** | Defer | Structured audit logging | Verify GenericAPIServer audit covers these paths first. |
| — | **DEFER** | Defer | `search/subject` (inverse query) | Requires cache internal change; least-demanded endpoint. |

---

## Preparing the "Not Exactly AuthZen" Defense

When reviewers compare this implementation to the AuthZen spec, the posture is:

> "We implement the AuthZen interface as a defined multicluster profile. Where we deviate,
> we deviate intentionally because AuthZen's model is insufficient for a multicluster
> Kubernetes system — and any implementation targeting this problem domain would face the
> same gaps. Where we are short of the spec, we have a clear sequenced plan to close them."

Specific answers to prepare:

| Likely reviewer challenge | Answer |
|---|---|
| "Your `search/resource` doesn't return resource instances" | "Our PDP is a permission-scope server, not a resource catalog. Returning (cluster, namespace) pairs is the only O(1) design at fleet scale. Search intersects those scopes with its own index. Coupling the PDP to Search's resource inventory would create a circular dependency." |
| "You're missing the `semantics` field on batch" | "Implemented — `options.evaluations_semantic` supports `execute_all`, `deny_on_first_deny`, and `permit_on_first_permit`." |
| "You're missing `search/action`" | "Being added before the external review." OR "Explicitly deferred with a timeline." |
| "You're missing `search/subject`" | "Explicitly deferred. The cache has no public enumeration method today; adding it safely is the sequencing constraint." |
| "Cross-subject queries lose group permissions" | "Addressed via `subject.properties.groups` — callers pass the subject's groups alongside their name. Callers hold the user's bearer token and resolve groups via a single `TokenReview`. This is spec-compliant use of AuthZen's `subject.properties` extensibility." |
| "AuthZen is a new and immature standard" | "Correct. We align with it for its type-agnostic resource model, built-in batch semantics, and standards trajectory — not because it fully solves the multicluster problem today. Where it falls short, we have documented ACM-specific adaptations." |

---

## Strategic Argument for Migration

Consumer reviews (search-v2-api, search-mcp-server) raise valid concerns about migration
effort. There are two ways to read those concerns.

**Reviewer frame:** "Can I swap AuthZen in today without breaking search?"
Answer: Partially — with a non-trivial rewrite.

**Architecture frame:** "Can AuthZen become the stable contract layer so the backend
can change freely?"
Answer: Yes — and that is the entire point.

### The cost of NOT migrating

Right now every consumer reads the raw `UserPermission` CRD format directly. They all
have code that walks `ClusterBinding`, `ClusterRoleDefinition`, and `PolicyRule`. When
Phase 1 adds auto-MCRA, or Phase 2 adds hub permissions, or the cache changes shape —
every consumer must be updated simultaneously.

```
Before (today):
  search-v2-api      ──reads──▶ UserPermission CRD internals
  search-mcp-server  ──reads──▶ UserPermission CRD internals
  console            ──reads──▶ UserPermission CRD internals

After (AuthZen as contract layer):
  search-v2-api      ──calls──▶ AuthZen API ──▶ backend (changes freely)
  search-mcp-server  ──calls──▶ AuthZen API ──▶ backend (changes freely)
  console            ──calls──▶ AuthZen API ──▶ backend (changes freely)
```

Once consumers are behind the AuthZen contract, the backend is free to evolve. The entire
`userpermission.Cache` can be replaced — new MCRA pipeline, hub permissions, different
informer structure — and no consumer changes. The AuthZen server absorbs the change.
This is not philosophical. It is operational leverage.

### The migration cost is one-time

The reviewers treat the search-v2-api rewrite as a reason not to migrate. The correct
frame is that it is a necessary one-time cost to reach a better architecture. The rewrite
happens once. The decoupling benefit is permanent. After migration, search-v2-api never
touches `ClusterBinding` or `PolicyRule` again — it calls an API and gets structured
scope lists.

### What this means for open gaps

The functional gaps the reviews identify (`matchNamespaces()` implicit visibility, SQL
shape, transport) are real engineering problems. They are not arguments against migration
— they are the scope of the migration. They should be solved as part of the adoption
work, not used as reasons to defer it indefinitely.

---

## Production Adoption Concerns

Three architectural concerns raised during consumer review.
Classified by effort and priority.

### Point 1 — New mandatory RBAC rollout (Easy, operational, not MVP)

The `ocm-proxyserver`'s `DelegatingAuthorizationOptions` enforces authorization on all
paths including non-resource URLs like `/access/v1/*`. Every caller needs a `ClusterRole`
with `nonResourceURLs: ["/access/v1/..."] verbs: ["get","post"]` bound to them.

This doesn't exist in ACM's out-of-box RBAC today. Adoption requires:
- For self-queries by end users: bind a minimal `ClusterRole` to `system:authenticated`
- For elevated callers (Search SA, MCP SA): explicit `impersonate` grant in addition. These already exist.

**Classification:** Easy operational/packaging work. Standard RBAC rollout, no design
changes required. Not an MVP blocker — handled as part of the feature's adoption rollout.

---

### Point 2 — New network dependency (Architectural — needs peer review and debate)

The AuthZen endpoints are served by `ocm-proxyserver` on its `NonGoRestfulMux`
(`/access/v1/...` paths), **not** proxied through the standard Kubernetes aggregated
API server path (`/apis/<group>/<version>/...`). Today, all in-cluster consumers make
one connection to `kubernetes.default.svc` (the kube-apiserver) and get everything —
including `userpermissions` via aggregation.

If a consumer adopts the AuthZen endpoints, it needs a **second, separate connection**:

```
Today:
  consumer ──▶ kubernetes.default.svc (one front door, one TLS cert, one badge check)
               │
               └── /apis/clusterview.../userpermissions → routes to ocm-proxyserver

With AuthZen:
  consumer ──▶ kubernetes.default.svc               (still needed for everything else)
  consumer ──▶ ocm-proxyserver.multicluster-engine.svc:443  (NEW — different door)
               └── /access/v1/...
```

The second connection requires:
- New endpoint configuration (service address, port)
- Different TLS trust — `ocm-proxyserver` has its own cert, not the kube-apiserver CA
- Possible NetworkPolicy changes to allow the new traffic path
- New service dependency in consumer deployment manifests

**Root cause:** AuthZen spec mandates `/access/v1/...` paths, which Kubernetes
aggregation only routes for `/apis/...` paths. There is a real tension: spec compliance
requires these paths, but Kubernetes's aggregation infrastructure only forwards `/apis/`.

**Potential mitigation (not implemented):** Register a Kubernetes APIService at
`/apis/authzen.open-cluster-management.io/v1/` that proxies to `ocm-proxyserver` and
translates paths. This would restore the single-connection model but is complex and
would break AuthZen path compliance for external clients.

**Classification:** Hard architectural concern. Requires peer review and debate before
any existing in-cluster consumer (search-mcp-server, search-v2-api) adopts the API.
New consumers designed specifically for AuthZen are not affected — they expect to call
a separate endpoint.

---

### Point 4 — Namespace visibility: OCP constraint, not an AuthZen gap (Implement in AuthZen)

**The OCP constraint:**

In OpenShift, namespace visibility is "all or none" at the RBAC level. You can either
list ALL namespaces (cluster-admin) or NONE. Standard Kubernetes RBAC provides no way
to say "show only the namespaces where this user has some access." This is an OCP
platform limitation.

Confirmed by search-v2-api team: *"Yes, that's important. It comes from the fact that in
OCP for the Namespace object you can only authorize a user to see all or none. We have
several cases where the user needs to see only the namespaces they are authorized for, so
this logic is taking care of that."*

Standard Kubernetes RBAC:
```bash
kubectl get pods -n foo          # ✅ works — you have the rule
kubectl get namespace foo        # ❌ fails — namespaces is separate, no rule granted
kubectl get namespaces           # ❌ fails — all or none in OCP
```

**What `matchNamespaces()` does:**

search-v2-api works around the OCP constraint with `matchNamespaces()`
(`rbacFineGrainedHelper.go:162-206`): if a user has **any binding** on a cluster, grant
them visibility of the `Namespace` object for any namespace in that binding, regardless
of whether any RBAC rule covers `namespaces`. This is binding-driven, not rule-driven.

**AuthZen is correct — but the OCP workaround must live somewhere:**

`search/resources` is strictly rule-gated and correctly mirrors Kubernetes RBAC. It does
NOT include the OCP namespace workaround — which is right. AuthZen should not invent
permissions that don't exist in RBAC.

However, the OCP workaround is legitimate and every consumer will need it. If it stays
in search-v2-api only, console, observability, and MCP server will all reimplement it
independently. This is exactly the duplication the AuthZen contract layer is designed
to prevent.

**The right fix: implement once in AuthZen, all consumers benefit.**

Add `include_binding_namespace_scopes` flag to `search/resources`. When set, the server
walks `Status.Bindings` directly and emits `Namespace` scopes for any bound
cluster/namespace, regardless of rules:

```json
{
  "subject": { "type": "user", "id": "alice" },
  "action":  { "name": "get" },
  "all_resource_types": true,
  "include_binding_namespace_scopes": true
}
```

Response includes additional namespace entries:
```json
{ "type": "namespaces", "api_group": "", "scopes": [{"cluster": "bar", "namespace": "alpha"}] }
```

**Implemented** — see `SearchResourcesRequest.IncludeBindingNamespaceScopes` in
`pkg/proxyserver/authzen/types.go` and `decider.go`.

**Classification:** ACM/OCP-specific extension. Not part of the AuthZen spec. Documented
in `authzen-api.yaml`. Justified by the OCP platform constraint and the value of
centralising the workaround rather than duplicating it across every consumer.

---

### Point 3 — No official Go client (Easy, not MVP)

Only server-side code exists (`pkg/proxyserver/authzen/{decider,handler,types}.go`).
Consumers would need to hand-roll `net/http` + JSON clients. Additionally, error
responses currently use `http.Error()` returning `text/plain` bodies — not the
structured `Status` JSON objects that `client-go` and other Kubernetes tooling expect.

**What is needed:**
- `pkg/client/authzen/` — typed Go client with methods for each endpoint
- Replace `http.Error()` with structured JSON `Status` error responses

**Classification:** Easy, straightforward engineering work. Not an MVP blocker but
required before any Go-based consumer integrates. A typed client removes adoption
friction significantly.

---

## References

- [AuthZen Authorization API 1.0](https://openid.github.io/authzen/) — OpenID Foundation, July 2026
- `docs/proxyserver/authzen-api.yaml` — ACM OpenAPI spec for these endpoints
- `docs/proxyserver/authzen-architecture.md` — PIP → PDP architecture explanation
- `pkg/proxyserver/authzen/` — implementation
- ACM-DDR-083 — parent design document
