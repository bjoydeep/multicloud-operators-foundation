# AuthZen Implementation Review

| Field | Value |
|---|---|
| **Last reviewed** | 2026-08-18 15:02 PDT |
| **Reviewer** | Joydeep Banerjee |
| **Scope** | Phase 3 MVP — AuthZen endpoints in `ocm-proxyserver` |
| **Parent DDR** | ACM-DDR-083 |
| **Code reviewed** | `pkg/proxyserver/authzen/`, `pkg/proxyserver/api/register.go`, `cmd/proxyserver/app/server.go` |
| **API spec reviewed** | `docs/proxyserver/authzen-api.yaml` |
| **Status** | Action items identified — see below |

---

## Overall Assessment

The design is architecturally sound. The phasing (PIP unification first, PDP on top) is
correct: a decision service built on fragmented data would just centralize the inconsistency.
Phase 3 as implemented is a solid POC. The Decider interface boundary is clean. The test
coverage is good for a first pass. The gaps below are the difference between a POC and a
production-grade, standards-aligned PDP that can survive an API review.

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
| [A. Spec-compliant uses](#a-spec-compliant-uses) | 1 | Strengths — lead with these |
| [B. Intentional architectural deviations](#b-intentional-architectural-deviations) | 3 | Design choices we own and can defend |
| [C. Where AuthZen is inadequate for multicluster Kubernetes](#c-where-authzen-is-inadequate-for-multicluster-kubernetes) | 2 | Spec gaps, not our gaps |
| [D. Spec features not yet implemented](#d-spec-features-not-yet-implemented) | 5 | Gaps to close — tracked in action items |

---

### A. Spec-Compliant Uses

These look like they might be deviations but are not. Lead with them in any review.

**`properties.cluster`, `properties.namespace`, `properties.apiGroup` — intended use of the extension mechanism.**

AuthZen's spec defines `properties` on the Resource object as:

> *"OPTIONAL. An object which can be used to express additional attributes of a Resource.
> Such attributes can include, **but are not limited to**, attributes of the resource
> used in access evaluations or metadata about the resource."*

The phrase "but are not limited to" is deliberate — the spec enumerates no specific
property names. Implementations define whatever attributes their authorization policy
requires. ACM's three properties (`cluster`, `namespace`, `apiGroup`) are exactly what
`properties` is for. This is a **strength** in a review, not something to defend.

*Posture:* "We use `properties` as the spec intends — to carry the authorization context
our policy requires. Cluster and namespace are the dimensions ACM policy evaluates against.
They belong in `properties` by design."

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

*Defense:* "We implement the AuthZen interface. Our PDP is a permission-scope server,
not a resource catalog. Resource inventory belongs to Search — it already indexes every
resource across every managed cluster. Coupling the PDP to that inventory would create
a circular dependency: Search needs the PDP to scope what to show, and the PDP would
need Search's data to know what exists. Separating them keeps each service in its own
domain. The PDP returns permission scope; Search intersects that scope against its own
index. This is the only design that is O(1) at fleet scale."

**`resource.id` omitted on search requests.**

The AuthZen spec marks `id` as REQUIRED on the Resource object. ACM omits it on
`/access/v1/search/resource` requests because the search endpoint asks "in which scopes
can alice access this resource type?" — the specific resource instance is unknown and
irrelevant. The spec's schema was designed with evaluation (checking a known instance)
in mind; the schema and the search endpoint's own semantics are in tension. The spec's
rationale for the search endpoint supports omitting `id`.

*Defense:* "Requiring `id` on a search request contradicts the purpose of the search
endpoint, which the spec itself defines as discovering what a subject can access. We
follow the endpoint's stated purpose over its schema constraint."

**Batch `action` is shared across all items, not per-item.**

The AuthZen spec defines `evaluations` as a list of `{action, resource}` pairs, allowing
a different action per resource. ACM uses a single top-level `action` that applies to
all resources in the batch. This is a deliberate simplification: ACM's batch use case
is always the same operation across multiple resources ("can alice GET each of these?").
Per-item actions add schema complexity with no current consumer benefit.

*Defense:* "Our batch use case is homogeneous by design. We can add per-item actions
when a consumer needs them without a breaking change — the simplification is additive."

---

### C. Where AuthZen Is Inadequate for Multicluster Kubernetes

These are not our gaps — they are places where the AuthZen spec does not address the
problem domain well. Document them as spec limitations, not implementation limitations.

**The cluster dimension has no AuthZen equivalent.**

AuthZen's resource model (`type`, `id`, `properties`) has no concept of a cluster
boundary. In a multicluster system, "can alice GET pods in namespace foo?" is
meaningless without specifying which cluster. The spec's `properties` extension fills
this gap (see section A), but the absence of cluster as a first-class dimension means
the spec cannot validate or reason about multicluster scope at the protocol level.

*Implication:* Any AuthZen implementation targeting a multicluster system will need
this extension. This is a gap in the spec for distributed Kubernetes environments.

**AuthZen has no answer for cross-subject group resolution.**

Search does not yet call these AuthZen endpoints — it currently uses the `userpermissions`
API directly. This gap will surface when Search (or Console) integrates with the PDP.
A concrete example shows why it matters.

Alice is a member of the `sre-team` group. An admin granted `sre-team` admin access
on cluster `bar`. There is no direct binding to alice — her access flows entirely
through the group.

Alice queries the PDP herself: the PDP extracts her full identity from her bearer
token (name `alice`, groups `[sre-team, system:authenticated]`), looks up both alice's
direct permissions and `sre-team`'s permissions, and correctly returns `decision: true`.

When Search integrates with the PDP, it will call on alice's behalf as a service account:
```json
{ "subject": { "type": "user", "id": "alice" }, "action": { "name": "get" }, ... }
```
The PDP knows the caller is `search-sa`, not alice. All it has for alice is her name.
It has no way to know alice is in `sre-team` — that information lives in OpenShift's
OAuth server (or whichever identity provider issued alice's token), not in the
authorization store. So the PDP looks up alice by name, finds no direct binding, and
returns `decision: false` — the wrong answer.

AuthZen's subject model (`type` + `id`) provides no mechanism for a caller to supply
a subject's group memberships, and no guidance on how a PDP should resolve them when
evaluating on behalf of another caller. The spec simply says "here is the subject, go
decide" — it does not address the fact that the information needed to decide may live
in a separate system the PDP cannot reach.

*Resolution — `subject.properties.groups` extension:*

The fix is small and spec-compliant. AuthZen already defines `subject.properties` as
an optional extensibility bag (same pattern as `resource.properties`). The caller
passes alice's groups alongside her name:

```json
{
  "subject": {
    "type": "user",
    "id": "alice",
    "properties": { "groups": "sre-team,system:authenticated" }
  }
}
```

The PDP builds a full `user.Info{Name: "alice", Groups: ["sre-team", ...]}` and the
cache lookup resolves both direct and group-inherited permissions correctly.

In ACM's architecture, consumers (Search, Console) always operate on behalf of an
authenticated user whose bearer token is present in the request. A `TokenReview`
against the hub kube-apiserver returns the user's full identity including all group
memberships. The caller has everything it needs to populate `subject.properties.groups`
without any additional IDP integration.

This extension is not implemented today because no consumer has integrated with these
endpoints yet. However, it **must be implemented before MVP**. In Kubernetes, most
permissions flow through groups — `cluster-admin` via `system:masters`, team access
via group bindings. Shipping the endpoints without this fix means the PDP returns
wrong answers for the majority of real users. Silent incorrectness in an authorization
service is not an acceptable MVP trade-off.

---

### D. Spec Features Not Yet Implemented

These are actual gaps against the AuthZen spec. Each is either deferred with a
rationale or flagged as needing a decision. See the MVP Action Items table for
which of these must be closed before an external review.

**Batch `executeStrategy` / `semantics` field — always runs `execute_all`.**

AuthZen's batch evaluation endpoint defines three execution semantics: `execute_all`
(run all, return all results), `deny_on_first_deny` (short-circuit on first denial —
logical AND), `permit_on_first_permit` (short-circuit on first permit — logical OR).
The current implementation silently ignores any `semantics` field and always runs
`execute_all`. *Must be closed before MVP.*

**Discovery document does not follow the AuthZen spec format.**

The `/.well-known/authzen-configuration` endpoint returns a non-standard key structure.
This is the first endpoint a compliance reviewer will check. *Must be closed before MVP.*

**Resource type taxonomy is unresolved.**

The convention for mapping Kubernetes `apiGroup+resource` to the AuthZen `resource.type`
string is not established. Tests use `"virtualmachines"` and `"virtualmachines.kubevirt.io"`
inconsistently. This must be frozen before any consumer integrates — it is a breaking
API change after the fact. *Must be closed before MVP.*

**`search/action` endpoint — not yet implemented.**

AuthZen defines this as "what actions can this subject perform on this resource?" It is
the simplest of the unimplemented endpoints (collect all verbs the subject has on the
given cluster). Without it, the implementation covers 3 of 5 AuthZen endpoint types.
*Recommended for MVP — see action items.*

**`search/subject` (inverse query) — explicitly deferred.**

"Who can access cluster bar?" Requires iterating all subjects in the `permissionStore`,
which has no public enumeration method today. The least-demanded endpoint for immediate
consumers. *Deferred until `evaluation` and `search/resource` are proven in production.*

---

## Correctness Issues

**`namespace == ""` creates false positives in `bindingCovers`** (`decider.go:114`)

```go
if ns == "*" || ns == namespace || namespace == "" {
    return true
}
```

If a caller omits `namespace` from `resource.properties`, the empty string matches any
binding, including namespace-scoped bindings for specific namespaces. A user with access
only to `alpha` on cluster `bar` receives `decision: true` for a query with no namespace
specified — a false allow. This is a correctness bug with a security implication. Callers
should be required to pass `"*"` explicitly for cluster-scoped intent.

---

## Operational Issues

**`klog.Infof` on every impersonation SAR** (`handler.go:188`)

Fires on every cross-subject query. At Search's query frequency, this floods the default
log level. Downgrade to `klog.V(4).Infof`.

**`EvaluateBatch` is O(P×R)** (`decider.go:54`)

For each resource in the batch, the implementation scans all permissions linearly.
At POC scale this is acceptable. Under real Search load (100-item batches across 50
concurrent users), building the permission index once per batch call and doing O(1)
lookups per resource will be necessary.

---

## MVP Action Items

Items are sequenced by impact in an API review. Items 1-6 should be completed before
any external review. Item 7 is worth the investment given the scrutiny context.
Items 8 onward are post-MVP.

| # | Priority | Action | Why it matters in review |
|---|---|---|---|
| 1 | **Must** | Establish `{resource}.{group}` resource type taxonomy; encode in discovery response and validate in handlers | First question in any API review; breaking change if deferred past consumer integration |
| 2 | **Must** | Fix discovery document to follow AuthZen spec format | First thing an AuthZen compliance reviewer checks |
| 3 | **Must** | Add `semantics` field to `EvaluationsRequest` (`execute_all` / `deny_on_first_deny` / `permit_on_first_permit`) | Spec gap; low implementation cost; real consumer value |
| 4 | **Must** | Fix `namespace == ""` false positive in `bindingCovers` | Security finding if caught in a demo or review |
| 5 | **Must** | Document impersonation group-resolution limitation in discovery response, OpenAPI spec, and architecture doc | Will be found by any reviewer who tests `kube:admin` via impersonation |
| 6 | **Must** | Downgrade impersonation SAR log from `klog.Infof` to `klog.V(4).Infof` | Trivial; avoids log noise being flagged in demo |
| 7 | **Argue for** | Implement `search/action` endpoint | 4/5 AuthZen endpoints is a defensible position; 3/5 is not |
| 8 | **Defer** | Optimize `EvaluateBatch` to build permission index once | Performance, not correctness; becomes relevant under real Search load |
| 9 | **Must** | Implement `subject.properties.groups` extension for cross-subject group resolution | In Kubernetes, most permissions flow through groups. Without this, the PDP silently returns wrong answers for the majority of real users. Callers already have alice's bearer token and can get groups via a single `TokenReview` — no IDP integration required. |
| 10 | **Defer** | Add rate limiting on AuthZen `NonGoRestfulMux` paths | Have an answer ready ("global GenericAPIServer rate limiting applies"); don't spend MVP time here |
| 11 | **Defer** | Add cache readiness signal to discovery response | Operationally valuable; not a review blocker |
| 12 | **Defer** | Add structured audit logging for authorization decisions | Important for compliance customers; verify that GenericAPIServer audit middleware covers these paths first |

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
| "Your `search/resource` doesn't return resource instances" | "AuthZen assumes a PDP that is also a resource catalog. Ours is a permission-scope server. Returning (cluster, namespace) pairs is the only O(1) design at fleet scale. Search intersects those scopes with its own index." |
| "You're missing the `semantics` field on batch" | "Being added in MVP — it was missing in the POC." |
| "You're missing `search/action`" | "Being added before the external review." OR "Explicitly deferred with a timeline." |
| "You're missing `search/subject`" | "Explicitly deferred. The cache has no public enumeration method today; adding it safely is the sequencing constraint." |
| "Cross-subject queries lose group permissions" | "Being fixed in MVP via `subject.properties.groups` — callers pass the subject's groups alongside their name. Callers already hold the user's bearer token and resolve groups via a single `TokenReview`. This is a spec-compliant use of AuthZen's `subject.properties` extensibility." |
| "AuthZen is a new and immature standard" | "Correct. We align with it for its type-agnostic resource model, built-in batch semantics, and standards trajectory — not because it fully solves the multicluster problem today. Where it falls short, we have documented ACM-specific adaptations." |

---

## References

- [AuthZen Authorization API 1.0](https://openid.github.io/authzen/) — OpenID Foundation, July 2026
- `docs/proxyserver/authzen-api.yaml` — ACM OpenAPI spec for these endpoints
- `docs/proxyserver/authzen-architecture.md` — PIP → PDP architecture explanation
- `pkg/proxyserver/authzen/` — implementation
- ACM-DDR-083 — parent design document
