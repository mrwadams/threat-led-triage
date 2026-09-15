# Scoring rubric

The priority of a finding is a function of reachability, the boundary it crosses, its blast radius
if exploited, and whether it participates in a chain. Severity score from the source tool is an
input, not the answer. It sets a ceiling on impact, not on priority.

Do not compute a false-precision number. Use the bands below and let the reasoning carry the
decision. The bands exist to make orderings consistent across findings, not to look quantitative.

## Reachability sets the floor

Reachability is the dominant term. Nothing an untrusted actor cannot reach is Critical, whatever
its CVSS.

| Reachability | Meaning | Ceiling on priority |
|--------------|---------|---------------------|
| `unauthenticated` | Reachable pre-auth from outside the perimeter | Critical |
| `authenticated` | Reachable by any logged-in user | High |
| `privileged` | Requires admin or a specific role already held | Medium |
| `internal` | Only reachable from another trusted service | Medium |
| `unreachable` | No path from any untrusted actor; dead code, disabled feature, uncalled dependency | Low / informational |
| `undetermined` | Could not trace a path either way | Ranked in a separate band, flagged |

A finding cannot exceed the ceiling its reachability allows, no matter how severe the flaw is in
the abstract. A CVSS 9.8 in a code path with no reachable caller is not a 9.8 in this system.

## Boundary and impact set the position within the ceiling

Within a reachability band, order by what the reaching path reaches:

- **Boundary crossed.** Untrusted → authorization decision, or untrusted → data store, or one
  tenant → another tenant, outranks a flaw that stays inside an already-trusted zone. Cross-tenant
  reach is close to always the top of its band.
- **Blast radius.** Full account or data-set compromise outranks single-record exposure. Write
  access outranks read. Persistent outranks transient.
- **STRIDE category as a tie-breaker.** Elevation of privilege and tampering with an authz or
  integrity control generally outrank information disclosure of non-sensitive data. Judge by what
  is actually exposed, not by the category label alone.

## Chaining promotes

A finding's rank is the max of its own reachability and the reachability it inherits from any chain
it belongs to.

- A finding only reachable while authenticated, but which an unauthenticated finding feeds into,
  inherits `unauthenticated` reachability for ranking, because the combined path starts pre-auth.
- Rank a chain as a unit at the reachability of its entry point and the impact of its endpoint. Its
  links then sit together near that rank, annotated with their position in the chain.
- The multi-primitive point from the AI Vulnerability Storm briefing lives here: individually minor
  findings that combine into one exploit path are exactly what per-finding severity scoring misses,
  and exactly what this step recovers.

## Remediation cost is a tie-breaker only

Among findings of equal priority, prefer the cheaper fix first, so the queue drains and exposure
drops faster. Never let a low remediation cost raise a finding's priority above what its
reachability and impact justify. Cost breaks ties; it does not set rank.

## Priority labels

Map the result to four labels. Keep them, do not invent an ordinal score.

- **Critical** — fix now. Unauthenticated reach to a serious impact, or the entry of a chain that
  reaches one.
- **High** — fix this cycle. Authenticated reach to serious impact, or a strong cross-boundary flaw.
- **Medium** — scheduled. Privileged or internal reach, or limited impact.
- **Low / informational** — backlog or accept. Unreachable, or trivial impact even when reachable.

Put `undetermined`-reachability findings in their own clearly-labelled group rather than
distributing them across the bands. Guessing their reachability is exactly the error this method
exists to avoid.
