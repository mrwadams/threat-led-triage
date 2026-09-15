---
name: threat-led-triage
description: |
  Rank security findings by what an attacker can actually reach and chain in a
  specific codebase, not by severity score alone. Use when you have a list of
  vulnerabilities (scanner output, SCA report, CVE list, pentest findings, or a
  STRIDE-GPT threat model) and a checked-out repo, and you need a defensible fix
  order. Answers reachability, trust-boundary, and chaining questions per finding
  and produces a ranked list with per-finding reasoning you can argue with.
license: MIT
metadata:
  version: "0.1.0"
---

# Threat-led triage

Order findings by exploitability in this architecture, not by their abstract severity.

A CVSS score describes a flaw in isolation. It does not know whether an untrusted actor can
reach the vulnerable code in this deployment, what trust boundary the path crosses, or what the
flaw chains into. Those three questions decide fix order. This skill answers them by reading the
code and, where available, a threat model of it, then produces a ranked list with the reasoning
attached to each finding so an engineer can disagree with a specific claim rather than a number.

This is triage, not a scanner. It does not find new vulnerabilities. It ranks the ones you give it.

## Inputs

You need two of these three. The third is optional but improves the ranking.

1. **Findings** (required). A list of vulnerabilities in any form: SARIF, an SCA/dependency
   report, a list of CVE IDs, pentest findings, or free text. Each finding should have, or let you
   infer, a location (file, component, endpoint, or dependency) and a description.
2. **Repo access** (required). The codebase checked out where you are running. You read it to
   resolve findings to real code and trace reachability. Without the code this is guesswork.
3. **Threat model** (optional, strongly preferred). A STRIDE-GPT analysis of the same repo
   (`stride-gpt analyze . -o model.json -f json`). It supplies trust boundaries, components, a
   data flow diagram, and enumerated threats, which turn reachability from inference into lookup.
   If you do not have one and the repo is non-trivial, offer to generate it first.

If a required input is missing, say what is missing and what you can still do with what remains,
then stop. Do not invent findings or a threat model to fill the gap.

## The ranking question

For every finding, answer three questions in order. Later questions only matter if earlier ones
land. A finding no untrusted actor can reach ranks low almost regardless of its CVSS score.

1. **Reachability.** Can an actor outside the trust boundary reach the vulnerable code path? Trace
   it: entry point, the calls between it and the finding, and the privilege required to get there.
   Classify as one of: `unauthenticated` (reachable pre-auth from outside), `authenticated`
   (any logged-in user), `privileged` (admin or specific role), `internal` (only from another
   trusted service), `unreachable` (no path from any untrusted actor; dead code, disabled feature,
   or a dependency function never called).
2. **Trust boundary.** Which boundary does the reaching path cross? Name it from the threat model
   if you have one (gateway, service-to-service, service-to-data-store, tenant isolation). A flaw
   that crosses from untrusted to a data store or an authz decision is worth more than one that
   stays inside an already-trusted zone.
3. **Chaining.** What does this finding enable or combine with? Two flaws that are individually
   minor can form a single exploit path: an info leak that exposes an ID, then an authz gap that
   uses it. Note which other findings in the set it chains with, in which direction. Chained
   findings inherit each other's reachability, so a chain that starts pre-auth pulls its later
   links up the ranking.

## How to work

Do this in passes. Do not rank finding by finding in isolation, because chaining is a property of
the set.

1. **Load and normalise.** Read the findings and, if present, the threat model. Build one working
   list where each finding has: id, description, claimed severity (if any), and a location. Read
   `references/scoring.md` for the rubric before you score.
2. **Locate each finding in the code.** Resolve the location to real files and functions. For a
   dependency finding, find the call sites of the vulnerable function, not just the manifest entry.
   If you cannot find any use of it, that is itself the finding: flag it `unreachable — no call
   site found` and say so. Record the file:line you relied on so the reasoning is checkable.
3. **Map to the threat model.** Match each finding's location to a component and its trust
   boundaries. If there is no model, derive the boundaries yourself from the code (entry points,
   auth middleware, network config, service topology) and say you did, because that inference is
   weaker than a reviewed model.
4. **Answer the three questions per finding.** Reachability first, then boundary, then chaining.
   Trace real paths. When you assert a path exists, cite the code you followed. When you cannot
   determine reachability, say `undetermined` and explain what you would need, rather than
   guessing high or low.
5. **Find the chains.** Across the whole set, look for findings that feed each other. An
   information disclosure that reveals an identifier, a missing authorization check that consumes
   one, a mass-assignment that sets a field another endpoint trusts. Draw the chains explicitly.
6. **Score and rank.** Apply the rubric in `references/scoring.md`. Produce a total ordering. Where
   two findings tie, order by blast radius, then by remediation cost (cheaper fix first among
   equals, so the queue drains faster).
7. **Write the output.** Use the format below. Lead with the ranked list. Attach reasoning to each.

## Output format

Lead with the ranked table, most urgent first. Then one reasoning block per finding. Then the
chains. Then the limits of this analysis.

```
## Fix order

| Rank | Finding | Reachability | Boundary crossed | Chains | Priority |
|------|---------|--------------|------------------|--------|----------|
| 1    | ...     | unauthenticated | untrusted → data store | →#4, →#7 | Critical |
```

For each finding, a short block:

```
### 1. <finding> (was: <claimed severity>, now: <priority>)
Reachability: <classification>. <the path you traced, with file:line>.
Boundary: <which boundary the path crosses>.
Chains: <what it feeds or is fed by, with direction>.
Why this rank: <one or two sentences. Say plainly why it moved up or down from its claimed severity>.
```

Then:

```
## Chains
<Each chain as an ordered path: #5 (leak id) → #10 (modify) → #7 (delete). One line on the
combined impact and why the chain outranks its individual links.>

## Limits of this analysis
<State what you could not determine and what would change the ranking. Be specific:
undetermined reachability, a threat model that may be stale relative to the code, findings whose
location you could not resolve. Do not present the ranking as more certain than it is.>
```

## Honesty rules

These are the difference between a triage aid and a black box that launders guesses.

- **Cite the path.** Every reachability claim names the code you followed. "Reachable pre-auth"
  with no path is an assertion, not a finding.
- **Say undetermined when it is.** If you cannot trace reachability, rank it in a clearly-marked
  undetermined band and explain what is missing. Never round uncertainty up to Critical to be safe
  or down to Low to be tidy.
- **Do not invent findings.** You rank what you are given. If the code obviously contains something
  worse that is not in the findings list, note it under limits, separately, and do not fold it into
  the ranking as if it were an input.
- **Flag a stale model.** If the threat model references components or paths that no longer match
  the code, the ranking built on it is suspect. Say so.
- **No ground truth.** There is no oracle that says a ranking was correct. Present it as a defensible
  ordering with its reasoning exposed, not as a verified answer. This is the honest limit of the
  method and it belongs in the output.

## When the repo is large

Analysing reachability for every finding in a large monorepo is expensive. If the finding set is
large, triage in reachability tiers: resolve the entry points and trust boundaries once, bucket
findings by the component they touch, and trace paths hardest first (the components exposed to
untrusted actors). State that you tiered and which components you traced fully versus bucketed, so
a silent cap never reads as full coverage.
