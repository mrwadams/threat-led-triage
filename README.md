# Threat-led triage

A Claude Code / Codex skill that ranks security findings by what an attacker can actually reach and
chain in a specific codebase, rather than by abstract severity score.

When discovery is cheap and the findings are real, the useful question is not whether a bug is
real. It is whether an untrusted actor can reach it in your architecture, what trust boundary the
path crosses, and what it chains into. CVSS scores the flaw in isolation and cannot answer that.
This skill reads the code, and where available a STRIDE-GPT threat model of it, and produces a
defensible fix order with the reasoning attached to each finding.

## Inputs
- A list of findings (SARIF, SCA report, CVE list, pentest findings, or free text).
- The repo, checked out where the skill runs.
- Optionally a STRIDE-GPT threat model of the same repo (`stride-gpt analyze . -o model.json -f json`),
  which supplies trust boundaries and enumerated threats.

## Output
A ranked list, most urgent first, with per-finding reasoning: the reachability classification and
the code path behind it, the boundary crossed, the chains it participates in, and why it moved up
or down from its claimed severity. Plus an explicit statement of what the analysis could not
determine.

## What it is not
It does not find new vulnerabilities. It ranks the ones you give it. There is no oracle for whether
a ranking was correct; it is a defensible ordering with exposed reasoning, not a verified answer.

## Install
Copy or symlink `skills/threat-led-triage` into `~/.claude/skills/`.

## Companion tools
- [STRIDE-GPT](https://github.com/mrwadams/stride-gpt) — generates the threat model this skill consumes.
- [TM-Bench](https://tmbench.com) — benchmarks whether self-hostable models can generate threat
  models well enough to feed a pipeline like this.
