# Threat-led triage

A Claude Code / Codex skill that ranks security findings by what an attacker can actually reach and
chain in a specific codebase, rather than by abstract severity score.

When discovery is cheap and the findings are real, the useful question is not whether a bug is
real. It is whether an untrusted actor can reach it in your architecture, what trust boundary the
path crosses, and what it chains into. CVSS scores the flaw in isolation and cannot answer that.
This skill reads the code, and where available a STRIDE-GPT threat model of it, and produces a
defensible fix order with the reasoning attached to each finding.

## Install
Copy or symlink `skills/threat-led-triage` into `~/.claude/skills/`.

## Quickstart
From the root of the repo you want to triage:

```
stride-gpt analyze . -o model.json -f json
/threat-led-triage rank findings.json against model.json for this repo
```

The first line generates the threat model. The second invokes the skill, which reads your findings,
the model and the code, and writes a ranked fix order.

The skill takes a plain instruction, so name your files explicitly when they are not in the working
directory. The committed worked example was produced with an instruction of this shape:

```
/threat-led-triage Rank the findings in test/crapi-findings.json using the STRIDE-GPT threat model
at test/crapi-threat-model.json and the checked-out repo at ~/src/crapi. Write the result to
test/crapi-triage-result.md
```

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

## Worked example
A full run against [OWASP crAPI](https://github.com/OWASP/crAPI) is committed under `test/`:

- [`test/crapi-findings.json`](test/crapi-findings.json) — the 20 findings, with what Semgrep and
  Trivy detected and what a frontier model rated each one.
- [`test/crapi-threat-model.json`](test/crapi-threat-model.json) — the STRIDE-GPT model of the same
  code.
- [`test/crapi-triage-result.md`](test/crapi-triage-result.md) — the ranked output, unedited.

The clearest illustration is rank 3. A Low-rated information leak and a Medium-rated mass
assignment chain into remote code execution, which neither scanner detected and no isolated
severity rating could express.

## What it is not
It does not find new vulnerabilities. It ranks the ones you give it. There is no oracle for whether
a ranking was correct; it is a defensible ordering with exposed reasoning, not a verified answer.

## Companion tools
- [STRIDE-GPT](https://github.com/mrwadams/stride-gpt) — generates the threat model this skill consumes.
- [TM-Bench](https://tmbench.com) — benchmarks whether self-hostable models can generate threat
  models well enough to feed a pipeline like this.

## Licence
MIT. See [LICENSE](LICENSE).
