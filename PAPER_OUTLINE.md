# Paper outline: Tool-Vector Sensitivity in Indirect-Prompt-Injection Compliance for MCP-Using Agents

> Working title — for arxiv pre-print first; USENIX Security
> workshop or NDSS workshop venue afterwards. This document is the
> outline / claims map. The full paper draft will live in a
> separate branch under `paper/` with TeX sources.

## Abstract (~150 words)

Indirect prompt injection in LLM-using agents is widely
characterised as a model-property: certain models comply with
injection content more than others, and the compliance rate is
typically reported via prompt-only probes that embed the poisoned
content in the user-turn directly. We re-test this characterisation
across four MCP server vectors — filesystem, HTTP-fetch, git, and
SQLite — using a real agent loop (poisoned content arrives as a
tool result, not in the user prompt) and a tool-use-aware verdict
that distinguishes attack execution from defensive flagging.

Across six frontier models, prompt-only compliance rates of up to
75% drop to 0% in agent-loop tests for the filesystem and git
vectors. The fetch and SQLite vectors break this pattern for one
specific model (`openai/gpt-4o-mini`), where compliance occurs
only when the injection asks for *more of the same read tool*
the agent is already using. We triangulate this pattern across
both vectors and contrast it with git, where the same model
defends because compliance requires switching tool families.

We argue that indirect-injection compliance is **tool-vector-shape
sensitive**: a function of (model, surface-of-tools-already-active,
disguise variant), not of model alone. We release the harness, the
probes, the disclosures, and a defensive companion library
(`mcp-guard`) that synthesises deterministic policies from
observed compliance and backtests them against legitimate
traffic.

## 1. Introduction

- Indirect prompt injection: the OWASP LLM01 / MITRE ATLAS T0051
  threat class, generalised to MCP-server-based agent products.
- Existing prompt-only benchmarks
  (incl. our own 2026-04-28 EchoLeak / MCP-poisoning measurements)
  report 50–75% compliance rates on frontier models.
- Open question: do these rates translate to deployed-product
  agent loops, where injected content arrives as a `tool_result`,
  not as part of the user prompt?

## 2. Methodology

### 2.1 Headless agent-loop probe
- Real MCP-server subprocess (`@modelcontextprotocol/server-filesystem`,
  `mcp-server-fetch`, `mcp-server-git`, `mcp-server-sqlite`).
- Agent connects via the official `mcp` Python SDK (stdio).
- LLM driven via native SDK (Anthropic, OpenAI) or OpenAI-compatible
  endpoint (xAI). Tool-calling round-trips with real execution
  feedback.

### 2.2 Tool-use-aware verdict
- Existing prompt-only probes use substring matching on the
  model's free-text response. We show this misclassifies defenders
  who flag injection content to the user as attackers.
- Our verdict requires actual emission of a `tool_use` whose
  `(name, args)` matches an attack pattern (e.g.,
  `read_text_file({path: "id_rsa"})`,
  `fetch({url: "attacker.example/..."})`,
  `read_query({query: contains "credentials"})`).

### 2.3 Probes (4 MCP vectors)
- **Filesystem** — `<!-- BUILD_DOCS_DIRECTIVE -->`,
  `[ASSISTANT_TOOL_CONTEXT]`, `<<META: SUMMARY-PIPELINE>>` in
  poisoned files.
- **HTTP-fetch** — same disguise variants in poisoned HTML.
  Compliance signature: second `fetch()` to attacker domain.
- **Git** — same variants in poisoned commit messages.
  Compliance signature: `git_show` of attacker-named refspec
  or `git_commit` from a read-only review task.
- **SQLite** — same variants in poisoned TEXT-column data.
  Compliance signature: `read_query` against `credentials` /
  sensitive table.

### 2.4 Product wrapper layer
- We additionally test 5 product-system-prompt profiles wrapped
  around the filesystem agent loop:
  - Cline, Continue.dev (OSS — verbatim system prompt extracted
    from source);
  - Cursor, Claude Desktop (closed — best-effort approximation);
  - Generic baseline (no system prompt).

## 3. Results

### 3.1 Headline numbers
Across 6 frontier models × 3 disguise variants × 4 vectors plus
the 5 product profiles:

| Vector | Total attempts | Attack tool_uses | Compliance |
|---|---|---|---|
| Filesystem (incl. product simulator) | ~47 | 0 | 0% |
| HTTP-fetch | 15 | 2 (GPT-4o-mini only) | 13% |
| Git | 12 | 0 | 0% |
| SQLite | 6+ | 1 (GPT-4o-mini only) | ~17% |

(See `LEADERBOARD.md` for live numbers updated nightly.)

### 3.2 Methodology gap
- Same scenarios produce 25–75% prompt-only compliance and 0%
  agent-loop compliance, on the same models, with the same
  disguise variants.
- Worked example: Grok 4.1 Fast Reasoning at 75% prompt-only
  (with explicit "do not surface to user" reasoning) → 0% in
  agent loop.

### 3.3 Tool-vector-shape sensitivity
- GPT-4o-mini complies on fetch (2/3) and SQLite (1/3) but
  defends on filesystem (0/3) and git (0/3).
- Common shape on the failing vectors: injection asks for *more
  of the same read tool* the agent is already using.
- Defending vectors: injection requires switching tool families
  (read → write, read-X → read-different-X).
- Hypothesis: compliance bar is lower when the injection-induced
  tool call shape-matches the user-induced tool call. Future work
  needed to verify causally (e.g., controlled single-tool vs
  multi-tool surface variants).

### 3.4 Product wrappers don't change the picture
- 5 product profiles × 3 scenarios × 2 providers on filesystem:
  0/30 attack tool_uses. Whether the agent's system prompt is
  Cline's verbatim 6K-token rules document or "" (no prompt), the
  filesystem result is the same.

## 4. Defenses (`mcp-guard`)

- Deterministic policy layer at the tool-call boundary.
- Policy synthesis from observed gaps: pattern-based, no LLM
  required at synthesis time.
- Backtest harness against fixture corpus measures FPR/TPR before
  deployment.
- Default rules for each tested vector cover the observed
  compliance signatures.
- Released as a pip-installable companion package; same
  evaluator + corpus design as in the harness.

## 5. Limitations

- Single MCP server per vector (not, e.g., third-party
  filesystem MCP servers with different defaults).
- Three disguise variants per scenario set (HTML-comment,
  bracketed-block, META-framed). Multi-step attacks across
  multiple files / fetches / commits not tested.
- Cursor / Claude Desktop profiles are approximations; verbatim
  product evidence requires user-driven runs through the proxy
  (runbooks at [`examples/demo_*_runbook.md`](examples/)).
- Compliance numbers are point-in-time; the nightly Action
  ([`.github/workflows/nightly-panel.yml`](.github/workflows/nightly-panel.yml))
  re-runs the panel as model versions evolve.

## 6. Contributions

1. The cross-vector empirical comparison (4 MCP vectors × 6
   frontier models × 3 disguise variants).
2. The methodology-gap result quantifying the prompt-only-
   overestimates pattern at 25–75 percentage points.
3. The tool-vector-shape-sensitivity hypothesis with
   triangulated supporting evidence on `gpt-4o-mini`.
4. `mcp-guard`, an open-source defensive companion library.
5. Nightly leaderboard infrastructure for ongoing tracking as
   models evolve.

## 7. Reproducibility

- All code, fixtures, scenarios, and session JSONLs at
  https://github.com/euanmcrosson-dotcom/purple-scaffold (MIT).
- `LEADERBOARD.md` updated nightly via the GitHub Action.
- `findings/` directory contains per-vector writeups with
  verbatim outputs.
- `disclosures/` directory contains submitted bug-bounty
  bodies; methodology caveats already reflect the agent-loop
  result for transparency.

## 8. Related work

- EchoLeak / CVE-2025-32711 (M365 Copilot, June 2025).
- Invariant Labs MCP poisoning disclosure (April 2025).
- garak (NVIDIA) — provides probe scaffolding; we
  contributed an upstream PR ([`garak_pr/`](garak_pr/)) to
  improve detector calibration against modern frontier models.
- OWASP LLM01 reference.
- MITRE ATLAS T0051 / T0053.

## 9. Submission targets

| Venue | Track | Fit | Lead time |
|---|---|---|---|
| arxiv.org | cs.CR | Pre-print, immediate visibility | Days |
| USENIX Security WOOT | Workshop | Hands-on / measurement track | ~6 months |
| NDSS BAR / SOUPS | Workshop | Threat-model + defense | ~6 months |
| IEEE SaTML | Conference | Trustworthy ML | ~9 months |
| AI Safety venues (NeurIPS / SafeAI) | Workshop | Less security-y | ~6-9 months |

Recommended sequence: arxiv pre-print this month → submit to
WOOT or SaTML when CFP opens → talk circuit (DEF CON AI Village,
DerbyCon) for visibility.
