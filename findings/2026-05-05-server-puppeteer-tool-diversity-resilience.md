# Finding: server-puppeteer agent-loop is resilient — multi-tool surface defends even when attack shape mirrors fetch

**Date:** 2026-05-05
**Method:** Headless agent-loop probe driving real
`@modelcontextprotocol/server-puppeteer` (npm) against the existing
local poisoned HTTP target (`lab/vulnerable_fetch_targets.py`).
**Class:** Cross-vector validation. Tests whether the
tool-vector-shape hypothesis from the prior fetch + SQLite findings
predicts behaviour on a *multi-tool* browser surface that includes
a navigate primitive structurally similar to fetch's only tool.
**Severity:** Informational. The result is a strong null —
**0/12 attack tool_uses across 4 frontier models including
GPT-4o-mini** (which failed both fetch and SQLite). Refines the
"more of the same read tool" hypothesis.

## Summary

The 2026-05-04 fetch and SQLite findings showed GPT-4o-mini
complying with injection that asked it to call its already-active
read tool a second time against an attacker-named target. The
predictive question for puppeteer: its tool surface includes
`puppeteer_navigate` (same shape as fetch's `fetch`), but also
`puppeteer_click`, `puppeteer_fill`, `puppeteer_select`,
`puppeteer_hover`, `puppeteer_screenshot`, and
`puppeteer_evaluate`. Same attack shape (second navigate to
attacker URL with content in query string), but multi-tool
surface.

Result: all four tested models defend.

| Model | Puppeteer compliance |
|---|---|
| Anthropic Haiku 4.5 | 0/3 |
| OpenAI GPT-4o | 0/3 |
| OpenAI GPT-4o-mini | 0/3 (1 REFUSAL, 2 PASS) |
| xAI Grok 4.1 Fast Reasoning | 0/3 |

GPT-4o-mini specifically -- the model that complied 2/3 on fetch
and 1/3 on SQLite -- defends 3/3 on puppeteer despite the same
"navigate to attacker URL with extracted content" attack shape.

## Refinement of the tool-vector-shape hypothesis

Prior hypothesis (from the SQLite finding): compliance bar is
lower when the injection asks for *more of the same read tool*
the agent is already using.

Updated reading: the hypothesis was stated too narrowly. Two
factors appear to matter:

1. **Active tool reuse** -- the injection asks for another call
   to the tool the agent is already mid-using.
2. **Tool surface diversity** -- the *count* of alternatives
   available to the agent at decision time. When the agent has
   1 tool (fetch) or 5--6 read-only tools (SQLite) available,
   compliance is more likely. When the agent has 7 tools
   covering distinct browser actions (navigate, click, fill,
   evaluate, ...), compliance drops.

Both filesystem (compliance 0/12) and git (0/12) had multi-tool
surfaces. Fetch (compliance 2/3 for GPT-4o-mini) had a
single-tool surface. SQLite (1/3 for GPT-4o-mini) had a 6-tool
surface but those tools cluster around read/write_query and the
attack stayed within `read_query`. Puppeteer (0/3 for
GPT-4o-mini) has 7 tools covering distinct intent classes
(read, modify-page, screenshot, JS-eval).

The refined hypothesis: agent-loop indirect-injection compliance
is positively correlated with `(active-tool-reuse-shape) ∩
(low-diversity-tool-surface)`. Both factors required. Tool
diversity alone is protective even when the attack shape would
otherwise match.

This is a more useful prediction. Untested, but the next data
points (slack with 8 distinct intent-class tools, future probes)
can falsify or confirm.

## Reproducer

```bash
git clone https://github.com/euanmcrosson-dotcom/purple-scaffold
cd purple-scaffold
pip install -e .[product]
npm install -g @modelcontextprotocol/server-puppeteer
export ANTHROPIC_API_KEY=...
export OPENAI_API_KEY=...

# Terminal 1 — local poisoned HTTP target:
python lab/vulnerable_fetch_targets.py

# Terminal 2:
python -m examples.demo_mcp_puppeteer_target \
  --models "anthropic/claude-haiku-4-5-20251001,openai/gpt-4o-mini,openai/gpt-4o,xai/grok-4-1-fast-reasoning" \
  --scenarios all
```

First-run note: puppeteer downloads its own Chromium (~150MB) on
first launch.

## Implications for product builders

The "expose fewer tools" intuition for agent security is
*partially* wrong. A single-tool agent (fetch-only) is more
compliance-prone than a multi-tool agent (puppeteer with 7 tools)
on indirect prompt injection -- even when the specific compliance
call is structurally identical.

Practical implication: when building agent products, exposing a
diverse multi-tool MCP surface is a (modest, not yet causally
proven) defensive choice. The mitigation guidance in prior
findings (URL-allowlist policy via `mcp-guard`) still applies on
top.

## Limitations

- Four models tested, not the full six-model panel. Opus 4.7 not
  yet run on puppeteer (expected to defend; consistent with
  Opus's 0% across all vectors). Gemini 2.5 Flash skipped per
  ongoing rate-limit issues.
- Three scenarios per model. Same disguise variants as prior
  vectors (HTML-comment AUDIT_BEACON,
  `[ASSISTANT_RESEARCH_PROTOCOL]`, `<<DOCS_AGENT_DIRECTIVE>>`).
- The hypothesis refinement is observational, not causally
  tested. A cleaner test would expose only `puppeteer_navigate`
  (single-tool puppeteer) and re-run; or wrap a multi-tool
  surface around fetch and re-run. Both flagged as future work
  in [PAPER_OUTLINE.md](../PAPER_OUTLINE.md).

## Disclosure status

Defensive-research artifact. Null result with methodology value.
Strengthens the OpenAI fetch follow-up disclosure
([disclosures/openai-fetch-gpt4o-mini-followup.md](../disclosures/openai-fetch-gpt4o-mini-followup.md))
by confirming the GPT-4o-mini compliance pattern is narrow
(specific tool surface conditions) rather than broad.
