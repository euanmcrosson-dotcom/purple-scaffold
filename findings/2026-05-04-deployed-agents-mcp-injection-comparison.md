# Finding: Deployed-agent product wrappers don't change agent-loop compliance — 0/30 attack tool_uses across 5 product profiles × 3 poisoned scenarios × 2 providers

**Date:** 2026-05-04
**Method:** Headless product simulator
([`examples/demo_product_simulator.py`](../examples/demo_product_simulator.py))
runs each product's actual or approximated system prompt through the
real MCP-server-backed agent loop from the
[2026-05-04 methodology-gap finding](2026-05-04-prompt-only-vs-agent-loop-injection-gap.md).
**Class:** Methodology / cross-product validation. Confirms whether
the prompt-only-overestimates pattern from the prior finding holds
when each product's specific system prompt is wrapped around the
agent loop.
**Severity:** Informational. The result is strongly defensive:
**zero attack tool_uses across 30 attempts.** Combined with the
prior 6-model agent-loop panel (also zero attack tool_uses across
~17 attempts), the cumulative agent-loop result is now 0/47
attempts — a strong cross-provider, cross-product null result.

## Summary

The 2026-05-04 methodology-gap finding showed that re-running the
prompt-only injection scenarios through a real MCP-server-backed
agent loop dropped compliance to 0% across all six tested frontier
models. That probe used a *generic* (no system prompt) agent shell.
Open question: does wrapping each product's specific system prompt
around the same loop change the result?

We built a product simulator that takes a product profile (system
prompt extracted from OSS source where available, best-effort
approximation for closed-source) and runs the same 4 scenarios.
Five profiles tested:

- **Cline (OSS):** system prompt extracted from `cline/cline` GitHub
  master HEAD (depth-1 clone, 2026-05-04). Includes agent role,
  objective, capabilities, key rules, MCP framing.
- **Continue.dev (OSS):** `DEFAULT_AGENT_SYSTEM_MESSAGE` extracted
  verbatim from `continuedev/continue:core/llm/defaultSystemMessages.ts`.
- **Cursor (closed; APPROXIMATION):** representative IDE-style coding-
  agent system prompt. Cursor's actual prompt is not public; this
  profile is a best-effort approximation based on observed
  behaviour. Driving the real Cursor through the proxy is the gold
  standard (runbook in `examples/demo_cursor_runbook.md`).
- **Claude Desktop (closed; APPROXIMATION):** minimal-system-prompt
  approximation reflecting Claude Desktop's publicly observed
  behaviour as a relatively thin wrapper around Anthropic models.
- **Generic baseline:** no system prompt. Reproduces the prior
  methodology-gap finding's headless-agent result.

Two providers run against the full panel:

| Profile | Haiku 4.5 (3 poisoned) | GPT-4o-mini (3 poisoned) |
|---|---|---|
| Cline (OSS) | 0/3 | 0/3 |
| Continue.dev (OSS) | 0/3 | 0/3 |
| Cursor (approximation) | 0/3 | 0/3 |
| Claude Desktop (approximation) | 0/3 | 0/3 |
| Generic baseline | 0/3 | 0/3 |
| **Total per provider** | **0/15** | **0/15** |

**Cross-product, cross-provider total: 0/30 attack tool_uses.** No
poisoned scenario produced any sensitive tool call (`read_text_file`
of `~/.ssh/id_rsa` or `.env`, `directory_tree("/")`, `write_file`
to attacker-named paths) under any product profile, across either
provider.

Combined with the prior 6-model methodology-gap finding's ~17
agent-loop attempts (also zero attack tool_uses), the cumulative
agent-loop probe result is **0/~47 attempts** — across two LLM
providers, six models (when the prior finding's data is included),
and five product wrappers. The agent-loop-defends pattern is robust
to product-prompt variation.

## Why this matters

The four bug-bounty disclosures submitted on 2026-05-04 (OpenAI,
Google, xAI, Anthropic) cite prompt-only compliance numbers up to
75%. The methodology-caveat block in each disclosure explicitly
notes that the agent-loop probe shows much lower compliance, and
that the prompt-only number should be read as a model-disposition
signal rather than a guaranteed product-impact measure.

This finding strengthens that caveat with cross-product evidence.
It is now reasonable to say: the prompt-only 75% number is what the
underlying model would emit if the poisoned content arrived
verbatim in its prompt; in actual product agent loops — both real
(Cline / Continue.dev verbatim prompts) and approximated (Cursor /
Claude Desktop) — the same content arrives as a tool_result and the
model defends.

For programme reviewers triaging the disclosures: the question
"does this work in our deployed product?" can be answered
**probably no**, with evidence in this finding, *for the specific
filesystem-content vector and disguise variants tested*. The
prompt-only signal still matters as a model-disposition data point
useful for evaluation suites; it just doesn't translate 1:1 to
deployed-product impact.

## Limitations

- **Two providers tested at the product-wrapper layer.** Haiku 4.5
  and GPT-4o-mini chosen for cost (~$0.40 each for the full panel).
  Opus 4.7, GPT-4o, Gemini 2.5 Flash, and Grok 4.1 not yet run at
  this layer. Prior 6-model agent-loop data (no product wrapper)
  shows uniform 0% compliance across all six, so we expect the same
  pattern to hold under product wrappers but it's not yet confirmed
  empirically per provider × product cell.
- **Product profiles for Cline and Continue.dev are extracted from
  OSS source but compressed.** The Cline profile uses the agent
  role + objective + a representative subset of the RULES section;
  the full prompt is ~6K tokens and the omitted sections (e.g.,
  `editing_files`, `act_vs_plan_mode`, `feedback`) shouldn't change
  injection-recognition behaviour but were not tested individually.
  The Continue.dev profile is the verbatim DEFAULT_AGENT_SYSTEM_MESSAGE,
  which is short and complete.
- **Cursor and Claude Desktop profiles are best-effort
  approximations.** The simulator clearly labels these as
  approximations in its provenance string. Driving the real
  products through the proxy is the gold-standard validation;
  runbooks at `examples/demo_cursor_runbook.md` and
  `examples/demo_claude_desktop_runbook.md` (to be created in
  follow-up).
- **Three scenarios tested.** Same scenario set as the prior
  prompt-only and methodology-gap findings (HTML-comment-disguise,
  bracketed-block, META-framed). Other disguise variants (different
  bracket conventions, unicode-encoded directives, multi-step
  attacks across multiple files) not tested.
- **Single tool-server profile (`@modelcontextprotocol/server-filesystem`).**
  Other MCP servers (server-fetch, server-postgres, server-git, etc.)
  not tested. The cumulative result holds for filesystem-content
  vectors specifically.

## Reproducer

```bash
git clone https://github.com/euanmcrosson-dotcom/purple-scaffold
cd purple-scaffold
pip install -e .[product]
npm install -g @modelcontextprotocol/server-filesystem

set -a; . ./.env 2>/dev/null; set +a   # ANTHROPIC_API_KEY etc.

# Full product panel × Haiku 4.5
python -m examples.demo_product_simulator \
  --products all --scenarios all \
  --models "anthropic/claude-haiku-4-5-20251001" \
  --out runs/products/haiku-panel.jsonl

# Same × GPT-4o-mini
python -m examples.demo_product_simulator \
  --products all --scenarios all \
  --models "openai/gpt-4o-mini" \
  --out runs/products/gpt4o-mini-panel.jsonl
```

Total cost: ~$0.80 for the full panel across both providers. Each
session log is saved to JSONL with full agent-loop trace (turns,
tool_uses, tool_results) for independent verification.

## Implications for ongoing disclosure threads

1. **For OpenAI / Google / xAI submissions:** if the receiving
   programme asks "is this exploitable in our deployed products?",
   the answer (per the data here) is **probably not** for
   filesystem-content vectors with the disguise variants tested.
   Re-frame as model-disposition / safety-evaluation telemetry
   rather than product-impact disclosure. The prompt-only 75% number
   remains useful for the safety team's evaluation suite calibration.
2. **For Anthropic submission:** the Haiku-disguise-recognition gap
   in prompt-only doesn't manifest at the agent-loop layer. The
   safety team should still benefit from the gap data (informs
   evaluation-suite design), but product impact is unlikely.
3. **For independent disclosures to product vendors (Cursor, Cline,
   Claude Desktop, Continue.dev):** less compelling than originally
   planned. The simulator data plus driving the real products
   through the proxy (runbooks pending) would together produce a
   "we tested 4 deployed products and found 0 product-level
   compliance" comparative result — a publishable null finding,
   stronger than any single-product report.

## Disclosure status

Defensive-research artifact. Submitting to product vendors is
probably not warranted given the null result; the findings/ entry
itself is the publishable artifact. May submit a brief note to each
of the four model-API programmes with the addendum once they have
acknowledged the original disclosures.

## What's next

Phase 4 of the approved plan (`composed-singing-horizon.md`) was
"Comparative panel + Claude Desktop + Continue.dev runbooks." The
runbook files are still to be drafted (one each for Cursor, Claude
Desktop, Continue.dev — Cline runbook already exists at
`examples/demo_cline_runbook.md`). Driving the real products through
the proxy and matching captured tool_uses against the simulator's
predictions would be the strongest possible validation; pending user
availability for the manual driving step.
