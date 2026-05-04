# purple-scaffold

[![tests](https://github.com/euanmcrosson-dotcom/purple-scaffold/actions/workflows/test.yml/badge.svg)](https://github.com/euanmcrosson-dotcom/purple-scaffold/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)

A minimal, runnable scaffold for an iterative purple-team harness. Five
specialist agents under a deterministic orchestrator, ATT&CK / ATLAS aware,
producing per-technique test cards as the durable artifact.

This is a **scaffold**: contracts and state are real, agents are stubs that
return deterministic results so the demo runs end-to-end. Replace each stub
with an LLM- or tool-driven implementation as you go.

## Findings produced with this harness

Real defensive-research artifacts produced by running this scaffold + the
custom probes in `custom_probes/` against frontier models. Each is a
reproducible card in `findings/`.

| Date | Class | Models affected | Repo |
|------|-------|-----------------|------|
| 2026-04-28 | EchoLeak-style indirect prompt injection in email-summarization | GPT-4o (66.67% silent compliance), GPT-4o-mini (50.00%) — Anthropic models 0% | [findings/2026-04-28-echoleak-style-injection-openai.md](findings/2026-04-28-echoleak-style-injection-openai.md) |
| 2026-04-28 | MCP tool-description prompt injection (cross-tool confused deputy) | GPT-4o, GPT-4o-mini comply with SSH-key exfil plan; Anthropic refuses | [findings/2026-04-28-mcp-tool-description-poisoning-openai.md](findings/2026-04-28-mcp-tool-description-poisoning-openai.md) |
| 2026-05-04 | Indirect prompt injection via filesystem content read by `@modelcontextprotocol/server-filesystem`-using agents | **Gemini 2.5 Flash 75%, Grok 4.1 Fast Reasoning 75%** silent compliance on all 3 disguise variants (incl. SSH-key + `.env` reads); Haiku 4.5 25% (slips on HTML-comment disguise only); Opus 4.7 0% | [findings/2026-05-04-server-filesystem-indirect-injection.md](findings/2026-05-04-server-filesystem-indirect-injection.md) |

To run the server-filesystem probe sweep against the 4-model panel:

```powershell
# Set ANTHROPIC_API_KEY and OPENAI_API_KEY first.
.\scripts\run_custom_sweep.ps1
```

Single-probe single-model:

```bash
python scripts/run_custom_probes.py mcp_filesystem openai/gpt-4o
```

The probe (`custom_probes/mcp_filesystem.py`) uses
`server-filesystem`'s actual exposed tool surface (`read_text_file`,
`read_multiple_files`, `write_file`, `directory_tree`,
`search_files`, etc.) and three indirect-injection scenarios + one
control. The threat model and mitigations are documented in the draft
finding above.

## Upstream tooling contribution

Empirical measurement showed three of [garak](https://github.com/NVIDIA/garak)'s
default detectors produce 86–100% false-positive rates against safety-trained
2026-era frontier models. Issue + ready-to-file PR (4 detector patches + 46
unit tests) drafted in [`upstream/`](upstream/garak-detector-fp-issue.md) and
[`garak_pr/`](garak_pr/PR_DESCRIPTION.md). The fix introduces an opt-in
`refusal_filter` flag using a new `RefusalLanguageClassifier` post-filter,
fully backward-compatible.

## Architecture (one screen)

```
   Scout ─► Attacker ─► Analyst ─► Engineer (only on gap)
                          │             │
                          └─► Scribe ◄──┘
                                │
                        per-technique card
                        (markdown, run history)
```

Five agents:

| Agent     | Job                                                        |
|-----------|------------------------------------------------------------|
| Scout     | Pick technique, write hypothesis                           |
| Attacker  | Run the atomic against an isolated target                  |
| Analyst   | Pull telemetry, decide PASS / PARTIAL / FAIL / INCONCLUSIVE|
| Engineer  | When there's a gap, propose a detection rule (PR, not prod)|
| Scribe    | Update the per-technique card and coverage heatmap         |

The orchestrator is **deterministic code**, not an LLM. State transitions
are bounded and auditable.

## Quickstart

```bash
pip install -e .

# All-stub: ATT&CK campaign (encoded PowerShell, T1059.001)
python -m examples.demo

# All-stub: ATLAS campaign (indirect prompt injection, AML.T0051)
python -m examples.demo_atlas

# LIVE: real HTTP probe of a running vulnerable agent (no API key needed)
# Terminal 1:
python lab/vulnerable_agent.py
# Terminal 2:
python -m examples.demo_atlas_live
```

The all-stub demos drive one technique through the full loop entirely
in-process. The live demo actually starts a separate vulnerable-agent
process, sends a real HTTP probe with an indirect prompt injection,
verifies exfiltration succeeded (FAIL), **synthesizes a tool-call
policy from the analysis gap, backtests it against a fixture corpus to
measure real FPR / TPR**, applies the synthesized policy to the live
target, re-runs the probe, and confirms the gap is closed (PASS).

Sample run record (real numbers from the LIVE demo):

```
Run [FAIL]: ... Gap: email.send to external address, no policy gate.
Run [PASS]: ... Action: Synthesized 1 rule(s) from gap pattern.
            Backtest: corpus=15 TP=3 FP=2 TN=7 FN=3
            FPR=0.2222 TPR=0.5000. Applied to live target.
            Sample failure: legit-fp-001 expected=allow actual=deny
            (Alice emails a new vendor — legitimate first-time
            recipient — FP risk).
```

The Engineer is no longer a stub: synthesis is in
[`purple/policy_synthesis.py`](purple/policy_synthesis.py), the
deterministic backtest is in
[`purple/policy_backtest.py`](purple/policy_backtest.py), and the
policy data model + evaluator is in
[`purple/policy.py`](purple/policy.py). The orchestrator's auto-merge
guard correctly denies merge at FPR=22% (above the 1% threshold) and
records the human-gate reason on the audit log.

Output (per demo):
- `runs/<campaign_id>/audit.jsonl` — every envelope + state transition
- `examples/cards/<TECHNIQUE>.md` — the iterative test card

## Live lab target — `lab/vulnerable_agent.py`

A deterministic, self-contained vulnerable AI-agent simulator with three
tools (`read_ticket`, `search_users`, `send_email`) and a known indirect
prompt injection in ticket `T-1002`. Defenses (input classifier, output
classifier, tool-call policy) are togglable via `POST /defenses`. Use
this as your local probing target while developing — no API key, no
external services.

See `CHECKLIST.md` for the complete 30-day plan from this scaffold to
real-world findings + bug-bounty submissions.

## Two flavors, one harness

| Aspect              | ATT&CK demo (`demo.py`)               | ATLAS demo (`demo_atlas.py`)                       |
|---------------------|----------------------------------------|----------------------------------------------------|
| Technique space     | Endpoint / network                     | AI agent / model                                   |
| Atomic source       | atomic-red-team / Caldera              | garak / PyRIT / custom prompt payloads             |
| Telemetry sources   | Sysmon, EDR, SIEM events               | Model API logs, tool-call traces, classifier scores|
| Detection format    | Sigma / KQL / SPL                      | Tool-call policy, prompt firewall, output classifier|
| Engineering output  | SIEM rule PR                           | Agent policy PR                                    |
| Card format         | Same iterative markdown                | Same iterative markdown                            |

Contracts, envelope, state machine, orchestrator, and Scout/Scribe agents
are shared. Only Attacker, Analyst, and Engineer differ between flavors —
see `purple/agents.py` vs. `purple/agents_atlas.py`.

## File layout

```
purple-scaffold/
├── purple/
│   ├── envelope.py        # Common message envelope
│   ├── contracts.py       # Pydantic models (the schema)
│   ├── state_machine.py   # State enum + transition table
│   ├── agents.py          # ATT&CK-flavored stubs (5 agents)
│   ├── agents_atlas.py    # ATLAS-flavored Attacker / Analyst / Engineer
│   ├── orchestrator.py    # The deterministic loop
│   └── audit_log.py       # JSONL append-only log
├── examples/
│   ├── demo.py            # ATT&CK end-to-end (T1059.001)
│   ├── demo_atlas.py      # ATLAS end-to-end (AML.T0051)
│   └── cards/             # Generated test cards (one per technique)
└── tests/
    └── test_state_machine.py
```

## Where to plug in real implementations

ATT&CK flavor (`agents.py`):

| Replace | With | Notes |
|---|---|---|
| `ScoutAgent.handle` | LLM picking next technique from a coverage map | Inputs: heatmap + threat-intel feed |
| `AttackerAgent.handle` | Subprocess to Atomic Red Team / Caldera | Sandbox: separate VM |
| `AnalystAgent.handle` | SIEM/EDR API client + LLM comparing hypothesis vs. telemetry | Most reasoning lives here |
| `EngineerAgent.handle` | LLM that drafts a Sigma rule + backtest harness + GitHub PR | Always PR, never direct to prod |
| `ScribeAgent.handle` | Already real — writes markdown | Add commit + heatmap render |

ATLAS flavor (`agents_atlas.py`):

| Replace | With | Notes |
|---|---|---|
| `ATLASAttackerAgent.handle` | garak / PyRIT / custom prompt probe | Run with a *separate* model API key in a network-segmented sandbox |
| `ATLASAnalystAgent.handle` | Model API log query + tool-call trace inspection + LLM judge | Decide if the agent leaked / made unauthorized tool calls |
| `ATLASEngineerAgent.handle` | LLM drafts tool-call policy / prompt firewall / output classifier | Backtest against legitimate agent traces; PR with FPR threshold gate |

## Sandbox warning

`AttackerAgent` is the highest-blast-radius component. When you replace
the stub with a real executor:

- Run in a network-segmented VM/container, never the host.
- Use a *separate* model API key with no access to the rest of the fleet.
- Treat the target as fully untrusted — return values can prompt-inject
  the agent. Sanitize at the orchestrator boundary, not inside the agent.

## License

MIT. Build on it.
