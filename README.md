# purple-scaffold

A minimal, runnable scaffold for an iterative purple-team harness. Five
specialist agents under a deterministic orchestrator, ATT&CK / ATLAS aware,
producing per-technique test cards as the durable artifact.

This is a **scaffold**: contracts and state are real, agents are stubs that
return deterministic results so the demo runs end-to-end. Replace each stub
with an LLM- or tool-driven implementation as you go.

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
verifies exfiltration succeeded (FAIL), enables the tool-call policy on
the live target, re-runs the probe, and confirms the gap is closed (PASS).

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
