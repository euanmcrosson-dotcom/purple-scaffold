# Contributing

Thanks for considering a contribution. This repo is research code
+ a small library; the bar for accepting changes is "would I want
this in my next paper / next disclosure submission?"

## Setup

```bash
git clone https://github.com/euanmcrosson-dotcom/purple-scaffold
cd purple-scaffold
pip install -e ".[dev,product]"
npm install -g @modelcontextprotocol/server-filesystem
pip install mcp-server-fetch mcp-server-git mcp-server-sqlite
pytest tests/ -q   # 34 tests should be green
```

## Adding a new MCP-server probe

To add a probe for a new MCP server (e.g., server-puppeteer,
server-slack):

1. **Build the lab fixture** under `lab/` — a script that produces
   the poisoned content the probe will read. See
   [`lab/poisoned_git_repo.py`](lab/poisoned_git_repo.py) and
   [`lab/poisoned_sqlite_db.py`](lab/poisoned_sqlite_db.py) for
   reference shapes.
2. **Build the probe driver** under `examples/`. Mirror the shape
   of [`examples/demo_mcp_git_target.py`](examples/demo_mcp_git_target.py)
   or [`examples/demo_mcp_sqlite_target.py`](examples/demo_mcp_sqlite_target.py)
   — keep the dataclass scenarios + tool-use-aware verdict
   pattern.
3. **Wire into the leaderboard generator** at
   [`scripts/generate_leaderboard.py`](scripts/generate_leaderboard.py)
   — add a `_load_all(("runs/<vector>/*.jsonl",))` call and a
   per-vector section.
4. **Wire into the nightly Action** at
   [`.github/workflows/nightly-panel.yml`](.github/workflows/nightly-panel.yml)
   — add a `Run <vector> probe` step.
5. **Write the finding** under `findings/` documenting per-model
   verdicts. Follow the structure of the existing per-vector
   findings.

## Adding a new product simulator profile

To add Cursor / Cline / etc. with a real-product driving runbook
or a simulator profile:

- For OSS products: extract the actual system prompt from source
  (clearly labelled with repo + commit SHA in the simulator's
  `provenance` string).
- For closed products: best-effort approximation, clearly labelled.
- Add to [`examples/demo_product_simulator.py`](examples/demo_product_simulator.py).
- Add a runbook for verbatim-product driving at
  `examples/demo_<product>_runbook.md`.

## Adding a new disguise variant

If you find a new injection disguise that frontier models comply
with, the cleanest contribution shape:

1. Add the variant to a scenario in `lab/poisoned_*.py`.
2. Add a corresponding attack-pattern matcher in the probe's
   `attack_tool_patterns` list.
3. Run the panel; if any model FAILs, write a finding and
   propose a `mcp-guard` policy update.

## Running tests

```bash
pytest tests/ -q
```

Tests cover the policy / synthesis / backtest pipeline. Probes are
not unit-tested (they require live API calls); they are validated
end-to-end via the demo scripts and the nightly Action.

## Style

- No comments unless they explain *why*, not what.
- Pure functions where reasonable; the policy evaluator is pure
  (no I/O), and that property is load-bearing for audit-loggability.
- Verdict logic should be tool-use-aware, not text-substring-
  based, when the agent loop has tool execution available. The
  filesystem probe's
  [history](findings/2026-05-04-prompt-only-vs-agent-loop-injection-gap.md)
  is the cautionary tale.

## Disclosure

If you produce a finding using this harness against a third-party
product / model, follow that party's published security policy.
The `disclosures/` directory contains drafted submission bodies
for the model-API providers; copy that structure for new
submissions.

Default disclosure window: 90 days.
