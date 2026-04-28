"""End-to-end demo: one technique through the full loop.

Run from the repo root:
    python -m examples.demo

Produces:
    runs/<campaign_id>/audit.jsonl   — every envelope + transition
    examples/cards/T1059.001.md      — the iterative test card
"""

from pathlib import Path
from uuid import uuid4

from purple import contracts as c
from purple.agents import (
    AnalystAgent,
    AttackerAgent,
    EngineerAgent,
    ScoutAgent,
    ScribeAgent,
)
from purple.orchestrator import CampaignConfig, Orchestrator


def main() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    runs_dir = repo_root / "runs"
    cards_dir = repo_root / "examples" / "cards"

    plan = c.TechniquePlan(
        technique_id="T1059.001",
        framework="ATTACK",
        rationale=(
            "Encoded PowerShell is one of the most common LOLBin techniques "
            "in real intrusions. Verifying detection coverage is high-value."
        ),
        hypothesis=(
            "Encoded PowerShell (-enc) execution should generate Sysmon EID 1 "
            "with CommandLine containing '-enc' AND PowerShell ScriptBlock "
            "EID 4104, triggering rule PS-Encoded-Execution-001."
        ),
        expected_telemetry=[
            c.TelemetrySource(source="sysmon", expected_event_id="1"),
            c.TelemetrySource(source="powershell-4104", expected_event_id="4104"),
        ],
        priority="p1",
        budget_seconds=600,
    )

    config = CampaignConfig(
        campaign_id=uuid4().hex[:8],
        runs_dir=runs_dir,
        cards_dir=cards_dir,
        max_retests_per_technique=1,
    )

    orchestrator = Orchestrator(
        config=config,
        scout=ScoutAgent(queue=[plan]),
        attacker=AttackerAgent(),
        analyst=AnalystAgent(),
        engineer=EngineerAgent(),
        scribe=ScribeAgent(cards_dir=cards_dir),
    )

    orchestrator.run()

    print(f"Campaign:  {config.campaign_id}")
    print(f"Final:     {orchestrator.state.value}")
    print(f"Audit log: {runs_dir / config.campaign_id / 'audit.jsonl'}")
    print(f"Card:      {cards_dir / (plan.technique_id + '.md')}")


if __name__ == "__main__":
    main()
