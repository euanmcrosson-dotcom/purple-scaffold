"""Guard stress demo — trigger each transition guard's deny path.

The standard demos (`demo.py`, `demo_atlas.py`) exercise the happy
path. This one runs four mini-campaigns, each with a misbehaving
agent stub that forces exactly one guard to fire its deny path:

  Scenario A   Attacker always returns exec_error with a rotating
                set of root-cause kinds. Three distinct kinds →
                attack_executing_to_escalate fires. Campaign should
                end in `escalated`, not `campaign_complete`.

  Scenario B   Analyst always returns INCONCLUSIVE. The first time
                triggers a retry; the second time the
                inconclusive_to_retry guard escalates.

  Scenario C   Engineer returns FPR 0.05 (above the 0.01 auto-merge
                threshold). pr_open_to_deployed denies with
                deny_human_gate. The demo treats human_gate as
                auto-deploy so the campaign completes; the audit log
                records the gate reason.

  Scenario D   Analyst always returns FAIL (no PASS ever). After 3
                re-test cycles, retest_to_escalate fires.

Run from the repo root:
    python -m examples.demo_guard_stress
"""

from __future__ import annotations

import json
import sys
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


# ─── Misbehaving agent stubs ───────────────────────────────────────


class RotatingErrorAttacker(AttackerAgent):
    """Returns exec_error on every call, rotating through a list of
    distinct root-cause kinds. Forces attack_executing_to_escalate to
    accumulate distinct kinds and eventually escalate."""

    name = "attacker"

    def __init__(self) -> None:
        self.kinds = ["network_unreachable", "auth_failed", "subprocess_killed"]
        self.i = 0

    def handle(self, payload: c.TestRequest) -> c.AttackResult:
        kind = self.kinds[self.i % len(self.kinds)]
        self.i += 1
        return c.AttackResult(
            status="exec_error",
            started_at="2026-04-28T00:00:00Z",
            ended_at="2026-04-28T00:00:01Z",
            exit_code=1,
            artifacts=[],
            observed_indicators=[],
            error=c.AttackError(kind=kind, detail=f"forced {kind} for stress demo"),
        )


class AlwaysInconclusiveAnalyst(AnalystAgent):
    """Returns INCONCLUSIVE on every call. inconclusive_to_retry
    allows one retry then escalates on the second."""

    name = "analyst"

    def handle(self, payload: c.AnalysisRequest) -> c.AnalysisResult:
        return c.AnalysisResult(
            verdict="inconclusive",
            telemetry_seen=[],
            detections_fired=[],
            mttd_seconds=None,
            mttr_seconds=None,
            gap=None,
            evidence=[],
        )


class HighFprEngineer(EngineerAgent):
    """Returns a patch with FPR 0.05 — well above the 0.01 auto-merge
    threshold. Forces pr_open_to_deployed to deny_human_gate."""

    name = "engineer"

    def handle(self, payload: c.DetectionTask) -> c.DetectionPatch:
        return c.DetectionPatch(
            status="pr_opened",
            pr_url="https://github.com/example/detections/pull/9999",
            rule_diff="--- /dev/null\n+++ a/rule.yml\n+ stress-demo-rule",
            test_results=c.DetectionTestResults(
                matches_attack_sample=True,
                false_positive_rate=0.05,  # above the 0.01 auto-merge threshold
                backtest_corpus_size=10_000,
            ),
            auto_merge_eligible=False,
            reasoning="FPR 0.05 — exceeds auto-merge gate intentionally for stress demo",
        )


class AlwaysFailAnalyst(AnalystAgent):
    """Returns FAIL on every call. After 3 re-test cycles,
    retest_to_escalate fires."""

    name = "analyst"

    def handle(self, payload: c.AnalysisRequest) -> c.AnalysisResult:
        return c.AnalysisResult(
            verdict="fail",
            telemetry_seen=[
                c.TelemetryObservation(source="sysmon", observed=True, event_count=1)
            ],
            detections_fired=[],
            mttd_seconds=None,
            mttr_seconds=None,
            gap=c.GapDescription(
                kind="rule_too_narrow",
                detail="forced FAIL for stress demo — rule never matches",
                proposed_fix_summary="(no real fix — demo)",
            ),
            evidence=[],
        )


# ─── Single-technique Scout (one technique per scenario, then done) ─


class SingleTechniqueScout(ScoutAgent):
    name = "scout"

    def __init__(self, technique_id: str = "T1059.001") -> None:
        self._consumed = False
        self._technique_id = technique_id

    def handle(self, payload):
        if self._consumed:
            raise RuntimeError("queue empty")
        self._consumed = True
        return c.TechniquePlan(
            technique_id=self._technique_id,
            framework="ATTACK",
            rationale="guard stress demo",
            hypothesis="(stress demo — guards under test)",
            expected_telemetry=[c.TelemetrySource(source="sysmon")],
            priority="p1",
        )


# ─── Run-one-scenario helper ───────────────────────────────────────


def run_scenario(
    label: str,
    *,
    attacker: AttackerAgent | None = None,
    analyst: AnalystAgent | None = None,
    engineer: EngineerAgent | None = None,
) -> dict:
    """Run a single stress scenario and return summary stats."""

    campaign_id = uuid4().hex[:8]
    runs_dir = Path("runs")
    cards_dir = Path("examples/cards")
    config = CampaignConfig(
        campaign_id=campaign_id,
        runs_dir=runs_dir,
        cards_dir=cards_dir,
        max_retests_per_technique=5,  # don't let this be the limit
    )
    orch = Orchestrator(
        config=config,
        scout=SingleTechniqueScout(f"T9999.{label.replace(' ', '-')}"),
        attacker=attacker or AttackerAgent(),
        analyst=analyst or AnalystAgent(),
        engineer=engineer or EngineerAgent(),
        scribe=ScribeAgent(cards_dir=cards_dir),
    )
    orch.run()

    log_path = runs_dir / campaign_id / "audit.jsonl"
    guard_events = []
    for line in log_path.read_text().splitlines():
        rec = json.loads(line)
        if rec.get("kind") == "guard":
            guard_events.append(rec)

    return {
        "label": label,
        "campaign_id": campaign_id,
        "final_state": orch.state.value,
        "guard_events": guard_events,
        "log_path": str(log_path),
    }


# ─── Main ──────────────────────────────────────────────────────────


def main() -> int:
    scenarios = [
        ("A: rotating exec errors", {"attacker": RotatingErrorAttacker()}),
        ("B: always INCONCLUSIVE", {"analyst": AlwaysInconclusiveAnalyst()}),
        ("C: engineer high FPR", {"engineer": HighFprEngineer()}),
        ("D: always FAIL (retest budget exhaustion)", {"analyst": AlwaysFailAnalyst()}),
    ]

    print(f"{'Scenario':<55} {'Final state':<22} {'Guard events'}")
    print("-" * 115)

    failures = []
    for label, overrides in scenarios:
        result = run_scenario(label, **overrides)
        guard_summary = " | ".join(
            f"{g['name']}={g['outcome']}" for g in result["guard_events"]
        )
        print(
            f"{label:<55} {result['final_state']:<22} {guard_summary}"
        )
        # Sanity expectations per scenario:
        if label.startswith("A") and result["final_state"] != "escalated":
            failures.append(f"{label}: expected escalated, got {result['final_state']}")
        if label.startswith("B") and result["final_state"] != "escalated":
            failures.append(f"{label}: expected escalated, got {result['final_state']}")
        if label.startswith("C"):
            # Should complete but with a deny_human_gate guard event.
            if not any(
                g["outcome"] == "deny_human_gate" for g in result["guard_events"]
            ):
                failures.append(f"{label}: expected deny_human_gate, none seen")
        if label.startswith("D") and result["final_state"] != "escalated":
            failures.append(f"{label}: expected escalated, got {result['final_state']}")

    print()
    if failures:
        print("FAILURES:")
        for f in failures:
            print(f"  {f}")
        return 1

    print(
        "All four guards fired their deny paths as expected. "
        "Audit logs in runs/<campaign_id>/audit.jsonl preserve every decision."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
