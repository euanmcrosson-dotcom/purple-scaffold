"""Five specialist agents.

Each `handle()` is a deterministic stub returning a realistic payload so the
demo runs end-to-end without external services. The seams marked
`# REPLACE` are where you plug in real implementations:

  - Scout    : LLM call against the coverage map + threat intel
  - Attacker : subprocess to Atomic Red Team / Caldera / garak / pyrit
  - Analyst  : SIEM/EDR query + LLM compare hypothesis vs. telemetry
  - Engineer : LLM-drafted Sigma rule + backtest + GitHub PR
  - Scribe   : already real (writes the markdown card)

Stubs use a `phase` counter on Attacker/Analyst so the demo can show a
FAIL-then-PASS cycle without wiring real telemetry.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel

from . import contracts as c
from .envelope import AgentName


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Agent(ABC):
    name: AgentName

    @abstractmethod
    def handle(self, payload: BaseModel) -> BaseModel:
        ...


# ─── Scout ─────────────────────────────────────────────────────────


class ScoutAgent(Agent):
    name: AgentName = "scout"

    def __init__(self, queue: list[c.TechniquePlan]) -> None:
        self._queue = list(queue)

    def handle(self, payload: BaseModel) -> c.TechniquePlan:
        # REPLACE: LLM call. Inputs: coverage heatmap + threat-intel feed.
        # Output: next TechniquePlan.
        if not self._queue:
            raise RuntimeError("Scout queue empty")
        return self._queue.pop(0)


# ─── Attacker ──────────────────────────────────────────────────────


class AttackerAgent(Agent):
    name: AgentName = "attacker"

    def handle(self, payload: BaseModel) -> c.AttackResult:
        # REPLACE: invoke Atomic Red Team / Caldera / garak in a sandbox.
        # The current stub fabricates a successful execution with realistic
        # indicators so the Analyst stub has something to analyze.
        assert isinstance(payload, c.TestRequest)
        started = _now()
        ended = _now()
        return c.AttackResult(
            status="executed",
            started_at=started,
            ended_at=ended,
            exit_code=0,
            artifacts=[
                c.Artifact(
                    kind="stdout",
                    uri=f"file://runs/stdout-{payload.atomic_ref.identifier}.log",
                    sha256="0" * 64,
                    bytes=1024,
                )
            ],
            observed_indicators=[
                "powershell.exe",
                "-EncodedCommand",
                "lab-host-01",
            ],
        )


# ─── Analyst ───────────────────────────────────────────────────────


class AnalystAgent(Agent):
    name: AgentName = "analyst"

    def __init__(self) -> None:
        # First call returns a gap (FAIL); subsequent calls return PASS.
        # Demonstrates the iterative loop without real telemetry.
        self._call_count = 0

    def handle(self, payload: BaseModel) -> c.AnalysisResult:
        # REPLACE: SIEM/EDR query against the attack window, then an LLM
        # that compares observed telemetry to the hypothesis.
        assert isinstance(payload, c.AnalysisRequest)
        self._call_count += 1

        if self._call_count == 1:
            return c.AnalysisResult(
                verdict="fail",
                telemetry_seen=[
                    c.TelemetryObservation(
                        source="sysmon", observed=True, event_count=3
                    ),
                    c.TelemetryObservation(
                        source="powershell-4104", observed=False, event_count=0
                    ),
                ],
                detections_fired=[],
                mttd_seconds=None,
                mttr_seconds=None,
                gap=c.GapDescription(
                    kind="telemetry_no_rule",
                    detail=(
                        "Sysmon EID 1 captured the encoded PowerShell, but "
                        "no detection rule fired. ScriptBlock logging (4104) "
                        "is disabled at the GPO level."
                    ),
                    proposed_fix_summary=(
                        "(1) Enable PowerShell ScriptBlock logging via GPO. "
                        "(2) Add fallback Sigma rule keyed on Sysmon EID 1 "
                        "CommandLine regex matching '-enc' / '-EncodedCommand'."
                    ),
                ),
            )

        return c.AnalysisResult(
            verdict="pass",
            telemetry_seen=[
                c.TelemetryObservation(
                    source="sysmon", observed=True, event_count=3
                ),
                c.TelemetryObservation(
                    source="powershell-4104", observed=True, event_count=1
                ),
            ],
            detections_fired=[
                c.DetectionFiring(
                    rule_id="PS-Encoded-Execution-001",
                    fired=True,
                    alert_count=1,
                    first_alert_at=_now(),
                ),
            ],
            mttd_seconds=42.0,
            mttr_seconds=660.0,
        )


# ─── Engineer ──────────────────────────────────────────────────────


class EngineerAgent(Agent):
    name: AgentName = "engineer"

    def handle(self, payload: BaseModel) -> c.DetectionPatch:
        # REPLACE: LLM drafts a Sigma rule from telemetry samples + gap;
        # backtest harness measures false-positive rate against a corpus;
        # GitHub PR is opened via the API.
        assert isinstance(payload, c.DetectionTask)
        return c.DetectionPatch(
            status="pr_opened",
            pr_url="https://github.com/example/detections/pull/42",
            rule_diff=(
                "+ - title: Encoded PowerShell via Sysmon CommandLine\n"
                "+   id: PS-Encoded-Execution-001\n"
                "+   detection:\n"
                "+     selection:\n"
                "+       EventID: 1\n"
                "+       CommandLine|contains:\n"
                "+         - '-enc'\n"
                "+         - '-EncodedCommand'\n"
                "+     condition: selection\n"
            ),
            test_results=c.DetectionTestResults(
                matches_attack_sample=True,
                false_positive_rate=0.002,
                backtest_corpus_size=50000,
            ),
            auto_merge_eligible=True,
            reasoning=(
                "Rule keyed on Sysmon EID 1 with '-enc' substring matches the "
                "atomic sample and produced 100 hits over a 50k-event corpus "
                "(0.2% FPR), under the 1% auto-merge threshold."
            ),
        )


# ─── Scribe ────────────────────────────────────────────────────────


class ScribeAgent(Agent):
    name: AgentName = "scribe"

    def __init__(self, cards_dir: Path) -> None:
        self.cards_dir = Path(cards_dir)
        self.cards_dir.mkdir(parents=True, exist_ok=True)

    def handle(self, payload: BaseModel) -> c.CardAck:
        assert isinstance(payload, c.CardUpdate)
        path = self.cards_dir / f"{payload.technique_id}.md"
        existing = path.read_text(encoding="utf-8") if path.exists() else None
        new_content = self._render_card(payload, existing)
        path.write_text(new_content, encoding="utf-8")
        return c.CardAck(card_uri=str(path), commit_sha=None, heatmap_updated=False)

    @staticmethod
    def _render_card(update: c.CardUpdate, existing: str | None) -> str:
        run = update.run_record
        run_block = (
            f"### Run {run.run_id} — {run.ran_at}  [{run.result}]\n"
            f"- Telemetry: {run.telemetry_summary}\n"
            f"- MTTD: {run.mttd_seconds if run.mttd_seconds is not None else 'N/A'}s\n"
            f"- MTTR: {run.mttr_seconds if run.mttr_seconds is not None else 'N/A'}s\n"
            f"- Gap: {run.gap_summary or 'None'}\n"
            f"- Action: {run.action_taken or '—'}\n\n"
        )

        if existing and "## Run history" in existing:
            return existing + run_block

        header = (
            f"# {update.technique_id}\n\n"
            f"**Hypothesis:** {update.hypothesis}\n\n"
            f"**Campaign:** `{update.campaign_id}`\n\n"
            "## Run history\n\n"
        )
        return header + run_block
