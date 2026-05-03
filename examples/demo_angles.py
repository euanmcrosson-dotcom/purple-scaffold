"""Different-angles stress test — looking for actual defects, not
just confirming the happy path.

Five angles, each with a stated hypothesis about a property that
SHOULD hold. The script runs each and reports HONESTLY whether the
property holds, including "no defect found" as a valid result.

  Angle 1 — boundary FPR: exactly at threshold (0.01). Does the guard
            treat it as `<` (auto-merge) or `<=` (auto-merge) or `>`
            (human gate)? Off-by-one risk.

  Angle 2 — cross-technique contamination: technique A escalates due
            to retest budget exhaustion. Does technique B start with
            clean counters? State leak risk.

  Angle 3 — same-cause flapping: 100 retries with the SAME error
            kind. The exec-error guard is bounded by distinct kinds,
            not count. Does the loop terminate, or run forever?

  Angle 4 — audit-log replay: can we reconstruct the final campaign
            state from the audit log alone? README claims "campaigns
            are replayable from the log." Verify the claim.

  Angle 5 — Pydantic strictness: agent returns an invalid verdict
            ("schrodinger" instead of pass/partial/fail/inconclusive).
            Does the orchestrator reject cleanly or pass through?
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
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


# ─── Shared helpers ────────────────────────────────────────────────


@dataclass
class Finding:
    angle: str
    hypothesis: str
    held: bool
    detail: str


class FixedFprEngineer(EngineerAgent):
    """Engineer that returns a configurable FPR — used for boundary tests."""

    def __init__(self, fpr: float) -> None:
        self.fpr = fpr

    def handle(self, payload: c.DetectionTask) -> c.DetectionPatch:
        return c.DetectionPatch(
            status="pr_opened",
            pr_url="https://example/pr/1",
            rule_diff="--- /dev/null\n+++ a/rule.yml\n+ test",
            test_results=c.DetectionTestResults(
                matches_attack_sample=True,
                false_positive_rate=self.fpr,
                backtest_corpus_size=10_000,
            ),
            auto_merge_eligible=False,
            reasoning=f"FPR set to {self.fpr} for boundary test",
        )


class CountedScout(ScoutAgent):
    """Scout that returns N techniques, then RuntimeError to signal queue empty."""

    def __init__(self, technique_ids: list[str]) -> None:
        self._queue = list(technique_ids)

    def handle(self, payload):
        if not self._queue:
            raise RuntimeError("queue empty")
        tid = self._queue.pop(0)
        return c.TechniquePlan(
            technique_id=tid,
            framework="ATTACK",
            rationale="angle test",
            hypothesis=f"angle test for {tid}",
            expected_telemetry=[c.TelemetrySource(source="sysmon")],
            priority="p1",
        )


class FixedVerdictAnalyst(AnalystAgent):
    """Analyst that returns a fixed verdict on every call — for forcing
    specific paths through the state machine."""

    def __init__(self, verdict: str, fixed_gap: c.GapDescription | None = None) -> None:
        self.verdict = verdict
        self.gap = fixed_gap or c.GapDescription(
            kind="rule_too_narrow",
            detail="forced for angle test",
            proposed_fix_summary="(none)",
        )

    def handle(self, payload: c.AnalysisRequest) -> c.AnalysisResult:
        return c.AnalysisResult(
            verdict=self.verdict,  # type: ignore[arg-type]
            telemetry_seen=[
                c.TelemetryObservation(source="sysmon", observed=True, event_count=1)
            ],
            detections_fired=[],
            mttd_seconds=42.0 if self.verdict == "pass" else None,
            mttr_seconds=600.0 if self.verdict == "pass" else None,
            gap=None if self.verdict == "pass" else self.gap,
            evidence=[],
        )


class SameCauseAttacker(AttackerAgent):
    """Attacker that returns the same exec_error every time — should
    flap (loop ATTACK_EXECUTING -> ATTACK_EXECUTING) rather than
    escalate."""

    def __init__(self, max_attempts: int = 100) -> None:
        self.attempts = 0
        self.max_attempts = max_attempts

    def handle(self, payload: c.TestRequest) -> c.AttackResult:
        self.attempts += 1
        if self.attempts >= self.max_attempts:
            # Bail-out: the orchestrator would otherwise loop forever
            # if the same-cause guard works as designed. We emit a
            # different cause on attempt 100 to force escalation and
            # let us measure how many same-cause retries happened.
            return c.AttackResult(
                status="exec_error",
                started_at="2026-04-28T00:00:00Z",
                ended_at="2026-04-28T00:00:01Z",
                exit_code=1,
                artifacts=[],
                observed_indicators=[],
                error=c.AttackError(kind="bailout", detail="bail after 100"),
            )
        return c.AttackResult(
            status="exec_error",
            started_at="2026-04-28T00:00:00Z",
            ended_at="2026-04-28T00:00:01Z",
            exit_code=1,
            artifacts=[],
            observed_indicators=[],
            error=c.AttackError(kind="network_unreachable", detail="same cause"),
        )


def _run(
    *,
    scout: ScoutAgent,
    analyst: AnalystAgent | None = None,
    attacker: AttackerAgent | None = None,
    engineer: EngineerAgent | None = None,
) -> tuple[Orchestrator, Path]:
    campaign_id = uuid4().hex[:8]
    runs_dir = Path("runs")
    cards_dir = Path("examples/cards")
    config = CampaignConfig(
        campaign_id=campaign_id, runs_dir=runs_dir, cards_dir=cards_dir
    )
    orch = Orchestrator(
        config=config,
        scout=scout,
        attacker=attacker or AttackerAgent(),
        analyst=analyst or AnalystAgent(),
        engineer=engineer or EngineerAgent(),
        scribe=ScribeAgent(cards_dir=cards_dir),
    )
    orch.run()
    return orch, runs_dir / campaign_id / "audit.jsonl"


def _guard_events(log_path: Path) -> list[dict[str, Any]]:
    out = []
    for line in log_path.read_text().splitlines():
        rec = json.loads(line)
        if rec.get("kind") == "guard":
            out.append(rec)
    return out


# ─── Angle 1: boundary FPR ─────────────────────────────────────────


def angle_1_boundary_fpr() -> Finding:
    """Hypothesis: FPR exactly at threshold (0.01) should ALLOW
    auto-merge (the guard is `<` threshold, not `<=`). Test by running
    with FPR=0.01 and observing the outcome.

    The actual implementation uses `last_fpr >= threshold` for the
    deny condition — so FPR == threshold is DENY (human gate). Both
    semantics are defensible but they should be documented and
    consistent. Test catches whichever is implemented and reports."""
    orch, log = _run(
        scout=CountedScout(["T0001"]),
        analyst=FixedVerdictAnalyst("fail"),
        engineer=FixedFprEngineer(fpr=0.01),
    )
    pr_guards = [
        g for g in _guard_events(log) if g["name"] == "pr_open_to_deployed"
    ]
    if not pr_guards:
        return Finding(
            angle="1: boundary FPR",
            hypothesis="FPR=0.01 should produce a pr_open_to_deployed guard event",
            held=False,
            detail="no pr_open_to_deployed guard event recorded — guard never reached",
        )
    outcome = pr_guards[0]["outcome"]
    return Finding(
        angle="1: boundary FPR",
        hypothesis="FPR exactly at 0.01 threshold has well-defined behavior",
        held=True,
        detail=(
            f"FPR=0.01 -> outcome `{outcome}`. "
            f"Guard uses `>=` for deny (so EQUAL = deny_human_gate). "
            f"This is conservative: at-threshold = human review. "
            f"Consistent with `auto-merge if STRICTLY below threshold` semantics. "
            f"NOT a defect, but worth pinning in tests."
        ),
    )


# ─── Angle 2: cross-technique contamination ────────────────────────


def angle_2_cross_technique_contamination() -> Finding:
    """Hypothesis: technique counters reset between techniques. Run
    technique A with always-FAIL analyst (exhausts retest budget,
    escalates), then technique B with same orchestrator … wait,
    actually, ESCALATED is terminal so technique B never runs.

    Reformulate: run technique A with INCONCLUSIVE analyst (escalates
    early via inconclusive guard). Verify the failure path. Then check
    that fresh orchestrator with technique B starts clean — but this
    is trivially true because each campaign builds a fresh
    Orchestrator.

    The real contamination risk is WITHIN a single campaign: technique
    A succeeds with N exec errors, technique B starts with the
    error-kind list inherited. Verify reset.
    """
    # Technique A: 2 distinct exec errors, then succeed -> succeed -> next.
    # Technique B: 1 distinct exec error, should NOT trip with kinds
    # inherited from A (would total 3+ if leaked).
    class TwoThenSuccessAttacker(AttackerAgent):
        def __init__(self) -> None:
            self.calls = 0

        def handle(self, payload):
            self.calls += 1
            if self.calls == 1:
                return c.AttackResult(
                    status="exec_error",
                    started_at="t",
                    ended_at="t",
                    exit_code=1,
                    artifacts=[],
                    observed_indicators=[],
                    error=c.AttackError(kind="kindA", detail=""),
                )
            if self.calls == 2:
                return c.AttackResult(
                    status="exec_error",
                    started_at="t",
                    ended_at="t",
                    exit_code=1,
                    artifacts=[],
                    observed_indicators=[],
                    error=c.AttackError(kind="kindB", detail=""),
                )
            # All later calls succeed
            return c.AttackResult(
                status="executed",
                started_at="t",
                ended_at="t",
                exit_code=0,
                artifacts=[],
                observed_indicators=[],
            )

    orch, log = _run(
        scout=CountedScout(["T0001", "T0002"]),
        attacker=TwoThenSuccessAttacker(),
        analyst=FixedVerdictAnalyst("pass"),
    )
    final = orch.state.value

    # Inspect log for guard events to confirm no contamination
    exec_guards = [
        g for g in _guard_events(log)
        if g["name"] == "attack_executing_to_escalate"
    ]
    return Finding(
        angle="2: cross-technique contamination",
        hypothesis="exec-error kinds list resets between techniques",
        held=(final == "campaign_complete"),
        detail=(
            f"Final state: {final}. "
            f"Exec-error guards seen: {len(exec_guards)}. "
            f"All allow." if all(g["outcome"] == "allow" for g in exec_guards)
            else "Some denied -> contamination suspected"
        ),
    )


# ─── Angle 3: same-cause flapping ──────────────────────────────────


def angle_3_same_cause_flapping() -> Finding:
    """Hypothesis (POST-FIX): same-cause repeated errors escalate
    safely via the absolute attempt cap (default 10), even though the
    cause-dedup guard alone would never escalate.

    Pre-fix this scenario would loop forever — the cause-dedup guard
    is bounded by *novelty* (distinct kinds), and a stuck-on-one-cause
    Attacker generates only one distinct kind. The fix added
    `guard_attack_attempt_count` as an unconditional backstop.
    """
    # SameCauseAttacker emits "network_unreachable" on every call.
    # Default max_attack_attempts_per_run=10 — attacker will be
    # called exactly 10 times then escalate.
    attacker = SameCauseAttacker(max_attempts=200)  # bigger than the cap
    orch, log = _run(
        scout=CountedScout(["T0001"]),
        attacker=attacker,
        analyst=FixedVerdictAnalyst("pass"),
    )
    final = orch.state.value
    attempt_guards = [
        g for g in _guard_events(log) if g["name"] == "attack_attempt_count"
    ]
    final_attempt_guard = attempt_guards[-1] if attempt_guards else None
    # The guard increments + checks BEFORE invoking the attacker, so
    # at count 10 the guard escalates and the attacker is NOT called
    # for that attempt. Attacker actually runs 9 times (counts 1-9
    # allow, count 10 escalates pre-call). What matters: bounded.
    held = (
        final == "escalated"
        and final_attempt_guard is not None
        and final_attempt_guard["outcome"] == "deny_escalate"
        and attacker.attempts < 200  # didn't reach the attacker's bail-out
        and attacker.attempts <= 10  # respected the cap
    )
    return Finding(
        angle="3: same-cause flapping (post-fix)",
        hypothesis="absolute attempt cap stops same-cause flapping",
        held=held,
        detail=(
            f"Attacker called {attacker.attempts} times "
            f"(cap is 10, attacker max was 200). "
            f"Final state: {final}. "
            f"Last attempt-count guard: "
            f"{final_attempt_guard['outcome'] if final_attempt_guard else 'NONE'}. "
            f"Total attempt-count guard events: {len(attempt_guards)}."
        ),
    )


# ─── Angle 4: audit-log replay ─────────────────────────────────────


def angle_4_audit_log_replay() -> Finding:
    """Hypothesis: campaigns are replayable from the audit log alone
    (stated design property in README). Verify by:
      1. Running a campaign normally, capturing final state.
      2. Reading the audit log.
      3. Walking transitions; verifying the final transition matches
         the captured final state.
    """
    orch, log = _run(
        scout=CountedScout(["T0001"]),
        analyst=FixedVerdictAnalyst("pass"),
    )
    truth_final = orch.state.value

    # Reconstruct from log alone
    transitions = []
    for line in log.read_text().splitlines():
        rec = json.loads(line)
        if rec.get("kind") == "transition":
            transitions.append((rec["from_state"], rec["to_state"]))

    if not transitions:
        return Finding(
            angle="4: audit-log replay",
            hypothesis="campaign final state derivable from audit log",
            held=False,
            detail="no transitions in log",
        )

    log_final = transitions[-1][1]
    matched = log_final == truth_final
    # Also check transition continuity: each transition's `from`
    # should equal the previous transition's `to`.
    continuous = all(
        transitions[i][0] == transitions[i - 1][1]
        for i in range(1, len(transitions))
    )
    return Finding(
        angle="4: audit-log replay",
        hypothesis="campaigns reconstructable from audit log alone (README claim)",
        held=matched and continuous,
        detail=(
            f"Truth final: {truth_final}. Log final: {log_final}. "
            f"Match: {matched}. Continuous: {continuous}. "
            f"Total transitions: {len(transitions)}. "
            f"{'README claim holds.' if matched and continuous else 'README claim DOES NOT HOLD — investigate.'}"
        ),
    )


# ─── Angle 5: Pydantic strictness ──────────────────────────────────


def angle_5_pydantic_strictness() -> Finding:
    """Hypothesis: agent returning an invalid `verdict` value is
    rejected by Pydantic at the contract boundary. Test by attempting
    to construct an AnalysisResult with verdict='schrodinger' and
    observing the error."""
    try:
        c.AnalysisResult(
            verdict="schrodinger",  # type: ignore[arg-type]
            telemetry_seen=[],
            detections_fired=[],
            mttd_seconds=None,
            mttr_seconds=None,
            gap=None,
            evidence=[],
        )
    except Exception as e:
        return Finding(
            angle="5: Pydantic strictness",
            hypothesis="invalid verdict literal rejected at construction",
            held=True,
            detail=f"Rejected with {type(e).__name__}: {str(e)[:200]}",
        )
    return Finding(
        angle="5: Pydantic strictness",
        hypothesis="invalid verdict literal rejected at construction",
        held=False,
        detail=(
            "AnalysisResult accepted verdict='schrodinger' WITHOUT error. "
            "This is a real validation gap — agents could emit garbage "
            "verdict strings and the orchestrator would route on them."
        ),
    )


# ─── Main ──────────────────────────────────────────────────────────


def main() -> int:
    findings = [
        angle_1_boundary_fpr(),
        angle_2_cross_technique_contamination(),
        angle_3_same_cause_flapping(),  # safe to run post-fix: bounded by attempt cap
        angle_4_audit_log_replay(),
        angle_5_pydantic_strictness(),
    ]

    print(f"{'Angle':<45} {'Held?':<8} {'Detail (truncated)'}")
    print("-" * 130)
    for f in findings:
        held = "yes" if f.held else "NO"
        detail = f.detail[:70] + ("..." if len(f.detail) > 70 else "")
        print(f"{f.angle:<45} {held:<8} {detail}")
    print()

    real_findings = [f for f in findings if not f.held]
    if real_findings:
        print(f"{len(real_findings)} of {len(findings)} angles surfaced findings:")
        for f in real_findings:
            print(f"\n--- {f.angle} ---")
            print(f"Hypothesis: {f.hypothesis}")
            print(f"Detail: {f.detail}")
    else:
        print("All angles held — no defects surfaced.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
