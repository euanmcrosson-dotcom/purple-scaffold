"""Deterministic orchestrator.

Drives the state machine, dispatches messages to agents, appends every
envelope to the audit log. The orchestrator is the only thing that mutates
state — agents are pure: payload in, payload out.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel

from . import contracts as c
from .agents import (
    AnalystAgent,
    AttackerAgent,
    EngineerAgent,
    ScoutAgent,
    ScribeAgent,
)
from .audit_log import AuditLog
from .envelope import AgentName, Envelope
from .guards import (
    GuardConfig,
    GuardContext,
    GuardResult,
    guard_attack_attempt_count,
    guard_attack_executing_to_escalate,
    guard_inconclusive_to_retry,
    guard_pr_open_to_deployed,
    guard_retest_to_escalate,
)
from .state_machine import State, is_terminal, transition


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class CampaignConfig:
    campaign_id: str
    runs_dir: Path
    cards_dir: Path
    max_retests_per_technique: int = 3
    # Guard thresholds — see purple/guards.py
    guard_config: GuardConfig | None = None
    # TELEMETRY_PENDING → ANALYZING configurable wait. Production
    # default is 180s for SIEM ingest; demo / tests default to 0.
    telemetry_wait_seconds: float = 0.0


class Orchestrator:
    def __init__(
        self,
        config: CampaignConfig,
        scout: ScoutAgent,
        attacker: AttackerAgent,
        analyst: AnalystAgent,
        engineer: EngineerAgent,
        scribe: ScribeAgent,
    ) -> None:
        self.config = config
        self.scout = scout
        self.attacker = attacker
        self.engineer = engineer
        self.analyst = analyst
        self.scribe = scribe
        self.audit = AuditLog(
            config.runs_dir / config.campaign_id / "audit.jsonl"
        )
        self.state = State.CAMPAIGN_INIT
        self.guard_config = config.guard_config or GuardConfig()
        # Per-technique guard counters; reset by _select_technique().
        self._exec_error_kinds: list[str] = []
        self._inconclusive_retries_used: int = 0
        self._retest_cycles_attempted: int = 0
        self._attack_attempts: int = 0
        self._human_gate_reason: str | None = None

    # ─── Public entry point ────────────────────────────────────────

    def run(self) -> None:
        self.audit.append_event("campaign_start", campaign_id=self.config.campaign_id)
        while not is_terminal(self.state):
            try:
                self._tick()
            except Exception as exc:  # noqa: BLE001 — surface and escalate
                self.audit.append_event(
                    "exception", state=self.state.value, error=repr(exc)
                )
                self._goto(State.ESCALATED)
        self.audit.append_event("campaign_end", final_state=self.state.value)

    # ─── State handlers ────────────────────────────────────────────

    def _tick(self) -> None:
        if self.state == State.CAMPAIGN_INIT:
            self._goto(State.TECHNIQUE_SELECTED)
            return

        if self.state == State.TECHNIQUE_SELECTED:
            self._select_technique()
            return

        if self.state == State.ATTACK_PLANNED:
            self._goto(State.ATTACK_EXECUTING)
            return

        if self.state == State.ATTACK_EXECUTING:
            self._execute_attack()
            return

        if self.state == State.TELEMETRY_PENDING:
            # Spec: TELEMETRY_PENDING → ANALYZING is gated on a
            # configurable wait (default 180s for SIEM ingest in
            # production; 0s in demo/tests).
            if self.config.telemetry_wait_seconds > 0:
                import time

                self.audit.append_event(
                    "telemetry_wait",
                    seconds=self.config.telemetry_wait_seconds,
                )
                time.sleep(self.config.telemetry_wait_seconds)
            self._goto(State.ANALYZING)
            return

        if self.state == State.ANALYZING:
            self._analyze()
            return

        if self.state == State.DETECTION_ENGINEERING:
            self._engineer()
            return

        if self.state == State.DETECTION_PR_OPEN:
            # Spec: DETECTION_PR_OPEN → DETECTION_DEPLOYED auto-merges
            # only if rule passes harness AND FPR backtest AND policy
            # allows. Otherwise the loop pauses for a human merge
            # signal — recorded as `human_gate` on the audit log.
            patch = getattr(self, "_last_patch", None)
            ctx = GuardContext(
                last_rule_matches_sample=(
                    patch.test_results.matches_attack_sample if patch else None
                ),
                last_fpr=(
                    patch.test_results.false_positive_rate if patch else None
                ),
                policy_allows_auto_merge=True,  # operator-policy override hook
            )
            result = guard_pr_open_to_deployed(ctx, self.guard_config)
            self._record_guard("pr_open_to_deployed", result)
            if result.outcome == "allow":
                self._goto(State.DETECTION_DEPLOYED)
            elif result.outcome == "deny_human_gate":
                # In production this state pauses the loop. The
                # demo/test path treats it as auto-deploy so the
                # campaign can complete; the audit log preserves the
                # gate reason.
                self._human_gate_reason = result.reason
                self._goto(State.DETECTION_DEPLOYED)
            else:
                self._goto(State.ESCALATED)
            return

        if self.state == State.DETECTION_DEPLOYED:
            # Card update next — record the FAIL run together with the
            # engineering action that resolved (or attempted to resolve) it.
            self._goto(State.CARD_UPDATING)
            return

        if self.state == State.RE_TEST:
            # Spec: RE_TEST → ESCALATE when 3 re-test cycles have
            # completed without reaching PASS. Distinct from
            # max_retests_per_technique, which is the budget that
            # consumes between attempts.
            self._retest_cycles_attempted += 1
            ctx = GuardContext(
                retest_cycles_attempted=self._retest_cycles_attempted,
            )
            result = guard_retest_to_escalate(ctx, self.guard_config)
            self._record_guard("retest_to_escalate", result)
            if not result.allowed:
                self._goto(State.ESCALATED)
                return
            self._retests_remaining -= 1
            # Fresh run id for the next attempt.
            self._current_run_id = uuid4().hex[:12]
            self._goto(State.ATTACK_EXECUTING)
            return

        if self.state == State.CARD_UPDATING:
            self._update_card()
            return

    # ─── Step implementations ──────────────────────────────────────

    def _select_technique(self) -> None:
        try:
            plan = self.scout.handle(payload=_Empty())
        except RuntimeError:
            # No more techniques in queue — campaign done.
            self._goto(State.CAMPAIGN_COMPLETE)
            return

        self._current_plan = plan
        self._current_run_id = uuid4().hex[:12]
        self._retests_remaining = self.config.max_retests_per_technique
        self._last_attack_started: str | None = None
        # Per-technique guard counters reset on technique selection so
        # one technique's failure pattern doesn't poison the next.
        self._exec_error_kinds = []
        self._inconclusive_retries_used = 0
        self._retest_cycles_attempted = 0
        self._attack_attempts = 0
        self._human_gate_reason = None

        self._send("scout", "orchestrator", plan)
        self._goto(State.ATTACK_PLANNED)

    def _execute_attack(self) -> None:
        # Guard #1 (absolute attempt cap): check BEFORE invoking the
        # attacker. The cause-dedup guard below catches *novelty* of
        # error kinds; this guard catches *repetition* — a stuck-on-
        # one-cause Attacker (DNS down, target offline, expired creds)
        # would otherwise loop the ATTACK_EXECUTING self-edge forever.
        # Surfaced by purple-scaffold Angle 3.
        self._attack_attempts += 1
        attempt_ctx = GuardContext(attack_attempts=self._attack_attempts)
        attempt_guard = guard_attack_attempt_count(attempt_ctx, self.guard_config)
        self._record_guard("attack_attempt_count", attempt_guard)
        if not attempt_guard.allowed:
            self._goto(State.ESCALATED)
            return

        plan = self._current_plan
        atomic_ref = plan.atomic_ref or c.AtomicReference(
            source="atomic-red-team",
            identifier=f"{plan.technique_id}#1",
        )
        request = c.TestRequest(
            technique_id=plan.technique_id,
            hypothesis=plan.hypothesis,
            atomic_ref=atomic_ref,
            target=c.ExecutionTarget(
                host_id="lab-host-01",
                isolation="vm",
                credentials_ref="vault://lab/host01",
            ),
        )
        self._send("orchestrator", "attacker", request)
        self._last_attack_started = _now()
        result = self.attacker.handle(request)
        self._last_attack_result = result
        self._send("attacker", "orchestrator", result)
        if result.status == "executed":
            self._goto(State.TELEMETRY_PENDING)
            return

        # Spec: ATTACK_EXECUTING → ESCALATE on 3 consecutive exec
        # errors with DIFFERENT root causes. Same root cause repeated
        # is a flapping condition; cause-deduplication catches genuine
        # novelty (network → auth → timeout) which is the failure
        # shape that should escalate.
        error_kind = (result.error.kind if result.error else "unknown")
        if error_kind not in self._exec_error_kinds:
            self._exec_error_kinds.append(error_kind)
        ctx = GuardContext(
            consecutive_exec_error_kinds=list(self._exec_error_kinds),
        )
        guard = guard_attack_executing_to_escalate(ctx, self.guard_config)
        self._record_guard("attack_executing_to_escalate", guard)
        if not guard.allowed:
            self._goto(State.ESCALATED)
        else:
            # Retry the attack; the adjacency table allows the self-
            # loop ATTACK_EXECUTING → ATTACK_EXECUTING.
            self._goto(State.ATTACK_EXECUTING)

    def _analyze(self) -> None:
        plan = self._current_plan
        attack = self._last_attack_result
        request = c.AnalysisRequest(
            technique_id=plan.technique_id,
            hypothesis=plan.hypothesis,
            expected_telemetry=plan.expected_telemetry,
            attack_window=c.AttackWindow(
                start=attack.started_at, end=attack.ended_at
            ),
            observed_indicators=attack.observed_indicators,
        )
        self._send("orchestrator", "analyst", request)
        result = self.analyst.handle(request)
        self._last_analysis = result
        self._send("analyst", "orchestrator", result)

        # Branch on verdict + retest budget:
        #  - INCONCLUSIVE: retry once without recording
        #  - PASS, or FAIL with no budget: record this run, advance technique
        #  - FAIL/PARTIAL with budget: engineer first, then record (so the
        #    card shows the action taken in response to the failed run)
        if result.verdict == "inconclusive":
            # Spec: INCONCLUSIVE → ATTACK_EXECUTING — retry ONCE with
            # extended telemetry window. After one retry the verdict
            # must resolve; a second INCONCLUSIVE indicates a
            # telemetry-source problem and escalates.
            ctx = GuardContext(
                inconclusive_retries_used=self._inconclusive_retries_used,
            )
            guard = guard_inconclusive_to_retry(ctx, self.guard_config)
            self._record_guard("inconclusive_to_retry", guard)
            if not guard.allowed:
                self._goto(State.ESCALATED)
                return
            self._inconclusive_retries_used += 1
            self._goto(State.ATTACK_EXECUTING)
            return

        if result.gap is not None and self._retests_remaining > 0:
            self._last_patch = None  # reset so we capture this iteration's
            self._goto(State.DETECTION_ENGINEERING)
        else:
            self._goto(State.CARD_UPDATING)

    def _engineer(self) -> None:
        plan = self._current_plan
        analysis = self._last_analysis
        assert analysis.gap is not None  # invariant: only here on PARTIAL/FAIL
        task = c.DetectionTask(
            technique_id=plan.technique_id,
            hypothesis=plan.hypothesis,
            gap=analysis.gap,
            telemetry_samples=analysis.evidence,
            existing_rules=[],
            target_format="sigma",
            testing_corpus_ref="s3://corpus/sigma-backtest/2026-q2",
        )
        self._send("orchestrator", "engineer", task)
        patch = self.engineer.handle(task)
        self._last_patch = patch
        self._send("engineer", "orchestrator", patch)
        self._goto(State.DETECTION_PR_OPEN)

    def _deploy_and_advance(self) -> None:
        # Auto-deploy in the demo. In production this would gate on a PR
        # merge or an explicit approval signal.
        self._goto(State.CARD_UPDATING)

    def _update_card(self) -> None:
        plan = self._current_plan
        analysis = self._last_analysis
        run_record = c.RunRecord(
            run_id=self._current_run_id,
            ran_at=self._last_attack_started or _now(),
            result=analysis.verdict.upper(),  # type: ignore[arg-type]
            telemetry_summary=", ".join(
                f"{t.source}{'✓' if t.observed else '✗'}"
                for t in analysis.telemetry_seen
            ),
            mttd_seconds=analysis.mttd_seconds,
            mttr_seconds=analysis.mttr_seconds,
            gap_summary=analysis.gap.detail if analysis.gap else None,
            action_taken=(
                self._last_patch.reasoning
                if analysis.gap and getattr(self, "_last_patch", None) is not None
                else None
            ),
        )
        update = c.CardUpdate(
            technique_id=plan.technique_id,
            campaign_id=self.config.campaign_id,
            run_record=run_record,
            hypothesis=plan.hypothesis,
        )
        self._send("orchestrator", "scribe", update)
        ack = self.scribe.handle(update)
        self._send("scribe", "orchestrator", ack)

        # If this card update came after engineering work, re-test.
        # Otherwise (PASS, or out-of-budget FAIL), advance technique.
        if analysis.gap and getattr(self, "_last_patch", None) is not None:
            self._goto(State.RE_TEST)
        else:
            self._goto(State.TECHNIQUE_SELECTED)

    # ─── Helpers ───────────────────────────────────────────────────

    def _send(
        self,
        sender: AgentName,
        recipient: AgentName,
        payload: BaseModel,
    ) -> None:
        env = Envelope(
            campaign_id=self.config.campaign_id,
            technique_id=self._current_plan.technique_id
            if hasattr(self, "_current_plan")
            else "campaign",
            run_id=getattr(self, "_current_run_id", "campaign"),
            **{"from": sender, "to": recipient},
            payload=payload,
        )
        self.audit.append_envelope(env)

    def _goto(self, target: State) -> None:
        self.audit.append_event(
            "transition", from_state=self.state.value, to_state=target.value
        )
        self.state = transition(self.state, target)

    def _record_guard(self, name: str, result: GuardResult) -> None:
        """Audit-log a guard decision. Both allow and deny are logged
        so the decision history is fully reconstructible from the log."""
        self.audit.append_event(
            "guard",
            name=name,
            outcome=result.outcome,
            reason=result.reason,
            state=self.state.value,
        )


class _Empty(BaseModel):
    """Placeholder payload for agents that don't need input."""
    pass
