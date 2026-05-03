"""Per-transition guards.

Adjacency in `state_machine.py` says which transitions are *legal*.
Guards here say when each one is *allowed to fire* — the runtime
conditions specified in the state-transition rules table.

Guard functions are pure: they take a `GuardContext` snapshot of the
orchestrator's per-campaign counters and return a `GuardResult`. The
orchestrator records the result on the audit log either way, so a
denied guard is debuggable from the log alone.

This module is independent of the orchestrator so it can be unit-
tested without spinning up agents or the full state machine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


# ─── Guard inputs ──────────────────────────────────────────────────


@dataclass
class GuardContext:
    """Snapshot of orchestrator counters relevant to guard decisions.

    Populated by the orchestrator before each guard call. Pure data —
    no methods, no behavior.
    """

    # Distinct root-cause strings observed during the current technique
    # loop's ATTACK_EXECUTING attempts. Deduped: the same root cause
    # repeated counts as one entry. The guard fires after THREE distinct
    # causes have been seen.
    consecutive_exec_error_kinds: list[str] = field(default_factory=list)

    # How many times INCONCLUSIVE → ATTACK_EXECUTING has fired for the
    # CURRENT run. The guard allows one retry (so this must be 0 to
    # transition; 1 means the retry already happened).
    inconclusive_retries_used: int = 0

    # Engineer's reported false-positive rate from the backtest. The
    # auto-merge gate uses this; values above the threshold require a
    # human gate.
    last_fpr: float | None = None
    # Whether the rule passed the harness's match-against-attack-sample
    # check. Auto-merge requires this to be true.
    last_rule_matches_sample: bool | None = None
    # Whether deployment policy permits auto-merge for this technique
    # at all (some operators want every detection-for-this-class to be
    # human-reviewed regardless of FPR).
    policy_allows_auto_merge: bool = True

    # How many RE_TEST → ATTACK_EXECUTING cycles have completed for the
    # current technique without reaching PASS.
    retest_cycles_attempted: int = 0

    # Total ATTACK_EXECUTING entries this technique loop, regardless of
    # success/failure. Bounds same-cause flapping: a real-world Attacker
    # stuck on one persistent cause (DNS down, target offline, wrong
    # creds) doesn't generate novelty for `consecutive_exec_error_kinds`
    # to count, so the cause-dedup guard never escalates. This counter
    # is the absolute backstop.
    attack_attempts: int = 0


# ─── Guard outputs ─────────────────────────────────────────────────


GuardOutcome = Literal["allow", "deny_escalate", "deny_human_gate"]


@dataclass
class GuardResult:
    outcome: GuardOutcome
    reason: str

    @property
    def allowed(self) -> bool:
        return self.outcome == "allow"


# ─── Guard thresholds (knobs the orchestrator can override) ────────


@dataclass
class GuardConfig:
    """Operator-tunable thresholds for each guard."""

    max_consecutive_exec_error_kinds: int = 3
    max_inconclusive_retries: int = 1
    auto_merge_fpr_threshold: float = 0.01
    max_retest_cycles: int = 3
    # Absolute backstop on ATTACK_EXECUTING attempts per technique
    # loop. Catches same-cause flapping that the cause-dedup guard
    # cannot — a stuck-on-one-cause Attacker (network down, target
    # offline) would otherwise loop forever because the distinct-kinds
    # count stays at 1.
    max_attack_attempts_per_run: int = 10


# ─── Individual guards ─────────────────────────────────────────────


def guard_attack_executing_to_escalate(
    ctx: GuardContext, cfg: GuardConfig
) -> GuardResult:
    """Spec row: ATTACK_EXECUTING → ESCALATE on 3 consecutive exec
    errors with different root causes.

    `consecutive_exec_error_kinds` is a deduped list, so its length is
    the number of *distinct* root causes seen this technique loop.
    Three distinct causes is the trigger — three retries of the same
    cause is a flapping condition that retry doesn't solve, but
    cause-deduplication catches genuine novelty (network → auth →
    timeout) which is the failure shape that should escalate.
    """
    distinct = len(ctx.consecutive_exec_error_kinds)
    if distinct >= cfg.max_consecutive_exec_error_kinds:
        return GuardResult(
            outcome="deny_escalate",
            reason=(
                f"{distinct} distinct exec-error root causes seen "
                f"({', '.join(ctx.consecutive_exec_error_kinds)}); escalating"
            ),
        )
    return GuardResult(outcome="allow", reason="exec-error budget remains")


def guard_inconclusive_to_retry(
    ctx: GuardContext, cfg: GuardConfig
) -> GuardResult:
    """Spec row: INCONCLUSIVE → ATTACK_EXECUTING — retry ONCE with
    extended telemetry window.

    After one retry the verdict must resolve to PASS / PARTIAL / FAIL;
    a second INCONCLUSIVE indicates a telemetry-source problem, not a
    detection problem, and should escalate.
    """
    if ctx.inconclusive_retries_used >= cfg.max_inconclusive_retries:
        return GuardResult(
            outcome="deny_escalate",
            reason=(
                f"INCONCLUSIVE budget exhausted "
                f"({ctx.inconclusive_retries_used} retries used); "
                "telemetry source likely broken — escalating"
            ),
        )
    return GuardResult(
        outcome="allow",
        reason="INCONCLUSIVE retry permitted (extended telemetry window)",
    )


def guard_pr_open_to_deployed(
    ctx: GuardContext, cfg: GuardConfig
) -> GuardResult:
    """Spec row: DETECTION_PR_OPEN → DETECTION_DEPLOYED — auto-merge
    if the rule passes the test harness AND the false-positive backtest
    AND policy permits.

    Three conditions, ALL must hold:
      1. Rule matches the attack sample (the rule fires on the
         positive case from the run that triggered engineering)
      2. FPR is below threshold (e.g. 0.01 — 1% on the backtest
         corpus)
      3. Operator policy permits auto-merge for this technique class

    Otherwise the transition denies with `deny_human_gate`, which the
    orchestrator interprets as "pause for a human merge signal." This
    is distinct from `deny_escalate`, which is a hard error.
    """
    if ctx.last_rule_matches_sample is not True:
        return GuardResult(
            outcome="deny_human_gate",
            reason="rule did not match the attack sample on the test harness",
        )
    if ctx.last_fpr is None:
        return GuardResult(
            outcome="deny_human_gate",
            reason="no FPR measurement available; auto-merge gate requires backtest",
        )
    if ctx.last_fpr >= cfg.auto_merge_fpr_threshold:
        return GuardResult(
            outcome="deny_human_gate",
            reason=(
                f"FPR {ctx.last_fpr:.4f} is above auto-merge threshold "
                f"{cfg.auto_merge_fpr_threshold:.4f}; human review required"
            ),
        )
    if not ctx.policy_allows_auto_merge:
        return GuardResult(
            outcome="deny_human_gate",
            reason="deployment policy disallows auto-merge for this technique",
        )
    return GuardResult(
        outcome="allow",
        reason=(
            f"auto-merge eligible (rule matches sample, FPR "
            f"{ctx.last_fpr:.4f} < {cfg.auto_merge_fpr_threshold:.4f}, "
            "policy permits)"
        ),
    )


def guard_attack_attempt_count(
    ctx: GuardContext, cfg: GuardConfig
) -> GuardResult:
    """Absolute backstop on ATTACK_EXECUTING attempts per technique loop.

    Surfaced by purple-scaffold Angle 3 (same-cause flapping): the
    cause-dedup guard `guard_attack_executing_to_escalate` is bounded
    by *novelty* of error kinds, not by attempt count. A real-world
    Attacker stuck on a single persistent cause (DNS unreachable,
    target VM offline, expired credentials) would generate the same
    error kind on every attempt, the dedup'd kinds list stays at
    length 1, and the orchestrator loops forever.

    This guard is the unconditional cap. It fires regardless of
    cause variety. The two guards compose: the cause-dedup guard
    catches "the system is genuinely broken in 3 different ways"
    fast (could happen in 3 attempts); this guard catches "the
    system is genuinely broken in 1 way that won't resolve."

    Default: 10 attempts. Operator can tune via
    `GuardConfig.max_attack_attempts_per_run`.
    """
    if ctx.attack_attempts >= cfg.max_attack_attempts_per_run:
        return GuardResult(
            outcome="deny_escalate",
            reason=(
                f"{ctx.attack_attempts} attack attempts this technique "
                f"(max {cfg.max_attack_attempts_per_run}); "
                "cause-dedup guard insufficient against same-cause "
                "flapping — escalating"
            ),
        )
    return GuardResult(
        outcome="allow",
        reason=f"{ctx.attack_attempts}/{cfg.max_attack_attempts_per_run} attempts used",
    )


def guard_retest_to_escalate(
    ctx: GuardContext, cfg: GuardConfig
) -> GuardResult:
    """Spec row: RE_TEST → ESCALATE on 3 re-test cycles without
    reaching PASS.

    Distinct from `max_retests_per_technique` (the budget that
    consumes between attempts). This guard checks the count of
    *completed* re-test cycles that did NOT reach PASS — three of
    those means the engineering loop is not converging and a human
    must take over.
    """
    if ctx.retest_cycles_attempted >= cfg.max_retest_cycles:
        return GuardResult(
            outcome="deny_escalate",
            reason=(
                f"{ctx.retest_cycles_attempted} re-test cycles without PASS "
                f"(max {cfg.max_retest_cycles}); engineering loop not "
                "converging — escalating"
            ),
        )
    return GuardResult(
        outcome="allow",
        reason=f"{ctx.retest_cycles_attempted}/{cfg.max_retest_cycles} cycles used",
    )
