"""Unit tests for transition guards.

Independent of the orchestrator and agents — these test the guard
functions in isolation against the rules table from the design doc.
"""

import pytest

from purple.guards import (
    GuardConfig,
    GuardContext,
    guard_attack_executing_to_escalate,
    guard_inconclusive_to_retry,
    guard_pr_open_to_deployed,
    guard_retest_to_escalate,
)


# ─── ATTACK_EXECUTING → ESCALATE ───────────────────────────────────


def test_exec_error_guard_allows_below_threshold():
    cfg = GuardConfig(max_consecutive_exec_error_kinds=3)
    ctx = GuardContext(consecutive_exec_error_kinds=["network", "auth"])
    assert guard_attack_executing_to_escalate(ctx, cfg).allowed


def test_exec_error_guard_escalates_at_threshold():
    cfg = GuardConfig(max_consecutive_exec_error_kinds=3)
    ctx = GuardContext(
        consecutive_exec_error_kinds=["network", "auth", "timeout"]
    )
    result = guard_attack_executing_to_escalate(ctx, cfg)
    assert not result.allowed
    assert result.outcome == "deny_escalate"
    assert "3 distinct exec-error" in result.reason


def test_exec_error_guard_dedup_means_same_cause_doesnt_escalate():
    """The list passed in is already deduped (orchestrator does the
    dedup). One distinct cause repeated should never escalate this
    guard regardless of how many retries; the design point is novelty
    of root cause, not retry count."""
    cfg = GuardConfig(max_consecutive_exec_error_kinds=3)
    ctx = GuardContext(consecutive_exec_error_kinds=["network"])
    assert guard_attack_executing_to_escalate(ctx, cfg).allowed


# ─── INCONCLUSIVE → ATTACK_EXECUTING ───────────────────────────────


def test_inconclusive_first_retry_allowed():
    cfg = GuardConfig(max_inconclusive_retries=1)
    ctx = GuardContext(inconclusive_retries_used=0)
    assert guard_inconclusive_to_retry(ctx, cfg).allowed


def test_inconclusive_second_retry_escalates():
    """Spec: retry ONCE. A second INCONCLUSIVE means telemetry is
    broken, not detection — escalate."""
    cfg = GuardConfig(max_inconclusive_retries=1)
    ctx = GuardContext(inconclusive_retries_used=1)
    result = guard_inconclusive_to_retry(ctx, cfg)
    assert not result.allowed
    assert result.outcome == "deny_escalate"


# ─── DETECTION_PR_OPEN → DETECTION_DEPLOYED ────────────────────────


def test_auto_merge_allowed_when_all_conditions_hold():
    cfg = GuardConfig(auto_merge_fpr_threshold=0.01)
    ctx = GuardContext(
        last_rule_matches_sample=True,
        last_fpr=0.005,
        policy_allows_auto_merge=True,
    )
    assert guard_pr_open_to_deployed(ctx, cfg).allowed


def test_auto_merge_human_gate_when_fpr_too_high():
    cfg = GuardConfig(auto_merge_fpr_threshold=0.01)
    ctx = GuardContext(
        last_rule_matches_sample=True,
        last_fpr=0.05,
        policy_allows_auto_merge=True,
    )
    result = guard_pr_open_to_deployed(ctx, cfg)
    assert not result.allowed
    assert result.outcome == "deny_human_gate"
    assert "0.05" in result.reason or "0.0500" in result.reason


def test_auto_merge_human_gate_when_rule_doesnt_match_sample():
    cfg = GuardConfig(auto_merge_fpr_threshold=0.01)
    ctx = GuardContext(
        last_rule_matches_sample=False,
        last_fpr=0.001,
        policy_allows_auto_merge=True,
    )
    result = guard_pr_open_to_deployed(ctx, cfg)
    assert not result.allowed
    assert result.outcome == "deny_human_gate"


def test_auto_merge_human_gate_when_no_fpr_measurement():
    cfg = GuardConfig(auto_merge_fpr_threshold=0.01)
    ctx = GuardContext(
        last_rule_matches_sample=True,
        last_fpr=None,
        policy_allows_auto_merge=True,
    )
    result = guard_pr_open_to_deployed(ctx, cfg)
    assert not result.allowed
    assert result.outcome == "deny_human_gate"


def test_auto_merge_human_gate_when_policy_disallows():
    """Even with a perfect FPR and matching rule, an operator-level
    policy can force human review. This test pins that override."""
    cfg = GuardConfig(auto_merge_fpr_threshold=0.01)
    ctx = GuardContext(
        last_rule_matches_sample=True,
        last_fpr=0.001,
        policy_allows_auto_merge=False,
    )
    result = guard_pr_open_to_deployed(ctx, cfg)
    assert not result.allowed
    assert result.outcome == "deny_human_gate"
    assert "policy" in result.reason


# ─── RE_TEST → ESCALATE ────────────────────────────────────────────


def test_retest_under_budget_allowed():
    cfg = GuardConfig(max_retest_cycles=3)
    ctx = GuardContext(retest_cycles_attempted=2)
    assert guard_retest_to_escalate(ctx, cfg).allowed


def test_retest_at_budget_escalates():
    cfg = GuardConfig(max_retest_cycles=3)
    ctx = GuardContext(retest_cycles_attempted=3)
    result = guard_retest_to_escalate(ctx, cfg)
    assert not result.allowed
    assert result.outcome == "deny_escalate"
    assert "not converging" in result.reason


# ─── Default config sanity ─────────────────────────────────────────


def test_default_guard_config_thresholds():
    """The defaults must match what the spec table says."""
    cfg = GuardConfig()
    assert cfg.max_consecutive_exec_error_kinds == 3
    assert cfg.max_inconclusive_retries == 1
    assert cfg.auto_merge_fpr_threshold == 0.01
    assert cfg.max_retest_cycles == 3
