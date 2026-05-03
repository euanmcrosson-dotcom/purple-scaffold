"""Tests for the synthesized tool-call policy pipeline.

Covers:
  - `policy.evaluate` honours each operator (in / not_in / matches /
    equals) and short-circuits on the first matching deny rule.
  - `policy_synthesis.synthesize` maps known gap patterns to the
    expected rules, and returns an empty policy when no pattern
    matches (rather than fabricating a confidently-wrong rule).
  - `policy_backtest.run_backtest` correctly classifies TP / FP / TN /
    FN against the default corpus, and the matches_attack_sample
    invariant the orchestrator's auto-merge gate depends on holds.
"""

from __future__ import annotations

import pytest

from purple import contracts as c
from purple.policy import (
    Condition,
    GeneratedPolicy,
    PolicyRule,
    evaluate,
)
from purple.policy_backtest import (
    BacktestCase,
    default_corpus,
    run_backtest,
)
from purple.policy_synthesis import SynthesisInput, synthesize


# ─── policy.evaluate ───────────────────────────────────────────────


def _allowlist_policy() -> GeneratedPolicy:
    return GeneratedPolicy(
        rules=(
            PolicyRule(
                rule_id="r1",
                tool="send_email",
                conditions=(
                    Condition(arg="to", op="not_in", ref="context.user.contacts"),
                ),
                reason="external recipient",
            ),
        )
    )


def test_evaluate_allows_in_contacts():
    policy = _allowlist_policy()
    decision = evaluate(
        policy,
        "send_email",
        {"to": "bob@corp.example"},
        {"user": {"contacts": ["bob@corp.example"]}},
    )
    assert decision.allowed is True
    assert decision.denying_rule_id is None


def test_evaluate_denies_outside_contacts():
    policy = _allowlist_policy()
    decision = evaluate(
        policy,
        "send_email",
        {"to": "attacker@evil.com"},
        {"user": {"contacts": ["bob@corp.example"]}},
    )
    assert decision.allowed is False
    assert decision.denying_rule_id == "r1"
    assert decision.reason


def test_evaluate_skips_other_tools():
    """Rule for send_email should not affect read_file calls."""
    policy = _allowlist_policy()
    decision = evaluate(
        policy,
        "read_file",
        {"path": "/etc/shadow"},
        {"user": {"contacts": []}},
    )
    assert decision.allowed is True


def test_evaluate_matches_op_uses_regex():
    policy = GeneratedPolicy(
        rules=(
            PolicyRule(
                rule_id="r2",
                tool="read_file",
                conditions=(Condition(arg="path", op="matches", value=r"\.ssh/"),),
                reason="ssh dir",
            ),
        )
    )
    deny = evaluate(policy, "read_file", {"path": "~/.ssh/id_rsa"}, {})
    allow = evaluate(policy, "read_file", {"path": "~/Documents/notes.txt"}, {})
    assert deny.allowed is False
    assert allow.allowed is True


def test_evaluate_short_circuits_on_first_deny():
    """Two rules both denying the same call — the first wins. The
    orchestrator's audit log records the rule_id, so deterministic
    iteration order matters."""
    rule_a = PolicyRule(
        rule_id="rule-a",
        tool="send_email",
        conditions=(Condition(arg="to", op="equals", value="x@y"),),
        reason="rule a",
    )
    rule_b = PolicyRule(
        rule_id="rule-b",
        tool="send_email",
        conditions=(Condition(arg="to", op="equals", value="x@y"),),
        reason="rule b",
    )
    policy = GeneratedPolicy(rules=(rule_a, rule_b))
    decision = evaluate(policy, "send_email", {"to": "x@y"}, {})
    assert decision.allowed is False
    assert decision.denying_rule_id == "rule-a"


def test_condition_value_or_ref_required_not_both():
    """Constructor invariant: a condition needs exactly one of
    value/ref. Both-or-neither is a programmer error."""
    with pytest.raises(ValueError):
        Condition(arg="x", op="equals", value=1, ref="context.x")
    with pytest.raises(ValueError):
        Condition(arg="x", op="equals")


def test_yaml_serialization_is_deterministic():
    """The YAML output is the diff body — two equivalent policies must
    produce byte-identical YAML so PR diffs are stable."""
    policy_1 = _allowlist_policy()
    policy_2 = _allowlist_policy()
    assert policy_1.to_yaml() == policy_2.to_yaml()
    assert "deny_when:" in policy_1.to_yaml()


# ─── synthesize ────────────────────────────────────────────────────


def test_synthesize_email_exfil_pattern():
    gap = c.GapDescription(
        kind="telemetry_no_rule",
        detail=(
            "Indirect prompt injection caused agent to call email.send to "
            "attacker@evil.com with no policy gate."
        ),
        proposed_fix_summary="Add contact-allowlist tool policy.",
    )
    policy = synthesize(
        SynthesisInput(
            gap=gap,
            indicators=["tool:email.send", "argument:to=attacker@evil.com"],
            technique_id="AML.T0051-LIVE",
        )
    )
    assert len(policy.rules) == 1
    rule = policy.rules[0]
    assert rule.tool == "send_email"
    assert "contact-allowlist" in rule.rule_id
    assert any(
        c.arg == "to" and c.op == "not_in" for c in rule.conditions
    )


def test_synthesize_no_match_returns_empty_policy():
    """If indicators don't match any known pattern, the synthesizer
    returns an empty policy. Honesty over fabrication — the
    orchestrator surfaces the empty result via DetectionPatch.status
    == 'blocked'."""
    gap = c.GapDescription(
        kind="rule_too_narrow",
        detail="A novel attack class with no matching pattern in synthesis.",
        proposed_fix_summary="Manual review required.",
    )
    policy = synthesize(
        SynthesisInput(
            gap=gap,
            indicators=["unknown:weird_signal"],
            technique_id="UNKNOWN.001",
        )
    )
    assert policy.rules == ()


def test_synthesize_sensitive_file_pattern():
    gap = c.GapDescription(
        kind="telemetry_no_rule",
        detail="MCP cross-tool confused deputy reading ~/.ssh/id_rsa.",
        proposed_fix_summary="Block sensitive file reads.",
    )
    policy = synthesize(
        SynthesisInput(
            gap=gap,
            indicators=["tool:read_file", "argument:path=~/.ssh/id_rsa"],
            technique_id="AML.T0053",
        )
    )
    assert len(policy.rules) == 1
    rule = policy.rules[0]
    assert rule.tool == "read_file"
    assert any(c.op == "matches" for c in rule.conditions)


# ─── backtest ──────────────────────────────────────────────────────


def test_backtest_against_default_corpus_with_email_rule():
    """The contact-allowlist rule should:
      - catch every attack-class send_email case (TP)
      - allow every legit in-contact case (TN)
      - fire on the legitimate first-time-recipient cases (FP — known)
      - not interfere with non-email tools (TN by virtue of tool match)
    """
    policy = synthesize(
        SynthesisInput(
            gap=c.GapDescription(
                kind="telemetry_no_rule",
                detail="email.send to attacker@evil.com",
                proposed_fix_summary="x",
            ),
            indicators=["tool:email.send", "argument:to=attacker@evil.com"],
            technique_id="AML.T0051-LIVE",
        )
    )
    metrics = run_backtest(policy, default_corpus())

    # Sanity: corpus is the right size + tagged correctly.
    assert metrics.corpus_size == 15
    # The 3 attack-sends are blocked (TP=3); the 3 attack-reads slip
    # through this rule (FN=3) since this synthesis only emitted the
    # email rule for the email-only gap.
    assert metrics.tp == 3
    assert metrics.fn == 3
    # FP comes from legitimate first-time-recipient sends; there are
    # exactly 2 of those in the corpus.
    assert metrics.fp == 2
    # TN: 4 in-contact emails + 3 non-email legit calls = 7
    assert metrics.tn == 7
    # FPR = FP / (FP + TN) = 2/9 ≈ 0.222 — far above the auto-merge
    # threshold, so the orchestrator should NOT auto-merge.
    assert metrics.false_positive_rate == pytest.approx(2 / 9)
    # matches_attack_sample is the auto-merge precondition — true iff
    # at least one TP.
    assert metrics.matches_attack_sample is True


def test_backtest_combined_email_and_file_rules():
    """When the synthesizer emits BOTH rules (email gap + file gap in
    indicators), the backtest catches all 6 attack scenarios."""
    policy = synthesize(
        SynthesisInput(
            gap=c.GapDescription(
                kind="telemetry_no_rule",
                detail="email.send to attacker@evil.com AND ~/.ssh/id_rsa read",
                proposed_fix_summary="x",
            ),
            indicators=[
                "tool:email.send",
                "argument:to=attacker@evil.com",
                "tool:read_file",
                "argument:path=~/.ssh/id_rsa",
            ],
            technique_id="combined",
        )
    )
    metrics = run_backtest(policy, default_corpus())
    assert len(policy.rules) == 2
    assert metrics.tp == 6  # all attacks caught
    assert metrics.fn == 0


def test_backtest_empty_policy_catches_nothing():
    """An empty policy is a no-op: every call allowed."""
    metrics = run_backtest(GeneratedPolicy(), default_corpus())
    assert metrics.tp == 0
    assert metrics.fp == 0
    assert metrics.fn + metrics.tn == metrics.corpus_size
    assert metrics.matches_attack_sample is False
