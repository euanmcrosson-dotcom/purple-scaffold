"""State machine tests — guards prevent illegal transitions."""

import pytest

from purple.state_machine import (
    State,
    StateMachineError,
    is_terminal,
    transition,
)


def test_legal_transition() -> None:
    assert transition(State.CAMPAIGN_INIT, State.TECHNIQUE_SELECTED) == (
        State.TECHNIQUE_SELECTED
    )


def test_illegal_transition_raises() -> None:
    with pytest.raises(StateMachineError):
        transition(State.CAMPAIGN_INIT, State.ATTACK_EXECUTING)


def test_any_state_can_escalate() -> None:
    for state in State:
        if state in {State.CAMPAIGN_COMPLETE, State.ESCALATED}:
            continue
        assert transition(state, State.ESCALATED) == State.ESCALATED


def test_terminal_states() -> None:
    assert is_terminal(State.CAMPAIGN_COMPLETE)
    assert is_terminal(State.ESCALATED)
    assert not is_terminal(State.ATTACK_EXECUTING)


def test_terminal_has_no_outgoing() -> None:
    with pytest.raises(StateMachineError):
        transition(State.CAMPAIGN_COMPLETE, State.TECHNIQUE_SELECTED)
