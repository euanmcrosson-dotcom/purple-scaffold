"""State machine for the purple-team campaign loop.

Deterministic. The orchestrator is the only thing that calls `transition()`,
which raises if a move is not in the adjacency table.
"""

from enum import Enum


class State(str, Enum):
    CAMPAIGN_INIT = "campaign_init"
    TECHNIQUE_SELECTED = "technique_selected"
    ATTACK_PLANNED = "attack_planned"
    ATTACK_EXECUTING = "attack_executing"
    TELEMETRY_PENDING = "telemetry_pending"
    ANALYZING = "analyzing"
    DETECTION_ENGINEERING = "detection_engineering"
    DETECTION_PR_OPEN = "detection_pr_open"
    DETECTION_DEPLOYED = "detection_deployed"
    RE_TEST = "re_test"
    CARD_UPDATING = "card_updating"
    CAMPAIGN_COMPLETE = "campaign_complete"
    ESCALATED = "escalated"


# Every state can transition to ESCALATED on unhandled error — added below.
TRANSITIONS: dict[State, set[State]] = {
    State.CAMPAIGN_INIT: {State.TECHNIQUE_SELECTED, State.CAMPAIGN_COMPLETE},
    State.TECHNIQUE_SELECTED: {State.ATTACK_PLANNED, State.CAMPAIGN_COMPLETE},
    State.ATTACK_PLANNED: {State.ATTACK_EXECUTING},
    State.ATTACK_EXECUTING: {State.TELEMETRY_PENDING, State.ATTACK_EXECUTING},
    State.TELEMETRY_PENDING: {State.ANALYZING},
    State.ANALYZING: {
        State.CARD_UPDATING,        # PASS, or FAIL with no budget
        State.DETECTION_ENGINEERING, # FAIL/PARTIAL with budget remaining
        State.ATTACK_EXECUTING,     # INCONCLUSIVE retry
    },
    State.DETECTION_ENGINEERING: {State.DETECTION_PR_OPEN},
    State.DETECTION_PR_OPEN: {State.DETECTION_DEPLOYED},
    State.DETECTION_DEPLOYED: {State.CARD_UPDATING},
    State.CARD_UPDATING: {
        State.RE_TEST,              # had gap + action → re-test
        State.TECHNIQUE_SELECTED,
        State.CAMPAIGN_COMPLETE,
    },
    State.RE_TEST: {State.ATTACK_EXECUTING},
    State.CAMPAIGN_COMPLETE: set(),
    State.ESCALATED: set(),
}

# Any non-terminal state can escalate.
for _state in list(TRANSITIONS.keys()):
    if _state not in {State.CAMPAIGN_COMPLETE, State.ESCALATED}:
        TRANSITIONS[_state].add(State.ESCALATED)


class StateMachineError(RuntimeError):
    pass


def transition(current: State, target: State) -> State:
    if target not in TRANSITIONS.get(current, set()):
        raise StateMachineError(
            f"Illegal transition: {current.value} -> {target.value}"
        )
    return target


def is_terminal(state: State) -> bool:
    return state in {State.CAMPAIGN_COMPLETE, State.ESCALATED}
