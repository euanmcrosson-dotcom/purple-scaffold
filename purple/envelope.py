"""Common message envelope.

Every inter-agent message is wrapped in an Envelope. The orchestrator
appends every envelope to the audit log so a campaign is fully replayable.
"""

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, SerializeAsAny

AgentName = Literal[
    "scout", "attacker", "analyst", "engineer", "scribe", "orchestrator"
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return uuid4().hex


class Envelope(BaseModel):
    """Common envelope wrapping every inter-agent message.

    `payload` is annotated `SerializeAsAny[BaseModel]` so the *concrete*
    payload type round-trips through model_dump — without this, generic
    typing erases the fields of the actual subclass.
    """

    message_id: str = Field(default_factory=_new_id)
    campaign_id: str
    technique_id: str
    run_id: str
    parent_message_id: str | None = None
    sender: AgentName = Field(alias="from")
    recipient: AgentName = Field(alias="to")
    schema_version: Literal["1.0"] = "1.0"
    timestamp: str = Field(default_factory=_now_iso)
    payload: SerializeAsAny[BaseModel]

    model_config = ConfigDict(populate_by_name=True)

    def to_jsonable(self) -> dict[str, Any]:
        return self.model_dump(by_alias=True, mode="json")
