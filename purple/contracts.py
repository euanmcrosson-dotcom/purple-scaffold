"""Message payload contracts — the schema the agents speak.

All payloads are Pydantic models so they validate on construction and
serialize losslessly into the audit log.
"""

from typing import Literal

from pydantic import BaseModel, Field

# ─── Shared types ──────────────────────────────────────────────────

ArtifactKind = Literal["stdout", "file", "screenshot", "pcap", "har"]
DetectionFormat = Literal[
    # Traditional endpoint / SIEM detection formats
    "sigma", "kql", "spl", "yara-l",
    # ATLAS / AI agent detection formats
    "prompt-firewall", "output-classifier", "tool-policy", "guard-rail",
]
Verdict = Literal["pass", "partial", "fail", "inconclusive"]
CardStatus = Literal["open", "in_progress", "partial", "closed", "escalated"]
RunResult = Literal["PASS", "PARTIAL", "FAIL", "INCONCLUSIVE"]


class Artifact(BaseModel):
    kind: ArtifactKind
    uri: str
    sha256: str
    bytes: int


class TelemetrySource(BaseModel):
    source: str
    expected_event_id: str | None = None
    query_hint: str | None = None


class GapDescription(BaseModel):
    kind: Literal[
        "no_telemetry", "telemetry_no_rule", "rule_misfire", "rule_too_narrow"
    ]
    detail: str
    proposed_fix_summary: str


class DetectionRef(BaseModel):
    rule_id: str
    format: DetectionFormat
    uri: str


class AtomicReference(BaseModel):
    """Reference to a runnable test.

    `source` covers both traditional endpoint atomics (atomic-red-team,
    Caldera) and AI-agent atomics (garak, PyRIT, custom prompt payloads).
    """

    source: Literal["atomic-red-team", "caldera", "garak", "pyrit", "custom"]
    identifier: str
    inputs: dict[str, str] = Field(default_factory=dict)


# ─── Scout ─────────────────────────────────────────────────────────


class TechniquePlan(BaseModel):
    technique_id: str
    framework: Literal["ATTACK", "ATLAS"]
    rationale: str
    hypothesis: str
    expected_telemetry: list[TelemetrySource]
    priority: Literal["p0", "p1", "p2"]
    budget_seconds: int = 600
    # If supplied by Scout, used verbatim. If None, the orchestrator falls
    # back to atomic-red-team with the technique_id as the identifier.
    atomic_ref: AtomicReference | None = None


# ─── Attacker ──────────────────────────────────────────────────────


class ExecutionTarget(BaseModel):
    host_id: str
    isolation: Literal["vm", "container", "ephemeral_browser"]
    credentials_ref: str


class TestConstraints(BaseModel):
    max_runtime_seconds: int = 300
    network_egress_allowed: bool = False
    destructive: bool = False


class TestRequest(BaseModel):
    technique_id: str
    hypothesis: str
    atomic_ref: AtomicReference
    target: ExecutionTarget
    constraints: TestConstraints = Field(default_factory=TestConstraints)


class AttackError(BaseModel):
    kind: str
    detail: str


class AttackResult(BaseModel):
    status: Literal["executed", "exec_error", "skipped"]
    started_at: str
    ended_at: str
    exit_code: int | None
    artifacts: list[Artifact] = Field(default_factory=list)
    observed_indicators: list[str] = Field(default_factory=list)
    error: AttackError | None = None


# ─── Analyst ───────────────────────────────────────────────────────


class AttackWindow(BaseModel):
    start: str
    end: str


class AnalysisRequest(BaseModel):
    technique_id: str
    hypothesis: str
    expected_telemetry: list[TelemetrySource]
    attack_window: AttackWindow
    observed_indicators: list[str]
    existing_detections: list[DetectionRef] = Field(default_factory=list)


class TelemetryObservation(BaseModel):
    source: str
    observed: bool
    event_count: int
    sample_event_ref: str | None = None


class DetectionFiring(BaseModel):
    rule_id: str
    fired: bool
    alert_count: int
    first_alert_at: str | None = None


class AnalysisResult(BaseModel):
    verdict: Verdict
    telemetry_seen: list[TelemetryObservation]
    detections_fired: list[DetectionFiring]
    mttd_seconds: float | None = None
    mttr_seconds: float | None = None
    gap: GapDescription | None = None
    evidence: list[Artifact] = Field(default_factory=list)


# ─── Engineer ──────────────────────────────────────────────────────


class DetectionTask(BaseModel):
    technique_id: str
    hypothesis: str
    gap: GapDescription
    telemetry_samples: list[Artifact]
    existing_rules: list[DetectionRef]
    target_format: Literal[
        "sigma", "kql", "spl",
        "prompt-firewall", "output-classifier", "tool-policy", "guard-rail",
    ] = "sigma"
    testing_corpus_ref: str


class DetectionTestResults(BaseModel):
    matches_attack_sample: bool
    false_positive_rate: float
    backtest_corpus_size: int


class DetectionPatch(BaseModel):
    status: Literal["pr_opened", "rule_updated", "blocked"]
    pr_url: str | None = None
    rule_diff: str | None = None
    test_results: DetectionTestResults
    auto_merge_eligible: bool
    reasoning: str


# ─── Scribe ────────────────────────────────────────────────────────


class RunRecord(BaseModel):
    run_id: str
    ran_at: str
    result: RunResult
    telemetry_summary: str
    mttd_seconds: float | None = None
    mttr_seconds: float | None = None
    gap_summary: str | None = None
    action_taken: str | None = None


class StatusTransition(BaseModel):
    from_status: CardStatus
    to_status: CardStatus


class CardUpdate(BaseModel):
    technique_id: str
    campaign_id: str
    run_record: RunRecord
    hypothesis: str
    status_transition: StatusTransition | None = None


class CardAck(BaseModel):
    card_uri: str
    commit_sha: str | None = None
    heatmap_updated: bool = False
