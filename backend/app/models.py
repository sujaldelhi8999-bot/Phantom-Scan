from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


Mode = Literal["defend", "pentest"]
JobStatus = Literal["QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"]
Intensity = Literal["low", "medium", "high"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
Confidence = Literal["CONFIRMED", "HIGH", "MEDIUM", "LOW", "POTENTIAL"]
ScanStatus = Literal["queued", "running", "cancelling", "cancelled", "complete", "error"]
AgentRunStatus = Literal["idle", "active", "complete", "error"]
ExecutionType = Literal["DEFEND_SCAN", "AUTHORIZED_TEST", "SELF_AUDIT", "LAB_OPERATION"]
ExecutionLifecycle = Literal["IDLE", "QUEUED", "STARTING", "RUNNING", "PAUSED", "COMPLETED", "FAILED", "CANCELLED"]
AgentApplicability = Literal["IDLE", "QUEUED", "RUNNING", "WAITING", "COMPLETED", "FAILED", "NOT_APPLICABLE"]
VerificationMethod = Literal["dns", "http"]
VerificationStatus = Literal["PENDING", "VERIFIED", "EXPIRED", "REVOKED"]
TestModule = Literal[
    "input_security",
    "authentication",
    "authorization",
    "injection",
    "xss",
    "auth_session",
    "access_control",
    "csrf",
    "ssrf",
    "file_upload",
    "api_security",
    "graphql",
    "jwt",
    "websocket",
    "websockets",
    "rate_limits",
    "business_logic",
    "path_handling",
    "redirect",
    "redirect_security",
    "cors",
    "security_headers",
    "tls_https",
    "sensitive_exposure",
]


class BusinessLogicTest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    method: Literal["GET", "HEAD", "OPTIONS"] = "GET"
    path: str = Field(min_length=1, max_length=500)
    expected_status: int = Field(ge=100, le=599)
    description: str = Field(default="", max_length=500)

    @field_validator("path")
    @classmethod
    def path_must_be_relative(cls, value: str) -> str:
        if not value.startswith("/") or value.startswith("//"):
            raise ValueError("Business logic paths must be relative to the verified target")
        return value


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: str = Field(min_length=4, max_length=2048)
    mode: Mode
    intensity: Intensity = "medium"
    selected_tests: list[TestModule] = Field(default_factory=list, max_length=25)
    attack_types: list[TestModule] = Field(default_factory=list, max_length=25)
    authorization_id: int | None = Field(default=None, ge=1)
    authorization_confirmed: bool = False
    business_logic_tests: list[BusinessLogicTest] = Field(default_factory=list, max_length=10)
    enable_exploitation: bool = False

    @model_validator(mode="after")
    def normalize_test_selection(self) -> "ScanRequest":
        if self.selected_tests and self.attack_types and set(self.selected_tests) != set(self.attack_types):
            raise ValueError("selected_tests and attack_types cannot define different scopes")
        selected = self.selected_tests or self.attack_types
        self.selected_tests = list(dict.fromkeys(selected))
        self.attack_types = []
        return self


class FindingCreate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    title: str = Field(min_length=1, max_length=300)
    category: str = Field(min_length=1, max_length=120)
    severity: Severity
    confidence: Confidence
    target: str = Field(min_length=1, max_length=2048)
    endpoint: str = Field(default="", max_length=2048)
    evidence: str = Field(default="", max_length=12000)
    impact: str = Field(default="", max_length=4000)
    recommendation: str = Field(default="", max_length=6000)
    verification: str = Field(default="", max_length=4000)
    agent: str = Field(min_length=1, max_length=120)
    timestamp: datetime
    cve_id: str | None = Field(default=None, max_length=40)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    parameter: str | None = Field(default=None, max_length=200)
    module: str | None = Field(default=None, max_length=120)
    recommended_fix: str | None = Field(default=None, max_length=6000)
    remediation_status: Literal["OPEN", "IN_PROGRESS", "RESOLVED"] = "OPEN"
    verification_status: Literal["NOT_VERIFIED", "FIX_VERIFIED", "ISSUE_STILL_PRESENT", "VERIFY_FAILED"] = "NOT_VERIFIED"
    risk_status: Literal["ACTIVE", "FALSE_POSITIVE", "ACCEPTED_RISK"] = "ACTIVE"
    exploited: bool = False
    exploitation_result: dict[str, Any] | None = None


class Finding(FindingCreate):
    id: int
    scan_id: int
    description: str = ""
    how_exploited: str = ""
    fix: str = ""


class ScanResponse(BaseModel):
    scan_id: int
    target_url: str
    mode: Mode
    intensity: Intensity = "medium"
    selected_tests: list[TestModule] = Field(default_factory=list)
    user_id: str = "local-user"
    authorization_id: int | None = None
    authorization_confirmed: bool = False
    status: ScanStatus
    progress: int = Field(ge=0, le=100)
    request_count: int = Field(ge=0)
    sandbox_id: str | None = None
    error_message: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    findings: list[Finding]


class ScanHistoryItem(BaseModel):
    id: int
    target_url: str
    mode: Mode
    status: ScanStatus
    progress: int = Field(ge=0, le=100)
    created_at: datetime
    completed_at: datetime | None = None


class AuditLog(BaseModel):
    id: int
    scan_id: int
    agent_name: str
    action: str
    timestamp: datetime
    details: str
    user_id: str | None = None
    target: str | None = None
    authorization_status: str | None = None
    selected_module: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    result: str | None = None
    request_count: int | None = None
    sandbox_id: str | None = None


class AgentStatus(BaseModel):
    name: str
    status: AgentRunStatus


class AuthorizationChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: str = Field(min_length=4, max_length=2048)
    verification_method: VerificationMethod


class AuthorizationChallengeResponse(BaseModel):
    id: int
    domain: str
    target_origin: str
    verification_method: VerificationMethod
    token: str
    dns_record: str
    http_url: str
    challenge_expires_at: datetime
    status: VerificationStatus


class AuthorizationStatusResponse(BaseModel):
    id: int | None = None
    domain: str
    target_origin: str
    verification_method: VerificationMethod | None = None
    verified_at: datetime | None = None
    expires_at: datetime | None = None
    status: VerificationStatus
    message: str


class StopScanResponse(BaseModel):
    scan_id: int
    status: ScanStatus


class ScanArtifactsResponse(BaseModel):
    scan_id: int
    scanner_output: dict[str, Any] | None = None
    shadow_recon_output: dict[str, Any] | None = None
    hindi_findings: list[dict[str, Any]] | None = None
    markdown_report: str | None = None
    notification_result: dict[str, Any] | None = None
    active_security_output: dict[str, Any] | None = None
    browser_security_output: dict[str, Any] | None = None
    ai_analyst_output: dict[str, Any] | None = None
    updated_at: datetime | None = None


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    service: str
    database: Literal["available", "unavailable"]
    scheduler: Literal["running", "stopped", "unavailable"]
    agents: Literal["available", "unavailable"]
    ai_provider: str = "OpenRouter"
    ai_model: str = "openrouter/free"
    ai_status: Literal["connected", "offline"] = "offline"


class SelfAuditStatusResponse(BaseModel):
    status: ScanStatus | Literal["never_run"]
    scan_id: int | None = None
    target_url: str | None = None
    progress: int | None = Field(default=None, ge=0, le=100)
    finding_count: int | None = Field(default=None, ge=0)
    created_at: datetime | None = None
    completed_at: datetime | None = None


class ActiveRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: str = Field(min_length=4, max_length=2048)
    selected_modules: list[TestModule] = Field(default_factory=list, max_length=25)
    authorization_id: int | None = Field(default=None, ge=1)
    authorization_confirmed: bool = False


class AuthorizedTestRunResponse(BaseModel):
    job_id: str
    status: JobStatus
    message: str


class JobEvent(BaseModel):
    id: int
    job_id: str
    sequence_number: int
    timestamp: str
    module: str | None = None
    event_type: str
    message: str | None = None
    status: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str | None = None


class JobEventsResponse(BaseModel):
    job_id: str
    events: list[JobEvent] = Field(default_factory=list)
    latest_sequence: int = 0


class AuthorizedTestJobError(BaseModel):
    code: str
    message: str


class AuthorizedTestJobResponse(BaseModel):
    job_id: str
    status: JobStatus
    progress_percent: int = Field(ge=0, le=100)
    current_phase: str | None = None
    current_module: str | None = None
    surfaces_total: int = Field(ge=0)
    surfaces_completed: int = Field(ge=0)
    findings_count: int = Field(ge=0)
    raw_surfaces_discovered: int = Field(default=0, ge=0)
    testable_surfaces: int = Field(default=0, ge=0)
    surface_groups: int = Field(default=0, ge=0)
    started_at: str | None = None
    updated_at: str | None = None
    completed_at: str | None = None
    error: AuthorizedTestJobError | None = None
    target_url: str = ""
    selected_modules: list[str] = Field(default_factory=list)
    authorization_id: int | None = None
    scan_id: int | None = None


class AuthorizedTestJobResultsResponse(BaseModel):
    job_id: str
    status: JobStatus
    target_url: str = ""
    surfaces_total: int = Field(ge=0)
    surfaces_completed: int = Field(ge=0)
    raw_surfaces_discovered: int = Field(default=0, ge=0)
    testable_surfaces: int = Field(default=0, ge=0)
    surface_groups: int = Field(default=0, ge=0)
    findings_count: int = Field(ge=0)
    started_at: str | None = None
    completed_at: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    result_summary: dict[str, Any] | None = None


class RequestEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int = 0
    request_id: str = Field(min_length=1, max_length=64)
    job_id: str | None = Field(default=None, max_length=64)
    scan_id: int | None = None
    module: str = Field(default="", max_length=120)
    surface: str = Field(default="", max_length=500)
    method: str = Field(default="", max_length=10)
    request_url: str = Field(default="", max_length=4096)
    safe_test_marker: str = Field(default="", max_length=200)
    request_timestamp: str = Field(default="")
    response_status: int | None = None
    response_time_ms: int | None = None
    response_observed: bool = False
    detection_result: str = Field(default="INCONCLUSIVE", max_length=30)
    evidence_summary: str = Field(default="", max_length=2000)
    finding_id: int | None = None
    error: str | None = Field(default=None, max_length=500)


AgentApplicabilityLiteral = Literal["IDLE", "QUEUED", "RUNNING", "WAITING", "COMPLETED", "FAILED", "NOT_APPLICABLE"]


class AgentStateDetail(BaseModel):
    name: str
    applicability: AgentApplicabilityLiteral
    responsibility: str = ""
    current_module: str | None = None
    progress: int = Field(default=0, ge=0, le=100)
    last_updated: str | None = None
    detail: str = ""


class ExecutionStatusResponse(BaseModel):
    execution_type: ExecutionType | None = None
    lifecycle: ExecutionLifecycle
    job_id: str | None = None
    scan_id: int | None = None
    target_url: str = ""
    progress_percent: int = Field(default=0, ge=0, le=100)
    current_module: str | None = None
    current_phase: str | None = None
    surfaces_total: int = Field(default=0, ge=0)
    surfaces_completed: int = Field(default=0, ge=0)
    findings_count: int = Field(default=0, ge=0)
    started_at: str | None = None
    updated_at: str | None = None
    completed_at: str | None = None
    error_message: str | None = None
    error_code: str | None = None
    agents: list[AgentStateDetail] = Field(default_factory=list)
    is_lab: bool = False
    authorization_status: str = ""
