from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


Mode = Literal["defend", "pentest"]
Intensity = Literal["low", "medium", "high"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
Confidence = Literal["CONFIRMED", "HIGH", "MEDIUM", "LOW", "POTENTIAL"]
ScanStatus = Literal["queued", "running", "cancelling", "cancelled", "complete", "error"]
AgentRunStatus = Literal["idle", "active", "complete", "error"]
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

    @model_validator(mode="after")
    def normalize_test_selection(self) -> "ScanRequest":
        if self.selected_tests and self.attack_types and set(self.selected_tests) != set(self.attack_types):
            raise ValueError("selected_tests and attack_types cannot define different scopes")
        selected = self.selected_tests or self.attack_types
        self.selected_tests = list(dict.fromkeys(selected))
        self.attack_types = []
        return self


class FindingCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

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
