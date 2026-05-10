from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class AccessDecision(str, Enum):
    approved = "approved"
    needs_approval = "needs_approval"
    rejected = "rejected"


class Subject(BaseModel):
    user_id: str
    department: str = "unknown"
    role: str = "employee"
    clearance: str = "internal"
    attributes: dict[str, Any] = Field(default_factory=dict)


class Resource(BaseModel):
    resource_type: Literal["api", "document", "dashboard", "unknown"] = "unknown"
    resource_id: str
    owner_department: str = "unknown"
    sensitivity: Literal["public", "internal", "confidential", "restricted"] = "internal"
    attributes: dict[str, Any] = Field(default_factory=dict)


class AccessRequest(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str | None = None
    request_text: str
    subject: Subject
    resource_hint: Resource | None = None
    action: str = "read"
    business_justification: str | None = None
    requested_duration_hours: int = 8


class AgentTrace(BaseModel):
    agent: str
    status: Literal["started", "completed", "failed"] = "completed"
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PolicyValidation(BaseModel):
    abac_allowed: bool
    iam_allowed: bool
    opa_allowed: bool
    matched_policies: list[str] = Field(default_factory=list)
    denials: list[str] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    level: Literal["low", "medium", "high", "critical"]
    factors: list[str] = Field(default_factory=list)


class AccessResponse(BaseModel):
    request_id: str
    decision: AccessDecision
    message: str
    analyzed_request: AccessRequest
    policy_validation: PolicyValidation
    risk: RiskAssessment
    trace: list[AgentTrace]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuditRecord(BaseModel):
    request_id: str
    tenant_id: str
    user_id: str
    resource_id: str
    action: str
    decision: AccessDecision
    risk_score: int
    trace: list[AgentTrace]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class StoredPolicy(BaseModel):
    policy_id: str
    tenant_id: str
    name: str
    effect: Literal["allow", "deny"]
    conditions: dict[str, Any] = Field(default_factory=dict)
