from typing import Any, TypedDict

from app.config import Settings
from app.models import (
    AccessDecision,
    AccessRequest,
    AccessResponse,
    AgentTrace,
    AuditRecord,
    PolicyValidation,
    Resource,
    RiskAssessment,
)
from app.services.bedrock_client import BedrockGateway
from app.services.policy_engine import PolicyEngine
from app.services.policy_store import PolicyStore


class GovernanceState(TypedDict, total=False):
    request: AccessRequest
    resource: Resource
    validation: PolicyValidation
    risk: RiskAssessment
    decision: AccessDecision
    message: str
    trace: list[AgentTrace]


class GovernanceWorkflow:
    def __init__(
        self,
        settings: Settings,
        bedrock: BedrockGateway,
        policy_engine: PolicyEngine,
        policy_store: PolicyStore,
    ) -> None:
        self.settings = settings
        self.bedrock = bedrock
        self.policy_engine = policy_engine
        self.policy_store = policy_store
        self.graph = self._build_graph()

    def run(self, request: AccessRequest) -> AccessResponse:
        if request.tenant_id is None:
            request.tenant_id = self.settings.default_tenant

        initial: GovernanceState = {"request": request, "trace": []}
        final_state = self.graph.invoke(initial) if self.graph else self._run_sequential(initial)
        response = AccessResponse(
            request_id=request.request_id,
            decision=final_state["decision"],
            message=final_state["message"],
            analyzed_request=final_state["request"],
            policy_validation=final_state["validation"],
            risk=final_state["risk"],
            trace=final_state["trace"],
        )
        self.policy_store.save_audit(
            AuditRecord(
                request_id=response.request_id,
                tenant_id=request.tenant_id or self.settings.default_tenant,
                user_id=request.subject.user_id,
                resource_id=response.analyzed_request.resource_hint.resource_id
                if response.analyzed_request.resource_hint
                else final_state["resource"].resource_id,
                action=request.action,
                decision=response.decision,
                risk_score=response.risk.score,
                trace=response.trace,
            )
        )
        return response

    def _build_graph(self) -> Any | None:
        try:
            from langgraph.graph import END, StateGraph
        except ImportError:
            return None

        graph = StateGraph(GovernanceState)
        graph.add_node("request_analyzer", self.request_analyzer)
        graph.add_node("policy_validator", self.policy_validator)
        graph.add_node("risk_scorer", self.risk_scorer)
        graph.add_node("approval_agent", self.approval_agent)
        graph.set_entry_point("request_analyzer")
        graph.add_edge("request_analyzer", "policy_validator")
        graph.add_edge("policy_validator", "risk_scorer")
        graph.add_edge("risk_scorer", "approval_agent")
        graph.add_edge("approval_agent", END)
        return graph.compile()

    def _run_sequential(self, state: GovernanceState) -> GovernanceState:
        for step in (
            self.request_analyzer,
            self.policy_validator,
            self.risk_scorer,
            self.approval_agent,
        ):
            state = step(state)
        return state

    def request_analyzer(self, state: GovernanceState) -> GovernanceState:
        request = state["request"]
        parsed = self.bedrock.analyze_access_request(request.request_text)
        resource = request.resource_hint or Resource(
            resource_type=parsed.get("resource_type", "unknown"),
            resource_id=parsed.get("resource_id", "unknown-resource"),
            sensitivity=parsed.get("sensitivity", "internal"),
            owner_department=request.subject.department,
        )
        request.action = parsed.get("action") or request.action
        request.business_justification = (
            request.business_justification or parsed.get("business_justification")
        )
        request.resource_hint = resource
        state["resource"] = resource
        state["trace"].append(
            AgentTrace(
                agent="Request Analyzer",
                summary="Parsed natural-language request into governed access attributes.",
                details={"resource": resource.model_dump(), "action": request.action},
            )
        )
        return state

    def policy_validator(self, state: GovernanceState) -> GovernanceState:
        request = state["request"]
        policies = self.policy_store.list_policies(request.tenant_id or self.settings.default_tenant)
        validation = self.policy_engine.validate(request, state["resource"], policies)
        state["validation"] = validation
        state["trace"].append(
            AgentTrace(
                agent="Policy Validator",
                summary="Evaluated ABAC rules, IAM-style permissions, and OPA policy result.",
                details=validation.model_dump(),
            )
        )
        return state

    def risk_scorer(self, state: GovernanceState) -> GovernanceState:
        request = state["request"]
        resource = state["resource"]
        validation = state["validation"]
        score = 10
        factors: list[str] = []

        if resource.sensitivity == "confidential":
            score += 25
            factors.append("Confidential resource.")
        if resource.sensitivity == "restricted":
            score += 45
            factors.append("Restricted resource.")
        if (
            resource.owner_department != "unknown"
            and request.subject.department != resource.owner_department
        ):
            score += 15
            factors.append("Cross-department resource access.")
        if request.action in {"write", "admin", "delete"}:
            score += 20
            factors.append("Privileged action.")
        if request.requested_duration_hours > 24:
            score += 15
            factors.append("Long requested duration.")
        if validation.denials:
            score += 25
            factors.append("One or more policy controls denied the request.")

        score = min(score, 100)
        level = "low"
        if score >= 85:
            level = "critical"
        elif score >= 65:
            level = "high"
        elif score >= 35:
            level = "medium"

        risk = RiskAssessment(score=score, level=level, factors=factors)
        state["risk"] = risk
        state["trace"].append(
            AgentTrace(
                agent="Risk Scorer",
                summary=f"Calculated {level} risk with score {score}.",
                details=risk.model_dump(),
            )
        )
        return state

    def approval_agent(self, state: GovernanceState) -> GovernanceState:
        validation = state["validation"]
        risk = state["risk"]
        resource = state["resource"]

        controls_allow = validation.abac_allowed and validation.iam_allowed and validation.opa_allowed
        if not controls_allow or risk.score >= self.settings.rejection_threshold:
            decision = AccessDecision.rejected
        elif risk.score >= self.settings.approval_threshold:
            decision = AccessDecision.needs_approval
        else:
            decision = AccessDecision.approved

        state["decision"] = decision
        state["message"] = self.bedrock.final_response(
            decision.value, {"resource_id": resource.resource_id, "risk": risk.model_dump()}
        )
        state["trace"].append(
            AgentTrace(
                agent="Approval/Rejection Agent",
                summary=f"Produced final decision: {decision.value}.",
                details={"decision": decision.value, "message": state["message"]},
            )
        )
        return state
