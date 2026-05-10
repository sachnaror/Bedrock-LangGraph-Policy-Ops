from app.agents.governance_graph import GovernanceWorkflow
from app.config import Settings
from app.models import AccessDecision, AccessRequest, Resource, Subject
from app.services.bedrock_client import BedrockGateway
from app.services.opa_client import OPAClient
from app.services.policy_engine import PolicyEngine
from app.services.policy_store import InMemoryPolicyStore


def build_workflow() -> GovernanceWorkflow:
    settings = Settings()
    return GovernanceWorkflow(
        settings=settings,
        bedrock=BedrockGateway(settings),
        policy_engine=PolicyEngine(OPAClient(settings)),
        policy_store=InMemoryPolicyStore(),
    )


def test_internal_dashboard_request_is_approved() -> None:
    response = build_workflow().run(
        AccessRequest(
            request_text="Please give me read access to dashboard revenue-overview",
            subject=Subject(user_id="u-1", department="finance", role="employee"),
        )
    )

    assert response.decision == AccessDecision.approved
    assert [step.agent for step in response.trace] == [
        "Request Analyzer",
        "Policy Validator",
        "Risk Scorer",
        "Approval/Rejection Agent",
    ]


def test_restricted_api_without_clearance_is_rejected() -> None:
    response = build_workflow().run(
        AccessRequest(
            request_text="Need invoke access to restricted production api billing-admin",
            subject=Subject(user_id="u-2", department="sales", role="employee"),
        )
    )

    assert response.decision == AccessDecision.rejected
    assert response.policy_validation.denials


def test_confidential_audit_request_needs_manual_approval() -> None:
    response = build_workflow().run(
        AccessRequest(
            request_text="Need read access to confidential document payroll-q4 for quarterly audit",
            subject=Subject(user_id="u-3", department="hr", role="auditor"),
            resource_hint=Resource(
                resource_type="document",
                resource_id="payroll-q4",
                owner_department="finance",
                sensitivity="confidential",
            ),
            requested_duration_hours=72,
        )
    )

    assert response.decision == AccessDecision.needs_approval
    assert response.risk.level == "high"


def test_memory_store_loads_policy_files() -> None:
    store = InMemoryPolicyStore(Settings())
    policy_ids = {policy.policy_id for policy in store.list_policies("zoneone")}

    assert "abac-internal-same-department-read" in policy_ids
    assert "abac-deny-restricted-without-clearance" in policy_ids
