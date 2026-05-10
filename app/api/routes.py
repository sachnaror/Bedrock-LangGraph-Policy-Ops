from fastapi import APIRouter, Depends, HTTPException

from app.agents.governance_graph import GovernanceWorkflow
from app.config import Settings, get_settings
from app.dependencies import get_policy_store, get_workflow
from app.models import AccessRequest, AccessResponse, AuditRecord, Resource, StoredPolicy, Subject
from app.services.policy_store import PolicyStore

router = APIRouter()


@router.get("/health")
def health(settings: Settings = Depends(get_settings)) -> dict[str, str]:
    return {
        "status": "ok",
        "app": settings.app_name,
        "environment": settings.environment,
        "storage_backend": settings.storage_backend,
        "llm_provider": settings.llm_provider,
        "local_demo_mode": str(settings.local_demo_mode).lower(),
        "opa_enabled": str(settings.opa_enabled).lower(),
    }


@router.post("/access/request", response_model=AccessResponse)
def request_access(
    payload: AccessRequest,
    workflow: GovernanceWorkflow = Depends(get_workflow),
) -> AccessResponse:
    return workflow.run(payload)


@router.get("/demo/scenarios")
def demo_scenarios() -> list[dict[str, str]]:
    return [
        {
            "id": "approved-dashboard",
            "title": "Approved internal dashboard",
            "description": "Finance employee asks for read access to a finance dashboard.",
        },
        {
            "id": "manual-approval-payroll",
            "title": "Manual approval for payroll document",
            "description": "HR auditor asks for confidential payroll document access.",
        },
        {
            "id": "rejected-production-api",
            "title": "Rejected restricted production API",
            "description": "Sales employee asks to invoke a restricted production API.",
        },
    ]


@router.get("/demo/run/{scenario_id}", response_model=AccessResponse)
@router.post("/demo/run/{scenario_id}", response_model=AccessResponse)
def run_demo_scenario(
    scenario_id: str,
    workflow: GovernanceWorkflow = Depends(get_workflow),
) -> AccessResponse:
    scenarios = {
        "approved-dashboard": AccessRequest(
            request_text="Please give me read access to dashboard revenue-overview",
            subject=Subject(user_id="demo-finance-1", department="finance", role="employee"),
            requested_duration_hours=8,
        ),
        "manual-approval-payroll": AccessRequest(
            request_text="Need read access to confidential document payroll-q4 for quarterly audit",
            subject=Subject(
                user_id="demo-auditor-1",
                department="hr",
                role="auditor",
                clearance="internal",
            ),
            resource_hint=Resource(
                resource_type="document",
                resource_id="payroll-q4",
                owner_department="finance",
                sensitivity="confidential",
            ),
            requested_duration_hours=72,
        ),
        "rejected-production-api": AccessRequest(
            request_text="Need invoke access to restricted production api billing-admin",
            subject=Subject(user_id="demo-sales-1", department="sales", role="employee"),
            requested_duration_hours=8,
        ),
    }
    scenario = scenarios.get(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Demo scenario not found")
    return workflow.run(scenario)


@router.get("/policies", response_model=list[StoredPolicy])
def list_policies(
    tenant_id: str | None = None,
    settings: Settings = Depends(get_settings),
    store: PolicyStore = Depends(get_policy_store),
) -> list[StoredPolicy]:
    return store.list_policies(tenant_id or settings.default_tenant)


@router.post("/policies/reload")
def reload_policies(store: PolicyStore = Depends(get_policy_store)) -> dict[str, int | str]:
    loaded_count = store.reload_policies()
    return {"status": "reloaded", "policy_count": loaded_count}


@router.get("/audit/{request_id}", response_model=AuditRecord)
def get_audit_record(
    request_id: str,
    store: PolicyStore = Depends(get_policy_store),
) -> AuditRecord:
    record = store.get_audit(request_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Audit record not found")
    return record
