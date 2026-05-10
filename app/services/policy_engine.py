from app.models import AccessRequest, PolicyValidation, Resource, StoredPolicy
from app.services.opa_client import OPAClient


class PolicyEngine:
    def __init__(self, opa_client: OPAClient):
        self.opa_client = opa_client

    def validate(
        self, request: AccessRequest, resource: Resource, policies: list[StoredPolicy]
    ) -> PolicyValidation:
        matched: list[str] = []
        denials: list[str] = []
        subject = request.subject

        abac_allowed = True
        if resource.sensitivity == "restricted" and subject.clearance != "restricted":
            abac_allowed = False
            denials.append("ABAC: subject clearance is insufficient for restricted resource.")
        if (
            resource.sensitivity == "confidential"
            and subject.department != resource.owner_department
            and subject.role not in {"security", "admin", "auditor"}
        ):
            abac_allowed = False
            denials.append("ABAC: confidential resource is outside subject department.")

        iam_allowed = request.action in {"read", "invoke"} or subject.role in {"admin", "security"}
        if not iam_allowed:
            denials.append("IAM: action is not allowed for subject role.")

        for policy in policies:
            if policy.effect == "deny" and policy.conditions.get("sensitivity") == resource.sensitivity:
                matched.append(policy.policy_id)
            elif policy.effect == "allow":
                matched.append(policy.policy_id)

        opa_allowed, opa_denials = self.opa_client.evaluate(
            {
                "subject": subject.model_dump(),
                "resource": resource.model_dump(),
                "action": request.action,
                "tenant_id": request.tenant_id,
            }
        )
        denials.extend(opa_denials)

        return PolicyValidation(
            abac_allowed=abac_allowed,
            iam_allowed=iam_allowed,
            opa_allowed=opa_allowed,
            matched_policies=matched,
            denials=denials,
        )
