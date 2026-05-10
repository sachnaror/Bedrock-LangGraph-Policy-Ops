from functools import lru_cache

from app.agents.governance_graph import GovernanceWorkflow
from app.config import get_settings
from app.services.bedrock_client import BedrockGateway
from app.services.opa_client import OPAClient
from app.services.policy_engine import PolicyEngine
from app.services.policy_store import PolicyStore, build_policy_store


@lru_cache
def get_policy_store() -> PolicyStore:
    return build_policy_store(get_settings())


@lru_cache
def get_workflow() -> GovernanceWorkflow:
    settings = get_settings()
    bedrock = BedrockGateway(settings)
    opa = OPAClient(settings)
    policy_engine = PolicyEngine(opa)
    return GovernanceWorkflow(settings, bedrock, policy_engine, get_policy_store())
