from functools import lru_cache
from os import getenv
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel, Field


load_dotenv()


StorageBackend = Literal["memory", "postgres", "dynamodb"]
LLMProvider = Literal["local", "bedrock", "openai"]


class Settings(BaseModel):
    app_name: str = "AI Access Governance Assistant"
    environment: str = Field(default_factory=lambda: getenv("ENVIRONMENT", "local"))
    policy_dir: str = Field(
        default_factory=lambda: getenv(
            "POLICY_DIR",
            str(Path(__file__).resolve().parent / "policy"),
        )
    )
    storage_backend: StorageBackend = Field(
        default_factory=lambda: getenv("STORAGE_BACKEND", "memory").lower()
    )
    local_demo_mode: bool = Field(
        default_factory=lambda: getenv("LOCAL_DEMO_MODE", "true").lower() == "true"
    )

    llm_provider: LLMProvider = Field(default_factory=lambda: getenv("LLM_PROVIDER", "local").lower())
    openai_api_key: str = Field(default_factory=lambda: getenv("OPENAI_API_KEY", ""))
    openai_model: str = Field(default_factory=lambda: getenv("OPENAI_MODEL", "gpt-5.2-codex"))
    aws_region: str = Field(default_factory=lambda: getenv("AWS_REGION", "us-east-1"))
    bedrock_model_id: str = Field(
        default_factory=lambda: getenv(
            "BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20240620-v1:0"
        )
    )
    bedrock_enabled: bool = Field(
        default_factory=lambda: getenv("BEDROCK_ENABLED", "false").lower() == "true"
    )

    opa_enabled: bool = Field(default_factory=lambda: getenv("OPA_ENABLED", "false").lower() == "true")
    opa_url: str = Field(default_factory=lambda: getenv("OPA_URL", ""))
    postgres_dsn: str = Field(default_factory=lambda: getenv("POSTGRES_DSN", ""))
    dynamodb_policy_table: str = Field(
        default_factory=lambda: getenv("DYNAMODB_POLICY_TABLE", "access-governance-policies")
    )
    dynamodb_audit_table: str = Field(
        default_factory=lambda: getenv("DYNAMODB_AUDIT_TABLE", "access-governance-audit")
    )

    default_tenant: str = Field(default_factory=lambda: getenv("DEFAULT_TENANT", "zoneone"))
    approval_threshold: int = Field(
        default_factory=lambda: int(getenv("APPROVAL_THRESHOLD", "65"))
    )
    rejection_threshold: int = Field(
        default_factory=lambda: int(getenv("REJECTION_THRESHOLD", "85"))
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
