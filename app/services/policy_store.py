import json
from pathlib import Path
from typing import Any, Protocol

from app.config import Settings
from app.models import AuditRecord, StoredPolicy


class PolicyStore(Protocol):
    def list_policies(self, tenant_id: str) -> list[StoredPolicy]:
        ...

    def reload_policies(self) -> int:
        ...

    def save_audit(self, record: AuditRecord) -> None:
        ...

    def get_audit(self, request_id: str) -> AuditRecord | None:
        ...


class InMemoryPolicyStore:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings
        self._audit: dict[str, AuditRecord] = {}
        self._policies = [
            StoredPolicy(
                policy_id="abac-department-match",
                tenant_id="zoneone",
                name="Allow same-department access to internal resources",
                effect="allow",
                conditions={"department_matches_owner": True, "max_sensitivity": "internal"},
            ),
            StoredPolicy(
                policy_id="deny-restricted-without-clearance",
                tenant_id="zoneone",
                name="Deny restricted data without restricted clearance",
                effect="deny",
                conditions={"sensitivity": "restricted", "required_clearance": "restricted"},
            ),
            StoredPolicy(
                policy_id="iam-admin-write",
                tenant_id="zoneone",
                name="Admins and security may write governed resources",
                effect="allow",
                conditions={"roles": ["admin", "security"], "actions": ["write", "admin"]},
            ),
        ]
        self.reload_policies()

    def list_policies(self, tenant_id: str) -> list[StoredPolicy]:
        return [policy for policy in self._policies if policy.tenant_id == tenant_id]

    def reload_policies(self) -> int:
        if self.settings is None:
            return len(self._policies)

        loaded = _load_stored_policies(Path(self.settings.policy_dir))
        existing_ids = {policy.policy_id for policy in self._policies}
        for policy in loaded:
            if policy.policy_id not in existing_ids:
                self._policies.append(policy)
                existing_ids.add(policy.policy_id)
        return len(self._policies)

    def save_audit(self, record: AuditRecord) -> None:
        self._audit[record.request_id] = record

    def get_audit(self, request_id: str) -> AuditRecord | None:
        return self._audit.get(request_id)


class PostgresPolicyStore(InMemoryPolicyStore):
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        if not settings.postgres_dsn:
            raise ValueError("POSTGRES_DSN is required for STORAGE_BACKEND=postgres")
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError("psycopg is required for STORAGE_BACKEND=postgres") from exc

        self.psycopg = psycopg
        self._ensure_schema()

    def reload_policies(self) -> int:
        loaded = _load_stored_policies(Path(self.settings.policy_dir))
        with self.psycopg.connect(self.settings.postgres_dsn) as conn:
            for policy in loaded:
                conn.execute(
                    """
                    INSERT INTO policies (policy_id, tenant_id, name, effect, conditions)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (policy_id) DO UPDATE SET
                        tenant_id = EXCLUDED.tenant_id,
                        name = EXCLUDED.name,
                        effect = EXCLUDED.effect,
                        conditions = EXCLUDED.conditions
                    """,
                    (
                        policy.policy_id,
                        policy.tenant_id,
                        policy.name,
                        policy.effect,
                        json.dumps(policy.conditions),
                    ),
                )
        return len(loaded)

    def list_policies(self, tenant_id: str) -> list[StoredPolicy]:
        with self.psycopg.connect(self.settings.postgres_dsn) as conn:
            rows = conn.execute(
                """
                SELECT policy_id, tenant_id, name, effect, conditions
                FROM policies
                WHERE tenant_id = %s
                ORDER BY policy_id
                """,
                (tenant_id,),
            ).fetchall()
        return [
            StoredPolicy(
                policy_id=row[0],
                tenant_id=row[1],
                name=row[2],
                effect=row[3],
                conditions=_json_loads(row[4]),
            )
            for row in rows
        ]

    def save_audit(self, record: AuditRecord) -> None:
        with self.psycopg.connect(self.settings.postgres_dsn) as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (
                    request_id, tenant_id, user_id, resource_id, action,
                    decision, risk_score, trace, created_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (request_id) DO UPDATE SET
                    decision = EXCLUDED.decision,
                    risk_score = EXCLUDED.risk_score,
                    trace = EXCLUDED.trace
                """,
                (
                    record.request_id,
                    record.tenant_id,
                    record.user_id,
                    record.resource_id,
                    record.action,
                    record.decision.value,
                    record.risk_score,
                    json.dumps([item.model_dump(mode="json") for item in record.trace]),
                    record.created_at,
                ),
            )

    def get_audit(self, request_id: str) -> AuditRecord | None:
        with self.psycopg.connect(self.settings.postgres_dsn) as conn:
            row = conn.execute(
                """
                SELECT request_id, tenant_id, user_id, resource_id, action,
                       decision, risk_score, trace, created_at
                FROM audit_logs
                WHERE request_id = %s
                """,
                (request_id,),
            ).fetchone()
        if row is None:
            return None
        return AuditRecord(
            request_id=row[0],
            tenant_id=row[1],
            user_id=row[2],
            resource_id=row[3],
            action=row[4],
            decision=row[5],
            risk_score=row[6],
            trace=_json_loads(row[7]),
            created_at=row[8],
        )

    def _ensure_schema(self) -> None:
        with self.psycopg.connect(self.settings.postgres_dsn) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS policies (
                    policy_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    effect TEXT NOT NULL,
                    conditions JSONB NOT NULL DEFAULT '{}'::jsonb
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_logs (
                    request_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    trace JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL
                )
                """
            )


class DynamoDBPolicyStore(InMemoryPolicyStore):
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError("boto3 is required for STORAGE_BACKEND=dynamodb") from exc
        dynamodb = boto3.resource("dynamodb", region_name=settings.aws_region)
        self.policy_table = dynamodb.Table(settings.dynamodb_policy_table)
        self.audit_table = dynamodb.Table(settings.dynamodb_audit_table)

    def reload_policies(self) -> int:
        loaded = _load_stored_policies(Path(self.settings.policy_dir))
        for policy in loaded:
            self.policy_table.put_item(Item=policy.model_dump(mode="json"))
        return len(loaded)

    def list_policies(self, tenant_id: str) -> list[StoredPolicy]:
        response = self.policy_table.query(
            KeyConditionExpression="tenant_id = :tenant_id",
            ExpressionAttributeValues={":tenant_id": tenant_id},
        )
        return [StoredPolicy(**item) for item in response.get("Items", [])]

    def save_audit(self, record: AuditRecord) -> None:
        self.audit_table.put_item(Item=record.model_dump(mode="json"))

    def get_audit(self, request_id: str) -> AuditRecord | None:
        response = self.audit_table.get_item(Key={"request_id": request_id})
        item = response.get("Item")
        return AuditRecord(**item) if item else None


def build_policy_store(settings: Settings) -> PolicyStore:
    if settings.storage_backend == "postgres":
        return PostgresPolicyStore(settings)
    if settings.storage_backend == "dynamodb":
        return DynamoDBPolicyStore(settings)
    return InMemoryPolicyStore(settings)


def _json_loads(value: Any) -> Any:
    if isinstance(value, str):
        return json.loads(value)
    return value


def _load_stored_policies(policy_dir: Path) -> list[StoredPolicy]:
    policy_file = policy_dir / "abac_policies.json"
    if not policy_file.exists():
        return []

    with policy_file.open("r", encoding="utf-8") as file:
        raw_policies = json.load(file)

    return [
        StoredPolicy(
            policy_id=item["policy_id"],
            tenant_id=item.get("tenant_id", "zoneone"),
            name=item["name"],
            effect=item["effect"],
            conditions=item.get("conditions", {}),
        )
        for item in raw_policies
    ]
