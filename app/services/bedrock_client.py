import json
from typing import Any

from app.config import Settings


class BedrockGateway:
    def __init__(self, settings: Settings):
        self.settings = settings

    def analyze_access_request(self, request_text: str) -> dict[str, Any]:
        if not self.settings.bedrock_enabled:
            return self._local_parse(request_text)

        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError("boto3 is required when BEDROCK_ENABLED=true") from exc

        client = boto3.client("bedrock-runtime", region_name=self.settings.aws_region)
        prompt = (
            "Extract access governance fields as compact JSON with keys "
            "resource_type, resource_id, action, sensitivity, business_justification. "
            f"Request: {request_text}"
        )
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 500,
            "messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}],
        }
        response = client.invoke_model(
            modelId=self.settings.bedrock_model_id,
            body=json.dumps(body),
            contentType="application/json",
            accept="application/json",
        )
        payload = json.loads(response["body"].read())
        text = payload["content"][0]["text"]
        return json.loads(text)

    def final_response(self, decision: str, facts: dict[str, Any]) -> str:
        if not self.settings.bedrock_enabled:
            return (
                f"Access {decision}. Resource `{facts['resource_id']}` was evaluated "
                f"with ABAC, IAM-style policy, OPA, and risk controls."
            )
        return (
            f"Access {decision}. Resource `{facts['resource_id']}` was evaluated with "
            "ABAC, IAM-style policy, OPA, and risk controls."
        )

    @staticmethod
    def _local_parse(request_text: str) -> dict[str, Any]:
        lowered = request_text.lower()
        resource_type = "unknown"
        for candidate in ("dashboard", "document", "api"):
            if candidate in lowered:
                resource_type = candidate
                break

        sensitivity = "internal"
        if any(word in lowered for word in ("restricted", "prod", "production", "pii")):
            sensitivity = "restricted"
        elif any(word in lowered for word in ("confidential", "finance", "payroll")):
            sensitivity = "confidential"

        action = "read"
        for candidate in ("admin", "write", "read", "invoke", "delete"):
            if candidate in lowered:
                action = candidate
                break

        resource_id = "unknown-resource"
        words = [word.strip(".,:;()[]{}'\"") for word in request_text.split()]
        for index, word in enumerate(words):
            if word.lower() in {"api", "document", "dashboard"} and index + 1 < len(words):
                resource_id = words[index + 1]
                break

        return {
            "resource_type": resource_type,
            "resource_id": resource_id,
            "action": action,
            "sensitivity": sensitivity,
            "business_justification": request_text,
        }
