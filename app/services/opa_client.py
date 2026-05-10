import json
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from app.config import Settings


class OPAClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    def evaluate(self, input_payload: dict[str, Any]) -> tuple[bool, list[str]]:
        if not self.settings.opa_enabled or not self.settings.opa_url:
            return self._local_evaluate(input_payload)

        request = Request(
            f"{self.settings.opa_url.rstrip('/')}/v1/data/access/allow",
            data=json.dumps({"input": input_payload}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=3) as response:
                payload = json.loads(response.read().decode("utf-8"))
                return bool(payload.get("result")), []
        except (OSError, URLError, json.JSONDecodeError) as exc:
            return False, [f"OPA evaluation failed: {exc}"]

    @staticmethod
    def _local_evaluate(input_payload: dict[str, Any]) -> tuple[bool, list[str]]:
        subject = input_payload["subject"]
        resource = input_payload["resource"]
        action = input_payload["action"]

        if action == "delete":
            return False, ["Delete access requires a break-glass workflow."]
        if resource["sensitivity"] == "restricted" and subject["clearance"] != "restricted":
            return False, ["Restricted resources require restricted clearance."]
        if (
            resource["sensitivity"] == "confidential"
            and subject["department"] != resource["owner_department"]
            and subject["role"] not in {"security", "admin", "auditor"}
        ):
            return False, ["Confidential cross-department access needs elevated role."]
        return True, []
