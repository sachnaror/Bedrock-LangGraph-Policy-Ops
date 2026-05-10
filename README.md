# AI Access Governance Assistant

A FastAPI service where users request access to APIs, documents, and dashboards in natural language. The assistant analyzes the request with AWS Bedrock, runs a multi-agent LangGraph workflow, validates access with ABAC rules, IAM-style checks, and Open Policy Agent, then returns an approval, rejection, or manual-approval decision with full traceability.

## Architecture

```
├── Bedrock-Lang-Graph-Policy-Ops-AIenterprise/
│   ├── requirements.txt
│   ├── README.md
│   ├── .env
│   ├── docker-compose.yml
│   ├── .env.example
│   ├── app/
│   │   ├── config.py
│   │   ├── models.py
│   │   ├── main.py
│   │   └── dependencies.py
│   │   ├── agents/
│   │   │   ├── governance_graph.py
│   │   ├── api/
│   │   │   └── routes.py
│   │   ├── services/
│   │   │   ├── bedrock_client.py
│   │   │   ├── policy_engine.py
│   │   │   ├── policy_store.py
│   │   │   └── opa_client.py
│   │   ├── policy/
│   │   │   ├── iam_permission_sets.json
│   │   │   ├── README.md
│   │   │   ├── abac_policies.json
│   │   │   └── risk_controls.json
│   ├── tests/
│   │   └── test_governance_workflow.py
│   ├── opa/
│   │   ├── policies/
│   │   │   ├── access.rego
│   │   │   ├── document_access.rego
│   │   │   ├── dashboard_access.rego
│   │   │   └── api_access.rego


```

Request flow:

```text
User -> FastAPI -> Request Analyzer -> Policy Validator -> Risk Scorer -> Approval/Rejection Agent
```

Core components:

- `FastAPI`: HTTP API for access requests, policies, health, and audit retrieval.
- `Bedrock`: optional natural-language extraction and response generation through AWS Bedrock.
- `LangGraph`: orchestrates the multi-agent governance flow when installed.
- `OPA`: evaluates external Rego policies through `OPA_URL`, with a safe local fallback.
- `ABAC`: evaluates subject/resource attributes such as department, clearance, and sensitivity.
- `IAM-style checks`: validates action permissions against role-like rules.
- `Postgres or DynamoDB`: optional persistence for policies and audit logs.
- `python-dotenv`: loads `.env` values into runtime environment variables before settings are created.

## Agents

- `Request Analyzer`: extracts resource type, resource ID, action, sensitivity, and justification from natural language.
- `Policy Validator`: evaluates ABAC rules, IAM-style permissions, stored policies, and OPA.
- `Risk Scorer`: scores sensitivity, privileged action, long duration, and policy-denial risk.
- `Approval/Rejection Agent`: returns `approved`, `needs_approval`, or `rejected` with trace details.

Every response includes a `trace` array showing each agent's summary, details, and timestamp.

## Local Demo Setup

```bash
cd /Users/homesachin/Desktop/zoneone/Bedrock-Lang-Graph-Policy-Ops-AIenterprise
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Optional, but recommended for pretty console output:

```bash
pip install rich-cli
```

Run locally with in-memory storage, local deterministic parsing, file-backed policy examples, and local policy checks:

```bash
uvicorn app.main:app --reload
```

Open the API docs:

```text
http://localhost:8000/docs
```

No AWS credentials, OpenAI key, AI model, OPA server, Postgres, or DynamoDB table is required for the default local demo.

Try demo scenarios:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/demo/scenarios
curl http://localhost:8000/demo/run/approved-dashboard
curl http://localhost:8000/demo/run/manual-approval-payroll
curl http://localhost:8000/demo/run/rejected-production-api
```

The demo run endpoint accepts both `GET` and `POST`, so these also work:

```bash
curl -X POST http://localhost:8000/demo/run/approved-dashboard
curl -X POST http://localhost:8000/demo/run/manual-approval-payroll
curl -X POST http://localhost:8000/demo/run/rejected-production-api
```

Policy files in `app/policy` are loaded automatically in local memory mode when the app starts. If you edit those files while the server is running, reload them without restarting:

```bash
curl -X POST http://localhost:8000/policies/reload
curl http://localhost:8000/policies
```

Start OPA and Postgres:

```bash
docker compose up -d opa postgres
```

## Environment

`.env` is loaded by `python-dotenv` in `app/config.py`.

The committed [.env.example](/Users/homesachin/Desktop/zoneone/Bedrock-Lang-Graph-Policy-Ops-AIenterprise/.env.example) file is the dotenv template for GitHub users. It documents every supported runtime variable with safe placeholder values. Create your private `.env` from it:

```bash
cp .env.example .env
```

Real `.env` files are ignored by git, so secrets such as `AWS_SECRET_ACCESS_KEY` and `OPENAI_API_KEY` are not pushed.

Important values:

```bash
STORAGE_BACKEND=memory
LOCAL_DEMO_MODE=true
POLICY_DIR=app/policy
LLM_PROVIDER=local
BEDROCK_ENABLED=false
AWS_REGION=us-east-1
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20240620-v1:0
OPENAI_MODEL=gpt-5.2-codex
OPA_ENABLED=false
OPA_URL=http://localhost:8181
POSTGRES_DSN=postgresql://postgres:postgres@localhost:5432/access_governance
DYNAMODB_POLICY_TABLE=access-governance-policies
DYNAMODB_AUDIT_TABLE=access-governance-audit
```

Storage options:

- `STORAGE_BACKEND=memory`: demo mode with seeded policies and in-process audit records.
- `STORAGE_BACKEND=postgres`: creates `policies` and `audit_logs` tables automatically.
- `STORAGE_BACKEND=dynamodb`: uses `DYNAMODB_POLICY_TABLE` for policies and `DYNAMODB_AUDIT_TABLE` for audit records.

## Policy Files

Local policy examples live in `app/policy`:

- `abac_policies.json`: ABAC-style allow/deny policy examples loaded by the local memory store.
- `iam_permission_sets.json`: IAM-style role/action permission-set examples.
- `risk_controls.json`: risk scoring control examples used as documentation/reference.

OPA/Rego examples live in `opa/policies`:

- `access.rego`
- `api_access.rego`
- `dashboard_access.rego`
- `document_access.rego`

## Example Request

```bash
curl -X POST http://localhost:8000/access/request \
  -H "Content-Type: application/json" \
  -d '{
    "request_text": "Please give me read access to dashboard revenue-overview",
    "subject": {
      "user_id": "u-123",
      "department": "finance",
      "role": "employee",
      "clearance": "internal"
    },
    "requested_duration_hours": 8
  }'
```

Useful endpoints:

- `GET /health`
- `GET /demo/scenarios`
- `GET or POST /demo/run/{scenario_id}`
- `POST /access/request`
- `GET /policies?tenant_id=zoneone`
- `POST /policies/reload`
- `GET /audit/{request_id}`

## Tests

```bash
pytest tests -q
```

If dependencies are not installed yet, a lightweight syntax check still works with:

```bash
python3 -m compileall app tests
```



## 📩 Contact

| Name              | Details                             |
|-------------------|-------------------------------------|
| **👨‍💻 Developer**  | Sachin Arora                      |
| **📧 Email**      | [sachnaror@gmail.com](mailto:sacinaror@gmail.com) |
| **📍 Location**   | Noida, India                       |
| **📂 GitHub**     | [Link](https://github.com/sachnaror) |
| **🌐 Youtube**    | [Link](https://www.youtube.com/@sachnaror4841/videos) |
| **🌐 Blog**       | [Link](https://medium.com/@schnaror) |
| **🌐 Website**    | [Link](https://about.me/sachin-arora) |
| **🌐 Twitter**    | [Link](https://twitter.com/sachinhep) |
| **📱 Phone**      | [+91 9560330483](tel:+919560330483) |
