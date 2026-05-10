# Policy Examples

This folder contains example policy data that can be loaded into Postgres, DynamoDB, or used as reference fixtures for the local in-memory demo.

The running service currently seeds a few in-memory policies in `app/services/policy_store.py`. These JSON files show how to model more realistic enterprise access policies.

## Files

- `abac_policies.json`: Attribute-based access control examples using subject and resource attributes.
- `iam_permission_sets.json`: IAM-style role/action permission examples.
- `risk_controls.json`: Risk scoring controls that explain why some requests need approval.

OPA/Rego policy examples live in `opa/policies`.

