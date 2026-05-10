package access.documents

default allow := false

allow if {
  input.resource.resource_type == "document"
  input.action == "read"
  input.resource.sensitivity in {"public", "internal"}
}

allow if {
  input.resource.resource_type == "document"
  input.action == "read"
  input.resource.sensitivity == "confidential"
  input.subject.role in {"auditor", "security", "admin"}
}

deny contains reason if {
  input.resource.resource_type == "document"
  input.action == "delete"
  reason := "Document delete access is blocked by policy."
}

