package access.dashboards

default allow := false

allow if {
  input.resource.resource_type == "dashboard"
  input.action == "read"
  input.resource.sensitivity != "restricted"
  input.subject.department == input.resource.owner_department
}

allow if {
  input.resource.resource_type == "dashboard"
  input.action == "read"
  input.subject.role in {"executive", "security", "admin"}
}

deny contains reason if {
  input.resource.resource_type == "dashboard"
  input.resource.sensitivity == "restricted"
  input.subject.clearance != "restricted"
  reason := "Restricted dashboards require restricted clearance."
}

