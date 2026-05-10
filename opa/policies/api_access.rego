package access.apis

default allow := false

allow if {
  input.resource.resource_type == "api"
  input.action in {"read", "invoke"}
  input.subject.role in {"developer", "service-owner", "security", "admin"}
}

allow if {
  input.resource.resource_type == "api"
  input.action in {"write", "admin"}
  input.subject.role in {"service-owner", "security", "admin"}
  input.resource.sensitivity != "restricted"
}

deny contains reason if {
  input.resource.resource_type == "api"
  input.resource.sensitivity == "restricted"
  input.subject.clearance != "restricted"
  reason := "Restricted API access requires restricted clearance."
}

