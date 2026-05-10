package access

default allow := false

allow if {
  input.action == "read"
  input.resource.sensitivity == "internal"
}

allow if {
  input.subject.department == input.resource.owner_department
  input.resource.sensitivity != "restricted"
}

allow if {
  input.subject.clearance == "restricted"
  input.resource.sensitivity == "restricted"
  input.action != "delete"
}

allow if {
  input.subject.role in {"admin", "security"}
  input.action in {"read", "invoke", "write", "admin"}
}
