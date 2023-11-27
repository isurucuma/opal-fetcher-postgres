package policy

import future.keywords.in

default allow := false

allow {
	"admin" in input.user.roles
}

allow {
	user_in_whitelist
}

allow {
	user_role_has_mapping
	not user_in_blacklist
}

user_in_whitelist {
	some user_resource in data.user_resource_whitelist
	user_resource.user_id == input.user.user_id
	user_resource.tenant_id == input.user.tenant_id
	user_resource.resource_id == input.user.resource_id
	user_resource.action == input.user.action
}

user_in_blacklist {
	some user_resource in data.user_resource_blacklist
	user_resource.user_id == input.user.user_id
	user_resource.tenant_id == input.user.tenant_id
	user_resource.resource_id == input.user.resource_id
	user_resource.action == input.user.action
}

user_role_has_mapping {
	some user_role in input.user.roles
	some role_resource in data.role_resource_mapping
	role_resource.role_id == user_role
	role_resource.tenant_id == input.user.tenant_id
	role_resource.resource_id == input.user.resource_id
	role_resource.action == input.user.action
}
