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
	some user_resource in user_resources_whitelist
	user_resource.user_id == input.user.user_id
	user_resource.tenant_id == input.user.tenant_id
	user_resource.resource_id == input.user.resource_id
	user_resource.action == input.user.action
}

user_in_blacklist {
	some user_resource in user_resources_blacklist
	user_resource.user_id == input.user.user_id
	user_resource.tenant_id == input.user.tenant_id
	user_resource.resource_id == input.user.resource_id
	user_resource.action == input.user.action
}

user_role_has_mapping {
	some user_role in input.user.roles
	some role_resource in role_resources
	role_resource.role_id == user_role
	role_resource.tenant_id == input.user.tenant_id
	role_resource.resource_id == input.user.resource_id
	role_resource.action == input.user.action
}

user_resources_whitelist := [
	{"user_id": "saman", "tenant_id": "1", "resource_id": "pool1", "action": "view"},
	{"user_id": "saman", "tenant_id": "1", "resource_id": "pool1", "action": "edit"},
	{"user_id": "udara", "tenant_id": "1", "resource_id": "filter1", "action": "view"},
]

user_resources_blacklist := [
	{"user_id": "saman", "tenant_id": "1", "resource_id": "pool3", "action": "edit"},
	{"user_id": "gayan", "tenant_id": "1", "resource_id": "pool1", "action": "delete"},
	{"user_id": "udara", "tenant_id": "1", "resource_id": "filter1", "action": "delete"},
]

role_resources := [
	{"role_id": "nextgen", "tenant_id": "1", "resource_id": "pool3", "action": "view"},
	{"role_id": "nextgen", "tenant_id": "1", "resource_id": "pool3", "action": "edit"},
	{"role_id": "nextgen", "tenant_id": "1", "resource_id": "pool4", "action": "delete"},
	{"role_id": "base_roduct", "tenant_id": "1", "resource_id": "filter1", "action": "edit"},
]
