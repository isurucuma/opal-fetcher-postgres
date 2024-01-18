package policy

import future.keywords.in

default allow_resource_access := false

is_admin {
	"role_admin" in input.user.roles
}

is_publisher {
	"role_publisher" in input.user.roles
}

is_publisher {
	is_admin
}

allow_resource_add {
	is_admin
}

allow_resource_add {
	is_publisher
}

allow_resource_access {
	is_admin
}

allow_resource_access {
	is_not_fine_grained_enabled_resource
	is_publisher
}

allow_resource_access {
	user_in_whitelist
	is_publisher
}

allow_resource_access {
	user_role_has_mapping
	not user_in_blacklist
	is_publisher
}

user_in_whitelist {
	some user_resource in data.user_resource_whitelist
	user_resource.user_id == input.user.user_id
	user_resource.tenant_id == input.user.tenant_id
	user_resource.resource_id == input.user.resource_id
	user_resource.resource_type == input.user.resource_type
	user_resource.action == input.user.action
}

user_in_blacklist {
	some user_resource in data.user_resource_blacklist
	user_resource.user_id == input.user.user_id
	user_resource.tenant_id == input.user.tenant_id
	user_resource.resource_id == input.user.resource_id
	user_resource.resource_type == input.user.resource_type
	user_resource.action == input.user.action
}

user_role_has_mapping {
	some user_role in input.user.roles
	some role_resource in data.role_resource_mapping
	role_resource.role_id == user_role
	role_resource.tenant_id == input.user.tenant_id
	role_resource.resource_id == input.user.resource_id
	role_resource.resource_type == input.user.resource_type
	role_resource.action == input.user.action
}

is_not_fine_grained_enabled_resource {
	not is_resource_has_role_mapping
	not is_resource_has_user_whitelist_mapping
	not is_resource_has_user_blacklist_mapping
}

is_resource_has_user_whitelist_mapping {
	some resource in data.user_resource_whitelist
	resource.resource_id == input.user.resource_id
	resource.resource_type == input.user.resource_type
	resource.tenant_id == input.user.tenant_id
}

is_resource_has_user_blacklist_mapping {
	some resource in data.user_resource_blacklist
	resource.resource_id == input.user.resource_id
	resource.resource_type == input.user.resource_type
	resource.tenant_id == input.user.tenant_id
}

is_resource_has_role_mapping {
	some resource in data.role_resource_mapping
	resource.resource_id == input.user.resource_id
	resource.resource_type == input.user.resource_type
	resource.tenant_id == input.user.tenant_id
}

set_of_access_controlled_resources[item.resource_id] {
	some item in data.user_resource_whitelist
	item.resource_type == input.user.resource_type
    item.tenant_id == input.user.tenant_id
	item.action == "view"
}

set_of_access_controlled_resources[item.resource_id] {
	some item in data.role_resource_mapping
	item.resource_type == input.user.resource_type
	item.action == "view"
}

set_all_resource_ids[resource] {
	some resource in input.user.resource_ids
}

set_of_free_resources := set_all_resource_ids - set_of_access_controlled_resources

set_of_accessible_resources[resource] {
   	is_admin
	some resource in input.user.resource_ids
}

set_of_accessible_resources[item] {
	allow_resource_add
    not is_admin
	some item in set_of_free_resources
}

set_of_accessible_resources[item.resource_id] {
	allow_resource_add
    not is_admin
	some item in data.user_resource_whitelist
	item.resource_type == input.user.resource_type
	item.action == "view"
	item.user_id == input.user.user_id
	item.tenant_id == input.user.tenant_id
}

blacklist_of_user_blocked_resources[item.resource_id] {
	some item in data.user_resource_blacklist
	item.resource_type == input.user.resource_type
	item.action == "view"
	item.user_id == input.user.user_id
	item.tenant_id == input.user.tenant_id
}

set_of_accessible_resources[item.resource_id] {
	allow_resource_add
    not is_admin
	some item in data.role_resource_mapping
	item.resource_type == input.user.resource_type
	item.action == "view"
	item.role_id in input.user.roles
	item.tenant_id == input.user.tenant_id
	not item.resource_id in blacklist_of_user_blocked_resources
}
