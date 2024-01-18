package policy_test

import data.policy.allow_resource_add
import data.policy.allow_resource_access
import data.policy.set_of_accessible_resources

test_should_not_allow_without_admin_or_publisher {
    not allow_resource_add
    with input as {
        "user": {
        "roles": [
            "role_user"
        ]
    }
    }  
}

test_should_allow_resource_add_for_admin {
    allow_resource_add
    with input as {
        "user": {
        "roles": [
            "role_admin"
        ]
    }
    }  
}

test_should_allow_resource_add_for_publisher {
    allow_resource_add
    with input as {
        "user": {
        "roles": [
            "role_publisher"
        ]
    }
    }        
}

test_should_allow_any_resource_access_to_admin {
    allow_resource_access
    with input as {
        "user": {
        "roles": [
            "role_admin"
        ]
    }
    }
}

test_should_allow_with_whitelist_access_resource {
    allow_resource_access
    with input as {
        "user": {
            "user_id": "user1",
        "tenant_id": "1",
        "resource_id": "pool4",
        "resource_type": "pool",
        "action": "view",
        "roles": ["role_publisher"]
        }
        
    }

    with data.user_resource_whitelist as [
        {
            "id": 1,
            "user_id": "user2",
            "tenant_id": "1",
            "action": "view",
            "resource_id": "pool4",
            "resource_type": "pool"            
        },
        {
            "id": 1,
            "user_id": "user1",
            "tenant_id": "1",
            "action": "view",
            "resource_id": "pool4",
            "resource_type": "pool"            
        }
    ]
}

test_should_allow_non_access_controlled_resource {
    allow_resource_access
    with input as {
        "user": {
            "user_id": "user1",
        "tenant_id": "1",
        "resource_id": "pool10",
        "resource_type": "pool",
        "action": "view",
        "roles": ["role_publisher"]
        }
        
    }

    with data.user_resource_whitelist as [
        {
            "id": 1,
            "user_id": "user2",
            "tenant_id": "1",
            "action": "view",
            "resource_id": "pool4",
            "resource_type": "pool"            
        },
        {
            "id": 1,
            "user_id": "user1",
            "tenant_id": "1",
            "action": "view",
            "resource_id": "pool4",
            "resource_type": "pool"            
        }
    ]
}

test_should_block_non_access_controlled_resource_without_publisher_role {
    not allow_resource_access
    with input as {
        "user": {
            "user_id": "user1",
        "tenant_id": "1",
        "resource_id": "pool10",
        "resource_type": "pool",
        "action": "view",
        "roles": ["role_something"]
        }
        
    }

    with data.user_resource_whitelist as [
        {
            "id": 1,
            "user_id": "user2",
            "tenant_id": "1",
            "action": "view",
            "resource_id": "pool4",
            "resource_type": "pool"            
        },
        {
            "id": 1,
            "user_id": "user1",
            "tenant_id": "1",
            "action": "view",
            "resource_id": "pool4",
            "resource_type": "pool"            
        }
    ]
}

test_should_block_access_controlled_resource_with_whitelisted_but_without_publisher_role {
    not allow_resource_access
    with input as {
        "user": {
            "user_id": "user1",
        "tenant_id": "1",
        "resource_id": "pool10",
        "resource_type": "pool",
        "action": "view",
        "roles": ["role_something"]
        }
        
    }

    with data.user_resource_whitelist as [
        {
            "id": 1,
            "user_id": "user1",
            "tenant_id": "1",
            "action": "view",
            "resource_id": "pool10",
            "resource_type": "pool"            
        },
        {
            "id": 1,
            "user_id": "user1",
            "tenant_id": "1",
            "action": "view",
            "resource_id": "pool4",
            "resource_type": "pool"            
        }
    ]
}

test_should_block_access_controlled_resource_with_role_mapping_but_without_publisher_role {
    not allow_resource_access
    with input as {
        "user": {
            "user_id": "user1",
        "tenant_id": "1",
        "resource_id": "pool10",
        "resource_type": "pool",
        "action": "view",
        "roles": ["role_something"]
        }
    }

    with data.role_resource_mapping as [
        {
            "id": 1,
            "role_id": "role_something",
            "tenant_id": "1",
            "action": "view",
            "resource_id": "pool10",
            "resource_type": "pool"            
        }
    ]
}

test_should_block_access_controlled_resource {
    not allow_resource_access
    with input as {
        "user": {
            "user_id": "user1",
        "tenant_id": "1",
        "resource_id": "pool4",
        "resource_type": "pool",
        "action": "delete",
        "roles": ["role_publisher"]
        }
        
    }

    with data.user_resource_whitelist as [
        {
            "id": 1,
            "user_id": "user2",
            "tenant_id": "1",
            "action": "view",
            "resource_id": "pool4",
            "resource_type": "pool"            
        },
        {
            "id": 1,
            "user_id": "user2",
            "tenant_id": "1",
            "action": "delete",
            "resource_id": "pool4",
            "resource_type": "pool"            
        }
    ]
}


test_should_allow_role_allowed_resource {
    allow_resource_access
    with input as {
        "user": {
            "user_id": "user1",
            "tenant_id": "1",
            "resource_id": "pool3",
            "resource_type": "pool",
            "action": "view",
            "roles": ["role_publisher", "nextgen"]
        }
        
    }

    with data.role_resource_mapping as [
        {
            "id": 1,
            "action": "view",
            "resource_id": "pool3",
            "resource_type": "pool",
            "role_id": "nextgen",
            "tenant_id": "1"
        }
    ]
}

test_should_block_role_allowed_blacklisted_resource {
    not allow_resource_access
    with input as {
        "user": {
            "user_id": "user1",
            "tenant_id": "1",
            "resource_id": "pool3",
            "resource_type": "pool",
            "action": "view",
            "roles": ["role_publisher", "nextgen"]
        }
        
    }

    with data.role_resource_mapping as [
        {
            "id": 1,
            "action": "view",
            "resource_id": "pool3",
            "resource_type": "pool",
            "role_id": "nextgen",
            "tenant_id": "1"
        }
    ]

    with data.user_resource_blacklist as [
        {
            "id": 1,
            "action": "view",
            "resource_id": "pool3",
            "resource_type": "pool",
            "tenant_id": "1",
            "user_id": "user1"
        }
    ]
}

# checking action ............................................................
test_check_action_matching_whitelist_access_resource {
    not allow_resource_access
    with input as {
        "user": {
            "user_id": "user1",
        "tenant_id": "1",
        "resource_id": "pool3",
        "resource_type": "pool",
        "action": "view",
        "roles": ["role_publisher"]
        }
        
    }

    with data.user_resource_whitelist as [
        {
            "id": 1,
            "user_id": "user1",
            "tenant_id": "1",
            "action": "delte",
            "resource_id": "pool3",
            "resource_type": "pool"            
        }
    ]
}

test_check_action_matching_for_role_mapping {
    not allow_resource_access
    with input as {
        "user": {
            "user_id": "user1",
            "tenant_id": "1",
            "resource_id": "pool3",
            "resource_type": "pool",
            "action": "view",
            "roles": ["role_publisher", "nextgen"]
        }
        
    }

    with data.role_resource_mapping as [
        {
            "id": 1,
            "action": "edit",
            "resource_id": "pool3",
            "resource_type": "pool",
            "role_id": "nextgen",
            "tenant_id": "1"
        }
    ]
}


test_check_action_for_role_allowed_blacklisted_resource {
    allow_resource_access
    with input as {
        "user": {
            "user_id": "user1",
            "tenant_id": "1",
            "resource_id": "pool3",
            "resource_type": "pool",
            "action": "view",
            "roles": ["role_publisher", "nextgen"]
        }
        
    }

    with data.role_resource_mapping as [
        {
            "id": 1,
            "action": "view",
            "resource_id": "pool3",
            "resource_type": "pool",
            "role_id": "nextgen",
            "tenant_id": "1"
        }
    ]

    with data.user_resource_blacklist as [
        {
            "id": 1,
            "action": "edit",
            "resource_id": "pool3",
            "resource_type": "pool",
            "tenant_id": "1",
            "user_id": "user1"
        }
    ]
}

# checking userid .......................................................
test_check_userid_matching_whitelist_access_resource {
    not allow_resource_access
    with input as {
        "user": {
            "user_id": "user1",
        "tenant_id": "1",
        "resource_id": "pool3",
        "resource_type": "pool",
        "action": "view",
        "roles": ["role_publisher"]
        }
        
    }

    with data.user_resource_whitelist as [
        {
            "id": 1,
            "user_id": "user2",
            "tenant_id": "1",
            "action": "delte",
            "resource_id": "pool3",
            "resource_type": "pool"            
        }
    ]
}

test_check_roleid_matching_for_role_mapping {
    not allow_resource_access
    with input as {
        "user": {
            "user_id": "user1",
            "tenant_id": "1",
            "resource_id": "pool3",
            "resource_type": "pool",
            "action": "view",
            "roles": ["role_publisher", "nextgen2"]
        }
        
    }

    with data.role_resource_mapping as [
        {
            "id": 1,
            "action": "edit",
            "resource_id": "pool3",
            "resource_type": "pool",
            "role_id": "nextgen",
            "tenant_id": "1"
        }
    ]
}


test_check_userid_for_role_allowed_blacklisted_resource {
    allow_resource_access
    with input as {
        "user": {
            "user_id": "user1",
            "tenant_id": "1",
            "resource_id": "pool3",
            "resource_type": "pool",
            "action": "view",
            "roles": ["role_publisher", "nextgen"]
        }
        
    }

    with data.role_resource_mapping as [
        {
            "id": 1,
            "action": "view",
            "resource_id": "pool3",
            "resource_type": "pool",
            "role_id": "nextgen",
            "tenant_id": "1"
        }
    ]

    with data.user_resource_blacklist as [
        {
            "id": 1,
            "action": "edit",
            "resource_id": "pool3",
            "resource_type": "pool",
            "tenant_id": "1",
            "user_id": "user2"
        }
    ]
}

# checking tenantid ............................................................
test_not_allow_whitelistd_access_resource_in_different_tenant {
    not allow_resource_access
    with input as {
        "user": {
        "user_id": "user1",
        "tenant_id": "1",
        "resource_id": "pool3",
        "resource_type": "pool",
        "action": "view",
        "roles": ["role_publisher"]
        }
        
    }

    with data.user_resource_whitelist as [
        {
            "id": 1,
            "user_id": "user2",
            "tenant_id": "1",
            "action": "view",
            "resource_id": "pool3",
            "resource_type": "pool"            
        },
        {
            "id": 1,
            "user_id": "user1",
            "tenant_id": "2",
            "action": "view",
            "resource_id": "pool3",
            "resource_type": "pool"            
        }
    ]
}

test_allow_non_access_controlled_resource_in_different_tenant {
    allow_resource_access
    with input as {
        "user": {
        "user_id": "user1",
        "tenant_id": "1",
        "resource_id": "pool3",
        "resource_type": "pool",
        "action": "view",
        "roles": ["role_publisher"]
        }
    }

    with data.user_resource_whitelist as [
        {
            "id": 1,
            "user_id": "user2",
            "tenant_id": "2",
            "action": "view",
            "resource_id": "pool3",
            "resource_type": "pool"            
        }
    ]
}

# check getting list of accessible resources ............................................................

test_admin_should_get_all_resources_irrespective_of_access_control {
    set_of_accessible_resources == {
        "pool1",
        "pool2",
        "pool3",
        "pool4",
        "pool5"
    }

    with input as {
        "user": {
        "user_id": "user1",
        "tenant_id": "1",
        "resource_id": "pool3",
        "resource_type": "pool",
        "action": "view",
        "roles": ["role_admin"],
        "resource_ids": [
            "pool1",
            "pool2",
            "pool3",
            "pool4",
            "pool5"
        ]
        }
    }

    with data.user_resource_whitelist as [
        {
            "id": 1,
            "user_id": "user2",
            "tenant_id": "2",
            "action": "view",
            "resource_id": "pool3",
            "resource_type": "pool"            
        }
    ]
}

test_publisher_should_get_list_of_non_access_controlled_resources {
    set_of_accessible_resources == {
        "pool4",
        "pool5"
    }

    with input as {
        "user": {
        "user_id": "user1",
        "tenant_id": "2",
        "resource_type": "pool",
        "action": "view",
        "roles": ["role_publisher"],
        "resource_ids": [
            "pool1",
            "pool2",
            "pool3",
            "pool4",
            "pool5"
        ]
        }
    }

    with data.user_resource_whitelist as [
        {
            "id": 1,
            "user_id": "user5",
            "tenant_id": "2",
            "action": "view",
            "resource_id": "pool1",
            "resource_type": "pool"            
        },
        {
            "id": 1,
            "user_id": "user6",
            "tenant_id": "2",
            "action": "view",
            "resource_id": "pool2",
            "resource_type": "pool"            
        },
        {
            "id": 1,
            "user_id": "user7",
            "tenant_id": "2",
            "action": "view",
            "resource_id": "pool3",
            "resource_type": "pool"            
        }
    ]
}


test_publisher_should_get_list_of_accessible_resources {
    set_of_accessible_resources == {
        "pool4",
        "pool5",
        "pool1",
    }

    with input as {
        "user": {
        "user_id": "user1",
        "tenant_id": "2",
        "resource_type": "pool",
        "action": "view",
        "roles": ["role_publisher"],
        "resource_ids": [
            "pool1",
            "pool2",
            "pool3",
            "pool4",
            "pool5"
        ]
        }
    }

    with data.user_resource_whitelist as [
        {
            "id": 1,
            "user_id": "user1",
            "tenant_id": "2",
            "action": "view",
            "resource_id": "pool1",
            "resource_type": "pool"            
        },
        {
            "id": 1,
            "user_id": "user6",
            "tenant_id": "2",
            "action": "view",
            "resource_id": "pool2",
            "resource_type": "pool"            
        },
        {
            "id": 1,
            "user_id": "user7",
            "tenant_id": "2",
            "action": "view",
            "resource_id": "pool3",
            "resource_type": "pool"            
        }
    ]
}

test_non_publisher_should_not_get_list_of_any_resources {
    count(set_of_accessible_resources) == 0

    with input as {
        "user": {
        "user_id": "user1",
        "tenant_id": "2",
        "resource_type": "pool",
        "action": "view",
        "roles": ["role_something"],
        "resource_ids": [
            "pool1",
            "pool2",
            "pool3",
            "pool4",
            "pool5"
        ]
        }
    }

    with data.user_resource_whitelist as [
        {
            "id": 1,
            "user_id": "user1",
            "tenant_id": "2",
            "action": "view",
            "resource_id": "pool1",
            "resource_type": "pool"            
        },
        {
            "id": 1,
            "user_id": "user6",
            "tenant_id": "2",
            "action": "view",
            "resource_id": "pool2",
            "resource_type": "pool"            
        },
        {
            "id": 1,
            "user_id": "user7",
            "tenant_id": "2",
            "action": "view",
            "resource_id": "pool3",
            "resource_type": "pool"            
        }
    ]
}


test_publisher_should_get_list_of_accessible_resources_check_tenant {
    set_of_accessible_resources == {
        "pool1",
        "pool2",
        "pool3",
        "pool4",
        "pool5"
    }

    with input as {
        "user": {
        "user_id": "user1",
        "tenant_id": "1",
        "resource_type": "pool",
        "action": "view",
        "roles": ["role_publisher"],
        "resource_ids": [
            "pool1",
            "pool2",
            "pool3",
            "pool4",
            "pool5"
        ]
        }
    }

    with data.user_resource_whitelist as [
        {
            "id": 1,
            "user_id": "user1",
            "tenant_id": "2",
            "action": "view",
            "resource_id": "pool1",
            "resource_type": "pool"            
        },
        {
            "id": 1,
            "user_id": "user6",
            "tenant_id": "2",
            "action": "view",
            "resource_id": "pool2",
            "resource_type": "pool"            
        },
        {
            "id": 1,
            "user_id": "user7",
            "tenant_id": "2",
            "action": "view",
            "resource_id": "pool3",
            "resource_type": "pool"            
        }
    ]
}

