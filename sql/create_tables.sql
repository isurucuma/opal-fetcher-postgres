-- Creation of user_resource_whitelist table
CREATE TABLE IF NOT EXISTS user_resource_whitelist (
  user_id VARCHAR(50) NOT NULL,
  tenant_id VARCHAR(50) NOT NULL,
  resource_id VARCHAR(50) NOT NULL,
  action varchar(50) NOT NULL,
  PRIMARY KEY (user_id, tenant_id, resource_id, action)
);

-- Creation of user_resource_blacklist table
CREATE TABLE IF NOT EXISTS user_resource_blacklist (
  user_id VARCHAR(50) NOT NULL,
  tenant_id VARCHAR(50) NOT NULL,
  resource_id VARCHAR(50) NOT NULL,
  action varchar(50) NOT NULL,
  PRIMARY KEY (user_id, tenant_id, resource_id, action)
);

-- Creation of role resource mapping table
CREATE TABLE IF NOT EXISTS role_resource_mapping (
  role_id VARCHAR(50) NOT NULL,
  tenant_id VARCHAR(50) NOT NULL,
  resource_id VARCHAR(50) NOT NULL,
  action varchar(50) NOT NULL,
  PRIMARY KEY (role_id, tenant_id, resource_id, action)
);