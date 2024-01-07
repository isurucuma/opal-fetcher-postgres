-- Creation of user_resource_whitelist table
CREATE TABLE IF NOT EXISTS user_resource_whitelist (
  id SERIAL PRIMARY KEY,
  user_id VARCHAR(50) NOT NULL,
  tenant_id VARCHAR(50) NOT NULL,
  resource_id VARCHAR(50) NOT NULL,
  resource_type VARCHAR(50) NOT NULL, 
  action VARCHAR(50) NOT NULL,
  UNIQUE (user_id, tenant_id, resource_id, action)
);

-- Creation of user_resource_blacklist table
CREATE TABLE IF NOT EXISTS user_resource_blacklist (
  id SERIAL PRIMARY KEY,
  user_id VARCHAR(50) NOT NULL,
  tenant_id VARCHAR(50) NOT NULL,
  resource_id VARCHAR(50) NOT NULL,
  resource_type VARCHAR(50) NOT NULL, 
  action VARCHAR(50) NOT NULL,
  UNIQUE (user_id, tenant_id, resource_id, action)
);

-- Creation of role_resource_mapping table
CREATE TABLE IF NOT EXISTS role_resource_mapping (
  id SERIAL PRIMARY KEY,
  role_id VARCHAR(50) NOT NULL,
  tenant_id VARCHAR(50) NOT NULL,
  resource_id VARCHAR(50) NOT NULL,
  resource_type VARCHAR(50) NOT NULL, 
  action VARCHAR(50) NOT NULL,
  UNIQUE (role_id, tenant_id, resource_id, action)
);
