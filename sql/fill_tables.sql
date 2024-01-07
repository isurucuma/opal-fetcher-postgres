-- Insert data into user_resource_whitelist table
INSERT INTO user_resource_whitelist (user_id, tenant_id, resource_id, resource_type, action)
VALUES
  ('saman', '1', 'pool1', 'pool', 'view'),
  ('saman', '1', 'pool1', 'pool', 'edit'),
  ('udara', '1', 'filter1', 'filter', 'view');

-- Insert data into user_resource_blacklist table
INSERT INTO user_resource_blacklist (user_id, tenant_id, resource_id, resource_type, action)
VALUES
  ('saman', '1', 'pool3', 'pool', 'edit'),
  ('gayan', '1', 'pool1', 'pool', 'delete'),
  ('udara', '1', 'filter1', 'filter', 'delete');

-- Insert data into role_resource_mapping table
INSERT INTO role_resource_mapping (role_id, tenant_id, resource_id, resource_type, action)
VALUES
  ('nextgen', '1', 'pool3', 'pool', 'view'),
  ('nextgen', '1', 'pool3', 'pool', 'edit'),
  ('nextgen', '1', 'pool4', 'pool', 'delete'),
  ('base_roduct', '1', 'filter1', 'filter', 'edit');