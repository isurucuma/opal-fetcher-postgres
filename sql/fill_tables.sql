-- Insert data into user_resource_whitelist table
INSERT INTO user_resource_whitelist (user_id, tenant_id, resource_id, action)
VALUES
  ('saman', '1', 'pool1', 'view'),
  ('saman', '1', 'pool1', 'edit'),
  ('udara', '1', 'filter1', 'view');

-- Insert data into user_resource_blacklist table
INSERT INTO user_resource_blacklist (user_id, tenant_id, resource_id, action)
VALUES
  ('saman', '1', 'pool3', 'edit'),
  ('gayan', '1', 'pool1', 'delete'),
  ('udara', '1', 'filter1', 'delete');

-- Insert data into role_resource_mapping table
INSERT INTO role_resource_mapping (role_id, tenant_id, resource_id, action)
VALUES
  ('nextgen', '1', 'pool3', 'view'),
  ('nextgen', '1', 'pool3', 'edit'),
  ('nextgen', '1', 'pool4', 'delete'),
  ('base_roduct', '1', 'filter1', 'edit');
