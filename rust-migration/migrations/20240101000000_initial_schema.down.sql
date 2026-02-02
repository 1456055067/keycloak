-- Rollback initial schema

-- Drop triggers first
DROP TRIGGER IF EXISTS update_groups_updated_at ON groups;
DROP TRIGGER IF EXISTS update_roles_updated_at ON roles;
DROP TRIGGER IF EXISTS update_clients_updated_at ON clients;
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP TRIGGER IF EXISTS update_realms_updated_at ON realms;

-- Drop function
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop tables in reverse dependency order
DROP TABLE IF EXISTS single_use_objects;
DROP TABLE IF EXISTS realm_localization_texts;
DROP TABLE IF EXISTS user_federation_mappers;
DROP TABLE IF EXISTS user_federation_providers;
DROP TABLE IF EXISTS required_actions;
DROP TABLE IF EXISTS admin_events;
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS client_sessions;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS identity_provider_mappers;
DROP TABLE IF EXISTS identity_providers;
DROP TABLE IF EXISTS authenticator_configs;
DROP TABLE IF EXISTS authentication_executions;
DROP TABLE IF EXISTS authentication_flows;
DROP TABLE IF EXISTS protocol_mappers;
DROP TABLE IF EXISTS client_scope_mappings;
DROP TABLE IF EXISTS client_scopes;
DROP TABLE IF EXISTS user_group_memberships;
DROP TABLE IF EXISTS user_role_mappings;
DROP TABLE IF EXISTS credentials;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS clients;
DROP TABLE IF EXISTS federated_identities;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS realms;
