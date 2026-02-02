-- Initial schema for Keycloak Rust
-- This migration creates all core tables for the identity and access management system.

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- REALMS
-- ============================================================================
CREATE TABLE realms (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255),
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ssl_required VARCHAR(50) NOT NULL DEFAULT 'external',
    password_policy TEXT,
    otp_policy JSONB NOT NULL DEFAULT '{}',
    not_before BIGINT NOT NULL DEFAULT 0,

    -- Registration settings
    registration_allowed BOOLEAN NOT NULL DEFAULT false,
    registration_email_as_username BOOLEAN NOT NULL DEFAULT false,
    verify_email BOOLEAN NOT NULL DEFAULT false,
    reset_password_allowed BOOLEAN NOT NULL DEFAULT false,
    login_with_email_allowed BOOLEAN NOT NULL DEFAULT true,
    duplicate_emails_allowed BOOLEAN NOT NULL DEFAULT false,
    remember_me BOOLEAN NOT NULL DEFAULT false,
    edit_username_allowed BOOLEAN NOT NULL DEFAULT false,

    -- Token lifespans (in seconds)
    access_token_lifespan INT NOT NULL DEFAULT 300,
    access_token_lifespan_implicit INT NOT NULL DEFAULT 900,
    access_code_lifespan INT NOT NULL DEFAULT 60,
    access_code_lifespan_user_action INT NOT NULL DEFAULT 300,
    access_code_lifespan_login INT NOT NULL DEFAULT 1800,

    -- Session settings (in seconds)
    sso_session_idle_timeout INT NOT NULL DEFAULT 1800,
    sso_session_max_lifespan INT NOT NULL DEFAULT 36000,
    sso_session_idle_timeout_remember_me INT NOT NULL DEFAULT 0,
    sso_session_max_lifespan_remember_me INT NOT NULL DEFAULT 0,
    offline_session_idle_timeout INT NOT NULL DEFAULT 2592000,
    offline_session_max_lifespan INT NOT NULL DEFAULT 5184000,

    -- Themes
    login_theme VARCHAR(255),
    account_theme VARCHAR(255),
    admin_theme VARCHAR(255),
    email_theme VARCHAR(255),

    -- Events
    events_enabled BOOLEAN NOT NULL DEFAULT false,
    events_expiration BIGINT NOT NULL DEFAULT 0,
    admin_events_enabled BOOLEAN NOT NULL DEFAULT false,
    admin_events_details_enabled BOOLEAN NOT NULL DEFAULT false,
    events_listeners JSONB NOT NULL DEFAULT '[]',
    enabled_event_types JSONB NOT NULL DEFAULT '[]',

    -- Internationalization
    internationalization_enabled BOOLEAN NOT NULL DEFAULT false,
    default_locale VARCHAR(50),
    supported_locales JSONB NOT NULL DEFAULT '[]',

    -- Authentication flows (references to authentication_flows table)
    browser_flow UUID,
    registration_flow UUID,
    direct_grant_flow UUID,
    reset_credentials_flow UUID,
    client_authentication_flow UUID,

    -- Defaults
    default_role_id UUID,
    default_groups JSONB NOT NULL DEFAULT '[]',

    -- Configuration
    smtp_config JSONB NOT NULL DEFAULT '{}',
    attributes JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_realms_name ON realms(name);
CREATE INDEX idx_realms_enabled ON realms(enabled);

-- ============================================================================
-- USERS
-- ============================================================================
CREATE TABLE users (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    username VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    email VARCHAR(255),
    email_verified BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    not_before BIGINT NOT NULL DEFAULT 0,
    federation_link VARCHAR(255),
    service_account_client_link UUID,
    required_actions JSONB NOT NULL DEFAULT '[]',
    attributes JSONB NOT NULL DEFAULT '{}',

    UNIQUE(realm_id, username),
    UNIQUE(realm_id, email) -- Only enforced when email is NOT NULL and duplicate_emails_allowed is false
);

CREATE INDEX idx_users_realm_id ON users(realm_id);
CREATE INDEX idx_users_username ON users(realm_id, username);
CREATE INDEX idx_users_email ON users(realm_id, email);
CREATE INDEX idx_users_service_account ON users(realm_id, service_account_client_link) WHERE service_account_client_link IS NOT NULL;

-- ============================================================================
-- FEDERATED IDENTITIES
-- ============================================================================
CREATE TABLE federated_identities (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    identity_provider VARCHAR(255) NOT NULL,
    federated_user_id VARCHAR(255) NOT NULL,
    federated_user_name VARCHAR(255),

    PRIMARY KEY (user_id, identity_provider)
);

CREATE INDEX idx_federated_identities_provider ON federated_identities(identity_provider, federated_user_id);

-- ============================================================================
-- CLIENTS
-- ============================================================================
CREATE TABLE clients (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    protocol VARCHAR(50) NOT NULL DEFAULT 'openid-connect',
    secret VARCHAR(255),
    public_client BOOLEAN NOT NULL DEFAULT false,
    bearer_only BOOLEAN NOT NULL DEFAULT false,
    client_authenticator_type VARCHAR(255) NOT NULL DEFAULT 'client-secret',
    consent_required BOOLEAN NOT NULL DEFAULT false,
    not_before BIGINT NOT NULL DEFAULT 0,

    -- Flow settings
    standard_flow_enabled BOOLEAN NOT NULL DEFAULT true,
    implicit_flow_enabled BOOLEAN NOT NULL DEFAULT false,
    direct_access_grants_enabled BOOLEAN NOT NULL DEFAULT true,
    service_accounts_enabled BOOLEAN NOT NULL DEFAULT false,

    -- URLs
    root_url VARCHAR(2048),
    base_url VARCHAR(2048),
    admin_url VARCHAR(2048),
    redirect_uris JSONB NOT NULL DEFAULT '[]',
    web_origins JSONB NOT NULL DEFAULT '[]',

    -- Other settings
    frontchannel_logout BOOLEAN NOT NULL DEFAULT false,
    full_scope_allowed BOOLEAN NOT NULL DEFAULT true,
    always_display_in_console BOOLEAN NOT NULL DEFAULT false,

    -- Configuration
    attributes JSONB NOT NULL DEFAULT '{}',
    auth_flow_bindings JSONB NOT NULL DEFAULT '{}',

    UNIQUE(realm_id, client_id)
);

CREATE INDEX idx_clients_realm_id ON clients(realm_id);
CREATE INDEX idx_clients_client_id ON clients(realm_id, client_id);
CREATE INDEX idx_clients_enabled ON clients(realm_id, enabled);

-- ============================================================================
-- ROLES
-- ============================================================================
CREATE TABLE roles (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_id UUID REFERENCES clients(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    composite_roles JSONB NOT NULL DEFAULT '[]',
    attributes JSONB NOT NULL DEFAULT '{}',

    -- Unique constraint: realm role names must be unique within a realm,
    -- client role names must be unique within a client
    UNIQUE(realm_id, client_id, name)
);

CREATE INDEX idx_roles_realm_id ON roles(realm_id);
CREATE INDEX idx_roles_client_id ON roles(client_id) WHERE client_id IS NOT NULL;
CREATE INDEX idx_roles_name ON roles(realm_id, name);

-- ============================================================================
-- GROUPS
-- ============================================================================
CREATE TABLE groups (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attributes JSONB NOT NULL DEFAULT '{}',
    realm_roles JSONB NOT NULL DEFAULT '[]',
    client_roles JSONB NOT NULL DEFAULT '{}',

    -- Unique constraint: group names must be unique within the same parent
    UNIQUE(realm_id, parent_id, name)
);

CREATE INDEX idx_groups_realm_id ON groups(realm_id);
CREATE INDEX idx_groups_parent_id ON groups(parent_id);
CREATE INDEX idx_groups_name ON groups(realm_id, name);

-- ============================================================================
-- CREDENTIALS
-- ============================================================================
CREATE TABLE credentials (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    credential_type VARCHAR(50) NOT NULL,
    user_label VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    secret_data TEXT NOT NULL,
    credential_data TEXT NOT NULL,
    priority INT NOT NULL DEFAULT 0
);

CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_type ON credentials(user_id, credential_type);

-- ============================================================================
-- USER-ROLE MAPPINGS
-- ============================================================================
CREATE TABLE user_role_mappings (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,

    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_user_role_mappings_role ON user_role_mappings(role_id);

-- ============================================================================
-- USER-GROUP MEMBERSHIPS
-- ============================================================================
CREATE TABLE user_group_memberships (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,

    PRIMARY KEY (user_id, group_id)
);

CREATE INDEX idx_user_group_memberships_group ON user_group_memberships(group_id);

-- ============================================================================
-- CLIENT SCOPES
-- ============================================================================
CREATE TABLE client_scopes (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    protocol VARCHAR(50) NOT NULL DEFAULT 'openid-connect',
    attributes JSONB NOT NULL DEFAULT '{}',

    UNIQUE(realm_id, name)
);

CREATE INDEX idx_client_scopes_realm ON client_scopes(realm_id);

-- ============================================================================
-- CLIENT-SCOPE MAPPINGS
-- ============================================================================
CREATE TABLE client_scope_mappings (
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scope_id UUID NOT NULL REFERENCES client_scopes(id) ON DELETE CASCADE,
    default_scope BOOLEAN NOT NULL DEFAULT false,

    PRIMARY KEY (client_id, scope_id)
);

-- ============================================================================
-- PROTOCOL MAPPERS
-- ============================================================================
CREATE TABLE protocol_mappers (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    protocol VARCHAR(50) NOT NULL,
    protocol_mapper VARCHAR(255) NOT NULL,
    client_id UUID REFERENCES clients(id) ON DELETE CASCADE,
    client_scope_id UUID REFERENCES client_scopes(id) ON DELETE CASCADE,
    config JSONB NOT NULL DEFAULT '{}',

    -- Must belong to either a client or client scope
    CHECK ((client_id IS NOT NULL AND client_scope_id IS NULL) OR
           (client_id IS NULL AND client_scope_id IS NOT NULL))
);

CREATE INDEX idx_protocol_mappers_client ON protocol_mappers(client_id) WHERE client_id IS NOT NULL;
CREATE INDEX idx_protocol_mappers_scope ON protocol_mappers(client_scope_id) WHERE client_scope_id IS NOT NULL;

-- ============================================================================
-- AUTHENTICATION FLOWS
-- ============================================================================
CREATE TABLE authentication_flows (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    alias VARCHAR(255) NOT NULL,
    description TEXT,
    provider_id VARCHAR(255) NOT NULL DEFAULT 'basic-flow',
    top_level BOOLEAN NOT NULL DEFAULT false,
    built_in BOOLEAN NOT NULL DEFAULT false,

    UNIQUE(realm_id, alias)
);

CREATE INDEX idx_auth_flows_realm ON authentication_flows(realm_id);

-- ============================================================================
-- AUTHENTICATION EXECUTIONS
-- ============================================================================
CREATE TABLE authentication_executions (
    id UUID PRIMARY KEY,
    flow_id UUID NOT NULL REFERENCES authentication_flows(id) ON DELETE CASCADE,
    authenticator VARCHAR(255),
    authenticator_config_id UUID,
    requirement VARCHAR(50) NOT NULL DEFAULT 'DISABLED',
    priority INT NOT NULL DEFAULT 0,
    flow_id_child UUID REFERENCES authentication_flows(id) ON DELETE SET NULL
);

CREATE INDEX idx_auth_executions_flow ON authentication_executions(flow_id);

-- ============================================================================
-- AUTHENTICATOR CONFIGS
-- ============================================================================
CREATE TABLE authenticator_configs (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    alias VARCHAR(255),
    config JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_auth_configs_realm ON authenticator_configs(realm_id);

-- ============================================================================
-- IDENTITY PROVIDERS
-- ============================================================================
CREATE TABLE identity_providers (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    alias VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    provider_id VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    trust_email BOOLEAN NOT NULL DEFAULT false,
    store_token BOOLEAN NOT NULL DEFAULT false,
    link_only BOOLEAN NOT NULL DEFAULT false,
    first_broker_login_flow_id UUID REFERENCES authentication_flows(id),
    post_broker_login_flow_id UUID REFERENCES authentication_flows(id),
    config JSONB NOT NULL DEFAULT '{}',

    UNIQUE(realm_id, alias)
);

CREATE INDEX idx_identity_providers_realm ON identity_providers(realm_id);

-- ============================================================================
-- IDENTITY PROVIDER MAPPERS
-- ============================================================================
CREATE TABLE identity_provider_mappers (
    id UUID PRIMARY KEY,
    identity_provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    identity_provider_mapper VARCHAR(255) NOT NULL,
    config JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_idp_mappers_provider ON identity_provider_mappers(identity_provider_id);

-- ============================================================================
-- USER SESSIONS
-- ============================================================================
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    login_username VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    auth_method VARCHAR(255),
    broker_session_id VARCHAR(255),
    broker_user_id VARCHAR(255),
    started TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_session_refresh TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expiration TIMESTAMPTZ NOT NULL,
    remember_me BOOLEAN NOT NULL DEFAULT false,
    state VARCHAR(50) NOT NULL DEFAULT 'LOGGED_IN',
    notes JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_user_sessions_realm ON user_sessions(realm_id);
CREATE INDEX idx_user_sessions_user ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_expiration ON user_sessions(expiration);
CREATE INDEX idx_user_sessions_broker ON user_sessions(broker_session_id) WHERE broker_session_id IS NOT NULL;

-- ============================================================================
-- CLIENT SESSIONS
-- ============================================================================
CREATE TABLE client_sessions (
    id UUID PRIMARY KEY,
    user_session_id UUID NOT NULL REFERENCES user_sessions(id) ON DELETE CASCADE,
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    current_refresh_token VARCHAR(255),
    current_refresh_token_use_count INT NOT NULL DEFAULT 0,
    offline BOOLEAN NOT NULL DEFAULT false,
    notes JSONB NOT NULL DEFAULT '{}',

    UNIQUE(user_session_id, client_id)
);

CREATE INDEX idx_client_sessions_user_session ON client_sessions(user_session_id);
CREATE INDEX idx_client_sessions_client ON client_sessions(client_id);

-- ============================================================================
-- EVENTS
-- ============================================================================
CREATE TABLE events (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL,
    event_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type VARCHAR(255) NOT NULL,
    client_id VARCHAR(255),
    user_id UUID,
    session_id VARCHAR(255),
    ip_address VARCHAR(45),
    error VARCHAR(255),
    details JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_events_realm ON events(realm_id);
CREATE INDEX idx_events_time ON events(realm_id, event_time);
CREATE INDEX idx_events_type ON events(realm_id, event_type);
CREATE INDEX idx_events_user ON events(realm_id, user_id) WHERE user_id IS NOT NULL;

-- ============================================================================
-- ADMIN EVENTS
-- ============================================================================
CREATE TABLE admin_events (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL,
    event_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    operation_type VARCHAR(50) NOT NULL,
    auth_realm_id UUID,
    auth_client_id VARCHAR(255),
    auth_user_id UUID,
    ip_address VARCHAR(45),
    resource_type VARCHAR(255),
    resource_path TEXT,
    representation TEXT,
    error VARCHAR(255)
);

CREATE INDEX idx_admin_events_realm ON admin_events(realm_id);
CREATE INDEX idx_admin_events_time ON admin_events(realm_id, event_time);
CREATE INDEX idx_admin_events_operation ON admin_events(realm_id, operation_type);

-- ============================================================================
-- REQUIRED ACTIONS
-- ============================================================================
CREATE TABLE required_actions (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    alias VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    provider_id VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    default_action BOOLEAN NOT NULL DEFAULT false,
    priority INT NOT NULL DEFAULT 0,
    config JSONB NOT NULL DEFAULT '{}',

    UNIQUE(realm_id, alias)
);

CREATE INDEX idx_required_actions_realm ON required_actions(realm_id);

-- ============================================================================
-- USER FEDERATION PROVIDERS
-- ============================================================================
CREATE TABLE user_federation_providers (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    display_name VARCHAR(255),
    provider_name VARCHAR(255) NOT NULL,
    priority INT NOT NULL DEFAULT 0,
    full_sync_period INT NOT NULL DEFAULT -1,
    changed_sync_period INT NOT NULL DEFAULT -1,
    last_sync TIMESTAMPTZ,
    config JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_federation_providers_realm ON user_federation_providers(realm_id);

-- ============================================================================
-- USER FEDERATION MAPPERS
-- ============================================================================
CREATE TABLE user_federation_mappers (
    id UUID PRIMARY KEY,
    federation_provider_id UUID NOT NULL REFERENCES user_federation_providers(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    federation_mapper_type VARCHAR(255) NOT NULL,
    config JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_federation_mappers_provider ON user_federation_mappers(federation_provider_id);

-- ============================================================================
-- REALM LOCALIZATION TEXTS
-- ============================================================================
CREATE TABLE realm_localization_texts (
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    locale VARCHAR(50) NOT NULL,
    key VARCHAR(255) NOT NULL,
    value TEXT NOT NULL,

    PRIMARY KEY (realm_id, locale, key)
);

CREATE INDEX idx_localization_realm_locale ON realm_localization_texts(realm_id, locale);

-- ============================================================================
-- SINGLE USE OBJECTS (for tokens, etc.)
-- ============================================================================
CREATE TABLE single_use_objects (
    key VARCHAR(512) PRIMARY KEY,
    value TEXT,
    expiration TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_single_use_expiration ON single_use_objects(expiration);

-- ============================================================================
-- UPDATE TIMESTAMPS TRIGGER
-- ============================================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply trigger to tables with updated_at column
CREATE TRIGGER update_realms_updated_at BEFORE UPDATE ON realms
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_clients_updated_at BEFORE UPDATE ON clients
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_groups_updated_at BEFORE UPDATE ON groups
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
