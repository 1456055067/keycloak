-- Initialize Keycloak database with a test realm and client
-- This script runs on first startup via docker-compose

-- Create master realm
INSERT INTO realms (id, name, display_name, enabled, config, created_at, updated_at)
VALUES (
    'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
    'master',
    'Master Realm',
    true,
    '{"registrationAllowed": false, "loginWithEmailAllowed": true}',
    NOW(),
    NOW()
)
ON CONFLICT (name) DO NOTHING;

-- Create test realm
INSERT INTO realms (id, name, display_name, enabled, config, created_at, updated_at)
VALUES (
    'b1eebc99-9c0b-4ef8-bb6d-6bb9bd380a22',
    'test',
    'Test Realm',
    true,
    '{"registrationAllowed": true, "loginWithEmailAllowed": true}',
    NOW(),
    NOW()
)
ON CONFLICT (name) DO NOTHING;

-- Create admin client in master realm
INSERT INTO clients (
    id, realm_id, client_id, name, secret, public_client, enabled,
    redirect_uris, web_origins, protocol, created_at, updated_at
)
VALUES (
    'c2eebc99-9c0b-4ef8-bb6d-6bb9bd380a33',
    'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
    'admin-cli',
    'Admin CLI',
    NULL,
    true,
    true,
    ARRAY['http://localhost:*'],
    ARRAY['http://localhost:8080'],
    'openid-connect',
    NOW(),
    NOW()
)
ON CONFLICT (realm_id, client_id) DO NOTHING;

-- Create test client in test realm (confidential)
INSERT INTO clients (
    id, realm_id, client_id, name, secret, public_client, enabled,
    redirect_uris, web_origins, protocol, created_at, updated_at
)
VALUES (
    'd3eebc99-9c0b-4ef8-bb6d-6bb9bd380a44',
    'b1eebc99-9c0b-4ef8-bb6d-6bb9bd380a22',
    'test-client',
    'Test Client',
    'test-secret',
    false,
    true,
    ARRAY['http://localhost:*', 'http://127.0.0.1:*'],
    ARRAY['http://localhost:8080', 'http://127.0.0.1:8080'],
    'openid-connect',
    NOW(),
    NOW()
)
ON CONFLICT (realm_id, client_id) DO NOTHING;

-- Create public client in test realm
INSERT INTO clients (
    id, realm_id, client_id, name, secret, public_client, enabled,
    redirect_uris, web_origins, protocol, created_at, updated_at
)
VALUES (
    'e4eebc99-9c0b-4ef8-bb6d-6bb9bd380a55',
    'b1eebc99-9c0b-4ef8-bb6d-6bb9bd380a22',
    'test-public-client',
    'Test Public Client',
    NULL,
    true,
    true,
    ARRAY['http://localhost:*', 'http://127.0.0.1:*'],
    ARRAY['http://localhost:8080', 'http://127.0.0.1:8080'],
    'openid-connect',
    NOW(),
    NOW()
)
ON CONFLICT (realm_id, client_id) DO NOTHING;

-- Create test user in test realm
-- Password: testpassword (hashed with Argon2id)
INSERT INTO users (
    id, realm_id, username, email, email_verified, enabled, created_at, updated_at
)
VALUES (
    'f5eebc99-9c0b-4ef8-bb6d-6bb9bd380a66',
    'b1eebc99-9c0b-4ef8-bb6d-6bb9bd380a22',
    'testuser',
    'test@example.com',
    true,
    true,
    NOW(),
    NOW()
)
ON CONFLICT (realm_id, username) DO NOTHING;
