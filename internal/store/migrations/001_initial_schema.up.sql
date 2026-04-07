-- Networks
CREATE TABLE IF NOT EXISTS networks (
    network_id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS network_members (
    network_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (network_id, subject)
);

-- Groups
CREATE TABLE IF NOT EXISTS groups (
    network_id TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (network_id, name)
);

CREATE TABLE IF NOT EXISTS group_members (
    network_id TEXT NOT NULL,
    group_name TEXT NOT NULL,
    node_name TEXT NOT NULL,
    session_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (network_id, group_name, node_name, session_name)
);

CREATE TABLE IF NOT EXISTS group_policies (
    network_id TEXT NOT NULL,
    group_name TEXT NOT NULL,
    messages_policy TEXT NOT NULL,
    debug_policy TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (network_id, group_name)
);

-- Nodes
CREATE TABLE IF NOT EXISTS nodes (
    network_id TEXT NOT NULL,
    name TEXT NOT NULL,
    token TEXT NOT NULL DEFAULT '',
    peer_url TEXT NOT NULL DEFAULT '',
    github_id BIGINT,
    owner_subject TEXT NOT NULL DEFAULT '',
    authorized_by TEXT NOT NULL DEFAULT '',
    enrollment_id TEXT NOT NULL DEFAULT '',
    authorized_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (network_id, name)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_token ON nodes(token) WHERE token != '';

CREATE TABLE IF NOT EXISTS node_enrollments (
    id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL,
    owner_subject TEXT NOT NULL DEFAULT '',
    issued_by TEXT NOT NULL DEFAULT '',
    node_name TEXT NOT NULL DEFAULT '',
    token_hash TEXT NOT NULL UNIQUE,
    uses_remaining INTEGER NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    redeemed_at TIMESTAMPTZ
);

-- KV Store
CREATE TABLE IF NOT EXISTS kv (
    network_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    key TEXT NOT NULL,
    value BYTEA NOT NULL,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (network_id, namespace, key)
);

-- Device Auth
CREATE TABLE IF NOT EXISTS device_codes (
    code TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    node_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

-- GitHub App (singleton)
CREATE TABLE IF NOT EXISTS github_app (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    app_id INTEGER NOT NULL,
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    pem TEXT NOT NULL,
    webhook_secret TEXT NOT NULL DEFAULT '',
    owner TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

-- Users & Sessions
CREATE TABLE IF NOT EXISTS users (
    github_id BIGINT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    avatar_url TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    last_login_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    github_id BIGINT NOT NULL REFERENCES users(github_id),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_state (
    state TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

-- Invites
CREATE TABLE IF NOT EXISTS invites (
    network_id TEXT NOT NULL DEFAULT '',
    token TEXT PRIMARY KEY,
    created_by BIGINT REFERENCES users(github_id),
    uses_remaining INTEGER NOT NULL DEFAULT 1,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

-- Access Grants
CREATE TABLE IF NOT EXISTS access_grants (
    id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL,
    target_node TEXT NOT NULL,
    session_id INTEGER,
    session_name TEXT NOT NULL DEFAULT '',
    verbs TEXT NOT NULL,
    audience_subject_kind TEXT NOT NULL,
    audience_subject_id TEXT NOT NULL,
    audience_display TEXT NOT NULL DEFAULT '',
    issued_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_access_grants_network_expires ON access_grants(network_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_access_grants_network_audience ON access_grants(network_id, audience_subject_kind, audience_subject_id);
CREATE INDEX IF NOT EXISTS idx_access_grants_network_target ON access_grants(network_id, target_node);

-- Revoked Keys
CREATE TABLE IF NOT EXISTS revoked_keys (
    public_key TEXT PRIMARY KEY,
    revoked_at TIMESTAMPTZ NOT NULL,
    reason TEXT NOT NULL DEFAULT ''
);

-- OIDC
CREATE TABLE IF NOT EXISTS oidc_users (
    sub TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    avatar_url TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    last_login_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_sessions (
    token TEXT PRIMARY KEY,
    sub TEXT NOT NULL REFERENCES oidc_users(sub) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_device_flows (
    poll_token TEXT PRIMARY KEY,
    device_code TEXT NOT NULL UNIQUE,
    network_id TEXT NOT NULL DEFAULT '',
    node_name TEXT NOT NULL DEFAULT '',
    node_token TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_group_members_network_session
    ON group_members(network_id, node_name, session_name);
