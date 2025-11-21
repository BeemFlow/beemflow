-- Initial BeemFlow schema
-- SQLite-specific version with production-ready constraints and indexes

-- ============================================================================
-- CORE EXECUTION TABLES
-- ============================================================================

-- Runs table (execution tracking) - Multi-organization with full constraints
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    flow_name TEXT NOT NULL,
    event TEXT NOT NULL DEFAULT '{}',  -- JSON stored as TEXT (SQLite standard)
    vars TEXT NOT NULL DEFAULT '{}',  -- JSON stored as TEXT (SQLite standard)
    status TEXT NOT NULL CHECK(status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'WAITING', 'SKIPPED')),
    started_at BIGINT NOT NULL,
    ended_at BIGINT,

    -- Multi-organization support
    organization_id TEXT NOT NULL,
    triggered_by_user_id TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (strftime('%s', 'now') * 1000),

    -- Constraints
    CHECK (ended_at IS NULL OR started_at <= ended_at)
);

-- Steps table (step execution tracking)
CREATE TABLE IF NOT EXISTS steps (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    step_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'WAITING', 'SKIPPED')),
    started_at BIGINT NOT NULL,
    ended_at BIGINT,
    outputs TEXT NOT NULL DEFAULT '{}',  -- JSON stored as TEXT
    error TEXT,

    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE,

    -- Constraints
    CHECK (ended_at IS NULL OR started_at <= ended_at)
);

-- Waits table (timeout/wait tracking)
CREATE TABLE IF NOT EXISTS waits (
    token TEXT PRIMARY KEY,
    wake_at BIGINT  -- Nullable - wait can be indefinite
);

-- Paused runs table (await_event support) - Multi-organization
CREATE TABLE IF NOT EXISTS paused_runs (
    token TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    data TEXT NOT NULL DEFAULT '{}',  -- JSON stored as TEXT

    -- Organization/user tracking
    organization_id TEXT NOT NULL,
    user_id TEXT NOT NULL
);

-- ============================================================================
-- FLOW MANAGEMENT TABLES
-- ============================================================================

-- Flows table (flow definitions) - Multi-organization
CREATE TABLE IF NOT EXISTS flows (
    name TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    updated_at BIGINT NOT NULL DEFAULT (strftime('%s', 'now') * 1000),

    -- Multi-organization support
    organization_id TEXT NOT NULL,
    created_by_user_id TEXT NOT NULL,
    visibility TEXT DEFAULT 'private' CHECK(visibility IN ('private', 'shared', 'public')),
    tags TEXT DEFAULT '[]'  -- JSON array stored as TEXT
);

-- Flow versions table (deployment history) - Multi-organization
CREATE TABLE IF NOT EXISTS flow_versions (
    organization_id TEXT NOT NULL,
    flow_name TEXT NOT NULL,
    version TEXT NOT NULL,
    content TEXT NOT NULL,
    deployed_at BIGINT NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    deployed_by_user_id TEXT NOT NULL,
    PRIMARY KEY (organization_id, flow_name, version)
);

-- Deployed flows table (current live versions) - Multi-organization
CREATE TABLE IF NOT EXISTS deployed_flows (
    organization_id TEXT NOT NULL,
    flow_name TEXT NOT NULL,
    deployed_version TEXT NOT NULL,
    deployed_at BIGINT NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    PRIMARY KEY (organization_id, flow_name),
    FOREIGN KEY (organization_id, flow_name, deployed_version)
        REFERENCES flow_versions(organization_id, flow_name, version) ON DELETE CASCADE
);

-- Flow triggers table (O(1) webhook routing) - Multi-organization
CREATE TABLE IF NOT EXISTS flow_triggers (
    organization_id TEXT NOT NULL,
    flow_name TEXT NOT NULL,
    version TEXT NOT NULL,
    topic TEXT NOT NULL,
    PRIMARY KEY (organization_id, flow_name, version, topic),
    FOREIGN KEY (organization_id, flow_name, version)
        REFERENCES flow_versions(organization_id, flow_name, version) ON DELETE CASCADE
);

-- ============================================================================
-- OAUTH TABLES
-- ============================================================================

-- OAuth credentials table - User-scoped
CREATE TABLE IF NOT EXISTS oauth_credentials (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    integration TEXT NOT NULL,
    access_token TEXT NOT NULL,  -- Encrypted by application
    refresh_token TEXT,  -- Encrypted by application
    expires_at BIGINT,
    scope TEXT,
    created_at BIGINT NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    updated_at BIGINT NOT NULL DEFAULT (strftime('%s', 'now') * 1000),

    -- User/organization scoping
    user_id TEXT NOT NULL,
    organization_id TEXT NOT NULL,

    -- One credential per user/provider/integration combination
    UNIQUE(user_id, organization_id, provider, integration)
);

-- OAuth providers table - System-wide with optional organization overrides
CREATE TABLE IF NOT EXISTS oauth_providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,  -- Human-readable name (e.g., "Google", "GitHub")
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL,  -- Encrypted by application
    auth_url TEXT NOT NULL,
    token_url TEXT NOT NULL,
    scopes TEXT DEFAULT '[]',  -- JSON array stored as TEXT
    auth_params TEXT DEFAULT '{}',  -- JSON object stored as TEXT
    created_at BIGINT NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    updated_at BIGINT NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);

-- OAuth clients table (for BeemFlow as OAuth server)
CREATE TABLE IF NOT EXISTS oauth_clients (
    id TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    name TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,  -- JSON array stored as TEXT
    grant_types TEXT NOT NULL,  -- JSON array stored as TEXT
    response_types TEXT NOT NULL,  -- JSON array stored as TEXT
    scope TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    updated_at BIGINT NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);

-- OAuth tokens table (for BeemFlow as OAuth server)
CREATE TABLE IF NOT EXISTS oauth_tokens (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    redirect_uri TEXT,
    scope TEXT,
    code TEXT UNIQUE,
    code_create_at BIGINT,
    code_expires_in BIGINT,
    code_challenge TEXT,
    code_challenge_method TEXT,
    access TEXT UNIQUE,
    access_create_at BIGINT,
    access_expires_in BIGINT,
    refresh TEXT UNIQUE,
    refresh_create_at BIGINT,
    refresh_expires_in BIGINT,
    created_at BIGINT NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    updated_at BIGINT NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);

-- ============================================================================
-- AUTHENTICATION & AUTHORIZATION TABLES
-- ============================================================================

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    email_verified INTEGER DEFAULT 0,  -- SQLite uses INTEGER for boolean (0 = false, 1 = true)
    avatar_url TEXT,

    -- MFA
    mfa_enabled INTEGER DEFAULT 0,
    mfa_secret TEXT,  -- TOTP secret (encrypted by application)

    -- Metadata
    created_at BIGINT NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    updated_at BIGINT NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    last_login_at BIGINT,

    -- Account status
    disabled INTEGER DEFAULT 0,
    disabled_reason TEXT,
    disabled_at BIGINT
);

-- Organizations table (Teams/Workspaces)
CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,

    -- Subscription
    plan TEXT DEFAULT 'free' CHECK(plan IN ('free', 'starter', 'pro', 'enterprise')),
    plan_starts_at BIGINT,
    plan_ends_at BIGINT,

    -- Quotas
    max_users INTEGER DEFAULT 5 CHECK(max_users > 0),
    max_flows INTEGER DEFAULT 10 CHECK(max_flows > 0),
    max_runs_per_month INTEGER DEFAULT 1000 CHECK(max_runs_per_month > 0),

    -- Settings
    settings TEXT DEFAULT '{}',  -- JSON object stored as TEXT

    -- Metadata
    created_by_user_id TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    updated_at BIGINT NOT NULL DEFAULT (strftime('%s', 'now') * 1000),

    -- Status
    disabled INTEGER DEFAULT 0,

    FOREIGN KEY (created_by_user_id) REFERENCES users(id),

    -- Constraints
    CHECK (plan_ends_at IS NULL OR plan_starts_at <= plan_ends_at)
);

-- Organization members table (User-Organization Relationship)
CREATE TABLE IF NOT EXISTS organization_members (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    organization_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('owner', 'admin', 'member', 'viewer')),

    -- Invitation tracking
    invited_by_user_id TEXT,
    invited_at BIGINT,
    joined_at BIGINT NOT NULL DEFAULT (strftime('%s', 'now') * 1000),

    -- Status
    disabled INTEGER DEFAULT 0,

    UNIQUE(organization_id, user_id),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (invited_by_user_id) REFERENCES users(id)
);

-- Refresh tokens table (For JWT authentication)
-- User-scoped (users can belong to multiple organizations)
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,  -- SHA-256 hash

    expires_at BIGINT NOT NULL,
    revoked INTEGER DEFAULT 0,
    revoked_at BIGINT,

    created_at BIGINT NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    last_used_at BIGINT,

    -- Session metadata
    user_agent TEXT,
    client_ip TEXT,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,

    -- Constraints
    CHECK (created_at <= expires_at)
);

