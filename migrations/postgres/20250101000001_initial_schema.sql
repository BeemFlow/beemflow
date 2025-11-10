-- Initial BeemFlow schema
-- PostgreSQL-specific version with production-ready constraints and indexes

-- ============================================================================
-- CORE EXECUTION TABLES
-- ============================================================================

-- Runs table (execution tracking) - Multi-tenant with full constraints
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    flow_name TEXT NOT NULL,
    event JSONB NOT NULL DEFAULT '{}'::jsonb,
    vars JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL CHECK(status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'WAITING', 'SKIPPED')),
    started_at BIGINT NOT NULL,
    ended_at BIGINT,

    -- Multi-tenant support
    tenant_id TEXT NOT NULL,
    triggered_by_user_id TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000,

    -- Constraints
    CONSTRAINT runs_time_range_check CHECK (ended_at IS NULL OR started_at <= ended_at)
);

-- Steps table (step execution tracking)
CREATE TABLE IF NOT EXISTS steps (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    step_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'WAITING', 'SKIPPED')),
    started_at BIGINT NOT NULL,
    ended_at BIGINT,
    outputs JSONB NOT NULL DEFAULT '{}'::jsonb,
    error TEXT,

    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE,

    -- Constraints
    CONSTRAINT steps_time_range_check CHECK (ended_at IS NULL OR started_at <= ended_at)
);

-- Waits table (timeout/wait tracking)
CREATE TABLE IF NOT EXISTS waits (
    token TEXT PRIMARY KEY,
    wake_at BIGINT  -- Nullable - wait can be indefinite
);

-- Paused runs table (await_event support) - Multi-tenant
CREATE TABLE IF NOT EXISTS paused_runs (
    token TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    data JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Tenant/user tracking
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL
);

-- ============================================================================
-- FLOW MANAGEMENT TABLES
-- ============================================================================

-- Flows table (flow definitions) - Multi-tenant
CREATE TABLE IF NOT EXISTS flows (
    name TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000,
    updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000,

    -- Multi-tenant support
    tenant_id TEXT NOT NULL,
    created_by_user_id TEXT NOT NULL,
    visibility TEXT DEFAULT 'private' CHECK(visibility IN ('private', 'shared', 'public')),
    tags JSONB DEFAULT '[]'::jsonb
);

-- Flow versions table (deployment history) - Multi-tenant
CREATE TABLE IF NOT EXISTS flow_versions (
    tenant_id TEXT NOT NULL,
    flow_name TEXT NOT NULL,
    version TEXT NOT NULL,
    content TEXT NOT NULL,
    deployed_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000,
    deployed_by_user_id TEXT NOT NULL,
    PRIMARY KEY (tenant_id, flow_name, version)
);

-- Deployed flows table (current live versions) - Multi-tenant
CREATE TABLE IF NOT EXISTS deployed_flows (
    tenant_id TEXT NOT NULL,
    flow_name TEXT NOT NULL,
    deployed_version TEXT NOT NULL,
    deployed_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000,
    PRIMARY KEY (tenant_id, flow_name),
    FOREIGN KEY (tenant_id, flow_name, deployed_version)
        REFERENCES flow_versions(tenant_id, flow_name, version) ON DELETE CASCADE
);

-- Flow triggers table (O(1) webhook routing) - Multi-tenant
CREATE TABLE IF NOT EXISTS flow_triggers (
    tenant_id TEXT NOT NULL,
    flow_name TEXT NOT NULL,
    version TEXT NOT NULL,
    topic TEXT NOT NULL,
    PRIMARY KEY (tenant_id, flow_name, version, topic),
    FOREIGN KEY (tenant_id, flow_name, version)
        REFERENCES flow_versions(tenant_id, flow_name, version) ON DELETE CASCADE
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
    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000,
    updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000,

    -- User/tenant scoping
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,

    -- One credential per user/provider/integration combination
    UNIQUE(user_id, tenant_id, provider, integration)
);

-- OAuth providers table - System-wide with optional tenant overrides
CREATE TABLE IF NOT EXISTS oauth_providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,  -- Human-readable name (e.g., "Google", "GitHub")
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL,  -- Encrypted by application
    auth_url TEXT NOT NULL,
    token_url TEXT NOT NULL,
    scopes JSONB DEFAULT '[]'::jsonb,
    auth_params JSONB DEFAULT '{}'::jsonb,
    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000,
    updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000
);

-- OAuth clients table (for BeemFlow as OAuth server)
CREATE TABLE IF NOT EXISTS oauth_clients (
    id TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    name TEXT NOT NULL,
    redirect_uris JSONB NOT NULL,
    grant_types JSONB NOT NULL,
    response_types JSONB NOT NULL,
    scope TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000,
    updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000
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
    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000,
    updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000
);

-- ============================================================================
-- AUTHENTICATION & AUTHORIZATION TABLES
-- ============================================================================

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    avatar_url TEXT,

    -- MFA
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret TEXT,  -- TOTP secret (encrypted by application)

    -- Metadata
    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000,
    updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000,
    last_login_at BIGINT,

    -- Account status
    disabled BOOLEAN DEFAULT FALSE,
    disabled_reason TEXT,
    disabled_at BIGINT
);

-- Tenants table (Organizations/Workspaces)
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,

    -- Subscription
    plan TEXT DEFAULT 'free' CHECK(plan IN ('free', 'starter', 'pro', 'enterprise')),
    plan_starts_at BIGINT,
    plan_ends_at BIGINT,

    -- Quotas
    max_users INTEGER DEFAULT 5 CHECK(max_users > 0),
    max_flows INTEGER DEFAULT 10 CHECK(max_flows > 0),
    max_runs_per_month BIGINT DEFAULT 1000 CHECK(max_runs_per_month > 0),

    -- Settings
    settings JSONB DEFAULT '{}'::jsonb,

    -- Metadata
    created_by_user_id TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000,
    updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000,

    -- Status
    disabled BOOLEAN DEFAULT FALSE,

    FOREIGN KEY (created_by_user_id) REFERENCES users(id),

    -- Constraints
    CONSTRAINT tenants_plan_range_check CHECK (plan_ends_at IS NULL OR plan_starts_at <= plan_ends_at)
);

-- Tenant members table (User-Tenant Relationship)
CREATE TABLE IF NOT EXISTS tenant_members (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('owner', 'admin', 'member', 'viewer')),

    -- Invitation tracking
    invited_by_user_id TEXT,
    invited_at BIGINT,
    joined_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000,

    -- Status
    disabled BOOLEAN DEFAULT FALSE,

    UNIQUE(tenant_id, user_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (invited_by_user_id) REFERENCES users(id)
);

-- Refresh tokens table (For JWT authentication)
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,  -- SHA-256 hash

    expires_at BIGINT NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at BIGINT,

    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000,
    last_used_at BIGINT,

    -- Session metadata
    user_agent TEXT,
    client_ip TEXT,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,

    -- Constraints
    CONSTRAINT refresh_tokens_time_check CHECK (created_at <= expires_at)
);

-- Audit logs table (Immutable via triggers)
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,

    -- When & Where
    timestamp BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000,
    request_id TEXT,

    -- Who
    tenant_id TEXT NOT NULL,
    user_id TEXT,
    client_ip TEXT,
    user_agent TEXT,

    -- What
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    resource_name TEXT,

    -- How
    http_method TEXT,
    http_path TEXT,
    http_status_code INTEGER,

    -- Result
    success BOOLEAN NOT NULL,
    error_message TEXT,

    -- Details (JSON)
    metadata JSONB DEFAULT '{}'::jsonb,

    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000,

    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Tenant secrets table
CREATE TABLE IF NOT EXISTS tenant_secrets (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,  -- Encrypted by application
    description TEXT,

    created_by_user_id TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000,
    updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000,

    UNIQUE(tenant_id, key),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id)
);

-- ============================================================================
-- PERFORMANCE INDEXES
-- ============================================================================

-- Core execution indexes
CREATE INDEX IF NOT EXISTS idx_steps_run_id ON steps(run_id);
CREATE INDEX IF NOT EXISTS idx_runs_tenant_time ON runs(tenant_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_runs_tenant_flow_status_time ON runs(tenant_id, flow_name, status, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_runs_user ON runs(triggered_by_user_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_runs_status_time ON runs(status, started_at DESC) WHERE status IN ('PENDING', 'RUNNING');

-- Flow management indexes
CREATE INDEX IF NOT EXISTS idx_flows_tenant_name ON flows(tenant_id, name);
CREATE INDEX IF NOT EXISTS idx_flows_user ON flows(created_by_user_id);
CREATE INDEX IF NOT EXISTS idx_flow_versions_tenant_name ON flow_versions(tenant_id, flow_name, deployed_at DESC);
CREATE INDEX IF NOT EXISTS idx_deployed_flows_tenant ON deployed_flows(tenant_id);

-- Webhook routing indexes (HOT PATH - critical for performance)
CREATE INDEX IF NOT EXISTS idx_flow_triggers_tenant_topic ON flow_triggers(tenant_id, topic, flow_name, version);
CREATE INDEX IF NOT EXISTS idx_deployed_flows_join ON deployed_flows(tenant_id, flow_name, deployed_version);

-- OAuth indexes
CREATE INDEX IF NOT EXISTS idx_oauth_creds_user_tenant ON oauth_credentials(user_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_oauth_creds_tenant ON oauth_credentials(tenant_id);

-- Paused runs indexes
CREATE INDEX IF NOT EXISTS idx_paused_runs_tenant ON paused_runs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_paused_runs_source ON paused_runs(source) WHERE source IS NOT NULL;

-- User indexes
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_active ON users(email) WHERE disabled = FALSE;
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_users_disabled ON users(disabled, disabled_at) WHERE disabled = TRUE;

-- Tenant indexes
CREATE INDEX IF NOT EXISTS idx_tenants_created_by ON tenants(created_by_user_id);
CREATE INDEX IF NOT EXISTS idx_tenants_disabled ON tenants(disabled) WHERE disabled = TRUE;

-- Tenant membership indexes
CREATE INDEX IF NOT EXISTS idx_tenant_members_tenant_role ON tenant_members(tenant_id, role) WHERE disabled = FALSE;
CREATE INDEX IF NOT EXISTS idx_tenant_members_user ON tenant_members(user_id) WHERE disabled = FALSE;
CREATE INDEX IF NOT EXISTS idx_tenant_members_invited_by ON tenant_members(invited_by_user_id) WHERE invited_by_user_id IS NOT NULL;

-- Refresh token indexes (with partial indexes for active tokens)
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id) WHERE revoked = FALSE;
CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_tokens_hash_active ON refresh_tokens(token_hash) WHERE revoked = FALSE;
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at) WHERE revoked = FALSE;
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_tenant ON refresh_tokens(tenant_id);

-- Audit log indexes
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_time ON audit_logs(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_time ON audit_logs(user_id, timestamp DESC) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_logs_action_time ON audit_logs(action, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id, timestamp DESC) WHERE resource_id IS NOT NULL;

-- Tenant secrets indexes
CREATE INDEX IF NOT EXISTS idx_tenant_secrets_tenant ON tenant_secrets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_secrets_created_by ON tenant_secrets(created_by_user_id);

-- ============================================================================
-- JSONB INDEXES (GIN - for fast JSON queries)
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_runs_event_gin ON runs USING GIN(event);
CREATE INDEX IF NOT EXISTS idx_runs_vars_gin ON runs USING GIN(vars);
CREATE INDEX IF NOT EXISTS idx_steps_outputs_gin ON steps USING GIN(outputs);
CREATE INDEX IF NOT EXISTS idx_flows_tags_gin ON flows USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_tenants_settings_gin ON tenants USING GIN(settings);
CREATE INDEX IF NOT EXISTS idx_audit_logs_metadata_gin ON audit_logs USING GIN(metadata);

-- ============================================================================
-- AUDIT LOG IMMUTABILITY (Security & Compliance)
-- ============================================================================

-- Function to prevent audit log changes
CREATE OR REPLACE FUNCTION prevent_audit_log_changes()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit logs are immutable';
END;
$$ LANGUAGE plpgsql;

-- Trigger to prevent audit log deletion
DROP TRIGGER IF EXISTS trigger_prevent_audit_delete ON audit_logs;
CREATE TRIGGER trigger_prevent_audit_delete
BEFORE DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_changes();

-- Trigger to prevent audit log updates
DROP TRIGGER IF EXISTS trigger_prevent_audit_update ON audit_logs;
CREATE TRIGGER trigger_prevent_audit_update
BEFORE UPDATE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_changes();

-- ============================================================================
-- QUERY OPTIMIZATION HINTS
-- ============================================================================

-- Increase statistics target for high-cardinality columns
ALTER TABLE runs ALTER COLUMN tenant_id SET STATISTICS 1000;
ALTER TABLE flows ALTER COLUMN tenant_id SET STATISTICS 1000;
ALTER TABLE flow_triggers ALTER COLUMN topic SET STATISTICS 1000;
ALTER TABLE users ALTER COLUMN email SET STATISTICS 1000;

-- ============================================================================
-- COMMENTS (Documentation)
-- ============================================================================

COMMENT ON TABLE runs IS 'Workflow execution tracking with multi-tenant isolation';
COMMENT ON TABLE audit_logs IS 'Immutable audit trail (protected by triggers)';
COMMENT ON COLUMN users.mfa_secret IS 'TOTP secret - must be encrypted at application layer';
COMMENT ON COLUMN oauth_credentials.access_token IS 'OAuth access token - encrypted at application layer before storage';
COMMENT ON COLUMN tenant_secrets.value IS 'Secret value - encrypted at application layer before storage';
COMMENT ON COLUMN oauth_providers.client_secret IS 'OAuth provider secret - encrypted at application layer before storage';
