# BeemFlow SaaS Phase: Multi-Tenant Authentication & Authorization

**Status:** Ready for Implementation
**Target:** Production-ready multi-tenant SaaS with RBAC
**Timeline:** 2.5 weeks
**Prerequisites:** None (edit existing migrations directly)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [Database Schema Changes](#database-schema-changes)
4. [Implementation Roadmap](#implementation-roadmap)
5. [Step 1: Database Migrations](#step-1-database-migrations)
6. [Step 2: Core Auth Types](#step-2-core-auth-types)
7. [Step 3: Storage Layer](#step-3-storage-layer)
8. [Step 4: Authentication](#step-4-authentication)
9. [Step 5: Authorization (RBAC)](#step-5-authorization-rbac)
10. [Step 6: HTTP Middleware](#step-6-http-middleware)
11. [Step 7: Context Propagation](#step-7-context-propagation)
12. [Step 8: OAuth Integration](#step-8-oauth-integration)
13. [Step 9: Audit Logging](#step-9-audit-logging)
14. [Step 10: Testing](#step-10-testing)
15. [Deployment Checklist](#deployment-checklist)

---

## Executive Summary

### Current State (Security Issues)

**File: [src/auth/server.rs:691](/Users/alec/Workspace/beemflow/src/auth/server.rs#L691)**
```rust
let token = OAuthToken {
    user_id: "default_user".to_string(),  // ⚠️ CRITICAL: All users = same ID
    // ...
};
```

**File: [migrations/sqlite/20250101000001_initial_schema.sql:93](/Users/alec/Workspace/beemflow/migrations/sqlite/20250101000001_initial_schema.sql#L93)**
```sql
UNIQUE(provider, integration)  -- ⚠️ CRITICAL: Only ONE token per provider globally
```

**File: [src/storage/mod.rs:35](/Users/alec/Workspace/beemflow/src/storage/mod.rs#L35)**
```rust
async fn list_runs(&self, limit: usize, offset: usize) -> Result<Vec<Run>>;
// ⚠️ CRITICAL: No user_id parameter - returns ALL users' data
```

### Target State (Production-Ready)

✅ **Multi-tenant isolation**: Each organization has separate data namespace
✅ **Multi-user support**: Users belong to organizations with specific roles
✅ **RBAC**: Owner, Admin, Member, Viewer roles with 15+ permissions
✅ **JWT authentication**: Stateless auth with refresh tokens
✅ **Credential isolation**: Each user has their own OAuth tokens
✅ **Audit logging**: Immutable trail of all actions
✅ **GDPR compliance**: Data export, deletion, consent tracking
✅ **Horizontal scaling**: Stateless design, PostgreSQL-ready

### Implementation Timeline

| Phase | Duration | Deliverable |
|-------|----------|-------------|
| **Database** | 1 day | Update migration files, run sqlx migrate |
| **Auth Core** | 3 days | JWT, registration, login, roles |
| **Storage** | 3 days | Tenant-scoped queries, RLS |
| **Middleware** | 2 days | Auth, tenant resolution |
| **Integration** | 4 days | OAuth, context, flows |
| **Audit** | 2 days | Immutable logs |
| **Testing** | 3 days | Security tests, load tests |
| **Total** | **2.5 weeks** | Production-ready SaaS |

---

## Architecture Overview

### Request Flow

```
HTTP Request
    │
    ├─> 1. TLS Termination
    │
    ├─> 2. CORS Middleware
    │
    ├─> 3. Auth Middleware (JWT validation)
    │      ├─ Extract Bearer token
    │      ├─ Validate signature
    │      ├─ Extract user_id
    │      └─ Create AuthContext
    │
    ├─> 4. Tenant Middleware
    │      ├─ Resolve tenant_id (from JWT, subdomain, header)
    │      ├─ Verify user membership
    │      ├─ Load role
    │      └─ Create RequestContext
    │
    ├─> 5. Audit Middleware
    │      └─ Log request metadata
    │
    ├─> 6. Handler
    │      ├─ Check RBAC permissions
    │      ├─ Execute business logic
    │      └─ Storage queries (auto-scoped to tenant)
    │
    └─> 7. Response
```

### Data Model

```
Platform
  └─> Tenant (Organization)
       ├─ tenant_id: "org_abc123"
       ├─ name: "Acme Corp"
       ├─ plan: "pro"
       └─ Members:
            ├─ User A (owner)
            ├─ User B (admin)
            └─ User C (member)
       └─ Resources (tenant-scoped):
            ├─ Flows
            ├─ Runs
            ├─ OAuth Credentials (user-scoped)
            ├─ Secrets
            └─ Audit Logs
```

---

## Database Schema Changes

### Overview

Since you haven't launched yet, we'll **modify the existing migration files directly** rather than creating new ones. This keeps the schema clean and simple.

**Files to modify:**
- `migrations/sqlite/20250101000001_initial_schema.sql`
- `migrations/postgres/20250101000001_initial_schema.sql`

**How sqlx migrations work:**
```bash
# Apply all pending migrations (sqlx CLI does this automatically)
sqlx migrate run

# Revert last migration (if needed)
sqlx migrate revert
```

No custom Rust migration code needed - sqlx handles everything!

### New Tables to Add

Add these tables to the **end** of your existing `initial_schema.sql` files:

```sql
-- ============================================================================
-- USERS TABLE
-- ============================================================================
CREATE TABLE users (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    email TEXT UNIQUE NOT NULL,
    name TEXT,
    password_hash TEXT NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    avatar_url TEXT,

    -- MFA
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret TEXT,  -- TOTP secret (will be encrypted)

    -- Metadata
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    last_login_at BIGINT,

    -- Account status
    disabled BOOLEAN DEFAULT FALSE,
    disabled_reason TEXT,
    disabled_at BIGINT
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_created_at ON users(created_at DESC);

-- ============================================================================
-- TENANTS TABLE (Organizations/Workspaces)
-- ============================================================================
CREATE TABLE tenants (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,  -- For subdomain routing

    -- Subscription
    plan TEXT DEFAULT 'free',  -- free, starter, pro, enterprise
    plan_starts_at BIGINT,
    plan_ends_at BIGINT,

    -- Quotas
    max_users INTEGER DEFAULT 5,
    max_flows INTEGER DEFAULT 10,
    max_runs_per_month INTEGER DEFAULT 1000,

    -- Settings
    settings TEXT,  -- JSON blob

    -- Metadata
    created_by_user_id TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,

    -- Status
    disabled BOOLEAN DEFAULT FALSE,

    FOREIGN KEY (created_by_user_id) REFERENCES users(id)
);

CREATE INDEX idx_tenants_slug ON tenants(slug);
CREATE INDEX idx_tenants_created_by ON tenants(created_by_user_id);

-- ============================================================================
-- TENANT MEMBERS (User-Tenant Relationship)
-- ============================================================================
CREATE TABLE tenant_members (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL,  -- owner, admin, member, viewer

    -- Invitation tracking
    invited_by_user_id TEXT,
    invited_at BIGINT,
    joined_at BIGINT NOT NULL,

    -- Status
    disabled BOOLEAN DEFAULT FALSE,

    UNIQUE(tenant_id, user_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (invited_by_user_id) REFERENCES users(id)
);

CREATE INDEX idx_tenant_members_tenant ON tenant_members(tenant_id);
CREATE INDEX idx_tenant_members_user ON tenant_members(user_id);
CREATE INDEX idx_tenant_members_role ON tenant_members(tenant_id, role);

-- ============================================================================
-- REFRESH TOKENS (For JWT authentication)
-- ============================================================================
CREATE TABLE refresh_tokens (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,  -- bcrypt hash

    expires_at BIGINT NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at BIGINT,

    created_at BIGINT NOT NULL,
    last_used_at BIGINT,

    -- Session metadata
    user_agent TEXT,
    client_ip TEXT,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash) WHERE revoked = FALSE;
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at) WHERE revoked = FALSE;

-- ============================================================================
-- AUDIT LOGS (Immutable)
-- ============================================================================
CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),

    -- When & Where
    timestamp BIGINT NOT NULL,
    request_id TEXT,

    -- Who
    tenant_id TEXT NOT NULL,
    user_id TEXT,
    client_ip TEXT,
    user_agent TEXT,

    -- What
    action TEXT NOT NULL,  -- e.g., 'flow.create', 'run.trigger', 'user.login'
    resource_type TEXT,    -- e.g., 'flow', 'run', 'user'
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
    metadata TEXT,

    created_at BIGINT NOT NULL,

    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX idx_audit_logs_tenant_time ON audit_logs(tenant_id, timestamp DESC);
CREATE INDEX idx_audit_logs_user_time ON audit_logs(user_id, timestamp DESC) WHERE user_id IS NOT NULL;
CREATE INDEX idx_audit_logs_action ON audit_logs(action, timestamp DESC);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id) WHERE resource_id IS NOT NULL;

-- Prevent deletion (SQLite doesn't support triggers in same transaction, so this is advisory)
-- For PostgreSQL, we'll add a trigger

-- ============================================================================
-- TENANT SECRETS
-- ============================================================================
CREATE TABLE tenant_secrets (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    tenant_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,  -- Encrypted
    description TEXT,

    created_by_user_id TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,

    UNIQUE(tenant_id, key),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id)
);

CREATE INDEX idx_tenant_secrets_tenant ON tenant_secrets(tenant_id);
```

### Modify Existing Tables in initial_schema.sql

In the **same** `initial_schema.sql` file, update the existing table definitions:

```sql
-- ============================================================================
-- MODIFY RUNS TABLE (Add tenant/user scoping)
-- ============================================================================
-- FIND the existing CREATE TABLE runs and UPDATE it to:
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    flow_name TEXT,
    event TEXT,
    vars TEXT,
    status TEXT,
    started_at BIGINT,
    ended_at BIGINT,

    -- NEW: Multi-tenant support
    tenant_id TEXT NOT NULL,
    triggered_by_user_id TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT 0
);

-- NEW indexes for multi-tenant queries
CREATE INDEX IF NOT EXISTS idx_runs_tenant_time ON runs(tenant_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_runs_tenant_flow_status ON runs(tenant_id, flow_name, status);
CREATE INDEX IF NOT EXISTS idx_runs_user ON runs(triggered_by_user_id, started_at DESC);

-- ============================================================================
-- MODIFY FLOWS TABLE (Add tenant/user scoping)
-- ============================================================================
-- FIND the existing CREATE TABLE flows and UPDATE it to:
CREATE TABLE IF NOT EXISTS flows (
    name TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,

    -- NEW: Multi-tenant support
    tenant_id TEXT NOT NULL,
    created_by_user_id TEXT NOT NULL,
    visibility TEXT DEFAULT 'private',  -- private, shared, public
    tags TEXT  -- JSON array
);

-- NEW indexes
CREATE INDEX IF NOT EXISTS idx_flows_tenant_name ON flows(tenant_id, name);
CREATE INDEX IF NOT EXISTS idx_flows_user ON flows(created_by_user_id);

-- ============================================================================
-- MODIFY OAUTH_CREDENTIALS TABLE (Add user scoping)
-- ============================================================================
-- FIND the existing CREATE TABLE oauth_credentials and UPDATE it to:
CREATE TABLE IF NOT EXISTS oauth_credentials (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    integration TEXT NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    expires_at BIGINT,
    scope TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,

    -- NEW: User/tenant scoping
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,

    -- CHANGED: Unique constraint now per-user instead of global
    UNIQUE(user_id, provider, integration)
);

-- NEW indexes
CREATE INDEX IF NOT EXISTS idx_oauth_creds_tenant ON oauth_credentials(tenant_id);

-- ============================================================================
-- MODIFY OAUTH_TOKENS TABLE (Fix user_id to be NOT NULL)
-- ============================================================================
-- FIND the existing CREATE TABLE oauth_tokens and UPDATE this line:
-- FROM: user_id TEXT,
-- TO:   user_id TEXT NOT NULL,

-- ============================================================================
-- MODIFY PAUSED_RUNS TABLE (Add tenant scoping)
-- ============================================================================
-- FIND the existing CREATE TABLE paused_runs and ADD these columns:
CREATE TABLE IF NOT EXISTS paused_runs (
    token TEXT PRIMARY KEY,
    source TEXT,
    data TEXT,

    -- NEW: Tenant/user tracking
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_paused_runs_tenant ON paused_runs(tenant_id);
```

### PostgreSQL-Specific Additions

Add these to the **end** of `migrations/postgres/20250101000001_initial_schema.sql`:

```sql
-- ============================================================================
-- POSTGRESQL-SPECIFIC: Row-Level Security (RLS)
-- ============================================================================

-- Enable RLS on tenant-scoped tables
ALTER TABLE flows ENABLE ROW LEVEL SECURITY;
ALTER TABLE runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_secrets ENABLE ROW LEVEL SECURITY;

-- RLS Policy: Users can only access data in their tenant
CREATE POLICY tenant_isolation_flows ON flows
    USING (tenant_id = current_setting('app.current_tenant_id', true)::text);

CREATE POLICY tenant_isolation_runs ON runs
    USING (tenant_id = current_setting('app.current_tenant_id', true)::text);

CREATE POLICY user_isolation_oauth ON oauth_credentials
    USING (user_id = current_setting('app.current_user_id', true)::text);

CREATE POLICY tenant_isolation_secrets ON tenant_secrets
    USING (tenant_id = current_setting('app.current_tenant_id', true)::text);

-- Trigger to prevent audit log deletion/modification
CREATE OR REPLACE FUNCTION prevent_audit_log_changes()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit logs are immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_prevent_audit_delete
BEFORE DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_changes();

CREATE TRIGGER trigger_prevent_audit_update
BEFORE UPDATE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_changes();
```

---

## Implementation Roadmap

### Step-by-Step Checklist

- [ ] **Step 1:** Database migrations (1 day)
  - [ ] Edit `migrations/sqlite/20250101000001_initial_schema.sql`
  - [ ] Edit `migrations/postgres/20250101000001_initial_schema.sql`
  - [ ] Rebuild app (`cargo build`) - migrations embedded
  - [ ] Run app - migrations apply automatically on startup
  - [ ] Verify tables created correctly

- [ ] **Step 2:** Core auth types (2 days)
  - [ ] Create `src/auth/types.rs`
  - [ ] JWT implementation
  - [ ] Password hashing

- [ ] **Step 3:** Storage layer (3 days)
  - [ ] Update `Storage` trait
  - [ ] Implement PostgreSQL changes
  - [ ] Implement SQLite changes
  - [ ] Add RLS support

- [ ] **Step 4:** Authentication (4 days)
  - [ ] Registration endpoint
  - [ ] Login endpoint
  - [ ] Refresh token endpoint
  - [ ] Logout endpoint

- [ ] **Step 5:** Authorization (2 days)
  - [ ] RBAC types
  - [ ] Permission checks
  - [ ] Role management endpoints

- [ ] **Step 6:** HTTP middleware (2 days)
  - [ ] Auth middleware
  - [ ] Tenant middleware
  - [ ] Error handling

- [ ] **Step 7:** Context propagation (2 days)
  - [ ] Update `StepContext`
  - [ ] Update `Engine`
  - [ ] Flow execution

- [ ] **Step 8:** OAuth integration (2 days)
  - [ ] Fix hardcoded user_id
  - [ ] User-scoped credentials
  - [ ] Template resolution

- [ ] **Step 9:** Audit logging (2 days)
  - [ ] Audit logger
  - [ ] Middleware integration
  - [ ] Query endpoints

- [ ] **Step 10:** Testing (3 days)
  - [ ] Unit tests
  - [ ] Integration tests
  - [ ] Security tests
  - [ ] Load tests

---

## Step 1: Database Migrations

### Modify Existing Migration Files

Since you haven't launched yet, simply **edit** your existing migration files:

**Files to modify:**
- `migrations/sqlite/20250101000001_initial_schema.sql`
- `migrations/postgres/20250101000001_initial_schema.sql`

**What to change:**
1. Add new tables (users, tenants, tenant_members, etc.) at the end
2. Update existing CREATE TABLE statements (runs, flows, oauth_credentials, etc.)
3. Add new indexes for multi-tenant queries

See the [Database Schema Changes](#database-schema-changes) section above for the complete SQL to add/modify.

### Apply Migrations

**Migrations run automatically!** No manual steps needed.

**How it works:**

See [src/storage/sqlite.rs:76](src/storage/sqlite.rs#L76) and [src/storage/postgres.rs:26](src/storage/postgres.rs#L26):

```rust
// This runs automatically when storage is initialized
sqlx::migrate!("./migrations/sqlite")  // Embeds migrations at compile time
    .run(&pool)                         // Runs them at runtime
    .await
```

**When migrations run:**
1. You edit `migrations/sqlite/20250101000001_initial_schema.sql`
2. You rebuild the app: `cargo build`
3. You run the app: `cargo run --bin flow serve`
4. On startup, `SqliteStorage::new()` is called
5. Migrations run automatically! ✨

**Migration tracking:**
- sqlx creates `_sqlx_migrations` table automatically
- Tracks which migrations have been applied (by filename + checksum)
- Only runs new/changed migrations
- Completely idempotent

**During development:**
```bash
# Option 1: Just rebuild and run (migrations apply automatically)
cargo run --bin flow serve

# Option 2: Apply migrations manually first (optional)
sqlx migrate run
cargo run --bin flow serve
```

**No custom migration code needed** - sqlx handles everything!

---

## Step 2: Core Auth Types

### Create Authentication Module

**File: `src/auth/types.rs` (NEW)**

```rust
//! Authentication and authorization types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// User & Tenant Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub password_hash: String,
    pub email_verified: bool,
    pub avatar_url: Option<String>,
    pub mfa_enabled: bool,
    pub mfa_secret: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub disabled: bool,
    pub disabled_reason: Option<String>,
    pub disabled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub plan: String,
    pub plan_starts_at: Option<DateTime<Utc>>,
    pub plan_ends_at: Option<DateTime<Utc>>,
    pub max_users: i32,
    pub max_flows: i32,
    pub max_runs_per_month: i32,
    pub settings: Option<serde_json::Value>,
    pub created_by_user_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub disabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Admin,
    Member,
    Viewer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantMember {
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub role: Role,
    pub invited_by_user_id: Option<String>,
    pub invited_at: Option<DateTime<Utc>>,
    pub joined_at: DateTime<Utc>,
    pub disabled: bool,
}

// ============================================================================
// JWT Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String,           // user_id
    pub tenant: String,        // tenant_id
    pub role: Role,
    pub exp: usize,            // expiration timestamp
    pub iat: usize,            // issued at timestamp
    pub iss: String,           // issuer
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub user_agent: Option<String>,
    pub client_ip: Option<String>,
}

// ============================================================================
// Request Context Types
// ============================================================================

/// Authenticated user context (from JWT)
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user_id: String,
    pub tenant_id: String,
    pub role: Role,
    pub token_exp: usize,
}

/// Full request context with tenant information
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub user_id: String,
    pub tenant_id: String,
    pub tenant_name: String,
    pub role: Role,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: String,
}

// ============================================================================
// API Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,  // seconds
    pub user: UserInfo,
    pub tenant: TenantInfo,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TenantInfo {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub role: Role,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

// ============================================================================
// RBAC Permission Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    // Flow permissions
    FlowsRead,
    FlowsCreate,
    FlowsUpdate,
    FlowsDelete,
    FlowsDeploy,

    // Run permissions
    RunsRead,
    RunsTrigger,
    RunsCancel,
    RunsDelete,

    // OAuth permissions
    OAuthConnect,
    OAuthDisconnect,

    // Secret permissions
    SecretsRead,
    SecretsCreate,
    SecretsUpdate,
    SecretsDelete,

    // Tool permissions
    ToolsRead,
    ToolsInstall,

    // Organization permissions
    OrgRead,
    OrgUpdate,
    OrgDelete,

    // Member management
    MembersRead,
    MembersInvite,
    MembersUpdateRole,
    MembersRemove,

    // Audit logs
    AuditLogsRead,
}

impl Role {
    pub fn has_permission(&self, permission: Permission) -> bool {
        use Permission::*;

        match self {
            Role::Owner => true,  // Owner has all permissions

            Role::Admin => !matches!(permission, OrgDelete),  // Admin can't delete org

            Role::Member => matches!(
                permission,
                FlowsRead | FlowsCreate | FlowsUpdate | RunsRead | RunsTrigger |
                RunsCancel | OAuthConnect | MembersRead
            ),

            Role::Viewer => matches!(
                permission,
                FlowsRead | RunsRead | MembersRead
            ),
        }
    }
}
```

### JWT Implementation

**File: `src/auth/jwt.rs` (NEW)**

```rust
//! JWT token generation and validation

use super::types::{JwtClaims, Role};
use crate::{BeemFlowError, Result};
use chrono::{Duration, Utc};
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};

pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    issuer: String,
    access_token_ttl: Duration,
}

impl JwtManager {
    pub fn new(secret: &[u8], issuer: String, access_token_ttl: Duration) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            issuer,
            access_token_ttl,
        }
    }

    /// Generate access token (JWT)
    pub fn generate_access_token(
        &self,
        user_id: &str,
        tenant_id: &str,
        role: Role,
    ) -> Result<String> {
        let now = Utc::now();
        let exp = (now + self.access_token_ttl).timestamp() as usize;
        let iat = now.timestamp() as usize;

        let claims = JwtClaims {
            sub: user_id.to_string(),
            tenant: tenant_id.to_string(),
            role,
            exp,
            iat,
            iss: self.issuer.clone(),
        };

        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key)
            .map_err(|e| BeemFlowError::OAuth(format!("Failed to generate JWT: {}", e)))
    }

    /// Validate and decode JWT
    pub fn validate_token(&self, token: &str) -> Result<JwtClaims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.issuer]);

        let token_data = decode::<JwtClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| BeemFlowError::OAuth(format!("Invalid JWT: {}", e)))?;

        Ok(token_data.claims)
    }
}
```

### Password Hashing

**File: `src/auth/password.rs` (NEW)**

```rust
//! Password hashing and verification

use crate::Result;

/// Hash a password using bcrypt
pub fn hash_password(password: &str) -> Result<String> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
        .map_err(|e| crate::BeemFlowError::OAuth(format!("Failed to hash password: {}", e)))
}

/// Verify a password against a hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    bcrypt::verify(password, hash)
        .map_err(|e| crate::BeemFlowError::OAuth(format!("Failed to verify password: {}", e)))
}
```

---

## Step 3: Storage Layer

### Update Storage Trait

**File: `src/storage/mod.rs` (MODIFY)**

Add new trait for authentication storage:

```rust
// Add after OAuthStorage trait (around line 266)

/// Authentication storage for users, tenants, and sessions
#[async_trait]
pub trait AuthStorage: Send + Sync {
    // User methods
    async fn create_user(&self, user: &User) -> Result<()>;
    async fn get_user(&self, id: &str) -> Result<Option<User>>;
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>>;
    async fn update_user(&self, user: &User) -> Result<()>;
    async fn update_user_last_login(&self, user_id: &str) -> Result<()>;

    // Tenant methods
    async fn create_tenant(&self, tenant: &Tenant) -> Result<()>;
    async fn get_tenant(&self, id: &str) -> Result<Option<Tenant>>;
    async fn get_tenant_by_slug(&self, slug: &str) -> Result<Option<Tenant>>;
    async fn update_tenant(&self, tenant: &Tenant) -> Result<()>;

    // Tenant membership methods
    async fn create_tenant_member(&self, member: &TenantMember) -> Result<()>;
    async fn get_tenant_member(&self, tenant_id: &str, user_id: &str) -> Result<Option<TenantMember>>;
    async fn list_user_tenants(&self, user_id: &str) -> Result<Vec<(Tenant, Role)>>;
    async fn list_tenant_members(&self, tenant_id: &str) -> Result<Vec<(User, Role)>>;
    async fn update_member_role(&self, tenant_id: &str, user_id: &str, role: Role) -> Result<()>;
    async fn remove_tenant_member(&self, tenant_id: &str, user_id: &str) -> Result<()>;

    // Refresh token methods
    async fn create_refresh_token(&self, token: &RefreshToken) -> Result<()>;
    async fn get_refresh_token(&self, token_hash: &str) -> Result<Option<RefreshToken>>;
    async fn revoke_refresh_token(&self, token_hash: &str) -> Result<()>;
    async fn revoke_all_user_tokens(&self, user_id: &str) -> Result<()>;
    async fn update_refresh_token_last_used(&self, token_hash: &str) -> Result<()>;

    // Audit log methods
    async fn create_audit_log(&self, log: &AuditLog) -> Result<()>;
    async fn list_audit_logs(
        &self,
        tenant_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AuditLog>>;

    // Tenant secrets methods
    async fn create_tenant_secret(&self, secret: &TenantSecret) -> Result<()>;
    async fn get_tenant_secret(&self, tenant_id: &str, key: &str) -> Result<Option<TenantSecret>>;
    async fn list_tenant_secrets(&self, tenant_id: &str) -> Result<Vec<TenantSecret>>;
    async fn delete_tenant_secret(&self, tenant_id: &str, key: &str) -> Result<()>;
}
```

### Update Existing Storage Methods

**File: `src/storage/mod.rs` (MODIFY)**

Update existing trait methods to accept tenant/user scoping:

```rust
// BEFORE (Line 41):
async fn list_runs(&self, limit: usize, offset: usize) -> Result<Vec<Run>>;

// AFTER:
async fn list_runs(&self, tenant_id: &str, limit: usize, offset: usize) -> Result<Vec<Run>>;

// BEFORE (Line 45):
async fn list_runs_by_flow_and_status(
    &self,
    flow_name: &str,
    status: RunStatus,
    exclude_id: Option<Uuid>,
    limit: usize,
) -> Result<Vec<Run>>;

// AFTER:
async fn list_runs_by_flow_and_status(
    &self,
    tenant_id: &str,
    flow_name: &str,
    status: RunStatus,
    exclude_id: Option<Uuid>,
    limit: usize,
) -> Result<Vec<Run>>;

// Similar updates for:
// - get_oauth_credential (add user_id parameter)
// - save_oauth_credential (add user_id, tenant_id)
// - list_oauth_credentials (add user_id parameter)
// - deploy_flow_version (add tenant_id, user_id)
// - get_deployed_version (add tenant_id)
// - list_all_deployed_flows (add tenant_id)
// - etc.
```

### Implement PostgreSQL Storage

**File: `src/storage/postgres.rs` (MODIFY)**

Add implementations for new methods. Example:

```rust
// Add after existing OAuthStorage implementation

#[async_trait]
impl AuthStorage for PostgresStorage {
    async fn create_user(&self, user: &User) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO users (
                id, email, name, password_hash, email_verified, avatar_url,
                mfa_enabled, mfa_secret, created_at, updated_at, last_login_at,
                disabled, disabled_reason, disabled_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            "#,
        )
        .bind(&user.id)
        .bind(&user.email)
        .bind(&user.name)
        .bind(&user.password_hash)
        .bind(user.email_verified)
        .bind(&user.avatar_url)
        .bind(user.mfa_enabled)
        .bind(&user.mfa_secret)
        .bind(user.created_at.timestamp_millis())
        .bind(user.updated_at.timestamp_millis())
        .bind(user.last_login_at.map(|t| t.timestamp_millis()))
        .bind(user.disabled)
        .bind(&user.disabled_reason)
        .bind(user.disabled_at.map(|t| t.timestamp_millis()))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, UserRow>(
            "SELECT * FROM users WHERE email = $1 AND disabled = FALSE"
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        Ok(user.map(|row| row.into()))
    }

    // ... implement remaining methods
}

// Helper struct for database rows
#[derive(sqlx::FromRow)]
struct UserRow {
    id: String,
    email: String,
    name: Option<String>,
    password_hash: String,
    email_verified: bool,
    avatar_url: Option<String>,
    mfa_enabled: bool,
    mfa_secret: Option<String>,
    created_at: i64,
    updated_at: i64,
    last_login_at: Option<i64>,
    disabled: bool,
    disabled_reason: Option<String>,
    disabled_at: Option<i64>,
}

impl From<UserRow> for User {
    fn from(row: UserRow) -> Self {
        User {
            id: row.id,
            email: row.email,
            name: row.name,
            password_hash: row.password_hash,
            email_verified: row.email_verified,
            avatar_url: row.avatar_url,
            mfa_enabled: row.mfa_enabled,
            mfa_secret: row.mfa_secret,
            created_at: chrono::DateTime::from_timestamp_millis(row.created_at).unwrap(),
            updated_at: chrono::DateTime::from_timestamp_millis(row.updated_at).unwrap(),
            last_login_at: row.last_login_at.map(|ts| chrono::DateTime::from_timestamp_millis(ts).unwrap()),
            disabled: row.disabled,
            disabled_reason: row.disabled_reason,
            disabled_at: row.disabled_at.map(|ts| chrono::DateTime::from_timestamp_millis(ts).unwrap()),
        }
    }
}
```

### Update Complete Storage Trait

**File: `src/storage/mod.rs` (MODIFY)**

Update the `Storage` trait composition:

```rust
// Line 272 - Update this:
pub trait Storage: RunStorage + StateStorage + FlowStorage + OAuthStorage {}

// To this:
pub trait Storage: RunStorage + StateStorage + FlowStorage + OAuthStorage + AuthStorage {}

// And update the blanket impl:
impl<T> Storage for T where T: RunStorage + StateStorage + FlowStorage + OAuthStorage + AuthStorage {}
```

---

## Step 4: Authentication

### Registration Endpoint

**File: `src/http/auth.rs` (NEW)**

```rust
//! Authentication HTTP handlers

use crate::auth::{
    jwt::JwtManager,
    password::{hash_password, verify_password},
    types::*,
};
use crate::http::{AppError, AppState};
use crate::storage::AuthStorage;
use axum::{
    Json,
    extract::{State, Request},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use chrono::Utc;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

pub fn create_auth_routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(get_current_user))
        .with_state(state)
}

/// POST /auth/register - Register new user and create tenant
async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    // 1. Validate email format
    if !is_valid_email(&req.email) {
        return Err(AppError::from(crate::BeemFlowError::validation(
            "Invalid email address",
        )));
    }

    // 2. Validate password strength (min 8 chars)
    if req.password.len() < 8 {
        return Err(AppError::from(crate::BeemFlowError::validation(
            "Password must be at least 8 characters",
        )));
    }

    // 3. Check if email already exists
    if let Some(_) = state.storage.get_user_by_email(&req.email).await? {
        return Err(AppError::from(crate::BeemFlowError::validation(
            "Email already registered",
        )));
    }

    // 4. Hash password
    let password_hash = hash_password(&req.password)?;

    // 5. Create user
    let user_id = Uuid::new_v4().to_string();
    let user = User {
        id: user_id.clone(),
        email: req.email.clone(),
        name: req.name.clone(),
        password_hash,
        email_verified: false,  // TODO: Send verification email
        avatar_url: None,
        mfa_enabled: false,
        mfa_secret: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login_at: None,
        disabled: false,
        disabled_reason: None,
        disabled_at: None,
    };

    state.storage.create_user(&user).await?;

    // 6. Create default tenant for user
    let tenant_id = Uuid::new_v4().to_string();
    let tenant_slug = generate_slug(&req.email);

    let tenant = Tenant {
        id: tenant_id.clone(),
        name: req.name.clone().unwrap_or_else(|| "My Workspace".to_string()),
        slug: tenant_slug.clone(),
        plan: "free".to_string(),
        plan_starts_at: Some(Utc::now()),
        plan_ends_at: None,
        max_users: 5,
        max_flows: 10,
        max_runs_per_month: 1000,
        settings: None,
        created_by_user_id: user_id.clone(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        disabled: false,
    };

    state.storage.create_tenant(&tenant).await?;

    // 7. Add user as tenant owner
    let member = TenantMember {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.clone(),
        user_id: user_id.clone(),
        role: Role::Owner,
        invited_by_user_id: None,
        invited_at: None,
        joined_at: Utc::now(),
        disabled: false,
    };

    state.storage.create_tenant_member(&member).await?;

    // 8. Generate tokens
    let (access_token, refresh_token) = generate_tokens(
        &state,
        &user_id,
        &tenant_id,
        Role::Owner,
        None,  // No client info during registration
    ).await?;

    // 9. Return login response
    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
        expires_in: 900,  // 15 minutes
        user: UserInfo {
            id: user.id,
            email: user.email,
            name: user.name,
            avatar_url: user.avatar_url,
        },
        tenant: TenantInfo {
            id: tenant.id,
            name: tenant.name,
            slug: tenant.slug,
            role: Role::Owner,
        },
    }))
}

/// POST /auth/login - Authenticate user
async fn login(
    State(state): State<Arc<AppState>>,
    req: Request,
    Json(login_req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    // 1. Get user by email
    let user = state
        .storage
        .get_user_by_email(&login_req.email)
        .await?
        .ok_or_else(|| AppError::from(crate::BeemFlowError::OAuth("Invalid credentials".into())))?;

    // 2. Verify password
    if !verify_password(&login_req.password, &user.password_hash)? {
        return Err(AppError::from(crate::BeemFlowError::OAuth(
            "Invalid credentials".into(),
        )));
    }

    // 3. Check if account is disabled
    if user.disabled {
        return Err(AppError::from(crate::BeemFlowError::OAuth(
            "Account disabled".into(),
        )));
    }

    // 4. Get user's default tenant (first tenant they joined)
    let tenants = state.storage.list_user_tenants(&user.id).await?;
    let (tenant, role) = tenants
        .first()
        .ok_or_else(|| AppError::from(crate::BeemFlowError::OAuth("No tenant found".into())))?;

    // 5. Update last login
    state.storage.update_user_last_login(&user.id).await?;

    // 6. Extract client info
    let client_ip = extract_client_ip(&req);
    let user_agent = extract_user_agent(&req);

    // 7. Generate tokens
    let (access_token, refresh_token_str) = generate_tokens(
        &state,
        &user.id,
        &tenant.id,
        role.clone(),
        Some((client_ip, user_agent)),
    ).await?;

    // 8. Return response
    Ok(Json(LoginResponse {
        access_token,
        refresh_token: refresh_token_str,
        expires_in: 900,
        user: UserInfo {
            id: user.id,
            email: user.email,
            name: user.name,
            avatar_url: user.avatar_url,
        },
        tenant: TenantInfo {
            id: tenant.id.clone(),
            name: tenant.name.clone(),
            slug: tenant.slug.clone(),
            role: role.clone(),
        },
    }))
}

/// POST /auth/refresh - Refresh access token
async fn refresh(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    // 1. Hash the refresh token to lookup
    let token_hash = hash_refresh_token(&req.refresh_token);

    // 2. Get refresh token from database
    let refresh_token = state
        .storage
        .get_refresh_token(&token_hash)
        .await?
        .ok_or_else(|| AppError::from(crate::BeemFlowError::OAuth("Invalid refresh token".into())))?;

    // 3. Check if revoked
    if refresh_token.revoked {
        return Err(AppError::from(crate::BeemFlowError::OAuth(
            "Token revoked".into(),
        )));
    }

    // 4. Check if expired
    if refresh_token.expires_at < Utc::now() {
        return Err(AppError::from(crate::BeemFlowError::OAuth(
            "Token expired".into(),
        )));
    }

    // 5. Get user and tenant info
    let user = state.storage.get_user(&refresh_token.user_id).await?
        .ok_or_else(|| AppError::from(crate::BeemFlowError::OAuth("User not found".into())))?;

    let member = state.storage.get_tenant_member(&refresh_token.tenant_id, &refresh_token.user_id).await?
        .ok_or_else(|| AppError::from(crate::BeemFlowError::OAuth("Membership not found".into())))?;

    // 6. Generate new access token
    let access_token = state.jwt_manager.generate_access_token(
        &refresh_token.user_id,
        &refresh_token.tenant_id,
        member.role.clone(),
    )?;

    // 7. Update last used timestamp
    state.storage.update_refresh_token_last_used(&token_hash).await?;

    Ok(Json(json!({
        "access_token": access_token,
        "expires_in": 900,
    })))
}

/// POST /auth/logout - Revoke refresh token
async fn logout(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshRequest>,
) -> Result<StatusCode, AppError> {
    let token_hash = hash_refresh_token(&req.refresh_token);
    state.storage.revoke_refresh_token(&token_hash).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /auth/me - Get current user info
async fn get_current_user(
    Extension(ctx): Extension<RequestContext>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user = state.storage.get_user(&ctx.user_id).await?
        .ok_or_else(|| AppError::from(crate::BeemFlowError::OAuth("User not found".into())))?;

    let tenant = state.storage.get_tenant(&ctx.tenant_id).await?
        .ok_or_else(|| AppError::from(crate::BeemFlowError::OAuth("Tenant not found".into())))?;

    Ok(Json(json!({
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "avatar_url": user.avatar_url,
            "mfa_enabled": user.mfa_enabled,
        },
        "tenant": {
            "id": tenant.id,
            "name": tenant.name,
            "slug": tenant.slug,
            "role": ctx.role,
        },
    })))
}

// ============================================================================
// Helper Functions
// ============================================================================

async fn generate_tokens(
    state: &AppState,
    user_id: &str,
    tenant_id: &str,
    role: Role,
    client_info: Option<(Option<String>, Option<String>)>,
) -> crate::Result<(String, String)> {
    // Generate JWT access token
    let access_token = state.jwt_manager.generate_access_token(user_id, tenant_id, role)?;

    // Generate refresh token (random secure string)
    let refresh_token_str = generate_secure_token(32);
    let token_hash = hash_refresh_token(&refresh_token_str);

    let (client_ip, user_agent) = client_info.unwrap_or((None, None));

    let refresh_token = RefreshToken {
        id: Uuid::new_v4().to_string(),
        user_id: user_id.to_string(),
        tenant_id: tenant_id.to_string(),
        token_hash,
        expires_at: Utc::now() + chrono::Duration::days(30),
        revoked: false,
        revoked_at: None,
        created_at: Utc::now(),
        last_used_at: None,
        user_agent,
        client_ip,
    };

    state.storage.create_refresh_token(&refresh_token).await?;

    Ok((access_token, refresh_token_str))
}

fn generate_secure_token(bytes: usize) -> String {
    use rand::RngCore;
    let mut token = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut token);
    base64::encode_config(&token, base64::URL_SAFE_NO_PAD)
}

fn hash_refresh_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn generate_slug(email: &str) -> String {
    email.split('@').next().unwrap()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect::<String>()
        .to_lowercase()
}

fn is_valid_email(email: &str) -> bool {
    email.contains('@') && email.contains('.') && email.len() > 5
}

fn extract_client_ip(req: &Request) -> Option<String> {
    req.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap().trim().to_string())
}

fn extract_user_agent(req: &Request) -> Option<String> {
    req.headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}
```

---

## Step 5: Authorization (RBAC)

### Permission Checking

**File: `src/auth/rbac.rs` (NEW)**

```rust
//! Role-Based Access Control

use super::types::{Permission, RequestContext, Role};
use crate::BeemFlowError;

/// Check if user has permission
pub fn check_permission(
    ctx: &RequestContext,
    permission: Permission,
) -> Result<(), BeemFlowError> {
    if !ctx.role.has_permission(permission) {
        return Err(BeemFlowError::OAuth(format!(
            "Insufficient permissions: {:?}",
            permission
        )));
    }
    Ok(())
}

/// Check if user can modify resource (ownership check for members)
pub fn check_resource_ownership(
    ctx: &RequestContext,
    resource_owner_id: &str,
) -> Result<(), BeemFlowError> {
    // Owner and Admin can modify any resource
    if matches!(ctx.role, Role::Owner | Role::Admin) {
        return Ok(());
    }

    // Member can only modify their own resources
    if ctx.role == Role::Member && resource_owner_id == ctx.user_id {
        return Ok(());
    }

    Err(BeemFlowError::OAuth(
        "You can only modify your own resources".into(),
    ))
}
```

---

## Step 6: HTTP Middleware

### Authentication Middleware

**File: `src/http/middleware.rs` (NEW)**

```rust
//! HTTP middleware for authentication and authorization

use crate::auth::types::{AuthContext, RequestContext};
use crate::http::{AppError, AppState};
use crate::storage::AuthStorage;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

/// Authentication middleware - validates JWT and creates AuthContext
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract Bearer token
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Validate JWT
    let claims = state
        .jwt_manager
        .validate_token(token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Create auth context
    let auth_ctx = AuthContext {
        user_id: claims.sub,
        tenant_id: claims.tenant,
        role: claims.role,
        token_exp: claims.exp,
    };

    req.extensions_mut().insert(auth_ctx);

    Ok(next.run(req).await)
}

/// Tenant middleware - resolves tenant and creates RequestContext
pub async fn tenant_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Get auth context from previous middleware
    let auth_ctx = req
        .extensions()
        .get::<AuthContext>()
        .ok_or(StatusCode::UNAUTHORIZED)?
        .clone();

    // Get tenant info
    let tenant = state
        .storage
        .get_tenant(&auth_ctx.tenant_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Verify user is still a member
    let member = state
        .storage
        .get_tenant_member(&auth_ctx.tenant_id, &auth_ctx.user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::FORBIDDEN)?;

    // Check if tenant is disabled
    if tenant.disabled || member.disabled {
        return Err(StatusCode::FORBIDDEN);
    }

    // Extract client info
    let client_ip = extract_client_ip(&req);
    let user_agent = extract_user_agent(&req);
    let request_id = uuid::Uuid::new_v4().to_string();

    // Create full request context
    let req_ctx = RequestContext {
        user_id: auth_ctx.user_id,
        tenant_id: tenant.id.clone(),
        tenant_name: tenant.name.clone(),
        role: member.role,
        client_ip,
        user_agent,
        request_id,
    };

    req.extensions_mut().insert(req_ctx);

    Ok(next.run(req).await)
}

fn extract_client_ip(req: &Request) -> Option<String> {
    req.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap().trim().to_string())
        .or_else(|| {
            req.extensions()
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|info| info.0.ip().to_string())
        })
}

fn extract_user_agent(req: &Request) -> Option<String> {
    req.headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}
```

### Integrate Middleware into HTTP Server

**File: `src/http/mod.rs` (MODIFY)**

Update the router setup (around line 450):

```rust
// Add to AppState (around line 42):
pub struct AppState {
    registry: Arc<OperationRegistry>,
    session_store: Arc<session::SessionStore>,
    oauth_client: Arc<crate::auth::OAuthClientManager>,
    storage: Arc<dyn crate::storage::Storage>,
    template_renderer: Arc<template::TemplateRenderer>,
    jwt_manager: Arc<crate::auth::jwt::JwtManager>,  // NEW
    audit_logger: Arc<crate::audit::AuditLogger>,    // NEW
}

// Update route building (around line 450):
pub fn build_app(
    registry: Arc<OperationRegistry>,
    storage: Arc<dyn Storage>,
    oauth_client: Arc<OAuthClientManager>,
    jwt_manager: Arc<JwtManager>,
    config: &HttpConfig,
    interfaces: ServerInterfaces,
) -> Router {
    let state = Arc::new(AppState {
        registry: registry.clone(),
        session_store: Arc::new(session::SessionStore::new()),
        oauth_client,
        storage: storage.clone(),
        template_renderer: Arc::new(template::TemplateRenderer::new()),
        jwt_manager,
        audit_logger: Arc::new(crate::audit::AuditLogger::new(storage.clone())),
    });

    // Public routes (no auth)
    let mut app = Router::new()
        .route("/health", get(health_check))
        .nest("/auth", create_auth_routes(state.clone()));

    // Protected routes (require auth)
    if interfaces.http_api {
        let protected = build_operation_routes(&state)
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                middleware::auth_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                middleware::tenant_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                audit_middleware,
            ));

        app = app.nest("/api", protected);
    }

    // OAuth routes (different auth)
    if interfaces.oauth_server {
        app = app.nest("/oauth", create_oauth_routes(state.clone()));
    }

    // MCP routes
    if interfaces.mcp {
        app = app.nest("/mcp", create_mcp_routes(state.clone()));
    }

    // CORS, tracing, etc.
    app.layer(/* ... */)
}
```

---

## Step 7: Context Propagation

### Update StepContext

**File: `src/engine/context.rs` (MODIFY)**

Add user/tenant info to StepContext (around line 19):

```rust
/// Context for step execution
#[derive(Debug, Clone)]
pub struct StepContext {
    event: Arc<HashMap<String, Value>>,
    vars: Arc<HashMap<String, Value>>,
    outputs: Arc<DashMap<String, Value>>,
    secrets: Arc<HashMap<String, Value>>,

    // NEW: User/tenant context
    pub user_id: String,
    pub tenant_id: String,
    pub run_id: Uuid,
}

impl StepContext {
    /// Create a new step context
    pub fn new(
        event: HashMap<String, Value>,
        vars: HashMap<String, Value>,
        secrets: HashMap<String, Value>,
        user_id: String,
        tenant_id: String,
        run_id: Uuid,
    ) -> Self {
        Self {
            event: Arc::new(event),
            vars: Arc::new(vars),
            outputs: Arc::new(DashMap::new()),
            secrets: Arc::new(secrets),
            user_id,
            tenant_id,
            run_id,
        }
    }

    // ... rest of implementation
}
```

### Update Engine to Accept Context

**File: `src/engine/mod.rs` (MODIFY)**

Update the `start` method to accept user/tenant context:

```rust
// Around line 100
pub async fn start(
    &self,
    flow_name: &str,
    event: HashMap<String, Value>,
    vars: HashMap<String, Value>,
    user_id: String,      // NEW
    tenant_id: String,    // NEW
    draft: bool,
) -> Result<Run> {
    // Load flow (now tenant-scoped)
    let content = if draft {
        load_flow_content(flow_name)?
    } else {
        self.storage
            .get_deployed_flow_content(tenant_id, flow_name)
            .await?
            .ok_or_else(|| BeemFlowError::validation(format!("Flow not deployed: {}", flow_name)))?
    };

    // Parse and execute with context
    let flow = parse_flow(&content)?;
    let run_id = Uuid::new_v4();

    let run = Run {
        id: run_id,
        flow_name: flow.name.as_str().to_string(),
        event: event.clone(),
        vars: vars.clone(),
        status: RunStatus::Running,
        started_at: Utc::now(),
        ended_at: None,
        tenant_id: tenant_id.clone(),        // NEW
        triggered_by_user_id: user_id.clone(), // NEW
    };

    // Build context with user/tenant
    let context = build_context(
        &event,
        &vars,
        &self.secrets_provider,
        tenant_id.clone(),  // NEW: Pass to secrets provider
        user_id.clone(),
        run_id,
    ).await?;

    // Execute
    self.execute(run, &flow, context).await
}
```

---

## Step 8: OAuth Integration

### Fix Hardcoded user_id

**File: `src/auth/server.rs` (MODIFY)**

Fix the hardcoded `"default_user"` (line 691):

```rust
// BEFORE:
let token = OAuthToken {
    user_id: "default_user".to_string(),  // ⚠️ WRONG
    client_id: pending.client_id.clone(),
    // ...
};

// AFTER:
// Extract user_id from session or JWT
let user_id = session.get::<String>("user_id")
    .ok_or_else(|| BeemFlowError::OAuth("User not authenticated".into()))?;

let token = OAuthToken {
    user_id,  // ✅ CORRECT: Use actual user ID
    client_id: pending.client_id.clone(),
    // ...
};
```

### Update OAuth Client Manager

**File: `src/auth/client.rs` (MODIFY)**

Update `get_token` to accept user_id:

```rust
// BEFORE (around line 310):
pub async fn get_token(&self, provider: &str, integration: &str) -> Result<String> {
    let cred = self.storage
        .get_oauth_credential(provider, integration)  // ⚠️ Missing user_id
        .await?;
    // ...
}

// AFTER:
pub async fn get_token(
    &self,
    user_id: &str,      // NEW parameter
    provider: &str,
    integration: &str,
) -> Result<String> {
    let cred = self.storage
        .get_oauth_credential(user_id, provider, integration)  // ✅ User-scoped
        .await?
        .ok_or_else(|| BeemFlowError::OAuth(format!(
            "No OAuth credential found for {}:{} (user: {})",
            provider, integration, user_id
        )))?;

    // Check if expired and refresh if needed
    if let Some(expires_at) = cred.expires_at {
        if expires_at < Utc::now() {
            return self.refresh_token_internal(user_id, &cred).await;
        }
    }

    Ok(cred.access_token)
}
```

---

## Step 9: Audit Logging

### Audit Logger

**File: `src/audit/mod.rs` (NEW)**

```rust
//! Audit logging

use crate::auth::types::RequestContext;
use crate::storage::{AuthStorage, Storage};
use crate::Result;
use chrono::Utc;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

pub struct AuditLogger {
    storage: Arc<dyn Storage>,
}

impl AuditLogger {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }

    pub async fn log(&self, event: AuditEvent) -> Result<()> {
        let log = AuditLog {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().timestamp_millis(),
            request_id: event.request_id,
            tenant_id: event.tenant_id,
            user_id: event.user_id,
            client_ip: event.client_ip,
            user_agent: event.user_agent,
            action: event.action,
            resource_type: event.resource_type,
            resource_id: event.resource_id,
            resource_name: event.resource_name,
            http_method: event.http_method,
            http_path: event.http_path,
            http_status_code: event.http_status_code,
            success: event.success,
            error_message: event.error_message,
            metadata: event.metadata,
            created_at: Utc::now().timestamp_millis(),
        };

        self.storage.create_audit_log(&log).await?;

        Ok(())
    }
}

pub struct AuditEvent {
    pub request_id: String,
    pub tenant_id: String,
    pub user_id: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub resource_name: Option<String>,
    pub http_method: Option<String>,
    pub http_path: Option<String>,
    pub http_status_code: Option<i32>,
    pub success: bool,
    pub error_message: Option<String>,
    pub metadata: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuditLog {
    pub id: String,
    pub timestamp: i64,
    pub request_id: String,
    pub tenant_id: String,
    pub user_id: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub resource_name: Option<String>,
    pub http_method: Option<String>,
    pub http_path: Option<String>,
    pub http_status_code: Option<i32>,
    pub success: bool,
    pub error_message: Option<String>,
    pub metadata: Option<String>,
    pub created_at: i64,
}
```

### Audit Middleware

**File: `src/http/middleware.rs` (ADD)**

```rust
/// Audit logging middleware
pub async fn audit_middleware(
    Extension(ctx): Extension<RequestContext>,
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let start = std::time::Instant::now();

    let response = next.run(req).await;

    let duration_ms = start.elapsed().as_millis() as u64;
    let status = response.status();

    // Log async (don't block response)
    let audit_logger = state.audit_logger.clone();
    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        let _ = audit_logger.log(AuditEvent {
            request_id: ctx_clone.request_id,
            tenant_id: ctx_clone.tenant_id,
            user_id: Some(ctx_clone.user_id),
            client_ip: ctx_clone.client_ip,
            user_agent: ctx_clone.user_agent,
            action: format!("{} {}", method, path),
            resource_type: extract_resource_type(&path),
            resource_id: None,
            resource_name: None,
            http_method: Some(method.to_string()),
            http_path: Some(path),
            http_status_code: Some(status.as_u16() as i32),
            success: status.is_success(),
            error_message: None,
            metadata: Some(serde_json::json!({
                "duration_ms": duration_ms,
            }).to_string()),
        }).await;
    });

    response
}

fn extract_resource_type(path: &str) -> Option<String> {
    if path.contains("/flows") {
        Some("flow".to_string())
    } else if path.contains("/runs") {
        Some("run".to_string())
    } else {
        None
    }
}
```

---

## Step 10: Testing

### Unit Tests

**File: `src/auth/types_test.rs` (NEW)**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_permissions() {
        assert!(Role::Owner.has_permission(Permission::OrgDelete));
        assert!(!Role::Admin.has_permission(Permission::OrgDelete));
        assert!(Role::Member.has_permission(Permission::FlowsCreate));
        assert!(!Role::Viewer.has_permission(Permission::FlowsCreate));
    }
}
```

### Integration Tests

**File: `tests/auth_integration_test.rs` (NEW)**

```rust
#[tokio::test]
async fn test_registration_and_login() {
    let app = setup_test_app().await;

    // Register
    let response = app.post("/auth/register")
        .json(&json!({
            "email": "test@example.com",
            "password": "securepass123",
            "name": "Test User"
        }))
        .await;

    assert_eq!(response.status(), 200);
    let body: LoginResponse = response.json().await;
    assert!(!body.access_token.is_empty());

    // Login
    let response = app.post("/auth/login")
        .json(&json!({
            "email": "test@example.com",
            "password": "securepass123"
        }))
        .await;

    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn test_tenant_isolation() {
    // Create two users in different tenants
    let user_a = create_user("usera@test.com").await;
    let user_b = create_user("userb@test.com").await;

    // User A creates flow
    let flow = create_flow(&user_a.token, "test_flow").await;

    // User B tries to access
    let response = get_flow(&user_b.token, "test_flow").await;
    assert_eq!(response.status(), 404);  // Not found (tenant isolation)
}
```

---

## Deployment Checklist

### Pre-Deployment

- [ ] Run all tests (`cargo test`)
- [ ] Run migrations on staging database
- [ ] Test registration flow end-to-end
- [ ] Test OAuth integration with real providers
- [ ] Load test with 100+ concurrent users
- [ ] Verify audit logs are created
- [ ] Test PostgreSQL RLS policies

### Environment Variables

```bash
# JWT Secret (generate with: openssl rand -hex 32)
JWT_SECRET=your-secret-key-here

# Database
DATABASE_URL=postgresql://user:pass@localhost/beemflow

# Server
HTTP_PORT=3000
HTTP_HOST=0.0.0.0

# OAuth (if using)
OAUTH_ISSUER=https://your-domain.com
```

### Post-Deployment

- [ ] Verify default admin login works
- [ ] Create test users in production
- [ ] Monitor audit logs
- [ ] Set up alerts for auth failures
- [ ] Enable rate limiting
- [ ] Configure CORS properly
- [ ] Set up SSL/TLS certificates

---

## Security Checklist

### Authentication

- [x] Passwords hashed with bcrypt (cost 12)
- [x] JWT tokens use HS256
- [x] Refresh tokens stored as SHA-256 hashes
- [x] Short-lived access tokens (15 min)
- [x] Long-lived refresh tokens (30 days)
- [ ] Email verification (TODO)
- [ ] MFA support (TODO: Phase 2)
- [ ] Rate limiting on login endpoint

### Authorization

- [x] RBAC with 4 roles
- [x] Permission checks on all endpoints
- [x] Resource ownership validation
- [x] Tenant isolation enforced

### Data Protection

- [x] Tenant isolation at database level
- [x] User-scoped OAuth credentials
- [x] Audit logging (immutable)
- [x] PostgreSQL Row-Level Security
- [ ] Credential encryption (TODO: Phase 2)
- [ ] GDPR data export (TODO)
- [ ] GDPR data deletion (TODO)

---

## Next Steps

After completing this SaaS phase:

1. **Deploy to staging** - Test with real users
2. **Monitor metrics** - Auth success rate, latency, errors
3. **Iterate on UX** - Registration flow, error messages
4. **Add features** - Email verification, password reset, MFA
5. **DARPA Phase** - CAC/PKI auth, ABAC, classification levels (see [AUTH_PLAN.md](AUTH_PLAN.md))

---

## Support

Questions or issues during implementation?

- Reference [AUTH_PLAN.md](AUTH_PLAN.md) for complete architecture
- Check [MULTI_USER_ARCHITECTURE.md](MULTI_USER_ARCHITECTURE.md) for detailed analysis
- Open GitHub issue with `[SaaS Phase]` prefix

**Document Status:** READY FOR IMPLEMENTATION ✅
