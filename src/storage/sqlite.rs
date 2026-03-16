//! SQLite storage implementation
//!
//! Provides persistent storage for flows, runs, steps, and OAuth data using SQLite.

use crate::model::*;
use crate::storage::{
    FlowSnapshot, FlowStorage, OAuthStorage, RunStorage, StateStorage, sql_common::*,
};
use crate::{BeemFlowError, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, SqlitePool};
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;

// ============================================================================
// SQLite Row Types (FromRow) - compile-time verified column mappings
// ============================================================================

/// SQLite runs table - matches schema exactly
#[derive(FromRow)]
struct RunRow {
    id: String,
    flow_name: String,
    event: String,
    vars: String,
    status: String,
    started_at: i64,
    ended_at: Option<i64>,
    organization_id: String,
    triggered_by_user_id: String,
}

impl TryFrom<RunRow> for Run {
    type Error = BeemFlowError;

    fn try_from(row: RunRow) -> Result<Self> {
        Ok(Run {
            id: Uuid::parse_str(&row.id)?,
            flow_name: FlowName::new(row.flow_name)?,
            event: serde_json::from_str(&row.event)?,
            vars: serde_json::from_str(&row.vars)?,
            status: parse_run_status(&row.status),
            started_at: DateTime::from_timestamp_millis(row.started_at).unwrap_or_else(Utc::now),
            ended_at: row.ended_at.and_then(DateTime::from_timestamp_millis),
            steps: None,
            organization_id: row.organization_id,
            triggered_by_user_id: row.triggered_by_user_id,
        })
    }
}

/// SQLite steps table - matches schema exactly
#[derive(FromRow)]
struct StepRow {
    id: String,
    run_id: String,
    organization_id: String,
    step_name: String,
    status: String,
    started_at: i64,
    ended_at: Option<i64>,
    outputs: String,
    error: Option<String>,
}

impl TryFrom<StepRow> for StepRun {
    type Error = BeemFlowError;

    fn try_from(row: StepRow) -> Result<Self> {
        Ok(StepRun {
            id: Uuid::parse_str(&row.id)?,
            run_id: Uuid::parse_str(&row.run_id)?,
            organization_id: row.organization_id,
            step_name: StepId::new(row.step_name)?,
            status: parse_step_status(&row.status),
            started_at: DateTime::from_timestamp_millis(row.started_at).unwrap_or_else(Utc::now),
            ended_at: row.ended_at.and_then(DateTime::from_timestamp_millis),
            outputs: serde_json::from_str(&row.outputs)?,
            error: row.error,
        })
    }
}

/// SQLite users table - matches schema exactly
#[derive(FromRow)]
struct UserRow {
    id: String,
    email: String,
    name: Option<String>,
    password_hash: String,
    email_verified: i32,
    avatar_url: Option<String>,
    mfa_enabled: i32,
    mfa_secret: Option<String>,
    created_at: i64,
    updated_at: i64,
    last_login_at: Option<i64>,
    disabled: i32,
    disabled_reason: Option<String>,
    disabled_at: Option<i64>,
}

impl TryFrom<UserRow> for crate::auth::User {
    type Error = BeemFlowError;

    fn try_from(row: UserRow) -> Result<Self> {
        Ok(crate::auth::User {
            id: row.id,
            email: row.email,
            name: row.name,
            password_hash: row.password_hash,
            email_verified: row.email_verified != 0,
            avatar_url: row.avatar_url,
            mfa_enabled: row.mfa_enabled != 0,
            mfa_secret: row.mfa_secret,
            created_at: DateTime::from_timestamp_millis(row.created_at).unwrap_or_else(Utc::now),
            updated_at: DateTime::from_timestamp_millis(row.updated_at).unwrap_or_else(Utc::now),
            last_login_at: row.last_login_at.and_then(DateTime::from_timestamp_millis),
            disabled: row.disabled != 0,
            disabled_reason: row.disabled_reason,
            disabled_at: row.disabled_at.and_then(DateTime::from_timestamp_millis),
        })
    }
}

/// SQLite oauth_credentials table - matches schema exactly
#[derive(FromRow)]
struct OAuthCredentialRow {
    id: String,
    provider: String,
    integration: String,
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<i64>,
    scope: Option<String>,
    created_at: i64,
    updated_at: i64,
    user_id: String,
    organization_id: String,
}

impl OAuthCredentialRow {
    fn into_credential(self) -> Result<OAuthCredential> {
        let (access_token, refresh_token) =
            crate::auth::TokenEncryption::decrypt_credential_tokens(
                self.access_token,
                self.refresh_token,
            )?;

        Ok(OAuthCredential {
            id: self.id,
            provider: self.provider,
            integration: self.integration,
            access_token,
            refresh_token,
            expires_at: self.expires_at.and_then(DateTime::from_timestamp_millis),
            scope: self.scope,
            created_at: DateTime::from_timestamp_millis(self.created_at).unwrap_or_else(Utc::now),
            updated_at: DateTime::from_timestamp_millis(self.updated_at).unwrap_or_else(Utc::now),
            user_id: self.user_id,
            organization_id: self.organization_id,
        })
    }
}

/// SQLite oauth_providers table - matches schema exactly
#[derive(FromRow)]
struct OAuthProviderRow {
    id: String,
    name: String,
    client_id: String,
    client_secret: String,
    auth_url: String,
    token_url: String,
    scopes: String,
    auth_params: String,
    created_at: i64,
    updated_at: i64,
}

impl TryFrom<OAuthProviderRow> for OAuthProvider {
    type Error = BeemFlowError;

    fn try_from(row: OAuthProviderRow) -> Result<Self> {
        Ok(OAuthProvider {
            id: row.id,
            name: row.name,
            client_id: row.client_id,
            client_secret: row.client_secret,
            auth_url: row.auth_url,
            token_url: row.token_url,
            scopes: serde_json::from_str(&row.scopes).ok(),
            auth_params: serde_json::from_str(&row.auth_params).ok(),
            created_at: DateTime::from_timestamp_millis(row.created_at).unwrap_or_else(Utc::now),
            updated_at: DateTime::from_timestamp_millis(row.updated_at).unwrap_or_else(Utc::now),
        })
    }
}

/// SQLite oauth_clients table - matches schema exactly
#[derive(FromRow)]
struct OAuthClientRow {
    id: String,
    secret: String,
    name: String,
    redirect_uris: String,
    grant_types: String,
    response_types: String,
    scope: String,
    created_at: i64,
    updated_at: i64,
}

impl TryFrom<OAuthClientRow> for OAuthClient {
    type Error = BeemFlowError;

    fn try_from(row: OAuthClientRow) -> Result<Self> {
        Ok(OAuthClient {
            id: row.id,
            secret: row.secret,
            name: row.name,
            redirect_uris: serde_json::from_str(&row.redirect_uris)?,
            grant_types: serde_json::from_str(&row.grant_types)?,
            response_types: serde_json::from_str(&row.response_types)?,
            scope: row.scope,
            client_uri: None,
            logo_uri: None,
            created_at: DateTime::from_timestamp_millis(row.created_at).unwrap_or_else(Utc::now),
            updated_at: DateTime::from_timestamp_millis(row.updated_at).unwrap_or_else(Utc::now),
        })
    }
}

/// SQLite oauth_tokens table - matches schema exactly
#[derive(FromRow)]
struct OAuthTokenRow {
    id: String,
    client_id: String,
    user_id: String,
    redirect_uri: String,
    scope: String,
    code: String,
    code_create_at: Option<i64>,
    code_expires_in: Option<i64>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    access: String,
    access_create_at: Option<i64>,
    access_expires_in: Option<i64>,
    refresh: String,
    refresh_create_at: Option<i64>,
    refresh_expires_in: Option<i64>,
}

impl TryFrom<OAuthTokenRow> for OAuthToken {
    type Error = BeemFlowError;

    fn try_from(row: OAuthTokenRow) -> Result<Self> {
        Ok(OAuthToken {
            id: row.id,
            client_id: row.client_id,
            user_id: row.user_id,
            redirect_uri: row.redirect_uri,
            scope: row.scope,
            code: Some(row.code),
            code_create_at: row.code_create_at.and_then(DateTime::from_timestamp_millis),
            code_expires_in: row
                .code_expires_in
                .filter(|&s| s >= 0)
                .map(|s| std::time::Duration::from_secs(s as u64)),
            code_challenge: row.code_challenge,
            code_challenge_method: row.code_challenge_method,
            access: Some(row.access),
            access_create_at: row
                .access_create_at
                .and_then(DateTime::from_timestamp_millis),
            access_expires_in: row
                .access_expires_in
                .filter(|&s| s >= 0)
                .map(|s| std::time::Duration::from_secs(s as u64)),
            refresh: Some(row.refresh),
            refresh_create_at: row
                .refresh_create_at
                .and_then(DateTime::from_timestamp_millis),
            refresh_expires_in: row
                .refresh_expires_in
                .filter(|&s| s >= 0)
                .map(|s| std::time::Duration::from_secs(s as u64)),
        })
    }
}

/// SQLite organizations table - matches schema exactly
#[derive(FromRow)]
struct OrganizationRow {
    id: String,
    name: String,
    slug: String,
    plan: String,
    plan_starts_at: Option<i64>,
    plan_ends_at: Option<i64>,
    max_users: i32,
    max_flows: i32,
    max_runs_per_month: i32,
    settings: Option<String>,
    created_by_user_id: String,
    created_at: i64,
    updated_at: i64,
    disabled: i32,
}

impl TryFrom<OrganizationRow> for crate::auth::Organization {
    type Error = BeemFlowError;

    fn try_from(row: OrganizationRow) -> Result<Self> {
        Ok(crate::auth::Organization {
            id: row.id,
            name: row.name,
            slug: row.slug,
            plan: row.plan,
            plan_starts_at: row.plan_starts_at.and_then(DateTime::from_timestamp_millis),
            plan_ends_at: row.plan_ends_at.and_then(DateTime::from_timestamp_millis),
            max_users: row.max_users,
            max_flows: row.max_flows,
            max_runs_per_month: row.max_runs_per_month,
            settings: row.settings.and_then(|s| serde_json::from_str(&s).ok()),
            created_by_user_id: row.created_by_user_id,
            created_at: DateTime::from_timestamp_millis(row.created_at).unwrap_or_else(Utc::now),
            updated_at: DateTime::from_timestamp_millis(row.updated_at).unwrap_or_else(Utc::now),
            disabled: row.disabled != 0,
        })
    }
}

/// SQLite paused_runs table - matches schema exactly
#[derive(FromRow)]
struct PausedRunRow {
    token: String,
    data: String,
}

/// SQLite refresh_tokens table - matches schema exactly
#[derive(FromRow)]
struct RefreshTokenRow {
    id: String,
    user_id: String,
    token_hash: String,
    expires_at: i64,
    revoked: i32,
    revoked_at: Option<i64>,
    created_at: i64,
    last_used_at: Option<i64>,
    user_agent: Option<String>,
    client_ip: Option<String>,
}

impl TryFrom<RefreshTokenRow> for crate::auth::RefreshToken {
    type Error = BeemFlowError;

    fn try_from(row: RefreshTokenRow) -> Result<Self> {
        Ok(crate::auth::RefreshToken {
            id: row.id,
            user_id: row.user_id,
            token_hash: row.token_hash,
            expires_at: DateTime::from_timestamp_millis(row.expires_at).unwrap_or_else(Utc::now),
            revoked: row.revoked != 0,
            revoked_at: row.revoked_at.and_then(DateTime::from_timestamp_millis),
            created_at: DateTime::from_timestamp_millis(row.created_at).unwrap_or_else(Utc::now),
            last_used_at: row.last_used_at.and_then(DateTime::from_timestamp_millis),
            user_agent: row.user_agent,
            client_ip: row.client_ip,
        })
    }
}

/// SQLite organization_members table - matches schema exactly
#[derive(FromRow)]
struct OrganizationMemberRow {
    id: String,
    organization_id: String,
    user_id: String,
    role: String,
    invited_by_user_id: Option<String>,
    invited_at: Option<i64>,
    joined_at: i64,
    disabled: i32,
}

impl TryFrom<OrganizationMemberRow> for crate::auth::OrganizationMember {
    type Error = BeemFlowError;

    fn try_from(row: OrganizationMemberRow) -> Result<Self> {
        let role = row
            .role
            .parse::<crate::auth::Role>()
            .map_err(|_| BeemFlowError::storage(format!("Invalid role: {}", row.role)))?;

        Ok(crate::auth::OrganizationMember {
            id: row.id,
            organization_id: row.organization_id,
            user_id: row.user_id,
            role,
            invited_by_user_id: row.invited_by_user_id,
            invited_at: row.invited_at.and_then(DateTime::from_timestamp_millis),
            joined_at: DateTime::from_timestamp_millis(row.joined_at).unwrap_or_else(Utc::now),
            disabled: row.disabled != 0,
        })
    }
}

/// SQLite flow_versions table row for list_flow_versions
#[derive(FromRow)]
struct FlowSnapshotRow {
    version: String,
    deployed_at: i64,
    is_live: i32,
}

/// Helper row types for single-column queries
#[derive(FromRow)]
struct StringRow {
    value: String,
}

/// Row type for flow content queries
#[derive(FromRow)]
struct FlowContentRow {
    flow_name: String,
    content: String,
}

/// Row type for organization with role (joined query)
#[derive(FromRow)]
struct OrganizationWithRoleRow {
    id: String,
    name: String,
    slug: String,
    plan: String,
    plan_starts_at: Option<i64>,
    plan_ends_at: Option<i64>,
    max_users: i32,
    max_flows: i32,
    max_runs_per_month: i32,
    settings: Option<String>,
    created_by_user_id: String,
    created_at: i64,
    updated_at: i64,
    disabled: i32,
    role: String,
}

impl OrganizationWithRoleRow {
    fn into_tuple(self) -> Result<(crate::auth::Organization, crate::auth::Role)> {
        let role = self
            .role
            .parse::<crate::auth::Role>()
            .map_err(|_| BeemFlowError::storage(format!("Invalid role: {}", self.role)))?;

        let org = crate::auth::Organization {
            id: self.id,
            name: self.name,
            slug: self.slug,
            plan: self.plan,
            plan_starts_at: self
                .plan_starts_at
                .and_then(DateTime::from_timestamp_millis),
            plan_ends_at: self.plan_ends_at.and_then(DateTime::from_timestamp_millis),
            max_users: self.max_users,
            max_flows: self.max_flows,
            max_runs_per_month: self.max_runs_per_month,
            settings: self.settings.and_then(|s| serde_json::from_str(&s).ok()),
            created_by_user_id: self.created_by_user_id,
            created_at: DateTime::from_timestamp_millis(self.created_at).unwrap_or_else(Utc::now),
            updated_at: DateTime::from_timestamp_millis(self.updated_at).unwrap_or_else(Utc::now),
            disabled: self.disabled != 0,
        };

        Ok((org, role))
    }
}

/// Row type for user with role (joined query)
#[derive(FromRow)]
struct UserWithRoleRow {
    id: String,
    email: String,
    name: Option<String>,
    password_hash: String,
    email_verified: i32,
    avatar_url: Option<String>,
    mfa_enabled: i32,
    mfa_secret: Option<String>,
    created_at: i64,
    updated_at: i64,
    last_login_at: Option<i64>,
    disabled: i32,
    disabled_reason: Option<String>,
    disabled_at: Option<i64>,
    role: String,
}

impl UserWithRoleRow {
    fn into_tuple(self) -> Result<(crate::auth::User, crate::auth::Role)> {
        let role = self
            .role
            .parse::<crate::auth::Role>()
            .map_err(|_| BeemFlowError::storage(format!("Invalid role: {}", self.role)))?;

        let user = crate::auth::User {
            id: self.id,
            email: self.email,
            name: self.name,
            password_hash: self.password_hash,
            email_verified: self.email_verified != 0,
            avatar_url: self.avatar_url,
            mfa_enabled: self.mfa_enabled != 0,
            mfa_secret: self.mfa_secret,
            created_at: DateTime::from_timestamp_millis(self.created_at).unwrap_or_else(Utc::now),
            updated_at: DateTime::from_timestamp_millis(self.updated_at).unwrap_or_else(Utc::now),
            last_login_at: self.last_login_at.and_then(DateTime::from_timestamp_millis),
            disabled: self.disabled != 0,
            disabled_reason: self.disabled_reason,
            disabled_at: self.disabled_at.and_then(DateTime::from_timestamp_millis),
        };

        Ok((user, role))
    }
}

// ============================================================================
// SQLite Storage Implementation
// ============================================================================

/// SQLite storage backend
pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    /// Create a new SQLite storage
    ///
    /// # Arguments
    /// * `dsn` - Database path (e.g., ".beemflow/flow.db" or ":memory:" for in-memory)
    pub async fn new(dsn: &str) -> Result<Self> {
        // Prepend sqlite: prefix if not present and add create-if-missing option
        let connection_string = if dsn.starts_with("sqlite:") {
            if dsn.contains('?') {
                dsn.to_string()
            } else {
                format!("{}?mode=rwc", dsn)
            }
        } else {
            format!("sqlite:{}?mode=rwc", dsn)
        };

        // Extract actual file path for directory creation
        let file_path = dsn.strip_prefix("sqlite:").unwrap_or(dsn);

        // Validate path to prevent directory traversal attacks
        if file_path.contains("..") {
            return Err(BeemFlowError::config(
                "Database path cannot contain '..' (path traversal not allowed)",
            ));
        }

        // Create parent directory if needed (unless it's :memory:)
        if file_path != ":memory:"
            && let Some(parent) = Path::new(file_path).parent()
        {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Create connection pool
        let pool = SqlitePool::connect(&connection_string)
            .await
            .map_err(|e| BeemFlowError::storage(format!("Failed to connect to SQLite: {}", e)))?;

        // Configure SQLite for better performance
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(&pool)
            .await?;
        sqlx::query("PRAGMA synchronous = NORMAL")
            .execute(&pool)
            .await?;
        sqlx::query("PRAGMA busy_timeout = 5000")
            .execute(&pool)
            .await?;
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await?;

        // Run SQLite-specific migrations
        sqlx::migrate!("./migrations/sqlite")
            .run(&pool)
            .await
            .map_err(|e| BeemFlowError::storage(format!("Failed to run migrations: {}", e)))?;

        Ok(Self { pool })
    }
}

#[async_trait]
impl RunStorage for SqliteStorage {
    // Run methods
    async fn save_run(&self, run: &Run) -> Result<()> {
        sqlx::query(
            "INSERT INTO runs (id, flow_name, event, vars, status, started_at, ended_at, organization_id, triggered_by_user_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                flow_name = excluded.flow_name,
                event = excluded.event,
                vars = excluded.vars,
                status = excluded.status,
                started_at = excluded.started_at,
                ended_at = excluded.ended_at,
                organization_id = excluded.organization_id,
                triggered_by_user_id = excluded.triggered_by_user_id",
        )
        .bind(run.id.to_string())
        .bind(run.flow_name.as_str())
        .bind(serde_json::to_string(&run.event)?)
        .bind(serde_json::to_string(&run.vars)?)
        .bind(run_status_to_str(run.status))
        .bind(run.started_at.timestamp_millis())
        .bind(run.ended_at.map(|dt| dt.timestamp_millis()))
        .bind(&run.organization_id)
        .bind(&run.triggered_by_user_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_run(&self, id: Uuid, organization_id: &str) -> Result<Option<Run>> {
        sqlx::query_as::<_, RunRow>(
            "SELECT id, flow_name, event, vars, status, started_at, ended_at, organization_id, triggered_by_user_id
             FROM runs WHERE id = ? AND organization_id = ?",
        )
        .bind(id.to_string())
        .bind(organization_id)
        .fetch_optional(&self.pool)
        .await?
        .map(Run::try_from)
        .transpose()
    }

    async fn list_runs(
        &self,
        organization_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Run>> {
        // Cap limit at 10,000 to prevent unbounded queries
        let capped_limit = limit.min(10_000);

        sqlx::query_as::<_, RunRow>(
            "SELECT id, flow_name, event, vars, status, started_at, ended_at, organization_id, triggered_by_user_id
             FROM runs
             WHERE organization_id = ?
             ORDER BY started_at DESC
             LIMIT ? OFFSET ?",
        )
        .bind(organization_id)
        .bind(capped_limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(Run::try_from)
        .collect()
    }

    async fn list_runs_by_flow_and_status(
        &self,
        organization_id: &str,
        flow_name: &str,
        status: RunStatus,
        exclude_id: Option<Uuid>,
        limit: usize,
    ) -> Result<Vec<Run>> {
        let status_str = run_status_to_str(status);

        // Build query with optional exclude clause
        let rows = if let Some(id) = exclude_id {
            sqlx::query_as::<_, RunRow>(
                "SELECT id, flow_name, event, vars, status, started_at, ended_at, organization_id, triggered_by_user_id
                 FROM runs
                 WHERE organization_id = ? AND flow_name = ? AND status = ? AND id != ?
                 ORDER BY started_at DESC
                 LIMIT ?",
            )
            .bind(organization_id)
            .bind(flow_name)
            .bind(status_str)
            .bind(id.to_string())
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, RunRow>(
                "SELECT id, flow_name, event, vars, status, started_at, ended_at, organization_id, triggered_by_user_id
                 FROM runs
                 WHERE organization_id = ? AND flow_name = ? AND status = ?
                 ORDER BY started_at DESC
                 LIMIT ?",
            )
            .bind(organization_id)
            .bind(flow_name)
            .bind(status_str)
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await?
        };

        rows.into_iter().map(Run::try_from).collect()
    }

    async fn delete_run(&self, id: Uuid, organization_id: &str) -> Result<()> {
        // Verify run belongs to organization before deleting
        let run = self.get_run(id, organization_id).await?;
        if run.is_none() {
            return Err(BeemFlowError::not_found("run", id.to_string()));
        }

        sqlx::query("DELETE FROM steps WHERE run_id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        sqlx::query("DELETE FROM runs WHERE id = ? AND organization_id = ?")
            .bind(id.to_string())
            .bind(organization_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn try_insert_run(&self, run: &Run) -> Result<bool> {
        let result = sqlx::query(
            "INSERT INTO runs (id, flow_name, event, vars, status, started_at, ended_at, organization_id, triggered_by_user_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(run.id.to_string())
        .bind(run.flow_name.as_str())
        .bind(serde_json::to_string(&run.event)?)
        .bind(serde_json::to_string(&run.vars)?)
        .bind(run_status_to_str(run.status))
        .bind(run.started_at.timestamp_millis())
        .bind(run.ended_at.map(|dt| dt.timestamp_millis()))
        .bind(&run.organization_id)
        .bind(&run.triggered_by_user_id)
        .execute(&self.pool)
        .await?;

        // Returns true if a row was inserted, false if conflict occurred
        Ok(result.rows_affected() == 1)
    }

    // Step methods
    async fn save_step(&self, step: &StepRun) -> Result<()> {
        sqlx::query(
            "INSERT INTO steps (id, run_id, organization_id, step_name, status, started_at, ended_at, outputs, error)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                run_id = excluded.run_id,
                organization_id = excluded.organization_id,
                step_name = excluded.step_name,
                status = excluded.status,
                started_at = excluded.started_at,
                ended_at = excluded.ended_at,
                outputs = excluded.outputs,
                error = excluded.error"
        )
        .bind(step.id.to_string())
        .bind(step.run_id.to_string())
        .bind(&step.organization_id)
        .bind(step.step_name.as_str())
        .bind(step_status_to_str(step.status))
        .bind(step.started_at.timestamp_millis())
        .bind(step.ended_at.map(|dt| dt.timestamp_millis()))
        .bind(serde_json::to_string(&step.outputs)?)
        .bind(&step.error)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_steps(&self, run_id: Uuid, organization_id: &str) -> Result<Vec<StepRun>> {
        sqlx::query_as::<_, StepRow>(
            "SELECT id, run_id, organization_id, step_name, status, started_at, ended_at, outputs, error
             FROM steps WHERE run_id = ? AND organization_id = ?",
        )
        .bind(run_id.to_string())
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(StepRun::try_from)
        .collect()
    }
}

#[async_trait]
impl StateStorage for SqliteStorage {
    // Wait/timeout methods
    async fn register_wait(&self, token: Uuid, wake_at: Option<i64>) -> Result<()> {
        sqlx::query(
            "INSERT INTO waits (token, wake_at) VALUES (?, ?) 
             ON CONFLICT(token) DO UPDATE SET wake_at = excluded.wake_at",
        )
        .bind(token.to_string())
        .bind(wake_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn resolve_wait(&self, token: Uuid) -> Result<Option<Run>> {
        sqlx::query("DELETE FROM waits WHERE token = ?")
            .bind(token.to_string())
            .execute(&self.pool)
            .await?;

        // SQLite storage doesn't resolve waits to specific runs
        Ok(None)
    }

    // Paused run methods
    async fn save_paused_run(
        &self,
        token: &str,
        source: &str,
        data: serde_json::Value,
        organization_id: &str,
        user_id: &str,
    ) -> Result<()> {
        let data_json = serde_json::to_string(&data)?;

        sqlx::query(
            "INSERT INTO paused_runs (token, source, data, organization_id, user_id) VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(token) DO UPDATE SET source = excluded.source, data = excluded.data, organization_id = excluded.organization_id, user_id = excluded.user_id",
        )
        .bind(token)
        .bind(source)
        .bind(data_json)
        .bind(organization_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn load_paused_runs(&self) -> Result<HashMap<String, serde_json::Value>> {
        let rows = sqlx::query_as::<_, PausedRunRow>("SELECT token, data FROM paused_runs")
            .fetch_all(&self.pool)
            .await?;

        let mut result = HashMap::new();
        for row in rows {
            if let Ok(data) = serde_json::from_str(&row.data) {
                result.insert(row.token, data);
            }
        }

        Ok(result)
    }

    async fn find_paused_runs_by_source(
        &self,
        source: &str,
        organization_id: &str,
    ) -> Result<Vec<(String, serde_json::Value)>> {
        let rows = sqlx::query_as::<_, PausedRunRow>(
            "SELECT token, data FROM paused_runs WHERE source = ? AND organization_id = ?",
        )
        .bind(source)
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await?;

        let mut result = Vec::new();
        for row in rows {
            if let Ok(data) = serde_json::from_str(&row.data) {
                result.push((row.token, data));
            }
        }

        Ok(result)
    }

    async fn delete_paused_run(&self, token: &str) -> Result<()> {
        sqlx::query("DELETE FROM paused_runs WHERE token = ?")
            .bind(token)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn fetch_and_delete_paused_run(&self, token: &str) -> Result<Option<serde_json::Value>> {
        // Use DELETE ... RETURNING for atomic fetch-and-delete (SQLite 3.35+)
        // Note: RETURNING with query_as would need a separate row type; using query here is acceptable
        #[derive(FromRow)]
        struct DataRow {
            data: String,
        }

        sqlx::query_as::<_, DataRow>("DELETE FROM paused_runs WHERE token = ? RETURNING data")
            .bind(token)
            .fetch_optional(&self.pool)
            .await?
            .map(|row| serde_json::from_str(&row.data))
            .transpose()
            .map_err(Into::into)
    }
}

#[async_trait]
impl FlowStorage for SqliteStorage {
    // Flow versioning methods
    async fn deploy_flow_version(
        &self,
        organization_id: &str,
        flow_name: &str,
        version: &str,
        content: &str,
        deployed_by_user_id: &str,
    ) -> Result<()> {
        let now = Utc::now().timestamp_millis();

        // Parse flow to extract trigger topics
        let topics = extract_topics_from_flow_yaml(content);

        // Start transaction
        let mut tx = self.pool.begin().await?;

        // Check if this version already exists (enforce version immutability)
        let exists =
            sqlx::query("SELECT 1 FROM flow_versions WHERE organization_id = ? AND flow_name = ? AND version = ? LIMIT 1")
                .bind(organization_id)
                .bind(flow_name)
                .bind(version)
                .fetch_optional(&mut *tx)
                .await?;

        if exists.is_some() {
            return Err(BeemFlowError::validation(format!(
                "Version '{}' already exists for flow '{}'. Versions are immutable - use a new version number.",
                version, flow_name
            )));
        }

        // Save new version snapshot
        sqlx::query(
            "INSERT INTO flow_versions (organization_id, flow_name, version, content, deployed_at, deployed_by_user_id)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(organization_id)
        .bind(flow_name)
        .bind(version)
        .bind(content)
        .bind(now)
        .bind(deployed_by_user_id)
        .execute(&mut *tx)
        .await?;

        // Update deployed version pointer
        sqlx::query(
            "INSERT INTO deployed_flows (organization_id, flow_name, deployed_version, deployed_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(organization_id, flow_name) DO UPDATE SET
                deployed_version = excluded.deployed_version,
                deployed_at = excluded.deployed_at",
        )
        .bind(organization_id)
        .bind(flow_name)
        .bind(version)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // Insert flow_triggers for this version
        // Note: No need to delete - version is new (checked above)
        for topic in topics {
            sqlx::query(
                "INSERT INTO flow_triggers (organization_id, flow_name, version, topic)
                 VALUES (?, ?, ?, ?)
                 ON CONFLICT DO NOTHING",
            )
            .bind(organization_id)
            .bind(flow_name)
            .bind(version)
            .bind(&topic)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn set_deployed_version(
        &self,
        organization_id: &str,
        flow_name: &str,
        version: &str,
    ) -> Result<()> {
        let now = Utc::now().timestamp_millis();

        sqlx::query(
            "INSERT INTO deployed_flows (organization_id, flow_name, deployed_version, deployed_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(organization_id, flow_name) DO UPDATE SET
                deployed_version = excluded.deployed_version,
                deployed_at = excluded.deployed_at",
        )
        .bind(organization_id)
        .bind(flow_name)
        .bind(version)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_deployed_version(
        &self,
        organization_id: &str,
        flow_name: &str,
    ) -> Result<Option<String>> {
        Ok(sqlx::query_as::<_, StringRow>(
            "SELECT deployed_version AS value FROM deployed_flows WHERE organization_id = ? AND flow_name = ?",
        )
        .bind(organization_id)
        .bind(flow_name)
        .fetch_optional(&self.pool)
        .await?
        .map(|r| r.value))
    }

    async fn get_flow_version_content(
        &self,
        organization_id: &str,
        flow_name: &str,
        version: &str,
    ) -> Result<Option<String>> {
        Ok(sqlx::query_as::<_, StringRow>(
            "SELECT content AS value FROM flow_versions WHERE organization_id = ? AND flow_name = ? AND version = ?",
        )
        .bind(organization_id)
        .bind(flow_name)
        .bind(version)
        .fetch_optional(&self.pool)
        .await?
        .map(|r| r.value))
    }

    async fn list_flow_versions(
        &self,
        organization_id: &str,
        flow_name: &str,
    ) -> Result<Vec<FlowSnapshot>> {
        let rows = sqlx::query_as::<_, FlowSnapshotRow>(
            "SELECT v.version, v.deployed_at,
                CASE WHEN d.deployed_version = v.version THEN 1 ELSE 0 END as is_live
             FROM flow_versions v
             LEFT JOIN deployed_flows d ON v.organization_id = d.organization_id AND v.flow_name = d.flow_name
             WHERE v.organization_id = ? AND v.flow_name = ?
             ORDER BY v.deployed_at DESC",
        )
        .bind(organization_id)
        .bind(flow_name)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| FlowSnapshot {
                flow_name: flow_name.to_string(),
                version: row.version,
                deployed_at: DateTime::from_timestamp_millis(row.deployed_at)
                    .unwrap_or_else(Utc::now),
                is_live: row.is_live == 1,
            })
            .collect())
    }

    async fn get_latest_deployed_version_from_history(
        &self,
        organization_id: &str,
        flow_name: &str,
    ) -> Result<Option<String>> {
        Ok(sqlx::query_as::<_, StringRow>(
            "SELECT version AS value FROM flow_versions
             WHERE organization_id = ? AND flow_name = ?
             ORDER BY deployed_at DESC, version DESC
             LIMIT 1",
        )
        .bind(organization_id)
        .bind(flow_name)
        .fetch_optional(&self.pool)
        .await?
        .map(|r| r.value))
    }

    async fn unset_deployed_version(&self, organization_id: &str, flow_name: &str) -> Result<()> {
        sqlx::query("DELETE FROM deployed_flows WHERE organization_id = ? AND flow_name = ?")
            .bind(organization_id)
            .bind(flow_name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_all_deployed_flows(
        &self,
        organization_id: &str,
    ) -> Result<Vec<(String, String)>> {
        Ok(sqlx::query_as::<_, FlowContentRow>(
            "SELECT d.flow_name, v.content
             FROM deployed_flows d
             INNER JOIN flow_versions v
               ON d.organization_id = v.organization_id
               AND d.flow_name = v.flow_name
               AND d.deployed_version = v.version
             WHERE d.organization_id = ?",
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|row| (row.flow_name, row.content))
        .collect())
    }

    async fn find_flow_names_by_topic(
        &self,
        organization_id: &str,
        topic: &str,
    ) -> Result<Vec<String>> {
        Ok(sqlx::query_as::<_, StringRow>(
            "SELECT DISTINCT ft.flow_name AS value
             FROM flow_triggers ft
             INNER JOIN deployed_flows d ON ft.organization_id = d.organization_id AND ft.flow_name = d.flow_name AND ft.version = d.deployed_version
             WHERE ft.organization_id = ? AND ft.topic = ?
             ORDER BY ft.flow_name",
        )
        .bind(organization_id)
        .bind(topic)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|r| r.value)
        .collect())
    }

    async fn get_deployed_flows_content(
        &self,
        organization_id: &str,
        flow_names: &[String],
    ) -> Result<Vec<(String, String)>> {
        if flow_names.is_empty() {
            return Ok(Vec::new());
        }

        // Build placeholders for IN clause
        let placeholders = flow_names
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(", ");

        let query_str = format!(
            "SELECT df.flow_name, fv.content
             FROM deployed_flows df
             INNER JOIN flow_versions fv ON df.organization_id = fv.organization_id AND df.flow_name = fv.flow_name AND df.deployed_version = fv.version
             WHERE df.organization_id = ? AND df.flow_name IN ({})",
            placeholders
        );

        // Dynamic SQL with query_as - column mapping is still compile-time checked via FlowContentRow
        let mut query = sqlx::query_as::<_, FlowContentRow>(&query_str);
        query = query.bind(organization_id);
        for name in flow_names {
            query = query.bind(name);
        }

        Ok(query
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(|row| (row.flow_name, row.content))
            .collect())
    }

    async fn get_deployed_by(
        &self,
        organization_id: &str,
        flow_name: &str,
    ) -> Result<Option<String>> {
        Ok(sqlx::query_as::<_, StringRow>(
            "SELECT fv.deployed_by_user_id AS value
             FROM deployed_flows df
             INNER JOIN flow_versions fv
               ON df.organization_id = fv.organization_id
               AND df.flow_name = fv.flow_name
               AND df.deployed_version = fv.version
             WHERE df.organization_id = ? AND df.flow_name = ?",
        )
        .bind(organization_id)
        .bind(flow_name)
        .fetch_optional(&self.pool)
        .await?
        .map(|r| r.value))
    }
}

#[async_trait]
impl OAuthStorage for SqliteStorage {
    // OAuth credential methods
    async fn save_oauth_credential(&self, credential: &OAuthCredential) -> Result<()> {
        let now = Utc::now().timestamp_millis();

        // Encrypt tokens before storage (protects against database compromise)
        let (encrypted_access, encrypted_refresh) =
            crate::auth::TokenEncryption::encrypt_credential_tokens(
                &credential.access_token,
                &credential.refresh_token,
            )?;

        sqlx::query(
            "INSERT OR REPLACE INTO oauth_credentials
             (id, provider, integration, access_token, refresh_token, expires_at, scope, created_at, updated_at, user_id, organization_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&credential.id)
        .bind(&credential.provider)
        .bind(&credential.integration)
        .bind(encrypted_access.as_str())  // Store encrypted
        .bind(encrypted_refresh.as_ref().map(|e| e.as_str()))  // Store encrypted
        .bind(credential.expires_at.map(|dt| dt.timestamp_millis()))
        .bind(&credential.scope)
        .bind(credential.created_at.timestamp_millis())
        .bind(now)
        .bind(&credential.user_id)
        .bind(&credential.organization_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_oauth_credential(
        &self,
        provider: &str,
        integration: &str,
        user_id: &str,
        organization_id: &str,
    ) -> Result<Option<OAuthCredential>> {
        sqlx::query_as::<_, OAuthCredentialRow>(
            "SELECT id, provider, integration, access_token, refresh_token, expires_at, scope, created_at, updated_at, user_id, organization_id
             FROM oauth_credentials
             WHERE provider = ? AND integration = ? AND user_id = ? AND organization_id = ?"
        )
        .bind(provider)
        .bind(integration)
        .bind(user_id)
        .bind(organization_id)
        .fetch_optional(&self.pool)
        .await?
        .map(OAuthCredentialRow::into_credential)
        .transpose()
    }

    async fn list_oauth_credentials(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<Vec<OAuthCredential>> {
        sqlx::query_as::<_, OAuthCredentialRow>(
            "SELECT id, provider, integration, access_token, refresh_token, expires_at, scope, created_at, updated_at, user_id, organization_id
             FROM oauth_credentials
             WHERE user_id = ? AND organization_id = ?
             ORDER BY created_at DESC"
        )
        .bind(user_id)
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(OAuthCredentialRow::into_credential)
        .collect()
    }

    async fn get_oauth_credential_by_id(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<OAuthCredential>> {
        sqlx::query_as::<_, OAuthCredentialRow>(
            "SELECT id, provider, integration, access_token, refresh_token, expires_at, scope, created_at, updated_at, user_id, organization_id
             FROM oauth_credentials
             WHERE id = ? AND organization_id = ?"
        )
        .bind(id)
        .bind(organization_id)
        .fetch_optional(&self.pool)
        .await?
        .map(OAuthCredentialRow::into_credential)
        .transpose()
    }

    async fn delete_oauth_credential(&self, id: &str, organization_id: &str) -> Result<()> {
        // Defense in depth: Verify organization ownership at storage layer
        let result =
            sqlx::query("DELETE FROM oauth_credentials WHERE id = ? AND organization_id = ?")
                .bind(id)
                .bind(organization_id)
                .execute(&self.pool)
                .await?;

        if result.rows_affected() == 0 {
            return Err(BeemFlowError::not_found("OAuth credential", id));
        }

        Ok(())
    }

    async fn refresh_oauth_credential(
        &self,
        id: &str,
        organization_id: &str,
        new_token: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        // Encrypt new token before storage
        let (encrypted, _) =
            crate::auth::TokenEncryption::encrypt_credential_tokens(new_token, &None)?;

        let now = Utc::now().timestamp_millis();
        let result = sqlx::query(
            "UPDATE oauth_credentials
             SET access_token = ?, expires_at = ?, updated_at = ?
             WHERE id = ? AND organization_id = ?",
        )
        .bind(encrypted.as_str()) // Store encrypted
        .bind(expires_at.map(|dt| dt.timestamp_millis()))
        .bind(now)
        .bind(id)
        .bind(organization_id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(BeemFlowError::not_found("OAuth credential", id));
        }

        Ok(())
    }

    // OAuth provider methods
    async fn save_oauth_provider(&self, provider: &OAuthProvider) -> Result<()> {
        let scopes_json = serde_json::to_string(&provider.scopes)?;
        let auth_params_json = serde_json::to_string(&provider.auth_params)?;
        let now = Utc::now().timestamp_millis();

        sqlx::query(
            "INSERT OR REPLACE INTO oauth_providers
             (id, name, client_id, client_secret, auth_url, token_url, scopes, auth_params, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&provider.id)
        .bind(&provider.name)
        .bind(&provider.client_id)
        .bind(&provider.client_secret)
        .bind(&provider.auth_url)
        .bind(&provider.token_url)
        .bind(scopes_json)
        .bind(auth_params_json)
        .bind(provider.created_at.timestamp_millis())
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_oauth_provider(&self, id: &str) -> Result<Option<OAuthProvider>> {
        sqlx::query_as::<_, OAuthProviderRow>(
            "SELECT id, name, client_id, client_secret, auth_url, token_url, scopes, auth_params, created_at, updated_at
             FROM oauth_providers
             WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .map(OAuthProvider::try_from)
        .transpose()
    }

    async fn list_oauth_providers(&self) -> Result<Vec<OAuthProvider>> {
        sqlx::query_as::<_, OAuthProviderRow>(
            "SELECT id, name, client_id, client_secret, auth_url, token_url, scopes, auth_params, created_at, updated_at
             FROM oauth_providers
             ORDER BY created_at DESC"
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(OAuthProvider::try_from)
        .collect()
    }

    async fn delete_oauth_provider(&self, id: &str) -> Result<()> {
        let result = sqlx::query("DELETE FROM oauth_providers WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(BeemFlowError::not_found("OAuth provider", id));
        }

        Ok(())
    }

    // OAuth client methods
    async fn save_oauth_client(&self, client: &OAuthClient) -> Result<()> {
        let redirect_uris_json = serde_json::to_string(&client.redirect_uris)?;
        let grant_types_json = serde_json::to_string(&client.grant_types)?;
        let response_types_json = serde_json::to_string(&client.response_types)?;
        let now = Utc::now().timestamp_millis();

        sqlx::query(
            "INSERT OR REPLACE INTO oauth_clients
             (id, secret, name, redirect_uris, grant_types, response_types, scope, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&client.id)
        .bind(&client.secret)
        .bind(&client.name)
        .bind(redirect_uris_json)
        .bind(grant_types_json)
        .bind(response_types_json)
        .bind(&client.scope)
        .bind(client.created_at.timestamp_millis())
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_oauth_client(&self, id: &str) -> Result<Option<OAuthClient>> {
        sqlx::query_as::<_, OAuthClientRow>(
            "SELECT id, secret, name, redirect_uris, grant_types, response_types, scope, created_at, updated_at
             FROM oauth_clients
             WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .map(OAuthClient::try_from)
        .transpose()
    }

    async fn list_oauth_clients(&self) -> Result<Vec<OAuthClient>> {
        sqlx::query_as::<_, OAuthClientRow>(
            "SELECT id, secret, name, redirect_uris, grant_types, response_types, scope, created_at, updated_at
             FROM oauth_clients
             ORDER BY created_at DESC"
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(OAuthClient::try_from)
        .collect()
    }

    async fn delete_oauth_client(&self, id: &str) -> Result<()> {
        let result = sqlx::query("DELETE FROM oauth_clients WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(BeemFlowError::not_found("OAuth client", id));
        }

        Ok(())
    }

    // OAuth token methods
    async fn save_oauth_token(&self, token: &OAuthToken) -> Result<()> {
        let now = Utc::now().timestamp_millis();

        sqlx::query(
            "INSERT OR REPLACE INTO oauth_tokens
             (id, client_id, user_id, redirect_uri, scope, code, code_create_at, code_expires_in,
              code_challenge, code_challenge_method, access, access_create_at, access_expires_in,
              refresh, refresh_create_at, refresh_expires_in, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&token.id)
        .bind(&token.client_id)
        .bind(&token.user_id)
        .bind(&token.redirect_uri)
        .bind(&token.scope)
        .bind(&token.code)
        .bind(token.code_create_at.map(|dt| dt.timestamp_millis()))
        .bind(token.code_expires_in.map(|d| d.as_secs() as i64))
        .bind(&token.code_challenge)
        .bind(&token.code_challenge_method)
        .bind(&token.access)
        .bind(token.access_create_at.map(|dt| dt.timestamp_millis()))
        .bind(token.access_expires_in.map(|d| d.as_secs() as i64))
        .bind(&token.refresh)
        .bind(token.refresh_create_at.map(|dt| dt.timestamp_millis()))
        .bind(token.refresh_expires_in.map(|d| d.as_secs() as i64))
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_oauth_token_by_code(&self, code: &str) -> Result<Option<OAuthToken>> {
        self.get_oauth_token_by_field(OAuthTokenField::Code, code)
            .await
    }

    async fn get_oauth_token_by_access(&self, access: &str) -> Result<Option<OAuthToken>> {
        self.get_oauth_token_by_field(OAuthTokenField::Access, access)
            .await
    }

    async fn get_oauth_token_by_refresh(&self, refresh: &str) -> Result<Option<OAuthToken>> {
        self.get_oauth_token_by_field(OAuthTokenField::Refresh, refresh)
            .await
    }

    async fn delete_oauth_token_by_code(&self, code: &str) -> Result<()> {
        sqlx::query("DELETE FROM oauth_tokens WHERE code = ?")
            .bind(code)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_oauth_token_by_access(&self, access: &str) -> Result<()> {
        sqlx::query("DELETE FROM oauth_tokens WHERE access = ?")
            .bind(access)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_oauth_token_by_refresh(&self, refresh: &str) -> Result<()> {
        sqlx::query("DELETE FROM oauth_tokens WHERE refresh = ?")
            .bind(refresh)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

/// OAuth token field selector (prevents SQL injection)
enum OAuthTokenField {
    Code,
    Access,
    Refresh,
}

impl SqliteStorage {
    async fn get_oauth_token_by_field(
        &self,
        field: OAuthTokenField,
        value: &str,
    ) -> Result<Option<OAuthToken>> {
        // Use explicit match to prevent SQL injection
        let query = match field {
            OAuthTokenField::Code => {
                "SELECT id, client_id, user_id, redirect_uri, scope, code, code_create_at, code_expires_in,
                        code_challenge, code_challenge_method, access, access_create_at, access_expires_in,
                        refresh, refresh_create_at, refresh_expires_in
                 FROM oauth_tokens WHERE code = ?"
            }
            OAuthTokenField::Access => {
                "SELECT id, client_id, user_id, redirect_uri, scope, code, code_create_at, code_expires_in,
                        code_challenge, code_challenge_method, access, access_create_at, access_expires_in,
                        refresh, refresh_create_at, refresh_expires_in
                 FROM oauth_tokens WHERE access = ?"
            }
            OAuthTokenField::Refresh => {
                "SELECT id, client_id, user_id, redirect_uri, scope, code, code_create_at, code_expires_in,
                        code_challenge, code_challenge_method, access, access_create_at, access_expires_in,
                        refresh, refresh_create_at, refresh_expires_in
                 FROM oauth_tokens WHERE refresh = ?"
            }
        };

        sqlx::query_as::<_, OAuthTokenRow>(query)
            .bind(value)
            .fetch_optional(&self.pool)
            .await?
            .map(OAuthToken::try_from)
            .transpose()
    }
}

// ============================================================================
// AuthStorage Implementation
// ============================================================================

#[async_trait]
impl crate::storage::AuthStorage for SqliteStorage {
    // User methods
    async fn create_user(&self, user: &crate::auth::User) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO users (
                id, email, name, password_hash, email_verified, avatar_url,
                mfa_enabled, mfa_secret, created_at, updated_at, last_login_at,
                disabled, disabled_reason, disabled_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&user.id)
        .bind(&user.email)
        .bind(&user.name)
        .bind(&user.password_hash)
        .bind(user.email_verified as i32)
        .bind(&user.avatar_url)
        .bind(user.mfa_enabled as i32)
        .bind(&user.mfa_secret)
        .bind(user.created_at.timestamp_millis())
        .bind(user.updated_at.timestamp_millis())
        .bind(user.last_login_at.map(|t| t.timestamp_millis()))
        .bind(user.disabled as i32)
        .bind(&user.disabled_reason)
        .bind(user.disabled_at.map(|t| t.timestamp_millis()))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_user(&self, id: &str) -> Result<Option<crate::auth::User>> {
        sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .map(crate::auth::User::try_from)
            .transpose()
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<crate::auth::User>> {
        sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE email = ? AND disabled = 0")
            .bind(email)
            .fetch_optional(&self.pool)
            .await?
            .map(crate::auth::User::try_from)
            .transpose()
    }

    async fn update_user(&self, user: &crate::auth::User) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE users SET
                email = ?, name = ?, password_hash = ?, email_verified = ?,
                avatar_url = ?, mfa_enabled = ?, mfa_secret = ?,
                updated_at = ?, last_login_at = ?,
                disabled = ?, disabled_reason = ?, disabled_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&user.email)
        .bind(&user.name)
        .bind(&user.password_hash)
        .bind(user.email_verified as i32)
        .bind(&user.avatar_url)
        .bind(user.mfa_enabled as i32)
        .bind(&user.mfa_secret)
        .bind(user.updated_at.timestamp_millis())
        .bind(user.last_login_at.map(|t| t.timestamp_millis()))
        .bind(user.disabled as i32)
        .bind(&user.disabled_reason)
        .bind(user.disabled_at.map(|t| t.timestamp_millis()))
        .bind(&user.id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn update_user_last_login(&self, user_id: &str) -> Result<()> {
        sqlx::query("UPDATE users SET last_login_at = ? WHERE id = ?")
            .bind(Utc::now().timestamp_millis())
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    // Organization methods
    async fn create_organization(&self, organization: &crate::auth::Organization) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO organizations (
                id, name, slug, plan, plan_starts_at, plan_ends_at,
                max_users, max_flows, max_runs_per_month, settings,
                created_by_user_id, created_at, updated_at, disabled
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&organization.id)
        .bind(&organization.name)
        .bind(&organization.slug)
        .bind(&organization.plan)
        .bind(organization.plan_starts_at.map(|t| t.timestamp_millis()))
        .bind(organization.plan_ends_at.map(|t| t.timestamp_millis()))
        .bind(organization.max_users)
        .bind(organization.max_flows)
        .bind(organization.max_runs_per_month)
        .bind(organization.settings.as_ref().map(|s| s.to_string()))
        .bind(&organization.created_by_user_id)
        .bind(organization.created_at.timestamp_millis())
        .bind(organization.updated_at.timestamp_millis())
        .bind(organization.disabled as i32)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_organization(&self, id: &str) -> Result<Option<crate::auth::Organization>> {
        sqlx::query_as::<_, OrganizationRow>("SELECT * FROM organizations WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .map(crate::auth::Organization::try_from)
            .transpose()
    }

    async fn get_organization_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<crate::auth::Organization>> {
        sqlx::query_as::<_, OrganizationRow>("SELECT * FROM organizations WHERE slug = ?")
            .bind(slug)
            .fetch_optional(&self.pool)
            .await?
            .map(crate::auth::Organization::try_from)
            .transpose()
    }

    async fn update_organization(&self, organization: &crate::auth::Organization) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE organizations SET
                name = ?, slug = ?, plan = ?, plan_starts_at = ?, plan_ends_at = ?,
                max_users = ?, max_flows = ?, max_runs_per_month = ?,
                settings = ?, updated_at = ?, disabled = ?
            WHERE id = ?
            "#,
        )
        .bind(&organization.name)
        .bind(&organization.slug)
        .bind(&organization.plan)
        .bind(organization.plan_starts_at.map(|t| t.timestamp_millis()))
        .bind(organization.plan_ends_at.map(|t| t.timestamp_millis()))
        .bind(organization.max_users)
        .bind(organization.max_flows)
        .bind(organization.max_runs_per_month)
        .bind(organization.settings.as_ref().map(|s| s.to_string()))
        .bind(organization.updated_at.timestamp_millis())
        .bind(organization.disabled as i32)
        .bind(&organization.id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn list_active_organizations(&self) -> Result<Vec<crate::auth::Organization>> {
        sqlx::query_as::<_, OrganizationRow>(
            "SELECT * FROM organizations WHERE disabled = 0 ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(crate::auth::Organization::try_from)
        .collect()
    }

    // Organization membership methods
    async fn create_organization_member(
        &self,
        member: &crate::auth::OrganizationMember,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO organization_members (
                id, organization_id, user_id, role,
                invited_by_user_id, invited_at, joined_at, disabled
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&member.id)
        .bind(&member.organization_id)
        .bind(&member.user_id)
        .bind(member.role.as_str())
        .bind(&member.invited_by_user_id)
        .bind(member.invited_at.map(|t| t.timestamp_millis()))
        .bind(member.joined_at.timestamp_millis())
        .bind(member.disabled as i32)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_organization_member(
        &self,
        organization_id: &str,
        user_id: &str,
    ) -> Result<Option<crate::auth::OrganizationMember>> {
        sqlx::query_as::<_, OrganizationMemberRow>(
            "SELECT * FROM organization_members WHERE organization_id = ? AND user_id = ? AND disabled = 0",
        )
        .bind(organization_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?
        .map(crate::auth::OrganizationMember::try_from)
        .transpose()
    }

    async fn list_user_organizations(
        &self,
        user_id: &str,
    ) -> Result<Vec<(crate::auth::Organization, crate::auth::Role)>> {
        sqlx::query_as::<_, OrganizationWithRoleRow>(
            r#"
            SELECT t.*, tm.role
            FROM organizations t
            INNER JOIN organization_members tm ON t.id = tm.organization_id
            WHERE tm.user_id = ? AND tm.disabled = 0 AND t.disabled = 0
            ORDER BY tm.joined_at ASC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(OrganizationWithRoleRow::into_tuple)
        .collect()
    }

    async fn list_organization_members(
        &self,
        organization_id: &str,
    ) -> Result<Vec<(crate::auth::User, crate::auth::Role)>> {
        sqlx::query_as::<_, UserWithRoleRow>(
            r#"
            SELECT u.*, tm.role
            FROM users u
            INNER JOIN organization_members tm ON u.id = tm.user_id
            WHERE tm.organization_id = ? AND tm.disabled = 0 AND u.disabled = 0
            ORDER BY tm.joined_at ASC
            "#,
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(UserWithRoleRow::into_tuple)
        .collect()
    }

    async fn update_member_role(
        &self,
        organization_id: &str,
        user_id: &str,
        role: crate::auth::Role,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE organization_members SET role = ? WHERE organization_id = ? AND user_id = ?",
        )
        .bind(role.as_str())
        .bind(organization_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn remove_organization_member(&self, organization_id: &str, user_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM organization_members WHERE organization_id = ? AND user_id = ?")
            .bind(organization_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    // Refresh token methods
    async fn create_refresh_token(&self, token: &crate::auth::RefreshToken) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO refresh_tokens (
                id, user_id, token_hash, expires_at,
                revoked, revoked_at, created_at, last_used_at,
                user_agent, client_ip
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&token.id)
        .bind(&token.user_id)
        .bind(&token.token_hash)
        .bind(token.expires_at.timestamp_millis())
        .bind(token.revoked as i32)
        .bind(token.revoked_at.map(|t| t.timestamp_millis()))
        .bind(token.created_at.timestamp_millis())
        .bind(token.last_used_at.map(|t| t.timestamp_millis()))
        .bind(&token.user_agent)
        .bind(&token.client_ip)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_refresh_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<crate::auth::RefreshToken>> {
        sqlx::query_as::<_, RefreshTokenRow>(
            "SELECT * FROM refresh_tokens WHERE token_hash = ? AND revoked = 0",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?
        .map(crate::auth::RefreshToken::try_from)
        .transpose()
    }

    async fn revoke_refresh_token(&self, token_hash: &str) -> Result<()> {
        sqlx::query("UPDATE refresh_tokens SET revoked = 1, revoked_at = ? WHERE token_hash = ?")
            .bind(Utc::now().timestamp_millis())
            .bind(token_hash)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn revoke_all_user_tokens(&self, user_id: &str) -> Result<()> {
        sqlx::query("UPDATE refresh_tokens SET revoked = 1, revoked_at = ? WHERE user_id = ?")
            .bind(Utc::now().timestamp_millis())
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn update_refresh_token_last_used(&self, token_hash: &str) -> Result<()> {
        sqlx::query("UPDATE refresh_tokens SET last_used_at = ? WHERE token_hash = ?")
            .bind(Utc::now().timestamp_millis())
            .bind(token_hash)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
