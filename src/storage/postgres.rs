//! PostgreSQL storage backend
//!
//! Provides a production-ready PostgreSQL implementation of the Storage trait.

use super::{FlowSnapshot, FlowStorage, OAuthStorage, RunStorage, StateStorage, sql_common::*};
use crate::{BeemFlowError, Result, model::*};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use std::collections::HashMap;
use uuid::Uuid;

// ============================================================================
// PostgreSQL Row Types (FromRow) - compile-time verified column mappings
// ============================================================================

/// PostgreSQL runs table - matches schema exactly
#[derive(FromRow)]
struct RunRow {
    id: Uuid,
    flow_name: String,
    event: serde_json::Value,
    vars: serde_json::Value,
    status: String,
    started_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
    organization_id: String,
    triggered_by_user_id: String,
}

impl TryFrom<RunRow> for Run {
    type Error = BeemFlowError;

    fn try_from(row: RunRow) -> Result<Self> {
        Ok(Run {
            id: row.id,
            flow_name: FlowName::new(row.flow_name)?,
            event: parse_hashmap_from_jsonb(row.event),
            vars: parse_hashmap_from_jsonb(row.vars),
            status: parse_run_status(&row.status),
            started_at: row.started_at,
            ended_at: row.ended_at,
            steps: None,
            organization_id: row.organization_id,
            triggered_by_user_id: row.triggered_by_user_id,
        })
    }
}

/// PostgreSQL steps table - matches schema exactly
#[derive(FromRow)]
struct StepRow {
    id: Uuid,
    run_id: Uuid,
    organization_id: String,
    step_name: String,
    status: String,
    started_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
    outputs: serde_json::Value,
    error: Option<String>,
}

impl TryFrom<StepRow> for StepRun {
    type Error = BeemFlowError;

    fn try_from(row: StepRow) -> Result<Self> {
        Ok(StepRun {
            id: row.id,
            run_id: row.run_id,
            organization_id: row.organization_id,
            step_name: StepId::new(row.step_name)?,
            status: parse_step_status(&row.status),
            started_at: row.started_at,
            ended_at: row.ended_at,
            outputs: row
                .outputs
                .as_object()
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
            error: row.error,
        })
    }
}

/// PostgreSQL users table - matches schema exactly
#[derive(FromRow)]
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

impl TryFrom<UserRow> for crate::auth::User {
    type Error = BeemFlowError;

    fn try_from(row: UserRow) -> Result<Self> {
        Ok(crate::auth::User {
            id: row.id,
            email: row.email,
            name: row.name,
            password_hash: row.password_hash,
            email_verified: row.email_verified,
            avatar_url: row.avatar_url,
            mfa_enabled: row.mfa_enabled,
            mfa_secret: row.mfa_secret,
            created_at: DateTime::from_timestamp_millis(row.created_at).unwrap_or_else(Utc::now),
            updated_at: DateTime::from_timestamp_millis(row.updated_at).unwrap_or_else(Utc::now),
            last_login_at: row.last_login_at.and_then(DateTime::from_timestamp_millis),
            disabled: row.disabled,
            disabled_reason: row.disabled_reason,
            disabled_at: row.disabled_at.and_then(DateTime::from_timestamp_millis),
        })
    }
}

/// PostgreSQL oauth_credentials table - matches schema exactly
#[derive(FromRow)]
struct OAuthCredentialRow {
    id: String,
    provider: String,
    integration: String,
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    scope: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
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
            expires_at: self.expires_at,
            scope: self.scope,
            created_at: self.created_at,
            updated_at: self.updated_at,
            user_id: self.user_id,
            organization_id: self.organization_id,
        })
    }
}

/// PostgreSQL oauth_providers table - matches schema exactly
#[derive(FromRow)]
struct OAuthProviderRow {
    id: String,
    name: String,
    client_id: String,
    client_secret: String,
    auth_url: String,
    token_url: String,
    scopes: serde_json::Value,
    auth_params: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
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
            scopes: row.scopes.as_array().map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            }),
            auth_params: row.auth_params.as_object().map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                    .collect()
            }),
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

/// PostgreSQL oauth_clients table - matches schema exactly
#[derive(FromRow)]
struct OAuthClientRow {
    id: String,
    secret: String,
    name: String,
    redirect_uris: serde_json::Value,
    grant_types: serde_json::Value,
    response_types: serde_json::Value,
    scope: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<OAuthClientRow> for OAuthClient {
    type Error = BeemFlowError;

    fn try_from(row: OAuthClientRow) -> Result<Self> {
        Ok(OAuthClient {
            id: row.id,
            secret: row.secret,
            name: row.name,
            redirect_uris: serde_json::from_value(row.redirect_uris)?,
            grant_types: serde_json::from_value(row.grant_types)?,
            response_types: serde_json::from_value(row.response_types)?,
            scope: row.scope,
            client_uri: None,
            logo_uri: None,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

/// PostgreSQL oauth_tokens table - matches schema exactly
#[derive(FromRow)]
struct OAuthTokenRow {
    id: String,
    client_id: String,
    user_id: String,
    redirect_uri: String,
    scope: String,
    code: String,
    code_create_at: Option<DateTime<Utc>>,
    code_expires_in: Option<i64>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    access: String,
    access_create_at: Option<DateTime<Utc>>,
    access_expires_in: Option<i64>,
    refresh: String,
    refresh_create_at: Option<DateTime<Utc>>,
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
            code_create_at: row.code_create_at,
            code_expires_in: row
                .code_expires_in
                .filter(|&s| s >= 0)
                .map(|s| std::time::Duration::from_secs(s as u64)),
            code_challenge: row.code_challenge,
            code_challenge_method: row.code_challenge_method,
            access: Some(row.access),
            access_create_at: row.access_create_at,
            access_expires_in: row
                .access_expires_in
                .filter(|&s| s >= 0)
                .map(|s| std::time::Duration::from_secs(s as u64)),
            refresh: Some(row.refresh),
            refresh_create_at: row.refresh_create_at,
            refresh_expires_in: row
                .refresh_expires_in
                .filter(|&s| s >= 0)
                .map(|s| std::time::Duration::from_secs(s as u64)),
        })
    }
}

/// PostgreSQL organizations table - matches schema exactly
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
    settings: Option<serde_json::Value>,
    created_by_user_id: String,
    created_at: i64,
    updated_at: i64,
    disabled: bool,
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
            settings: row.settings,
            created_by_user_id: row.created_by_user_id,
            created_at: DateTime::from_timestamp_millis(row.created_at).unwrap_or_else(Utc::now),
            updated_at: DateTime::from_timestamp_millis(row.updated_at).unwrap_or_else(Utc::now),
            disabled: row.disabled,
        })
    }
}

/// PostgreSQL paused_runs table - matches schema exactly
#[derive(FromRow)]
struct PausedRunRow {
    token: String,
    data: serde_json::Value,
}

/// PostgreSQL refresh_tokens table - matches schema exactly
#[derive(FromRow)]
struct RefreshTokenRow {
    id: String,
    user_id: String,
    token_hash: String,
    expires_at: i64,
    revoked: bool,
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
            revoked: row.revoked,
            revoked_at: row.revoked_at.and_then(DateTime::from_timestamp_millis),
            created_at: DateTime::from_timestamp_millis(row.created_at).unwrap_or_else(Utc::now),
            last_used_at: row.last_used_at.and_then(DateTime::from_timestamp_millis),
            user_agent: row.user_agent,
            client_ip: row.client_ip,
        })
    }
}

/// PostgreSQL organization_members table - matches schema exactly
#[derive(FromRow)]
struct OrganizationMemberRow {
    id: String,
    organization_id: String,
    user_id: String,
    role: String,
    invited_by_user_id: Option<String>,
    invited_at: Option<i64>,
    joined_at: i64,
    disabled: bool,
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
            disabled: row.disabled,
        })
    }
}

/// PostgreSQL flow_versions row for list_flow_versions
#[derive(FromRow)]
struct FlowSnapshotRow {
    version: String,
    deployed_at: DateTime<Utc>,
    is_live: bool,
}

/// Helper row type for single-column queries
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
    settings: Option<serde_json::Value>,
    created_by_user_id: String,
    created_at: i64,
    updated_at: i64,
    disabled: bool,
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
            settings: self.settings,
            created_by_user_id: self.created_by_user_id,
            created_at: DateTime::from_timestamp_millis(self.created_at).unwrap_or_else(Utc::now),
            updated_at: DateTime::from_timestamp_millis(self.updated_at).unwrap_or_else(Utc::now),
            disabled: self.disabled,
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
            email_verified: self.email_verified,
            avatar_url: self.avatar_url,
            mfa_enabled: self.mfa_enabled,
            mfa_secret: self.mfa_secret,
            created_at: DateTime::from_timestamp_millis(self.created_at).unwrap_or_else(Utc::now),
            updated_at: DateTime::from_timestamp_millis(self.updated_at).unwrap_or_else(Utc::now),
            last_login_at: self.last_login_at.and_then(DateTime::from_timestamp_millis),
            disabled: self.disabled,
            disabled_reason: self.disabled_reason,
            disabled_at: self.disabled_at.and_then(DateTime::from_timestamp_millis),
        };

        Ok((user, role))
    }
}

// ============================================================================
// PostgreSQL Storage Implementation
// ============================================================================

/// PostgreSQL storage implementation
pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    /// Create a new PostgreSQL storage from a connection string
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = PgPool::connect(database_url).await.map_err(|e| {
            BeemFlowError::storage(format!("Failed to connect to PostgreSQL: {}", e))
        })?;

        // Run PostgreSQL-specific migrations
        sqlx::migrate!("./migrations/postgres")
            .run(&pool)
            .await
            .map_err(|e| BeemFlowError::storage(format!("Failed to run migrations: {}", e)))?;

        Ok(Self { pool })
    }
}

#[async_trait]
impl RunStorage for PostgresStorage {
    // Run methods
    async fn save_run(&self, run: &Run) -> Result<()> {
        sqlx::query(
            "INSERT INTO runs (id, flow_name, event, vars, status, started_at, ended_at, organization_id, triggered_by_user_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT(id) DO UPDATE SET
                flow_name = EXCLUDED.flow_name,
                event = EXCLUDED.event,
                vars = EXCLUDED.vars,
                status = EXCLUDED.status,
                started_at = EXCLUDED.started_at,
                ended_at = EXCLUDED.ended_at,
                organization_id = EXCLUDED.organization_id,
                triggered_by_user_id = EXCLUDED.triggered_by_user_id",
        )
        .bind(run.id)
        .bind(run.flow_name.as_str())
        .bind(serde_json::to_value(&run.event)?)
        .bind(serde_json::to_value(&run.vars)?)
        .bind(run_status_to_str(run.status))
        .bind(run.started_at)
        .bind(run.ended_at)
        .bind(&run.organization_id)
        .bind(&run.triggered_by_user_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_run(&self, id: Uuid, organization_id: &str) -> Result<Option<Run>> {
        sqlx::query_as::<_, RunRow>(
            "SELECT id, flow_name, event, vars, status, started_at, ended_at, organization_id, triggered_by_user_id
             FROM runs WHERE id = $1 AND organization_id = $2",
        )
        .bind(id)
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
             WHERE organization_id = $1
             ORDER BY started_at DESC
             LIMIT $2 OFFSET $3",
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
                 WHERE organization_id = $1 AND flow_name = $2 AND status = $3 AND id != $4
                 ORDER BY started_at DESC
                 LIMIT $5",
            )
            .bind(organization_id)
            .bind(flow_name)
            .bind(status_str)
            .bind(id)
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, RunRow>(
                "SELECT id, flow_name, event, vars, status, started_at, ended_at, organization_id, triggered_by_user_id
                 FROM runs
                 WHERE organization_id = $1 AND flow_name = $2 AND status = $3
                 ORDER BY started_at DESC
                 LIMIT $4",
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

        // Postgres will cascade delete steps due to foreign key
        sqlx::query("DELETE FROM runs WHERE id = $1 AND organization_id = $2")
            .bind(id)
            .bind(organization_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn try_insert_run(&self, run: &Run) -> Result<bool> {
        let result = sqlx::query(
            "INSERT INTO runs (id, flow_name, event, vars, status, started_at, ended_at, organization_id, triggered_by_user_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(run.id)
        .bind(run.flow_name.as_str())
        .bind(serde_json::to_value(&run.event)?)
        .bind(serde_json::to_value(&run.vars)?)
        .bind(run_status_to_str(run.status))
        .bind(run.started_at)
        .bind(run.ended_at)
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
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT(id) DO UPDATE SET
                run_id = EXCLUDED.run_id,
                organization_id = EXCLUDED.organization_id,
                step_name = EXCLUDED.step_name,
                status = EXCLUDED.status,
                started_at = EXCLUDED.started_at,
                ended_at = EXCLUDED.ended_at,
                outputs = EXCLUDED.outputs,
                error = EXCLUDED.error"
        )
        .bind(step.id)
        .bind(step.run_id)
        .bind(&step.organization_id)
        .bind(step.step_name.as_str())
        .bind(step_status_to_str(step.status))
        .bind(step.started_at)
        .bind(step.ended_at)
        .bind(serde_json::to_value(&step.outputs)?)
        .bind(&step.error)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_steps(&self, run_id: Uuid, organization_id: &str) -> Result<Vec<StepRun>> {
        sqlx::query_as::<_, StepRow>(
            "SELECT id, run_id, organization_id, step_name, status, started_at, ended_at, outputs, error
             FROM steps WHERE run_id = $1 AND organization_id = $2",
        )
        .bind(run_id)
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(StepRun::try_from)
        .collect()
    }
}

#[async_trait]
impl StateStorage for PostgresStorage {
    // Wait/timeout methods
    async fn register_wait(&self, token: Uuid, wake_at: Option<i64>) -> Result<()> {
        sqlx::query(
            "INSERT INTO waits (token, wake_at) VALUES ($1, $2) 
             ON CONFLICT(token) DO UPDATE SET wake_at = EXCLUDED.wake_at",
        )
        .bind(token.to_string())
        .bind(wake_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn resolve_wait(&self, token: Uuid) -> Result<Option<Run>> {
        sqlx::query("DELETE FROM waits WHERE token = $1")
            .bind(token.to_string())
            .execute(&self.pool)
            .await?;

        // Postgres storage doesn't resolve waits to specific runs
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
        sqlx::query(
            "INSERT INTO paused_runs (token, source, data, organization_id, user_id) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT(token) DO UPDATE SET source = EXCLUDED.source, data = EXCLUDED.data, organization_id = EXCLUDED.organization_id, user_id = EXCLUDED.user_id",
        )
        .bind(token)
        .bind(source)
        .bind(data)
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

        Ok(rows.into_iter().map(|row| (row.token, row.data)).collect())
    }

    async fn find_paused_runs_by_source(
        &self,
        source: &str,
        organization_id: &str,
    ) -> Result<Vec<(String, serde_json::Value)>> {
        let rows = sqlx::query_as::<_, PausedRunRow>(
            "SELECT token, data FROM paused_runs WHERE source = $1 AND organization_id = $2",
        )
        .bind(source)
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|row| (row.token, row.data)).collect())
    }

    async fn delete_paused_run(&self, token: &str) -> Result<()> {
        sqlx::query("DELETE FROM paused_runs WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn fetch_and_delete_paused_run(&self, token: &str) -> Result<Option<serde_json::Value>> {
        // Use DELETE ... RETURNING for atomic fetch-and-delete
        #[derive(FromRow)]
        struct DataRow {
            data: serde_json::Value,
        }

        Ok(
            sqlx::query_as::<_, DataRow>("DELETE FROM paused_runs WHERE token = $1 RETURNING data")
                .bind(token)
                .fetch_optional(&self.pool)
                .await?
                .map(|row| row.data),
        )
    }
}

#[async_trait]
impl FlowStorage for PostgresStorage {
    // Flow versioning methods
    async fn deploy_flow_version(
        &self,
        organization_id: &str,
        flow_name: &str,
        version: &str,
        content: &str,
        deployed_by_user_id: &str,
    ) -> Result<()> {
        let now = Utc::now();

        // Parse flow to extract trigger topics
        let topics = extract_topics_from_flow_yaml(content);

        // Start transaction
        let mut tx = self.pool.begin().await?;

        // Check if this version already exists (enforce version immutability)
        let exists = sqlx::query(
            "SELECT 1 FROM flow_versions WHERE organization_id = $1 AND flow_name = $2 AND version = $3 LIMIT 1",
        )
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
            VALUES ($1, $2, $3, $4, $5, $6)",
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
             VALUES ($1, $2, $3, $4)
             ON CONFLICT(organization_id, flow_name) DO UPDATE SET
                deployed_version = EXCLUDED.deployed_version,
                deployed_at = EXCLUDED.deployed_at",
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
                 VALUES ($1, $2, $3, $4)
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
        let now = Utc::now();

        sqlx::query(
            "INSERT INTO deployed_flows (organization_id, flow_name, deployed_version, deployed_at)
            VALUES ($1, $2, $3, $4)
             ON CONFLICT(organization_id, flow_name) DO UPDATE SET
                deployed_version = EXCLUDED.deployed_version,
                deployed_at = EXCLUDED.deployed_at",
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
            "SELECT deployed_version AS value FROM deployed_flows WHERE organization_id = $1 AND flow_name = $2",
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
            "SELECT content AS value FROM flow_versions WHERE organization_id = $1 AND flow_name = $2 AND version = $3",
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
                CASE WHEN d.deployed_version = v.version THEN true ELSE false END as is_live
             FROM flow_versions v
             LEFT JOIN deployed_flows d ON v.organization_id = d.organization_id AND v.flow_name = d.flow_name
             WHERE v.organization_id = $1 AND v.flow_name = $2
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
                deployed_at: row.deployed_at,
                is_live: row.is_live,
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
             WHERE organization_id = $1 AND flow_name = $2
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
        sqlx::query("DELETE FROM deployed_flows WHERE organization_id = $1 AND flow_name = $2")
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
             WHERE d.organization_id = $1",
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
             WHERE ft.organization_id = $1 AND ft.topic = $2
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

        // Build placeholders for IN clause: $2, $3, $4, ... ($1 is organization_id)
        let placeholders = (2..=flow_names.len() + 1)
            .map(|i| format!("${}", i))
            .collect::<Vec<_>>()
            .join(", ");

        let query_str = format!(
            "SELECT df.flow_name, fv.content
             FROM deployed_flows df
             INNER JOIN flow_versions fv ON df.organization_id = fv.organization_id AND df.flow_name = fv.flow_name AND df.deployed_version = fv.version
             WHERE df.organization_id = $1 AND df.flow_name IN ({})",
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
             WHERE df.organization_id = $1 AND df.flow_name = $2",
        )
        .bind(organization_id)
        .bind(flow_name)
        .fetch_optional(&self.pool)
        .await?
        .map(|r| r.value))
    }
}

#[async_trait]
impl OAuthStorage for PostgresStorage {
    // OAuth credential methods (similar pattern to SQLite)
    async fn save_oauth_credential(&self, credential: &OAuthCredential) -> Result<()> {
        // Encrypt tokens before storage (protects against database compromise)
        let (encrypted_access, encrypted_refresh) =
            crate::auth::TokenEncryption::encrypt_credential_tokens(
                &credential.access_token,
                &credential.refresh_token,
            )?;

        sqlx::query(
            "INSERT INTO oauth_credentials
             (id, provider, integration, access_token, refresh_token, expires_at, scope, created_at, updated_at, user_id, organization_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             ON CONFLICT(user_id, provider, integration) DO UPDATE SET
                id = EXCLUDED.id,
                access_token = EXCLUDED.access_token,
                refresh_token = EXCLUDED.refresh_token,
                expires_at = EXCLUDED.expires_at,
                scope = EXCLUDED.scope,
                updated_at = EXCLUDED.updated_at,
                organization_id = EXCLUDED.organization_id"
        )
        .bind(&credential.id)
        .bind(&credential.provider)
        .bind(&credential.integration)
        .bind(encrypted_access.as_str())  // Store encrypted
        .bind(encrypted_refresh.as_ref().map(|e| e.as_str()))  // Store encrypted
        .bind(credential.expires_at)
        .bind(&credential.scope)
        .bind(credential.created_at)
        .bind(Utc::now())
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
             WHERE provider = $1 AND integration = $2 AND user_id = $3 AND organization_id = $4"
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
             WHERE user_id = $1 AND organization_id = $2
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
             WHERE id = $1 AND organization_id = $2"
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
            sqlx::query("DELETE FROM oauth_credentials WHERE id = $1 AND organization_id = $2")
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
        // Encrypt the new token before storage
        let (encrypted_token, _) =
            crate::auth::TokenEncryption::encrypt_credential_tokens(new_token, &None)?;

        let result = sqlx::query(
            "UPDATE oauth_credentials
             SET access_token = $1, expires_at = $2, updated_at = $3
             WHERE id = $4 AND organization_id = $5",
        )
        .bind(encrypted_token.as_str()) // Store encrypted
        .bind(expires_at)
        .bind(Utc::now())
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
        let scopes_json = serde_json::to_value(&provider.scopes)?;
        let auth_params_json = serde_json::to_value(&provider.auth_params)?;

        sqlx::query(
            "INSERT INTO oauth_providers
             (id, name, client_id, client_secret, auth_url, token_url, scopes, auth_params, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT(id) DO UPDATE SET
                name = EXCLUDED.name,
                client_id = EXCLUDED.client_id,
                client_secret = EXCLUDED.client_secret,
                auth_url = EXCLUDED.auth_url,
                token_url = EXCLUDED.token_url,
                scopes = EXCLUDED.scopes,
                auth_params = EXCLUDED.auth_params,
                updated_at = EXCLUDED.updated_at",
        )
        .bind(&provider.id)
        .bind(&provider.name)
        .bind(&provider.client_id)
        .bind(&provider.client_secret)
        .bind(&provider.auth_url)
        .bind(&provider.token_url)
        .bind(scopes_json)
        .bind(auth_params_json)
        .bind(provider.created_at)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_oauth_provider(&self, id: &str) -> Result<Option<OAuthProvider>> {
        sqlx::query_as::<_, OAuthProviderRow>(
            "SELECT id, name, client_id, client_secret, auth_url, token_url, scopes, auth_params, created_at, updated_at
             FROM oauth_providers WHERE id = $1",
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
             FROM oauth_providers ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(OAuthProvider::try_from)
        .collect()
    }

    async fn delete_oauth_provider(&self, id: &str) -> Result<()> {
        let result = sqlx::query("DELETE FROM oauth_providers WHERE id = $1")
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
        let redirect_uris_json = serde_json::to_value(&client.redirect_uris)?;
        let grant_types_json = serde_json::to_value(&client.grant_types)?;
        let response_types_json = serde_json::to_value(&client.response_types)?;

        sqlx::query(
            "INSERT INTO oauth_clients
             (id, secret, name, redirect_uris, grant_types, response_types, scope, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT(id) DO UPDATE SET
                secret = EXCLUDED.secret,
                name = EXCLUDED.name,
                redirect_uris = EXCLUDED.redirect_uris,
                grant_types = EXCLUDED.grant_types,
                response_types = EXCLUDED.response_types,
                scope = EXCLUDED.scope,
                updated_at = EXCLUDED.updated_at"
        )
        .bind(&client.id)
        .bind(&client.secret)
        .bind(&client.name)
        .bind(redirect_uris_json)
        .bind(grant_types_json)
        .bind(response_types_json)
        .bind(&client.scope)
        .bind(client.created_at)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_oauth_client(&self, id: &str) -> Result<Option<OAuthClient>> {
        sqlx::query_as::<_, OAuthClientRow>(
            "SELECT id, secret, name, redirect_uris, grant_types, response_types, scope, created_at, updated_at
             FROM oauth_clients WHERE id = $1",
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
             FROM oauth_clients ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(OAuthClient::try_from)
        .collect()
    }

    async fn delete_oauth_client(&self, id: &str) -> Result<()> {
        let result = sqlx::query("DELETE FROM oauth_clients WHERE id = $1")
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
        sqlx::query(
            "INSERT INTO oauth_tokens
             (id, client_id, user_id, redirect_uri, scope, code, code_create_at, code_expires_in,
              code_challenge, code_challenge_method, access, access_create_at, access_expires_in,
              refresh, refresh_create_at, refresh_expires_in, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
             ON CONFLICT(id) DO UPDATE SET
                client_id = EXCLUDED.client_id,
                user_id = EXCLUDED.user_id,
                redirect_uri = EXCLUDED.redirect_uri,
                scope = EXCLUDED.scope,
                code = EXCLUDED.code,
                code_create_at = EXCLUDED.code_create_at,
                code_expires_in = EXCLUDED.code_expires_in,
                code_challenge = EXCLUDED.code_challenge,
                code_challenge_method = EXCLUDED.code_challenge_method,
                access = EXCLUDED.access,
                access_create_at = EXCLUDED.access_create_at,
                access_expires_in = EXCLUDED.access_expires_in,
                refresh = EXCLUDED.refresh,
                refresh_create_at = EXCLUDED.refresh_create_at,
                refresh_expires_in = EXCLUDED.refresh_expires_in,
                updated_at = EXCLUDED.updated_at"
        )
        .bind(&token.id)
        .bind(&token.client_id)
        .bind(&token.user_id)
        .bind(&token.redirect_uri)
        .bind(&token.scope)
        .bind(&token.code)
        .bind(token.code_create_at)
        .bind(token.code_expires_in.map(|d| d.as_secs() as i64))
        .bind(&token.code_challenge)
        .bind(&token.code_challenge_method)
        .bind(&token.access)
        .bind(token.access_create_at)
        .bind(token.access_expires_in.map(|d| d.as_secs() as i64))
        .bind(&token.refresh)
        .bind(token.refresh_create_at)
        .bind(token.refresh_expires_in.map(|d| d.as_secs() as i64))
        .bind(Utc::now())
        .bind(Utc::now())
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
        sqlx::query("DELETE FROM oauth_tokens WHERE code = $1")
            .bind(code)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_oauth_token_by_access(&self, access: &str) -> Result<()> {
        sqlx::query("DELETE FROM oauth_tokens WHERE access = $1")
            .bind(access)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_oauth_token_by_refresh(&self, refresh: &str) -> Result<()> {
        sqlx::query("DELETE FROM oauth_tokens WHERE refresh = $1")
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

impl PostgresStorage {
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
                 FROM oauth_tokens WHERE code = $1"
            }
            OAuthTokenField::Access => {
                "SELECT id, client_id, user_id, redirect_uri, scope, code, code_create_at, code_expires_in,
                        code_challenge, code_challenge_method, access, access_create_at, access_expires_in,
                        refresh, refresh_create_at, refresh_expires_in
                 FROM oauth_tokens WHERE access = $1"
            }
            OAuthTokenField::Refresh => {
                "SELECT id, client_id, user_id, redirect_uri, scope, code, code_create_at, code_expires_in,
                        code_challenge, code_challenge_method, access, access_create_at, access_expires_in,
                        refresh, refresh_create_at, refresh_expires_in
                 FROM oauth_tokens WHERE refresh = $1"
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
impl crate::storage::AuthStorage for PostgresStorage {
    // User methods
    async fn create_user(&self, user: &crate::auth::User) -> Result<()> {
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

    async fn get_user(&self, id: &str) -> Result<Option<crate::auth::User>> {
        sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .map(crate::auth::User::try_from)
            .transpose()
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<crate::auth::User>> {
        sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE email = $1 AND disabled = FALSE")
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
                email = $1, name = $2, password_hash = $3, email_verified = $4,
                avatar_url = $5, mfa_enabled = $6, mfa_secret = $7,
                updated_at = $8, last_login_at = $9,
                disabled = $10, disabled_reason = $11, disabled_at = $12
            WHERE id = $13
            "#,
        )
        .bind(&user.email)
        .bind(&user.name)
        .bind(&user.password_hash)
        .bind(user.email_verified)
        .bind(&user.avatar_url)
        .bind(user.mfa_enabled)
        .bind(&user.mfa_secret)
        .bind(user.updated_at.timestamp_millis())
        .bind(user.last_login_at.map(|t| t.timestamp_millis()))
        .bind(user.disabled)
        .bind(&user.disabled_reason)
        .bind(user.disabled_at.map(|t| t.timestamp_millis()))
        .bind(&user.id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn update_user_last_login(&self, user_id: &str) -> Result<()> {
        sqlx::query("UPDATE users SET last_login_at = $1 WHERE id = $2")
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
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
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
        .bind(organization.settings.as_ref())
        .bind(&organization.created_by_user_id)
        .bind(organization.created_at.timestamp_millis())
        .bind(organization.updated_at.timestamp_millis())
        .bind(organization.disabled)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_organization(&self, id: &str) -> Result<Option<crate::auth::Organization>> {
        sqlx::query_as::<_, OrganizationRow>("SELECT * FROM organizations WHERE id = $1")
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
        sqlx::query_as::<_, OrganizationRow>("SELECT * FROM organizations WHERE slug = $1")
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
                name = $1, slug = $2, plan = $3, plan_starts_at = $4, plan_ends_at = $5,
                max_users = $6, max_flows = $7, max_runs_per_month = $8,
                settings = $9, updated_at = $10, disabled = $11
            WHERE id = $12
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
        .bind(organization.settings.as_ref())
        .bind(organization.updated_at.timestamp_millis())
        .bind(organization.disabled)
        .bind(&organization.id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn list_active_organizations(&self) -> Result<Vec<crate::auth::Organization>> {
        sqlx::query_as::<_, OrganizationRow>(
            "SELECT * FROM organizations WHERE disabled = FALSE ORDER BY created_at ASC",
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
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(&member.id)
        .bind(&member.organization_id)
        .bind(&member.user_id)
        .bind(member.role.as_str())
        .bind(&member.invited_by_user_id)
        .bind(member.invited_at.map(|t| t.timestamp_millis()))
        .bind(member.joined_at.timestamp_millis())
        .bind(member.disabled)
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
            "SELECT * FROM organization_members WHERE organization_id = $1 AND user_id = $2 AND disabled = FALSE",
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
            SELECT o.*, om.role
            FROM organizations o
            INNER JOIN organization_members om ON o.id = om.organization_id
            WHERE om.user_id = $1 AND om.disabled = FALSE AND o.disabled = FALSE
            ORDER BY om.joined_at ASC
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
            SELECT u.*, om.role
            FROM users u
            INNER JOIN organization_members om ON u.id = om.user_id
            WHERE om.organization_id = $1 AND om.disabled = FALSE AND u.disabled = FALSE
            ORDER BY om.joined_at ASC
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
            "UPDATE organization_members SET role = $1 WHERE organization_id = $2 AND user_id = $3",
        )
        .bind(role.as_str())
        .bind(organization_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn remove_organization_member(&self, organization_id: &str, user_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2")
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
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(&token.id)
        .bind(&token.user_id)
        .bind(&token.token_hash)
        .bind(token.expires_at.timestamp_millis())
        .bind(token.revoked)
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
            "SELECT * FROM refresh_tokens WHERE token_hash = $1 AND revoked = FALSE",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?
        .map(crate::auth::RefreshToken::try_from)
        .transpose()
    }

    async fn revoke_refresh_token(&self, token_hash: &str) -> Result<()> {
        sqlx::query(
            "UPDATE refresh_tokens SET revoked = TRUE, revoked_at = $1 WHERE token_hash = $2",
        )
        .bind(Utc::now().timestamp_millis())
        .bind(token_hash)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn revoke_all_user_tokens(&self, user_id: &str) -> Result<()> {
        sqlx::query("UPDATE refresh_tokens SET revoked = TRUE, revoked_at = $1 WHERE user_id = $2")
            .bind(Utc::now().timestamp_millis())
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn update_refresh_token_last_used(&self, token_hash: &str) -> Result<()> {
        sqlx::query("UPDATE refresh_tokens SET last_used_at = $1 WHERE token_hash = $2")
            .bind(Utc::now().timestamp_millis())
            .bind(token_hash)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
