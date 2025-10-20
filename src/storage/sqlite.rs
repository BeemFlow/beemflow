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
use sqlx::{Row, SqlitePool, sqlite::SqliteRow};
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;

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

    fn parse_run(row: &SqliteRow) -> Result<Run> {
        Ok(Run {
            id: Uuid::parse_str(&row.try_get::<String, _>("id")?)?,
            flow_name: row.try_get::<String, _>("flow_name")?.into(),
            event: serde_json::from_str(&row.try_get::<String, _>("event")?)?,
            vars: serde_json::from_str(&row.try_get::<String, _>("vars")?)?,
            status: parse_run_status(&row.try_get::<String, _>("status")?),
            started_at: DateTime::from_timestamp(row.try_get("started_at")?, 0)
                .unwrap_or_else(Utc::now),
            ended_at: row
                .try_get::<Option<i64>, _>("ended_at")?
                .map(|ts| DateTime::from_timestamp(ts, 0).unwrap_or_else(Utc::now)),
            steps: None,
        })
    }

    fn parse_step(row: &SqliteRow) -> Result<StepRun> {
        Ok(StepRun {
            id: Uuid::parse_str(&row.try_get::<String, _>("id")?)?,
            run_id: Uuid::parse_str(&row.try_get::<String, _>("run_id")?)?,
            step_name: row.try_get::<String, _>("step_name")?.into(),
            status: parse_step_status(&row.try_get::<String, _>("status")?),
            started_at: DateTime::from_timestamp(row.try_get("started_at")?, 0)
                .unwrap_or_else(Utc::now),
            ended_at: row
                .try_get::<Option<i64>, _>("ended_at")?
                .map(|ts| DateTime::from_timestamp(ts, 0).unwrap_or_else(Utc::now)),
            outputs: serde_json::from_str(&row.try_get::<String, _>("outputs")?)?,
            error: row.try_get("error")?,
        })
    }
}

#[async_trait]
impl RunStorage for SqliteStorage {
    // Run methods
    async fn save_run(&self, run: &Run) -> Result<()> {
        sqlx::query(
            "INSERT INTO runs (id, flow_name, event, vars, status, started_at, ended_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                flow_name = excluded.flow_name,
                event = excluded.event,
                vars = excluded.vars,
                status = excluded.status,
                started_at = excluded.started_at,
                ended_at = excluded.ended_at",
        )
        .bind(run.id.to_string())
        .bind(run.flow_name.as_str())
        .bind(serde_json::to_string(&run.event)?)
        .bind(serde_json::to_string(&run.vars)?)
        .bind(run_status_to_str(run.status))
        .bind(run.started_at.timestamp())
        .bind(run.ended_at.map(|dt| dt.timestamp()))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_run(&self, id: Uuid) -> Result<Option<Run>> {
        let row = sqlx::query(
            "SELECT id, flow_name, event, vars, status, started_at, ended_at 
             FROM runs WHERE id = ?",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(Self::parse_run(&row)?)),
            None => Ok(None),
        }
    }

    async fn list_runs(&self, limit: usize, offset: usize) -> Result<Vec<Run>> {
        // Cap limit at 10,000 to prevent unbounded queries
        let capped_limit = limit.min(10_000);

        let rows = sqlx::query(
            "SELECT id, flow_name, event, vars, status, started_at, ended_at
             FROM runs
             ORDER BY started_at DESC
             LIMIT ? OFFSET ?",
        )
        .bind(capped_limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await?;

        let mut runs = Vec::new();
        for row in rows {
            if let Ok(run) = Self::parse_run(&row) {
                runs.push(run);
            }
        }
        Ok(runs)
    }

    async fn list_runs_by_flow_and_status(
        &self,
        flow_name: &str,
        status: RunStatus,
        exclude_id: Option<Uuid>,
        limit: usize,
    ) -> Result<Vec<Run>> {
        let status_str = run_status_to_str(status);

        // Build query with optional exclude clause
        let query = if let Some(id) = exclude_id {
            sqlx::query(
                "SELECT id, flow_name, event, vars, status, started_at, ended_at
                 FROM runs
                 WHERE flow_name = ? AND status = ? AND id != ?
                 ORDER BY started_at DESC
                 LIMIT ?",
            )
            .bind(flow_name)
            .bind(status_str)
            .bind(id.to_string())
            .bind(limit as i64)
        } else {
            sqlx::query(
                "SELECT id, flow_name, event, vars, status, started_at, ended_at
                 FROM runs
                 WHERE flow_name = ? AND status = ?
                 ORDER BY started_at DESC
                 LIMIT ?",
            )
            .bind(flow_name)
            .bind(status_str)
            .bind(limit as i64)
        };

        let rows = query.fetch_all(&self.pool).await?;

        let mut runs = Vec::new();
        for row in rows {
            if let Ok(run) = Self::parse_run(&row) {
                runs.push(run);
            }
        }
        Ok(runs)
    }

    async fn delete_run(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM steps WHERE run_id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        sqlx::query("DELETE FROM runs WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn try_insert_run(&self, run: &Run) -> Result<bool> {
        let result = sqlx::query(
            "INSERT INTO runs (id, flow_name, event, vars, status, started_at, ended_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(run.id.to_string())
        .bind(run.flow_name.as_str())
        .bind(serde_json::to_string(&run.event)?)
        .bind(serde_json::to_string(&run.vars)?)
        .bind(run_status_to_str(run.status))
        .bind(run.started_at.timestamp())
        .bind(run.ended_at.map(|dt| dt.timestamp()))
        .execute(&self.pool)
        .await?;

        // Returns true if a row was inserted, false if conflict occurred
        Ok(result.rows_affected() == 1)
    }

    // Step methods
    async fn save_step(&self, step: &StepRun) -> Result<()> {
        sqlx::query(
            "INSERT INTO steps (id, run_id, step_name, status, started_at, ended_at, outputs, error)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                run_id = excluded.run_id,
                step_name = excluded.step_name,
                status = excluded.status,
                started_at = excluded.started_at,
                ended_at = excluded.ended_at,
                outputs = excluded.outputs,
                error = excluded.error"
        )
        .bind(step.id.to_string())
        .bind(step.run_id.to_string())
        .bind(step.step_name.as_str())
        .bind(step_status_to_str(step.status))
        .bind(step.started_at.timestamp())
        .bind(step.ended_at.map(|dt| dt.timestamp()))
        .bind(serde_json::to_string(&step.outputs)?)
        .bind(&step.error)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_steps(&self, run_id: Uuid) -> Result<Vec<StepRun>> {
        let rows = sqlx::query(
            "SELECT id, run_id, step_name, status, started_at, ended_at, outputs, error 
             FROM steps WHERE run_id = ?",
        )
        .bind(run_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        let mut steps = Vec::new();
        for row in rows {
            if let Ok(step) = Self::parse_step(&row) {
                steps.push(step);
            }
        }
        Ok(steps)
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
    ) -> Result<()> {
        let data_json = serde_json::to_string(&data)?;

        sqlx::query(
            "INSERT INTO paused_runs (token, source, data) VALUES (?, ?, ?)
             ON CONFLICT(token) DO UPDATE SET source = excluded.source, data = excluded.data",
        )
        .bind(token)
        .bind(source)
        .bind(data_json)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn load_paused_runs(&self) -> Result<HashMap<String, serde_json::Value>> {
        let rows = sqlx::query("SELECT token, data FROM paused_runs")
            .fetch_all(&self.pool)
            .await?;

        let mut result = HashMap::new();
        for row in rows {
            let token: String = row.try_get("token")?;
            let data_json: String = row.try_get("data")?;
            if let Ok(data) = serde_json::from_str(&data_json) {
                result.insert(token, data);
            }
        }

        Ok(result)
    }

    async fn find_paused_runs_by_source(
        &self,
        source: &str,
    ) -> Result<Vec<(String, serde_json::Value)>> {
        let rows = sqlx::query("SELECT token, data FROM paused_runs WHERE source = ?")
            .bind(source)
            .fetch_all(&self.pool)
            .await?;

        let mut result = Vec::new();
        for row in rows {
            let token: String = row.try_get("token")?;
            let data_json: String = row.try_get("data")?;
            if let Ok(data) = serde_json::from_str(&data_json) {
                result.push((token, data));
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
        let row = sqlx::query("DELETE FROM paused_runs WHERE token = ? RETURNING data")
            .bind(token)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(row) => {
                let data_json: String = row.try_get("data")?;
                Ok(Some(serde_json::from_str(&data_json)?))
            }
            None => Ok(None),
        }
    }
}

#[async_trait]
impl FlowStorage for SqliteStorage {
    // Flow versioning methods
    async fn deploy_flow_version(
        &self,
        flow_name: &str,
        version: &str,
        content: &str,
    ) -> Result<()> {
        let now = Utc::now().timestamp();

        // Parse flow to extract trigger topics
        let topics = extract_topics_from_flow_yaml(content);

        // Start transaction
        let mut tx = self.pool.begin().await?;

        // Check if this version already exists (enforce version immutability)
        let exists =
            sqlx::query("SELECT 1 FROM flow_versions WHERE flow_name = ? AND version = ? LIMIT 1")
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
            "INSERT INTO flow_versions (flow_name, version, content, deployed_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(flow_name)
        .bind(version)
        .bind(content)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // Update deployed version pointer
        sqlx::query(
            "INSERT INTO deployed_flows (flow_name, deployed_version, deployed_at)
             VALUES (?, ?, ?)
             ON CONFLICT(flow_name) DO UPDATE SET
                deployed_version = excluded.deployed_version,
                deployed_at = excluded.deployed_at",
        )
        .bind(flow_name)
        .bind(version)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // Insert flow_triggers for this version
        // Note: No need to delete - version is new (checked above)
        for topic in topics {
            sqlx::query(
                "INSERT INTO flow_triggers (flow_name, version, topic)
                 VALUES (?, ?, ?)
                 ON CONFLICT DO NOTHING",
            )
            .bind(flow_name)
            .bind(version)
            .bind(&topic)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn set_deployed_version(&self, flow_name: &str, version: &str) -> Result<()> {
        let now = Utc::now().timestamp();

        sqlx::query(
            "INSERT INTO deployed_flows (flow_name, deployed_version, deployed_at)
             VALUES (?, ?, ?)
             ON CONFLICT(flow_name) DO UPDATE SET
                deployed_version = excluded.deployed_version,
                deployed_at = excluded.deployed_at",
        )
        .bind(flow_name)
        .bind(version)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_deployed_version(&self, flow_name: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT deployed_version FROM deployed_flows WHERE flow_name = ?")
            .bind(flow_name)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.and_then(|r| r.try_get("deployed_version").ok()))
    }

    async fn get_flow_version_content(
        &self,
        flow_name: &str,
        version: &str,
    ) -> Result<Option<String>> {
        let row =
            sqlx::query("SELECT content FROM flow_versions WHERE flow_name = ? AND version = ?")
                .bind(flow_name)
                .bind(version)
                .fetch_optional(&self.pool)
                .await?;

        Ok(row.and_then(|r| r.try_get("content").ok()))
    }

    async fn list_flow_versions(&self, flow_name: &str) -> Result<Vec<FlowSnapshot>> {
        let rows = sqlx::query(
            "SELECT v.version, v.deployed_at,
                CASE WHEN d.deployed_version = v.version THEN 1 ELSE 0 END as is_live
             FROM flow_versions v
             LEFT JOIN deployed_flows d ON v.flow_name = d.flow_name
             WHERE v.flow_name = ?
             ORDER BY v.deployed_at DESC",
        )
        .bind(flow_name)
        .fetch_all(&self.pool)
        .await?;

        let mut snapshots = Vec::new();
        for row in rows {
            let version: String = row.try_get("version")?;
            let deployed_at_unix: i64 = row.try_get("deployed_at")?;
            let is_live: i32 = row.try_get("is_live")?;

            snapshots.push(FlowSnapshot {
                flow_name: flow_name.to_string(),
                version,
                deployed_at: DateTime::from_timestamp(deployed_at_unix, 0).unwrap_or_else(Utc::now),
                is_live: is_live == 1,
            });
        }

        Ok(snapshots)
    }

    async fn get_latest_deployed_version_from_history(
        &self,
        flow_name: &str,
    ) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT version FROM flow_versions
             WHERE flow_name = ?
             ORDER BY deployed_at DESC, version DESC
             LIMIT 1",
        )
        .bind(flow_name)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.and_then(|r| r.try_get("version").ok()))
    }

    async fn unset_deployed_version(&self, flow_name: &str) -> Result<()> {
        sqlx::query("DELETE FROM deployed_flows WHERE flow_name = ?")
            .bind(flow_name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_all_deployed_flows(&self) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query(
            "SELECT d.flow_name, v.content
             FROM deployed_flows d
             INNER JOIN flow_versions v
               ON d.flow_name = v.flow_name
               AND d.deployed_version = v.version",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut result = Vec::new();
        for row in rows {
            let flow_name: String = row.try_get("flow_name")?;
            let content: String = row.try_get("content")?;
            result.push((flow_name, content));
        }

        Ok(result)
    }

    async fn find_flow_names_by_topic(&self, topic: &str) -> Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT DISTINCT ft.flow_name
             FROM flow_triggers ft
             INNER JOIN deployed_flows d ON ft.flow_name = d.flow_name AND ft.version = d.deployed_version
             WHERE ft.topic = ?
             ORDER BY ft.flow_name"
        )
        .bind(topic)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|row| row.try_get("flow_name").ok())
            .collect())
    }

    async fn get_deployed_flows_content(
        &self,
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
             INNER JOIN flow_versions fv ON df.flow_name = fv.flow_name AND df.deployed_version = fv.version
             WHERE df.flow_name IN ({})",
            placeholders
        );

        let mut query = sqlx::query(&query_str);
        for name in flow_names {
            query = query.bind(name);
        }

        let rows = query.fetch_all(&self.pool).await?;

        rows.iter()
            .map(|row| Ok((row.try_get("flow_name")?, row.try_get("content")?)))
            .collect()
    }
}

#[async_trait]
impl OAuthStorage for SqliteStorage {
    // OAuth credential methods
    async fn save_oauth_credential(&self, credential: &OAuthCredential) -> Result<()> {
        let now = Utc::now().timestamp();

        sqlx::query(
            "INSERT OR REPLACE INTO oauth_credentials
             (id, provider, integration, access_token, refresh_token, expires_at, scope, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&credential.id)
        .bind(&credential.provider)
        .bind(&credential.integration)
        .bind(&credential.access_token)
        .bind(&credential.refresh_token)
        .bind(credential.expires_at.map(|dt| dt.timestamp()))
        .bind(&credential.scope)
        .bind(credential.created_at.timestamp())
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_oauth_credential(
        &self,
        provider: &str,
        integration: &str,
    ) -> Result<Option<OAuthCredential>> {
        let row = sqlx::query(
            "SELECT id, provider, integration, access_token, refresh_token, expires_at, scope, created_at, updated_at
             FROM oauth_credentials 
             WHERE provider = ? AND integration = ?"
        )
        .bind(provider)
        .bind(integration)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => {
                let created_at_unix: i64 = row.try_get("created_at")?;
                let updated_at_unix: i64 = row.try_get("updated_at")?;
                let expires_at_unix: Option<i64> = row.try_get("expires_at")?;

                Ok(Some(OAuthCredential {
                    id: row.try_get("id")?,
                    provider: row.try_get("provider")?,
                    integration: row.try_get("integration")?,
                    access_token: row.try_get("access_token")?,
                    refresh_token: row.try_get("refresh_token")?,
                    expires_at: expires_at_unix.and_then(|ts| DateTime::from_timestamp(ts, 0)),
                    scope: row.try_get("scope")?,
                    created_at: DateTime::from_timestamp(created_at_unix, 0)
                        .unwrap_or_else(Utc::now),
                    updated_at: DateTime::from_timestamp(updated_at_unix, 0)
                        .unwrap_or_else(Utc::now),
                }))
            }
            None => Ok(None),
        }
    }

    async fn list_oauth_credentials(&self) -> Result<Vec<OAuthCredential>> {
        let rows = sqlx::query(
            "SELECT id, provider, integration, access_token, refresh_token, expires_at, scope, created_at, updated_at
             FROM oauth_credentials 
             ORDER BY created_at DESC"
        )
        .fetch_all(&self.pool)
        .await?;

        let mut creds = Vec::new();
        for row in rows {
            let created_at_unix: i64 = row.try_get("created_at")?;
            let updated_at_unix: i64 = row.try_get("updated_at")?;
            let expires_at_unix: Option<i64> = row.try_get("expires_at")?;

            creds.push(OAuthCredential {
                id: row.try_get("id")?,
                provider: row.try_get("provider")?,
                integration: row.try_get("integration")?,
                access_token: row.try_get("access_token")?,
                refresh_token: row.try_get("refresh_token")?,
                expires_at: expires_at_unix.and_then(|ts| DateTime::from_timestamp(ts, 0)),
                scope: row.try_get("scope")?,
                created_at: DateTime::from_timestamp(created_at_unix, 0).unwrap_or_else(Utc::now),
                updated_at: DateTime::from_timestamp(updated_at_unix, 0).unwrap_or_else(Utc::now),
            });
        }

        Ok(creds)
    }

    async fn delete_oauth_credential(&self, id: &str) -> Result<()> {
        // Idempotent delete - don't error if credential doesn't exist
        sqlx::query("DELETE FROM oauth_credentials WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn refresh_oauth_credential(
        &self,
        id: &str,
        new_token: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let result = sqlx::query(
            "UPDATE oauth_credentials
             SET access_token = ?, expires_at = ?, updated_at = ?
             WHERE id = ?",
        )
        .bind(new_token)
        .bind(expires_at.map(|dt| dt.timestamp()))
        .bind(now)
        .bind(id)
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
        let now = Utc::now().timestamp();

        sqlx::query(
            "INSERT OR REPLACE INTO oauth_providers
             (id, client_id, client_secret, auth_url, token_url, scopes, auth_params, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&provider.id)
        .bind(&provider.client_id)
        .bind(&provider.client_secret)
        .bind(&provider.auth_url)
        .bind(&provider.token_url)
        .bind(scopes_json)
        .bind(auth_params_json)
        .bind(provider.created_at.timestamp())
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_oauth_provider(&self, id: &str) -> Result<Option<OAuthProvider>> {
        let row = sqlx::query(
            "SELECT id, client_id, client_secret, auth_url, token_url, scopes, auth_params, created_at, updated_at
             FROM oauth_providers
             WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => {
                let scopes_json: String = row.try_get("scopes")?;
                let auth_params_json: String = row.try_get("auth_params")?;
                let created_at_unix: i64 = row.try_get("created_at")?;
                let updated_at_unix: i64 = row.try_get("updated_at")?;

                Ok(Some(OAuthProvider {
                    id: row.try_get::<String, _>("id")?,
                    name: row.try_get::<String, _>("id")?, // DB schema has no name column, duplicate id
                    client_id: row.try_get("client_id")?,
                    client_secret: row.try_get("client_secret")?,
                    auth_url: row.try_get("auth_url")?,
                    token_url: row.try_get("token_url")?,
                    scopes: serde_json::from_str(&scopes_json).ok(),
                    auth_params: serde_json::from_str(&auth_params_json).ok(),
                    created_at: DateTime::from_timestamp(created_at_unix, 0)
                        .unwrap_or_else(Utc::now),
                    updated_at: DateTime::from_timestamp(updated_at_unix, 0)
                        .unwrap_or_else(Utc::now),
                }))
            }
            None => Ok(None),
        }
    }

    async fn list_oauth_providers(&self) -> Result<Vec<OAuthProvider>> {
        let rows = sqlx::query(
            "SELECT id, client_id, client_secret, auth_url, token_url, scopes, auth_params, created_at, updated_at
             FROM oauth_providers
             ORDER BY created_at DESC"
        )
        .fetch_all(&self.pool)
        .await?;

        let mut providers = Vec::new();
        for row in rows {
            let scopes_json: String = row.try_get("scopes")?;
            let auth_params_json: String = row.try_get("auth_params")?;
            let created_at_unix: i64 = row.try_get("created_at")?;
            let updated_at_unix: i64 = row.try_get("updated_at")?;

            providers.push(OAuthProvider {
                id: row.try_get::<String, _>("id")?,
                name: row.try_get::<String, _>("id")?, // DB schema has no name column, duplicate id
                client_id: row.try_get("client_id")?,
                client_secret: row.try_get("client_secret")?,
                auth_url: row.try_get("auth_url")?,
                token_url: row.try_get("token_url")?,
                scopes: serde_json::from_str(&scopes_json).ok(),
                auth_params: serde_json::from_str(&auth_params_json).ok(),
                created_at: DateTime::from_timestamp(created_at_unix, 0).unwrap_or_else(Utc::now),
                updated_at: DateTime::from_timestamp(updated_at_unix, 0).unwrap_or_else(Utc::now),
            });
        }

        Ok(providers)
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
        let now = Utc::now().timestamp();

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
        .bind(client.created_at.timestamp())
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_oauth_client(&self, id: &str) -> Result<Option<OAuthClient>> {
        let row = sqlx::query(
            "SELECT id, secret, name, redirect_uris, grant_types, response_types, scope, created_at, updated_at
             FROM oauth_clients
             WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => {
                let redirect_uris_json: String = row.try_get("redirect_uris")?;
                let grant_types_json: String = row.try_get("grant_types")?;
                let response_types_json: String = row.try_get("response_types")?;
                let created_at_unix: i64 = row.try_get("created_at")?;
                let updated_at_unix: i64 = row.try_get("updated_at")?;

                Ok(Some(OAuthClient {
                    id: row.try_get("id")?,
                    secret: row.try_get("secret")?,
                    name: row.try_get("name")?,
                    redirect_uris: serde_json::from_str(&redirect_uris_json)?,
                    grant_types: serde_json::from_str(&grant_types_json)?,
                    response_types: serde_json::from_str(&response_types_json)?,
                    scope: row.try_get("scope")?,
                    client_uri: None,
                    logo_uri: None,
                    created_at: DateTime::from_timestamp(created_at_unix, 0)
                        .unwrap_or_else(Utc::now),
                    updated_at: DateTime::from_timestamp(updated_at_unix, 0)
                        .unwrap_or_else(Utc::now),
                }))
            }
            None => Ok(None),
        }
    }

    async fn list_oauth_clients(&self) -> Result<Vec<OAuthClient>> {
        let rows = sqlx::query(
            "SELECT id, secret, name, redirect_uris, grant_types, response_types, scope, created_at, updated_at
             FROM oauth_clients
             ORDER BY created_at DESC"
        )
        .fetch_all(&self.pool)
        .await?;

        let mut clients = Vec::new();
        for row in rows {
            let redirect_uris_json: String = row.try_get("redirect_uris")?;
            let grant_types_json: String = row.try_get("grant_types")?;
            let response_types_json: String = row.try_get("response_types")?;
            let created_at_unix: i64 = row.try_get("created_at")?;
            let updated_at_unix: i64 = row.try_get("updated_at")?;

            if let (Ok(redirect_uris), Ok(grant_types), Ok(response_types)) = (
                serde_json::from_str(&redirect_uris_json),
                serde_json::from_str(&grant_types_json),
                serde_json::from_str(&response_types_json),
            ) {
                clients.push(OAuthClient {
                    id: row.try_get("id")?,
                    secret: row.try_get("secret")?,
                    name: row.try_get("name")?,
                    redirect_uris,
                    grant_types,
                    response_types,
                    scope: row.try_get("scope")?,
                    client_uri: None,
                    logo_uri: None,
                    created_at: DateTime::from_timestamp(created_at_unix, 0)
                        .unwrap_or_else(Utc::now),
                    updated_at: DateTime::from_timestamp(updated_at_unix, 0)
                        .unwrap_or_else(Utc::now),
                });
            }
        }

        Ok(clients)
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
        let now = Utc::now().timestamp();

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
        .bind(token.code_create_at.map(|dt| dt.timestamp()))
        .bind(token.code_expires_in.map(|d| d.as_secs() as i64))
        .bind(&token.code_challenge)
        .bind(&token.code_challenge_method)
        .bind(&token.access)
        .bind(token.access_create_at.map(|dt| dt.timestamp()))
        .bind(token.access_expires_in.map(|d| d.as_secs() as i64))
        .bind(&token.refresh)
        .bind(token.refresh_create_at.map(|dt| dt.timestamp()))
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

        let row = sqlx::query(query)
            .bind(value)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(row) => {
                let code_create_at_unix: Option<i64> = row.try_get("code_create_at")?;
                let code_expires_in_secs: Option<i64> = row.try_get("code_expires_in")?;
                let access_create_at_unix: Option<i64> = row.try_get("access_create_at")?;
                let access_expires_in_secs: Option<i64> = row.try_get("access_expires_in")?;
                let refresh_create_at_unix: Option<i64> = row.try_get("refresh_create_at")?;
                let refresh_expires_in_secs: Option<i64> = row.try_get("refresh_expires_in")?;

                Ok(Some(OAuthToken {
                    id: row.try_get("id")?,
                    client_id: row.try_get("client_id")?,
                    user_id: row.try_get("user_id")?,
                    redirect_uri: row.try_get("redirect_uri")?,
                    scope: row.try_get("scope")?,
                    code: row.try_get("code")?,
                    code_create_at: code_create_at_unix
                        .and_then(|ts| DateTime::from_timestamp(ts, 0)),
                    code_expires_in: code_expires_in_secs.and_then(|s| {
                        if s >= 0 {
                            Some(std::time::Duration::from_secs(s as u64))
                        } else {
                            None
                        }
                    }),
                    code_challenge: row.try_get("code_challenge").ok(),
                    code_challenge_method: row.try_get("code_challenge_method").ok(),
                    access: row.try_get("access")?,
                    access_create_at: access_create_at_unix
                        .and_then(|ts| DateTime::from_timestamp(ts, 0)),
                    access_expires_in: access_expires_in_secs.and_then(|s| {
                        if s >= 0 {
                            Some(std::time::Duration::from_secs(s as u64))
                        } else {
                            None
                        }
                    }),
                    refresh: row.try_get("refresh")?,
                    refresh_create_at: refresh_create_at_unix
                        .and_then(|ts| DateTime::from_timestamp(ts, 0)),
                    refresh_expires_in: refresh_expires_in_secs.and_then(|s| {
                        if s >= 0 {
                            Some(std::time::Duration::from_secs(s as u64))
                        } else {
                            None
                        }
                    }),
                }))
            }
            None => Ok(None),
        }
    }
}
