//! Storage backends for BeemFlow
//!
//! Provides multiple storage backends with a unified trait interface.
//!
//! The storage layer is split into focused traits following Interface Segregation Principle:
//! - `RunStorage`: Run and step execution tracking
//! - `FlowStorage`: Flow definition management and versioning
//! - `OAuthStorage`: OAuth credentials, providers, clients, and tokens
//! - `StateStorage`: Paused runs and wait tokens for durable execution
//! - `Storage`: Composition trait implementing all of the above

pub mod flows; // Pure functions for filesystem flow operations
pub mod postgres;
pub mod sql_common;
pub mod sqlite;

use crate::{Result, model::*};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// Run storage for tracking workflow executions
#[async_trait]
pub trait RunStorage: Send + Sync {
    // Run methods
    /// Save a run
    async fn save_run(&self, run: &Run) -> Result<()>;

    /// Get a run by ID
    async fn get_run(&self, id: Uuid) -> Result<Option<Run>>;

    /// List runs with pagination
    ///
    /// Parameters:
    /// - limit: Maximum number of runs to return (capped at 10,000)
    /// - offset: Number of runs to skip
    ///
    /// Returns runs ordered by started_at DESC
    async fn list_runs(&self, limit: usize, offset: usize) -> Result<Vec<Run>>;

    /// List runs filtered by flow name and status, ordered by most recent first
    /// This is optimized for finding previous successful runs without loading all data
    async fn list_runs_by_flow_and_status(
        &self,
        flow_name: &str,
        status: RunStatus,
        exclude_id: Option<Uuid>,
        limit: usize,
    ) -> Result<Vec<Run>>;

    /// Delete a run and its steps
    async fn delete_run(&self, id: Uuid) -> Result<()>;

    /// Try to insert a run atomically
    /// Returns true if inserted, false if run already exists (based on ID)
    async fn try_insert_run(&self, run: &Run) -> Result<bool>;

    // Step methods
    /// Save a step execution
    async fn save_step(&self, step: &StepRun) -> Result<()>;

    /// Get steps for a run
    async fn get_steps(&self, run_id: Uuid) -> Result<Vec<StepRun>>;
}

/// State storage for durable execution (paused runs, wait tokens)
#[async_trait]
pub trait StateStorage: Send + Sync {
    // Wait/timeout methods
    /// Register a wait token with optional wake time
    async fn register_wait(&self, token: Uuid, wake_at: Option<i64>) -> Result<()>;

    /// Resolve a wait token (returns run if found)
    async fn resolve_wait(&self, token: Uuid) -> Result<Option<Run>>;

    // Paused run methods
    /// Save a paused run (for await_event)
    async fn save_paused_run(
        &self,
        token: &str,
        source: &str,
        data: serde_json::Value,
    ) -> Result<()>;

    /// Load all paused runs
    async fn load_paused_runs(&self) -> Result<HashMap<String, serde_json::Value>>;

    /// Find paused runs by source (for webhook processing)
    /// Returns list of (token, data) tuples
    async fn find_paused_runs_by_source(
        &self,
        source: &str,
    ) -> Result<Vec<(String, serde_json::Value)>>;

    /// Delete a paused run
    async fn delete_paused_run(&self, token: &str) -> Result<()>;

    /// Atomically fetch and delete a paused run
    /// Returns None if not found, preventing double-resume
    async fn fetch_and_delete_paused_run(&self, token: &str) -> Result<Option<serde_json::Value>>;
}

/// Flow versioning and deployment storage (database-backed)
///
/// This trait handles production flow deployments and version history.
/// For draft flows, use the pure functions in storage::flows instead.
#[async_trait]
pub trait FlowStorage: Send + Sync {
    /// Deploy a flow version (creates immutable snapshot)
    async fn deploy_flow_version(
        &self,
        flow_name: &str,
        version: &str,
        content: &str,
    ) -> Result<()>;

    /// Set which version is currently deployed for a flow
    async fn set_deployed_version(&self, flow_name: &str, version: &str) -> Result<()>;

    /// Get the currently deployed version for a flow
    async fn get_deployed_version(&self, flow_name: &str) -> Result<Option<String>>;

    /// Get the content of a specific deployed version
    async fn get_flow_version_content(
        &self,
        flow_name: &str,
        version: &str,
    ) -> Result<Option<String>>;

    /// List all deployed versions for a flow
    async fn list_flow_versions(&self, flow_name: &str) -> Result<Vec<FlowSnapshot>>;

    /// Get the most recently deployed version from history (for enable)
    async fn get_latest_deployed_version_from_history(
        &self,
        flow_name: &str,
    ) -> Result<Option<String>>;

    /// Remove deployed version pointer (for disable)
    async fn unset_deployed_version(&self, flow_name: &str) -> Result<()>;

    /// List all currently deployed flows with their content
    ///
    /// Returns (flow_name, content) tuples for all flows with active deployment.
    /// This is efficient as it performs a single JOIN query instead of N+1 queries.
    /// Used by webhook handlers to find flows to trigger.
    async fn list_all_deployed_flows(&self) -> Result<Vec<(String, String)>>;

    /// Find deployed flow names by webhook topic (efficient lookup for webhook routing)
    ///
    /// Returns only flow names (not content) for flows registered to the given topic.
    /// This is more efficient when you'll load flows individually using engine.start().
    ///
    /// # Performance
    /// Uses flow_triggers index for O(log N) lookup, scalable to 1000+ flows.
    ///
    /// # Example
    /// ```ignore
    /// let flow_names = storage.find_flow_names_by_topic("slack.message.received").await?;
    /// for name in flow_names {
    ///     engine.start(&name, event, false).await?;
    /// }
    /// ```
    async fn find_flow_names_by_topic(&self, topic: &str) -> Result<Vec<String>>;

    /// Get content for multiple deployed flows by name (batch query).
    ///
    /// More efficient than N individual queries. Only returns flows that
    /// are currently deployed (have entry in deployed_flows table).
    ///
    /// # Performance
    ///
    /// Single JOIN query instead of N queries. For 10 flows:
    /// - N queries: 10 round trips
    /// - Batch query: 1 round trip
    ///
    /// # Example
    ///
    /// ```ignore
    /// let flow_names = storage.find_flow_names_by_topic("schedule.cron").await?;
    /// let contents = storage.get_deployed_flows_content(&flow_names).await?;
    /// ```
    async fn get_deployed_flows_content(
        &self,
        flow_names: &[String],
    ) -> Result<Vec<(String, String)>>;
}

/// OAuth storage for credentials, providers, clients, and tokens
#[async_trait]
pub trait OAuthStorage: Send + Sync {
    // OAuth credential methods
    /// Save OAuth credential
    async fn save_oauth_credential(&self, credential: &OAuthCredential) -> Result<()>;

    /// Get OAuth credential
    async fn get_oauth_credential(
        &self,
        provider: &str,
        integration: &str,
    ) -> Result<Option<OAuthCredential>>;

    /// List OAuth credentials
    async fn list_oauth_credentials(&self) -> Result<Vec<OAuthCredential>>;

    /// Delete OAuth credential by ID
    async fn delete_oauth_credential(&self, id: &str) -> Result<()>;

    /// Refresh OAuth credential token
    async fn refresh_oauth_credential(
        &self,
        id: &str,
        new_token: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()>;

    // OAuth provider methods
    /// Save OAuth provider
    async fn save_oauth_provider(&self, provider: &OAuthProvider) -> Result<()>;

    /// Get OAuth provider by ID
    async fn get_oauth_provider(&self, id: &str) -> Result<Option<OAuthProvider>>;

    /// List all OAuth providers
    async fn list_oauth_providers(&self) -> Result<Vec<OAuthProvider>>;

    /// Delete OAuth provider
    async fn delete_oauth_provider(&self, id: &str) -> Result<()>;

    // OAuth client methods (for dynamic client registration)
    /// Save OAuth client
    async fn save_oauth_client(&self, client: &OAuthClient) -> Result<()>;

    /// Get OAuth client by ID
    async fn get_oauth_client(&self, id: &str) -> Result<Option<OAuthClient>>;

    /// List all OAuth clients
    async fn list_oauth_clients(&self) -> Result<Vec<OAuthClient>>;

    /// Delete OAuth client
    async fn delete_oauth_client(&self, id: &str) -> Result<()>;

    // OAuth token methods (for token storage)
    /// Save OAuth token
    async fn save_oauth_token(&self, token: &OAuthToken) -> Result<()>;

    /// Get OAuth token by authorization code
    async fn get_oauth_token_by_code(&self, code: &str) -> Result<Option<OAuthToken>>;

    /// Get OAuth token by access token
    async fn get_oauth_token_by_access(&self, access: &str) -> Result<Option<OAuthToken>>;

    /// Get OAuth token by refresh token
    async fn get_oauth_token_by_refresh(&self, refresh: &str) -> Result<Option<OAuthToken>>;

    /// Delete OAuth token by authorization code
    async fn delete_oauth_token_by_code(&self, code: &str) -> Result<()>;

    /// Delete OAuth token by access token
    async fn delete_oauth_token_by_access(&self, access: &str) -> Result<()>;

    /// Delete OAuth token by refresh token
    async fn delete_oauth_token_by_refresh(&self, refresh: &str) -> Result<()>;
}

/// Complete storage trait combining all focused storage traits
///
/// This trait provides the full storage interface by composing all focused traits.
/// Implementations can implement each focused trait separately for better modularity.
pub trait Storage: RunStorage + StateStorage + FlowStorage + OAuthStorage {}

/// Blanket implementation: any type implementing all focused traits also implements Storage
impl<T> Storage for T where T: RunStorage + StateStorage + FlowStorage + OAuthStorage {}

/// Flow snapshot represents a deployed flow version
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FlowSnapshot {
    pub flow_name: String,
    pub version: String,
    pub deployed_at: DateTime<Utc>,
    pub is_live: bool,
}

pub use postgres::PostgresStorage;
pub use sqlite::SqliteStorage;

/// Create a storage backend from configuration
pub async fn create_storage_from_config(
    config: &crate::config::StorageConfig,
) -> crate::Result<Arc<dyn Storage>> {
    match config.driver.as_str() {
        "sqlite" => Ok(Arc::new(SqliteStorage::new(&config.dsn).await?)),
        "postgres" => Ok(Arc::new(PostgresStorage::new(&config.dsn).await?)),
        _ => Err(crate::BeemFlowError::config(format!(
            "Unknown storage driver: {}. Supported: sqlite, postgres",
            config.driver
        ))),
    }
}

#[cfg(test)]
mod postgres_test;
#[cfg(test)]
mod sqlite_test;
#[cfg(test)]
mod storage_test;
