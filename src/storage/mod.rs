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
    ///
    /// # Multi-organization isolation
    /// Verifies the run belongs to the specified organization. Returns None if the run
    /// exists but belongs to a different organization (don't leak existence).
    async fn get_run(&self, id: Uuid, organization_id: &str) -> Result<Option<Run>>;

    /// List runs with pagination
    ///
    /// # Parameters
    /// - organization_id: Only return runs for this organization
    /// - limit: Maximum number of runs to return (capped at 10,000)
    /// - offset: Number of runs to skip
    ///
    /// # Multi-organization isolation
    /// Only returns runs belonging to the specified organization.
    /// Returns runs ordered by started_at DESC.
    async fn list_runs(
        &self,
        organization_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Run>>;

    /// List runs filtered by flow name and status, ordered by most recent first
    ///
    /// This is optimized for finding previous successful runs without loading all data.
    ///
    /// # Multi-organization isolation
    /// Only searches within the specified organization's runs.
    async fn list_runs_by_flow_and_status(
        &self,
        organization_id: &str,
        flow_name: &str,
        status: RunStatus,
        exclude_id: Option<Uuid>,
        limit: usize,
    ) -> Result<Vec<Run>>;

    /// Delete a run and its steps
    ///
    /// # Multi-organization isolation
    /// Only deletes if the run belongs to the specified organization.
    /// Returns error if run belongs to different organization.
    async fn delete_run(&self, id: Uuid, organization_id: &str) -> Result<()>;

    /// Try to insert a run atomically
    /// Returns true if inserted, false if run already exists (based on ID)
    async fn try_insert_run(&self, run: &Run) -> Result<bool>;

    // Step methods
    /// Save a step execution
    ///
    /// The step's organization_id field is stored for isolation queries.
    async fn save_step(&self, step: &StepRun) -> Result<()>;

    /// Get steps for a run
    ///
    /// # Multi-organization isolation
    /// Verifies steps belong to the specified organization. Returns empty if
    /// the run exists but belongs to a different organization.
    async fn get_steps(&self, run_id: Uuid, organization_id: &str) -> Result<Vec<StepRun>>;
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
        organization_id: &str,
        user_id: &str,
    ) -> Result<()>;

    /// Load all paused runs
    async fn load_paused_runs(&self) -> Result<HashMap<String, serde_json::Value>>;

    /// Find paused runs by source (for webhook processing)
    /// Returns list of (token, data) tuples
    ///
    /// # Multi-organization isolation
    /// Only returns paused runs belonging to the specified organization.
    async fn find_paused_runs_by_source(
        &self,
        source: &str,
        organization_id: &str,
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
///
/// All methods are organization-scoped to ensure proper multi-tenant isolation.
#[async_trait]
pub trait FlowStorage: Send + Sync {
    /// Deploy a flow version (creates immutable snapshot)
    ///
    /// # Multi-organization isolation
    /// Creates version in organization's namespace. Different organizations can have flows
    /// with the same name without conflicts.
    async fn deploy_flow_version(
        &self,
        organization_id: &str,
        flow_name: &str,
        version: &str,
        content: &str,
        deployed_by_user_id: &str, // Audit trail
    ) -> Result<()>;

    /// Set which version is currently deployed for a flow
    ///
    /// # Multi-organization isolation
    /// Only affects the specified organization's deployment.
    async fn set_deployed_version(
        &self,
        organization_id: &str,
        flow_name: &str,
        version: &str,
    ) -> Result<()>;

    /// Get the currently deployed version for a flow
    ///
    /// # Multi-organization isolation
    /// Returns version for the specified organization only.
    async fn get_deployed_version(
        &self,
        organization_id: &str,
        flow_name: &str,
    ) -> Result<Option<String>>;

    /// Get the content of a specific deployed version
    ///
    /// # Multi-organization isolation
    /// Only returns content if version belongs to the specified organization.
    async fn get_flow_version_content(
        &self,
        organization_id: &str,
        flow_name: &str,
        version: &str,
    ) -> Result<Option<String>>;

    /// List all deployed versions for a flow
    ///
    /// # Multi-organization isolation
    /// Returns versions for the specified organization only.
    async fn list_flow_versions(
        &self,
        organization_id: &str,
        flow_name: &str,
    ) -> Result<Vec<FlowSnapshot>>;

    /// Get the most recently deployed version from history (for enable)
    ///
    /// # Multi-organization isolation
    /// Returns latest version for the specified organization only.
    async fn get_latest_deployed_version_from_history(
        &self,
        organization_id: &str,
        flow_name: &str,
    ) -> Result<Option<String>>;

    /// Remove deployed version pointer (for disable)
    ///
    /// # Multi-organization isolation
    /// Only removes deployment pointer for the specified organization.
    async fn unset_deployed_version(&self, organization_id: &str, flow_name: &str) -> Result<()>;

    /// List all currently deployed flows with their content for an organization
    ///
    /// Returns (flow_name, content) tuples for all flows with active deployment
    /// in the specified organization.
    ///
    /// # Multi-organization isolation
    /// Only returns flows belonging to the specified organization.
    async fn list_all_deployed_flows(&self, organization_id: &str)
    -> Result<Vec<(String, String)>>;

    /// Find deployed flow names by webhook topic for an organization
    ///
    /// Returns only flow names (not content) for flows in the specified organization
    /// that are registered to the given topic.
    ///
    /// # Performance
    /// Uses flow_triggers index for O(log N) lookup, scalable to 1000+ flows.
    ///
    /// # Multi-organization isolation
    /// Only searches within the specified organization's flows.
    async fn find_flow_names_by_topic(
        &self,
        organization_id: &str,
        topic: &str,
    ) -> Result<Vec<String>>;

    /// Get content for multiple deployed flows by name (batch query)
    ///
    /// More efficient than N individual queries. Only returns flows that
    /// are currently deployed and belong to the specified organization.
    ///
    /// # Multi-organization isolation
    /// Only returns flows belonging to the specified organization.
    async fn get_deployed_flows_content(
        &self,
        organization_id: &str,
        flow_names: &[String],
    ) -> Result<Vec<(String, String)>>;

    /// Get the user_id of who deployed the currently active version of a flow
    ///
    /// Returns None if:
    /// - Flow is not deployed
    /// - Deployed version has no deployer tracked (legacy deployments)
    ///
    /// This is used to determine which user's OAuth credentials to use for
    /// automated flow executions (cron, webhooks).
    ///
    /// # Multi-organization isolation
    /// Only queries within the specified organization.
    ///
    /// # Performance
    /// Single indexed query joining deployed_flows → flow_versions
    async fn get_deployed_by(
        &self,
        organization_id: &str,
        flow_name: &str,
    ) -> Result<Option<String>>;
}

/// OAuth storage for credentials, providers, clients, and tokens
#[async_trait]
pub trait OAuthStorage: Send + Sync {
    // OAuth credential methods
    /// Save OAuth credential
    async fn save_oauth_credential(&self, credential: &OAuthCredential) -> Result<()>;

    /// Get OAuth credential for a specific user
    async fn get_oauth_credential(
        &self,
        provider: &str,
        integration: &str,
        user_id: &str,
        organization_id: &str,
    ) -> Result<Option<OAuthCredential>>;

    /// List OAuth credentials for a specific user
    async fn list_oauth_credentials(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<Vec<OAuthCredential>>;

    /// Get OAuth credential by ID
    ///
    /// # Security
    /// Only returns credential if it belongs to the specified organization
    async fn get_oauth_credential_by_id(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<OAuthCredential>>;

    /// Delete OAuth credential by ID
    ///
    /// # Security
    /// Enforces organization isolation - only deletes if credential belongs to specified organization
    async fn delete_oauth_credential(&self, id: &str, organization_id: &str) -> Result<()>;

    /// Refresh OAuth credential token
    ///
    /// # Multi-organization isolation
    /// Only refreshes if credential belongs to the specified organization.
    async fn refresh_oauth_credential(
        &self,
        id: &str,
        organization_id: &str,
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

/// Authentication storage for users, organizations, and sessions
///
/// Provides multi-organization authentication and authorization storage.
#[async_trait]
pub trait AuthStorage: Send + Sync {
    // User methods
    /// Create a new user
    async fn create_user(&self, user: &crate::auth::User) -> Result<()>;

    /// Get user by ID
    async fn get_user(&self, id: &str) -> Result<Option<crate::auth::User>>;

    /// Get user by email
    async fn get_user_by_email(&self, email: &str) -> Result<Option<crate::auth::User>>;

    /// Update user
    async fn update_user(&self, user: &crate::auth::User) -> Result<()>;

    /// Update user's last login timestamp
    async fn update_user_last_login(&self, user_id: &str) -> Result<()>;

    // Organization methods
    /// Create a new organization
    async fn create_organization(&self, organization: &crate::auth::Organization) -> Result<()>;

    /// Get organization by ID
    async fn get_organization(&self, id: &str) -> Result<Option<crate::auth::Organization>>;

    /// Get organization by slug
    async fn get_organization_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<crate::auth::Organization>>;

    /// Update organization
    async fn update_organization(&self, organization: &crate::auth::Organization) -> Result<()>;

    /// List all active (non-disabled) organizations
    async fn list_active_organizations(&self) -> Result<Vec<crate::auth::Organization>>;

    // Organization membership methods
    /// Create a new organization member (user-organization relationship)
    async fn create_organization_member(
        &self,
        member: &crate::auth::OrganizationMember,
    ) -> Result<()>;

    /// Get organization member
    async fn get_organization_member(
        &self,
        organization_id: &str,
        user_id: &str,
    ) -> Result<Option<crate::auth::OrganizationMember>>;

    /// List all organizations for a user with their roles
    async fn list_user_organizations(
        &self,
        user_id: &str,
    ) -> Result<Vec<(crate::auth::Organization, crate::auth::Role)>>;

    /// List all members of an organization with their user info
    async fn list_organization_members(
        &self,
        organization_id: &str,
    ) -> Result<Vec<(crate::auth::User, crate::auth::Role)>>;

    /// Update member's role
    async fn update_member_role(
        &self,
        organization_id: &str,
        user_id: &str,
        role: crate::auth::Role,
    ) -> Result<()>;

    /// Remove member from organization
    async fn remove_organization_member(&self, organization_id: &str, user_id: &str) -> Result<()>;

    // Refresh token methods
    /// Create a new refresh token
    async fn create_refresh_token(&self, token: &crate::auth::RefreshToken) -> Result<()>;

    /// Get refresh token by hash
    async fn get_refresh_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<crate::auth::RefreshToken>>;

    /// Revoke a specific refresh token
    async fn revoke_refresh_token(&self, token_hash: &str) -> Result<()>;

    /// Revoke all refresh tokens for a user
    async fn revoke_all_user_tokens(&self, user_id: &str) -> Result<()>;

    /// Update refresh token's last used timestamp
    async fn update_refresh_token_last_used(&self, token_hash: &str) -> Result<()>;
}
/// Complete storage trait combining all focused storage traits
///
/// This trait provides the full storage interface by composing all focused traits.
/// Implementations can implement each focused trait separately for better modularity.
pub trait Storage: RunStorage + StateStorage + FlowStorage + OAuthStorage + AuthStorage {}

/// Blanket implementation: any type implementing all focused traits also implements Storage
impl<T> Storage for T where T: RunStorage + StateStorage + FlowStorage + OAuthStorage + AuthStorage {}

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
