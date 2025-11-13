//! Core operations module using attribute macros
//!
//! This module contains all BeemFlow operations organized by group.
//! Each operation uses #[operation] and #[operation_group] macros for metadata.

pub mod flows;
pub mod mcp;
pub mod runs;
pub mod system;
pub mod tools;

// Operation groups are available as modules
// (not re-exported to avoid namespace pollution)

use crate::config::Config;
use crate::engine::Engine;
use crate::registry::RegistryManager;
use crate::storage::Storage;
use crate::{BeemFlowError, Result};
use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Dependencies that operations need access to
#[derive(Clone)]
pub struct Dependencies {
    pub storage: Arc<dyn Storage>,
    pub engine: Arc<Engine>,
    pub registry_manager: Arc<RegistryManager>,
    pub config: Arc<Config>,
    pub oauth_client: Arc<crate::auth::OAuthClientManager>,
    pub cron_manager: Option<Arc<crate::cron::CronManager>>,
    /// Per-flow locks to prevent concurrent operations on the same flow.
    /// Prevents TOCTOU bugs in deploy/enable/rollback/disable operations.
    pub flow_locks: Arc<DashMap<String, Arc<Mutex<()>>>>,
}

/// Metadata for an operation (HTTP routes, CLI patterns, etc.)
#[derive(Debug, Clone)]
pub struct OperationMetadata {
    pub name: &'static str,
    pub description: &'static str,
    pub group: &'static str,
    pub http_method: Option<&'static str>,
    pub http_path: Option<&'static str>,
    pub cli_pattern: Option<&'static str>,
    pub schema: serde_json::Map<String, serde_json::Value>,
}

/// Trait for providing operation metadata
pub trait HasMetadata {
    fn metadata() -> OperationMetadata;
}

/// Core trait for all operations
#[async_trait]
pub trait Operation: Send + Sync + HasMetadata {
    type Input: for<'de> Deserialize<'de> + Send;
    type Output: Serialize + Send;

    async fn execute(&self, input: Self::Input) -> Result<Self::Output>;
}

/// Registry of all operations with dependency injection
pub struct OperationRegistry {
    operations: HashMap<String, Box<dyn OperationExecutor>>,
    metadata: HashMap<String, OperationMetadata>,
    dependencies: Arc<Dependencies>,
}

#[async_trait]
trait OperationExecutor: Send + Sync {
    async fn execute_json(&self, input: Value) -> Result<Value>;
}

impl OperationRegistry {
    pub fn new(dependencies: Dependencies) -> Self {
        // Arc Dependencies once for sharing with all operations
        // Note: Dependencies already contains Arc'd fields, so this is cheap to clone
        let deps = Arc::new(dependencies);

        let mut registry = Self {
            operations: HashMap::new(),
            metadata: HashMap::new(),
            dependencies: deps.clone(),
        };

        // Auto-register all operations by group
        // The macro-generated register_all functions expect Arc<Dependencies>
        [
            flows::flows::register_all,
            runs::runs::register_all,
            tools::tools::register_all,
            mcp::mcp::register_all,
            system::system::register_all,
        ]
        .into_iter()
        .for_each(|register_fn| register_fn(&mut registry, deps.clone()));

        registry
    }

    fn register<Op: Operation + 'static>(&mut self, op: Op, name: &str) {
        // Store metadata
        self.metadata.insert(name.to_string(), Op::metadata());

        // Store operation executor
        self.operations
            .insert(name.to_string(), Box::new(OperationWrapper(op)));
    }

    pub async fn execute(&self, name: &str, input: Value) -> Result<Value> {
        let op = self
            .operations
            .get(name)
            .ok_or_else(|| BeemFlowError::config(format!("Operation not found: {}", name)))?;

        op.execute_json(input).await
    }

    pub fn get_dependencies(&self) -> Arc<Dependencies> {
        self.dependencies.clone()
    }

    /// Get all operation metadata for building interfaces
    pub fn get_all_metadata(&self) -> &HashMap<String, OperationMetadata> {
        &self.metadata
    }

    /// Get metadata for a specific operation
    pub fn get_metadata(&self, name: &str) -> Option<&OperationMetadata> {
        self.metadata.get(name)
    }
}

// Operation metadata is derived from the macro-generated constants

struct OperationWrapper<Op>(Op);

#[async_trait]
impl<Op: Operation + 'static> OperationExecutor for OperationWrapper<Op> {
    async fn execute_json(&self, input: Value) -> Result<Value> {
        let typed_input: Op::Input = serde_json::from_value(input)?;
        let output = self.0.execute(typed_input).await?;
        Ok(serde_json::to_value(output)?)
    }
}

// Helper functions for common error patterns
fn not_found(entity: &str, name: &str) -> BeemFlowError {
    BeemFlowError::not_found(entity, name)
}

fn type_mismatch(name: &str, expected_type: &str, actual_type: &str) -> BeemFlowError {
    BeemFlowError::validation(format!(
        "Entry '{}' is not a {}, found {}",
        name, expected_type, actual_type
    ))
}

// Helper function for common search filtering
fn filter_by_query<'a, I>(
    entries: I,
    entry_type: &'a str,
    query: &'a Option<String>,
) -> Vec<crate::registry::RegistryEntry>
where
    I: Iterator<Item = crate::registry::RegistryEntry>,
{
    entries
        .filter(move |e| e.entry_type == entry_type)
        .filter(|e| {
            query.as_ref().is_none_or(|q| {
                let q_lower = q.to_lowercase();
                e.name.to_lowercase().contains(&q_lower)
                    || e.description
                        .as_ref()
                        .is_some_and(|d| d.to_lowercase().contains(&q_lower))
            })
        })
        .collect()
}

// Helper function for loading flows from name or file
async fn load_flow_from_config(
    config: &Config,
    name: Option<&str>,
    file: Option<&str>,
) -> Result<crate::model::Flow> {
    use crate::dsl::{parse_file, parse_string};
    match (file, name) {
        (Some(f), _) => parse_file(f, None),
        (None, Some(n)) => {
            let flows_dir = crate::config::get_flows_dir(config);
            let content = crate::storage::flows::get_flow(&flows_dir, n)
                .await?
                .ok_or_else(|| not_found("Flow", n))?;
            parse_string(&content, None)
        }
        _ => Err(BeemFlowError::validation(
            "Either name or file must be provided",
        )),
    }
}

/// Create Dependencies with properly configured engine and shared storage
///
/// This centralizes engine setup logic that was previously duplicated across
/// CLI, HTTP, and MCP interfaces. All presentation layers should use this
/// function to ensure consistent dependency configuration.
pub async fn create_dependencies(config: &Config) -> Result<Dependencies> {
    // Arc config once at the start - all callers will reuse this Arc
    let config = Arc::new(config.clone());

    // Create storage from config
    let storage = crate::storage::create_storage_from_config(&config.storage).await?;

    // Create secrets provider from config (needed by multiple components)
    let secrets_provider = config.create_secrets_provider();

    // Create registry manager with standard sources (needed by adapter registry)
    let registry_manager = Arc::new(RegistryManager::standard(
        Some(&config),
        secrets_provider.clone(),
    ));

    // Create adapter registry with lazy loading support
    let adapters = Arc::new(crate::adapter::AdapterRegistry::new(
        registry_manager.clone(),
    ));

    // Create remaining engine dependencies
    let templater = Arc::new(crate::dsl::Templater::new());

    // Register core adapters (built-in, not from registry)
    adapters.register(Arc::new(crate::adapter::CoreAdapter::new()));
    adapters.register(Arc::new(crate::adapter::HttpAdapter::new(
        crate::constants::HTTP_ADAPTER_ID.to_string(),
        None, // Generic HTTP adapter for fallback
    )));

    // Create and register MCP adapter
    let mcp_adapter = Arc::new(crate::adapter::McpAdapter::new(secrets_provider.clone()));
    adapters.register(mcp_adapter.clone());

    // Pre-load default tools and MCP servers for better startup performance
    // (Tools will also be lazy-loaded on-demand if not pre-loaded)
    Engine::load_default_registry_tools(&adapters, &mcp_adapter, &secrets_provider).await;

    // Get limits from config
    let limits = config.get_limits();

    // Create OAuth client manager with redirect URI from config
    let oauth_client = Arc::new(crate::auth::OAuthClientManager::new(
        storage.clone(),
        registry_manager.clone(),
        config.oauth_redirect_uri(),
    )?);

    // Create engine with shared storage and secrets provider
    let engine = Arc::new(Engine::new(
        adapters,
        templater,
        storage.clone(),
        secrets_provider.clone(),
        config.clone(),
        oauth_client.clone(),
        limits.max_concurrent_tasks,
    ));

    Ok(Dependencies {
        storage,
        engine,
        registry_manager,
        config,
        oauth_client,
        // Cron manager is None by default
        // Only created in HTTP server mode (flow serve) to prevent duplicate executions
        cron_manager: None,
        flow_locks: Arc::new(DashMap::new()),
    })
}
