//! Utility functions and helpers
//!
//! Common utilities used throughout BeemFlow.

use crate::config::{BlobConfig, Config};
use crate::storage::SqliteStorage;
use std::sync::Arc;
use tempfile::TempDir;

/// Test environment with isolated temporary directories (test builds only)
///
/// This struct provides a complete, isolated test environment that mirrors production:
/// - Temporary `.beemflow` directory (auto-cleaned on drop)
/// - SQLite database in the temp directory
/// - Config pointing to temp directories
/// - Complete Dependencies object ready to use
///
/// # Example
///
/// ```no_run
/// use beemflow::utils::TestEnvironment;
/// use beemflow::core::OperationRegistry;
///
/// #[tokio::test]
/// async fn my_test() {
///     let env = TestEnvironment::new().await;
///     let registry = OperationRegistry::new(env.deps);
///     // Cleanup happens automatically when env drops
/// }
/// ```
pub struct TestEnvironment {
    /// Temporary directory - kept alive for test duration
    /// When dropped, all temp files are automatically cleaned up
    _temp_dir: TempDir,

    /// Complete dependencies object ready to use in tests
    pub deps: crate::core::Dependencies,
}

impl TestEnvironment {
    /// Create a new isolated test environment
    ///
    /// Sets up:
    /// - Temporary root directory (auto-deleted on drop)
    /// - `.beemflow/` subdirectory
    /// - `.beemflow/flows/` subdirectory
    /// - `.beemflow/beemflow.db` SQLite database
    /// - Config pointing to these locations
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use beemflow::utils::TestEnvironment;
    /// # use beemflow::core::OperationRegistry;
    /// # async fn example() {
    /// let env = TestEnvironment::new().await;
    /// let registry = OperationRegistry::new(env.deps);
    /// // All dependencies available via env.deps.*
    /// # }
    /// ```
    pub async fn new() -> Self {
        Self::with_db_name("beemflow.db").await
    }

    /// Create a test environment with a custom database name
    ///
    /// Useful when you need multiple isolated environments in the same test
    pub async fn with_db_name(db_name: &str) -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let beemflow_dir = temp_dir.path().join(".beemflow");

        // Directories will be auto-created by SqliteStorage, FilesystemBlobStore, and save_flow

        // Create secrets provider for testing
        let secrets_provider: Arc<dyn crate::secrets::SecretsProvider> =
            Arc::new(crate::secrets::EnvSecretsProvider::new());

        // Create config for test environment
        let config = Arc::new(Config {
            flows_dir: Some(beemflow_dir.join("flows").to_str().unwrap().to_string()),
            blob: Some(BlobConfig {
                driver: Some("filesystem".to_string()),
                bucket: None,
                directory: Some(beemflow_dir.join("files").to_str().unwrap().to_string()),
            }),
            ..Default::default()
        });

        let storage = Arc::new(
            SqliteStorage::new(beemflow_dir.join(db_name).to_str().unwrap())
                .await
                .expect("Failed to create SQLite storage"),
        );

        // Create registry manager
        let registry_manager = Arc::new(crate::registry::RegistryManager::standard(
            None,
            secrets_provider.clone(),
        ));

        // Create adapter registry with lazy loading support
        let adapters = Arc::new(crate::adapter::AdapterRegistry::new(
            registry_manager.clone(),
        ));

        // Register core adapters
        adapters.register(Arc::new(crate::adapter::CoreAdapter::new()));
        adapters.register(Arc::new(crate::adapter::HttpAdapter::new(
            crate::constants::HTTP_ADAPTER_ID.to_string(),
            None,
        )));

        // Create and register MCP adapter
        let mcp_adapter = Arc::new(crate::adapter::McpAdapter::new(secrets_provider.clone()));
        adapters.register(mcp_adapter.clone());

        // Load tools and MCP servers from default registry
        crate::engine::Engine::load_default_registry_tools(
            &adapters,
            &mcp_adapter,
            &secrets_provider,
        )
        .await;

        // Create registry manager for shared use
        let registry_manager = Arc::new(crate::registry::RegistryManager::standard(
            None,
            secrets_provider.clone(),
        ));

        // Create OAuth client manager with test redirect URI
        let oauth_client =
            crate::auth::create_test_oauth_client(storage.clone(), secrets_provider.clone());

        // Create engine with test environment config and storage
        let engine = Arc::new(crate::engine::Engine::new(
            adapters,
            mcp_adapter,
            Arc::new(crate::dsl::Templater::new()),
            storage.clone(),
            secrets_provider.clone(),
            config.clone(),
            oauth_client.clone(),
            1000, // max_concurrent_tasks
        ));

        let deps = crate::core::Dependencies {
            storage,
            engine: engine.clone(),
            registry_manager,
            config,
            oauth_client,
            cron_manager: None,
            flow_locks: Arc::new(dashmap::DashMap::new()),
        };

        TestEnvironment {
            _temp_dir: temp_dir,
            deps,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_environment_creates_structure() {
        let env = TestEnvironment::new().await;

        // Verify storage is functional
        env.deps
            .storage
            .deploy_flow_version("test_flow", "1.0.0", "content")
            .await
            .expect("Should be able to write to database");

        let content = env
            .deps
            .storage
            .get_flow_version_content("test_flow", "1.0.0")
            .await
            .expect("Should be able to read from database");

        assert_eq!(content, Some("content".to_string()));
    }
}
