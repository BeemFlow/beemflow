//! Registry manager
//!
//! Coordinates multiple registries with priority order.

use super::*;
use crate::{Result, config::Config};

/// Registry manager that coordinates multiple registries
pub struct RegistryManager {
    registries: Vec<Box<dyn RegistrySource>>,
    secrets_provider: std::sync::Arc<dyn crate::secrets::SecretsProvider>,
}

/// Trait for registry sources
#[async_trait::async_trait]
pub trait RegistrySource: Send + Sync {
    async fn list_servers(&self) -> Result<Vec<RegistryEntry>>;
    async fn get_server(&self, name: &str) -> Result<Option<RegistryEntry>>;
}

#[async_trait::async_trait]
impl RegistrySource for DefaultRegistry {
    async fn list_servers(&self) -> Result<Vec<RegistryEntry>> {
        self.list_servers().await
    }

    async fn get_server(&self, name: &str) -> Result<Option<RegistryEntry>> {
        self.get_server(name).await
    }
}

#[async_trait::async_trait]
impl RegistrySource for LocalRegistry {
    async fn list_servers(&self) -> Result<Vec<RegistryEntry>> {
        self.list_servers().await
    }

    async fn get_server(&self, name: &str) -> Result<Option<RegistryEntry>> {
        self.get_server(name).await
    }
}

#[async_trait::async_trait]
impl RegistrySource for RemoteRegistry {
    async fn list_servers(&self) -> Result<Vec<RegistryEntry>> {
        self.list_servers().await
    }

    async fn get_server(&self, name: &str) -> Result<Option<RegistryEntry>> {
        self.get_server(name).await
    }
}

#[async_trait::async_trait]
impl RegistrySource for SmitheryRegistry {
    async fn list_servers(&self) -> Result<Vec<RegistryEntry>> {
        self.list_servers().await
    }

    async fn get_server(&self, name: &str) -> Result<Option<RegistryEntry>> {
        self.get_server(name).await
    }
}

impl RegistryManager {
    /// Create a new registry manager with given sources (in priority order)
    pub fn new(
        registries: Vec<Box<dyn RegistrySource>>,
        secrets_provider: std::sync::Arc<dyn crate::secrets::SecretsProvider>,
    ) -> Self {
        Self {
            registries,
            secrets_provider,
        }
    }

    /// Create standard manager with all registry types
    /// Priority: local #1 → remote registries #2 → default #3
    ///
    /// Users can add custom remote registries via config (federated model):
    /// ```json
    /// {
    ///   "registries": [
    ///     {"type": "remote", "url": "https://your-domain.com/registry.json", "name": "custom"},
    ///     {"type": "remote", "url": "https://hub.beemflow.com/registry.json", "name": "hub"}
    ///   ]
    /// }
    /// ```
    pub fn standard(
        config: Option<&Config>,
        secrets_provider: std::sync::Arc<dyn crate::secrets::SecretsProvider>,
    ) -> Self {
        let mut registries: Vec<Box<dyn RegistrySource>> = Vec::new();

        // 1. Local registry (highest priority) - user's custom tools
        let local_path = config
            .and_then(|c| c.registries.as_ref())
            .and_then(|regs| regs.iter().find(|r| r.registry_type == "local"))
            .and_then(|r| r.path.as_ref())
            .map(|p| p.as_str())
            .unwrap_or("");

        registries.push(Box::new(LocalRegistry::new(local_path)));

        // 2. Remote registries from config (federated model)
        // Allows users to add their own registries or community registries
        if let Some(cfg) = config
            && let Some(ref regs) = cfg.registries
        {
            for reg in regs {
                if reg.registry_type == "remote"
                    && let Some(ref url) = reg.url
                {
                    let name = reg.name.as_deref().unwrap_or("remote");
                    registries.push(Box::new(RemoteRegistry::new(url, name)));
                }
            }
        }

        // 3. Default registry (built-in, lowest priority)
        registries.push(Box::new(DefaultRegistry::new()));

        Self {
            registries,
            secrets_provider,
        }
    }

    /// List all servers from all registries (first wins for duplicates)
    pub async fn list_all_servers(&self) -> Result<Vec<RegistryEntry>> {
        let mut all_entries = Vec::new();
        let mut seen_names = std::collections::HashSet::new();

        // Iterate in priority order
        for registry in &self.registries {
            match registry.list_servers().await {
                Ok(entries) => {
                    for entry in entries {
                        // Only add if not already seen (first registry wins)
                        if seen_names.insert(entry.name.clone()) {
                            all_entries.push(entry);
                        }
                    }
                }
                Err(e) => {
                    // Only log at debug level for network errors (registries may be unavailable)
                    if matches!(e, crate::BeemFlowError::Network(_)) {
                        tracing::debug!("Skipping unavailable remote registry: {}", e);
                    } else {
                        tracing::warn!("Failed to load registry: {}", e);
                    }
                    // Continue with other registries
                }
            }
        }

        Ok(all_entries)
    }

    /// Get a specific server by name (first matching registry wins)
    pub async fn get_server(&self, name: &str) -> Result<Option<RegistryEntry>> {
        for registry in &self.registries {
            match registry.get_server(name).await {
                Ok(Some(entry)) => return Ok(Some(entry)),
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!("Error querying registry: {}", e);
                    continue;
                }
            }
        }

        Ok(None)
    }

    /// List OAuth provider definitions from all registries
    ///
    /// Returns OAuth provider entries with environment variables expanded.
    /// These define how to authenticate (client_id, auth_url, etc.)
    /// but don't contain user credentials (which are stored in Storage).
    pub async fn list_oauth_providers(&self) -> Result<Vec<RegistryEntry>> {
        let all_servers = self.list_all_servers().await?;

        // Filter and expand OAuth providers
        let mut providers = Vec::new();
        for entry in all_servers {
            if entry.entry_type == "oauth_provider"
                && let Some(expanded) =
                    super::default::expand_oauth_provider_env_vars(entry, &self.secrets_provider)
                        .await
            {
                providers.push(expanded);
            }
        }

        Ok(providers)
    }

    /// Get a specific OAuth provider by name
    ///
    /// Returns the OAuth provider definition with environment variables expanded.
    pub async fn get_oauth_provider(&self, name: &str) -> Result<Option<RegistryEntry>> {
        tracing::debug!("get_oauth_provider called for: {}", name);

        if let Some(entry) = self.get_server(name).await? {
            let has_client_id = entry.client_id.is_some();
            tracing::debug!(
                "Found server entry for '{}': type={}, has_client_id={}",
                name,
                entry.entry_type,
                has_client_id
            );

            if entry.entry_type == "oauth_provider" {
                tracing::debug!("Entry is oauth_provider, expanding env vars for '{}'", name);
                match super::default::expand_oauth_provider_env_vars(entry, &self.secrets_provider)
                    .await
                {
                    Some(expanded) => {
                        let has_expanded_client_id = expanded.client_id.is_some();
                        let has_expanded_client_secret = expanded.client_secret.is_some();
                        tracing::debug!(
                            "After expansion: has_client_id={}, has_client_secret={}",
                            has_expanded_client_id,
                            has_expanded_client_secret
                        );
                        return Ok(Some(expanded));
                    }
                    None => {
                        tracing::debug!("Provider '{}' skipped due to missing env vars", name);
                        return Ok(None);
                    }
                }
            } else {
                tracing::warn!(
                    "Entry '{}' is not an oauth_provider (type={})",
                    name,
                    entry.entry_type
                );
            }
        } else {
            tracing::warn!("No server entry found for '{}'", name);
        }
        Ok(None)
    }

    /// Register a tool from a manifest in the local registry
    pub async fn register_tool_from_manifest(&self, manifest: serde_json::Value) -> Result<()> {
        // Deserialize manifest to RegistryEntry
        let mut entry: RegistryEntry = serde_json::from_value(manifest).map_err(|e| {
            crate::error::BeemFlowError::validation(format!("Invalid tool manifest: {}", e))
        })?;

        // Ensure it's a tool
        if entry.entry_type != "tool" {
            return Err(crate::error::BeemFlowError::validation(format!(
                "Expected type 'tool', got '{}'",
                entry.entry_type
            )));
        }

        // Mark as local registry
        entry.registry = Some("local".to_string());

        // Capture name for logging before moving entry
        let tool_name = entry.name.clone();

        // Use the default local registry path (~/.beemflow/registry.json)
        let local_path = crate::constants::default_local_registry_path();
        let local_registry = LocalRegistry::new(local_path);
        local_registry.upsert_entry(entry).await?;

        tracing::info!("Registered tool: {}", tool_name);
        Ok(())
    }

    /// Register a webhook from a manifest in the local registry
    pub async fn register_webhook_from_manifest(&self, manifest: serde_json::Value) -> Result<()> {
        // Deserialize manifest to RegistryEntry
        let mut entry: RegistryEntry = serde_json::from_value(manifest).map_err(|e| {
            crate::error::BeemFlowError::validation(format!("Invalid webhook manifest: {}", e))
        })?;

        // Ensure it's a webhook
        if entry.entry_type != "webhook" {
            return Err(crate::error::BeemFlowError::validation(format!(
                "Expected type 'webhook', got '{}'",
                entry.entry_type
            )));
        }

        // Validate webhook config is present
        if entry.webhook.is_none() {
            return Err(crate::error::BeemFlowError::validation(
                "Webhook must have 'webhook' configuration".to_string(),
            ));
        }

        // Mark as local registry
        entry.registry = Some("local".to_string());

        // Capture name for logging before moving entry
        let webhook_name = entry.name.clone();

        // Use the default local registry path (~/.beemflow/registry.json)
        let local_path = crate::constants::default_local_registry_path();
        let local_registry = LocalRegistry::new(local_path);
        local_registry.upsert_entry(entry).await?;

        tracing::info!("Registered webhook: {}", webhook_name);
        Ok(())
    }
}
