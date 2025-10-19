//! Tool and MCP server registry
//!
//! Manages tool manifests and MCP server configurations.

pub mod default;
pub mod local;
pub mod manager;
pub mod remote;
pub mod smithery;

use crate::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub use default::DefaultRegistry;
pub use local::LocalRegistry;
pub use manager::RegistryManager;
pub use remote::RemoteRegistry;
pub use smithery::SmitheryRegistry;

/// OAuth scope with description
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeEntry {
    /// Scope identifier (e.g. "https://www.googleapis.com/auth/spreadsheets")
    pub scope: String,

    /// Human-readable description of what this scope grants
    pub description: String,
}

impl ScopeEntry {
    /// Extract just the scope strings from a slice of ScopeEntry
    pub fn to_scope_strings(entries: &[ScopeEntry]) -> Vec<String> {
        entries.iter().map(|e| e.scope.clone()).collect()
    }
}

/// Registry entry for tools and MCP servers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    /// Entry type (tool, mcp_server, oauth_provider)
    #[serde(rename = "type")]
    pub entry_type: String,

    /// Entry name
    pub name: String,

    /// Display name (for oauth_provider)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Icon emoji (for oauth_provider)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,

    /// Description (optional for oauth_provider)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Kind (task, resource, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,

    /// Version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Registry source
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,

    /// Parameters schema
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<HashMap<String, Value>>,

    /// HTTP endpoint (for tools)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// HTTP method (for tools)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// HTTP headers (for tools)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,

    /// MCP command (for mcp_server)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,

    /// MCP args (for mcp_server)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,

    /// MCP env (for mcp_server)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<HashMap<String, String>>,

    /// Transport type (for mcp_server)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,

    /// Port (for mcp_server)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    /// OAuth client ID (for oauth_provider)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    /// OAuth client secret (for oauth_provider)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,

    /// OAuth auth URL (for oauth_provider)
    #[serde(
        skip_serializing_if = "Option::is_none",
        alias = "authUrl",
        alias = "authorization_url"
    )]
    pub auth_url: Option<String>,

    /// OAuth token URL (for oauth_provider)
    #[serde(skip_serializing_if = "Option::is_none", alias = "tokenUrl")]
    pub token_url: Option<String>,

    /// OAuth scopes (for oauth_provider)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<ScopeEntry>>,

    /// OAuth authorization parameters (for oauth_provider)
    /// Additional query parameters to append to the authorization URL
    /// Example: {"prompt": "select_account", "access_type": "offline"}
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_params: Option<HashMap<String, String>>,

    /// Webhook configuration (for oauth_provider)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook: Option<WebhookConfig>,
}

impl RegistryEntry {
    /// Extract scope strings from the registry entry
    ///
    /// Converts `Option<Vec<ScopeEntry>>` to `Option<Vec<String>>` by extracting
    /// just the scope identifiers without descriptions.
    pub fn scope_strings(&self) -> Option<Vec<String>> {
        self.scopes
            .as_ref()
            .map(|scopes| ScopeEntry::to_scope_strings(scopes))
    }
}

/// Webhook configuration for providers
///
/// Webhooks are registered at `/webhooks/{provider}` where provider matches
/// the OAuth provider name (without the `oauth_` prefix).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<WebhookSignatureConfig>,
    pub events: Vec<WebhookEvent>,
}

/// Webhook signature verification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSignatureConfig {
    pub header: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_header: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age: Option<i64>,
}

/// Webhook event configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub topic: String,
    #[serde(rename = "match")]
    pub match_: HashMap<String, Value>,
    pub extract: HashMap<String, String>,
}

/// Registry manager for loading and managing registries
pub struct Registry {
    entries: HashMap<String, RegistryEntry>,
}

impl Registry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Load registry from JSON file
    pub fn load_from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let entries: Vec<RegistryEntry> = serde_json::from_str(&content)?;

        let mut registry = Self::new();
        for entry in entries {
            registry.entries.insert(entry.name.clone(), entry);
        }

        Ok(registry)
    }

    /// List all entries
    pub fn list_all(&self) -> Vec<RegistryEntry> {
        self.entries.values().cloned().collect()
    }

    /// Get an entry by name
    pub fn get(&self, name: &str) -> Option<&RegistryEntry> {
        self.entries.get(name)
    }

    /// Add an entry
    pub fn add(&mut self, entry: RegistryEntry) {
        self.entries.insert(entry.name.clone(), entry);
    }

    /// Remove an entry
    pub fn remove(&mut self, name: &str) -> Option<RegistryEntry> {
        self.entries.remove(name)
    }

    /// Save registry to JSON file
    pub fn save_to_file(&self, path: &str) -> Result<()> {
        let entries: Vec<&RegistryEntry> = self.entries.values().collect();
        let content = serde_json::to_string_pretty(&entries)?;

        // Create parent directory if it doesn't exist
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(path, content)?;
        Ok(())
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod registry_test;
