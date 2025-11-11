//! Adapter system for tool execution
//!
//! Adapters provide a unified interface for executing different types of tools.
//!
//! # ExecutionContext
//!
//! The `ExecutionContext` provides adapters with access to system-level resources
//! like storage, without polluting the tool's input parameters. This enables features like:
//!
//! - **OAuth Token Expansion**: HTTP adapters can look up OAuth credentials from storage
//!   to automatically inject access tokens into API requests
//! - **Future Security Features**: User context, permissions, rate limiting, audit logging
//! - **Multi-Tenancy**: Different users can have isolated OAuth credentials and permissions
//!
//! ## Design Rationale
//!
//! We pass ExecutionContext separately from tool inputs because:
//!
//! 1. **Separation of Concerns**: Tool inputs are user-provided data, while context
//!    contains system-level resources. Mixing them would blur this boundary.
//!
//! 2. **Type Safety**: Context uses proper Rust types (Arc<dyn Storage>) instead of
//!    trying to serialize trait objects into JSON, which is impossible.
//!
//! 3. **Extensibility**: We can add new context fields (user_id, permissions, etc.)
//!    without changing the Adapter trait again - just add fields to ExecutionContext.
//!
//! 4. **Security**: Makes it obvious what resources adapters can access, easier to audit.
//!
//! ## Example: OAuth Token Expansion
//!
//! ```yaml
//! # Registry tool definition
//! name: github.get_user
//! endpoint: https://api.github.com/user
//! headers:
//!   Authorization: $oauth:github:default  # Expanded at runtime!
//! ```
//!
//! The HttpAdapter receives ExecutionContext with Storage, looks up the OAuth
//! credential for "github:default", and replaces the placeholder with the actual
//! access token before making the HTTP request.

pub mod core;
pub mod http;
pub mod mcp;

use crate::Result;
use crate::storage::Storage;
use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// Execution context providing system-level resources to adapters
///
/// This context is passed to adapters during execution, giving them access to
/// system resources like storage without mixing them with user-provided tool inputs.
///
/// # Design Notes
///
/// ## Why a separate context instead of adding to inputs?
///
/// Tool inputs (`HashMap<String, Value>`) are user-provided parameters that get
/// serialized to/from JSON. ExecutionContext contains system resources like storage
/// that cannot be serialized into JSON (trait objects, Arc pointers, etc.).
///
/// Keeping them separate maintains a clean boundary:
/// - **Inputs**: User data (serializable, part of the workflow definition)
/// - **Context**: System resources (non-serializable, provided by the runtime)
///
/// ## Future Extensibility
///
/// This struct is designed to be extended without breaking the Adapter trait:
///
/// ```rust,ignore
/// pub struct ExecutionContext {
///     pub storage: Arc<dyn Storage>,
///
///     // Future additions (no trait changes needed!):
///     pub user_id: Option<String>,          // Who triggered this execution?
///     pub permissions: Arc<Permissions>,    // What can they access?
///     pub rate_limiter: Arc<RateLimiter>,   // Prevent abuse
///     pub audit_log: Arc<AuditLogger>,      // Track all actions
///     pub request_id: String,               // For tracing/debugging
/// }
/// ```
///
/// Adapters that don't need these features can simply ignore them.
///
/// ## Security Considerations
///
/// Having an explicit context makes security audits easier:
/// - Clear what resources each adapter can access
/// - Can add permission checks before execution
/// - Easy to see data flow from storage to adapters
///
/// Example future usage:
/// ```rust,ignore
/// if !ctx.permissions.can_http_request(&url) {
///     return Err("Permission denied");
/// }
/// ctx.audit_log.log(ctx.user_id, "http.request", &url);
/// ```
#[derive(Clone)]
pub struct ExecutionContext {
    /// Storage backend for general data access
    ///
    /// Note: OAuth token retrieval during execution should use oauth_client instead,
    /// which handles automatic token refresh.
    pub storage: Arc<dyn Storage>,

    /// Secrets provider for environment variable and secret access
    ///
    /// Used by HttpAdapter for expanding $env: references in headers and defaults:
    /// - Tool manifest specifies: `Authorization: Bearer $env:API_KEY`
    /// - HttpAdapter calls: `ctx.secrets_provider.get_secret("API_KEY")`
    /// - Secret value is injected into request headers automatically
    pub secrets_provider: Arc<dyn crate::secrets::SecretsProvider>,

    /// OAuth client manager for token management with automatic refresh
    ///
    /// Used by HttpAdapter for OAuth token expansion with automatic refresh:
    /// - Tool manifest specifies: `Authorization: $oauth:github:default`
    /// - HttpAdapter calls: `ctx.oauth_client.get_token("github", "default")`
    /// - Token is automatically refreshed if expired and injected into request headers
    pub oauth_client: Arc<crate::auth::OAuthClientManager>,

    /// User who triggered this execution (for per-user OAuth credentials)
    ///
    /// When a workflow is triggered via authenticated API, this contains the user's ID.
    /// Used to retrieve user-specific OAuth credentials during tool execution.
    pub user_id: Option<String>,

    /// Tenant context for this execution (for multi-tenant isolation)
    ///
    /// When a workflow is triggered via authenticated API, this contains the tenant ID.
    /// Used with user_id to retrieve tenant-scoped OAuth credentials.
    pub tenant_id: Option<String>,
}

impl ExecutionContext {
    /// Create a new execution context with user/tenant information
    pub fn new(
        storage: Arc<dyn Storage>,
        secrets_provider: Arc<dyn crate::secrets::SecretsProvider>,
        oauth_client: Arc<crate::auth::OAuthClientManager>,
        user_id: Option<String>,
        tenant_id: Option<String>,
    ) -> Self {
        Self {
            storage,
            secrets_provider,
            oauth_client,
            user_id,
            tenant_id,
        }
    }
}

/// Tool manifest information
#[derive(Debug, Clone)]
pub struct ToolManifest {
    pub name: String,
    pub description: String,
    pub kind: String,
    pub version: Option<String>,
    pub parameters: HashMap<String, Value>,
    pub endpoint: Option<String>,
    pub method: Option<String>,
    pub headers: Option<HashMap<String, String>>,
}

/// Adapter trait for tool execution
///
/// Adapters provide a unified interface for executing different types of tools
/// (core tools, HTTP APIs, MCP servers, etc.).
///
/// # ExecutionContext Parameter
///
/// All adapters receive an `ExecutionContext` during execution, providing access to
/// system resources like storage. This enables features like OAuth token expansion
/// without mixing system resources with user-provided tool inputs.
///
/// See module-level documentation for detailed rationale and examples.
#[async_trait]
pub trait Adapter: Send + Sync {
    /// Get adapter ID
    fn id(&self) -> &str;

    /// Execute a tool with given inputs and execution context
    ///
    /// # Parameters
    ///
    /// - `inputs`: User-provided tool parameters from the workflow definition
    /// - `ctx`: System resources (storage, future: permissions, rate limits, etc.)
    ///
    /// # Returns
    ///
    /// A HashMap of output values that will be available to subsequent steps via
    /// template expressions like `{{ steps.step_name.output.field }}`.
    async fn execute(
        &self,
        inputs: HashMap<String, Value>,
        ctx: &ExecutionContext,
    ) -> Result<HashMap<String, Value>>;

    /// Get tool manifest (if applicable)
    fn manifest(&self) -> Option<ToolManifest>;

    /// Get self as Any for downcasting
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Registry of adapters - uses DashMap for lock-free concurrent access
///
/// Supports lazy loading of tools from the registry when they are first accessed.
/// This allows dynamically installed tools to work without restarting the engine.
pub struct AdapterRegistry {
    adapters: Arc<DashMap<String, Arc<dyn Adapter>>>,
    registry_manager: Arc<crate::registry::RegistryManager>,
}

impl AdapterRegistry {
    /// Create a new adapter registry with lazy loading support
    ///
    /// When a tool is not found in the adapter registry, it will be automatically
    /// loaded from the registry manager if available. This enables dynamic tool
    /// installation without restarting the engine.
    pub fn new(registry_manager: Arc<crate::registry::RegistryManager>) -> Self {
        Self {
            adapters: Arc::new(DashMap::new()),
            registry_manager,
        }
    }

    /// Register an adapter
    pub fn register(&self, adapter: Arc<dyn Adapter>) {
        self.adapters.insert(adapter.id().to_string(), adapter);
    }

    /// Get a registered adapter by ID (synchronous, no lazy loading)
    ///
    /// This is used internally for built-in adapters (core, mcp, http) during prefix matching.
    /// For dynamically installed tools, use `get_or_load()` instead which supports lazy loading.
    pub(crate) fn get(&self, id: &str) -> Option<Arc<dyn Adapter>> {
        self.adapters.get(id).map(|entry| Arc::clone(&*entry))
    }

    /// Get an adapter by ID, lazy loading from registry if not found
    ///
    /// This method will:
    /// 1. Check if the adapter is already registered
    /// 2. If not, query the registry manager for a tool with this name
    /// 3. Create an HttpAdapter with the tool's manifest and cache it
    /// 4. Return the adapter for immediate use
    ///
    /// This enables dynamic tool installation - tools added via `flow tools install`
    /// are immediately available without restarting the engine.
    pub async fn get_or_load(&self, tool_name: &str) -> Option<Arc<dyn Adapter>> {
        // 1. Check if already registered (exact match)
        if let Some(entry) = self.adapters.get(tool_name) {
            return Some(Arc::clone(&*entry));
        }

        // 2. Try lazy load from registry
        if let Ok(Some(entry)) = self.registry_manager.get_server(tool_name).await {
            // Only load if it's actually a tool (not mcp_server, oauth_provider, etc.)
            if entry.entry_type == "tool" {
                tracing::debug!("Lazy loading tool '{}' from registry", tool_name);

                // Create tool manifest from registry entry
                let manifest = ToolManifest {
                    name: entry.name.clone(),
                    description: entry.description.clone().unwrap_or_default(),
                    kind: entry.kind.unwrap_or_else(|| "task".to_string()),
                    version: entry.version,
                    parameters: entry.parameters.unwrap_or_default(),
                    endpoint: entry.endpoint,
                    method: entry.method,
                    headers: entry.headers,
                };

                // Create HTTP adapter with this manifest
                let adapter = Arc::new(http::HttpAdapter::new(entry.name.clone(), Some(manifest)))
                    as Arc<dyn Adapter>;

                // Cache for future use
                self.adapters.insert(tool_name.to_string(), adapter.clone());

                tracing::info!("Loaded tool '{}' from registry", tool_name);
                return Some(adapter);
            }
        }

        None
    }

    /// Get all adapters
    pub fn all(&self) -> Vec<Arc<dyn Adapter>> {
        self.adapters
            .iter()
            .map(|entry| Arc::clone(&*entry))
            .collect()
    }
}

pub use core::CoreAdapter;
pub use http::HttpAdapter;

pub use mcp::McpAdapter;

#[cfg(test)]
mod adapter_test;
#[cfg(test)]
mod core_test;
#[cfg(test)]
mod mcp_test;
