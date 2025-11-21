//! Configuration management for BeemFlow
//!
//! Loads and manages BeemFlow configuration from flow.config.json

use crate::{BeemFlowError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Complete BeemFlow configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    /// Storage configuration (required)
    pub storage: StorageConfig,

    /// Blob storage configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<BlobConfig>,

    /// Event bus configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<EventConfig>,

    /// Secrets provider configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<SecretsConfig>,

    /// Registry configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registries: Option<Vec<RegistryConfig>>,

    /// HTTP server configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpConfig>,

    /// Logging configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<LogConfig>,

    /// Flows directory override
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flows_dir: Option<String>,

    /// MCP servers configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_servers: Option<HashMap<String, McpServerConfig>>,

    /// Tracing configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracing: Option<TracingConfig>,

    /// OAuth configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuthConfig>,

    /// MCP configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpConfig>,

    /// Runtime limits configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<LimitsConfig>,
}

/// Storage backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Driver name (sqlite, postgres, memory)
    pub driver: String,

    /// Data source name / connection string
    pub dsn: String,
}

/// Blob storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobConfig {
    /// Driver (filesystem, s3)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,

    /// S3 bucket name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,

    /// Filesystem directory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
}

/// Event bus configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventConfig {
    /// Driver (memory, nats)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,

    /// URL for external event bus
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Secrets provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsConfig {
    /// Driver (env, aws, vault)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,

    /// AWS region
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// Prefix for secret keys
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

/// Registry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryConfig {
    /// Registry type (local, smithery, remote)
    #[serde(rename = "type")]
    pub registry_type: String,

    /// Registry name (optional, used for logging and identification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Registry URL (for remote/smithery)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Local path (for local registry)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// API key (for Smithery)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
}

/// Smithery registry configuration (extends RegistryConfig)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmitheryRegistryConfig {
    /// Base registry configuration
    #[serde(flatten)]
    pub registry: RegistryConfig,

    /// Smithery API key
    pub api_key: String,
}

/// Internal registry entry structure for loading from JSON files
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegistryEntry {
    /// Entry type (mcp_server, tool, etc.)
    #[serde(rename = "type")]
    pub entry_type: String,

    /// Entry name
    pub name: String,

    /// Command to execute
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,

    /// Command arguments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,

    /// Environment variables
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<HashMap<String, String>>,

    /// Server port
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    /// Transport type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,

    /// Endpoint (for HTTP transport)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

// SecretsProvider trait has been moved to src/secrets/mod.rs
// All secret management now goes through the secrets module

/// HTTP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    /// Host to bind to
    #[serde(default = "default_host")]
    pub host: String,

    /// Port to bind to
    #[serde(default = "default_port")]
    pub port: u16,

    /// Enable secure cookies (requires HTTPS). Default: false for local development
    #[serde(default)]
    pub secure: bool,

    /// Allowed CORS origins (e.g., ["https://example.com", "https://app.example.com"])
    /// If not specified, defaults to localhost origins for development
    #[serde(skip_serializing_if = "Option::is_none", rename = "allowedOrigins")]
    pub allowed_origins: Option<Vec<String>>,

    /// Trust X-Forwarded-* headers from reverse proxy
    /// Enable this when running behind a reverse proxy (Caddy, Nginx, etc.)
    #[serde(default, rename = "trustProxy")]
    pub trust_proxy: bool,

    /// Enable HTTP REST API (default: true)
    #[serde(default = "default_true", rename = "enableHttpApi")]
    pub enable_http_api: bool,

    /// Enable MCP over HTTP transport (default: true)
    #[serde(default = "default_true", rename = "enableMcp")]
    pub enable_mcp: bool,

    /// Enable OAuth authorization server (default: false, opt-in)
    #[serde(default, rename = "enableOauthServer")]
    pub enable_oauth_server: bool,

    /// OAuth issuer URL (e.g., https://your-domain.com)
    /// If not set, defaults to http://host:port
    #[serde(skip_serializing_if = "Option::is_none", rename = "oauthIssuer")]
    pub oauth_issuer: Option<String>,

    /// Public-facing URL for this BeemFlow instance (e.g., https://your-domain.com)
    /// Used for OAuth callbacks, webhooks, and any external integrations that need to call back.
    /// If not set, defaults to http://host:port (or http://localhost:port if host is 0.0.0.0)
    #[serde(skip_serializing_if = "Option::is_none", rename = "publicUrl")]
    pub public_url: Option<String>,

    /// Frontend URL for separate deployment (optional)
    ///
    /// When None (default): Backend serves React build from frontend/dist/ (integrated mode)
    /// When Some: Backend serves API only, OAuth success redirects to this URL, CORS configured
    ///
    /// Environment variable: FRONTEND_URL
    ///
    /// Use cases:
    /// - Development with hot reload: "http://localhost:5173" (Vite dev server)
    /// - Production integrated: None (backend serves frontend from dist/)
    /// - Production separate: "https://app.beemflow.com" (CDN/separate deployment)
    #[serde(skip_serializing_if = "Option::is_none", rename = "frontendUrl")]
    pub frontend_url: Option<String>,

    /// Enable single-user mode (bypasses authentication, uses DEFAULT_ORGANIZATION_ID)
    /// WARNING: Only use for personal/local development. Disables all authentication.
    /// Default: false (multi-tenant mode with full authentication)
    #[serde(default, rename = "singleUser")]
    pub single_user: bool,
}

fn default_true() -> bool {
    true
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    crate::constants::DEFAULT_HTTP_PORT
}

/// Get the default BeemFlow directory (~/.beemflow)
fn default_beemflow_dir() -> String {
    if let Some(home) = dirs::home_dir() {
        home.join(".beemflow").to_string_lossy().to_string()
    } else {
        // Fallback to current directory if home can't be determined
        ".beemflow".to_string()
    }
}

/// Get the default SQLite database path (~/.beemflow/flow.db)
fn default_sqlite_path() -> String {
    format!("{}/flow.db", default_beemflow_dir())
}

/// Get the default blob files directory (~/.beemflow/files)
fn default_blob_dir() -> String {
    format!("{}/files", default_beemflow_dir())
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Log level (debug, info, warn, error)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
}

// Internal struct for default deserialization (no custom logic)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct McpServerConfigInternal {
    #[serde(default)]
    command: String,
    args: Option<Vec<String>>,
    env: Option<HashMap<String, String>>,
    port: Option<u16>,
    transport: Option<String>,
    endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct McpServerConfig {
    /// Command to execute
    pub command: String,

    /// Command arguments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,

    /// Environment variables
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<HashMap<String, String>>,

    /// Server port
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    /// Transport type (stdio, http)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,

    /// Server endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

// Custom deserialize to handle:
// 1. Full URL strings: "http://..." or "https://..."
// 2. Regular JSON object
impl<'de> Deserialize<'de> for McpServerConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        // Try to deserialize as either a string or an object
        let value = Value::deserialize(deserializer)?;

        match value {
            Value::String(s) => {
                // Handle full URLs only
                if s.contains("://") {
                    // Full URL - use as endpoint
                    Ok(McpServerConfig {
                        command: String::new(),
                        args: None,
                        env: None,
                        port: None,
                        transport: Some("http".to_string()),
                        endpoint: Some(s),
                    })
                } else {
                    Err(Error::custom(format!(
                        "Invalid MCP server config string: '{}'. Must be a full URL (http://... or https://...) or a JSON object",
                        s
                    )))
                }
            }
            Value::Object(_) => {
                // Regular JSON object - deserialize using internal struct to avoid recursion
                let internal: McpServerConfigInternal =
                    serde_json::from_value(value).map_err(|e| {
                        Error::custom(format!("Failed to deserialize MCP server config: {}", e))
                    })?;

                // Convert internal to public
                Ok(McpServerConfig {
                    command: internal.command,
                    args: internal.args,
                    env: internal.env,
                    port: internal.port,
                    transport: internal.transport,
                    endpoint: internal.endpoint,
                })
            }
            _ => Err(Error::custom(
                "MCP server config must be a URL string or JSON object",
            )),
        }
    }
}

/// Tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TracingConfig {
    /// Exporter (stdout, otlp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exporter: Option<String>,

    /// OTLP endpoint URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// Service name for traces
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
}

/// OAuth server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    /// Enable OAuth server (default: false for local dev)
    #[serde(default)]
    pub enabled: bool,
}

/// MCP server behavior configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpConfig {
    /// Require OAuth authentication for MCP
    #[serde(default, rename = "requireAuth")]
    pub require_auth: bool,
}

/// Runtime limits configuration for security and resource management
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LimitsConfig {
    /// Maximum number of concurrent tasks for parallel execution
    /// Default: 1000
    #[serde(default = "default_max_concurrent_tasks")]
    pub max_concurrent_tasks: usize,

    /// Maximum flow file size in bytes
    /// Default: 10MB (10 * 1024 * 1024)
    #[serde(default = "default_max_flow_file_size")]
    pub max_flow_file_size: u64,

    /// Maximum recursion depth for nested structures
    /// Default: 1000
    #[serde(default = "default_max_recursion_depth")]
    pub max_recursion_depth: usize,
}

fn default_max_concurrent_tasks() -> usize {
    100000
}

fn default_max_flow_file_size() -> u64 {
    10 * 1024 * 1024 // 10MB
}

fn default_max_recursion_depth() -> usize {
    1000
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_concurrent_tasks: default_max_concurrent_tasks(),
            max_flow_file_size: default_max_flow_file_size(),
            max_recursion_depth: default_max_recursion_depth(),
        }
    }
}

impl Config {
    /// Get runtime limits (with defaults if not configured)
    pub fn get_limits(&self) -> LimitsConfig {
        self.limits.clone().unwrap_or_default()
    }

    /// Get OAuth redirect URI from HTTP config
    ///
    /// Priority order:
    /// 1. Use public_url if explicitly configured (production deployments)
    /// 2. Auto-detect localhost when binding to 0.0.0.0 (local development)
    /// 3. Fall back to http://host:port (direct binding)
    /// 4. Default to localhost:3000 if no HTTP config present
    pub fn oauth_redirect_uri(&self) -> String {
        self.http
            .as_ref()
            .and_then(|http| {
                http.public_url
                    .as_ref()
                    .map(|url| format!("{}/oauth/callback", url.trim_end_matches('/')))
                    .or_else(|| {
                        Some(if http.host == "0.0.0.0" {
                            format!("http://localhost:{}/oauth/callback", http.port)
                        } else {
                            format!("http://{}:{}/oauth/callback", http.host, http.port)
                        })
                    })
            })
            .unwrap_or_else(|| "http://localhost:3000/oauth/callback".to_string())
    }

    /// Create a secrets provider based on configuration
    ///
    /// Returns the appropriate SecretsProvider implementation based on the
    /// `secrets.driver` config value:
    /// - "env" (default): EnvSecretsProvider - reads from environment variables
    /// - "aws" (future): AwsSecretsProvider - reads from AWS Secrets Manager
    /// - "vault" (future): VaultSecretsProvider - reads from HashiCorp Vault
    ///
    /// # Example
    ///
    /// ```no_run
    /// use beemflow::config::Config;
    /// use beemflow::secrets::SecretsProvider;
    ///
    /// let config = Config::default();
    /// let provider = config.create_secrets_provider();
    /// ```
    pub fn create_secrets_provider(&self) -> std::sync::Arc<dyn crate::secrets::SecretsProvider> {
        use std::sync::Arc;

        // Currently only supports environment variable provider
        // Future support for AWS Secrets Manager and HashiCorp Vault:
        // - Some("aws") => Arc::new(AwsSecretsProvider::new(self.secrets.as_ref())),
        // - Some("vault") => Arc::new(VaultSecretsProvider::new(self.secrets.as_ref())),
        self.secrets.as_ref().and_then(|s| s.driver.as_deref());
        Arc::new(crate::secrets::EnvSecretsProvider::new())
    }

    /// Load configuration from file
    pub fn load() -> Result<Self> {
        Self::load_from_path(crate::constants::CONFIG_FILE_NAME)
    }

    /// Load configuration from specific path
    ///
    /// Supports both JSON and YAML formats based on file extension:
    /// - `.json` files are parsed as JSON
    /// - `.yaml` or `.yml` files are parsed as YAML
    /// - Files without extension default to JSON parsing
    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            // Return default config if file doesn't exist
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path)?;

        // Detect format from file extension
        let config: Config = match path.extension().and_then(|s| s.to_str()) {
            Some("yaml") | Some("yml") => {
                // Parse as YAML
                serde_yaml::from_str(&content).map_err(|e| {
                    BeemFlowError::config(format!("Failed to parse YAML config: {}", e))
                })?
            }
            _ => {
                // Parse as JSON (default)
                serde_json::from_str(&content).map_err(|e| {
                    BeemFlowError::config(format!("Failed to parse JSON config: {}", e))
                })?
            }
        };

        // Validate config
        config.validate()?;

        Ok(config)
    }

    /// Load and inject environment variables into registries
    pub fn load_and_inject<P: AsRef<Path>>(path: P) -> Result<Self> {
        load_and_inject_registries(path)
    }

    /// Save configuration to file
    pub fn save(&self) -> Result<()> {
        self.save_to_path(crate::constants::CONFIG_FILE_NAME)
    }

    /// Save configuration to specific path
    ///
    /// Supports both JSON and YAML formats based on file extension:
    /// - `.json` files are written as JSON
    /// - `.yaml` or `.yml` files are written as YAML
    /// - Files without extension default to JSON format
    pub fn save_to_path<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path_ref = path.as_ref();

        // Create parent directory if needed
        if let Some(parent) = path_ref.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Detect format from file extension
        let content = match path_ref.extension().and_then(|s| s.to_str()) {
            Some("yaml") | Some("yml") => {
                // Serialize as YAML
                serde_yaml::to_string(self).map_err(|e| {
                    BeemFlowError::config(format!("Failed to serialize to YAML: {}", e))
                })?
            }
            _ => {
                // Serialize as JSON (default)
                serde_json::to_string_pretty(self)?
            }
        };

        std::fs::write(path_ref, content)?;
        Ok(())
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Validate storage configuration
        if self.storage.driver.is_empty() {
            return Err(BeemFlowError::config("storage.driver is required"));
        }

        if self.storage.dsn.is_empty() {
            return Err(BeemFlowError::config("storage.dsn is required"));
        }

        // Validate storage driver is supported
        match self.storage.driver.as_str() {
            "sqlite" | "postgres" | "memory" => {}
            _ => {
                return Err(BeemFlowError::config(format!(
                    "Unsupported storage driver: '{}'. Supported: sqlite, postgres, memory",
                    self.storage.driver
                )));
            }
        }

        // Validate HTTP configuration
        if let Some(ref http) = self.http {
            // Validate port is not zero (upper bound is enforced by u16 type)
            if http.port == 0 {
                return Err(BeemFlowError::config("http.port must be nonzero (1-65535)"));
            }

            // Validate host is not empty
            if http.host.is_empty() {
                return Err(BeemFlowError::config("http.host cannot be empty"));
            }

            // Validate allowed_origins if provided
            if let Some(ref origins) = http.allowed_origins {
                for origin in origins {
                    if origin.is_empty() {
                        return Err(BeemFlowError::config(
                            "http.allowedOrigins cannot contain empty strings",
                        ));
                    }

                    // Basic URL validation - must start with http:// or https://
                    if !origin.starts_with("http://") && !origin.starts_with("https://") {
                        return Err(BeemFlowError::config(format!(
                            "Invalid CORS origin '{}': must start with http:// or https://",
                            origin
                        )));
                    }
                }
            }
        }

        // Validate blob storage configuration
        if let Some(ref blob) = self.blob
            && let Some(ref driver) = blob.driver
        {
            match driver.as_str() {
                "filesystem" => {
                    // For filesystem, directory must be specified
                    if blob.directory.is_none() {
                        return Err(BeemFlowError::config(
                            "blob.directory is required when using filesystem driver",
                        ));
                    }
                }
                "s3" => {
                    // For S3, bucket must be specified
                    if blob.bucket.is_none() {
                        return Err(BeemFlowError::config(
                            "blob.bucket is required when using S3 driver",
                        ));
                    }
                }
                _ => {
                    return Err(BeemFlowError::config(format!(
                        "Unsupported blob driver: '{}'. Supported: filesystem, s3",
                        driver
                    )));
                }
            }
        }

        // Validate limits if provided
        if let Some(ref limits) = self.limits {
            if limits.max_concurrent_tasks == 0 {
                return Err(BeemFlowError::config(
                    "limits.maxConcurrentTasks must be greater than 0",
                ));
            }

            if limits.max_recursion_depth == 0 {
                return Err(BeemFlowError::config(
                    "limits.maxRecursionDepth must be greater than 0",
                ));
            }

            if limits.max_flow_file_size == 0 {
                return Err(BeemFlowError::config(
                    "limits.maxFlowFileSize must be greater than 0",
                ));
            }
        }

        Ok(())
    }

    /// Upsert MCP server configuration
    pub fn upsert_mcp_server(&mut self, name: String, spec: McpServerConfig) {
        self.mcp_servers
            .get_or_insert_with(HashMap::new)
            .insert(name, spec);
    }

    /// Get merged MCP server config (registry + config file)
    pub fn get_merged_mcp_config(&self, host: &str) -> Result<McpServerConfig> {
        get_merged_mcp_server_config(self, host)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            storage: StorageConfig {
                driver: "sqlite".to_string(),
                dsn: default_sqlite_path(),
            },
            blob: Some(BlobConfig {
                driver: Some("filesystem".to_string()),
                bucket: None,
                directory: Some(default_blob_dir()),
            }),
            event: Some(EventConfig {
                driver: Some("memory".to_string()),
                url: None,
            }),
            secrets: None,
            registries: None,
            http: Some(HttpConfig {
                host: default_host(),
                port: default_port(),
                secure: false,         // Default to false for local development
                allowed_origins: None, // Defaults to localhost origins
                trust_proxy: false,    // Default to false for local development
                enable_http_api: true,
                enable_mcp: true,
                enable_oauth_server: false,
                oauth_issuer: None, // Auto-generated from host:port if not set
                public_url: None,   // Auto-detected or explicitly configured
                frontend_url: None, // Integrated mode by default
                single_user: false, // Default to multi-tenant mode
            }),
            log: Some(LogConfig {
                level: Some("info".to_string()),
            }),
            flows_dir: None,
            mcp_servers: None,
            tracing: None,
            oauth: Some(OAuthConfig {
                enabled: false, // Disabled by default for local dev
            }),
            mcp: Some(McpConfig {
                require_auth: false, // Auth disabled by default
            }),
            limits: Some(LimitsConfig::default()),
        }
    }
}

/// Get the flows directory from config or default
///
/// Priority:
/// 1. Config.flows_dir if set
/// 2. ~/.beemflow/flows (default)
pub fn get_flows_dir(config: &Config) -> PathBuf {
    config
        .flows_dir
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(crate::constants::default_flows_dir()))
}

/// Get default local registry path
pub fn default_local_registry_path() -> PathBuf {
    PathBuf::from(".beemflow/registry.json")
}

/// Get default local registry full path (resolves relative to current directory)
pub fn default_local_registry_full_path() -> PathBuf {
    env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".beemflow/registry.json")
}

/// Parse registry config into specific type if needed
pub fn parse_registry_config(reg: RegistryConfig) -> Result<Box<dyn std::any::Any>> {
    match reg.registry_type.as_str() {
        "smithery" => {
            // In real implementation, would unmarshal full object into SmitheryRegistryConfig
            let smithery_config = SmitheryRegistryConfig {
                registry: reg,
                api_key: String::new(), // Would be populated from JSON
            };
            Ok(Box::new(smithery_config))
        }
        _ => Ok(Box::new(reg)),
    }
}

/// Validate configuration against JSON schema
pub fn validate_config(raw: &[u8]) -> Result<()> {
    use once_cell::sync::Lazy;

    // Embedded config schema - loaded once at startup
    #[allow(clippy::expect_used)] // Static schema compilation should fail-fast on invalid schema
    static CONFIG_SCHEMA: Lazy<jsonschema::Validator> = Lazy::new(|| {
        // For config validation, we use a simplified schema that checks required fields
        // The full BeemFlow schema is used for flow validation in dsl/validator.rs
        let schema_json = serde_json::json!({
            "type": "object",
            "required": ["storage"],
            "properties": {
                "storage": {
                    "type": "object",
                    "required": ["driver", "dsn"],
                    "properties": {
                        "driver": {"type": "string", "minLength": 1},
                        "dsn": {"type": "string", "minLength": 1}
                    }
                },
                "blob": {"type": "object"},
                "event": {"type": "object"},
                "secrets": {"type": "object"},
                "registries": {"type": "array"},
                "http": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "port": {"type": "integer", "minimum": 1, "maximum": 65535}
                    }
                },
                "log": {"type": "object"},
                "flowsDir": {"type": "string"},
                "mcpServers": {"type": "object"},
                "tracing": {"type": "object"},
                "oauth": {"type": "object"},
                "mcp": {"type": "object"}
            }
        });

        jsonschema::validator_for(&schema_json).expect("Failed to compile config schema")
    });

    // Parse the raw JSON
    let config_value: Value = serde_json::from_slice(raw)?;

    // Validate against schema
    if !CONFIG_SCHEMA.is_valid(&config_value) {
        let error_messages: Vec<String> = CONFIG_SCHEMA
            .iter_errors(&config_value)
            .map(|e| format!("{}: {}", e.instance_path, e))
            .collect();

        return Err(BeemFlowError::validation(format!(
            "Config validation failed:\n  - {}",
            error_messages.join("\n  - ")
        )));
    }

    Ok(())
}

/// Load configuration from file path
///
/// Supports both JSON and YAML formats. Auto-detects format from file extension.
/// Validates against schema before returning.
pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Config> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(BeemFlowError::not_found(
            "Config file",
            path.display().to_string(),
        ));
    }

    let content = fs::read_to_string(path)?;

    // Only validate JSON configs (YAML validation would need schema conversion)
    if matches!(
        path.extension().and_then(|s| s.to_str()),
        Some("json") | None
    ) {
        validate_config(content.as_bytes())?;
    }

    let config: Config = match path.extension().and_then(|s| s.to_str()) {
        Some("yaml") | Some("yml") => serde_yaml::from_str(&content)
            .map_err(|e| BeemFlowError::config(format!("Failed to parse YAML config: {}", e)))?,
        _ => serde_json::from_str(&content)
            .map_err(|e| BeemFlowError::config(format!("Failed to parse JSON config: {}", e)))?,
    };

    config.validate()?;
    Ok(config)
}

/// Save configuration to file
///
/// Supports both JSON and YAML formats based on file extension.
pub fn save_config<P: AsRef<Path>>(path: P, cfg: &Config) -> Result<()> {
    let path_ref = path.as_ref();

    let content = match path_ref.extension().and_then(|s| s.to_str()) {
        Some("yaml") | Some("yml") => serde_yaml::to_string(cfg)
            .map_err(|e| BeemFlowError::config(format!("Failed to serialize to YAML: {}", e)))?,
        _ => serde_json::to_string_pretty(cfg)?,
    };

    fs::write(path_ref, content)?;
    Ok(())
}

/// Load MCP servers from registry file
pub fn load_mcp_servers_from_registry<P: AsRef<Path>>(
    path: P,
) -> Result<HashMap<String, McpServerConfig>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(HashMap::new());
    }

    let content = fs::read_to_string(path)?;
    let entries: Vec<RegistryEntry> = serde_json::from_str(&content)?;

    let mut servers = HashMap::new();
    for entry in entries {
        if entry.entry_type == "mcp_server" {
            servers.insert(
                entry.name,
                McpServerConfig {
                    command: entry.command.unwrap_or_default(),
                    args: entry.args,
                    env: entry.env,
                    port: entry.port,
                    transport: entry.transport,
                    endpoint: entry.endpoint,
                },
            );
        }
    }

    Ok(servers)
}

/// Load MCP servers from registry factory (default + local)
pub fn load_mcp_servers_from_registry_factory() -> HashMap<String, McpServerConfig> {
    let mut servers = HashMap::new();

    // Load from embedded default registry
    let default_servers = load_mcp_servers_from_embedded_default();
    servers.extend(default_servers);

    // Load from local registry (higher precedence)
    let local_path = default_local_registry_full_path();
    if let Ok(local_servers) = load_mcp_servers_from_registry(local_path) {
        servers.extend(local_servers); // Local overrides default
    }

    servers
}

/// Load MCP servers from embedded default registry
pub fn load_mcp_servers_from_embedded_default() -> HashMap<String, McpServerConfig> {
    let mut servers = HashMap::new();

    // This is a simplified version - in a real implementation,
    // this would load from embedded default.json file
    servers.insert(
        "airtable".to_string(),
        McpServerConfig {
            command: "npx".to_string(),
            args: Some(vec!["-y".to_string(), "airtable-mcp-server".to_string()]),
            env: Some(HashMap::from([(
                "AIRTABLE_API_KEY".to_string(),
                "$env:AIRTABLE_API_KEY".to_string(),
            )])),
            port: None,
            transport: Some("stdio".to_string()),
            endpoint: None,
        },
    );

    servers
}

/// Read curated MCP server config from mcp_servers/ directory
pub fn read_curated_config(host: &str) -> (McpServerConfig, bool) {
    // Try current working directory first
    let cwd_path = PathBuf::from("mcp_servers").join(format!("{}.json", host));
    if let Ok(data) = fs::read_to_string(&cwd_path)
        && let Ok(mut servers) = serde_json::from_str::<HashMap<String, McpServerConfig>>(&data)
        && let Some(config) = servers.remove(host)
        && (!config.command.is_empty()
            || config.args.is_some()
            || config.env.is_some()
            || config.port.is_some()
            || config.transport.is_some()
            || config.endpoint.is_some())
    {
        return (config, true);
    }

    // Try project root (where Cargo.toml is located)
    if let Ok(current_exe) = env::current_exe()
        && let Some(parent) = current_exe.parent()
    {
        let project_root = parent.parent().unwrap_or(parent);
        let curated_path = project_root
            .join("mcp_servers")
            .join(format!("{}.json", host));
        if let Ok(data) = fs::read_to_string(curated_path)
            && let Ok(mut servers) = serde_json::from_str::<HashMap<String, McpServerConfig>>(&data)
            && let Some(config) = servers.remove(host)
            && (!config.command.is_empty()
                || config.args.is_some()
                || config.env.is_some()
                || config.port.is_some()
                || config.transport.is_some()
                || config.endpoint.is_some())
        {
            return (config, true);
        }
    }

    (McpServerConfig::default(), false)
}

/// Get merged MCP server configuration (registry + curated + config file)
pub fn get_merged_mcp_server_config(cfg: &Config, host: &str) -> Result<McpServerConfig> {
    // Check if server is defined in config file first
    let config_server = cfg
        .mcp_servers
        .as_ref()
        .and_then(|servers| servers.get(host))
        .cloned();

    // Load registry entries using the factory system
    let reg_map = load_mcp_servers_from_registry_factory();

    // Determine curated template
    let (curated_cfg, has_curated) = read_curated_config(host);

    // Determine base: curated > registry > config > error
    let base = if has_curated {
        Some(curated_cfg)
    } else if let Some(reg_config) = reg_map.get(host) {
        Some(reg_config.clone())
    } else {
        config_server.clone()
    };

    let mut merged = base.ok_or_else(|| {
        BeemFlowError::config(format!(
            "MCP server '{}' not found in registry or config",
            host
        ))
    })?;

    // If we have a config override AND a base from registry/curated, merge them
    if let Some(override_cfg) = config_server {
        // Only merge if base came from registry/curated (not from config itself)
        if has_curated || reg_map.contains_key(host) {
            // Command: only override if no curated template
            if !has_curated && !override_cfg.command.is_empty() {
                merged.command = override_cfg.command;
            }

            // Other fields override
            if let Some(args) = override_cfg.args
                && !args.is_empty()
            {
                merged.args = Some(args);
            }

            if let Some(env) = override_cfg.env {
                let merged_env = merged.env.get_or_insert_with(HashMap::new);
                merged_env.extend(env);
            }

            if let Some(port) = override_cfg.port
                && port != 0
            {
                merged.port = Some(port);
            }

            if let Some(transport) = override_cfg.transport
                && !transport.is_empty()
            {
                merged.transport = Some(transport);
            }

            if let Some(endpoint) = override_cfg.endpoint
                && !endpoint.is_empty()
            {
                merged.endpoint = Some(endpoint);
            }
        }
        // If base IS the config (no registry/curated), merged already equals config_server
    }

    Ok(merged)
}

/// Expand environment variable references in config values (bootstrap-time only)
///
/// **LIFECYCLE: Config-time (bootstrap) only**
///
/// This function is for CONFIG LOADING before the SecretsProvider exists.
/// For RUNTIME expansion, use `secrets::expand_value()` instead.
///
/// This solves the chicken-and-egg problem: config tells us which SecretsProvider
/// to create, so we can't use SecretsProvider to load config.
fn expand_env_value_at_config_time(value: &str) -> String {
    use once_cell::sync::Lazy;
    use regex::Regex;

    #[allow(clippy::expect_used)] // Static regex compilation should fail-fast on invalid pattern
    static ENV_VAR_PATTERN: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\$env:([A-Za-z_][A-Za-z0-9_]*)").expect("Invalid environment variable regex")
    });

    ENV_VAR_PATTERN
        .replace_all(value, |caps: &regex::Captures| {
            if let Some(var_match) = caps.get(1) {
                let var_name = var_match.as_str();
                env::var(var_name).unwrap_or_else(|_| {
                    caps.get(0)
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default()
                })
            } else {
                // Should never happen with this regex, but be defensive
                caps.get(0)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default()
            }
        })
        .to_string()
}

/// Inject environment variables into registry configuration
pub fn inject_env_vars_into_registry(reg: &mut HashMap<String, Value>) {
    for (k, v) in reg.iter_mut() {
        if let Some(str_val) = v.as_str() {
            // Use config-time expansion for $env:VARNAME format
            let expanded = expand_env_value_at_config_time(str_val);
            if expanded != *str_val {
                *v = Value::String(expanded);
            }
        } else if v.is_null() {
            // If the field is null, check for a matching env var by convention
            let env_var = k.to_uppercase();
            if let Ok(val) = env::var(&env_var)
                && !val.is_empty()
            {
                *v = Value::String(val);
            }
        }
    }
}

/// Load and inject registries with environment variables
pub fn load_and_inject_registries<P: AsRef<Path>>(path: P) -> Result<Config> {
    let mut cfg = load_config(path).unwrap_or_default();

    // Auto-enable Smithery if API key is present
    if let Ok(api_key) = env::var(crate::constants::ENV_SMITHERY_KEY)
        && !api_key.is_empty()
    {
        let has_smithery = cfg
            .registries
            .as_ref()
            .map(|regs| regs.iter().any(|r| r.registry_type == "smithery"))
            .unwrap_or(false);

        if !has_smithery {
            cfg.registries
                .get_or_insert_with(Vec::new)
                .push(RegistryConfig {
                    registry_type: "smithery".to_string(),
                    name: Some("smithery".to_string()),
                    url: Some("https://registry.smithery.ai/servers".to_string()),
                    path: None,
                    api_key: Some(api_key),
                });
        }
    }

    // Inject env vars for all registries
    if let Some(ref mut registries) = cfg.registries {
        for reg in registries.iter_mut() {
            let mut reg_map = HashMap::new();
            reg_map.insert("type".to_string(), Value::String(reg.registry_type.clone()));
            if let Some(ref url) = reg.url {
                reg_map.insert("url".to_string(), Value::String(url.clone()));
            }
            if let Some(ref path) = reg.path {
                reg_map.insert("path".to_string(), Value::String(path.clone()));
            }
            if let Some(ref api_key) = reg.api_key {
                reg_map.insert(
                    "apiKey".to_string(),
                    serde_json::Value::String(api_key.clone()),
                );
            }

            inject_env_vars_into_registry(&mut reg_map);

            if let Some(reg_type) = reg_map.get("type").and_then(|v| v.as_str()) {
                reg.registry_type = reg_type.to_string();
            }
            if let Some(reg_url) = reg_map.get("url").and_then(|v| v.as_str()) {
                reg.url = Some(reg_url.to_string());
            }
            if let Some(path) = reg_map.get("path").and_then(|v| v.as_str()) {
                reg.path = Some(path.to_string());
            }
            if let Some(api_key) = reg_map.get("apiKey").and_then(|v| v.as_str()) {
                reg.api_key = Some(api_key.to_string());
            }
        }
    }

    Ok(cfg)
}

#[cfg(test)]
mod config_test;
