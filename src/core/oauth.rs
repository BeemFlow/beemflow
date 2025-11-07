//! OAuth operations module
//!
//! All operations for managing OAuth provider connections and credentials.

use super::*;
use beemflow_core_macros::{operation, operation_group};
use schemars::JsonSchema;

#[operation_group(oauth)]
pub mod oauth {
    use super::*;

    // ============================================================================
    // Input/Output Types
    // ============================================================================

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Empty input (no parameters required)")]
    pub struct EmptyInput {}

    #[derive(Serialize)]
    pub struct ListProvidersOutput {
        pub providers: Vec<OAuthProviderInfo>,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for retrieving a specific OAuth provider")]
    pub struct GetProviderInput {
        #[schemars(description = "OAuth provider ID (e.g., google, github, slack, x)")]
        pub provider_id: String,
    }

    #[derive(Serialize)]
    pub struct GetProviderOutput {
        pub provider: OAuthProviderInfo,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for initiating OAuth connection flow")]
    pub struct ConnectInput {
        #[schemars(description = "OAuth provider ID to connect")]
        pub provider_id: String,

        #[serde(default)]
        #[schemars(description = "Optional list of OAuth scopes to request (defaults to required scopes)")]
        pub scopes: Option<Vec<String>>,
    }

    #[derive(Serialize)]
    pub struct ConnectOutput {
        pub auth_url: String,
        pub provider_id: String,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for disconnecting OAuth provider")]
    pub struct DisconnectInput {
        #[schemars(description = "OAuth provider ID to disconnect")]
        pub provider_id: String,
    }

    #[derive(Serialize)]
    pub struct DisconnectOutput {
        pub success: bool,
        pub provider_id: String,
    }

    #[derive(Serialize)]
    pub struct ListConnectionsOutput {
        pub connections: Vec<OAuthConnection>,
    }

    // ============================================================================
    // Data Structures
    // ============================================================================

    /// OAuth provider information with connection status
    #[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
    pub struct OAuthProviderInfo {
        /// Provider ID (e.g., google, github)
        pub id: String,

        /// Provider name
        pub name: String,

        /// Display name for UI
        #[serde(skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,

        /// Icon emoji
        #[serde(skip_serializing_if = "Option::is_none")]
        pub icon: Option<String>,

        /// Provider description
        #[serde(skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,

        /// Available scopes
        pub scopes: Vec<ScopeInfo>,

        /// Whether this provider is currently connected
        pub connected: bool,

        /// Connection status details (if connected)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub connection_status: Option<OAuthConnectionStatus>,
    }

    /// OAuth scope information
    #[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
    pub struct ScopeInfo {
        /// Scope identifier
        pub scope: String,

        /// Scope description
        pub description: String,
    }

    /// OAuth connection status details
    #[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
    pub struct OAuthConnectionStatus {
        /// When the connection was established
        pub connected_at: String,

        /// When the access token expires (if applicable)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<String>,

        /// List of granted scopes
        #[serde(skip_serializing_if = "Option::is_none")]
        pub scopes_granted: Option<Vec<String>>,
    }

    /// OAuth connection information
    #[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
    pub struct OAuthConnection {
        /// Provider ID
        pub provider_id: String,

        /// Provider display name
        pub provider_name: String,

        /// When connected
        pub connected_at: String,

        /// When token expires
        #[serde(skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<String>,

        /// Granted scopes
        #[serde(skip_serializing_if = "Option::is_none")]
        pub scopes: Option<Vec<String>>,
    }

    // ============================================================================
    // Operations
    // ============================================================================

    /// List all available OAuth providers with connection status
    #[operation(
        name = "list_oauth_providers",
        input = EmptyInput,
        http = "GET /oauth/providers",
        cli = "oauth list-providers",
        description = "List all available OAuth providers"
    )]
    pub struct ListProviders {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for ListProviders {
        type Input = EmptyInput;
        type Output = ListProvidersOutput;

        async fn execute(&self, _input: Self::Input) -> Result<Self::Output> {
            let registry = &self.deps.registry_manager;
            let storage = &self.deps.storage;

            // Get all OAuth provider entries from registry
            let provider_entries = registry.list_oauth_providers().await?;

            // Get all stored credentials to check connection status
            let credentials = storage.list_oauth_credentials().await?;

            let mut providers = Vec::new();

            for entry in provider_entries {
                // Find matching credential (if any)
                let credential = credentials
                    .iter()
                    .find(|c| c.provider == entry.name);

                // Convert scopes
                let scopes = entry
                    .scopes
                    .unwrap_or_default()
                    .into_iter()
                    .map(|s| ScopeInfo {
                        scope: s.scope,
                        description: s.description,
                    })
                    .collect();

                // Build connection status
                let connection_status = credential.map(|cred| OAuthConnectionStatus {
                    connected_at: cred.created_at.to_rfc3339(),
                    expires_at: cred.expires_at.map(|dt| dt.to_rfc3339()),
                    scopes_granted: cred.scope.as_ref().map(|s| {
                        s.split_whitespace()
                            .map(String::from)
                            .collect()
                    }),
                });

                providers.push(OAuthProviderInfo {
                    id: entry.name.clone(),
                    name: entry.name,
                    display_name: entry.display_name,
                    icon: entry.icon,
                    description: entry.description,
                    scopes,
                    connected: credential.is_some(),
                    connection_status,
                });
            }

            Ok(ListProvidersOutput { providers })
        }
    }

    /// Get details for a specific OAuth provider
    #[operation(
        name = "get_oauth_provider",
        input = GetProviderInput,
        http = "GET /oauth/providers/{provider_id}",
        cli = "oauth get-provider <PROVIDER_ID>",
        description = "Get details for a specific OAuth provider"
    )]
    pub struct GetProvider {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for GetProvider {
        type Input = GetProviderInput;
        type Output = GetProviderOutput;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            let registry = &self.deps.registry_manager;
            let storage = &self.deps.storage;

            // Get provider from registry
            let entry = registry
                .get_oauth_provider(&input.provider_id)
                .await?
                .ok_or_else(|| {
                    BeemFlowError::not_found("OAuth provider", &input.provider_id)
                })?;

            // Check connection status
            let credentials = storage.list_oauth_credentials().await?;
            let credential = credentials
                .iter()
                .find(|c| c.provider == entry.name);

            // Convert scopes
            let scopes = entry
                .scopes
                .unwrap_or_default()
                .into_iter()
                .map(|s| ScopeInfo {
                    scope: s.scope,
                    description: s.description,
                })
                .collect();

            // Build connection status
            let connection_status = credential.map(|cred| OAuthConnectionStatus {
                connected_at: cred.created_at.to_rfc3339(),
                expires_at: cred.expires_at.map(|dt| dt.to_rfc3339()),
                scopes_granted: cred.scope.as_ref().map(|s| {
                    s.split_whitespace()
                        .map(String::from)
                        .collect()
                }),
            });

            let provider = OAuthProviderInfo {
                id: entry.name.clone(),
                name: entry.name,
                display_name: entry.display_name,
                icon: entry.icon,
                description: entry.description,
                scopes,
                connected: credential.is_some(),
                connection_status,
            };

            Ok(GetProviderOutput { provider })
        }
    }

    /// Initiate OAuth connection flow for a provider
    ///
    /// Note: For HTTP requests, session management (PKCE verifier, CSRF token) is
    /// handled by the HTTP layer's custom handler. This operation is primarily for
    /// CLI usage where we just need to generate and display the auth URL.
    #[operation(
        name = "connect_oauth_provider",
        input = ConnectInput,
        http = "POST /oauth/providers/{provider_id}/connect",
        cli = "oauth connect <PROVIDER_ID> [--scopes <SCOPES>]",
        description = "Initiate OAuth connection flow for a provider (returns auth URL)"
    )]
    pub struct Connect {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for Connect {
        type Input = ConnectInput;
        type Output = ConnectOutput;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            let registry = &self.deps.registry_manager;
            let oauth_client = &self.deps.oauth_client;

            // Get provider config from registry
            let provider_entry = registry
                .get_oauth_provider(&input.provider_id)
                .await?
                .ok_or_else(|| {
                    BeemFlowError::not_found("OAuth provider", &input.provider_id)
                })?;

            // Validate that client_id and client_secret are configured
            if provider_entry.client_id.is_none() || provider_entry.client_secret.is_none() {
                return Err(BeemFlowError::config(format!(
                    "OAuth provider '{}' is not configured. Please set the required environment variables.",
                    input.provider_id
                )));
            }

            // Determine scopes to request
            let scope_strings = input.scopes.unwrap_or_else(|| {
                // Default to all available scopes from provider
                provider_entry
                    .scope_strings()
                    .unwrap_or_default()
            });

            // Convert to &str slice for build_auth_url
            let scopes: Vec<&str> = scope_strings.iter().map(|s| s.as_str()).collect();

            // Build auth URL (for CLI usage - HTTP layer will handle session)
            // Note: Using None for custom_state means a random CSRF token will be generated
            // This is fine for CLI display, but HTTP handler will use session-based state
            let (auth_url, _verifier) = oauth_client
                .build_auth_url(&input.provider_id, &scopes, None, None)
                .await?;

            Ok(ConnectOutput {
                auth_url,
                provider_id: input.provider_id,
            })
        }
    }

    /// Disconnect and remove OAuth credentials for a provider
    #[operation(
        name = "disconnect_oauth_provider",
        input = DisconnectInput,
        http = "DELETE /oauth/providers/{provider_id}",
        cli = "oauth disconnect <PROVIDER_ID>",
        description = "Disconnect and remove OAuth credentials for a provider"
    )]
    pub struct Disconnect {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for Disconnect {
        type Input = DisconnectInput;
        type Output = DisconnectOutput;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            let storage = &self.deps.storage;

            // Find credential for this provider
            let credentials = storage.list_oauth_credentials().await?;
            let credential = credentials
                .into_iter()
                .find(|c| c.provider == input.provider_id)
                .ok_or_else(|| {
                    BeemFlowError::not_found(
                        "OAuth connection",
                        &format!("provider '{}'", input.provider_id),
                    )
                })?;

            // Delete the credential
            storage.delete_oauth_credential(&credential.id).await?;

            Ok(DisconnectOutput {
                success: true,
                provider_id: input.provider_id,
            })
        }
    }

    /// List all active OAuth connections
    #[operation(
        name = "list_oauth_connections",
        input = EmptyInput,
        http = "GET /oauth/connections",
        cli = "oauth list-connections",
        description = "List all active OAuth connections"
    )]
    pub struct ListConnections {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for ListConnections {
        type Input = EmptyInput;
        type Output = ListConnectionsOutput;

        async fn execute(&self, _input: Self::Input) -> Result<Self::Output> {
            let storage = &self.deps.storage;
            let registry = &self.deps.registry_manager;

            let credentials = storage.list_oauth_credentials().await?;

            let mut connections = Vec::new();

            for cred in credentials {
                // Get provider info for display name
                let provider_entry = registry.get_oauth_provider(&cred.provider).await?;
                let provider_name = provider_entry
                    .and_then(|e| e.display_name)
                    .unwrap_or_else(|| cred.provider.clone());

                connections.push(OAuthConnection {
                    provider_id: cred.provider,
                    provider_name,
                    connected_at: cred.created_at.to_rfc3339(),
                    expires_at: cred.expires_at.map(|dt| dt.to_rfc3339()),
                    scopes: cred.scope.map(|s| {
                        s.split_whitespace()
                            .map(String::from)
                            .collect()
                    }),
                });
            }

            Ok(ListConnectionsOutput { connections })
        }
    }
}
