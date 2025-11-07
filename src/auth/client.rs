//! OAuth 2.0 client for connecting to external providers
//!
//! Manages OAuth credentials and token refresh for external services
//! like Google, Twitter, GitHub, etc.

use crate::http::session::SessionStore;
use crate::http::template::TemplateRenderer;
use crate::model::{OAuthCredential, OAuthProvider};
use crate::registry::RegistryManager;
use crate::storage::Storage;
use crate::{BeemFlowError, Result};
use axum::{
    Json, Router,
    extract::{Path as AxumPath, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{delete, get, post},
};
use chrono::{Duration, Utc};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RefreshToken, Scope, TokenResponse, TokenUrl,
    basic::BasicClient,
};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use uuid::Uuid;

/// OAuth client manager for handling tokens from external providers
///
/// This manages OAuth credentials and automatically refreshes expired tokens.
/// Providers can come from the registry (default.json) or be stored in the database.
#[derive(Clone)]
pub struct OAuthClientManager {
    storage: Arc<dyn Storage>,
    registry_manager: Arc<RegistryManager>,
    redirect_uri: String,
    http_client: reqwest::Client,
}

impl OAuthClientManager {
    /// Create a new OAuth client manager
    ///
    /// Returns an error if the HTTP client cannot be built (e.g., TLS initialization failure)
    pub fn new(
        storage: Arc<dyn Storage>,
        registry_manager: Arc<RegistryManager>,
        redirect_uri: String,
    ) -> Result<Self> {
        // Create HTTP client with security settings
        // Disable redirects to prevent authorization code interception
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| {
                BeemFlowError::config(format!("Failed to build HTTP client for OAuth: {}", e))
            })?;

        Ok(Self {
            storage,
            registry_manager,
            redirect_uri,
            http_client,
        })
    }

    /// Get OAuth provider from registry or storage
    ///
    /// First checks the registry (where default providers like Google, GitHub are defined),
    /// then falls back to storage for custom user-created providers.
    async fn get_provider(&self, provider_id: &str) -> Result<OAuthProvider> {
        // Try registry first (default providers with $env: variables expanded)
        if let Some(entry) = self
            .registry_manager
            .get_oauth_provider(provider_id)
            .await?
        {
            // Convert RegistryEntry to OAuthProvider
            // Note: id, created_at, updated_at are dummy values for registry providers

            // Extract scope strings first (borrows entry)
            let scopes = entry.scope_strings();

            return Ok(OAuthProvider {
                id: entry.name.clone(),
                name: entry.display_name.unwrap_or(entry.name),
                client_id: entry.client_id.ok_or_else(|| {
                    BeemFlowError::auth(format!(
                        "OAuth provider '{}' missing client_id",
                        provider_id
                    ))
                })?,
                client_secret: entry.client_secret.ok_or_else(|| {
                    BeemFlowError::auth(format!(
                        "OAuth provider '{}' missing client_secret",
                        provider_id
                    ))
                })?,
                auth_url: entry.auth_url.ok_or_else(|| {
                    BeemFlowError::auth(format!(
                        "OAuth provider '{}' missing auth_url",
                        provider_id
                    ))
                })?,
                token_url: entry.token_url.ok_or_else(|| {
                    BeemFlowError::auth(format!(
                        "OAuth provider '{}' missing token_url",
                        provider_id
                    ))
                })?,
                scopes,
                auth_params: entry.auth_params,
                created_at: Utc::now(), // Dummy timestamp for registry providers
                updated_at: Utc::now(), // Dummy timestamp for registry providers
            });
        }

        // Fall back to storage for custom providers
        self.storage
            .get_oauth_provider(provider_id)
            .await?
            .ok_or_else(|| {
                BeemFlowError::auth(format!(
                    "OAuth provider '{}' not found in registry or storage",
                    provider_id
                ))
            })
    }

    /// Build authorization URL for a provider using oauth2 crate
    ///
    /// Returns the URL to redirect the user to for authorization and the PKCE code verifier.
    ///
    /// # Parameters
    /// * `custom_state` - Optional custom state to send to OAuth provider. If provided,
    ///   this will be used instead of generating a random CSRF token. Use this to embed
    ///   session IDs or other context in the state parameter.
    ///
    /// # Returns
    /// `(auth_url, code_verifier)` - The caller is responsible for storing any CSRF tokens
    pub async fn build_auth_url(
        &self,
        provider_id: &str,
        scopes: &[&str],
        _integration: Option<&str>,
        custom_state: Option<String>,
    ) -> Result<(String, String)> {
        // Get provider configuration from registry or storage
        let config = self.get_provider(provider_id).await?;

        // Build OAuth client using oauth2 crate
        // Note: Can't extract this to a helper due to oauth2's typestate pattern
        let client = BasicClient::new(ClientId::new(config.client_id))
            .set_client_secret(ClientSecret::new(config.client_secret))
            .set_auth_uri(
                AuthUrl::new(config.auth_url)
                    .map_err(|e| BeemFlowError::auth(format!("Invalid auth URL: {}", e)))?,
            )
            .set_token_uri(
                TokenUrl::new(config.token_url)
                    .map_err(|e| BeemFlowError::auth(format!("Invalid token URL: {}", e)))?,
            )
            .set_redirect_uri(
                RedirectUrl::new(self.redirect_uri.clone())
                    .map_err(|e| BeemFlowError::auth(format!("Invalid redirect URI: {}", e)))?,
            );

        // Generate PKCE challenge
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        // Build authorization URL with PKCE
        // Use custom state if provided, otherwise generate random CSRF token
        let mut auth_url = if let Some(custom) = custom_state {
            // Use custom state (e.g., "{csrf_token}:{session_id}")
            // The oauth2 crate's CsrfToken is just a wrapper around a string
            let (url, _) = client
                .authorize_url(|| CsrfToken::new(custom))
                .add_scopes(scopes.iter().map(|s| Scope::new(s.to_string())))
                .set_pkce_challenge(pkce_challenge)
                .url();
            url
        } else {
            // Generate random CSRF token (for flows that don't need custom state)
            let (url, _) = client
                .authorize_url(CsrfToken::new_random)
                .add_scopes(scopes.iter().map(|s| Scope::new(s.to_string())))
                .set_pkce_challenge(pkce_challenge)
                .url();
            url
        };

        // Append any additional auth parameters from the provider configuration
        // This allows providers to specify arbitrary query params in the registry
        // Example: Google uses {"prompt": "select_account"} to force account selection
        if let Some(ref params) = config.auth_params
            && !params.is_empty()
        {
            let mut query_pairs = auth_url.query_pairs_mut();
            for (key, value) in params {
                query_pairs.append_pair(key, value);
            }
        }

        Ok((auth_url.to_string(), pkce_verifier.secret().clone()))
    }

    /// Exchange authorization code for access token using oauth2 crate
    ///
    /// After user authorizes, exchange the authorization code for tokens
    /// and store the credential.
    pub async fn exchange_code(
        &self,
        provider_id: &str,
        code: &str,
        code_verifier: &str,
        integration: &str,
    ) -> Result<OAuthCredential> {
        // Get provider configuration from registry or storage
        let config = self.get_provider(provider_id).await?;

        // Build OAuth client using oauth2 crate
        // Note: Can't extract this to a helper due to oauth2's typestate pattern
        let client = BasicClient::new(ClientId::new(config.client_id))
            .set_client_secret(ClientSecret::new(config.client_secret))
            .set_auth_uri(
                AuthUrl::new(config.auth_url)
                    .map_err(|e| BeemFlowError::auth(format!("Invalid auth URL: {}", e)))?,
            )
            .set_token_uri(
                TokenUrl::new(config.token_url)
                    .map_err(|e| BeemFlowError::auth(format!("Invalid token URL: {}", e)))?,
            )
            .set_redirect_uri(
                RedirectUrl::new(self.redirect_uri.clone())
                    .map_err(|e| BeemFlowError::auth(format!("Invalid redirect URI: {}", e)))?,
            );

        // Exchange code for token with PKCE verifier using cached HTTP client
        let token_result = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(PkceCodeVerifier::new(code_verifier.to_string()))
            .request_async(&self.http_client)
            .await
            .map_err(|e| BeemFlowError::auth(format!("Token exchange failed: {}", e)))?;

        // Extract token details
        let now = Utc::now();
        let expires_at = token_result
            .expires_in()
            .map(|duration| now + Duration::seconds(duration.as_secs() as i64));

        let credential = OAuthCredential {
            id: Uuid::new_v4().to_string(),
            provider: provider_id.to_string(),
            integration: integration.to_string(),
            access_token: token_result.access_token().secret().clone(),
            refresh_token: token_result.refresh_token().map(|t| t.secret().clone()),
            expires_at,
            scope: token_result.scopes().map(|scopes| {
                scopes
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            }),
            created_at: now,
            updated_at: now,
        };

        // Save credential
        self.storage.save_oauth_credential(&credential).await?;

        tracing::info!(
            "Successfully exchanged authorization code for {}:{}",
            provider_id,
            integration
        );

        Ok(credential)
    }

    /// Get a valid OAuth access token for the given provider and integration
    ///
    /// Automatically refreshes the token if it's expired.
    ///
    /// # Example
    /// ```no_run
    /// use beemflow::auth::OAuthClientManager;
    /// use beemflow::storage::SqliteStorage;
    /// use beemflow::registry::RegistryManager;
    /// use beemflow::secrets::EnvSecretsProvider;
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let storage = Arc::new(SqliteStorage::new(":memory:").await?);
    /// let secrets_provider = Arc::new(EnvSecretsProvider::new());
    /// let registry_manager = Arc::new(RegistryManager::standard(None, secrets_provider));
    /// let client = OAuthClientManager::new(
    ///     storage,
    ///     registry_manager,
    ///     "http://localhost:3000/oauth/callback".to_string()
    /// )?;
    ///
    /// let token = client.get_token("google", "sheets").await?;
    /// println!("Access token: {}", token);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_token(&self, provider: &str, integration: &str) -> Result<String> {
        let cred = self
            .storage
            .get_oauth_credential(provider, integration)
            .await
            .map_err(|e| {
                BeemFlowError::OAuth(format!(
                    "Failed to get OAuth credential for {}:{} - {}",
                    provider, integration, e
                ))
            })?
            .ok_or_else(|| {
                BeemFlowError::OAuth(format!(
                    "OAuth credential not found for {}:{}",
                    provider, integration
                ))
            })?;

        // Check if token needs refresh
        if Self::needs_refresh(&cred) {
            tracing::info!("Token expired for {}:{}, refreshing", provider, integration);

            let mut cred_mut = cred.clone();
            match self.refresh_token(&mut cred_mut).await {
                Ok(()) => {
                    tracing::info!(
                        "Successfully refreshed token for {}:{}",
                        provider,
                        integration
                    );
                    // Return the refreshed token
                    return Ok(cred_mut.access_token);
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to refresh OAuth token for {}:{}: {}. Using expired token.",
                        provider,
                        integration,
                        e
                    );
                    // Continue with expired token rather than failing
                }
            }
        }

        Ok(cred.access_token)
    }

    /// Refresh an expired OAuth token using oauth2 crate
    ///
    /// Uses the refresh token to obtain a new access token from the provider.
    pub async fn refresh_token(&self, cred: &mut OAuthCredential) -> Result<()> {
        let refresh_token_str = cred.refresh_token.as_ref().ok_or_else(|| {
            BeemFlowError::OAuth(format!(
                "No refresh token available for {}:{}",
                cred.provider, cred.integration
            ))
        })?;

        // Get OAuth provider configuration from registry or storage
        let config = self.get_provider(&cred.provider).await.map_err(|e| {
            BeemFlowError::OAuth(format!(
                "Failed to get OAuth provider {}: {}",
                cred.provider, e
            ))
        })?;

        // Build OAuth client using oauth2 crate
        // Note: Can't extract this to a helper due to oauth2's typestate pattern
        let client = BasicClient::new(ClientId::new(config.client_id))
            .set_client_secret(ClientSecret::new(config.client_secret))
            .set_auth_uri(
                AuthUrl::new(config.auth_url)
                    .map_err(|e| BeemFlowError::auth(format!("Invalid auth URL: {}", e)))?,
            )
            .set_token_uri(
                TokenUrl::new(config.token_url)
                    .map_err(|e| BeemFlowError::auth(format!("Invalid token URL: {}", e)))?,
            )
            .set_redirect_uri(
                RedirectUrl::new(self.redirect_uri.clone())
                    .map_err(|e| BeemFlowError::auth(format!("Invalid redirect URI: {}", e)))?,
            );

        // Refresh the token using cached HTTP client
        let token_result = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token_str.clone()))
            .request_async(&self.http_client)
            .await
            .map_err(|e| BeemFlowError::OAuth(format!("Token refresh failed: {}", e)))?;

        // Extract new token info
        let new_access_token = token_result.access_token().secret().clone();
        let new_expires_at = token_result
            .expires_in()
            .map(|duration| Utc::now() + Duration::seconds(duration.as_secs() as i64));

        // Update local credential object for return value
        cred.access_token = new_access_token.clone();
        if let Some(new_refresh) = token_result.refresh_token() {
            cred.refresh_token = Some(new_refresh.secret().clone());
        }
        cred.expires_at = new_expires_at;
        cred.updated_at = Utc::now();

        // Use storage's dedicated refresh method (more efficient than full save)
        self.storage
            .refresh_oauth_credential(&cred.id, &new_access_token, new_expires_at)
            .await
            .map_err(|e| {
                BeemFlowError::OAuth(format!("Failed to save refreshed credential: {}", e))
            })?;

        Ok(())
    }

    /// Check if a credential needs token refresh
    fn needs_refresh(cred: &OAuthCredential) -> bool {
        if let Some(expires_at) = cred.expires_at {
            // Add 5-minute buffer before expiry
            let buffer = Duration::minutes(5);
            Utc::now() + buffer >= expires_at
        } else {
            false
        }
    }
}

// ============================================================================
// TEST UTILITIES
// ============================================================================

/// Create OAuth client manager for testing
///
/// Helper function to reduce boilerplate when creating OAuthClientManager instances
/// in tests and test helpers (Engine::for_testing, TestEnvironment, etc).
/// Uses standard test configuration with localhost:3000 redirect URI.
pub fn create_test_oauth_client(
    storage: Arc<dyn Storage>,
    secrets_provider: Arc<dyn crate::secrets::SecretsProvider>,
) -> Arc<OAuthClientManager> {
    let registry_manager = Arc::new(RegistryManager::standard(None, secrets_provider));
    Arc::new(
        OAuthClientManager::new(
            storage,
            registry_manager,
            "http://localhost:3000/oauth/callback".to_string(),
        )
        .expect("Failed to create OAuth client manager for testing"),
    )
}

// ============================================================================
// OAUTH CLIENT ROUTES (UI and API for connecting TO providers)
// ============================================================================

/// OAuth client state for route handlers
pub struct OAuthClientState {
    pub oauth_client: Arc<OAuthClientManager>,
    pub storage: Arc<dyn Storage>,
    pub registry_manager: Arc<RegistryManager>,
    pub session_store: Arc<SessionStore>,
    pub template_renderer: Arc<TemplateRenderer>,
}

/// Create OAuth client routes (for connecting TO external providers)
pub fn create_oauth_client_routes(state: Arc<OAuthClientState>) -> Router {
    Router::new()
        // OAuth UI endpoints (OAuth CLIENT - for connecting TO providers)
        .route("/oauth/providers", get(oauth_providers_handler))
        .route("/oauth/providers/{provider}", get(oauth_provider_handler))
        .route("/oauth/success", get(oauth_success_handler))
        .route("/oauth/callback", get(oauth_callback_handler))
        // OAuth Provider management endpoints (JSON API)
        .route("/oauth/providers/list", get(list_oauth_providers_handler))
        .route(
            "/oauth/providers/create",
            post(create_oauth_provider_handler),
        )
        .route("/oauth/providers/{id}/get", get(get_oauth_provider_handler))
        .route(
            "/oauth/providers/{id}/update",
            post(update_oauth_provider_handler),
        )
        .route(
            "/oauth/providers/{id}/delete",
            delete(delete_oauth_provider_handler),
        )
        // OAuth Credential management endpoints (JSON API)
        .route(
            "/oauth/credentials/list",
            get(list_oauth_credentials_handler),
        )
        .route(
            "/oauth/credentials/{id}/delete",
            delete(delete_oauth_credential_handler),
        )
        .route(
            "/oauth/authorize/{provider}",
            get(authorize_oauth_provider_handler),
        )
        // Add POST route for React frontend compatibility
        .route(
            "/oauth/providers/{provider}/connect",
            post(connect_oauth_provider_post_handler),
        )
        .route("/oauth/callback/api", get(oauth_api_callback_handler))
        .with_state(state)
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Encode OAuth state with embedded session ID for stateless callback handling
///
/// Format: `{csrf_token}:{session_id}`
///
/// This allows the OAuth callback to identify the session without cookies or
/// query parameters, making the flow work across web, mobile, and CLI contexts.
fn encode_oauth_state(csrf_token: &str, session_id: &str) -> String {
    format!("{}:{}", csrf_token, session_id)
}

/// Decode OAuth state to extract CSRF token and session ID
///
/// Returns `(csrf_token, session_id)` if the state has the expected format,
/// otherwise returns an authentication error.
fn decode_oauth_state(state: &str) -> Result<(String, String)> {
    let mut parts = state.splitn(2, ':');

    match (parts.next(), parts.next()) {
        (Some(csrf), Some(session)) if !csrf.is_empty() && !session.is_empty() => {
            Ok((csrf.to_string(), session.to_string()))
        }
        _ => Err(BeemFlowError::auth(
            "Invalid OAuth state format - expected format: {csrf_token}:{session_id}",
        )),
    }
}

/// Generate a simple HTML error page
fn error_html(title: &str, heading: &str, message: Option<&str>, retry_link: bool) -> String {
    let message_html = message.map_or(String::new(), |msg| format!("    <p>{}</p>\n", msg));
    let retry_html = if retry_link {
        "    <a href=\"/oauth/providers\">Try again</a>\n"
    } else {
        ""
    };

    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>{}</title></head>
<body>
    <h1>{}</h1>
{}{}</body>
</html>"#,
        title, heading, message_html, retry_html
    )
}

// ============================================================================
// OAUTH CLIENT UI HANDLERS
// ============================================================================

async fn oauth_providers_handler(
    State(state): State<Arc<OAuthClientState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // Fetch providers from registry and storage
    let registry_providers = match state.registry_manager.list_oauth_providers().await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to list OAuth providers from registry: {}", e);
            vec![]
        }
    };

    let storage_providers = match state.storage.list_oauth_providers().await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to list OAuth providers from storage: {}", e);
            vec![]
        }
    };

    // Fetch all credentials and build a set of connected provider IDs for O(1) lookup
    let connected_providers: HashSet<String> = match state.storage.list_oauth_credentials().await {
        Ok(credentials) => credentials.iter().map(|c| c.provider.clone()).collect(),
        Err(e) => {
            tracing::error!("Failed to list OAuth credentials: {}", e);
            HashSet::new()
        }
    };

    // Build provider data for template from registry providers
    let mut provider_data: Vec<Value> = registry_providers
        .iter()
        .map(|entry| {
            let name = entry.display_name.as_ref().unwrap_or(&entry.name);
            let icon = entry.icon.as_deref().unwrap_or("🔗");
            let connected = connected_providers.contains(&entry.name);

            json!({
                "id": entry.name,
                "name": name,
                "icon": icon,
                "scopes": entry.scopes.as_deref().unwrap_or(&[]),
                "connected": connected,
            })
        })
        .collect();

    // Add storage providers (custom providers added by users)
    for p in storage_providers.iter() {
        let connected = connected_providers.contains(&p.id);

        provider_data.push(json!({
            "id": p.id,
            "name": p.name,
            "icon": "🔗",
            "scopes": p.scopes.as_deref().map(|scopes| {
                scopes.iter().map(|s| json!({"scope": s, "description": ""})).collect::<Vec<_>>()
            }).unwrap_or_default(),
            "connected": connected,
        }));
    }

    // Check if client wants JSON (for API requests)
    let wants_json = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("application/json"))
        .unwrap_or(false);

    if wants_json {
        // Return JSON for API clients (React frontend)
        return axum::Json(json!({
            "providers": provider_data
        })).into_response();
    }

    // Render template with provider data (for browser HTML requests)
    let template_data = json!({
        "providers": provider_data
    });

    match state
        .template_renderer
        .render_json("providers", &template_data)
    {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Failed to render providers template: {}", e);
            let message = format!("{}", e);
            Html(error_html("Error", "Template Error", Some(&message), false)).into_response()
        }
    }
}

async fn oauth_success_handler() -> impl IntoResponse {
    Html(include_str!("../../static/oauth/success.html"))
}

pub async fn oauth_callback_handler(
    State(state): State<Arc<OAuthClientState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // Check for OAuth error response
    if let Some(error) = params.get("error") {
        let error_desc = params
            .get("error_description")
            .map(|s| s.as_str())
            .unwrap_or("Unknown error");
        tracing::error!("OAuth authorization failed: {} - {}", error, error_desc);
        let message = format!("Error: {}\nDescription: {}", error, error_desc);
        return (
            StatusCode::BAD_REQUEST,
            Html(error_html(
                "OAuth Error",
                "OAuth Authorization Failed",
                Some(&message),
                true,
            )),
        )
            .into_response();
    }

    // Get authorization code and state from query params
    let code = match params.get("code") {
        Some(c) => c,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Html(error_html(
                    "OAuth Error",
                    "Missing Authorization Code",
                    None,
                    true,
                )),
            )
                .into_response();
        }
    };

    let state_param = match params.get("state") {
        Some(s) => s,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Html(error_html(
                    "OAuth Error",
                    "Missing State Parameter",
                    None,
                    true,
                )),
            )
                .into_response();
        }
    };

    // Decode state to extract CSRF token and session ID
    // Format: {csrf_token}:{session_id}
    let (csrf_token, session_id) = match decode_oauth_state(state_param) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to decode OAuth state: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Html(error_html(
                    "OAuth Error",
                    "Invalid State Parameter",
                    Some("The OAuth state parameter is invalid or malformed."),
                    true,
                )),
            )
                .into_response();
        }
    };

    // Look up session by ID (extracted from state parameter)
    let session = match state.session_store.get_session(&session_id) {
        Some(s) => s,
        None => {
            tracing::error!("Invalid or expired session: {}", session_id);
            return (
                StatusCode::BAD_REQUEST,
                Html(error_html(
                    "OAuth Error",
                    "Session Expired",
                    Some("Your session has expired. Please try again."),
                    true,
                )),
            )
                .into_response();
        }
    };

    // Validate CSRF token matches what we stored in the session
    let stored_csrf = match session.data.get("oauth_state").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            tracing::error!("No oauth_state found in session");
            return (
                StatusCode::BAD_REQUEST,
                Html(error_html(
                    "OAuth Error",
                    "Invalid Session",
                    Some("Session is missing OAuth state. Please try again."),
                    true,
                )),
            )
                .into_response();
        }
    };

    if stored_csrf != csrf_token {
        tracing::error!(
            "CSRF token mismatch - possible CSRF attack. Expected: {}, Got: {}",
            stored_csrf,
            csrf_token
        );
        return (
            StatusCode::BAD_REQUEST,
            Html(error_html(
                "OAuth Error",
                "Security Error",
                Some("State parameter mismatch. Possible CSRF attack detected."),
                true,
            )),
        )
            .into_response();
    }

    // Get stored OAuth parameters from session
    let code_verifier = match session
        .data
        .get("oauth_code_verifier")
        .and_then(|v| v.as_str())
    {
        Some(cv) => cv,
        None => {
            tracing::error!("No code_verifier found in session");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(error_html(
                    "OAuth Error",
                    "Session Error",
                    Some("Missing code verifier. Please try again."),
                    true,
                )),
            )
                .into_response();
        }
    };

    let provider_id = match session
        .data
        .get("oauth_provider_id")
        .and_then(|v| v.as_str())
    {
        Some(p) => p,
        None => {
            tracing::error!("No provider_id found in session");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(error_html(
                    "OAuth Error",
                    "Session Error",
                    Some("Missing provider ID. Please try again."),
                    true,
                )),
            )
                .into_response();
        }
    };

    let integration = session
        .data
        .get("oauth_integration")
        .and_then(|v| v.as_str())
        .unwrap_or("default");

    // Exchange authorization code for tokens using oauth2 crate
    match state
        .oauth_client
        .exchange_code(provider_id, code, code_verifier, integration)
        .await
    {
        Ok(credential) => {
            tracing::info!(
                "Successfully exchanged OAuth code for tokens: {}:{}",
                credential.provider,
                credential.integration
            );

            // Clean up session
            state.session_store.delete_session(&session_id);

            // Redirect to success page
            Redirect::to("/oauth/success").into_response()
        }
        Err(e) => {
            tracing::error!("Failed to exchange authorization code: {}", e);

            // Clean up session even on error
            state.session_store.delete_session(&session_id);

            let message = format!("Failed to exchange authorization code for tokens: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(error_html(
                    "OAuth Error",
                    "Token Exchange Failed",
                    Some(&message),
                    true,
                )),
            )
                .into_response()
        }
    }
}

async fn oauth_provider_handler(
    State(state): State<Arc<OAuthClientState>>,
    AxumPath(provider): AxumPath<String>,
) -> impl IntoResponse {
    // Get default scopes for the provider from registry
    let scopes = match state.registry_manager.get_oauth_provider(&provider).await {
        Ok(Some(entry)) => entry
            .scope_strings()
            .unwrap_or_else(|| vec!["read".to_string()]),
        _ => vec!["read".to_string()],
    };

    // Convert Vec<String> to Vec<&str>
    let scope_refs: Vec<&str> = scopes.iter().map(|s| s.as_str()).collect();

    // Create session first (needed for encoding session_id into state)
    let session = state
        .session_store
        .create_session("oauth_flow", chrono::Duration::minutes(10));

    // Generate random CSRF token for security
    let csrf_token = oauth2::CsrfToken::new_random();
    let csrf_secret = csrf_token.secret().clone();

    // Encode session ID into state parameter for stateless callback handling
    let combined_state = encode_oauth_state(&csrf_secret, &session.id);

    // Build authorization URL with custom state (csrf embedded in state parameter)
    let (auth_url, code_verifier) = match state
        .oauth_client
        .build_auth_url(&provider, &scope_refs, None, Some(combined_state))
        .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to build auth URL for {}: {}", provider, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to build authorization URL: {}", e),
            )
                .into_response();
        }
    };

    // Store CSRF token (not combined state!) in session for callback validation
    state
        .session_store
        .update_session(&session.id, "oauth_state".to_string(), json!(csrf_secret));
    state.session_store.update_session(
        &session.id,
        "oauth_code_verifier".to_string(),
        json!(code_verifier),
    );
    state.session_store.update_session(
        &session.id,
        "oauth_provider_id".to_string(),
        json!(provider),
    );
    state.session_store.update_session(
        &session.id,
        "oauth_integration".to_string(),
        json!("default"),
    );

    // Redirect to OAuth provider (session_id is embedded in state parameter)
    (
        StatusCode::FOUND,
        [(axum::http::header::LOCATION, auth_url.as_str())],
    )
        .into_response()
}

// ============================================================================
// OAUTH PROVIDER API HANDLERS
// ============================================================================

/// List all OAuth providers (from both registry and storage)
async fn list_oauth_providers_handler(
    State(state): State<Arc<OAuthClientState>>,
) -> std::result::Result<Json<Value>, StatusCode> {
    // Get built-in providers from registry
    let registry_providers = state
        .registry_manager
        .list_oauth_providers()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Get custom providers from storage
    let storage_providers = state
        .storage
        .list_oauth_providers()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Convert registry entries to simplified provider format
    let mut all_providers: Vec<Value> = registry_providers
        .iter()
        .map(|entry| {
            json!({
                "id": entry.name,
                "name": entry.display_name.as_ref().unwrap_or(&entry.name),
                "auth_url": entry.auth_url,
                "token_url": entry.token_url,
                "scopes": entry.scopes,
                "source": "registry",
                // Don't expose client_id/secret for registry providers
            })
        })
        .collect();

    // Add storage providers
    for provider in storage_providers {
        all_providers.push(json!({
            "id": provider.id,
            "name": provider.name,
            "auth_url": provider.auth_url,
            "token_url": provider.token_url,
            "scopes": provider.scopes,
            "source": "storage",
        }));
    }

    Ok(Json(json!({ "providers": all_providers })))
}

/// Get a specific OAuth provider (checks registry first, then storage)
async fn get_oauth_provider_handler(
    State(state): State<Arc<OAuthClientState>>,
    AxumPath(id): AxumPath<String>,
) -> std::result::Result<Json<Value>, StatusCode> {
    // Check registry first for built-in providers
    if let Some(entry) = state
        .registry_manager
        .get_server(&id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        && entry.entry_type == "oauth_provider"
    {
        return Ok(Json(json!({
            "id": entry.name,
            "name": entry.display_name.as_ref().unwrap_or(&entry.name),
            "auth_url": entry.auth_url,
            "token_url": entry.token_url,
            "scopes": entry.scopes,
            "source": "registry",
            // Don't expose client_id/secret for registry providers
        })));
    }

    // Fall back to storage for custom providers
    let provider = state
        .storage
        .get_oauth_provider(&id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(json!({
        "id": provider.id,
        "name": provider.name,
        "auth_url": provider.auth_url,
        "token_url": provider.token_url,
        "scopes": provider.scopes,
        "source": "storage",
    })))
}

/// Create a new OAuth provider
async fn create_oauth_provider_handler(
    State(state): State<Arc<OAuthClientState>>,
    Json(mut provider): Json<crate::model::OAuthProvider>,
) -> std::result::Result<Json<Value>, StatusCode> {
    // Validate provider
    provider.validate().map_err(|_| StatusCode::BAD_REQUEST)?;

    // Ensure timestamps are set
    let now = chrono::Utc::now();
    provider.created_at = now;
    provider.updated_at = now;

    // Save provider
    state
        .storage
        .save_oauth_provider(&provider)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(json!({
        "success": true,
        "provider": provider,
    })))
}

/// Update an existing OAuth provider
async fn update_oauth_provider_handler(
    State(state): State<Arc<OAuthClientState>>,
    AxumPath(id): AxumPath<String>,
    Json(mut provider): Json<crate::model::OAuthProvider>,
) -> std::result::Result<Json<Value>, StatusCode> {
    // Verify provider exists
    let existing = state
        .storage
        .get_oauth_provider(&id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Update fields while preserving ID and created_at
    provider.id = id;
    provider.created_at = existing.created_at;
    provider.updated_at = chrono::Utc::now();

    // Validate and save
    provider.validate().map_err(|_| StatusCode::BAD_REQUEST)?;
    state
        .storage
        .save_oauth_provider(&provider)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(json!({
        "success": true,
        "provider": provider,
    })))
}

/// Delete an OAuth provider
async fn delete_oauth_provider_handler(
    State(state): State<Arc<OAuthClientState>>,
    AxumPath(id): AxumPath<String>,
) -> std::result::Result<Json<Value>, StatusCode> {
    state
        .storage
        .delete_oauth_provider(&id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "success": true })))
}

// ============================================================================
// OAUTH CREDENTIAL API HANDLERS
// ============================================================================

/// List all OAuth credentials
async fn list_oauth_credentials_handler(
    State(state): State<Arc<OAuthClientState>>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let credentials = state
        .storage
        .list_oauth_credentials()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Redact access tokens for security
    let safe_credentials: Vec<Value> = credentials
        .iter()
        .map(|cred| {
            json!({
                "id": cred.id,
                "provider": cred.provider,
                "integration": cred.integration,
                "scope": cred.scope,
                "expires_at": cred.expires_at,
                "created_at": cred.created_at,
                "updated_at": cred.updated_at,
                "has_refresh_token": cred.refresh_token.is_some(),
            })
        })
        .collect();

    Ok(Json(json!({ "credentials": safe_credentials })))
}

/// Delete an OAuth credential
async fn delete_oauth_credential_handler(
    State(state): State<Arc<OAuthClientState>>,
    AxumPath(id): AxumPath<String>,
) -> std::result::Result<Json<Value>, StatusCode> {
    state
        .storage
        .delete_oauth_credential(&id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "success": true })))
}

/// Initiate OAuth authorization flow for a provider
async fn authorize_oauth_provider_handler(
    State(state): State<Arc<OAuthClientState>>,
    AxumPath(provider_id): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
) -> std::result::Result<Json<Value>, StatusCode> {
    // Get scopes from query parameters (comma-separated)
    let scopes = params
        .get("scopes")
        .map(|s| s.split(',').map(|s| s.trim()).collect::<Vec<_>>())
        .unwrap_or_else(|| vec!["read"]);

    // Get integration name (optional)
    let integration = params.get("integration").map(|s| s.as_str());

    // Create session first (needed for encoding session_id into state)
    let session = state
        .session_store
        .create_session("oauth_flow", chrono::Duration::minutes(10));

    // Generate random CSRF token for security
    let csrf_token = oauth2::CsrfToken::new_random();
    let csrf_secret = csrf_token.secret().clone();

    // Encode session ID into state parameter for stateless callback handling
    // Format: {csrf_token}:{session_id}
    // This eliminates the need for cookies or query parameters in the callback
    let combined_state = encode_oauth_state(&csrf_secret, &session.id);

    // Build authorization URL with custom state (csrf embedded in state parameter)
    let (auth_url, code_verifier) = state
        .oauth_client
        .build_auth_url(&provider_id, &scopes, integration, Some(combined_state))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Store CSRF token (not combined state!) in session for callback validation
    state
        .session_store
        .update_session(&session.id, "oauth_state".to_string(), json!(csrf_secret));
    state.session_store.update_session(
        &session.id,
        "oauth_code_verifier".to_string(),
        json!(code_verifier),
    );
    state.session_store.update_session(
        &session.id,
        "oauth_provider_id".to_string(),
        json!(provider_id),
    );
    state.session_store.update_session(
        &session.id,
        "oauth_integration".to_string(),
        json!(integration.unwrap_or("default")),
    );

    // Return authorization URL (session_id is now embedded in the state parameter)
    Ok(Json(json!({
        "authorization_url": auth_url,
        "expires_at": session.expires_at,
    })))
}

/// Handle OAuth connection initiation (POST version for React frontend)
async fn connect_oauth_provider_post_handler(
    State(state): State<Arc<OAuthClientState>>,
    AxumPath(provider_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> std::result::Result<Json<Value>, StatusCode> {
    // Extract scopes from JSON body
    let scopes: Vec<&str> = body
        .get("scopes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .collect()
        })
        .unwrap_or_else(|| vec!["read"]);

    // Get integration name (optional)
    let integration = body.get("integration").and_then(|v| v.as_str());

    // Create session first (needed for encoding session_id into state)
    let session = state
        .session_store
        .create_session("oauth_flow", chrono::Duration::minutes(10));

    // Generate random CSRF token for security
    let csrf_token = oauth2::CsrfToken::new_random();
    let csrf_secret = csrf_token.secret().clone();

    // Encode session ID into state parameter for stateless callback handling
    let combined_state = encode_oauth_state(&csrf_secret, &session.id);

    // Build authorization URL with custom state
    let (auth_url, code_verifier) = state
        .oauth_client
        .build_auth_url(&provider_id, &scopes, integration, Some(combined_state))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Store CSRF token in session for callback validation
    state
        .session_store
        .update_session(&session.id, "oauth_state".to_string(), json!(csrf_secret));
    state.session_store.update_session(
        &session.id,
        "oauth_code_verifier".to_string(),
        json!(code_verifier),
    );
    state.session_store.update_session(
        &session.id,
        "oauth_provider_id".to_string(),
        json!(provider_id.clone()),
    );
    state.session_store.update_session(
        &session.id,
        "oauth_integration".to_string(),
        json!(integration.unwrap_or("default")),
    );

    // Return response matching frontend expectations
    Ok(Json(json!({
        "auth_url": auth_url,
        "provider_id": provider_id,
    })))
}

/// Handle OAuth callback and exchange code for tokens
async fn oauth_api_callback_handler(
    State(state): State<Arc<OAuthClientState>>,
    Query(params): Query<HashMap<String, String>>,
) -> std::result::Result<Json<Value>, StatusCode> {
    // Check for OAuth provider errors first (e.g., user denied access)
    if let Some(error) = params.get("error") {
        let error_desc = params
            .get("error_description")
            .map(|s| s.as_str())
            .unwrap_or("Unknown OAuth error");

        tracing::warn!("OAuth provider error: {} - {}", error, error_desc);
        return Err(StatusCode::BAD_REQUEST);
    }

    // Get authorization code and state from OAuth provider
    let code = params.get("code").ok_or(StatusCode::BAD_REQUEST)?;
    let state_param = params.get("state").ok_or(StatusCode::BAD_REQUEST)?;

    // Decode state to extract CSRF token and session ID
    // Format: {csrf_token}:{session_id}
    let (csrf_token, session_id) =
        decode_oauth_state(state_param).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Look up session by ID (extracted from state parameter)
    let session = state
        .session_store
        .get_session(&session_id)
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Validate CSRF token matches what we stored in the session
    let stored_csrf = session
        .data
        .get("oauth_state")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;

    if stored_csrf != csrf_token {
        return Err(StatusCode::FORBIDDEN);
    }

    // Get stored code_verifier and provider_id
    let code_verifier = session
        .data
        .get("oauth_code_verifier")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;

    let provider_id = session
        .data
        .get("oauth_provider_id")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;

    let stored_integration = session
        .data
        .get("oauth_integration")
        .and_then(|v| v.as_str())
        .unwrap_or("default");

    // Exchange code for tokens
    let credential = state
        .oauth_client
        .exchange_code(provider_id, code, code_verifier, stored_integration)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Clean up session
    state.session_store.delete_session(&session_id);

    Ok(Json(json!({
        "success": true,
        "credential": {
            "id": credential.id,
            "provider": credential.provider,
            "integration": credential.integration,
            "scope": credential.scope,
            "expires_at": credential.expires_at,
            "created_at": credential.created_at,
        }
    })))
}

#[cfg(test)]
mod client_test {
    include!("client_test.rs");
}
