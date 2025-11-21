//! Authentication middleware for both OAuth and JWT
//!
//! Provides two types of authentication:
//! 1. OAuth 2.0 middleware (for OAuth client - validates OAuth tokens)
//! 2. JWT middleware (for multi-tenant auth - validates JWTs, resolves tenants)

use super::{AuthContext, JwtClaims, JwtManager, RequestContext};
use crate::audit::{AuditEvent, AuditLogger};
use crate::model::OAuthToken;
use crate::storage::Storage;
use crate::{BeemFlowError, Result};
use axum::{
    extract::{FromRequestParts, Request, State},
    http::{StatusCode, header, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration as StdDuration, SystemTime};
use uuid::Uuid;

// ============================================================================
// OAuth 2.0 Middleware (for OAuth client)
// ============================================================================

/// Authenticated user extracted from valid Bearer token
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub token: OAuthToken,
}

/// Required scopes for an endpoint
#[derive(Debug, Clone)]
pub struct RequiredScopes(pub Vec<String>);

impl RequiredScopes {
    pub fn any(scopes: &[&str]) -> Self {
        Self(scopes.iter().map(|s| s.to_string()).collect())
    }

    pub fn all(scopes: &[&str]) -> Self {
        Self(scopes.iter().map(|s| s.to_string()).collect())
    }
}

/// Scope validation strategy
pub trait ScopeValidator: Send + Sync {
    /// Check if provided scopes satisfy requirements
    fn validate(&self, provided: &[String], required: &RequiredScopes) -> bool;
}

/// Require ANY of the specified scopes
pub struct AnyScopeValidator;

impl ScopeValidator for AnyScopeValidator {
    fn validate(&self, provided: &[String], required: &RequiredScopes) -> bool {
        required.0.iter().any(|req| provided.contains(req))
    }
}

/// Require ALL of the specified scopes
pub struct AllScopesValidator;

impl ScopeValidator for AllScopesValidator {
    fn validate(&self, provided: &[String], required: &RequiredScopes) -> bool {
        required.0.iter().all(|req| provided.contains(req))
    }
}

/// State for OAuth middleware
#[derive(Clone)]
pub struct OAuthMiddlewareState {
    pub storage: Arc<dyn Storage>,
    pub rate_limiter: Arc<RwLock<HashMap<String, Vec<SystemTime>>>>,
    pub rate_limit_requests: usize,
    pub rate_limit_window: StdDuration,
}

impl OAuthMiddlewareState {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self {
            storage,
            rate_limiter: Arc::new(RwLock::new(HashMap::new())),
            rate_limit_requests: 100,
            rate_limit_window: StdDuration::from_secs(60),
        }
    }

    pub fn with_rate_limit(mut self, requests: usize, window: StdDuration) -> Self {
        self.rate_limit_requests = requests;
        self.rate_limit_window = window;
        self
    }
}

/// Extractor for authenticated user from Bearer token
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = std::result::Result<Self, Self::Rejection>> + Send {
        // Extract data from parts before moving into async block
        let oauth_state = parts.extensions.get::<OAuthMiddlewareState>().cloned();

        let token_result: std::result::Result<String, (StatusCode, String)> = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "Missing Authorization header".to_string(),
            ))
            .and_then(|auth_header| {
                auth_header
                    .strip_prefix("Bearer ")
                    .map(|s| s.to_string())
                    .ok_or((
                        StatusCode::UNAUTHORIZED,
                        "Invalid Authorization header format".to_string(),
                    ))
            });

        async move {
            // Get OAuth middleware state from extensions (set by middleware)
            let oauth_state = oauth_state.ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "OAuth middleware not configured".to_string(),
            ))?;

            let token = token_result?;

            // Validate token against storage
            let oauth_token = oauth_state
                .storage
                .get_oauth_token_by_access(&token)
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Storage error: {}", e),
                    )
                })?
                .ok_or((
                    StatusCode::UNAUTHORIZED,
                    "Invalid or expired token".to_string(),
                ))?;

            // Check token expiration
            if let (Some(created), Some(expires_in)) =
                (oauth_token.access_create_at, oauth_token.access_expires_in)
            {
                let expires_at = created
                    + chrono::Duration::from_std(expires_in).map_err(|_| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Invalid duration".to_string(),
                        )
                    })?;

                if Utc::now() > expires_at {
                    return Err((StatusCode::UNAUTHORIZED, "Token expired".to_string()));
                }
            }

            // Parse scopes
            let scopes: Vec<String> = oauth_token
                .scope
                .split_whitespace()
                .map(String::from)
                .collect();

            Ok(AuthenticatedUser {
                user_id: oauth_token.user_id.clone(),
                client_id: oauth_token.client_id.clone(),
                scopes,
                token: oauth_token,
            })
        }
    }
}

/// Extractor for authenticated user with required scopes
pub struct AuthenticatedUserWithScopes<V: ScopeValidator = AnyScopeValidator> {
    pub user: AuthenticatedUser,
    _validator: std::marker::PhantomData<V>,
}

impl<V: ScopeValidator + Default> AuthenticatedUserWithScopes<V> {
    pub fn new(
        user: AuthenticatedUser,
        required: &RequiredScopes,
    ) -> std::result::Result<Self, (StatusCode, String)> {
        let validator = V::default();
        if validator.validate(&user.scopes, required) {
            Ok(Self {
                user,
                _validator: std::marker::PhantomData,
            })
        } else {
            Err((StatusCode::FORBIDDEN, "Insufficient scopes".to_string()))
        }
    }
}

impl Default for AnyScopeValidator {
    fn default() -> Self {
        Self
    }
}

impl Default for AllScopesValidator {
    fn default() -> Self {
        Self
    }
}

/// Middleware to inject OAuth state into request extensions
pub async fn oauth_middleware(req: Request, next: Next) -> Response {
    // OAuth state should be in app state, extract and add to extensions
    // This allows extractors to access it
    // Note: This is set up in the router configuration
    next.run(req).await
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    req: Request,
    next: Next,
    oauth_state: Arc<OAuthMiddlewareState>,
) -> Response {
    // Extract client identifier (IP or OAuth client_id)
    let identifier = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(String::from)
        .unwrap_or_else(|| {
            req.headers()
                .get("X-Forwarded-For")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .to_string()
        });

    // Check rate limit (scope the lock tightly to avoid holding across await)
    let is_rate_limited = {
        let mut rate_limiter = oauth_state.rate_limiter.write();
        let now = SystemTime::now();
        let window_start = now - oauth_state.rate_limit_window;

        let requests = rate_limiter.entry(identifier.clone()).or_default();

        // Remove old requests outside the window
        requests.retain(|&time| time > window_start);

        // Check if limit exceeded
        if requests.len() >= oauth_state.rate_limit_requests {
            true
        } else {
            // Add current request
            requests.push(now);
            false
        }
    };

    if is_rate_limited {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
    }

    next.run(req).await
}

/// Validate token and return authenticated user
pub async fn validate_token(storage: &Arc<dyn Storage>, token: &str) -> Result<AuthenticatedUser> {
    // Get token from storage
    let oauth_token = storage
        .get_oauth_token_by_access(token)
        .await?
        .ok_or_else(|| BeemFlowError::auth("Invalid or expired token"))?;

    // Check token expiration
    if let (Some(created), Some(expires_in)) =
        (oauth_token.access_create_at, oauth_token.access_expires_in)
    {
        let expires_at = created
            + chrono::Duration::from_std(expires_in)
                .map_err(|_| BeemFlowError::auth("Invalid duration"))?;

        if Utc::now() > expires_at {
            return Err(BeemFlowError::auth("Token expired"));
        }
    }

    // Parse scopes
    let scopes: Vec<String> = oauth_token
        .scope
        .split_whitespace()
        .map(String::from)
        .collect();

    Ok(AuthenticatedUser {
        user_id: oauth_token.user_id.clone(),
        client_id: oauth_token.client_id.clone(),
        scopes,
        token: oauth_token,
    })
}

/// Check if user has required scopes
pub fn has_scope(user: &AuthenticatedUser, scope: &str) -> bool {
    user.scopes.iter().any(|s| s == scope)
}

/// Check if user has any of the required scopes
pub fn has_any_scope(user: &AuthenticatedUser, scopes: &[&str]) -> bool {
    scopes.iter().any(|scope| has_scope(user, scope))
}

/// Check if user has all of the required scopes
pub fn has_all_scopes(user: &AuthenticatedUser, scopes: &[&str]) -> bool {
    scopes.iter().all(|scope| has_scope(user, scope))
}

// ============================================================================
// JWT Middleware (for multi-tenant auth)
// ============================================================================

/// Shared state for JWT auth middleware
pub struct AuthMiddlewareState {
    pub storage: Arc<dyn Storage>,
    pub jwt_manager: Arc<JwtManager>,
    pub audit_logger: Option<Arc<AuditLogger>>,
}

/// Authentication middleware - validates JWT and creates AuthContext
///
/// Extracts Bearer token, validates JWT signature and expiration,
/// and inserts AuthContext into request extensions.
///
/// Returns 401 if:
/// - No Authorization header
/// - Invalid Bearer format
/// - Invalid or expired JWT
pub async fn auth_middleware(
    State(state): State<Arc<AuthMiddlewareState>>,
    mut req: Request,
    next: Next,
) -> std::result::Result<Response, StatusCode> {
    // Extract Authorization header
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Extract Bearer token
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Validate JWT
    let claims = state.jwt_manager.validate_token(token).map_err(|e| {
        tracing::warn!("JWT validation failed: {}", e);
        StatusCode::UNAUTHORIZED
    })?;

    // Create simplified auth context (organization/role determined by organization_middleware)
    let auth_ctx = AuthContext {
        user_id: claims.sub.clone(),
        organization_id: String::new(), // Filled by organization_middleware
        role: super::Role::Viewer,      // Filled by organization_middleware
        token_exp: claims.exp,
    };

    // Insert both Claims and AuthContext
    req.extensions_mut().insert(claims);
    req.extensions_mut().insert(auth_ctx);

    Ok(next.run(req).await)
}

/// Organization middleware - validates organization header and creates RequestContext
///
/// HEADER-BASED ORGANIZATION SELECTION (Stripe/Twilio pattern):
/// 1. Client sends X-Organization-ID header with each request
/// 2. Middleware validates user is a member (checks JWT's memberships array)
/// 3. Creates RequestContext with organization_id and role from validated membership
///
/// Returns:
/// - 400 if X-Organization-ID header missing
/// - 401 if no JWT Claims (must run after auth_middleware)
/// - 403 if user is not a member of requested organization
/// - 403 if organization or membership is disabled
pub async fn organization_middleware(
    State(state): State<Arc<AuthMiddlewareState>>,
    mut req: Request,
    next: Next,
) -> std::result::Result<Response, StatusCode> {
    // Get JWT claims from previous auth middleware
    let claims = req
        .extensions()
        .get::<JwtClaims>()
        .ok_or(StatusCode::UNAUTHORIZED)?
        .clone();

    // Extract requested organization from header
    let requested_organization = req
        .headers()
        .get("X-Organization-ID")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            tracing::warn!("Missing X-Organization-ID header");
            StatusCode::BAD_REQUEST
        })?;

    // Validate user is member of requested organization
    let membership = claims
        .memberships
        .iter()
        .find(|m| m.organization_id == requested_organization)
        .ok_or_else(|| {
            tracing::warn!(
                "User {} not a member of organization {}",
                claims.sub,
                requested_organization
            );
            StatusCode::FORBIDDEN
        })?;

    // Get organization info to check if disabled
    let organization = state
        .storage
        .get_organization(requested_organization)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get organization: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            tracing::warn!("Organization not found: {}", requested_organization);
            StatusCode::NOT_FOUND
        })?;

    // Verify user membership status in database (in case it changed since JWT issued)
    let member = state
        .storage
        .get_organization_member(requested_organization, &claims.sub)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get organization member: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            tracing::warn!(
                "User {} membership in organization {} not found in database",
                claims.sub,
                requested_organization
            );
            StatusCode::FORBIDDEN
        })?;

    // Check if organization or membership is disabled
    if organization.disabled || member.disabled {
        tracing::warn!(
            "Access denied: organization_disabled={}, member_disabled={}",
            organization.disabled,
            member.disabled
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Extract client metadata
    let client_ip = extract_client_ip(&req);
    let user_agent = extract_user_agent(&req);
    let request_id = Uuid::new_v4().to_string();

    // Create full request context with validated org and role from membership
    let req_ctx = RequestContext {
        user_id: claims.sub.clone(),
        organization_id: requested_organization.to_string(),
        organization_name: organization.name.clone(),
        role: membership.role, // Role from JWT membership (validated above)
        client_ip,
        user_agent,
        request_id,
    };

    // Insert full context into request
    req.extensions_mut().insert(req_ctx);

    Ok(next.run(req).await)
}

/// Extract client IP from request headers or connection info
fn extract_client_ip(req: &Request) -> Option<String> {
    // Try X-Forwarded-For header first (for reverse proxy setups)
    req.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next().map(|ip| ip.trim().to_string()))
        .or_else(|| {
            // Fallback to connection info
            req.extensions()
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|info| info.0.ip().to_string())
        })
}

/// Extract user agent from request headers
fn extract_user_agent(req: &Request) -> Option<String> {
    req.headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Audit logging middleware - logs all authenticated API requests
///
/// Automatically logs:
/// - HTTP method, path, status code
/// - User, organization, request ID
/// - Client IP and user agent
/// - Success/failure status
///
/// Should be applied AFTER auth_middleware and organization_middleware
/// so RequestContext is available.
pub async fn audit_middleware(
    State(state): State<Arc<AuthMiddlewareState>>,
    req: Request,
    next: Next,
) -> Response {
    // Get request context (if authenticated)
    let req_ctx = req.extensions().get::<RequestContext>().cloned();

    // Extract request details before consuming the request
    let method = req.method().to_string();
    let path = req.uri().path().to_string();

    // Execute request
    let response = next.run(req).await;

    // Log the request if we have an audit logger and request context
    if let Some(audit_logger) = &state.audit_logger
        && let Some(ctx) = req_ctx
    {
        let status_code = response.status().as_u16() as i32;
        let success = (200..400).contains(&status_code);

        // Determine action from HTTP method + path
        let action = format!(
            "api.{}.{}",
            method.to_lowercase(),
            path.trim_start_matches('/').replace('/', ".")
        );

        // Log asynchronously (don't block response)
        let logger = audit_logger.clone();
        tokio::spawn(async move {
            let _ = logger
                .log(AuditEvent {
                    request_id: ctx.request_id.clone(),
                    organization_id: ctx.organization_id.clone(),
                    user_id: Some(ctx.user_id.clone()),
                    client_ip: ctx.client_ip.clone(),
                    user_agent: ctx.user_agent.clone(),
                    action,
                    resource_type: None,
                    resource_id: None,
                    resource_name: None,
                    http_method: Some(method),
                    http_path: Some(path),
                    http_status_code: Some(status_code),
                    success,
                    error_message: None,
                    metadata: None,
                })
                .await;
        });
    }

    response
}
