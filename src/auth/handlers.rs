//! HTTP handlers for authentication
//!
//! Provides registration, login, token refresh, and logout endpoints.
use super::{
    LoginRequest, LoginResponse, OrganizationInfo, RefreshRequest, RegisterRequest, Role, UserInfo,
};
use super::{
    Organization, OrganizationMember, RefreshToken, User,
    jwt::JwtManager,
    password::{hash_password, validate_password_strength, verify_password},
};
use crate::audit::{AuditEvent, AuditLogger, actions};
use crate::constants::DEFAULT_ORGANIZATION_ID;
use crate::http::AppError;
use crate::storage::Storage;
use crate::{BeemFlowError, Result};
use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
use chrono::Utc;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// Application state for auth handlers
pub struct AuthState {
    pub storage: Arc<dyn Storage>,
    pub jwt_manager: Arc<JwtManager>,
    pub audit_logger: Arc<AuditLogger>,
}

/// Create authentication router
pub fn create_auth_routes(state: Arc<AuthState>) -> Router {
    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .with_state(state)
}

/// POST /auth/register - Register new user and create default organization
async fn register(
    State(state): State<Arc<AuthState>>,
    Json(req): Json<RegisterRequest>,
) -> std::result::Result<Json<LoginResponse>, AppError> {
    // 1. Validate email format
    if !is_valid_email(&req.email) {
        return Err(BeemFlowError::validation("Invalid email address").into());
    }

    // 2. Validate password strength
    validate_password_strength(&req.password)?;

    // 3. Check if email already exists
    if state.storage.get_user_by_email(&req.email).await?.is_some() {
        return Err(BeemFlowError::validation("Email already registered").into());
    }

    // 4. Hash password
    let password_hash = hash_password(&req.password)?;

    // 5. Create user
    let user_id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let user = User {
        id: user_id.clone(),
        email: req.email.clone(),
        name: req.name.clone(),
        password_hash,
        email_verified: false,
        avatar_url: None,
        mfa_enabled: false,
        mfa_secret: None,
        created_at: now,
        updated_at: now,
        last_login_at: None,
        disabled: false,
        disabled_reason: None,
        disabled_at: None,
    };

    state.storage.create_user(&user).await?;

    // 6. Create default organization for user
    let organization_id = Uuid::new_v4().to_string();
    let organization_slug = generate_unique_slug(&state.storage, &req.email).await?;

    let organization = Organization {
        id: organization_id.clone(),
        name: req
            .name
            .clone()
            .unwrap_or_else(|| "My Workspace".to_string()),
        slug: organization_slug.clone(),
        plan: "free".to_string(),
        plan_starts_at: Some(now),
        plan_ends_at: None,
        max_users: 5,
        max_flows: 10,
        max_runs_per_month: 1000,
        settings: None,
        created_by_user_id: user_id.clone(),
        created_at: now,
        updated_at: now,
        disabled: false,
    };

    state.storage.create_organization(&organization).await?;

    // 7. Add user as organization owner
    let member = OrganizationMember {
        id: Uuid::new_v4().to_string(),
        organization_id: organization_id.clone(),
        user_id: user_id.clone(),
        role: Role::Owner,
        invited_by_user_id: None,
        invited_at: None,
        joined_at: now,
        disabled: false,
    };

    state.storage.create_organization_member(&member).await?;

    // 8. Generate tokens (JWT includes ALL memberships)
    let (access_token, refresh_token_str) =
        generate_tokens(&state, &user_id, &req.email, None).await?;

    // 9. Log registration
    let _ = state
        .audit_logger
        .log(AuditEvent {
            request_id: Uuid::new_v4().to_string(),
            organization_id: organization_id.clone(),
            user_id: Some(user_id.clone()),
            client_ip: None,
            user_agent: None,
            action: actions::USER_REGISTER.to_string(),
            resource_type: Some("user".to_string()),
            resource_id: Some(user_id.clone()),
            resource_name: Some(req.email.clone()),
            http_method: Some("POST".to_string()),
            http_path: Some("/auth/register".to_string()),
            http_status_code: Some(200),
            success: true,
            error_message: None,
            metadata: None,
        })
        .await;

    // 10. Return login response
    Ok(Json(LoginResponse {
        access_token,
        refresh_token: refresh_token_str,
        expires_in: 900, // 15 minutes
        user: UserInfo {
            id: user.id,
            email: user.email,
            name: user.name,
            avatar_url: user.avatar_url,
        },
        organization: OrganizationInfo {
            id: organization.id,
            name: organization.name,
            slug: organization.slug,
            role: Role::Owner,
        },
    }))
}

/// POST /auth/login - Authenticate user
async fn login(
    State(state): State<Arc<AuthState>>,
    Json(login_req): Json<LoginRequest>,
) -> std::result::Result<Json<LoginResponse>, AppError> {
    // 1. Get user by email
    let user = state
        .storage
        .get_user_by_email(&login_req.email)
        .await?
        .ok_or_else(|| BeemFlowError::OAuth("Invalid credentials".into()))?;

    // 2. Verify password
    if !verify_password(&login_req.password, &user.password_hash)? {
        // Log failed login attempt
        let _ = state
            .audit_logger
            .log(AuditEvent {
                request_id: Uuid::new_v4().to_string(),
                organization_id: DEFAULT_ORGANIZATION_ID.to_string(),
                user_id: Some(user.id.clone()),
                client_ip: None,
                user_agent: None,
                action: actions::USER_LOGIN.to_string(),
                resource_type: Some("user".to_string()),
                resource_id: Some(user.id.clone()),
                resource_name: Some(user.email.clone()),
                http_method: Some("POST".to_string()),
                http_path: Some("/auth/login".to_string()),
                http_status_code: Some(401),
                success: false,
                error_message: Some("Invalid credentials".to_string()),
                metadata: None,
            })
            .await;

        return Err(BeemFlowError::OAuth("Invalid credentials".into()).into());
    }

    // 3. Check if account is disabled
    if user.disabled {
        return Err(BeemFlowError::OAuth("Account disabled".into()).into());
    }

    // 4. Get user's default organization (first organization for backward compatibility with LoginResponse)
    let organizations = state.storage.list_user_organizations(&user.id).await?;
    let (organization, role) = organizations
        .first()
        .ok_or_else(|| BeemFlowError::OAuth("No organization found".into()))?;

    // 5. Update last login
    state.storage.update_user_last_login(&user.id).await?;

    // 6. Generate tokens (JWT includes ALL memberships, not just default organization)
    let (access_token, refresh_token_str) = generate_tokens(
        &state,
        &user.id,
        &user.email,
        None, // Client info captured by audit middleware
    )
    .await?;

    // 7. Log successful login
    let _ = state
        .audit_logger
        .log(AuditEvent {
            request_id: Uuid::new_v4().to_string(),
            organization_id: organization.id.clone(),
            user_id: Some(user.id.clone()),
            client_ip: None,
            user_agent: None,
            action: actions::USER_LOGIN.to_string(),
            resource_type: Some("user".to_string()),
            resource_id: Some(user.id.clone()),
            resource_name: Some(user.email.clone()),
            http_method: Some("POST".to_string()),
            http_path: Some("/auth/login".to_string()),
            http_status_code: Some(200),
            success: true,
            error_message: None,
            metadata: None,
        })
        .await;

    // 9. Return response
    Ok(Json(LoginResponse {
        access_token,
        refresh_token: refresh_token_str,
        expires_in: 900,
        user: UserInfo {
            id: user.id,
            email: user.email,
            name: user.name,
            avatar_url: user.avatar_url,
        },
        organization: OrganizationInfo {
            id: organization.id.clone(),
            name: organization.name.clone(),
            slug: organization.slug.clone(),
            role: *role,
        },
    }))
}

/// POST /auth/refresh - Refresh access token using refresh token
async fn refresh(
    State(state): State<Arc<AuthState>>,
    Json(req): Json<RefreshRequest>,
) -> std::result::Result<impl IntoResponse, AppError> {
    // 1. Hash the refresh token to lookup
    let token_hash = hash_token(&req.refresh_token);

    // 2. Get refresh token from database
    let refresh_token = state
        .storage
        .get_refresh_token(&token_hash)
        .await?
        .ok_or_else(|| BeemFlowError::OAuth("Invalid refresh token".into()))?;

    // 3. Check if revoked
    if refresh_token.revoked {
        return Err(BeemFlowError::OAuth("Token revoked".into()).into());
    }

    // 4. Check if expired
    if refresh_token.expires_at < Utc::now() {
        return Err(BeemFlowError::OAuth("Token expired".into()).into());
    }

    // 5. Get user
    let user = state
        .storage
        .get_user(&refresh_token.user_id)
        .await?
        .ok_or_else(|| BeemFlowError::OAuth("User not found".into()))?;

    // Check if user is disabled
    if user.disabled {
        return Err(BeemFlowError::OAuth("Account disabled".into()).into());
    }

    // 6. Generate new access token with ALL memberships
    let (access_token, _new_refresh_token) = generate_tokens(
        &state,
        &refresh_token.user_id,
        &user.email,
        Some((
            refresh_token.client_ip.clone(),
            refresh_token.user_agent.clone(),
        )),
    )
    .await?;

    // Note: We generate a new refresh token but don't return it (security: refresh token rotation)
    // For now, keep the old refresh token valid (simpler - can add rotation later)

    // 7. Update last used timestamp
    state
        .storage
        .update_refresh_token_last_used(&token_hash)
        .await?;

    // 8. Log token refresh (organization_id empty - refresh is user-scoped, not organization-scoped)
    let _ = state
        .audit_logger
        .log(AuditEvent {
            request_id: Uuid::new_v4().to_string(),
            organization_id: String::new(), // Refresh is user-scoped
            user_id: Some(refresh_token.user_id.clone()),
            client_ip: refresh_token.client_ip.clone(),
            user_agent: refresh_token.user_agent.clone(),
            action: actions::TOKEN_REFRESH.to_string(),
            resource_type: Some("token".to_string()),
            resource_id: Some(refresh_token.id),
            resource_name: None,
            http_method: Some("POST".to_string()),
            http_path: Some("/auth/refresh".to_string()),
            http_status_code: Some(200),
            success: true,
            error_message: None,
            metadata: None,
        })
        .await;

    Ok(Json(json!({
        "access_token": access_token,
        "expires_in": 900,
    })))
}

/// POST /auth/logout - Revoke refresh token
async fn logout(
    State(state): State<Arc<AuthState>>,
    Json(req): Json<RefreshRequest>,
) -> std::result::Result<StatusCode, AppError> {
    let token_hash = hash_token(&req.refresh_token);

    // Get token info before revoking (for audit log)
    if let Ok(Some(token)) = state.storage.get_refresh_token(&token_hash).await {
        // Revoke token
        state.storage.revoke_refresh_token(&token_hash).await?;

        // Log logout
        let _ = state
            .audit_logger
            .log(AuditEvent {
                request_id: Uuid::new_v4().to_string(),
                organization_id: String::new(), // Logout is user-scoped, not organization-specific
                user_id: Some(token.user_id),
                client_ip: token.client_ip,
                user_agent: token.user_agent,
                action: actions::USER_LOGOUT.to_string(),
                resource_type: Some("token".to_string()),
                resource_id: Some(token.id),
                resource_name: None,
                http_method: Some("POST".to_string()),
                http_path: Some("/auth/logout".to_string()),
                http_status_code: Some(204),
                success: true,
                error_message: None,
                metadata: None,
            })
            .await;
    }

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate access and refresh tokens for a user
///
/// Fetches ALL user's organization memberships and includes them in the JWT.
/// Client specifies which org to use via X-Organization-ID header on each request.
async fn generate_tokens(
    state: &AuthState,
    user_id: &str,
    email: &str,
    client_info: Option<(Option<String>, Option<String>)>,
) -> Result<(String, String)> {
    use super::Membership;

    // Fetch ALL user's organization memberships from storage
    let user_organizations = state.storage.list_user_organizations(user_id).await?;

    // Convert to Membership vector for JWT
    let memberships: Vec<Membership> = user_organizations
        .into_iter()
        .map(|(organization, role)| Membership {
            organization_id: organization.id,
            role,
        })
        .collect();

    if memberships.is_empty() {
        return Err(BeemFlowError::validation(
            "User has no organization memberships",
        ));
    }

    // Generate JWT access token with ALL memberships
    let access_token = state
        .jwt_manager
        .generate_access_token(user_id, email, memberships)?;

    // Generate refresh token (random secure string)
    let refresh_token_str = generate_secure_token(32);
    let token_hash = hash_token(&refresh_token_str);

    let (client_ip, user_agent) = client_info.unwrap_or((None, None));

    // Refresh token is user-scoped (not organization-scoped)
    let refresh_token = RefreshToken {
        id: Uuid::new_v4().to_string(),
        user_id: user_id.to_string(),
        token_hash,
        expires_at: Utc::now() + chrono::Duration::days(30),
        revoked: false,
        revoked_at: None,
        created_at: Utc::now(),
        last_used_at: None,
        user_agent,
        client_ip,
    };

    state.storage.create_refresh_token(&refresh_token).await?;

    Ok((access_token, refresh_token_str))
}

/// Generate cryptographically secure random token
fn generate_secure_token(bytes: usize) -> String {
    use rand::RngCore;
    let mut token = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut token);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &token)
}

/// Hash a refresh token using SHA-256
fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Generate unique slug from email
async fn generate_unique_slug(storage: &Arc<dyn Storage>, email: &str) -> Result<String> {
    let base_slug = email
        .split('@')
        .next()
        .unwrap_or("workspace")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect::<String>()
        .to_lowercase();

    // Try base slug first
    if storage
        .get_organization_by_slug(&base_slug)
        .await?
        .is_none()
    {
        return Ok(base_slug);
    }

    // Add random suffix if base is taken
    for _ in 0..10 {
        let suffix = Uuid::new_v4()
            .to_string()
            .chars()
            .take(6)
            .collect::<String>();
        let slug = format!("{}-{}", base_slug, suffix);
        if storage.get_organization_by_slug(&slug).await?.is_none() {
            return Ok(slug);
        }
    }

    // Fallback to UUID if all attempts fail
    Ok(Uuid::new_v4().to_string())
}

/// Validate email format (basic check)
fn is_valid_email(email: &str) -> bool {
    email.contains('@')
        && email.contains('.')
        && email.len() > 5
        && !email.starts_with('@')
        && !email.ends_with('@')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_email() {
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("test.user@company.co.uk"));

        assert!(!is_valid_email("invalid"));
        assert!(!is_valid_email("@example.com"));
        assert!(!is_valid_email("user@"));
        assert!(!is_valid_email("a@b"));
    }

    #[test]
    fn test_hash_token() {
        let token1 = "test-token-123";
        let token2 = "test-token-456";

        let hash1 = hash_token(token1);
        let hash2 = hash_token(token2);

        // Different tokens produce different hashes
        assert_ne!(hash1, hash2);

        // Same token produces same hash
        assert_eq!(hash1, hash_token(token1));

        // Hash is SHA-256 (64 hex characters)
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_generate_secure_token() {
        let token1 = generate_secure_token(32);
        let token2 = generate_secure_token(32);

        // Tokens are different
        assert_ne!(token1, token2);

        // Tokens are non-empty
        assert!(!token1.is_empty());
        assert!(!token2.is_empty());

        // Base64 URL-safe format
        assert!(
            token1
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        );
    }
}
