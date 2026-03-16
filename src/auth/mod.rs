//! Authentication and authorization system
//!
//! Provides comprehensive auth for BeemFlow:
//! - **Multi-organization**: Organization-based isolation with RBAC
//! - **JWT Auth**: Stateless authentication with refresh tokens
//! - **OAuth Server**: OAuth 2.1 authorization server for MCP tools
//! - **OAuth Client**: OAuth 2.0 client for external providers
//! - **RBAC**: Role-based access control (Owner, Admin, Member, Viewer)

use crate::{Result, model::*};
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ============================================================================
// Core Auth Types
// ============================================================================

/// User account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub email_verified: bool,
    pub avatar_url: Option<String>,
    pub mfa_enabled: bool,
    #[serde(skip_serializing)]
    pub mfa_secret: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub disabled: bool,
    pub disabled_reason: Option<String>,
    pub disabled_at: Option<DateTime<Utc>>,
}

/// Organization (Workspace/Team)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub plan: String,
    pub plan_starts_at: Option<DateTime<Utc>>,
    pub plan_ends_at: Option<DateTime<Utc>>,
    pub max_users: i32,
    pub max_flows: i32,
    pub max_runs_per_month: i32,
    pub settings: Option<serde_json::Value>,
    pub created_by_user_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub disabled: bool,
}

/// User role within an organization
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Admin,
    Member,
    Viewer,
}

impl std::str::FromStr for Role {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "owner" => Ok(Role::Owner),
            "admin" => Ok(Role::Admin),
            "member" => Ok(Role::Member),
            "viewer" => Ok(Role::Viewer),
            _ => Err(format!("Invalid role: {}", s)),
        }
    }
}

impl Role {
    /// Convert role to string
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Admin => "admin",
            Role::Member => "member",
            Role::Viewer => "viewer",
        }
    }

    /// Check if role has a specific permission
    pub fn has_permission(&self, permission: Permission) -> bool {
        use Permission::*;

        match self {
            // Owner has all permissions
            Role::Owner => true,

            // Admin has all permissions except deleting the organization
            Role::Admin => !matches!(permission, OrgDelete),

            // Member has limited permissions
            Role::Member => matches!(
                permission,
                FlowsRead
                    | FlowsCreate
                    | FlowsUpdate
                    | RunsRead
                    | RunsTrigger
                    | RunsCancel
                    | OAuthConnect
                    | MembersRead
                    | ToolsRead
            ),

            // Viewer has read-only permissions
            Role::Viewer => matches!(permission, FlowsRead | RunsRead | MembersRead | ToolsRead),
        }
    }

    /// Get all permissions for this role
    pub fn permissions(&self) -> Vec<Permission> {
        use Permission::*;

        let all_permissions = vec![
            FlowsRead,
            FlowsCreate,
            FlowsUpdate,
            FlowsDelete,
            FlowsDeploy,
            RunsRead,
            RunsTrigger,
            RunsCancel,
            RunsDelete,
            OAuthConnect,
            OAuthDisconnect,
            SecretsRead,
            SecretsCreate,
            SecretsUpdate,
            SecretsDelete,
            ToolsRead,
            ToolsInstall,
            OrgRead,
            OrgUpdate,
            OrgDelete,
            MembersRead,
            MembersInvite,
            MembersUpdateRole,
            MembersRemove,
            AuditLogsRead,
        ];

        all_permissions
            .into_iter()
            .filter(|p| self.has_permission(*p))
            .collect()
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Organization member (user-organization relationship)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationMember {
    pub id: String,
    pub organization_id: String,
    pub user_id: String,
    pub role: Role,
    pub invited_by_user_id: Option<String>,
    pub invited_at: Option<DateTime<Utc>>,
    pub joined_at: DateTime<Utc>,
    pub disabled: bool,
}

/// Organization membership in JWT
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Membership {
    /// Organization ID
    pub organization_id: String,
    /// User's role in this organization
    pub role: Role,
}

/// JWT token claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject (user_id)
    pub sub: String,
    /// User email (for debugging/logging)
    pub email: String,
    /// All organization memberships
    pub memberships: Vec<Membership>,
    /// Expiration timestamp (seconds since epoch)
    pub exp: usize,
    /// Issued at timestamp (seconds since epoch)
    pub iat: usize,
    /// Issuer
    pub iss: String,
}

/// Refresh token (stored in database)
///
/// Refresh tokens are user-scoped (not organization-scoped).
/// When refreshed, the new JWT includes ALL user's organization memberships.
/// The client specifies which org to use via X-Organization-ID header.
#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub user_agent: Option<String>,
    pub client_ip: Option<String>,
}

/// Authenticated user context (extracted from JWT)
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user_id: String,
    pub organization_id: String,
    pub role: Role,
    pub token_exp: usize,
}

/// Full request context with organization information
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub user_id: String,
    pub organization_id: String,
    pub organization_name: String,
    pub role: Role,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: String,
}

/// Registration request
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub name: Option<String>,
}

/// Login request
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Login/registration response
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64, // seconds
    pub user: UserInfo,
    pub organization: OrganizationInfo,
}

/// User info (public subset)
#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
}

/// Organization info
#[derive(Debug, Serialize)]
pub struct OrganizationInfo {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub role: Role,
}

/// Refresh token request
#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

/// System permissions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    // Flow permissions
    FlowsRead,
    FlowsCreate,
    FlowsUpdate,
    FlowsDelete,
    FlowsDeploy,

    // Run permissions
    RunsRead,
    RunsTrigger,
    RunsCancel,
    RunsDelete,

    // OAuth permissions
    OAuthConnect,
    OAuthDisconnect,

    // Secret permissions
    SecretsRead,
    SecretsCreate,
    SecretsUpdate,
    SecretsDelete,

    // Tool permissions
    ToolsRead,
    ToolsInstall,

    // Organization permissions
    OrgRead,
    OrgUpdate,
    OrgDelete,

    // Member management
    MembersRead,
    MembersInvite,
    MembersUpdateRole,
    MembersRemove,

    // Audit logs
    AuditLogsRead,
}

// ============================================================================
// Submodules
// ============================================================================

pub mod client;
pub mod handlers;
pub mod jwt;
pub mod management;
pub mod middleware;
pub mod password;
pub mod rbac;
pub mod server;

// OAuth re-exports
pub use client::{
    OAuthClientManager, create_protected_oauth_client_routes, create_public_oauth_client_routes,
    create_test_oauth_client,
};
pub use server::{OAuthConfig, OAuthServerState, create_oauth_routes};

// Middleware re-exports (both OAuth and JWT)
pub use middleware::{
    // JWT middleware
    AuthMiddlewareState,
    // OAuth middleware
    AuthenticatedUser,
    OAuthMiddlewareState,
    RequiredScopes,
    auth_middleware,
    has_all_scopes,
    has_any_scope,
    has_scope,
    oauth_middleware,
    organization_middleware,
    rate_limit_middleware,
    validate_token,
};

// Multi-organization auth re-exports
pub use handlers::{AuthState, create_auth_routes};
pub use jwt::{EncryptedToken, JwtManager, TokenEncryption, ValidatedJwtSecret};
pub use management::create_management_routes;
pub use password::{hash_password, validate_password_strength, verify_password};
pub use rbac::{
    check_all_permissions, check_any_permission, check_can_invite_role, check_can_update_role,
    check_permission, check_resource_ownership,
};

/// OAuth server for providing authentication
pub struct OAuthServer {
    providers: Arc<RwLock<Vec<OAuthProvider>>>,
    clients: Arc<RwLock<Vec<OAuthClient>>>,
}

impl OAuthServer {
    /// Create a new OAuth server
    pub fn new() -> Self {
        Self {
            providers: Arc::new(RwLock::new(Vec::new())),
            clients: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register an OAuth provider
    pub fn register_provider(&self, provider: OAuthProvider) -> Result<()> {
        provider.validate()?;
        self.providers.write().push(provider);
        Ok(())
    }

    /// Register an OAuth client
    pub fn register_client(&self, client: OAuthClient) -> Result<()> {
        self.clients.write().push(client);
        Ok(())
    }
}

impl Default for OAuthServer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod middleware_test;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_from_str() {
        assert_eq!("owner".parse::<Role>().ok(), Some(Role::Owner));
        assert_eq!("ADMIN".parse::<Role>().ok(), Some(Role::Admin));
        assert_eq!("member".parse::<Role>().ok(), Some(Role::Member));
        assert_eq!("viewer".parse::<Role>().ok(), Some(Role::Viewer));
        assert!("invalid".parse::<Role>().is_err());
    }

    #[test]
    fn test_role_permissions() {
        // Owner has all permissions
        assert!(Role::Owner.has_permission(Permission::OrgDelete));
        assert!(Role::Owner.has_permission(Permission::FlowsDelete));

        // Admin has all except org delete
        assert!(!Role::Admin.has_permission(Permission::OrgDelete));
        assert!(Role::Admin.has_permission(Permission::FlowsDelete));
        assert!(Role::Admin.has_permission(Permission::MembersRemove));

        // Member has limited permissions
        assert!(Role::Member.has_permission(Permission::FlowsRead));
        assert!(Role::Member.has_permission(Permission::FlowsCreate));
        assert!(!Role::Member.has_permission(Permission::FlowsDelete));
        assert!(!Role::Member.has_permission(Permission::MembersRemove));

        // Viewer is read-only
        assert!(Role::Viewer.has_permission(Permission::FlowsRead));
        assert!(!Role::Viewer.has_permission(Permission::FlowsCreate));
        assert!(!Role::Viewer.has_permission(Permission::FlowsDelete));
    }

    #[test]
    fn test_role_display() {
        assert_eq!(Role::Owner.to_string(), "owner");
        assert_eq!(Role::Admin.to_string(), "admin");
        assert_eq!(Role::Member.to_string(), "member");
        assert_eq!(Role::Viewer.to_string(), "viewer");
    }
}
