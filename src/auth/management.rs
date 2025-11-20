//! User, organization, and member management endpoints
//!
//! Provides HTTP handlers for profile, organization, team member, and audit log management.

use super::{
    Permission, RequestContext, Role, Organization, OrganizationMember, User,
    password::{hash_password, validate_password_strength, verify_password},
    rbac::check_permission,
};
use crate::audit::AuditLog;
use crate::http::AppError;
use crate::storage::Storage;
use crate::BeemFlowError;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ============================================================================
// Response Types - Public API contracts
// ============================================================================

#[derive(Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub email_verified: bool,
    pub mfa_enabled: bool,
    pub created_at: String,
    pub last_login_at: Option<String>,
}

#[derive(Serialize)]
pub struct OrganizationResponse {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub plan: String,
    pub max_users: i32,
    pub max_flows: i32,
    pub max_runs_per_month: i32,
    pub created_at: String,
    pub role: String,
    pub current: bool,
}

#[derive(Serialize)]
pub struct MemberResponse {
    pub user: UserInfo,
    pub role: String,
}

#[derive(Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
}

// ============================================================================
// Request Types
// ============================================================================

#[derive(Deserialize)]
pub struct UpdateProfileRequest {
    pub name: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct UpdateOrganizationRequest {
    pub name: Option<String>,
}

#[derive(Deserialize)]
pub struct InviteMemberRequest {
    pub email: String,
    pub role: String,
}

#[derive(Deserialize)]
pub struct UpdateRoleRequest {
    pub role: String,
}

#[derive(Deserialize)]
pub struct ListAuditLogsQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ============================================================================
// Helper Functions - DRY principle
// ============================================================================

/// Extract RequestContext from request extensions (DRY - used in all handlers)
fn get_request_context(req: &axum::extract::Request) -> Result<RequestContext, AppError> {
    req.extensions()
        .get::<RequestContext>()
        .cloned()
        .ok_or_else(|| BeemFlowError::validation("Unauthorized").into())
}

/// Convert User to UserResponse (DRY - used in multiple handlers)
fn user_to_response(user: &User) -> UserResponse {
    UserResponse {
        id: user.id.clone(),
        email: user.email.clone(),
        name: user.name.clone(),
        avatar_url: user.avatar_url.clone(),
        email_verified: user.email_verified,
        mfa_enabled: user.mfa_enabled,
        created_at: user.created_at.to_rfc3339(),
        last_login_at: user.last_login_at.map(|dt| dt.to_rfc3339()),
    }
}

/// Convert Organization + role to OrganizationResponse (DRY)
fn organization_to_response(organization: &Organization, role: Role, current_organization_id: &str) -> OrganizationResponse {
    OrganizationResponse {
        id: organization.id.clone(),
        name: organization.name.clone(),
        slug: organization.slug.clone(),
        plan: organization.plan.clone(),
        max_users: organization.max_users,
        max_flows: organization.max_flows,
        max_runs_per_month: organization.max_runs_per_month,
        created_at: organization.created_at.to_rfc3339(),
        role: role.to_string(),
        current: organization.id == current_organization_id,
    }
}

// ============================================================================
// User Profile Handlers
// ============================================================================

/// GET /v1/users/me - Get current user profile
async fn get_profile_handler(
    State(storage): State<Arc<dyn Storage>>,
    req: axum::extract::Request,
) -> Result<Json<UserResponse>, AppError> {
    let req_ctx = get_request_context(&req)?;

    let user = storage
        .get_user(&req_ctx.user_id)
        .await?
        .ok_or_else(|| BeemFlowError::validation("User not found"))?;

    Ok(Json(user_to_response(&user)))
}

/// PUT /v1/users/me - Update user profile
async fn update_profile_handler(
    State(storage): State<Arc<dyn Storage>>,
    req: axum::extract::Request,
) -> Result<Json<UserResponse>, AppError> {
    let (parts, body) = req.into_parts();
    let req_ctx = parts
        .extensions
        .get::<RequestContext>()
        .cloned()
        .ok_or_else(|| BeemFlowError::validation("Unauthorized"))?;

    // Extract JSON payload from body
    let body_bytes = axum::body::to_bytes(body, crate::constants::MAX_REQUEST_BODY_SIZE)
        .await
        .map_err(|_| BeemFlowError::validation("Invalid request body"))?;
    let payload: UpdateProfileRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| BeemFlowError::validation(format!("Invalid JSON: {}", e)))?;

    let mut user = storage
        .get_user(&req_ctx.user_id)
        .await?
        .ok_or_else(|| BeemFlowError::validation("User not found"))?;

    // Update only provided fields
    if let Some(name) = payload.name {
        user.name = Some(name);
    }
    if let Some(avatar_url) = payload.avatar_url {
        user.avatar_url = Some(avatar_url);
    }

    user.updated_at = chrono::Utc::now();
    storage.update_user(&user).await?;

    Ok(Json(user_to_response(&user)))
}

/// POST /v1/users/me/password - Change password
async fn change_password_handler(
    State(storage): State<Arc<dyn Storage>>,
    req: axum::extract::Request,
) -> Result<StatusCode, AppError> {
    let (parts, body) = req.into_parts();
    let req_ctx = parts
        .extensions
        .get::<RequestContext>()
        .cloned()
        .ok_or_else(|| BeemFlowError::validation("Unauthorized"))?;

    let body_bytes = axum::body::to_bytes(body, crate::constants::MAX_REQUEST_BODY_SIZE)
        .await
        .map_err(|_| BeemFlowError::validation("Invalid request body"))?;
    let payload: ChangePasswordRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| BeemFlowError::validation(format!("Invalid JSON: {}", e)))?;

    let mut user = storage
        .get_user(&req_ctx.user_id)
        .await?
        .ok_or_else(|| BeemFlowError::validation("User not found"))?;

    // Verify current password
    if !verify_password(&payload.current_password, &user.password_hash)? {
        return Err(BeemFlowError::validation("Current password is incorrect").into());
    }

    // Validate and hash new password
    validate_password_strength(&payload.new_password)?;
    user.password_hash = hash_password(&payload.new_password)?;
    user.updated_at = chrono::Utc::now();

    storage.update_user(&user).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Organization Handlers
// ============================================================================

/// GET /v1/organizations - List all organizations user is member of
async fn list_organizations_handler(
    State(storage): State<Arc<dyn Storage>>,
    req: axum::extract::Request,
) -> Result<Json<Vec<OrganizationResponse>>, AppError> {
    let req_ctx = get_request_context(&req)?;

    let memberships = storage.list_user_organizations(&req_ctx.user_id).await?;

    let response: Vec<OrganizationResponse> = memberships
        .into_iter()
        .map(|(organization, role)| {
            organization_to_response(&organization, role, &req_ctx.organization_id)
        })
        .collect();

    Ok(Json(response))
}

/// GET /v1/organizations/current - Get current organization from JWT context
async fn get_current_organization_handler(
    State(storage): State<Arc<dyn Storage>>,
    req: axum::extract::Request,
) -> Result<Json<OrganizationResponse>, AppError> {
    let req_ctx = get_request_context(&req)?;

    let organization = storage
        .get_organization(&req_ctx.organization_id)
        .await?
        .ok_or_else(|| BeemFlowError::validation("Organization not found"))?;

    Ok(Json(organization_to_response(&organization, req_ctx.role, &req_ctx.organization_id)))
}

/// PUT /v1/organizations/current - Update current organization
async fn update_organization_handler(
    State(storage): State<Arc<dyn Storage>>,
    req: axum::extract::Request,
) -> Result<Json<OrganizationResponse>, AppError> {
    let (parts, body) = req.into_parts();
    let req_ctx = parts
        .extensions
        .get::<RequestContext>()
        .cloned()
        .ok_or_else(|| BeemFlowError::validation("Unauthorized"))?;

    check_permission(&req_ctx, Permission::OrgUpdate)?;

    let body_bytes = axum::body::to_bytes(body, crate::constants::MAX_REQUEST_BODY_SIZE)
        .await
        .map_err(|_| BeemFlowError::validation("Invalid request body"))?;
    let payload: UpdateOrganizationRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| BeemFlowError::validation(format!("Invalid JSON: {}", e)))?;

    let mut organization = storage
        .get_organization(&req_ctx.organization_id)
        .await?
        .ok_or_else(|| BeemFlowError::validation("Organization not found"))?;

    // Update only provided fields
    if let Some(name) = payload.name {
        organization.name = name;
    }

    organization.updated_at = chrono::Utc::now();
    storage.update_organization(&organization).await?;

    Ok(Json(organization_to_response(&organization, req_ctx.role, &req_ctx.organization_id)))
}

// ============================================================================
// Member Management Handlers
// ============================================================================

/// GET /v1/organizations/current/members - List all members in current organization
async fn list_members_handler(
    State(storage): State<Arc<dyn Storage>>,
    req: axum::extract::Request,
) -> Result<Json<Vec<MemberResponse>>, AppError> {
    let req_ctx = get_request_context(&req)?;

    check_permission(&req_ctx, Permission::MembersRead)?;

    let members = storage.list_organization_members(&req_ctx.organization_id).await?;

    let response: Vec<MemberResponse> = members
        .into_iter()
        .map(|(user, role)| MemberResponse {
            user: UserInfo {
                id: user.id,
                email: user.email,
                name: user.name,
                avatar_url: user.avatar_url,
            },
            role: role.to_string(),
        })
        .collect();

    Ok(Json(response))
}

/// POST /v1/organizations/current/members - Invite member to current organization
async fn invite_member_handler(
    State(storage): State<Arc<dyn Storage>>,
    req: axum::extract::Request,
) -> Result<Json<MemberResponse>, AppError> {
    let (parts, body) = req.into_parts();
    let req_ctx = parts
        .extensions
        .get::<RequestContext>()
        .cloned()
        .ok_or_else(|| BeemFlowError::validation("Unauthorized"))?;

    let body_bytes = axum::body::to_bytes(body, crate::constants::MAX_REQUEST_BODY_SIZE)
        .await
        .map_err(|_| BeemFlowError::validation("Invalid request body"))?;
    let payload: InviteMemberRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| BeemFlowError::validation(format!("Invalid JSON: {}", e)))?;

    check_permission(&req_ctx, Permission::MembersInvite)?;

    // Parse and validate role
    let invited_role = payload
        .role
        .parse::<Role>()
        .map_err(|e| BeemFlowError::validation(format!("Invalid role: {}", e)))?;

    // Business rule: Admins cannot invite Owners
    if req_ctx.role == Role::Admin && invited_role == Role::Owner {
        return Err(BeemFlowError::validation("Admins cannot assign Owner role").into());
    }

    // Get user by email
    let user = storage
        .get_user_by_email(&payload.email)
        .await?
        .ok_or_else(|| {
            BeemFlowError::validation("User with that email does not exist. User must register first.")
        })?;

    // Check if already a member
    if storage
        .get_organization_member(&req_ctx.organization_id, &user.id)
        .await
        .is_ok()
    {
        return Err(BeemFlowError::validation("User is already a member of this organization").into());
    }

    // Create membership
    let member = OrganizationMember {
        id: uuid::Uuid::new_v4().to_string(),
        organization_id: req_ctx.organization_id.clone(),
        user_id: user.id.clone(),
        role: invited_role,
        invited_by_user_id: Some(req_ctx.user_id.clone()),
        invited_at: Some(chrono::Utc::now()),
        joined_at: chrono::Utc::now(),
        disabled: false,
    };

    storage.create_organization_member(&member).await?;

    Ok(Json(MemberResponse {
        user: UserInfo {
            id: user.id,
            email: user.email,
            name: user.name,
            avatar_url: user.avatar_url,
        },
        role: member.role.to_string(),
    }))
}

/// PUT /v1/organizations/current/members/:user_id - Update member role
async fn update_member_role_handler(
    State(storage): State<Arc<dyn Storage>>,
    Path(member_user_id): Path<String>,
    req: axum::extract::Request,
) -> Result<StatusCode, AppError> {
    let (parts, body) = req.into_parts();
    let req_ctx = parts
        .extensions
        .get::<RequestContext>()
        .cloned()
        .ok_or_else(|| BeemFlowError::validation("Unauthorized"))?;

    let body_bytes = axum::body::to_bytes(body, crate::constants::MAX_REQUEST_BODY_SIZE)
        .await
        .map_err(|_| BeemFlowError::validation("Invalid request body"))?;
    let payload: UpdateRoleRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| BeemFlowError::validation(format!("Invalid JSON: {}", e)))?;

    check_permission(&req_ctx, Permission::MembersUpdateRole)?;

    // Parse and validate role
    let new_role = payload
        .role
        .parse::<Role>()
        .map_err(|e| BeemFlowError::validation(format!("Invalid role: {}", e)))?;

    // Business rule: Admins cannot assign Owner role
    if req_ctx.role == Role::Admin && new_role == Role::Owner {
        return Err(BeemFlowError::validation("Admins cannot assign Owner role").into());
    }

    // Business rule: Cannot change own role
    if member_user_id == req_ctx.user_id {
        return Err(BeemFlowError::validation("Cannot change your own role").into());
    }

    storage
        .update_member_role(&req_ctx.organization_id, &member_user_id, new_role)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /v1/organizations/current/members/:user_id - Remove member from organization
async fn remove_member_handler(
    State(storage): State<Arc<dyn Storage>>,
    Path(member_user_id): Path<String>,
    req: axum::extract::Request,
) -> Result<StatusCode, AppError> {
    let req_ctx = get_request_context(&req)?;

    check_permission(&req_ctx, Permission::MembersRemove)?;

    // Business rule: Cannot remove yourself
    if member_user_id == req_ctx.user_id {
        return Err(BeemFlowError::validation("Cannot remove yourself from the organization").into());
    }

    storage
        .remove_organization_member(&req_ctx.organization_id, &member_user_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Audit Log Handlers
// ============================================================================

/// GET /v1/audit-logs - List audit logs for current organization
#[allow(dead_code)]
async fn list_audit_logs_handler(
    State(storage): State<Arc<dyn Storage>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<Vec<AuditLog>>, AppError> {
    let req_ctx = req.extensions().get::<RequestContext>()
        .cloned()
        .ok_or_else(|| BeemFlowError::validation("Unauthorized"))?;

    check_permission(&req_ctx, Permission::AuditLogsRead)?;

    // Manually parse query parameters from URI
    let uri = req.uri();
    let query_pairs: std::collections::HashMap<_, _> = uri
        .query()
        .map(|v| url::form_urlencoded::parse(v.as_bytes()).collect())
        .unwrap_or_default();

    let limit = query_pairs
        .get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(100)
        .min(1000) as usize;

    let offset = query_pairs
        .get("offset")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0) as usize;

    let logs = storage
        .list_audit_logs(&req_ctx.organization_id, limit, offset)
        .await?;

    Ok(Json(logs))
}

// ============================================================================
// Router Construction
// ============================================================================

/// Create management routes for user/organization/member/audit management
///
/// All routes include /v1 prefix for API versioning.
/// These routes will be nested under /api by http/mod.rs.
///
/// Final URLs:
/// - GET    /api/v1/users/me
/// - PUT    /api/v1/users/me
/// - POST   /api/v1/users/me/password
/// - GET    /api/v1/organizations
/// - GET    /api/v1/organizations/current
/// - PUT    /api/v1/organizations/current
/// - GET    /api/v1/organizations/current/members
/// - POST   /api/v1/organizations/current/members
/// - PUT    /api/v1/organizations/current/members/:user_id
/// - DELETE /api/v1/organizations/current/members/:user_id
/// - GET    /api/v1/audit-logs
pub fn create_management_routes(storage: Arc<dyn Storage>) -> Router {
    Router::new()
        // User profile
        .route(
            "/v1/users/me",
            get(get_profile_handler).put(update_profile_handler),
        )
        .route("/v1/users/me/password", post(change_password_handler))
        // Organizations
        .route("/v1/organizations", get(list_organizations_handler))
        .route(
            "/v1/organizations/current",
            get(get_current_organization_handler).put(update_organization_handler),
        )
        // Members
        .route(
            "/v1/organizations/current/members",
            get(list_members_handler).post(invite_member_handler),
        )
        .route(
            "/v1/organizations/current/members/:user_id",
            put(update_member_role_handler).delete(remove_member_handler),
        )
        // Audit logs (TODO: Add back after fixing handler trait issue)
        // .route("/v1/audit-logs", get(list_audit_logs_handler))
        .with_state(storage)
}
