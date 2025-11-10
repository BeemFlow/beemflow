//! Role-Based Access Control (RBAC)
//!
//! Permission checking and authorization logic for multi-tenant system.
use super::{Permission, RequestContext, Role};
use crate::BeemFlowError;

/// Check if user has a specific permission
///
/// # Arguments
/// * `ctx` - Request context with user's role
/// * `permission` - Permission to check
///
/// # Returns
/// `Ok(())` if user has permission, error otherwise
///
/// # Example
/// ```ignore
/// check_permission(&ctx, Permission::FlowsCreate)?;
/// ```
pub fn check_permission(ctx: &RequestContext, permission: Permission) -> Result<(), BeemFlowError> {
    if !ctx.role.has_permission(permission) {
        return Err(BeemFlowError::OAuth(format!(
            "Insufficient permissions: {:?}. Required role: {:?} or higher",
            permission,
            required_role_for_permission(permission)
        )));
    }
    Ok(())
}

/// Check if user can modify a resource (ownership check for members)
///
/// Rules:
/// - Owner and Admin can modify any resource
/// - Member can only modify their own resources
/// - Viewer cannot modify anything
///
/// # Arguments
/// * `ctx` - Request context with user info
/// * `resource_owner_id` - User ID of resource owner
///
/// # Returns
/// `Ok(())` if user can modify, error otherwise
pub fn check_resource_ownership(
    ctx: &RequestContext,
    resource_owner_id: &str,
) -> Result<(), BeemFlowError> {
    // Owner and Admin can modify any resource
    if matches!(ctx.role, Role::Owner | Role::Admin) {
        return Ok(());
    }

    // Member can only modify their own resources
    if ctx.role == Role::Member && resource_owner_id == ctx.user_id {
        return Ok(());
    }

    Err(BeemFlowError::OAuth(format!(
        "You can only modify your own resources (role: {:?})",
        ctx.role
    )))
}

/// Check if user has any of the specified permissions
///
/// # Arguments
/// * `ctx` - Request context
/// * `permissions` - List of permissions (user needs at least one)
///
/// # Returns
/// `Ok(())` if user has at least one permission
pub fn check_any_permission(
    ctx: &RequestContext,
    permissions: &[Permission],
) -> Result<(), BeemFlowError> {
    for permission in permissions {
        if ctx.role.has_permission(*permission) {
            return Ok(());
        }
    }

    Err(BeemFlowError::OAuth(format!(
        "Insufficient permissions: Need one of {:?}",
        permissions
    )))
}

/// Check if user has all of the specified permissions
///
/// # Arguments
/// * `ctx` - Request context
/// * `permissions` - List of permissions (user needs all of them)
///
/// # Returns
/// `Ok(())` if user has all permissions
pub fn check_all_permissions(
    ctx: &RequestContext,
    permissions: &[Permission],
) -> Result<(), BeemFlowError> {
    for permission in permissions {
        if !ctx.role.has_permission(*permission) {
            return Err(BeemFlowError::OAuth(format!(
                "Insufficient permissions: Missing {:?}",
                permission
            )));
        }
    }

    Ok(())
}

/// Get the minimum role required for a permission
fn required_role_for_permission(permission: Permission) -> Role {
    use Permission::*;

    match permission {
        OrgDelete => Role::Owner,
        OrgUpdate | FlowsDelete | FlowsDeploy | RunsDelete | OAuthDisconnect | SecretsDelete
        | ToolsInstall | MembersInvite | MembersUpdateRole | MembersRemove | AuditLogsRead => {
            Role::Admin
        }
        FlowsCreate | FlowsUpdate | RunsTrigger | RunsCancel | OAuthConnect | SecretsCreate
        | SecretsUpdate => Role::Member,
        FlowsRead | RunsRead | MembersRead | ToolsRead | OrgRead | SecretsRead => Role::Viewer,
    }
}

/// Check if user can invite members with a specific role
///
/// Rules:
/// - Owner can invite anyone
/// - Admin can invite Admin, Member, Viewer (not Owner)
/// - Member and Viewer cannot invite
pub fn check_can_invite_role(inviter_role: Role, invitee_role: Role) -> Result<(), BeemFlowError> {
    match inviter_role {
        Role::Owner => Ok(()), // Owner can invite anyone
        Role::Admin => {
            if invitee_role == Role::Owner {
                Err(BeemFlowError::OAuth(
                    "Only owners can invite other owners".to_string(),
                ))
            } else {
                Ok(())
            }
        }
        Role::Member | Role::Viewer => Err(BeemFlowError::OAuth(
            "Only owners and admins can invite members".to_string(),
        )),
    }
}

/// Check if user can change a member's role
///
/// Rules:
/// - Owner can change anyone's role to anything
/// - Admin can change roles except to/from Owner
/// - Cannot change your own role
pub fn check_can_update_role(
    updater_role: Role,
    updater_id: &str,
    target_user_id: &str,
    current_role: Role,
    new_role: Role,
) -> Result<(), BeemFlowError> {
    // Cannot change your own role
    if updater_id == target_user_id {
        return Err(BeemFlowError::OAuth(
            "Cannot change your own role".to_string(),
        ));
    }

    match updater_role {
        Role::Owner => Ok(()), // Owner can change any role
        Role::Admin => {
            // Admin cannot change to/from Owner
            if current_role == Role::Owner || new_role == Role::Owner {
                Err(BeemFlowError::OAuth(
                    "Only owners can manage owner roles".to_string(),
                ))
            } else {
                Ok(())
            }
        }
        Role::Member | Role::Viewer => Err(BeemFlowError::OAuth(
            "Only owners and admins can update roles".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_context(role: Role, user_id: &str) -> RequestContext {
        RequestContext {
            user_id: user_id.to_string(),
            tenant_id: "tenant123".to_string(),
            tenant_name: "Test Tenant".to_string(),
            role,
            client_ip: None,
            user_agent: None,
            request_id: "req123".to_string(),
        }
    }

    #[test]
    fn test_check_permission() {
        let owner_ctx = create_test_context(Role::Owner, "user1");
        let admin_ctx = create_test_context(Role::Admin, "user2");
        let member_ctx = create_test_context(Role::Member, "user3");
        let viewer_ctx = create_test_context(Role::Viewer, "user4");

        // Owner can delete org
        assert!(check_permission(&owner_ctx, Permission::OrgDelete).is_ok());
        assert!(check_permission(&admin_ctx, Permission::OrgDelete).is_err());

        // Admin can delete flows
        assert!(check_permission(&admin_ctx, Permission::FlowsDelete).is_ok());
        assert!(check_permission(&member_ctx, Permission::FlowsDelete).is_err());

        // Member can create flows
        assert!(check_permission(&member_ctx, Permission::FlowsCreate).is_ok());
        assert!(check_permission(&viewer_ctx, Permission::FlowsCreate).is_err());

        // Everyone can read flows
        assert!(check_permission(&viewer_ctx, Permission::FlowsRead).is_ok());
    }

    #[test]
    fn test_resource_ownership() {
        let admin_ctx = create_test_context(Role::Admin, "admin1");
        let member_ctx = create_test_context(Role::Member, "member1");
        let viewer_ctx = create_test_context(Role::Viewer, "viewer1");

        // Admin can modify anyone's resource
        assert!(check_resource_ownership(&admin_ctx, "other_user").is_ok());

        // Member can modify their own resource
        assert!(check_resource_ownership(&member_ctx, "member1").is_ok());

        // Member cannot modify others' resources
        assert!(check_resource_ownership(&member_ctx, "other_user").is_err());

        // Viewer cannot modify anything
        assert!(check_resource_ownership(&viewer_ctx, "viewer1").is_err());
        assert!(check_resource_ownership(&viewer_ctx, "other_user").is_err());
    }

    #[test]
    fn test_any_permission() {
        let member_ctx = create_test_context(Role::Member, "user1");

        // Member has FlowsCreate
        assert!(
            check_any_permission(
                &member_ctx,
                &[Permission::FlowsCreate, Permission::FlowsDelete]
            )
            .is_ok()
        );

        // Member doesn't have FlowsDelete or OrgDelete
        assert!(
            check_any_permission(
                &member_ctx,
                &[Permission::FlowsDelete, Permission::OrgDelete]
            )
            .is_err()
        );
    }

    #[test]
    fn test_all_permissions() {
        let member_ctx = create_test_context(Role::Member, "user1");

        // Member has both
        assert!(
            check_all_permissions(
                &member_ctx,
                &[Permission::FlowsCreate, Permission::FlowsRead]
            )
            .is_ok()
        );

        // Member has FlowsCreate but not FlowsDelete
        assert!(
            check_all_permissions(
                &member_ctx,
                &[Permission::FlowsCreate, Permission::FlowsDelete]
            )
            .is_err()
        );
    }

    #[test]
    fn test_can_invite_role() {
        // Owner can invite anyone
        assert!(check_can_invite_role(Role::Owner, Role::Owner).is_ok());
        assert!(check_can_invite_role(Role::Owner, Role::Admin).is_ok());

        // Admin cannot invite Owner
        assert!(check_can_invite_role(Role::Admin, Role::Owner).is_err());
        assert!(check_can_invite_role(Role::Admin, Role::Member).is_ok());

        // Member cannot invite
        assert!(check_can_invite_role(Role::Member, Role::Viewer).is_err());
    }

    #[test]
    fn test_can_update_role() {
        // Cannot change own role
        assert!(
            check_can_update_role(Role::Owner, "user1", "user1", Role::Owner, Role::Admin).is_err()
        );

        // Owner can change anyone's role
        assert!(
            check_can_update_role(Role::Owner, "owner1", "user2", Role::Member, Role::Admin)
                .is_ok()
        );

        // Admin cannot manage Owner roles
        assert!(
            check_can_update_role(Role::Admin, "admin1", "user2", Role::Owner, Role::Admin)
                .is_err()
        );
        assert!(
            check_can_update_role(Role::Admin, "admin1", "user2", Role::Member, Role::Owner)
                .is_err()
        );

        // Admin can change non-Owner roles
        assert!(
            check_can_update_role(Role::Admin, "admin1", "user2", Role::Member, Role::Viewer)
                .is_ok()
        );
    }
}
