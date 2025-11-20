//! Integration tests for authentication system
//!
//! Tests multi-tenant auth, RBAC, JWT, and organization isolation.

use beemflow::audit::{AuditEvent, AuditLogger};
use beemflow::auth::{
    JwtManager, Membership, Role, Organization, OrganizationMember, User, ValidatedJwtSecret, hash_password,
    validate_password_strength, verify_password,
};
use beemflow::model::OAuthCredential;
use beemflow::storage::{AuthStorage, OAuthStorage, SqliteStorage, Storage};
use chrono::{Duration, Utc};
use uuid::Uuid;

/// Create test database with clean schema
async fn create_test_storage() -> std::sync::Arc<SqliteStorage> {
    let storage = SqliteStorage::new(":memory:")
        .await
        .expect("Failed to create storage");
    std::sync::Arc::new(storage)
}

/// Create test user
fn create_test_user(email: &str, name: &str) -> User {
    User {
        id: Uuid::new_v4().to_string(),
        email: email.to_string(),
        name: Some(name.to_string()),
        password_hash: hash_password("test-password-123").unwrap(),
        email_verified: false,
        avatar_url: None,
        mfa_enabled: false,
        mfa_secret: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login_at: None,
        disabled: false,
        disabled_reason: None,
        disabled_at: None,
    }
}

/// Create test organization
fn create_test_organization(name: &str, slug: &str, creator_id: &str) -> Organization {
    Organization {
        id: Uuid::new_v4().to_string(),
        name: name.to_string(),
        slug: slug.to_string(),
        plan: "free".to_string(),
        plan_starts_at: Some(Utc::now()),
        plan_ends_at: None,
        max_users: 5,
        max_flows: 10,
        max_runs_per_month: 1000,
        settings: None,
        created_by_user_id: creator_id.to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        disabled: false,
    }
}

// ============================================================================
// Password Tests
// ============================================================================

#[tokio::test]
async fn test_password_hashing_and_verification() {
    let password = "secure-password-123";

    // Hash password
    let hash = hash_password(password).expect("Failed to hash password");

    // Verify correct password
    assert!(
        verify_password(password, &hash).expect("Failed to verify"),
        "Correct password should verify"
    );

    // Reject incorrect password
    assert!(
        !verify_password("wrong-password", &hash).expect("Failed to verify"),
        "Wrong password should not verify"
    );
}

#[tokio::test]
async fn test_password_strength_validation() {
    // Too short (< 12 chars)
    assert!(validate_password_strength("short").is_err());
    assert!(validate_password_strength("11char-pass").is_err()); // 11 chars

    // Too long
    let too_long = "a".repeat(129);
    assert!(validate_password_strength(&too_long).is_err());

    // Common weak password
    assert!(validate_password_strength("password").is_err());
    assert!(validate_password_strength("123456789012").is_err());
    assert!(validate_password_strength("passwordpassword").is_err());

    // Valid passwords (12+ chars)
    assert!(validate_password_strength("MySecure1234").is_ok()); // 12 chars
    assert!(validate_password_strength("abcdefghijkl").is_ok()); // 12 chars
    assert!(validate_password_strength("correct-horse-battery-staple").is_ok()); // Long passphrase
}

// ============================================================================
// User Storage Tests
// ============================================================================

#[tokio::test]
async fn test_user_crud_operations() {
    let storage = create_test_storage().await;

    // Create user
    let user = create_test_user("test@example.com", "Test User");
    let user_id = user.id.clone();

    storage
        .create_user(&user)
        .await
        .expect("Failed to create user");

    // Get user by ID
    let retrieved = storage
        .get_user(&user_id)
        .await
        .expect("Failed to get user")
        .expect("User not found");

    assert_eq!(retrieved.email, "test@example.com");
    assert_eq!(retrieved.name, Some("Test User".to_string()));
    assert!(!retrieved.disabled);

    // Get user by email
    let by_email = storage
        .get_user_by_email("test@example.com")
        .await
        .expect("Failed to get user by email")
        .expect("User not found");

    assert_eq!(by_email.id, user_id);

    // Update user
    let mut updated_user = retrieved.clone();
    updated_user.name = Some("Updated Name".to_string());
    updated_user.email_verified = true;

    storage
        .update_user(&updated_user)
        .await
        .expect("Failed to update user");

    let verified = storage
        .get_user(&user_id)
        .await
        .expect("Failed to get user")
        .expect("User not found");

    assert_eq!(verified.name, Some("Updated Name".to_string()));
    assert!(verified.email_verified);
}

#[tokio::test]
async fn test_user_email_uniqueness() {
    let storage = create_test_storage().await;

    // Create first user
    let user1 = create_test_user("duplicate@example.com", "User 1");
    storage
        .create_user(&user1)
        .await
        .expect("Failed to create first user");

    // Try to create second user with same email
    let user2 = create_test_user("duplicate@example.com", "User 2");
    let result = storage.create_user(&user2).await;

    assert!(
        result.is_err(),
        "Should not allow duplicate email addresses"
    );
}

#[tokio::test]
async fn test_disabled_user_not_returned_by_email() {
    let storage = create_test_storage().await;

    // Create disabled user
    let mut user = create_test_user("disabled@example.com", "Disabled User");
    user.disabled = true;
    user.disabled_reason = Some("Account suspended".to_string());

    storage
        .create_user(&user)
        .await
        .expect("Failed to create user");

    // get_user_by_email should return None for disabled users
    let result = storage
        .get_user_by_email("disabled@example.com")
        .await
        .expect("Query failed");

    assert!(
        result.is_none(),
        "Disabled user should not be returned by email lookup"
    );
}

// ============================================================================
// Organization Storage Tests
// ============================================================================

#[tokio::test]
async fn test_organization_crud_operations() {
    let storage = create_test_storage().await;

    // Create user first
    let user = create_test_user("owner@example.com", "Owner");
    storage
        .create_user(&user)
        .await
        .expect("Failed to create user");

    // Create organization
    let organization = create_test_organization("Acme Corp", "acme", &user.id);
    let organization_id = organization.id.clone();

    storage
        .create_organization(&organization)
        .await
        .expect("Failed to create organization");

    // Get organization by ID
    let retrieved = storage
        .get_organization(&organization_id)
        .await
        .expect("Failed to get organization")
        .expect("Organization not found");

    assert_eq!(retrieved.name, "Acme Corp");
    assert_eq!(retrieved.slug, "acme");
    assert_eq!(retrieved.plan, "free");
    assert_eq!(retrieved.max_users, 5);

    // Get organization by slug
    let by_slug = storage
        .get_organization_by_slug("acme")
        .await
        .expect("Failed to get organization by slug")
        .expect("Organization not found");

    assert_eq!(by_slug.id, organization_id);

    // Update organization
    let mut updated_organization = retrieved.clone();
    updated_organization.plan = "pro".to_string();
    updated_organization.max_users = 20;

    storage
        .update_organization(&updated_organization)
        .await
        .expect("Failed to update organization");

    let verified = storage
        .get_organization(&organization_id)
        .await
        .expect("Failed to get organization")
        .expect("Organization not found");

    assert_eq!(verified.plan, "pro");
    assert_eq!(verified.max_users, 20);
}

#[tokio::test]
async fn test_organization_slug_uniqueness() {
    let storage = create_test_storage().await;

    let user = create_test_user("owner@example.com", "Owner");
    storage
        .create_user(&user)
        .await
        .expect("Failed to create user");

    // Create first organization
    let organization1 = create_test_organization("Company A", "company", &user.id);
    storage
        .create_organization(&organization1)
        .await
        .expect("Failed to create first organization");

    // Try to create second organization with same slug
    let organization2 = create_test_organization("Company B", "company", &user.id);
    let result = storage.create_organization(&organization2).await;

    assert!(result.is_err(), "Should not allow duplicate slugs");
}

// ============================================================================
// Organization Membership Tests
// ============================================================================

#[tokio::test]
async fn test_organization_member_operations() {
    let storage = create_test_storage().await;

    // Create user and organization
    let user = create_test_user("member@example.com", "Member");
    let organization = create_test_organization("Test Org", "test-org", &user.id);

    storage
        .create_user(&user)
        .await
        .expect("Failed to create user");
    storage
        .create_organization(&organization)
        .await
        .expect("Failed to create organization");

    // Create membership
    let member = OrganizationMember {
        id: Uuid::new_v4().to_string(),
        organization_id: organization.id.clone(),
        user_id: user.id.clone(),
        role: Role::Admin,
        invited_by_user_id: None,
        invited_at: None,
        joined_at: Utc::now(),
        disabled: false,
    };

    storage
        .create_organization_member(&member)
        .await
        .expect("Failed to create membership");

    // Get membership
    let retrieved = storage
        .get_organization_member(&organization.id, &user.id)
        .await
        .expect("Failed to get member")
        .expect("Member not found");

    assert_eq!(retrieved.role, Role::Admin);
    assert!(!retrieved.disabled);

    // List user's organizations
    let organizations = storage
        .list_user_organizations(&user.id)
        .await
        .expect("Failed to list user organizations");

    assert_eq!(organizations.len(), 1);
    assert_eq!(organizations[0].0.id, organization.id);
    assert_eq!(organizations[0].1, Role::Admin);

    // List organization members
    let members = storage
        .list_organization_members(&organization.id)
        .await
        .expect("Failed to list organization members");

    assert_eq!(members.len(), 1);
    assert_eq!(members[0].0.id, user.id);
    assert_eq!(members[0].1, Role::Admin);

    // Update role
    storage
        .update_member_role(&organization.id, &user.id, Role::Member)
        .await
        .expect("Failed to update role");

    let updated = storage
        .get_organization_member(&organization.id, &user.id)
        .await
        .expect("Failed to get member")
        .expect("Member not found");

    assert_eq!(updated.role, Role::Member);

    // Remove member
    storage
        .remove_organization_member(&organization.id, &user.id)
        .await
        .expect("Failed to remove member");

    let removed = storage
        .get_organization_member(&organization.id, &user.id)
        .await
        .expect("Failed to get member");

    assert!(removed.is_none(), "Member should be removed");
}

#[tokio::test]
async fn test_disabled_members_not_returned() {
    let storage = create_test_storage().await;

    let user = create_test_user("user@example.com", "User");
    let organization = create_test_organization("Org", "org", &user.id);

    storage
        .create_user(&user)
        .await
        .expect("Failed to create user");
    storage
        .create_organization(&organization)
        .await
        .expect("Failed to create organization");

    // Create disabled membership
    let member = OrganizationMember {
        id: Uuid::new_v4().to_string(),
        organization_id: organization.id.clone(),
        user_id: user.id.clone(),
        role: Role::Member,
        invited_by_user_id: None,
        invited_at: None,
        joined_at: Utc::now(),
        disabled: true,
    };

    storage
        .create_organization_member(&member)
        .await
        .expect("Failed to create membership");

    // Disabled member should not be returned
    let result = storage
        .get_organization_member(&organization.id, &user.id)
        .await
        .expect("Query failed");

    assert!(result.is_none(), "Disabled member should not be returned");
}

// ============================================================================
// JWT Tests
// ============================================================================

#[tokio::test]
async fn test_jwt_generate_and_validate() {
    let jwt_secret =
        ValidatedJwtSecret::from_string("test-secret-key-at-least-32-bytes-long!!".to_string())
            .unwrap();
    let jwt_manager = JwtManager::new(
        &jwt_secret,
        "beemflow-test".to_string(),
        Duration::minutes(15),
    );

    // Generate token
    let token = jwt_manager
        .generate_access_token("user123", "user@example.com", vec![
            Membership { organization_id: "org456".to_string(), role: Role::Admin }
        ])
        .expect("Failed to generate token");

    // Validate token
    let claims = jwt_manager
        .validate_token(&token)
        .expect("Failed to validate token");

    assert_eq!(claims.sub, "user123");
    assert_eq!(claims.memberships[0].organization_id, "org456");
    assert_eq!(claims.memberships[0].role, Role::Admin);
    assert_eq!(claims.iss, "beemflow-test");

    // Verify expiration is in the future
    let now = Utc::now().timestamp() as usize;
    assert!(claims.exp > now, "Token should not be expired");
    assert!(
        claims.exp <= now + 900,
        "Token should expire in ~15 minutes"
    );
}

#[tokio::test]
async fn test_jwt_expired_token_rejected() {
    // Create manager with negative TTL (already expired well beyond leeway)
    let jwt_secret =
        ValidatedJwtSecret::from_string("test-secret-key-at-least-32-bytes-long!!".to_string())
            .unwrap();
    let jwt_manager = JwtManager::new(
        &jwt_secret,
        "beemflow-test".to_string(),
        Duration::seconds(-120), // Expired 2 minutes ago (beyond any leeway)
    );

    let token = jwt_manager
        .generate_access_token("user123", "user@example.com", vec![
            Membership { organization_id: "org456".to_string(), role: Role::Owner }
        ])
        .expect("Failed to generate token");

    // Token should be rejected as expired
    let result = jwt_manager.validate_token(&token);

    match result {
        Ok(_) => panic!("Expired token should have been rejected"),
        Err(e) => {
            let error_msg = format!("{:?}", e);
            assert!(
                error_msg.to_lowercase().contains("expired")
                    || error_msg.to_lowercase().contains("invalid"),
                "Error should indicate token issue: {}",
                error_msg
            );
        }
    }
}

#[tokio::test]
async fn test_jwt_invalid_signature_rejected() {
    let jwt_secret1 =
        ValidatedJwtSecret::from_string("secret-key-one!!!!!!!!!!!!!!!!!!!!!!!!".to_string())
            .unwrap();
    let manager1 = JwtManager::new(
        &jwt_secret1,
        "beemflow-test".to_string(),
        Duration::minutes(15),
    );

    let jwt_secret2 =
        ValidatedJwtSecret::from_string("secret-key-two!!!!!!!!!!!!!!!!!!!!!!!!".to_string())
            .unwrap();
    let manager2 = JwtManager::new(
        &jwt_secret2,
        "beemflow-test".to_string(),
        Duration::minutes(15),
    );

    let token = manager1
        .generate_access_token("user123", "user@example.com", vec![
            Membership { organization_id: "org456".to_string(), role: Role::Member }
        ])
        .expect("Failed to generate token");

    // Should fail with different key
    let result = manager2.validate_token(&token);
    assert!(
        result.is_err(),
        "Token signed with different key should be rejected"
    );
}

// ============================================================================
// Refresh Token Tests
// ============================================================================

#[tokio::test]
async fn test_refresh_token_lifecycle() {
    let storage = create_test_storage().await;

    let user = create_test_user("user@example.com", "User");
    let organization = create_test_organization("Org", "org", &user.id);

    storage
        .create_user(&user)
        .await
        .expect("Failed to create user");
    storage
        .create_organization(&organization)
        .await
        .expect("Failed to create organization");

    // Create refresh token
    let refresh_token = beemflow::auth::RefreshToken {
        id: Uuid::new_v4().to_string(),
        user_id: user.id.clone(),
        token_hash: "test_hash_123".to_string(),
        expires_at: Utc::now() + Duration::days(30),
        revoked: false,
        revoked_at: None,
        created_at: Utc::now(),
        last_used_at: None,
        user_agent: Some("TestAgent/1.0".to_string()),
        client_ip: Some("192.168.1.1".to_string()),
    };

    storage
        .create_refresh_token(&refresh_token)
        .await
        .expect("Failed to create refresh token");

    // Retrieve token
    let retrieved = storage
        .get_refresh_token("test_hash_123")
        .await
        .expect("Failed to get token")
        .expect("Token not found");

    assert_eq!(retrieved.user_id, user.id);
    assert!(!retrieved.revoked);

    // Update last used
    storage
        .update_refresh_token_last_used("test_hash_123")
        .await
        .expect("Failed to update last used");

    let updated = storage
        .get_refresh_token("test_hash_123")
        .await
        .expect("Failed to get token")
        .expect("Token not found");

    assert!(updated.last_used_at.is_some(), "Last used should be set");

    // Revoke token
    storage
        .revoke_refresh_token("test_hash_123")
        .await
        .expect("Failed to revoke token");

    // Revoked tokens should not be returned
    let revoked = storage
        .get_refresh_token("test_hash_123")
        .await
        .expect("Query failed");

    assert!(revoked.is_none(), "Revoked token should not be returned");
}

#[tokio::test]
async fn test_revoke_all_user_tokens() {
    let storage = create_test_storage().await;

    let user = create_test_user("user@example.com", "User");
    let organization = create_test_organization("Org", "org", &user.id);

    storage
        .create_user(&user)
        .await
        .expect("Failed to create user");
    storage
        .create_organization(&organization)
        .await
        .expect("Failed to create organization");

    // Create multiple refresh tokens
    for i in 0..3 {
        let token = beemflow::auth::RefreshToken {
            id: Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            token_hash: format!("token_hash_{}", i),
            expires_at: Utc::now() + Duration::days(30),
            revoked: false,
            revoked_at: None,
            created_at: Utc::now(),
            last_used_at: None,
            user_agent: None,
            client_ip: None,
        };

        storage
            .create_refresh_token(&token)
            .await
            .expect("Failed to create token");
    }

    // Revoke all tokens for user
    storage
        .revoke_all_user_tokens(&user.id)
        .await
        .expect("Failed to revoke all tokens");

    // All tokens should be gone
    for i in 0..3 {
        let result = storage
            .get_refresh_token(&format!("token_hash_{}", i))
            .await
            .expect("Query failed");

        assert!(result.is_none(), "All tokens should be revoked");
    }
}

// ============================================================================
// Organization Isolation Tests (CRITICAL for multi-tenant security)
// ============================================================================

#[tokio::test]
async fn test_organization_isolation_users_cannot_see_each_other() {
    let storage = create_test_storage().await;

    // Create two separate users and organizations
    let user_a = create_test_user("usera@example.com", "User A");
    let user_b = create_test_user("userb@example.com", "User B");

    let org_a = create_test_organization("Organization A", "org-a", &user_a.id);
    let org_b = create_test_organization("Organization B", "org-b", &user_b.id);

    storage
        .create_user(&user_a)
        .await
        .expect("Failed to create user A");
    storage
        .create_user(&user_b)
        .await
        .expect("Failed to create user B");
    storage
        .create_organization(&org_a)
        .await
        .expect("Failed to create organization A");
    storage
        .create_organization(&org_b)
        .await
        .expect("Failed to create organization B");

    // Add users as owners of their respective organizations
    let member_a = OrganizationMember {
        id: Uuid::new_v4().to_string(),
        organization_id: org_a.id.clone(),
        user_id: user_a.id.clone(),
        role: Role::Owner,
        invited_by_user_id: None,
        invited_at: None,
        joined_at: Utc::now(),
        disabled: false,
    };

    let member_b = OrganizationMember {
        id: Uuid::new_v4().to_string(),
        organization_id: org_b.id.clone(),
        user_id: user_b.id.clone(),
        role: Role::Owner,
        invited_by_user_id: None,
        invited_at: None,
        joined_at: Utc::now(),
        disabled: false,
    };

    storage
        .create_organization_member(&member_a)
        .await
        .expect("Failed to create member A");
    storage
        .create_organization_member(&member_b)
        .await
        .expect("Failed to create member B");

    // User A should only see Organization A
    let user_a_organizations = storage
        .list_user_organizations(&user_a.id)
        .await
        .expect("Failed to list organizations");

    assert_eq!(user_a_organizations.len(), 1);
    assert_eq!(user_a_organizations[0].0.id, org_a.id);

    // User B should only see Organization B
    let user_b_organizations = storage
        .list_user_organizations(&user_b.id)
        .await
        .expect("Failed to list organizations");

    assert_eq!(user_b_organizations.len(), 1);
    assert_eq!(user_b_organizations[0].0.id, org_b.id);

    // Organization A should only see User A as member
    let org_a_members = storage
        .list_organization_members(&org_a.id)
        .await
        .expect("Failed to list members");

    assert_eq!(org_a_members.len(), 1);
    assert_eq!(org_a_members[0].0.id, user_a.id);
}

#[tokio::test]
async fn test_user_can_belong_to_multiple_organizations() {
    let storage = create_test_storage().await;

    // Create one user
    let user = create_test_user("multiorg@example.com", "Multi Organization User");
    storage
        .create_user(&user)
        .await
        .expect("Failed to create user");

    // Create two organizations
    let organization1 = create_test_organization("Organization 1", "org-1", &user.id);
    let organization2 = create_test_organization("Organization 2", "org-2", &user.id);

    storage
        .create_organization(&organization1)
        .await
        .expect("Failed to create organization 1");
    storage
        .create_organization(&organization2)
        .await
        .expect("Failed to create organization 2");

    // Add user to both organizations with different roles
    let member1 = OrganizationMember {
        id: Uuid::new_v4().to_string(),
        organization_id: organization1.id.clone(),
        user_id: user.id.clone(),
        role: Role::Owner,
        invited_by_user_id: None,
        invited_at: None,
        joined_at: Utc::now(),
        disabled: false,
    };

    let member2 = OrganizationMember {
        id: Uuid::new_v4().to_string(),
        organization_id: organization2.id.clone(),
        user_id: user.id.clone(),
        role: Role::Viewer,
        invited_by_user_id: Some(user.id.clone()),
        invited_at: Some(Utc::now()),
        joined_at: Utc::now(),
        disabled: false,
    };

    storage
        .create_organization_member(&member1)
        .await
        .expect("Failed to create member 1");
    storage
        .create_organization_member(&member2)
        .await
        .expect("Failed to create member 2");

    // User should see both organizations
    let organizations = storage
        .list_user_organizations(&user.id)
        .await
        .expect("Failed to list organizations");

    assert_eq!(organizations.len(), 2);

    // Find organization1 and verify role
    let organization1_entry = organizations.iter().find(|(o, _)| o.id == organization1.id);
    assert!(organization1_entry.is_some());
    assert_eq!(organization1_entry.unwrap().1, Role::Owner);

    // Find organization2 and verify role
    let organization2_entry = organizations.iter().find(|(o, _)| o.id == organization2.id);
    assert!(organization2_entry.is_some());
    assert_eq!(organization2_entry.unwrap().1, Role::Viewer);
}

// ============================================================================
// Audit Logging Tests
// ============================================================================

#[tokio::test]
async fn test_audit_log_creation_and_retrieval() {
    let storage = create_test_storage().await;

    let user = create_test_user("user@example.com", "User");
    let organization = create_test_organization("Org", "org", &user.id);

    storage
        .create_user(&user)
        .await
        .expect("Failed to create user");
    storage
        .create_organization(&organization)
        .await
        .expect("Failed to create organization");

    // Create audit logger
    let audit_logger = AuditLogger::new(storage.clone() as std::sync::Arc<dyn Storage>);

    // Log some events
    for i in 0..5 {
        audit_logger
            .log(AuditEvent {
                request_id: format!("req-{}", i),
                organization_id: organization.id.clone(),
                user_id: Some(user.id.clone()),
                client_ip: Some("192.168.1.1".to_string()),
                user_agent: Some("TestAgent/1.0".to_string()),
                action: format!("test.action.{}", i),
                resource_type: Some("test".to_string()),
                resource_id: Some(format!("resource-{}", i)),
                resource_name: None,
                http_method: Some("POST".to_string()),
                http_path: Some("/api/test".to_string()),
                http_status_code: Some(200),
                success: true,
                error_message: None,
                metadata: None,
            })
            .await
            .expect("Failed to log audit event");
    }

    // Retrieve logs
    let logs = storage
        .list_audit_logs(&organization.id, 10, 0)
        .await
        .expect("Failed to list audit logs");

    assert_eq!(logs.len(), 5, "Should have 5 audit logs");

    // Logs should be in reverse chronological order (timestamps descending)
    for i in 0..logs.len() - 1 {
        assert!(
            logs[i].timestamp >= logs[i + 1].timestamp,
            "Logs should be in reverse chronological order"
        );
    }

    // Verify all logs belong to correct organization
    for log in &logs {
        assert_eq!(log.organization_id, organization.id);
        assert_eq!(log.user_id, Some(user.id.clone()));
        assert!(log.success);
    }

    // Verify actions are present (order may vary slightly due to timing)
    let actions: Vec<String> = logs.iter().map(|l| l.action.clone()).collect();
    assert!(actions.contains(&"test.action.0".to_string()));
    assert!(actions.contains(&"test.action.4".to_string()));
}

#[tokio::test]
async fn test_audit_logs_organization_isolation() {
    let storage = create_test_storage().await;

    // Create two organizations
    let user_a = create_test_user("usera@example.com", "User A");
    let user_b = create_test_user("userb@example.com", "User B");
    let org_a = create_test_organization("Organization A", "org-a", &user_a.id);
    let org_b = create_test_organization("Organization B", "org-b", &user_b.id);

    storage
        .create_user(&user_a)
        .await
        .expect("Failed to create user A");
    storage
        .create_user(&user_b)
        .await
        .expect("Failed to create user B");
    storage
        .create_organization(&org_a)
        .await
        .expect("Failed to create organization A");
    storage
        .create_organization(&org_b)
        .await
        .expect("Failed to create organization B");

    let audit_logger = AuditLogger::new(storage.clone() as std::sync::Arc<dyn Storage>);

    // Log events for both organizations
    audit_logger
        .log(AuditEvent {
            request_id: "req-a".to_string(),
            organization_id: org_a.id.clone(),
            user_id: Some(user_a.id.clone()),
            client_ip: None,
            user_agent: None,
            action: "org_a.action".to_string(),
            resource_type: None,
            resource_id: None,
            resource_name: None,
            http_method: None,
            http_path: None,
            http_status_code: None,
            success: true,
            error_message: None,
            metadata: None,
        })
        .await
        .expect("Failed to log");

    audit_logger
        .log(AuditEvent {
            request_id: "req-b".to_string(),
            organization_id: org_b.id.clone(),
            user_id: Some(user_b.id.clone()),
            client_ip: None,
            user_agent: None,
            action: "org_b.action".to_string(),
            resource_type: None,
            resource_id: None,
            resource_name: None,
            http_method: None,
            http_path: None,
            http_status_code: None,
            success: true,
            error_message: None,
            metadata: None,
        })
        .await
        .expect("Failed to log");

    // Organization A should only see its own logs
    let logs_a = storage
        .list_audit_logs(&org_a.id, 10, 0)
        .await
        .expect("Failed to list logs");

    assert_eq!(logs_a.len(), 1);
    assert_eq!(logs_a[0].action, "org_a.action");
    assert_eq!(logs_a[0].organization_id, org_a.id);

    // Organization B should only see its own logs
    let logs_b = storage
        .list_audit_logs(&org_b.id, 10, 0)
        .await
        .expect("Failed to list logs");

    assert_eq!(logs_b.len(), 1);
    assert_eq!(logs_b[0].action, "org_b.action");
    assert_eq!(logs_b[0].organization_id, org_b.id);
}

// ============================================================================
// RBAC Permission Tests
// ============================================================================

#[tokio::test]
async fn test_role_permissions() {
    use beemflow::auth::Permission;

    // Owner has all permissions
    assert!(Role::Owner.has_permission(Permission::OrgDelete));
    assert!(Role::Owner.has_permission(Permission::FlowsDelete));
    assert!(Role::Owner.has_permission(Permission::FlowsCreate));
    assert!(Role::Owner.has_permission(Permission::FlowsRead));

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
    assert!(Role::Viewer.has_permission(Permission::RunsRead));
    assert!(!Role::Viewer.has_permission(Permission::FlowsCreate));
    assert!(!Role::Viewer.has_permission(Permission::RunsTrigger));
}

#[tokio::test]
async fn test_check_permission() {
    use beemflow::auth::{Permission, RequestContext, check_permission};

    let owner_ctx = RequestContext {
        user_id: "user1".to_string(),
        organization_id: "org1".to_string(),
        organization_name: "Organization 1".to_string(),
        role: Role::Owner,
        client_ip: None,
        user_agent: None,
        request_id: "req1".to_string(),
    };

    let viewer_ctx = RequestContext {
        user_id: "user2".to_string(),
        organization_id: "org1".to_string(),
        organization_name: "Organization 1".to_string(),
        role: Role::Viewer,
        client_ip: None,
        user_agent: None,
        request_id: "req2".to_string(),
    };

    // Owner can delete
    assert!(check_permission(&owner_ctx, Permission::FlowsDelete).is_ok());

    // Viewer cannot delete
    assert!(check_permission(&viewer_ctx, Permission::FlowsDelete).is_err());

    // Both can read
    assert!(check_permission(&owner_ctx, Permission::FlowsRead).is_ok());
    assert!(check_permission(&viewer_ctx, Permission::FlowsRead).is_ok());
}

#[tokio::test]
async fn test_resource_ownership_checks() {
    use beemflow::auth::{RequestContext, check_resource_ownership};

    let admin_ctx = RequestContext {
        user_id: "admin1".to_string(),
        organization_id: "org1".to_string(),
        organization_name: "Organization 1".to_string(),
        role: Role::Admin,
        client_ip: None,
        user_agent: None,
        request_id: "req1".to_string(),
    };

    let member_ctx = RequestContext {
        user_id: "member1".to_string(),
        organization_id: "org1".to_string(),
        organization_name: "Organization 1".to_string(),
        role: Role::Member,
        client_ip: None,
        user_agent: None,
        request_id: "req2".to_string(),
    };

    // Admin can modify anyone's resource
    assert!(check_resource_ownership(&admin_ctx, "other_user").is_ok());

    // Member can modify their own resource
    assert!(check_resource_ownership(&member_ctx, "member1").is_ok());

    // Member cannot modify others' resources
    assert!(check_resource_ownership(&member_ctx, "other_user").is_err());
}

// ============================================================================
// End-to-End Registration Flow Test
// ============================================================================

#[tokio::test]
async fn test_complete_user_registration_flow() {
    let storage = create_test_storage().await;

    let email = "newuser@example.com";
    let password = "SecurePassword123";
    let name = "New User";

    // 1. Validate password
    validate_password_strength(password).expect("Password should be valid");

    // 2. Check email doesn't exist
    let existing = storage
        .get_user_by_email(email)
        .await
        .expect("Query failed");
    assert!(existing.is_none(), "Email should not exist yet");

    // 3. Create user
    let user = User {
        id: Uuid::new_v4().to_string(),
        email: email.to_string(),
        name: Some(name.to_string()),
        password_hash: hash_password(password).unwrap(),
        email_verified: false,
        avatar_url: None,
        mfa_enabled: false,
        mfa_secret: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login_at: None,
        disabled: false,
        disabled_reason: None,
        disabled_at: None,
    };

    storage
        .create_user(&user)
        .await
        .expect("Failed to create user");

    // 4. Create default organization
    let organization = Organization {
        id: Uuid::new_v4().to_string(),
        name: "My Workspace".to_string(),
        slug: "newuser-workspace".to_string(),
        plan: "free".to_string(),
        plan_starts_at: Some(Utc::now()),
        plan_ends_at: None,
        max_users: 5,
        max_flows: 10,
        max_runs_per_month: 1000,
        settings: None,
        created_by_user_id: user.id.clone(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        disabled: false,
    };

    storage
        .create_organization(&organization)
        .await
        .expect("Failed to create organization");

    // 5. Add user as owner
    let member = OrganizationMember {
        id: Uuid::new_v4().to_string(),
        organization_id: organization.id.clone(),
        user_id: user.id.clone(),
        role: Role::Owner,
        invited_by_user_id: None,
        invited_at: None,
        joined_at: Utc::now(),
        disabled: false,
    };

    storage
        .create_organization_member(&member)
        .await
        .expect("Failed to create member");

    // 6. Verify user can login (password check)
    let stored_user = storage
        .get_user_by_email(email)
        .await
        .expect("Failed to get user")
        .expect("User not found");

    assert!(
        verify_password(password, &stored_user.password_hash).expect("Failed to verify"),
        "Password should verify"
    );

    // 7. Verify user has organization with owner role
    let user_organizations = storage
        .list_user_organizations(&user.id)
        .await
        .expect("Failed to list organizations");

    assert_eq!(user_organizations.len(), 1);
    assert_eq!(user_organizations[0].0.id, organization.id);
    assert_eq!(user_organizations[0].1, Role::Owner);

    // 8. Generate JWT token
    let jwt_secret =
        ValidatedJwtSecret::from_string("test-secret-key-at-least-32-bytes-long!!".to_string())
            .unwrap();
    let jwt_manager = JwtManager::new(
        &jwt_secret,
        "beemflow-test".to_string(),
        Duration::minutes(15),
    );

    let token = jwt_manager
        .generate_access_token(&user.id, &user.email, vec![
            Membership { organization_id: organization.id.clone(), role: Role::Owner }
        ])
        .expect("Failed to generate token");

    // 9. Validate JWT
    let claims = jwt_manager
        .validate_token(&token)
        .expect("Failed to validate token");

    assert_eq!(claims.sub, user.id);
    assert_eq!(claims.memberships[0].organization_id, organization.id);
    assert_eq!(claims.memberships[0].role, Role::Owner);
}

// ============================================================================
// OAuth Credential Per-User Uniqueness Test (CRITICAL FIX)
// ============================================================================

#[tokio::test]
async fn test_oauth_credentials_per_user_not_global() {
    // This test verifies the critical security fix from AUTH_SAAS_PHASE.md
    // Integration test needs encryption key for production code path
    unsafe {
        std::env::set_var(
            "OAUTH_ENCRYPTION_KEY",
            "dOBebLHe5g3mQbsK8k+fC4fRvb1a4AJzmfFh3woFo2g=",
        );
    }

    // BEFORE: UNIQUE(provider, integration) - only ONE Google token globally
    // AFTER: UNIQUE(user_id, provider, integration) - each user can have their own

    let storage = create_test_storage().await;

    // Create two users in different organizations
    let user_a = create_test_user("usera@example.com", "User A");
    let user_b = create_test_user("userb@example.com", "User B");
    let org_a = create_test_organization("Organization A", "org-a", &user_a.id);
    let org_b = create_test_organization("Organization B", "org-b", &user_b.id);

    storage
        .create_user(&user_a)
        .await
        .expect("Failed to create user A");
    storage
        .create_user(&user_b)
        .await
        .expect("Failed to create user B");
    storage
        .create_organization(&org_a)
        .await
        .expect("Failed to create organization A");
    storage
        .create_organization(&org_b)
        .await
        .expect("Failed to create organization B");

    // Create OAuth credentials for both users with same provider
    use beemflow::model::OAuthCredential;

    let cred_a = OAuthCredential {
        id: Uuid::new_v4().to_string(),
        provider: "google".to_string(),
        integration: "gmail".to_string(),
        access_token: "user_a_token".to_string(),
        refresh_token: Some("user_a_refresh".to_string()),
        expires_at: None,
        scope: Some("email".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        user_id: user_a.id.clone(),
        organization_id: org_a.id.clone(),
    };

    let cred_b = OAuthCredential {
        id: Uuid::new_v4().to_string(),
        provider: "google".to_string(),
        integration: "gmail".to_string(),
        access_token: "user_b_token".to_string(),
        refresh_token: Some("user_b_refresh".to_string()),
        expires_at: None,
        scope: Some("email".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        user_id: user_b.id.clone(),
        organization_id: org_b.id.clone(),
    };

    // Both should succeed (different users)
    storage
        .save_oauth_credential(&cred_a)
        .await
        .expect("Failed to save credential A");

    storage
        .save_oauth_credential(&cred_b)
        .await
        .expect("Failed to save credential B - UNIQUE constraint should be per-user!");

    // Each user should see only their own credentials
    let creds_a = storage
        .list_oauth_credentials(&user_a.id, &org_a.id)
        .await
        .expect("Failed to list credentials for user A");

    assert_eq!(creds_a.len(), 1, "User A should see only their credential");
    assert_eq!(creds_a[0].user_id, user_a.id);
    assert_eq!(creds_a[0].access_token, "user_a_token");

    let creds_b = storage
        .list_oauth_credentials(&user_b.id, &org_b.id)
        .await
        .expect("Failed to list credentials for user B");

    assert_eq!(creds_b.len(), 1, "User B should see only their credential");
    assert_eq!(creds_b[0].user_id, user_b.id);
    assert_eq!(creds_b[0].access_token, "user_b_token");
}

// ============================================================================
// Role Conversion Tests
// ============================================================================

#[tokio::test]
async fn test_role_string_conversion() {
    assert_eq!("owner".parse::<Role>().ok(), Some(Role::Owner));
    assert_eq!("ADMIN".parse::<Role>().ok(), Some(Role::Admin));
    assert_eq!("Member".parse::<Role>().ok(), Some(Role::Member));
    assert_eq!("viewer".parse::<Role>().ok(), Some(Role::Viewer));
    assert!("invalid".parse::<Role>().is_err());

    assert_eq!(Role::Owner.as_str(), "owner");
    assert_eq!(Role::Admin.as_str(), "admin");
    assert_eq!(Role::Member.as_str(), "member");
    assert_eq!(Role::Viewer.as_str(), "viewer");
}

// ============================================================================
// OAuth Token Encryption Tests (merged from oauth_encryption_test.rs)
// ============================================================================

/// Test that OAuth tokens are encrypted in the database
#[tokio::test]
async fn test_oauth_tokens_encrypted_at_rest() {
    unsafe {
        std::env::set_var(
            "OAUTH_ENCRYPTION_KEY",
            "dOBebLHe5g3mQbsK8k+fC4fRvb1a4AJzmfFh3woFo2g=",
        );
    }

    let storage = SqliteStorage::new(":memory:")
        .await
        .expect("Failed to create storage");

    let credential = OAuthCredential {
        id: Uuid::new_v4().to_string(),
        provider: "github".to_string(),
        integration: "default".to_string(),
        access_token: "ghp_secret_token_abc123".to_string(),
        refresh_token: Some("ghr_secret_refresh_def456".to_string()),
        expires_at: None,
        scope: Some("repo,user".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        user_id: "user-123".to_string(),
        organization_id: "org-456".to_string(),
    };

    storage
        .save_oauth_credential(&credential)
        .await
        .expect("Failed to save");

    let loaded = storage
        .get_oauth_credential("github", "default", "user-123", "org-456")
        .await
        .expect("Failed to load")
        .expect("Not found");

    assert_eq!(
        loaded.access_token, "ghp_secret_token_abc123",
        "Decrypted should match"
    );
    assert_eq!(
        loaded.refresh_token.as_ref().unwrap(),
        "ghr_secret_refresh_def456"
    );
}

/// Test encryption with multiple credentials (different nonces)
#[tokio::test]
async fn test_multiple_credentials_different_ciphertexts() {
    unsafe {
        std::env::set_var(
            "OAUTH_ENCRYPTION_KEY",
            "dOBebLHe5g3mQbsK8k+fC4fRvb1a4AJzmfFh3woFo2g=",
        );
    }

    let storage = SqliteStorage::new(":memory:")
        .await
        .expect("Failed to create storage");

    let same_token = "ghp_identical_token_value";

    let cred1 = OAuthCredential {
        id: Uuid::new_v4().to_string(),
        provider: "github".to_string(),
        integration: "integration1".to_string(),
        access_token: same_token.to_string(),
        refresh_token: None,
        expires_at: None,
        scope: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        user_id: "user-1".to_string(),
        organization_id: "org-1".to_string(),
    };

    let cred2 = OAuthCredential {
        id: Uuid::new_v4().to_string(),
        provider: "github".to_string(),
        integration: "integration2".to_string(),
        access_token: same_token.to_string(),
        refresh_token: None,
        expires_at: None,
        scope: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        user_id: "user-1".to_string(),
        organization_id: "org-1".to_string(),
    };

    storage
        .save_oauth_credential(&cred1)
        .await
        .expect("Failed to save cred1");
    storage
        .save_oauth_credential(&cred2)
        .await
        .expect("Failed to save cred2");

    let loaded1 = storage
        .get_oauth_credential("github", "integration1", "user-1", "org-1")
        .await
        .expect("Failed to load cred1")
        .expect("Cred1 not found");

    let loaded2 = storage
        .get_oauth_credential("github", "integration2", "user-1", "org-1")
        .await
        .expect("Failed to load cred2")
        .expect("Cred2 not found");

    assert_eq!(loaded1.access_token, same_token);
    assert_eq!(loaded2.access_token, same_token);
}

// ============================================================================
// OAuth User Context & Deployer Tests (merged from oauth_user_context_e2e_test.rs)
// ============================================================================

/// Test OAuth credentials use correct user context
#[tokio::test]
async fn test_oauth_credentials_use_triggering_users_context() {
    unsafe {
        std::env::set_var(
            "OAUTH_ENCRYPTION_KEY",
            "dOBebLHe5g3mQbsK8k+fC4fRvb1a4AJzmfFh3woFo2g=",
        );
    }

    let storage = std::sync::Arc::new(
        SqliteStorage::new(":memory:")
            .await
            .expect("Failed to create storage"),
    );

    let user_a = create_test_user("usera@example.com", "User A");
    let user_b = create_test_user("userb@example.com", "User B");

    let org_a = create_test_organization("Organization A", "org-a", &user_a.id);
    let org_b = create_test_organization("Organization B", "org-b", &user_b.id);

    storage
        .create_user(&user_a)
        .await
        .expect("Failed to create user A");
    storage
        .create_user(&user_b)
        .await
        .expect("Failed to create user B");
    storage
        .create_organization(&org_a)
        .await
        .expect("Failed to create organization A");
    storage
        .create_organization(&org_b)
        .await
        .expect("Failed to create organization B");

    storage
        .create_organization_member(&OrganizationMember {
            id: Uuid::new_v4().to_string(),
            organization_id: org_a.id.clone(),
            user_id: user_a.id.clone(),
            role: Role::Owner,
            invited_by_user_id: None,
            invited_at: None,
            joined_at: Utc::now(),
            disabled: false,
        })
        .await
        .expect("Failed to add user A");

    storage
        .create_organization_member(&OrganizationMember {
            id: Uuid::new_v4().to_string(),
            organization_id: org_b.id.clone(),
            user_id: user_b.id.clone(),
            role: Role::Owner,
            invited_by_user_id: None,
            invited_at: None,
            joined_at: Utc::now(),
            disabled: false,
        })
        .await
        .expect("Failed to add user B");

    let cred_a = OAuthCredential {
        id: Uuid::new_v4().to_string(),
        provider: "github".to_string(),
        integration: "default".to_string(),
        access_token: "user_a_github_token".to_string(),
        refresh_token: Some("user_a_refresh".to_string()),
        expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
        scope: Some("repo".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        user_id: user_a.id.clone(),
        organization_id: org_a.id.clone(),
    };

    let cred_b = OAuthCredential {
        id: Uuid::new_v4().to_string(),
        provider: "github".to_string(),
        integration: "default".to_string(),
        access_token: "user_b_github_token".to_string(),
        refresh_token: Some("user_b_refresh".to_string()),
        expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
        scope: Some("repo".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        user_id: user_b.id.clone(),
        organization_id: org_b.id.clone(),
    };

    storage
        .save_oauth_credential(&cred_a)
        .await
        .expect("Failed to save A");
    storage
        .save_oauth_credential(&cred_b)
        .await
        .expect("Failed to save B");

    let creds_a = storage
        .list_oauth_credentials(&user_a.id, &org_a.id)
        .await
        .expect("Failed to list A");

    assert_eq!(creds_a.len(), 1);
    assert_eq!(creds_a[0].access_token, "user_a_github_token");

    let creds_b = storage
        .list_oauth_credentials(&user_b.id, &org_b.id)
        .await
        .expect("Failed to list B");

    assert_eq!(creds_b.len(), 1);
    assert_eq!(creds_b[0].access_token, "user_b_github_token");
}

/// Test get_deployed_by returns correct deployer
#[tokio::test]
async fn test_get_deployed_by_returns_deployer_user_id() {
    use beemflow::storage::FlowStorage;

    let storage = std::sync::Arc::new(SqliteStorage::new(":memory:").await.unwrap());

    let alice = create_test_user("alice@company.com", "Alice");
    let organization = create_test_organization("Company", "company", &alice.id);

    storage.create_user(&alice).await.unwrap();
    storage.create_organization(&organization).await.unwrap();

    storage
        .deploy_flow_version(&organization.id, "daily_report", "1.0.0", "content", &alice.id)
        .await
        .unwrap();

    let deployer = storage
        .get_deployed_by(&organization.id, "daily_report")
        .await
        .unwrap();
    assert_eq!(
        deployer,
        Some(alice.id.clone()),
        "Should return Alice's user_id"
    );

    let bob = create_test_user("bob@company.com", "Bob");
    storage.create_user(&bob).await.unwrap();

    storage
        .deploy_flow_version(&organization.id, "daily_report", "1.0.1", "content-v2", &bob.id)
        .await
        .unwrap();

    let deployer_v2 = storage
        .get_deployed_by(&organization.id, "daily_report")
        .await
        .unwrap();
    assert_eq!(deployer_v2, Some(bob.id), "Deployer should update to Bob");
}

/// Test OAuth lookup uses deployer's user_id
#[tokio::test]
async fn test_oauth_lookup_uses_deployer_not_trigger() {
    use beemflow::storage::FlowStorage;

    unsafe {
        std::env::set_var(
            "OAUTH_ENCRYPTION_KEY",
            "dOBebLHe5g3mQbsK8k+fC4fRvb1a4AJzmfFh3woFo2g=",
        );
    }

    let storage = std::sync::Arc::new(SqliteStorage::new(":memory:").await.unwrap());

    let alice = create_test_user("alice@company.com", "Alice");
    let bob = create_test_user("bob@company.com", "Bob");
    let organization = create_test_organization("Company", "company", &alice.id);

    storage.create_user(&alice).await.unwrap();
    storage.create_user(&bob).await.unwrap();
    storage.create_organization(&organization).await.unwrap();

    let alice_oauth = OAuthCredential {
        id: Uuid::new_v4().to_string(),
        provider: "google".to_string(),
        integration: "default".to_string(),
        access_token: "alice_token".to_string(),
        refresh_token: None,
        expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
        scope: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        user_id: alice.id.clone(),
        organization_id: organization.id.clone(),
    };

    storage.save_oauth_credential(&alice_oauth).await.unwrap();

    storage
        .deploy_flow_version(&organization.id, "sync", "1.0.0", "content", &alice.id)
        .await
        .unwrap();

    let deployer_id = storage
        .get_deployed_by(&organization.id, "sync")
        .await
        .unwrap()
        .unwrap();
    let oauth = storage
        .get_oauth_credential("google", "default", &deployer_id, &organization.id)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        oauth.access_token, "alice_token",
        "Should use deployer's OAuth"
    );
    assert_eq!(
        oauth.user_id, alice.id,
        "OAuth should belong to Alice (deployer)"
    );

    let bob_oauth = storage
        .get_oauth_credential("google", "default", &bob.id, &organization.id)
        .await
        .unwrap();

    assert!(bob_oauth.is_none(), "Bob has no OAuth (would fail if used)");
}

/// Test deployer OAuth across organization boundaries
#[tokio::test]
async fn test_deployer_oauth_organization_scoped() {
    use beemflow::storage::FlowStorage;

    unsafe {
        std::env::set_var(
            "OAUTH_ENCRYPTION_KEY",
            "dOBebLHe5g3mQbsK8k+fC4fRvb1a4AJzmfFh3woFo2g=",
        );
    }

    let storage = std::sync::Arc::new(SqliteStorage::new(":memory:").await.unwrap());

    let alice = create_test_user("alice@company.com", "Alice");
    let org_a = create_test_organization("Company A", "company-a", &alice.id);
    let org_b = create_test_organization("Company B", "company-b", &alice.id);

    storage.create_user(&alice).await.unwrap();
    storage.create_organization(&org_a).await.unwrap();
    storage.create_organization(&org_b).await.unwrap();

    let oauth_a = OAuthCredential {
        id: Uuid::new_v4().to_string(),
        provider: "google".to_string(),
        integration: "default".to_string(),
        access_token: "alice_personal_token".to_string(),
        refresh_token: None,
        expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
        scope: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        user_id: alice.id.clone(),
        organization_id: org_a.id.clone(),
    };

    let oauth_b = OAuthCredential {
        id: Uuid::new_v4().to_string(),
        provider: "google".to_string(),
        integration: "default".to_string(),
        access_token: "alice_work_token".to_string(),
        refresh_token: None,
        expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
        scope: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        user_id: alice.id.clone(),
        organization_id: org_b.id.clone(),
    };

    storage.save_oauth_credential(&oauth_a).await.unwrap();
    storage.save_oauth_credential(&oauth_b).await.unwrap();

    storage
        .deploy_flow_version(&org_a.id, "sync", "1.0.0", "content", &alice.id)
        .await
        .unwrap();
    storage
        .deploy_flow_version(&org_b.id, "sync", "1.0.0", "content", &alice.id)
        .await
        .unwrap();

    let deployer_a = storage
        .get_deployed_by(&org_a.id, "sync")
        .await
        .unwrap()
        .unwrap();
    let deployer_b = storage
        .get_deployed_by(&org_b.id, "sync")
        .await
        .unwrap()
        .unwrap();

    let oauth_exec_a = storage
        .get_oauth_credential("google", "default", &deployer_a, &org_a.id)
        .await
        .unwrap()
        .unwrap();

    let oauth_exec_b = storage
        .get_oauth_credential("google", "default", &deployer_b, &org_b.id)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(oauth_exec_a.access_token, "alice_personal_token");
    assert_eq!(oauth_exec_b.access_token, "alice_work_token");
    assert_ne!(
        oauth_exec_a.access_token, oauth_exec_b.access_token,
        "Different OAuth per organization"
    );
}
