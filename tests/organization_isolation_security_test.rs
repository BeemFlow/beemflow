//! Security tests for multi-organization isolation
//!
//! These tests verify that the multi-organization system properly isolates data between organizations
//! and that users cannot access resources from other organizations.
//!
//! CRITICAL: All tests must pass for production deployment.

use beemflow::auth::{Organization, User, hash_password};
use beemflow::model::{FlowName, Run, RunStatus};
use beemflow::storage::{AuthStorage, FlowStorage, RunStorage, SqliteStorage};
use chrono::Utc;
use uuid::Uuid;

/// Create test storage with clean schema
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
        password_hash: hash_password("TestPassword123").unwrap(),
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

/// Create test run
fn create_test_run(flow_name: &str, organization_id: &str, user_id: &str) -> Run {
    Run {
        id: Uuid::new_v4(),
        flow_name: FlowName::new(flow_name).expect("Valid flow name"),
        event: std::collections::HashMap::new(),
        vars: std::collections::HashMap::new(),
        status: RunStatus::Succeeded,
        started_at: Utc::now(),
        ended_at: Some(Utc::now()),
        steps: None,
        organization_id: organization_id.to_string(),
        triggered_by_user_id: user_id.to_string(),
    }
}

// ============================================================================
// CRITICAL SECURITY TEST: Run Isolation
// ============================================================================

#[tokio::test]
async fn test_runs_cannot_be_accessed_across_organizations() {
    let storage = create_test_storage().await;

    // Create two separate organizations
    let user_a = create_test_user("usera@acme.com", "User A");
    let user_b = create_test_user("userb@globex.com", "User B");

    let org_a = create_test_organization("ACME Corp", "acme", &user_a.id);
    let org_b = create_test_organization("Globex Inc", "globex", &user_b.id);

    storage.create_user(&user_a).await.unwrap();
    storage.create_user(&user_b).await.unwrap();
    storage.create_organization(&org_a).await.unwrap();
    storage.create_organization(&org_b).await.unwrap();

    // Create runs in each organization
    let run_a = create_test_run("workflow-a", &org_a.id, &user_a.id);
    let run_b = create_test_run("workflow-b", &org_b.id, &user_b.id);

    storage.save_run(&run_a).await.unwrap();
    storage.save_run(&run_b).await.unwrap();

    // ✅ CRITICAL TEST: OrganizationA can access their own run
    let result_a = storage.get_run(run_a.id, &org_a.id).await.unwrap();
    assert!(result_a.is_some(), "OrganizationA should see their own run");
    assert_eq!(result_a.unwrap().organization_id, org_a.id);

    // ✅ CRITICAL TEST: OrganizationA CANNOT access OrganizationB's run (returns None, not error)
    let result_cross = storage.get_run(run_b.id, &org_a.id).await.unwrap();
    assert!(
        result_cross.is_none(),
        "OrganizationA should NOT see OrganizationB's run (cross-organization access blocked)"
    );

    // ✅ CRITICAL TEST: OrganizationB can access their own run
    let result_b = storage.get_run(run_b.id, &org_b.id).await.unwrap();
    assert!(result_b.is_some(), "OrganizationB should see their own run");
    assert_eq!(result_b.unwrap().organization_id, org_b.id);

    // ✅ CRITICAL TEST: list_runs returns only organization's runs
    let runs_a = storage.list_runs(&org_a.id, 100, 0).await.unwrap();
    assert_eq!(runs_a.len(), 1, "OrganizationA should see exactly 1 run");
    assert_eq!(runs_a[0].id, run_a.id);

    let runs_b = storage.list_runs(&org_b.id, 100, 0).await.unwrap();
    assert_eq!(runs_b.len(), 1, "OrganizationB should see exactly 1 run");
    assert_eq!(runs_b[0].id, run_b.id);

    println!("✅ Run isolation verified: Cross-organization access properly blocked");
}

// ============================================================================
// CRITICAL SECURITY TEST: Flow Deployment Isolation
// ============================================================================

#[tokio::test]
async fn test_flow_deployments_isolated_across_organizations() {
    let storage = create_test_storage().await;

    // Create two separate organizations
    let user_a = create_test_user("usera@acme.com", "User A");
    let user_b = create_test_user("userb@globex.com", "User B");

    let org_a = create_test_organization("ACME Corp", "acme", &user_a.id);
    let org_b = create_test_organization("Globex Inc", "globex", &user_b.id);

    storage.create_user(&user_a).await.unwrap();
    storage.create_user(&user_b).await.unwrap();
    storage.create_organization(&org_a).await.unwrap();
    storage.create_organization(&org_b).await.unwrap();

    // Both organizations deploy flows with the SAME name
    let flow_name = "customer-webhook";
    let content_a = "name: customer-webhook\nsteps:\n  - log: ACME version";
    let content_b = "name: customer-webhook\nsteps:\n  - log: Globex version";

    storage
        .deploy_flow_version(&org_a.id, flow_name, "v1.0", content_a, &user_a.id)
        .await
        .expect("OrganizationA should deploy successfully");

    storage
        .deploy_flow_version(&org_b.id, flow_name, "v1.0", content_b, &user_b.id)
        .await
        .expect("OrganizationB should deploy successfully (no conflict with OrganizationA)");

    // ✅ CRITICAL TEST: OrganizationA gets their version
    let version_a = storage
        .get_flow_version_content(&org_a.id, flow_name, "v1.0")
        .await
        .unwrap()
        .expect("OrganizationA's version should exist");
    assert!(
        version_a.contains("ACME version"),
        "OrganizationA should get their version, not OrganizationB's"
    );

    // ✅ CRITICAL TEST: OrganizationB gets their version
    let version_b = storage
        .get_flow_version_content(&org_b.id, flow_name, "v1.0")
        .await
        .unwrap()
        .expect("OrganizationB's version should exist");
    assert!(
        version_b.contains("Globex version"),
        "OrganizationB should get their version, not OrganizationA's"
    );

    // ✅ CRITICAL TEST: OrganizationA cannot access OrganizationB's flow
    let cross_access = storage
        .get_flow_version_content(&org_a.id, flow_name, "v1.0")
        .await
        .unwrap();
    assert!(
        cross_access.is_some() && !cross_access.unwrap().contains("Globex version"),
        "OrganizationA should not see OrganizationB's flow content"
    );

    println!("✅ Flow deployment isolation verified: Same flow names coexist across organizations");
}

// ============================================================================
// CRITICAL SECURITY TEST: Flow Deployment List Isolation
// ============================================================================

#[tokio::test]
async fn test_deployed_flows_list_isolated_by_organization() {
    let storage = create_test_storage().await;

    let user_a = create_test_user("usera@acme.com", "User A");
    let user_b = create_test_user("userb@globex.com", "User B");

    let org_a = create_test_organization("ACME Corp", "acme", &user_a.id);
    let org_b = create_test_organization("Globex Inc", "globex", &user_b.id);

    storage.create_user(&user_a).await.unwrap();
    storage.create_user(&user_b).await.unwrap();
    storage.create_organization(&org_a).await.unwrap();
    storage.create_organization(&org_b).await.unwrap();

    // OrganizationA deploys 2 flows
    storage
        .deploy_flow_version(&org_a.id, "flow-1", "v1", "content-a1", &user_a.id)
        .await
        .unwrap();
    storage
        .deploy_flow_version(&org_a.id, "flow-2", "v1", "content-a2", &user_a.id)
        .await
        .unwrap();

    // OrganizationB deploys 3 flows
    storage
        .deploy_flow_version(&org_b.id, "flow-1", "v1", "content-b1", &user_b.id)
        .await
        .unwrap();
    storage
        .deploy_flow_version(&org_b.id, "flow-3", "v1", "content-b3", &user_b.id)
        .await
        .unwrap();
    storage
        .deploy_flow_version(&org_b.id, "flow-4", "v1", "content-b4", &user_b.id)
        .await
        .unwrap();

    // ✅ CRITICAL TEST: OrganizationA sees only their 2 flows
    let flows_a = storage.list_all_deployed_flows(&org_a.id).await.unwrap();
    assert_eq!(flows_a.len(), 2, "OrganizationA should see exactly 2 flows");

    let flow_names_a: Vec<&str> = flows_a.iter().map(|(name, _)| name.as_str()).collect();
    assert!(flow_names_a.contains(&"flow-1"));
    assert!(flow_names_a.contains(&"flow-2"));
    assert!(
        !flow_names_a.contains(&"flow-3"),
        "OrganizationA should NOT see OrganizationB's flow-3"
    );
    assert!(
        !flow_names_a.contains(&"flow-4"),
        "OrganizationA should NOT see OrganizationB's flow-4"
    );

    // ✅ CRITICAL TEST: OrganizationB sees only their 3 flows
    let flows_b = storage.list_all_deployed_flows(&org_b.id).await.unwrap();
    assert_eq!(flows_b.len(), 3, "OrganizationB should see exactly 3 flows");

    let flow_names_b: Vec<&str> = flows_b.iter().map(|(name, _)| name.as_str()).collect();
    assert!(
        flow_names_b.contains(&"flow-1"),
        "OrganizationB has their own flow-1"
    );
    assert!(flow_names_b.contains(&"flow-3"));
    assert!(flow_names_b.contains(&"flow-4"));
    assert!(
        !flow_names_b.contains(&"flow-2"),
        "OrganizationB should NOT see OrganizationA's flow-2"
    );

    println!("✅ Flow list isolation verified: Each organization sees only their flows");
}

// ============================================================================
// CRITICAL SECURITY TEST: Batch Flow Content Retrieval Isolation
// ============================================================================

#[tokio::test]
async fn test_batch_flow_content_isolated_by_organization() {
    let storage = create_test_storage().await;

    let user_a = create_test_user("usera@acme.com", "User A");
    let user_b = create_test_user("userb@globex.com", "User B");

    let org_a = create_test_organization("ACME Corp", "acme", &user_a.id);
    let org_b = create_test_organization("Globex Inc", "globex", &user_b.id);

    storage.create_user(&user_a).await.unwrap();
    storage.create_user(&user_b).await.unwrap();
    storage.create_organization(&org_a).await.unwrap();
    storage.create_organization(&org_b).await.unwrap();

    // Both organizations have flows with same names
    storage
        .deploy_flow_version(&org_a.id, "flow-1", "v1", "content-a1", &user_a.id)
        .await
        .unwrap();
    storage
        .deploy_flow_version(&org_a.id, "flow-2", "v1", "content-a2", &user_a.id)
        .await
        .unwrap();

    storage
        .deploy_flow_version(&org_b.id, "flow-1", "v1", "content-b1", &user_b.id)
        .await
        .unwrap();
    storage
        .deploy_flow_version(&org_b.id, "flow-3", "v1", "content-b3", &user_b.id)
        .await
        .unwrap();

    // ✅ CRITICAL TEST: Batch query for OrganizationA returns only their flows
    let flow_names_a = vec![
        "flow-1".to_string(),
        "flow-2".to_string(),
        "flow-3".to_string(),
    ];
    let contents_a = storage
        .get_deployed_flows_content(&org_a.id, &flow_names_a)
        .await
        .unwrap();

    // Should only return flow-1 and flow-2 (OrganizationA's flows), NOT flow-3 (OrganizationB's)
    assert_eq!(contents_a.len(), 2, "OrganizationA should get 2 flows");

    let returned_names_a: Vec<&str> = contents_a.iter().map(|(name, _)| name.as_str()).collect();
    assert!(returned_names_a.contains(&"flow-1"));
    assert!(returned_names_a.contains(&"flow-2"));
    assert!(
        !returned_names_a.contains(&"flow-3"),
        "Should NOT return OrganizationB's flow-3"
    );

    // Verify content is correct
    let flow1_content = contents_a
        .iter()
        .find(|(n, _)| n == "flow-1")
        .map(|(_, c)| c);
    assert_eq!(
        flow1_content,
        Some(&"content-a1".to_string()),
        "OrganizationA gets their content, not OrganizationB's"
    );

    // ✅ CRITICAL TEST: Batch query for OrganizationB returns only their flows
    let flow_names_b = vec![
        "flow-1".to_string(),
        "flow-2".to_string(),
        "flow-3".to_string(),
    ];
    let contents_b = storage
        .get_deployed_flows_content(&org_b.id, &flow_names_b)
        .await
        .unwrap();

    assert_eq!(
        contents_b.len(),
        2,
        "OrganizationB should get 2 flows (flow-1 and flow-3)"
    );

    let returned_names_b: Vec<&str> = contents_b.iter().map(|(name, _)| name.as_str()).collect();
    assert!(
        returned_names_b.contains(&"flow-1"),
        "OrganizationB has their own flow-1"
    );
    assert!(returned_names_b.contains(&"flow-3"));
    assert!(
        !returned_names_b.contains(&"flow-2"),
        "Should NOT return OrganizationA's flow-2"
    );

    println!("✅ Batch content retrieval isolation verified");
}

// ============================================================================
// CRITICAL SECURITY TEST: Flow Version History Isolation
// ============================================================================

#[tokio::test]
async fn test_flow_version_history_isolated() {
    let storage = create_test_storage().await;

    let user_a = create_test_user("usera@acme.com", "User A");
    let user_b = create_test_user("userb@globex.com", "User B");

    let org_a = create_test_organization("ACME Corp", "acme", &user_a.id);
    let org_b = create_test_organization("Globex Inc", "globex", &user_b.id);

    storage.create_user(&user_a).await.unwrap();
    storage.create_user(&user_b).await.unwrap();
    storage.create_organization(&org_a).await.unwrap();
    storage.create_organization(&org_b).await.unwrap();

    // Both organizations deploy multiple versions of "api-handler"
    let flow_name = "api-handler";

    // OrganizationA deploys v1.0, v1.1, v1.2
    storage
        .deploy_flow_version(&org_a.id, flow_name, "v1.0", "content-a-v1.0", &user_a.id)
        .await
        .unwrap();
    storage
        .deploy_flow_version(&org_a.id, flow_name, "v1.1", "content-a-v1.1", &user_a.id)
        .await
        .unwrap();
    storage
        .deploy_flow_version(&org_a.id, flow_name, "v1.2", "content-a-v1.2", &user_a.id)
        .await
        .unwrap();

    // OrganizationB deploys v2.0, v2.1
    storage
        .deploy_flow_version(&org_b.id, flow_name, "v2.0", "content-b-v2.0", &user_b.id)
        .await
        .unwrap();
    storage
        .deploy_flow_version(&org_b.id, flow_name, "v2.1", "content-b-v2.1", &user_b.id)
        .await
        .unwrap();

    // ✅ CRITICAL TEST: OrganizationA sees only their versions
    let versions_a = storage
        .list_flow_versions(&org_a.id, flow_name)
        .await
        .unwrap();
    assert_eq!(versions_a.len(), 3, "OrganizationA should see 3 versions");

    let version_strings_a: Vec<&str> = versions_a.iter().map(|v| v.version.as_str()).collect();
    assert!(version_strings_a.contains(&"v1.0"));
    assert!(version_strings_a.contains(&"v1.1"));
    assert!(version_strings_a.contains(&"v1.2"));
    assert!(
        !version_strings_a.contains(&"v2.0"),
        "OrganizationA should NOT see OrganizationB's versions"
    );

    // ✅ CRITICAL TEST: OrganizationB sees only their versions
    let versions_b = storage
        .list_flow_versions(&org_b.id, flow_name)
        .await
        .unwrap();
    assert_eq!(versions_b.len(), 2, "OrganizationB should see 2 versions");

    let version_strings_b: Vec<&str> = versions_b.iter().map(|v| v.version.as_str()).collect();
    assert!(version_strings_b.contains(&"v2.0"));
    assert!(version_strings_b.contains(&"v2.1"));
    assert!(
        !version_strings_b.contains(&"v1.0"),
        "OrganizationB should NOT see OrganizationA's versions"
    );

    println!("✅ Flow version isolation verified: Version histories are organization-scoped");
}

// ============================================================================
// CRITICAL SECURITY TEST: Run Deletion Isolation
// ============================================================================

#[tokio::test]
async fn test_run_deletion_respects_organization_boundaries() {
    let storage = create_test_storage().await;

    let user_a = create_test_user("usera@acme.com", "User A");
    let user_b = create_test_user("userb@globex.com", "User B");

    let org_a = create_test_organization("ACME Corp", "acme", &user_a.id);
    let org_b = create_test_organization("Globex Inc", "globex", &user_b.id);

    storage.create_user(&user_a).await.unwrap();
    storage.create_user(&user_b).await.unwrap();
    storage.create_organization(&org_a).await.unwrap();
    storage.create_organization(&org_b).await.unwrap();

    // Create runs
    let run_a = create_test_run("workflow-a", &org_a.id, &user_a.id);
    let run_b = create_test_run("workflow-b", &org_b.id, &user_b.id);

    storage.save_run(&run_a).await.unwrap();
    storage.save_run(&run_b).await.unwrap();

    // ✅ CRITICAL TEST: OrganizationA cannot delete OrganizationB's run
    let delete_result = storage.delete_run(run_b.id, &org_a.id).await;
    assert!(
        delete_result.is_err(),
        "OrganizationA should NOT be able to delete OrganizationB's run"
    );

    // Verify run B still exists
    let run_b_check = storage.get_run(run_b.id, &org_b.id).await.unwrap();
    assert!(
        run_b_check.is_some(),
        "OrganizationB's run should still exist after failed cross-organization delete"
    );

    // ✅ CRITICAL TEST: OrganizationA CAN delete their own run
    storage
        .delete_run(run_a.id, &org_a.id)
        .await
        .expect("OrganizationA should delete their own run");

    let run_a_check = storage.get_run(run_a.id, &org_a.id).await.unwrap();
    assert!(run_a_check.is_none(), "Run A should be deleted");

    println!("✅ Deletion isolation verified: Cross-organization deletion blocked");
}

// ============================================================================
// CRITICAL SECURITY TEST: Deployed Version Pointer Isolation
// ============================================================================

#[tokio::test]
async fn test_deployed_version_pointers_isolated() {
    let storage = create_test_storage().await;

    let user_a = create_test_user("usera@acme.com", "User A");
    let user_b = create_test_user("userb@globex.com", "User B");

    let org_a = create_test_organization("ACME Corp", "acme", &user_a.id);
    let org_b = create_test_organization("Globex Inc", "globex", &user_b.id);

    storage.create_user(&user_a).await.unwrap();
    storage.create_user(&user_b).await.unwrap();
    storage.create_organization(&org_a).await.unwrap();
    storage.create_organization(&org_b).await.unwrap();

    let flow_name = "api-handler";

    // Both organizations deploy the same flow name
    storage
        .deploy_flow_version(&org_a.id, flow_name, "v1.0", "content-a", &user_a.id)
        .await
        .unwrap();
    storage
        .deploy_flow_version(&org_b.id, flow_name, "v2.0", "content-b", &user_b.id)
        .await
        .unwrap();

    // ✅ CRITICAL TEST: OrganizationA's deployed version is v1.0
    let deployed_a = storage
        .get_deployed_version(&org_a.id, flow_name)
        .await
        .unwrap()
        .expect("OrganizationA should have deployed version");
    assert_eq!(
        deployed_a, "v1.0",
        "OrganizationA should have v1.0 deployed"
    );

    // ✅ CRITICAL TEST: OrganizationB's deployed version is v2.0 (NOT affected by OrganizationA)
    let deployed_b = storage
        .get_deployed_version(&org_b.id, flow_name)
        .await
        .unwrap()
        .expect("OrganizationB should have deployed version");
    assert_eq!(
        deployed_b, "v2.0",
        "OrganizationB should have v2.0 deployed (independent of OrganizationA)"
    );

    // OrganizationA disables their deployment
    storage
        .unset_deployed_version(&org_a.id, flow_name)
        .await
        .unwrap();

    // ✅ CRITICAL TEST: OrganizationA's deployment is disabled
    let deployed_a_after = storage
        .get_deployed_version(&org_a.id, flow_name)
        .await
        .unwrap();
    assert!(
        deployed_a_after.is_none(),
        "OrganizationA's deployment should be unset"
    );

    // ✅ CRITICAL TEST: OrganizationB's deployment is UNAFFECTED
    let deployed_b_after = storage
        .get_deployed_version(&org_b.id, flow_name)
        .await
        .unwrap();
    assert_eq!(
        deployed_b_after.unwrap(),
        "v2.0",
        "OrganizationB's deployment should be UNAFFECTED by OrganizationA's disable"
    );

    println!(
        "✅ Deployment pointer isolation verified: Each organization manages their own deployments"
    );
}

// ============================================================================
// CRITICAL SECURITY TEST: Run Filtering by Flow and Status
// ============================================================================

#[tokio::test]
async fn test_run_filtering_respects_organization_boundaries() {
    let storage = create_test_storage().await;

    let user_a = create_test_user("usera@acme.com", "User A");
    let user_b = create_test_user("userb@globex.com", "User B");

    let org_a = create_test_organization("ACME Corp", "acme", &user_a.id);
    let org_b = create_test_organization("Globex Inc", "globex", &user_b.id);

    storage.create_user(&user_a).await.unwrap();
    storage.create_user(&user_b).await.unwrap();
    storage.create_organization(&org_a).await.unwrap();
    storage.create_organization(&org_b).await.unwrap();

    // Both organizations have runs for "data-sync" flow
    let mut run_a1 = create_test_run("data-sync", &org_a.id, &user_a.id);
    run_a1.status = RunStatus::Succeeded;

    let mut run_a2 = create_test_run("data-sync", &org_a.id, &user_a.id);
    run_a2.status = RunStatus::Failed;

    let mut run_b1 = create_test_run("data-sync", &org_b.id, &user_b.id);
    run_b1.status = RunStatus::Succeeded;

    storage.save_run(&run_a1).await.unwrap();
    storage.save_run(&run_a2).await.unwrap();
    storage.save_run(&run_b1).await.unwrap();

    // ✅ CRITICAL TEST: OrganizationA finds only their successful runs
    let successful_a = storage
        .list_runs_by_flow_and_status(&org_a.id, "data-sync", RunStatus::Succeeded, None, 10)
        .await
        .unwrap();

    assert_eq!(
        successful_a.len(),
        1,
        "OrganizationA should find 1 successful run"
    );
    assert_eq!(successful_a[0].id, run_a1.id);
    assert_ne!(
        successful_a[0].id, run_b1.id,
        "OrganizationA should NOT see OrganizationB's run"
    );

    // ✅ CRITICAL TEST: OrganizationB finds only their run (not OrganizationA's)
    let successful_b = storage
        .list_runs_by_flow_and_status(&org_b.id, "data-sync", RunStatus::Succeeded, None, 10)
        .await
        .unwrap();

    assert_eq!(
        successful_b.len(),
        1,
        "OrganizationB should find 1 successful run"
    );
    assert_eq!(successful_b[0].id, run_b1.id);

    println!("✅ Run filtering isolation verified: Filters respect organization boundaries");
}
