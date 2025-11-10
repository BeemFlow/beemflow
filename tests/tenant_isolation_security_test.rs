//! Security tests for multi-tenant isolation
//!
//! These tests verify that the multi-tenant system properly isolates data between tenants
//! and that users cannot access resources from other tenants.
//!
//! CRITICAL: All tests must pass for production deployment.

use beemflow::auth::{Tenant, User, hash_password};
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

/// Create test tenant
fn create_test_tenant(name: &str, slug: &str, creator_id: &str) -> Tenant {
    Tenant {
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
fn create_test_run(flow_name: &str, tenant_id: &str, user_id: &str) -> Run {
    Run {
        id: Uuid::new_v4(),
        flow_name: FlowName::new(flow_name).expect("Valid flow name"),
        event: std::collections::HashMap::new(),
        vars: std::collections::HashMap::new(),
        status: RunStatus::Succeeded,
        started_at: Utc::now(),
        ended_at: Some(Utc::now()),
        steps: None,
        tenant_id: tenant_id.to_string(),
        triggered_by_user_id: user_id.to_string(),
    }
}

// ============================================================================
// CRITICAL SECURITY TEST: Run Isolation
// ============================================================================

#[tokio::test]
async fn test_runs_cannot_be_accessed_across_tenants() {
    let storage = create_test_storage().await;

    // Create two separate tenants
    let user_a = create_test_user("usera@acme.com", "User A");
    let user_b = create_test_user("userb@globex.com", "User B");

    let tenant_a = create_test_tenant("ACME Corp", "acme", &user_a.id);
    let tenant_b = create_test_tenant("Globex Inc", "globex", &user_b.id);

    storage.create_user(&user_a).await.unwrap();
    storage.create_user(&user_b).await.unwrap();
    storage.create_tenant(&tenant_a).await.unwrap();
    storage.create_tenant(&tenant_b).await.unwrap();

    // Create runs in each tenant
    let run_a = create_test_run("workflow-a", &tenant_a.id, &user_a.id);
    let run_b = create_test_run("workflow-b", &tenant_b.id, &user_b.id);

    storage.save_run(&run_a).await.unwrap();
    storage.save_run(&run_b).await.unwrap();

    // ✅ CRITICAL TEST: Tenant A can access their own run
    let result_a = storage.get_run(run_a.id, &tenant_a.id).await.unwrap();
    assert!(result_a.is_some(), "Tenant A should see their own run");
    assert_eq!(result_a.unwrap().tenant_id, tenant_a.id);

    // ✅ CRITICAL TEST: Tenant A CANNOT access Tenant B's run (returns None, not error)
    let result_cross = storage.get_run(run_b.id, &tenant_a.id).await.unwrap();
    assert!(
        result_cross.is_none(),
        "Tenant A should NOT see Tenant B's run (cross-tenant access blocked)"
    );

    // ✅ CRITICAL TEST: Tenant B can access their own run
    let result_b = storage.get_run(run_b.id, &tenant_b.id).await.unwrap();
    assert!(result_b.is_some(), "Tenant B should see their own run");
    assert_eq!(result_b.unwrap().tenant_id, tenant_b.id);

    // ✅ CRITICAL TEST: list_runs returns only tenant's runs
    let runs_a = storage.list_runs(&tenant_a.id, 100, 0).await.unwrap();
    assert_eq!(runs_a.len(), 1, "Tenant A should see exactly 1 run");
    assert_eq!(runs_a[0].id, run_a.id);

    let runs_b = storage.list_runs(&tenant_b.id, 100, 0).await.unwrap();
    assert_eq!(runs_b.len(), 1, "Tenant B should see exactly 1 run");
    assert_eq!(runs_b[0].id, run_b.id);

    println!("✅ Run isolation verified: Cross-tenant access properly blocked");
}

// ============================================================================
// CRITICAL SECURITY TEST: Flow Deployment Isolation
// ============================================================================

#[tokio::test]
async fn test_flow_deployments_isolated_across_tenants() {
    let storage = create_test_storage().await;

    // Create two separate tenants
    let user_a = create_test_user("usera@acme.com", "User A");
    let user_b = create_test_user("userb@globex.com", "User B");

    let tenant_a = create_test_tenant("ACME Corp", "acme", &user_a.id);
    let tenant_b = create_test_tenant("Globex Inc", "globex", &user_b.id);

    storage.create_user(&user_a).await.unwrap();
    storage.create_user(&user_b).await.unwrap();
    storage.create_tenant(&tenant_a).await.unwrap();
    storage.create_tenant(&tenant_b).await.unwrap();

    // Both tenants deploy flows with the SAME name
    let flow_name = "customer-webhook";
    let content_a = "name: customer-webhook\nsteps:\n  - log: ACME version";
    let content_b = "name: customer-webhook\nsteps:\n  - log: Globex version";

    storage
        .deploy_flow_version(&tenant_a.id, flow_name, "v1.0", content_a, &user_a.id)
        .await
        .expect("Tenant A should deploy successfully");

    storage
        .deploy_flow_version(&tenant_b.id, flow_name, "v1.0", content_b, &user_b.id)
        .await
        .expect("Tenant B should deploy successfully (no conflict with Tenant A)");

    // ✅ CRITICAL TEST: Tenant A gets their version
    let version_a = storage
        .get_flow_version_content(&tenant_a.id, flow_name, "v1.0")
        .await
        .unwrap()
        .expect("Tenant A's version should exist");
    assert!(
        version_a.contains("ACME version"),
        "Tenant A should get their version, not Tenant B's"
    );

    // ✅ CRITICAL TEST: Tenant B gets their version
    let version_b = storage
        .get_flow_version_content(&tenant_b.id, flow_name, "v1.0")
        .await
        .unwrap()
        .expect("Tenant B's version should exist");
    assert!(
        version_b.contains("Globex version"),
        "Tenant B should get their version, not Tenant A's"
    );

    // ✅ CRITICAL TEST: Tenant A cannot access Tenant B's flow
    let cross_access = storage
        .get_flow_version_content(&tenant_a.id, flow_name, "v1.0")
        .await
        .unwrap();
    assert!(
        cross_access.is_some() && !cross_access.unwrap().contains("Globex version"),
        "Tenant A should not see Tenant B's flow content"
    );

    println!("✅ Flow deployment isolation verified: Same flow names coexist across tenants");
}

// ============================================================================
// CRITICAL SECURITY TEST: Flow Deployment List Isolation
// ============================================================================

#[tokio::test]
async fn test_deployed_flows_list_isolated_by_tenant() {
    let storage = create_test_storage().await;

    let user_a = create_test_user("usera@acme.com", "User A");
    let user_b = create_test_user("userb@globex.com", "User B");

    let tenant_a = create_test_tenant("ACME Corp", "acme", &user_a.id);
    let tenant_b = create_test_tenant("Globex Inc", "globex", &user_b.id);

    storage.create_user(&user_a).await.unwrap();
    storage.create_user(&user_b).await.unwrap();
    storage.create_tenant(&tenant_a).await.unwrap();
    storage.create_tenant(&tenant_b).await.unwrap();

    // Tenant A deploys 2 flows
    storage
        .deploy_flow_version(&tenant_a.id, "flow-1", "v1", "content-a1", &user_a.id)
        .await
        .unwrap();
    storage
        .deploy_flow_version(&tenant_a.id, "flow-2", "v1", "content-a2", &user_a.id)
        .await
        .unwrap();

    // Tenant B deploys 3 flows
    storage
        .deploy_flow_version(&tenant_b.id, "flow-1", "v1", "content-b1", &user_b.id)
        .await
        .unwrap();
    storage
        .deploy_flow_version(&tenant_b.id, "flow-3", "v1", "content-b3", &user_b.id)
        .await
        .unwrap();
    storage
        .deploy_flow_version(&tenant_b.id, "flow-4", "v1", "content-b4", &user_b.id)
        .await
        .unwrap();

    // ✅ CRITICAL TEST: Tenant A sees only their 2 flows
    let flows_a = storage.list_all_deployed_flows(&tenant_a.id).await.unwrap();
    assert_eq!(flows_a.len(), 2, "Tenant A should see exactly 2 flows");

    let flow_names_a: Vec<&str> = flows_a.iter().map(|(name, _)| name.as_str()).collect();
    assert!(flow_names_a.contains(&"flow-1"));
    assert!(flow_names_a.contains(&"flow-2"));
    assert!(
        !flow_names_a.contains(&"flow-3"),
        "Tenant A should NOT see Tenant B's flow-3"
    );
    assert!(
        !flow_names_a.contains(&"flow-4"),
        "Tenant A should NOT see Tenant B's flow-4"
    );

    // ✅ CRITICAL TEST: Tenant B sees only their 3 flows
    let flows_b = storage.list_all_deployed_flows(&tenant_b.id).await.unwrap();
    assert_eq!(flows_b.len(), 3, "Tenant B should see exactly 3 flows");

    let flow_names_b: Vec<&str> = flows_b.iter().map(|(name, _)| name.as_str()).collect();
    assert!(
        flow_names_b.contains(&"flow-1"),
        "Tenant B has their own flow-1"
    );
    assert!(flow_names_b.contains(&"flow-3"));
    assert!(flow_names_b.contains(&"flow-4"));
    assert!(
        !flow_names_b.contains(&"flow-2"),
        "Tenant B should NOT see Tenant A's flow-2"
    );

    println!("✅ Flow list isolation verified: Each tenant sees only their flows");
}

// ============================================================================
// CRITICAL SECURITY TEST: Batch Flow Content Retrieval Isolation
// ============================================================================

#[tokio::test]
async fn test_batch_flow_content_isolated_by_tenant() {
    let storage = create_test_storage().await;

    let user_a = create_test_user("usera@acme.com", "User A");
    let user_b = create_test_user("userb@globex.com", "User B");

    let tenant_a = create_test_tenant("ACME Corp", "acme", &user_a.id);
    let tenant_b = create_test_tenant("Globex Inc", "globex", &user_b.id);

    storage.create_user(&user_a).await.unwrap();
    storage.create_user(&user_b).await.unwrap();
    storage.create_tenant(&tenant_a).await.unwrap();
    storage.create_tenant(&tenant_b).await.unwrap();

    // Both tenants have flows with same names
    storage
        .deploy_flow_version(&tenant_a.id, "flow-1", "v1", "content-a1", &user_a.id)
        .await
        .unwrap();
    storage
        .deploy_flow_version(&tenant_a.id, "flow-2", "v1", "content-a2", &user_a.id)
        .await
        .unwrap();

    storage
        .deploy_flow_version(&tenant_b.id, "flow-1", "v1", "content-b1", &user_b.id)
        .await
        .unwrap();
    storage
        .deploy_flow_version(&tenant_b.id, "flow-3", "v1", "content-b3", &user_b.id)
        .await
        .unwrap();

    // ✅ CRITICAL TEST: Batch query for Tenant A returns only their flows
    let flow_names_a = vec![
        "flow-1".to_string(),
        "flow-2".to_string(),
        "flow-3".to_string(),
    ];
    let contents_a = storage
        .get_deployed_flows_content(&tenant_a.id, &flow_names_a)
        .await
        .unwrap();

    // Should only return flow-1 and flow-2 (Tenant A's flows), NOT flow-3 (Tenant B's)
    assert_eq!(contents_a.len(), 2, "Tenant A should get 2 flows");

    let returned_names_a: Vec<&str> = contents_a.iter().map(|(name, _)| name.as_str()).collect();
    assert!(returned_names_a.contains(&"flow-1"));
    assert!(returned_names_a.contains(&"flow-2"));
    assert!(
        !returned_names_a.contains(&"flow-3"),
        "Should NOT return Tenant B's flow-3"
    );

    // Verify content is correct
    let flow1_content = contents_a
        .iter()
        .find(|(n, _)| n == "flow-1")
        .map(|(_, c)| c);
    assert_eq!(
        flow1_content,
        Some(&"content-a1".to_string()),
        "Tenant A gets their content, not Tenant B's"
    );

    // ✅ CRITICAL TEST: Batch query for Tenant B returns only their flows
    let flow_names_b = vec![
        "flow-1".to_string(),
        "flow-2".to_string(),
        "flow-3".to_string(),
    ];
    let contents_b = storage
        .get_deployed_flows_content(&tenant_b.id, &flow_names_b)
        .await
        .unwrap();

    assert_eq!(
        contents_b.len(),
        2,
        "Tenant B should get 2 flows (flow-1 and flow-3)"
    );

    let returned_names_b: Vec<&str> = contents_b.iter().map(|(name, _)| name.as_str()).collect();
    assert!(
        returned_names_b.contains(&"flow-1"),
        "Tenant B has their own flow-1"
    );
    assert!(returned_names_b.contains(&"flow-3"));
    assert!(
        !returned_names_b.contains(&"flow-2"),
        "Should NOT return Tenant A's flow-2"
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

    let tenant_a = create_test_tenant("ACME Corp", "acme", &user_a.id);
    let tenant_b = create_test_tenant("Globex Inc", "globex", &user_b.id);

    storage.create_user(&user_a).await.unwrap();
    storage.create_user(&user_b).await.unwrap();
    storage.create_tenant(&tenant_a).await.unwrap();
    storage.create_tenant(&tenant_b).await.unwrap();

    // Both tenants deploy multiple versions of "api-handler"
    let flow_name = "api-handler";

    // Tenant A deploys v1.0, v1.1, v1.2
    storage
        .deploy_flow_version(
            &tenant_a.id,
            flow_name,
            "v1.0",
            "content-a-v1.0",
            &user_a.id,
        )
        .await
        .unwrap();
    storage
        .deploy_flow_version(
            &tenant_a.id,
            flow_name,
            "v1.1",
            "content-a-v1.1",
            &user_a.id,
        )
        .await
        .unwrap();
    storage
        .deploy_flow_version(
            &tenant_a.id,
            flow_name,
            "v1.2",
            "content-a-v1.2",
            &user_a.id,
        )
        .await
        .unwrap();

    // Tenant B deploys v2.0, v2.1
    storage
        .deploy_flow_version(
            &tenant_b.id,
            flow_name,
            "v2.0",
            "content-b-v2.0",
            &user_b.id,
        )
        .await
        .unwrap();
    storage
        .deploy_flow_version(
            &tenant_b.id,
            flow_name,
            "v2.1",
            "content-b-v2.1",
            &user_b.id,
        )
        .await
        .unwrap();

    // ✅ CRITICAL TEST: Tenant A sees only their versions
    let versions_a = storage
        .list_flow_versions(&tenant_a.id, flow_name)
        .await
        .unwrap();
    assert_eq!(versions_a.len(), 3, "Tenant A should see 3 versions");

    let version_strings_a: Vec<&str> = versions_a.iter().map(|v| v.version.as_str()).collect();
    assert!(version_strings_a.contains(&"v1.0"));
    assert!(version_strings_a.contains(&"v1.1"));
    assert!(version_strings_a.contains(&"v1.2"));
    assert!(
        !version_strings_a.contains(&"v2.0"),
        "Tenant A should NOT see Tenant B's versions"
    );

    // ✅ CRITICAL TEST: Tenant B sees only their versions
    let versions_b = storage
        .list_flow_versions(&tenant_b.id, flow_name)
        .await
        .unwrap();
    assert_eq!(versions_b.len(), 2, "Tenant B should see 2 versions");

    let version_strings_b: Vec<&str> = versions_b.iter().map(|v| v.version.as_str()).collect();
    assert!(version_strings_b.contains(&"v2.0"));
    assert!(version_strings_b.contains(&"v2.1"));
    assert!(
        !version_strings_b.contains(&"v1.0"),
        "Tenant B should NOT see Tenant A's versions"
    );

    println!("✅ Flow version isolation verified: Version histories are tenant-scoped");
}

// ============================================================================
// CRITICAL SECURITY TEST: Run Deletion Isolation
// ============================================================================

#[tokio::test]
async fn test_run_deletion_respects_tenant_boundaries() {
    let storage = create_test_storage().await;

    let user_a = create_test_user("usera@acme.com", "User A");
    let user_b = create_test_user("userb@globex.com", "User B");

    let tenant_a = create_test_tenant("ACME Corp", "acme", &user_a.id);
    let tenant_b = create_test_tenant("Globex Inc", "globex", &user_b.id);

    storage.create_user(&user_a).await.unwrap();
    storage.create_user(&user_b).await.unwrap();
    storage.create_tenant(&tenant_a).await.unwrap();
    storage.create_tenant(&tenant_b).await.unwrap();

    // Create runs
    let run_a = create_test_run("workflow-a", &tenant_a.id, &user_a.id);
    let run_b = create_test_run("workflow-b", &tenant_b.id, &user_b.id);

    storage.save_run(&run_a).await.unwrap();
    storage.save_run(&run_b).await.unwrap();

    // ✅ CRITICAL TEST: Tenant A cannot delete Tenant B's run
    let delete_result = storage.delete_run(run_b.id, &tenant_a.id).await;
    assert!(
        delete_result.is_err(),
        "Tenant A should NOT be able to delete Tenant B's run"
    );

    // Verify run B still exists
    let run_b_check = storage.get_run(run_b.id, &tenant_b.id).await.unwrap();
    assert!(
        run_b_check.is_some(),
        "Tenant B's run should still exist after failed cross-tenant delete"
    );

    // ✅ CRITICAL TEST: Tenant A CAN delete their own run
    storage
        .delete_run(run_a.id, &tenant_a.id)
        .await
        .expect("Tenant A should delete their own run");

    let run_a_check = storage.get_run(run_a.id, &tenant_a.id).await.unwrap();
    assert!(run_a_check.is_none(), "Run A should be deleted");

    println!("✅ Deletion isolation verified: Cross-tenant deletion blocked");
}

// ============================================================================
// CRITICAL SECURITY TEST: Deployed Version Pointer Isolation
// ============================================================================

#[tokio::test]
async fn test_deployed_version_pointers_isolated() {
    let storage = create_test_storage().await;

    let user_a = create_test_user("usera@acme.com", "User A");
    let user_b = create_test_user("userb@globex.com", "User B");

    let tenant_a = create_test_tenant("ACME Corp", "acme", &user_a.id);
    let tenant_b = create_test_tenant("Globex Inc", "globex", &user_b.id);

    storage.create_user(&user_a).await.unwrap();
    storage.create_user(&user_b).await.unwrap();
    storage.create_tenant(&tenant_a).await.unwrap();
    storage.create_tenant(&tenant_b).await.unwrap();

    let flow_name = "api-handler";

    // Both tenants deploy the same flow name
    storage
        .deploy_flow_version(&tenant_a.id, flow_name, "v1.0", "content-a", &user_a.id)
        .await
        .unwrap();
    storage
        .deploy_flow_version(&tenant_b.id, flow_name, "v2.0", "content-b", &user_b.id)
        .await
        .unwrap();

    // ✅ CRITICAL TEST: Tenant A's deployed version is v1.0
    let deployed_a = storage
        .get_deployed_version(&tenant_a.id, flow_name)
        .await
        .unwrap()
        .expect("Tenant A should have deployed version");
    assert_eq!(deployed_a, "v1.0", "Tenant A should have v1.0 deployed");

    // ✅ CRITICAL TEST: Tenant B's deployed version is v2.0 (NOT affected by Tenant A)
    let deployed_b = storage
        .get_deployed_version(&tenant_b.id, flow_name)
        .await
        .unwrap()
        .expect("Tenant B should have deployed version");
    assert_eq!(
        deployed_b, "v2.0",
        "Tenant B should have v2.0 deployed (independent of Tenant A)"
    );

    // Tenant A disables their deployment
    storage
        .unset_deployed_version(&tenant_a.id, flow_name)
        .await
        .unwrap();

    // ✅ CRITICAL TEST: Tenant A's deployment is disabled
    let deployed_a_after = storage
        .get_deployed_version(&tenant_a.id, flow_name)
        .await
        .unwrap();
    assert!(
        deployed_a_after.is_none(),
        "Tenant A's deployment should be unset"
    );

    // ✅ CRITICAL TEST: Tenant B's deployment is UNAFFECTED
    let deployed_b_after = storage
        .get_deployed_version(&tenant_b.id, flow_name)
        .await
        .unwrap();
    assert_eq!(
        deployed_b_after.unwrap(),
        "v2.0",
        "Tenant B's deployment should be UNAFFECTED by Tenant A's disable"
    );

    println!("✅ Deployment pointer isolation verified: Each tenant manages their own deployments");
}

// ============================================================================
// CRITICAL SECURITY TEST: Run Filtering by Flow and Status
// ============================================================================

#[tokio::test]
async fn test_run_filtering_respects_tenant_boundaries() {
    let storage = create_test_storage().await;

    let user_a = create_test_user("usera@acme.com", "User A");
    let user_b = create_test_user("userb@globex.com", "User B");

    let tenant_a = create_test_tenant("ACME Corp", "acme", &user_a.id);
    let tenant_b = create_test_tenant("Globex Inc", "globex", &user_b.id);

    storage.create_user(&user_a).await.unwrap();
    storage.create_user(&user_b).await.unwrap();
    storage.create_tenant(&tenant_a).await.unwrap();
    storage.create_tenant(&tenant_b).await.unwrap();

    // Both tenants have runs for "data-sync" flow
    let mut run_a1 = create_test_run("data-sync", &tenant_a.id, &user_a.id);
    run_a1.status = RunStatus::Succeeded;

    let mut run_a2 = create_test_run("data-sync", &tenant_a.id, &user_a.id);
    run_a2.status = RunStatus::Failed;

    let mut run_b1 = create_test_run("data-sync", &tenant_b.id, &user_b.id);
    run_b1.status = RunStatus::Succeeded;

    storage.save_run(&run_a1).await.unwrap();
    storage.save_run(&run_a2).await.unwrap();
    storage.save_run(&run_b1).await.unwrap();

    // ✅ CRITICAL TEST: Tenant A finds only their successful runs
    let successful_a = storage
        .list_runs_by_flow_and_status(&tenant_a.id, "data-sync", RunStatus::Succeeded, None, 10)
        .await
        .unwrap();

    assert_eq!(
        successful_a.len(),
        1,
        "Tenant A should find 1 successful run"
    );
    assert_eq!(successful_a[0].id, run_a1.id);
    assert_ne!(
        successful_a[0].id, run_b1.id,
        "Tenant A should NOT see Tenant B's run"
    );

    // ✅ CRITICAL TEST: Tenant B finds only their run (not Tenant A's)
    let successful_b = storage
        .list_runs_by_flow_and_status(&tenant_b.id, "data-sync", RunStatus::Succeeded, None, 10)
        .await
        .unwrap();

    assert_eq!(
        successful_b.len(),
        1,
        "Tenant B should find 1 successful run"
    );
    assert_eq!(successful_b[0].id, run_b1.id);

    println!("✅ Run filtering isolation verified: Filters respect tenant boundaries");
}
