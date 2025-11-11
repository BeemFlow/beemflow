use super::*;

/// Comprehensive test helper that runs all storage operations
/// Used to ensure parity between Memory and SQLite implementations
async fn test_all_storage_operations<S: Storage>(storage: Arc<S>) {
    // Test 1: SaveRun and GetRun
    let run_id = Uuid::new_v4();
    let run = Run {
        id: run_id,
        flow_name: "test_flow".to_string().into(),
        event: {
            let mut m = HashMap::new();
            m.insert("key".to_string(), serde_json::json!("value"));
            m
        },
        vars: HashMap::new(),
        status: RunStatus::Running,
        started_at: Utc::now(),
        ended_at: None,
        steps: None,
        tenant_id: "test_tenant".to_string(),
        triggered_by_user_id: "test_user".to_string(),
    };

    storage
        .save_run(&run)
        .await
        .expect("SaveRun should succeed");

    let retrieved = storage
        .get_run(run_id, "test_tenant")
        .await
        .expect("GetRun should succeed");
    assert!(retrieved.is_some(), "Should find saved run");
    assert_eq!(retrieved.as_ref().unwrap().id, run_id);
    assert_eq!(retrieved.unwrap().flow_name.as_str(), "test_flow");

    // Test 2: GetRun with non-existent ID
    let non_existent_id = Uuid::new_v4();
    let missing = storage
        .get_run(non_existent_id, "test_tenant")
        .await
        .expect("GetRun should not error");
    assert!(missing.is_none(), "Should return None for non-existent run");

    // Test 3: SaveStep and GetSteps
    let step_id = Uuid::new_v4();
    let step = StepRun {
        id: step_id,
        run_id,
        step_name: "test_step".to_string().into(),
        status: StepStatus::Succeeded,
        outputs: Some({
            let mut m = HashMap::new();
            m.insert("result".to_string(), serde_json::json!("success"));
            m
        }),
        error: None,
        started_at: Utc::now(),
        ended_at: Some(Utc::now()),
    };

    storage
        .save_step(&step)
        .await
        .expect("SaveStep should succeed");

    let steps = storage
        .get_steps(run_id)
        .await
        .expect("GetSteps should succeed");
    assert_eq!(steps.len(), 1, "Expected 1 step");
    assert_eq!(steps[0].id, step_id);
    assert_eq!(steps[0].step_name.as_str(), "test_step");

    // Test 4: RegisterWait and ResolveWait
    let token = Uuid::new_v4();
    storage
        .register_wait(token, None)
        .await
        .expect("RegisterWait should succeed");

    let resolved = storage
        .resolve_wait(token)
        .await
        .expect("ResolveWait should succeed");
    // Behavior may vary between implementations
    let _ = resolved;

    // Test 5: ListRuns
    let runs = storage
        .list_runs("test_tenant", 100, 0)
        .await
        .expect("ListRuns should succeed");
    assert_eq!(runs.len(), 1, "Expected 1 run");

    // Test 6: SavePausedRun, LoadPausedRuns, DeletePausedRun
    let paused_data = serde_json::json!({
        "runID": run_id.to_string(),
        "token": "pause_token",
        "stepName": "paused_step"
    });

    storage
        .save_paused_run(
            "pause_token",
            "webhook.test_source",
            paused_data.clone(),
            "test_tenant",
            "test_user",
        )
        .await
        .expect("SavePausedRun should succeed");

    let paused_runs = storage
        .load_paused_runs()
        .await
        .expect("LoadPausedRuns should succeed");
    assert_eq!(paused_runs.len(), 1, "Expected 1 paused run");
    assert!(paused_runs.contains_key("pause_token"));

    storage
        .delete_paused_run("pause_token")
        .await
        .expect("DeletePausedRun should succeed");

    let paused_runs = storage
        .load_paused_runs()
        .await
        .expect("LoadPausedRuns should succeed");
    assert_eq!(paused_runs.len(), 0, "Expected 0 paused runs after delete");

    // Test 7: DeleteRun
    storage
        .delete_run(run_id, "test_tenant")
        .await
        .expect("DeleteRun should succeed");

    let runs = storage
        .list_runs("test_tenant", 100, 0)
        .await
        .expect("ListRuns should succeed");
    assert_eq!(runs.len(), 0, "Expected 0 runs after delete");
}

/// Test OAuth credential operations
async fn test_oauth_credential_operations<S: Storage>(storage: Arc<S>) {
    let cred = OAuthCredential {
        id: "test_cred".to_string(),
        provider: "google".to_string(),
        integration: "sheets".to_string(),
        access_token: "access_token_123".to_string(),
        refresh_token: Some("refresh_token_456".to_string()),
        expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
        scope: Some("spreadsheets.readonly".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        user_id: "test_user".to_string(),
        tenant_id: "test_tenant".to_string(),
    };

    // Save credential
    storage
        .save_oauth_credential(&cred)
        .await
        .expect("SaveOAuthCredential should succeed");

    // Get credential
    let retrieved = storage
        .get_oauth_credential("google", "sheets", "test_user", "test_tenant")
        .await
        .expect("GetOAuthCredential should succeed");
    assert!(retrieved.is_some(), "Should find saved credential");
    assert_eq!(retrieved.as_ref().unwrap().id, "test_cred");
    assert_eq!(retrieved.as_ref().unwrap().access_token, "access_token_123");

    // List credentials
    let creds = storage
        .list_oauth_credentials("test_user", "test_tenant")
        .await
        .expect("ListOAuthCredentials should succeed");
    assert_eq!(creds.len(), 1, "Expected 1 credential");

    // Refresh credential
    let new_expires = Utc::now() + chrono::Duration::hours(2);
    storage
        .refresh_oauth_credential("test_cred", "new_access_token", Some(new_expires))
        .await
        .expect("RefreshOAuthCredential should succeed");

    let refreshed = storage
        .get_oauth_credential("google", "sheets", "test_user", "test_tenant")
        .await
        .expect("GetOAuthCredential should succeed");
    assert_eq!(refreshed.as_ref().unwrap().access_token, "new_access_token");

    // Delete credential
    storage
        .delete_oauth_credential("test_cred", "test_tenant")
        .await
        .expect("DeleteOAuthCredential should succeed");

    let creds = storage
        .list_oauth_credentials("test_user", "test_tenant")
        .await
        .expect("ListOAuthCredentials should succeed");
    assert_eq!(creds.len(), 0, "Expected 0 credentials after delete");
}

/// Test flow versioning operations
async fn test_flow_versioning_operations<S: Storage>(storage: Arc<S>) {
    // Deploy version 1
    storage
        .deploy_flow_version("test_tenant", "my_flow", "1.0.0", "content v1", "test_user")
        .await
        .expect("Deploy v1 should succeed");

    // Deploy version 2
    storage
        .deploy_flow_version("test_tenant", "my_flow", "2.0.0", "content v2", "test_user")
        .await
        .expect("Deploy v2 should succeed");

    // Get deployed version (should be v2, latest)
    let deployed = storage
        .get_deployed_version("test_tenant", "my_flow")
        .await
        .expect("GetDeployedVersion should succeed");
    assert_eq!(
        deployed,
        Some("2.0.0".to_string()),
        "Latest deployed should be v2"
    );

    // Get specific version content
    let content_v1 = storage
        .get_flow_version_content("test_tenant", "my_flow", "1.0.0")
        .await
        .expect("GetFlowVersionContent should succeed");
    assert_eq!(content_v1, Some("content v1".to_string()));

    let content_v2 = storage
        .get_flow_version_content("test_tenant", "my_flow", "2.0.0")
        .await
        .expect("GetFlowVersionContent should succeed");
    assert_eq!(content_v2, Some("content v2".to_string()));

    // List versions
    let versions = storage
        .list_flow_versions("test_tenant", "my_flow")
        .await
        .expect("ListFlowVersions should succeed");
    assert_eq!(versions.len(), 2, "Expected 2 versions");
    assert!(
        versions.iter().any(|v| v.version == "2.0.0" && v.is_live),
        "v2 should be live"
    );
    assert!(
        versions.iter().any(|v| v.version == "1.0.0" && !v.is_live),
        "v1 should not be live"
    );

    // Rollback to v1
    storage
        .set_deployed_version("test_tenant", "my_flow", "1.0.0")
        .await
        .expect("SetDeployedVersion should succeed");

    let deployed = storage
        .get_deployed_version("test_tenant", "my_flow")
        .await
        .expect("GetDeployedVersion should succeed");
    assert_eq!(
        deployed,
        Some("1.0.0".to_string()),
        "Deployed should now be v1"
    );

    // Test list_all_deployed_flows (efficient JOIN query for webhooks)
    storage
        .deploy_flow_version(
            "test_tenant",
            "another_flow",
            "1.0.0",
            "another content",
            "test_user",
        )
        .await
        .expect("Deploy another_flow should succeed");

    // Now we have 2 flows deployed: my_flow@1.0.0 and another_flow@1.0.0
    let all_deployed = storage
        .list_all_deployed_flows("test_tenant")
        .await
        .expect("ListAllDeployedFlows should succeed");

    assert_eq!(all_deployed.len(), 2, "Should have 2 deployed flows");

    // Verify contents are correct
    let my_flow_entry = all_deployed.iter().find(|(name, _)| name == "my_flow");
    assert!(my_flow_entry.is_some(), "Should find my_flow");
    assert_eq!(
        my_flow_entry.unwrap().1,
        "content v1",
        "Should have v1 content"
    );

    let another_flow_entry = all_deployed.iter().find(|(name, _)| name == "another_flow");
    assert!(another_flow_entry.is_some(), "Should find another_flow");
    assert_eq!(another_flow_entry.unwrap().1, "another content");

    // Disable my_flow
    storage
        .unset_deployed_version("test_tenant", "my_flow")
        .await
        .expect("UnsetDeployedVersion should succeed");

    let all_deployed_after = storage
        .list_all_deployed_flows("test_tenant")
        .await
        .expect("ListAllDeployedFlows should succeed");

    assert_eq!(
        all_deployed_after.len(),
        1,
        "Should have 1 deployed flow after disable"
    );
    assert_eq!(all_deployed_after[0].0, "another_flow");
}

// Note: Flow CRUD operations (save/get/list/delete) are now handled by pure functions
// in storage::flows module and tested there. Database storage only handles versioning.

/// Test multiple steps per run
async fn test_multiple_steps<S: Storage>(storage: Arc<S>) {
    let run_id = Uuid::new_v4();
    let run = Run {
        id: run_id,
        flow_name: "multi_step_flow".to_string().into(),
        event: HashMap::new(),
        vars: HashMap::new(),
        status: RunStatus::Running,
        started_at: Utc::now(),
        ended_at: None,
        steps: None,
        tenant_id: "test_tenant".to_string(),
        triggered_by_user_id: "test_user".to_string(),
    };

    storage
        .save_run(&run)
        .await
        .expect("SaveRun should succeed");

    // Add 10 steps
    for i in 0..10 {
        let step = StepRun {
            id: Uuid::new_v4(),
            run_id,
            step_name: format!("step_{}", i).into(),
            status: if i % 2 == 0 {
                StepStatus::Succeeded
            } else {
                StepStatus::Failed
            },
            outputs: Some({
                let mut m = HashMap::new();
                m.insert("index".to_string(), serde_json::json!(i));
                m
            }),
            error: if i % 2 == 1 {
                Some(format!("Error in step {}", i))
            } else {
                None
            },
            started_at: Utc::now(),
            ended_at: Some(Utc::now()),
        };
        storage
            .save_step(&step)
            .await
            .expect("SaveStep should succeed");
    }

    let steps = storage
        .get_steps(run_id)
        .await
        .expect("GetSteps should succeed");
    assert_eq!(steps.len(), 10, "Expected 10 steps");

    // Verify step data integrity
    let succeeded_count = steps
        .iter()
        .filter(|s| s.status == StepStatus::Succeeded)
        .count();
    let failed_count = steps
        .iter()
        .filter(|s| s.status == StepStatus::Failed)
        .count();
    assert_eq!(succeeded_count, 5, "Expected 5 succeeded steps");
    assert_eq!(failed_count, 5, "Expected 5 failed steps");
}

#[tokio::test]
async fn test_sqlite_storage_all_operations() {
    let storage = Arc::new(
        SqliteStorage::new(":memory:")
            .await
            .expect("SQLite creation failed"),
    );
    test_all_storage_operations(storage).await;
}

#[tokio::test]
async fn test_sqlite_storage_oauth() {
    let storage = Arc::new(
        SqliteStorage::new(":memory:")
            .await
            .expect("SQLite creation failed"),
    );
    test_oauth_credential_operations(storage).await;
}

#[tokio::test]
async fn test_sqlite_storage_versioning() {
    let storage = Arc::new(
        SqliteStorage::new(":memory:")
            .await
            .expect("SQLite creation failed"),
    );
    test_flow_versioning_operations(storage).await;
}

#[tokio::test]
async fn test_sqlite_storage_multiple_steps() {
    let storage = Arc::new(
        SqliteStorage::new(":memory:")
            .await
            .expect("SQLite creation failed"),
    );
    test_multiple_steps(storage).await;
}

// ========================================
// Stress Tests
// ========================================

#[tokio::test]
async fn test_sqlite_storage_stress_runs() {
    let storage = Arc::new(
        SqliteStorage::new(":memory:")
            .await
            .expect("SQLite creation failed"),
    );

    // Create 100 runs
    for i in 0..100 {
        let run = Run {
            id: Uuid::new_v4(),
            flow_name: format!("flow_{}", i % 10).into(),
            event: HashMap::new(),
            vars: HashMap::new(),
            status: if i % 3 == 0 {
                RunStatus::Succeeded
            } else {
                RunStatus::Running
            },
            started_at: Utc::now(),
            ended_at: None,
            steps: None,
            tenant_id: "test_tenant".to_string(),
            triggered_by_user_id: "test_user".to_string(),
        };
        storage
            .save_run(&run)
            .await
            .expect("SaveRun should succeed");
    }

    let runs = storage
        .list_runs("test_tenant", 1000, 0)
        .await
        .expect("ListRuns should succeed");
    assert_eq!(runs.len(), 100, "Expected 100 runs");
}

#[tokio::test]
async fn test_sqlite_storage_concurrent_writes() {
    let storage = Arc::new(
        SqliteStorage::new(":memory:")
            .await
            .expect("SQLite creation failed"),
    );

    // Spawn 20 concurrent writers
    let mut handles = vec![];
    for i in 0..20 {
        let storage_clone = storage.clone();
        let handle = tokio::spawn(async move {
            let run = Run {
                id: Uuid::new_v4(),
                flow_name: format!("concurrent_flow_{}", i).into(),
                event: HashMap::new(),
                vars: HashMap::new(),
                status: RunStatus::Running,
                started_at: Utc::now(),
                ended_at: None,
                steps: None,
                tenant_id: "test_tenant".to_string(),
                triggered_by_user_id: "test_user".to_string(),
            };
            storage_clone.save_run(&run).await
        });
        handles.push(handle);
    }

    // Wait for all writes
    for handle in handles {
        handle
            .await
            .unwrap()
            .expect("Concurrent write should succeed");
    }

    let runs = storage
        .list_runs("test_tenant", 1000, 0)
        .await
        .expect("ListRuns should succeed");
    assert_eq!(runs.len(), 20, "Expected 20 runs from concurrent writes");
}

// ========================================
// Error Handling Tests
// ========================================

#[tokio::test]
async fn test_sqlite_storage_delete_nonexistent() {
    let storage = Arc::new(
        SqliteStorage::new(":memory:")
            .await
            .expect("SQLite creation failed"),
    );
    // Deleting non-existent run should return NotFound error (for tenant isolation)
    let result = storage.delete_run(Uuid::new_v4(), "test_tenant").await;
    assert!(result.is_err(), "Delete non-existent run should error");

    // OAuth credential deletion should also return NotFound error (for tenant isolation)
    let result = storage
        .delete_oauth_credential("nonexistent", "test_tenant")
        .await;
    assert!(result.is_err(), "Delete non-existent cred should error");
}

// ============================================================================
// Webhook Architecture Tests: source-based paused run queries
// ============================================================================

#[tokio::test]
async fn test_find_paused_runs_by_source() {
    let storage = SqliteStorage::new(":memory:")
        .await
        .expect("Failed to create storage");

    // Save paused runs with different sources
    storage
        .save_paused_run(
            "token1",
            "webhook.airtable",
            serde_json::json!({"flow": "approval_flow", "step": 0}),
            "test_tenant",
            "test_user",
        )
        .await
        .expect("Failed to save paused run 1");

    storage
        .save_paused_run(
            "token2",
            "webhook.airtable",
            serde_json::json!({"flow": "approval_flow", "step": 1}),
            "test_tenant",
            "test_user",
        )
        .await
        .expect("Failed to save paused run 2");

    storage
        .save_paused_run(
            "token3",
            "webhook.github",
            serde_json::json!({"flow": "ci_flow", "step": 0}),
            "test_tenant",
            "test_user",
        )
        .await
        .expect("Failed to save paused run 3");

    // Query by source
    let airtable_runs = storage
        .find_paused_runs_by_source("webhook.airtable")
        .await
        .expect("Failed to query by source");

    assert_eq!(airtable_runs.len(), 2, "Should find 2 airtable runs");

    // Verify tokens
    let tokens: Vec<String> = airtable_runs.iter().map(|(t, _)| t.clone()).collect();
    assert!(tokens.contains(&"token1".to_string()));
    assert!(tokens.contains(&"token2".to_string()));
    assert!(!tokens.contains(&"token3".to_string()));

    // Query by different source
    let github_runs = storage
        .find_paused_runs_by_source("webhook.github")
        .await
        .expect("Failed to query by source");

    assert_eq!(github_runs.len(), 1, "Should find 1 github run");
    assert_eq!(github_runs[0].0, "token3");

    // Query non-existent source
    let empty_runs = storage
        .find_paused_runs_by_source("webhook.nonexistent")
        .await
        .expect("Failed to query by source");

    assert_eq!(
        empty_runs.len(),
        0,
        "Should find 0 runs for nonexistent source"
    );
}

#[tokio::test]
async fn test_source_persists_after_save() {
    let storage = SqliteStorage::new(":memory:")
        .await
        .expect("Failed to create storage");

    let test_data = serde_json::json!({"test": "data"});

    // Save with source
    storage
        .save_paused_run(
            "test_token",
            "webhook.test",
            test_data.clone(),
            "test_tenant",
            "test_user",
        )
        .await
        .expect("Failed to save");

    // Query by source
    let runs = storage
        .find_paused_runs_by_source("webhook.test")
        .await
        .expect("Failed to query");

    assert_eq!(runs.len(), 1, "Should find the run");
    assert_eq!(runs[0].0, "test_token");
    assert_eq!(runs[0].1, test_data);
}

#[tokio::test]
async fn test_fetch_and_delete_removes_from_source_query() {
    let storage = SqliteStorage::new(":memory:")
        .await
        .expect("Failed to create storage");

    // Save a paused run
    storage
        .save_paused_run(
            "token1",
            "webhook.test",
            serde_json::json!({"data": 1}),
            "test_tenant",
            "test_user",
        )
        .await
        .expect("Failed to save");

    // Verify it's queryable by source
    let runs_before = storage
        .find_paused_runs_by_source("webhook.test")
        .await
        .expect("Failed to query");
    assert_eq!(runs_before.len(), 1);

    // Fetch and delete
    let fetched = storage
        .fetch_and_delete_paused_run("token1")
        .await
        .expect("Failed to fetch and delete");
    assert!(fetched.is_some());

    // Verify it's no longer queryable by source
    let runs_after = storage
        .find_paused_runs_by_source("webhook.test")
        .await
        .expect("Failed to query");
    assert_eq!(runs_after.len(), 0, "Should be deleted");
}

#[tokio::test]
async fn test_update_source_for_existing_token() {
    let storage = SqliteStorage::new(":memory:")
        .await
        .expect("Failed to create storage");

    // Save with initial source
    storage
        .save_paused_run(
            "token1",
            "webhook.old",
            serde_json::json!({"data": 1}),
            "test_tenant",
            "test_user",
        )
        .await
        .expect("Failed to save");

    // Update with new source (same token)
    storage
        .save_paused_run(
            "token1",
            "webhook.new",
            serde_json::json!({"data": 2}),
            "test_tenant",
            "test_user",
        )
        .await
        .expect("Failed to update");

    // Old source should have no results
    let old_runs = storage
        .find_paused_runs_by_source("webhook.old")
        .await
        .expect("Failed to query");
    assert_eq!(old_runs.len(), 0);

    // New source should have the run
    let new_runs = storage
        .find_paused_runs_by_source("webhook.new")
        .await
        .expect("Failed to query");
    assert_eq!(new_runs.len(), 1);
    assert_eq!(new_runs[0].1.get("data").unwrap(), &serde_json::json!(2));
}

#[tokio::test]
async fn test_multiple_sources_isolation() {
    let storage = SqliteStorage::new(":memory:")
        .await
        .expect("Failed to create storage");

    // Create runs across multiple sources
    for i in 1..=3 {
        storage
            .save_paused_run(
                &format!("airtable_{}", i),
                "webhook.airtable",
                serde_json::json!({"index": i}),
                "test_tenant",
                "test_user",
            )
            .await
            .expect("Failed to save");
    }

    for i in 1..=2 {
        storage
            .save_paused_run(
                &format!("github_{}", i),
                "webhook.github",
                serde_json::json!({"index": i}),
                "test_tenant",
                "test_user",
            )
            .await
            .expect("Failed to save");
    }

    // Verify isolation
    let airtable = storage
        .find_paused_runs_by_source("webhook.airtable")
        .await
        .expect("Query failed");
    assert_eq!(airtable.len(), 3);

    let github = storage
        .find_paused_runs_by_source("webhook.github")
        .await
        .expect("Query failed");
    assert_eq!(github.len(), 2);

    // Delete one from airtable
    storage
        .delete_paused_run("airtable_1")
        .await
        .expect("Delete failed");

    // Verify airtable count decreased but github unchanged
    let airtable_after = storage
        .find_paused_runs_by_source("webhook.airtable")
        .await
        .expect("Query failed");
    assert_eq!(airtable_after.len(), 2);

    let github_after = storage
        .find_paused_runs_by_source("webhook.github")
        .await
        .expect("Query failed");
    assert_eq!(github_after.len(), 2);
}
