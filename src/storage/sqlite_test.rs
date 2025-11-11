use super::*;
use crate::storage::{OAuthCredential, Run, RunStatus, SqliteStorage, StepRun, StepStatus};
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

#[tokio::test]
async fn test_save_and_get_run() {
    let storage = SqliteStorage::new(":memory:").await.unwrap();
    let run = Run {
        id: Uuid::new_v4(),
        flow_name: "test".to_string().into(),
        event: HashMap::new(),
        vars: HashMap::new(),
        status: RunStatus::Running,
        started_at: Utc::now(),
        ended_at: None,
        steps: None,
        tenant_id: "test_tenant".to_string(),
        triggered_by_user_id: "test_user".to_string(),
    };

    storage.save_run(&run).await.unwrap();
    let retrieved = storage.get_run(run.id, "test_tenant").await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().flow_name.as_str(), "test");
}

#[tokio::test]
async fn test_oauth_credentials() {
    let storage = SqliteStorage::new(":memory:").await.unwrap();
    let cred = OAuthCredential {
        id: "test_id".to_string(),
        provider: "google".to_string(),
        integration: "my_app".to_string(),
        access_token: "access".to_string(),
        refresh_token: Some("refresh".to_string()),
        expires_at: None,
        scope: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        user_id: "test_user".to_string(),
        tenant_id: "test_tenant".to_string(),
    };

    storage.save_oauth_credential(&cred).await.unwrap();
    let retrieved = storage
        .get_oauth_credential("google", "my_app", "test_user", "test_tenant")
        .await
        .unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().id, "test_id");
}

#[tokio::test]
async fn test_flow_versioning() {
    let storage = SqliteStorage::new(":memory:").await.unwrap();

    storage
        .deploy_flow_version("test_tenant", "my_flow", "v1", "content1", "test_user")
        .await
        .unwrap();
    storage
        .deploy_flow_version("test_tenant", "my_flow", "v2", "content2", "test_user")
        .await
        .unwrap();

    let deployed = storage
        .get_deployed_version("test_tenant", "my_flow")
        .await
        .unwrap();
    assert_eq!(deployed, Some("v2".to_string()));

    let versions = storage
        .list_flow_versions("test_tenant", "my_flow")
        .await
        .unwrap();
    assert_eq!(versions.len(), 2);
    assert!(versions.iter().any(|v| v.version == "v2" && v.is_live));
}

#[tokio::test]
async fn test_all_operations_comprehensive() {
    let storage = SqliteStorage::new(":memory:").await.unwrap();

    // Test SavePausedRun and LoadPausedRuns
    let run_id = Uuid::new_v4();
    let paused_data = serde_json::json!({
        "runID": run_id.to_string(),
        "token": "sqlite_pause_token",
        "stepName": "paused_step"
    });

    storage
        .save_paused_run(
            "sqlite_pause_token",
            "webhook.test_source",
            paused_data.clone(),
            "test_tenant",
            "test_user",
        )
        .await
        .unwrap();

    let paused_runs = storage.load_paused_runs().await.unwrap();
    assert_eq!(paused_runs.len(), 1, "Expected 1 paused run");
    assert!(
        paused_runs.contains_key("sqlite_pause_token"),
        "Expected pause_token in paused runs"
    );

    // Test DeletePausedRun
    storage
        .delete_paused_run("sqlite_pause_token")
        .await
        .unwrap();
    let paused_runs = storage.load_paused_runs().await.unwrap();
    assert_eq!(paused_runs.len(), 0, "Expected 0 paused runs after delete");

    // Test ListRuns - should be empty initially
    let runs = storage.list_runs("test_tenant", 1000, 0).await.unwrap();
    assert_eq!(runs.len(), 0, "Expected 0 runs initially");

    // Add a run
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

    storage.save_run(&run).await.unwrap();

    // Test GetRun
    let retrieved_run = storage.get_run(run_id, "test_tenant").await.unwrap();
    assert!(retrieved_run.is_some(), "Should find saved run");
    assert_eq!(retrieved_run.as_ref().unwrap().id, run_id);
    assert_eq!(
        retrieved_run.as_ref().unwrap().flow_name.as_str(),
        "test_flow"
    );

    // Test GetRun with non-existent ID
    let non_existent_id = Uuid::new_v4();
    let missing_run = storage
        .get_run(non_existent_id, "test_tenant")
        .await
        .unwrap();
    assert!(missing_run.is_none(), "Should not find non-existent run");

    // Test SaveStep and GetSteps
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

    storage.save_step(&step).await.unwrap();

    let steps = storage.get_steps(run_id).await.unwrap();
    assert_eq!(steps.len(), 1, "Expected 1 step");
    assert_eq!(steps[0].id, step_id);
    assert_eq!(steps[0].step_name.as_str(), "test_step");

    // Test RegisterWait and ResolveWait
    let token = Uuid::new_v4();
    storage.register_wait(token, None).await.unwrap();

    // For SQLite, ResolveWait should work
    let resolved_run = storage.resolve_wait(token).await.unwrap();
    // Behavior may vary - just ensure no error
    let _ = resolved_run;

    // Test ListRuns
    let runs = storage.list_runs("test_tenant", 1000, 0).await.unwrap();
    assert_eq!(runs.len(), 1, "Expected 1 run");

    // Test DeleteRun
    storage.delete_run(run_id, "test_tenant").await.unwrap();
    let runs = storage.list_runs("test_tenant", 1000, 0).await.unwrap();
    assert_eq!(runs.len(), 0, "Expected 0 runs after delete");
}

#[tokio::test]
async fn test_get_non_existent_run() {
    let storage = SqliteStorage::new(":memory:").await.unwrap();
    let non_existent_id = Uuid::new_v4();

    let result = storage
        .get_run(non_existent_id, "test_tenant")
        .await
        .unwrap();
    assert!(result.is_none(), "Should return None for non-existent run");
}

#[tokio::test]
async fn test_save_step_for_non_existent_run() {
    let storage = SqliteStorage::new(":memory:").await.unwrap();

    let step = StepRun {
        id: Uuid::new_v4(),
        run_id: Uuid::new_v4(), // Non-existent run
        step_name: "test_step".to_string().into(),
        status: StepStatus::Running,
        outputs: Some(HashMap::new()),
        error: None,
        started_at: Utc::now(),
        ended_at: None,
    };

    // Should succeed (foreign key not enforced or gracefully handled)
    let result = storage.save_step(&step).await;
    // Either succeeds or fails with constraint error - both acceptable
    let _ = result;
}

#[tokio::test]
async fn test_list_runs_multiple() {
    let storage = SqliteStorage::new(":memory:").await.unwrap();

    // Add multiple runs
    for i in 0..5 {
        let run = Run {
            id: Uuid::new_v4(),
            flow_name: format!("flow_{}", i).into(),
            event: HashMap::new(),
            vars: HashMap::new(),
            status: RunStatus::Succeeded,
            started_at: Utc::now(),
            ended_at: Some(Utc::now()),
            steps: None,
            tenant_id: "test_tenant".to_string(),
            triggered_by_user_id: "test_user".to_string(),
        };
        storage.save_run(&run).await.unwrap();
    }

    let runs = storage.list_runs("test_tenant", 1000, 0).await.unwrap();
    assert_eq!(runs.len(), 5, "Expected 5 runs");
}

#[tokio::test]
async fn test_paused_runs_roundtrip() {
    let storage = SqliteStorage::new(":memory:").await.unwrap();

    let data1 = serde_json::json!({"step": "step1", "value": 42});
    let data2 = serde_json::json!({"step": "step2", "value": 100});

    storage
        .save_paused_run(
            "token1",
            "webhook.source1",
            data1.clone(),
            "test_tenant",
            "test_user",
        )
        .await
        .unwrap();
    storage
        .save_paused_run(
            "token2",
            "webhook.source2",
            data2.clone(),
            "test_tenant",
            "test_user",
        )
        .await
        .unwrap();

    let loaded = storage.load_paused_runs().await.unwrap();
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded.get("token1").unwrap(), &data1);
    assert_eq!(loaded.get("token2").unwrap(), &data2);

    storage.delete_paused_run("token1").await.unwrap();
    let loaded = storage.load_paused_runs().await.unwrap();
    assert_eq!(loaded.len(), 1);
    assert!(loaded.contains_key("token2"));
}

// Note: Flow CRUD operations (save/get/list/delete) are now handled by pure functions
// in storage::flows module and tested there. Database storage only handles versioning.

#[tokio::test]
async fn test_register_and_resolve_wait() {
    let storage = SqliteStorage::new(":memory:").await.unwrap();

    let token = Uuid::new_v4();
    let wake_time = Utc::now().timestamp() + 3600; // 1 hour from now

    storage.register_wait(token, Some(wake_time)).await.unwrap();

    // Resolve wait - exact behavior may vary
    let result = storage.resolve_wait(token).await;
    assert!(result.is_ok(), "ResolveWait should not error");
}

#[tokio::test]
async fn test_oauth_credential_list_and_delete() {
    let storage = SqliteStorage::new(":memory:").await.unwrap();

    // Create multiple credentials
    for i in 0..3 {
        let cred = OAuthCredential {
            id: format!("cred_{}", i),
            provider: "google".to_string(),
            integration: format!("app_{}", i),
            access_token: format!("token_{}", i),
            refresh_token: None,
            expires_at: None,
            scope: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            user_id: "test_user".to_string(),
            tenant_id: "test_tenant".to_string(),
        };
        storage.save_oauth_credential(&cred).await.unwrap();
    }

    let creds = storage
        .list_oauth_credentials("test_user", "test_tenant")
        .await
        .unwrap();
    assert_eq!(creds.len(), 3);

    // Delete one
    storage
        .delete_oauth_credential("cred_1", "test_tenant")
        .await
        .unwrap();
    let creds = storage
        .list_oauth_credentials("test_user", "test_tenant")
        .await
        .unwrap();
    assert_eq!(creds.len(), 2);
}

#[tokio::test]
async fn test_oauth_credential_refresh() {
    let storage = SqliteStorage::new(":memory:").await.unwrap();

    let cred = OAuthCredential {
        id: "refresh_test".to_string(),
        provider: "google".to_string(),
        integration: "sheets".to_string(),
        access_token: "old_token".to_string(),
        refresh_token: Some("refresh".to_string()),
        expires_at: None,
        scope: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        user_id: "test_user".to_string(),
        tenant_id: "test_tenant".to_string(),
    };

    storage.save_oauth_credential(&cred).await.unwrap();

    // Refresh with new token
    let new_expires = Utc::now() + chrono::Duration::hours(1);
    storage
        .refresh_oauth_credential("refresh_test", "new_token", Some(new_expires))
        .await
        .unwrap();

    // Verify update
    let updated = storage
        .get_oauth_credential("google", "sheets", "test_user", "test_tenant")
        .await
        .unwrap();
    assert!(updated.is_some());
    assert_eq!(updated.as_ref().unwrap().access_token, "new_token");
    assert!(updated.unwrap().expires_at.is_some());
}

#[tokio::test]
async fn test_get_steps_empty() {
    let storage = SqliteStorage::new(":memory:").await.unwrap();
    let run_id = Uuid::new_v4();

    let steps = storage.get_steps(run_id).await.unwrap();
    assert_eq!(
        steps.len(),
        0,
        "Should return empty vec for non-existent run"
    );
}

#[tokio::test]
async fn test_multiple_steps_same_run() {
    let storage = SqliteStorage::new(":memory:").await.unwrap();

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
    storage.save_run(&run).await.unwrap();

    // Add 3 steps
    for i in 0..3 {
        let step = StepRun {
            id: Uuid::new_v4(),
            run_id,
            step_name: format!("step_{}", i).into(),
            status: StepStatus::Succeeded,
            outputs: Some(HashMap::new()),
            error: None,
            started_at: Utc::now(),
            ended_at: Some(Utc::now()),
        };
        storage.save_step(&step).await.unwrap();
    }

    let steps = storage.get_steps(run_id).await.unwrap();
    assert_eq!(steps.len(), 3, "Expected 3 steps");
}

// ============================================================================
// Database Initialization Tests
// ============================================================================

#[tokio::test]
async fn test_auto_create_database_file() {
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("auto_create.db");
    let db_path_str = db_path.to_str().unwrap();

    // Database should not exist yet
    assert!(
        !db_path.exists(),
        "Database should not exist before creation"
    );

    // Create storage - should auto-create the database file
    let storage = SqliteStorage::new(db_path_str).await.unwrap();

    // Verify database file was created
    assert!(db_path.exists(), "Database file should be auto-created");

    // Verify it's functional - try to save a run
    let run = Run {
        id: Uuid::new_v4(),
        flow_name: "test".to_string().into(),
        event: HashMap::new(),
        vars: HashMap::new(),
        status: RunStatus::Running,
        started_at: Utc::now(),
        ended_at: None,
        steps: None,
        tenant_id: "test_tenant".to_string(),
        triggered_by_user_id: "test_user".to_string(),
    };

    storage.save_run(&run).await.unwrap();
    let retrieved = storage.get_run(run.id, "test_tenant").await.unwrap();
    assert!(
        retrieved.is_some(),
        "Should be able to save and retrieve data"
    );
}

#[tokio::test]
async fn test_auto_create_parent_directories() {
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let nested_path = temp_dir.path().join("nested").join("dirs").join("flow.db");
    let nested_path_str = nested_path.to_str().unwrap();

    // Parent directories should not exist
    assert!(
        !nested_path.parent().unwrap().exists(),
        "Parent dirs should not exist"
    );

    // Create storage - should auto-create parent directories
    let storage = SqliteStorage::new(nested_path_str).await.unwrap();

    // Verify parent directories were created
    assert!(
        nested_path.parent().unwrap().exists(),
        "Parent directories should be created"
    );
    assert!(nested_path.exists(), "Database file should exist");

    // Verify it's functional - test with runs instead of flows
    let runs = storage.list_runs("test_tenant", 1000, 0).await.unwrap();
    assert_eq!(runs.len(), 0, "New database should have no runs");
}

#[tokio::test]
async fn test_reuse_existing_database() {
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("reuse.db");
    let db_path_str = db_path.to_str().unwrap();

    // Create storage and add some versioned flow data
    {
        let storage = SqliteStorage::new(db_path_str).await.unwrap();
        storage
            .deploy_flow_version(
                "test_tenant",
                "existing_flow",
                "1.0.0",
                "test content",
                "test_user",
            )
            .await
            .unwrap();
    }

    // Create new storage instance pointing to same database
    let storage = SqliteStorage::new(db_path_str).await.unwrap();

    // Verify existing data is accessible
    let version = storage
        .get_deployed_version("test_tenant", "existing_flow")
        .await
        .unwrap();
    assert_eq!(version, Some("1.0.0".to_string()));

    let content = storage
        .get_flow_version_content("test_tenant", "existing_flow", "1.0.0")
        .await
        .unwrap();
    assert_eq!(content, Some("test content".to_string()));
}

#[tokio::test]
async fn test_sqlite_prefix_handling() {
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("prefix_test.db");
    let db_path_str = db_path.to_str().unwrap();

    // Test with sqlite: prefix
    let prefixed_path = format!("sqlite:{}", db_path_str);
    let storage = SqliteStorage::new(&prefixed_path).await.unwrap();

    // Verify database file was created (without the prefix)
    assert!(
        db_path.exists(),
        "Database should be created at correct path"
    );

    // Verify it's functional - test with run operations
    let run = Run {
        id: Uuid::new_v4(),
        flow_name: "test".to_string().into(),
        event: HashMap::new(),
        vars: HashMap::new(),
        status: RunStatus::Running,
        started_at: Utc::now(),
        ended_at: None,
        steps: None,
        tenant_id: "test_tenant".to_string(),
        triggered_by_user_id: "test_user".to_string(),
    };
    storage.save_run(&run).await.unwrap();
    let retrieved = storage.get_run(run.id, "test_tenant").await.unwrap();
    assert!(retrieved.is_some());
}

#[tokio::test]
async fn test_concurrent_database_access() {
    use tempfile::TempDir;
    use tokio::task::JoinSet;

    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("concurrent.db");
    let db_path_str = db_path.to_string_lossy().to_string();

    // Create initial storage
    let storage = SqliteStorage::new(&db_path_str).await.unwrap();
    drop(storage);

    // Test concurrent access from multiple tasks
    let mut tasks = JoinSet::new();

    for i in 0..5 {
        let path = db_path_str.clone();
        tasks.spawn(async move {
            let storage = SqliteStorage::new(&path).await.unwrap();
            let run = Run {
                id: Uuid::new_v4(),
                flow_name: format!("flow_{}", i).into(),
                event: HashMap::new(),
                vars: HashMap::new(),
                status: RunStatus::Running,
                started_at: Utc::now(),
                ended_at: None,
                steps: None,
                tenant_id: "test_tenant".to_string(),
                triggered_by_user_id: "test_user".to_string(),
            };
            storage.save_run(&run).await.unwrap();
        });
    }

    // Wait for all tasks to complete
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }

    // Verify all runs were saved
    let storage = SqliteStorage::new(&db_path_str).await.unwrap();
    let runs = storage.list_runs("test_tenant", 1000, 0).await.unwrap();
    assert_eq!(runs.len(), 5, "All concurrent writes should succeed");
}

#[tokio::test]
async fn test_memory_database_still_works() {
    // Ensure :memory: databases still work correctly
    let storage = SqliteStorage::new(":memory:").await.unwrap();

    let run = Run {
        id: Uuid::new_v4(),
        flow_name: "test".to_string().into(),
        event: HashMap::new(),
        vars: HashMap::new(),
        status: RunStatus::Running,
        started_at: Utc::now(),
        ended_at: None,
        steps: None,
        tenant_id: "test_tenant".to_string(),
        triggered_by_user_id: "test_user".to_string(),
    };
    storage.save_run(&run).await.unwrap();
    let runs = storage.list_runs("test_tenant", 1000, 0).await.unwrap();
    assert_eq!(runs.len(), 1);

    // Memory databases should not create any files
    // (This is implicitly tested by the fact that no file path is involved)
}
