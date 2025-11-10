//! Cron scheduler integration tests
//!
//! These tests verify the cron scheduler actually works with real storage and engine.

use super::*;
use crate::config::{Config, StorageConfig};
use crate::storage::{Storage, create_storage_from_config};
use std::sync::Arc;

/// Create test storage with in-memory SQLite and default tenant
async fn create_test_storage() -> Arc<dyn Storage> {
    let config = StorageConfig {
        driver: "sqlite".to_string(),
        dsn: ":memory:".to_string(),
    };

    let storage = create_storage_from_config(&config)
        .await
        .expect("Failed to create test storage");

    // Create system user for tenant creation
    let user = crate::auth::User {
        id: "system".to_string(),
        email: "system@beemflow.local".to_string(),
        name: Some("System".to_string()),
        password_hash: "".to_string(),
        email_verified: true,
        avatar_url: None,
        mfa_enabled: false,
        mfa_secret: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        last_login_at: None,
        disabled: false,
        disabled_reason: None,
        disabled_at: None,
    };
    storage
        .create_user(&user)
        .await
        .expect("Failed to create system user");

    // Create default tenant for cron operations
    let tenant = crate::auth::Tenant {
        id: "default".to_string(),
        name: "Default Tenant".to_string(),
        slug: "default".to_string(),
        plan: "free".to_string(),
        plan_starts_at: None,
        plan_ends_at: None,
        max_users: 10,
        max_flows: 100,
        max_runs_per_month: 1000,
        settings: None,
        created_by_user_id: "system".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        disabled: false,
    };
    storage
        .create_tenant(&tenant)
        .await
        .expect("Failed to create default tenant");

    storage
}

/// Create minimal test engine
fn create_test_engine(storage: Arc<dyn Storage>) -> Arc<Engine> {
    let config = Arc::new(Config::default());
    let secrets = config.create_secrets_provider();
    let registry_manager = Arc::new(crate::registry::RegistryManager::standard(
        Some(&config),
        secrets.clone(),
    ));

    let adapters = Arc::new(crate::adapter::AdapterRegistry::new(
        registry_manager.clone(),
    ));
    adapters.register(Arc::new(crate::adapter::CoreAdapter::new()));

    let mcp_adapter = Arc::new(crate::adapter::McpAdapter::new(secrets.clone()));
    adapters.register(mcp_adapter.clone());

    let templater = Arc::new(crate::dsl::Templater::new());

    let oauth_client = Arc::new(
        crate::auth::OAuthClientManager::new(
            storage.clone(),
            registry_manager.clone(),
            "http://localhost:3000/oauth/callback".to_string(),
        )
        .expect("Failed to create OAuth client"),
    );

    Arc::new(Engine::new(
        adapters,
        templater,
        storage.clone(),
        secrets,
        config,
        oauth_client,
        100,
    ))
}

#[tokio::test]
async fn test_flow_triggers_populated() {
    let storage = create_test_storage().await;

    let flow = r#"
name: test
version: 1.0.0
on: schedule.cron
cron: "0 0 9 * * *"
steps:
  - id: log
    use: core.log
    with:
      message: "Test"
"#;

    storage
        .deploy_flow_version("default", "test", "1.0.0", flow, "test_user")
        .await
        .unwrap();

    // Verify flow_triggers table is populated
    let names = storage
        .find_flow_names_by_topic("default", "schedule.cron")
        .await
        .unwrap();
    assert_eq!(
        names.len(),
        1,
        "flow_triggers table not populated correctly"
    );
    assert_eq!(names[0], "test");

    // Verify batch content query works
    let contents = storage
        .get_deployed_flows_content("default", &names)
        .await
        .unwrap();
    assert_eq!(contents.len(), 1);
    assert_eq!(contents[0].0, "test");
    assert!(contents[0].1.contains("schedule.cron"));
}

#[tokio::test]
async fn test_sync_with_no_cron_flows() {
    let storage = create_test_storage().await;
    let engine = create_test_engine(storage.clone());
    let cron = CronManager::new(storage.clone(), engine).await.unwrap();

    // Deploy flow WITHOUT cron trigger
    let flow_yaml = r#"
name: no_cron_flow
version: 1.0.0
on: cli.manual
steps:
  - id: log
    use: core.log
    with:
      message: "No cron"
"#;
    storage
        .deploy_flow_version("default", "no_cron_flow", "1.0.0", flow_yaml, "test_user")
        .await
        .unwrap();

    // Sync should succeed with no scheduled flows
    let report = cron.sync().await.unwrap();
    assert_eq!(report.scheduled.len(), 0);
    assert_eq!(report.errors.len(), 0);

    cron.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_sync_with_cron_flows() {
    let storage = create_test_storage().await;
    let engine = create_test_engine(storage.clone());
    let cron = CronManager::new(storage.clone(), engine).await.unwrap();

    // Deploy two flows with cron triggers
    let flow1 = r#"
name: daily_flow
version: 1.0.0
on: schedule.cron
cron: "0 0 9 * * *"
steps:
  - id: log
    use: core.log
    with:
      message: "Daily"
"#;

    let flow2 = r#"
name: hourly_flow
version: 1.0.0
on: schedule.cron
cron: "0 0 * * * *"
steps:
  - id: log
    use: core.log
    with:
      message: "Hourly"
"#;

    storage
        .deploy_flow_version("default", "daily_flow", "1.0.0", flow1, "test_user")
        .await
        .unwrap();
    storage
        .deploy_flow_version("default", "hourly_flow", "1.0.0", flow2, "test_user")
        .await
        .unwrap();

    // Sync should schedule both flows
    let report = cron.sync().await.unwrap();

    // Debug: print errors if any
    if !report.errors.is_empty() {
        eprintln!("Sync errors: {:?}", report.errors);
    }

    assert_eq!(
        report.errors.len(),
        0,
        "Sync had errors: {:?}",
        report.errors
    );
    assert_eq!(
        report.scheduled.len(),
        2,
        "Expected 2 scheduled flows, got {}",
        report.scheduled.len()
    );

    // Verify both flows are in the report
    let scheduled_names: Vec<_> = report.scheduled.iter().map(|s| s.name.as_str()).collect();
    assert!(scheduled_names.contains(&"default/daily_flow"));
    assert!(scheduled_names.contains(&"default/hourly_flow"));

    // Verify cron expressions
    let daily = report
        .scheduled
        .iter()
        .find(|s| s.name == "default/daily_flow")
        .unwrap();
    assert_eq!(daily.cron_expression, "0 0 9 * * *");

    cron.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_add_schedule_creates_job() {
    let storage = create_test_storage().await;
    let engine = create_test_engine(storage.clone());
    let cron = CronManager::new(storage.clone(), engine).await.unwrap();

    // Deploy flow with cron trigger
    let flow_yaml = r#"
name: test_flow
version: 1.0.0
on: schedule.cron
cron: "0 */5 * * * *"
steps:
  - id: log
    use: core.log
    with:
      message: "Test"
"#;
    storage
        .deploy_flow_version("default", "test_flow", "1.0.0", flow_yaml, "test_user")
        .await
        .unwrap();

    // Add schedule should succeed
    let result = cron.add_schedule("default", "test_flow").await;
    assert!(result.is_ok(), "add_schedule failed: {:?}", result.err());

    // Verify job is tracked
    let jobs = cron.jobs.lock().await;
    assert!(jobs.contains_key(&("default".to_string(), "test_flow".to_string())));

    cron.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_add_schedule_without_cron_trigger() {
    let storage = create_test_storage().await;
    let engine = create_test_engine(storage.clone());
    let cron = CronManager::new(storage.clone(), engine).await.unwrap();

    // Deploy flow WITHOUT cron trigger
    let flow_yaml = r#"
name: manual_flow
version: 1.0.0
on: cli.manual
steps:
  - id: log
    use: core.log
    with:
      message: "Manual"
"#;
    storage
        .deploy_flow_version("default", "manual_flow", "1.0.0", flow_yaml, "test_user")
        .await
        .unwrap();

    // add_schedule should succeed but not create job
    cron.add_schedule("default", "manual_flow").await.unwrap();

    // Verify no job is tracked
    let jobs = cron.jobs.lock().await;
    assert!(!jobs.contains_key(&("default".to_string(), "manual_flow".to_string())));

    cron.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_add_schedule_not_deployed() {
    let storage = create_test_storage().await;
    let engine = create_test_engine(storage.clone());
    let cron = CronManager::new(storage.clone(), engine).await.unwrap();

    // Don't deploy the flow - just try to schedule it
    let result = cron.add_schedule("default", "nonexistent_flow").await;

    // Should succeed (no-op if not deployed)
    assert!(result.is_ok());

    // Verify no job is tracked
    let jobs = cron.jobs.lock().await;
    assert!(!jobs.contains_key(&("default".to_string(), "nonexistent_flow".to_string())));

    cron.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_add_schedule_invalid_cron_expression() {
    let storage = create_test_storage().await;
    let engine = create_test_engine(storage.clone());
    let cron = CronManager::new(storage.clone(), engine).await.unwrap();

    // Deploy flow with INVALID cron expression
    let flow_yaml = r#"
name: bad_cron
version: 1.0.0
on: schedule.cron
cron: "invalid expression"
steps:
  - id: log
    use: core.log
    with:
      message: "Test"
"#;
    storage
        .deploy_flow_version("default", "bad_cron", "1.0.0", flow_yaml, "test_user")
        .await
        .unwrap();

    // add_schedule should FAIL with validation error
    let result = cron.add_schedule("default", "bad_cron").await;
    assert!(result.is_err());
    assert!(format!("{:?}", result.err().unwrap()).contains("Invalid cron expression"));

    // Verify no job is tracked
    let jobs = cron.jobs.lock().await;
    assert!(!jobs.contains_key(&("default".to_string(), "bad_cron".to_string())));

    cron.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_add_schedule_missing_cron_field() {
    let storage = create_test_storage().await;
    let engine = create_test_engine(storage.clone());
    let cron = CronManager::new(storage.clone(), engine).await.unwrap();

    // Deploy flow with schedule.cron trigger but NO cron field
    let flow_yaml = r#"
name: missing_cron
version: 1.0.0
on: schedule.cron
steps:
  - id: log
    use: core.log
    with:
      message: "Test"
"#;
    storage
        .deploy_flow_version("default", "missing_cron", "1.0.0", flow_yaml, "test_user")
        .await
        .unwrap();

    // add_schedule should FAIL with validation error
    let result = cron.add_schedule("default", "missing_cron").await;
    assert!(result.is_err());
    assert!(format!("{:?}", result.err().unwrap()).contains("missing cron field"));

    cron.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_remove_schedule() {
    let storage = create_test_storage().await;
    let engine = create_test_engine(storage.clone());
    let cron = CronManager::new(storage.clone(), engine).await.unwrap();

    // Deploy and schedule a flow
    let flow_yaml = r#"
name: temp_flow
version: 1.0.0
on: schedule.cron
cron: "0 0 * * * *"
steps:
  - id: log
    use: core.log
    with:
      message: "Test"
"#;
    storage
        .deploy_flow_version("default", "temp_flow", "1.0.0", flow_yaml, "test_user")
        .await
        .unwrap();

    cron.add_schedule("default", "temp_flow").await.unwrap();

    // Verify job exists
    {
        let jobs = cron.jobs.lock().await;
        assert!(jobs.contains_key(&("default".to_string(), "temp_flow".to_string())));
    }

    // Remove schedule
    cron.remove_schedule("default", "temp_flow").await.unwrap();

    // Verify job is removed
    let jobs = cron.jobs.lock().await;
    assert!(!jobs.contains_key(&("default".to_string(), "temp_flow".to_string())));

    cron.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_remove_schedule_nonexistent() {
    let storage = create_test_storage().await;
    let engine = create_test_engine(storage.clone());
    let cron = CronManager::new(storage.clone(), engine).await.unwrap();

    // Remove schedule for flow that was never scheduled
    let result = cron.remove_schedule("default", "nonexistent").await;

    // Should succeed (idempotent)
    assert!(result.is_ok());

    cron.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_add_schedule_replaces_existing_job() {
    let storage = create_test_storage().await;
    let engine = create_test_engine(storage.clone());
    let cron = CronManager::new(storage.clone(), engine).await.unwrap();

    // Deploy initial version
    let flow_v1 = r#"
name: versioned_flow
version: 1.0.0
on: schedule.cron
cron: "0 0 9 * * *"
steps:
  - id: log
    use: core.log
    with:
      message: "Version 1"
"#;
    storage
        .deploy_flow_version("default", "versioned_flow", "1.0.0", flow_v1, "test_user")
        .await
        .unwrap();

    cron.add_schedule("default", "versioned_flow")
        .await
        .unwrap();

    // Get initial job ID
    let initial_job_id = {
        let jobs = cron.jobs.lock().await;
        *jobs
            .get(&("default".to_string(), "versioned_flow".to_string()))
            .unwrap()
    };

    // Deploy new version with DIFFERENT cron expression
    let flow_v2 = r#"
name: versioned_flow
version: 2.0.0
on: schedule.cron
cron: "0 0 10 * * *"
steps:
  - id: log
    use: core.log
    with:
      message: "Version 2"
"#;
    storage
        .deploy_flow_version("default", "versioned_flow", "2.0.0", flow_v2, "test_user")
        .await
        .unwrap();

    // Rollback (like real rollback operation does)
    storage
        .set_deployed_version("default", "versioned_flow", "2.0.0")
        .await
        .unwrap();

    // Schedule again - should replace old job
    cron.add_schedule("default", "versioned_flow")
        .await
        .unwrap();

    // Get new job ID
    let new_job_id = {
        let jobs = cron.jobs.lock().await;
        *jobs
            .get(&("default".to_string(), "versioned_flow".to_string()))
            .unwrap()
    };

    // Job IDs should be different (old job removed, new job added)
    assert_ne!(initial_job_id, new_job_id);

    // Should only have one job tracked
    let jobs = cron.jobs.lock().await;
    assert_eq!(jobs.len(), 1);

    cron.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_sync_uses_flow_triggers_table() {
    let storage = create_test_storage().await;
    let engine = create_test_engine(storage.clone());
    let cron = CronManager::new(storage.clone(), engine).await.unwrap();

    // Deploy multiple flows with different triggers
    let cron_flow = r#"
name: cron_flow
version: 1.0.0
on: schedule.cron
cron: "0 0 9 * * *"
steps:
  - id: log
    use: core.log
    with:
      message: "Cron"
"#;

    let webhook_flow = r#"
name: webhook_flow
version: 1.0.0
on: webhook.github
steps:
  - id: log
    use: core.log
    with:
      message: "Webhook"
"#;

    let manual_flow = r#"
name: manual_flow
version: 1.0.0
on: cli.manual
steps:
  - id: log
    use: core.log
    with:
      message: "Manual"
"#;

    storage
        .deploy_flow_version("default", "cron_flow", "1.0.0", cron_flow, "test_user")
        .await
        .unwrap();
    storage
        .deploy_flow_version(
            "default",
            "webhook_flow",
            "1.0.0",
            webhook_flow,
            "test_user",
        )
        .await
        .unwrap();
    storage
        .deploy_flow_version("default", "manual_flow", "1.0.0", manual_flow, "test_user")
        .await
        .unwrap();

    // Sync should only schedule the cron flow (uses flow_triggers query)
    let report = cron.sync().await.unwrap();
    assert_eq!(report.scheduled.len(), 1);
    assert_eq!(report.scheduled[0].name, "default/cron_flow");

    cron.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_sync_with_disabled_flow() {
    let storage = create_test_storage().await;
    let engine = create_test_engine(storage.clone());
    let cron = CronManager::new(storage.clone(), engine).await.unwrap();

    // Deploy two cron flows
    let flow1 = r#"
name: enabled_flow
version: 1.0.0
on: schedule.cron
cron: "0 0 9 * * *"
steps:
  - id: log
    use: core.log
    with:
      message: "Enabled"
"#;

    let flow2 = r#"
name: disabled_flow
version: 1.0.0
on: schedule.cron
cron: "0 0 10 * * *"
steps:
  - id: log
    use: core.log
    with:
      message: "Disabled"
"#;

    storage
        .deploy_flow_version("default", "enabled_flow", "1.0.0", flow1, "test_user")
        .await
        .unwrap();
    storage
        .deploy_flow_version("default", "disabled_flow", "1.0.0", flow2, "test_user")
        .await
        .unwrap();

    // Disable one flow
    storage
        .unset_deployed_version("default", "disabled_flow")
        .await
        .unwrap();

    // Sync should only schedule the enabled flow
    let report = cron.sync().await.unwrap();
    assert_eq!(report.scheduled.len(), 1);
    assert_eq!(report.scheduled[0].name, "default/enabled_flow");

    cron.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_sync_with_invalid_cron_expression() {
    let storage = create_test_storage().await;
    let engine = create_test_engine(storage.clone());
    let cron = CronManager::new(storage.clone(), engine).await.unwrap();

    // Deploy flow with invalid cron
    let bad_flow = r#"
name: bad_cron_flow
version: 1.0.0
on: schedule.cron
cron: "0 60 99 * * *"
steps:
  - id: log
    use: core.log
    with:
      message: "Test"
"#;

    storage
        .deploy_flow_version("default", "bad_cron_flow", "1.0.0", bad_flow, "test_user")
        .await
        .unwrap();

    // Sync should report error but not fail
    let report = cron.sync().await.unwrap();
    assert_eq!(report.scheduled.len(), 0);
    assert_eq!(report.errors.len(), 1);
    assert!(report.errors[0].contains("bad_cron_flow"));

    cron.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_concurrent_add_schedule() {
    let storage = create_test_storage().await;
    let engine = create_test_engine(storage.clone());
    let cron = Arc::new(CronManager::new(storage.clone(), engine).await.unwrap());

    // Deploy 5 flows concurrently
    for i in 0..5 {
        let flow = format!(
            r#"
name: flow_{}
version: 1.0.0
on: schedule.cron
cron: "0 0 {} * * *"
steps:
  - id: log
    use: core.log
    with:
      message: "Flow {}"
"#,
            i, i, i
        );

        storage
            .deploy_flow_version(
                "default",
                &format!("flow_{}", i),
                "1.0.0",
                &flow,
                "test_user",
            )
            .await
            .unwrap();
    }

    // Schedule all flows in parallel
    let mut handles = vec![];
    for i in 0..5 {
        let cron_clone = cron.clone();
        let handle = tokio::spawn(async move {
            cron_clone
                .add_schedule("default", &format!("flow_{}", i))
                .await
                .unwrap();
        });
        handles.push(handle);
    }

    // Wait for all to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Verify all 5 jobs are tracked
    let jobs = cron.jobs.lock().await;
    assert_eq!(jobs.len(), 5);

    cron.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_full_lifecycle() {
    let storage = create_test_storage().await;
    let engine = create_test_engine(storage.clone());
    let cron = CronManager::new(storage.clone(), engine).await.unwrap();

    // Deploy flow
    let flow_yaml = r#"
name: lifecycle_flow
version: 1.0.0
on: schedule.cron
cron: "0 0 9 * * *"
steps:
  - id: log
    use: core.log
    with:
      message: "Test"
"#;
    storage
        .deploy_flow_version("default", "lifecycle_flow", "1.0.0", flow_yaml, "test_user")
        .await
        .unwrap();

    // Initial sync
    let report = cron.sync().await.unwrap();
    assert_eq!(report.scheduled.len(), 1);

    // Disable
    storage
        .unset_deployed_version("default", "lifecycle_flow")
        .await
        .unwrap();
    cron.remove_schedule("default", "lifecycle_flow")
        .await
        .unwrap();

    {
        let jobs = cron.jobs.lock().await;
        assert!(!jobs.contains_key(&("default".to_string(), "lifecycle_flow".to_string())));
    }

    // Re-enable
    storage
        .set_deployed_version("default", "lifecycle_flow", "1.0.0")
        .await
        .unwrap();
    cron.add_schedule("default", "lifecycle_flow")
        .await
        .unwrap();

    {
        let jobs = cron.jobs.lock().await;
        assert!(jobs.contains_key(&("default".to_string(), "lifecycle_flow".to_string())));
    }

    cron.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_sync_clears_old_jobs_before_adding_new() {
    let storage = create_test_storage().await;
    let engine = create_test_engine(storage.clone());
    let cron = CronManager::new(storage.clone(), engine).await.unwrap();

    // Deploy and sync initial flow
    let flow1 = r#"
name: flow1
version: 1.0.0
on: schedule.cron
cron: "0 0 9 * * *"
steps:
  - id: log
    use: core.log
    with:
      message: "Flow 1"
"#;
    storage
        .deploy_flow_version("default", "flow1", "1.0.0", flow1, "test_user")
        .await
        .unwrap();

    cron.sync().await.unwrap();

    {
        let jobs = cron.jobs.lock().await;
        assert_eq!(jobs.len(), 1);
    }

    // Deploy different flow and resync
    storage
        .unset_deployed_version("default", "flow1")
        .await
        .unwrap();

    let flow2 = r#"
name: flow2
version: 1.0.0
on: schedule.cron
cron: "0 0 10 * * *"
steps:
  - id: log
    use: core.log
    with:
      message: "Flow 2"
"#;
    storage
        .deploy_flow_version("default", "flow2", "1.0.0", flow2, "test_user")
        .await
        .unwrap();

    cron.sync().await.unwrap();

    // Should only have flow2, not flow1
    let jobs = cron.jobs.lock().await;
    assert_eq!(jobs.len(), 1);
    assert!(jobs.contains_key(&("default".to_string(), "flow2".to_string())));
    assert!(!jobs.contains_key(&("default".to_string(), "flow1".to_string())));

    cron.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_multiple_triggers_including_cron() {
    let storage = create_test_storage().await;
    let engine = create_test_engine(storage.clone());
    let cron = CronManager::new(storage.clone(), engine).await.unwrap();

    // Deploy flow with MULTIPLE triggers including cron
    let flow_yaml = r#"
name: multi_trigger
version: 1.0.0
on:
  - cli.manual
  - schedule.cron
  - webhook.github
cron: "0 0 9 * * *"
steps:
  - id: log
    use: core.log
    with:
      message: "Multi"
"#;
    storage
        .deploy_flow_version("default", "multi_trigger", "1.0.0", flow_yaml, "test_user")
        .await
        .unwrap();

    // Should schedule successfully
    cron.add_schedule("default", "multi_trigger").await.unwrap();

    let jobs = cron.jobs.lock().await;
    assert!(jobs.contains_key(&("default".to_string(), "multi_trigger".to_string())));

    cron.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_array_format_with_cron() {
    let storage = create_test_storage().await;
    let engine = create_test_engine(storage.clone());
    let cron = CronManager::new(storage.clone(), engine).await.unwrap();

    // Deploy flow with array format: [cli.manual, schedule.cron]
    let flow_yaml = r#"
name: array_format
version: 1.0.0
on: [cli.manual, schedule.cron]
cron: "0 0 12 * * *"
steps:
  - id: log
    use: core.log
    with:
      message: "Array format"
"#;
    storage
        .deploy_flow_version("default", "array_format", "1.0.0", flow_yaml, "test_user")
        .await
        .unwrap();

    // Verify flow_triggers table has schedule.cron topic
    let names = storage
        .find_flow_names_by_topic("default", "schedule.cron")
        .await
        .unwrap();
    assert_eq!(names.len(), 1);
    assert_eq!(names[0], "array_format");

    // add_schedule should work
    cron.add_schedule("default", "array_format").await.unwrap();

    let jobs = cron.jobs.lock().await;
    assert!(jobs.contains_key(&("default".to_string(), "array_format".to_string())));

    cron.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_single_string_format_with_cron() {
    let storage = create_test_storage().await;
    let engine = create_test_engine(storage.clone());
    let cron = CronManager::new(storage.clone(), engine).await.unwrap();

    // Deploy flow with single string format: schedule.cron
    let flow_yaml = r#"
name: single_format
version: 1.0.0
on: schedule.cron
cron: "0 0 15 * * *"
steps:
  - id: log
    use: core.log
    with:
      message: "Single format"
"#;
    storage
        .deploy_flow_version("default", "single_format", "1.0.0", flow_yaml, "test_user")
        .await
        .unwrap();

    // Verify flow_triggers table has schedule.cron topic
    let names = storage
        .find_flow_names_by_topic("default", "schedule.cron")
        .await
        .unwrap();
    assert_eq!(names.len(), 1);
    assert_eq!(names[0], "single_format");

    // add_schedule should work
    cron.add_schedule("default", "single_format").await.unwrap();

    let jobs = cron.jobs.lock().await;
    assert!(jobs.contains_key(&("default".to_string(), "single_format".to_string())));

    cron.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_job_uuid_tracking() {
    let storage = create_test_storage().await;
    let engine = create_test_engine(storage.clone());
    let cron = CronManager::new(storage.clone(), engine).await.unwrap();

    // Deploy flow
    let flow_yaml = r#"
name: tracked_flow
version: 1.0.0
on: schedule.cron
cron: "0 0 9 * * *"
steps:
  - id: log
    use: core.log
    with:
      message: "Test"
"#;
    storage
        .deploy_flow_version("default", "tracked_flow", "1.0.0", flow_yaml, "test_user")
        .await
        .unwrap();

    // Schedule
    cron.add_schedule("default", "tracked_flow").await.unwrap();

    // Verify UUID is tracked
    {
        let jobs = cron.jobs.lock().await;
        assert!(jobs.contains_key(&("default".to_string(), "tracked_flow".to_string())));
    }

    // Remove
    cron.remove_schedule("default", "tracked_flow")
        .await
        .unwrap();

    // Verify UUID is removed from tracking
    {
        let jobs = cron.jobs.lock().await;
        assert!(!jobs.contains_key(&("default".to_string(), "tracked_flow".to_string())));
    }

    cron.shutdown().await.unwrap();
}
