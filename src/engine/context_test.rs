use crate::engine::{RunsAccess, StepContext, context::is_valid_identifier};
use crate::model::{Run, RunStatus, StepRun, StepStatus};
use crate::storage::{SqliteStorage, Storage};
use chrono::Utc;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

// ============================================================================
// StepContext Tests
// ============================================================================

#[test]
fn test_context_operations() {
    // Test context with initial vars
    let mut vars = HashMap::new();
    vars.insert("var1".to_string(), Value::Number(42.into()));
    let ctx = StepContext::new(HashMap::new(), vars, HashMap::new());

    // Test output operations (outputs are mutable)
    ctx.set_output("test".to_string(), Value::String("value".to_string()));
    assert_eq!(ctx.get_output("test").unwrap().as_str().unwrap(), "value");

    // Verify vars are accessible from snapshot
    let snapshot = ctx.snapshot();
    assert_eq!(snapshot.vars.get("var1").unwrap().as_i64().unwrap(), 42);

    // Verify outputs are in snapshot
    assert_eq!(
        snapshot.outputs.get("test").unwrap().as_str().unwrap(),
        "value"
    );
}

#[test]
fn test_is_valid_identifier() {
    assert!(is_valid_identifier("valid_id"));
    assert!(is_valid_identifier("_private"));
    assert!(is_valid_identifier("Step123"));

    assert!(!is_valid_identifier(""));
    assert!(!is_valid_identifier("123start"));
    assert!(!is_valid_identifier("has-dash"));
    assert!(!is_valid_identifier("{{ template }}"));
}

// ============================================================================
// RunsAccess Tests (formerly runs_access_test.rs)
// ============================================================================

#[tokio::test]
async fn test_runs_access_previous() {
    let storage = Arc::new(
        SqliteStorage::new(":memory:")
            .await
            .expect("Failed to create SQLite storage"),
    ) as Arc<dyn Storage>;

    // Create a previous run
    let prev_run = Run {
        id: Uuid::new_v4(),
        flow_name: "test_flow".to_string().into(),
        event: HashMap::new(),
        vars: HashMap::new(),
        status: RunStatus::Succeeded,
        started_at: Utc::now(),
        ended_at: Some(Utc::now()),
        steps: None,
        organization_id: "test_org".to_string(),
        triggered_by_user_id: "test_user".to_string(),
    };

    storage.save_run(&prev_run).await.unwrap();

    // Add step outputs
    let step = StepRun {
        id: Uuid::new_v4(),
        run_id: prev_run.id,
        organization_id: "test_org".to_string(),
        step_name: "step1".to_string().into(),
        status: StepStatus::Succeeded,
        started_at: Utc::now(),
        ended_at: Some(Utc::now()),
        error: None,
        outputs: Some(
            serde_json::json!({"result": "hello"})
                .as_object()
                .unwrap()
                .clone()
                .into_iter()
                .collect(),
        ),
    };

    storage.save_step(&step).await.unwrap();

    // Create RunsAccess - use same organization_id as the run
    let runs_access = RunsAccess::new(
        storage,
        None,
        "test_flow".to_string(),
        "test_org".to_string(),
    );

    // Get previous run
    let previous = runs_access.previous().await;

    // Verify outputs
    assert!(previous.contains_key("id"));
    assert!(previous.contains_key("outputs"));
}
