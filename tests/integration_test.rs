//! Integration tests for BeemFlow
//!
//! Tests the complete system end-to-end

use beemflow::dsl::{Validator, parse_file, parse_string};
use beemflow::storage::{FlowStorage, RunStorage};
use beemflow::{Engine, Flow};
use std::collections::HashMap;

/// Helper function to create a test auth context
fn create_test_context() -> beemflow::auth::RequestContext {
    beemflow::auth::RequestContext {
        user_id: "test_user".to_string(),
        organization_id: "test_org".to_string(),
        organization_name: "test_org".to_string(),
        role: beemflow::auth::Role::Admin,
        client_ip: None,
        user_agent: None,
        request_id: "test".to_string(),
    }
}

#[tokio::test]
async fn test_hello_world_flow() {
    // Parse the hello_world flow from examples
    let flow = parse_file("flows/examples/hello_world.flow.yaml", None).unwrap();

    // Validate it
    assert!(Validator::validate(&flow).is_ok());

    // Execute it
    let engine = Engine::for_testing().await;
    let result = engine
        .execute(&flow, HashMap::new(), "test_user", "test_org")
        .await
        .unwrap();
    let outputs = result.outputs;

    // Verify outputs
    assert!(outputs.contains_key("greet"));
    assert!(outputs.contains_key("greet_again"));

    // Check that greet has text field
    if let Some(greet_output) = outputs.get("greet") {
        let greet_map: HashMap<String, serde_json::Value> =
            serde_json::from_value(greet_output.clone()).unwrap();
        assert!(greet_map.contains_key("text"));
        assert_eq!(
            greet_map.get("text").unwrap().as_str().unwrap(),
            "Hello, world, I'm BeemFlow!"
        );
    } else {
        panic!("greet output not found");
    }
}

#[tokio::test]
async fn test_flow_validation() {
    // Valid flow
    let yaml = r#"
name: test_flow
on: cli.manual
steps:
  - id: step1
    use: core.echo
    with:
      text: "test"
"#;

    let flow = parse_string(yaml, None).unwrap();
    assert!(Validator::validate(&flow).is_ok());

    // Invalid flow - missing name
    let invalid_yaml = r#"
name: ""
on: cli.manual
steps:
  - id: step1
    use: core.echo
"#;

    let invalid_flow = parse_string(invalid_yaml, None).unwrap();

    // Validation should catch the empty name
    assert!(Validator::validate(&invalid_flow).is_err());
}

#[tokio::test]
async fn test_core_echo_adapter() {
    let yaml = r#"
name: echo_test
on: cli.manual
steps:
  - id: echo_step
    use: core.echo
    with:
      text: "Hello from Rust!"
"#;

    let flow = parse_string(yaml, None).unwrap();
    let engine = Engine::for_testing().await;
    let result = engine
        .execute(&flow, HashMap::new(), "test_user", "test_org")
        .await
        .unwrap();
    let outputs = result.outputs;

    assert!(outputs.contains_key("echo_step"));
    let echo_output: HashMap<String, serde_json::Value> =
        serde_json::from_value(outputs.get("echo_step").unwrap().clone()).unwrap();
    assert_eq!(
        echo_output.get("text").unwrap().as_str().unwrap(),
        "Hello from Rust!"
    );
}

#[tokio::test]
async fn test_template_rendering() {
    let yaml = r#"
name: template_test
on: cli.manual
vars:
  greeting: "Hello"
  name: "Rust"
steps:
  - id: templated_echo
    use: core.echo
    with:
      text: "{{ vars.greeting }}, {{ vars.name }}!"
"#;

    let flow = parse_string(yaml, None).unwrap();
    let engine = Engine::for_testing().await;
    let result = engine
        .execute(&flow, HashMap::new(), "test_user", "test_org")
        .await
        .unwrap();
    let outputs = result.outputs;

    assert!(outputs.contains_key("templated_echo"));
    let echo_output: HashMap<String, serde_json::Value> =
        serde_json::from_value(outputs.get("templated_echo").unwrap().clone()).unwrap();
    assert_eq!(
        echo_output.get("text").unwrap().as_str().unwrap(),
        "Hello, Rust!"
    );
}

#[tokio::test]
async fn test_multiple_steps_with_dependencies() {
    let yaml = r#"
name: multi_step_test
on: cli.manual
steps:
  - id: step1
    use: core.echo
    with:
      text: "First"
  - id: step2
    use: core.echo
    with:
      text: "Second: {{ outputs.step1.text }}"
  - id: step3
    use: core.echo
    with:
      text: "Third: {{ step1.text }} and {{ step2.text }}"
"#;

    let flow = parse_string(yaml, None).unwrap();
    let engine = Engine::for_testing().await;
    let result = engine
        .execute(&flow, HashMap::new(), "test_user", "test_org")
        .await
        .unwrap();
    let outputs = result.outputs;

    assert_eq!(outputs.len(), 3);
    assert!(outputs.contains_key("step1"));
    assert!(outputs.contains_key("step2"));
    assert!(outputs.contains_key("step3"));

    // Verify output propagation
    let step2: HashMap<String, serde_json::Value> =
        serde_json::from_value(outputs.get("step2").unwrap().clone()).unwrap();
    assert!(
        step2
            .get("text")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("First")
    );
}

#[test]
fn test_flow_deserialization_all_fields() {
    let yaml = r#"
name: complete_flow
description: A flow with all fields
version: "1.0.0"
on:
  - cli.manual
  - schedule.cron
cron: "0 9 * * *"
vars:
  key1: "value1"
  key2: 42
steps:
  - id: step1
    use: core.echo
    with:
      text: "test"
    if: "{{ vars.key2 > 10 }}"
    retry:
      attempts: 3
      delay_sec: 5
catch:
  - id: error_handler
    use: core.echo
    with:
      text: "Error occurred"
"#;

    let flow: Flow = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(flow.name.as_str(), "complete_flow");
    assert_eq!(flow.version.unwrap(), "1.0.0");
    assert!(flow.vars.is_some());
    assert!(flow.catch.is_some());
    assert_eq!(flow.steps.len(), 1);
    assert_eq!(flow.catch.unwrap().len(), 1);
}

#[tokio::test]
async fn test_storage_operations() {
    use beemflow::utils::TestEnvironment;
    use chrono::Utc;
    use uuid::Uuid;

    let env = TestEnvironment::new().await;

    // Test flow versioning
    env.deps
        .storage
        .deploy_flow_version("test_org", "test_flow", "1.0.0", "content", "test_user")
        .await
        .unwrap();
    let retrieved = env
        .deps
        .storage
        .get_flow_version_content("test_org", "test_flow", "1.0.0")
        .await
        .unwrap();
    assert_eq!(retrieved.unwrap(), "content");

    // Test run storage
    let run = beemflow::model::Run {
        id: Uuid::new_v4(),
        flow_name: "test".to_string().into(),
        event: HashMap::new(),
        vars: HashMap::new(),
        status: beemflow::model::RunStatus::Running,
        started_at: Utc::now(),
        ended_at: None,
        steps: None,
        organization_id: "test_org".to_string(),
        triggered_by_user_id: "test_user".to_string(),
    };

    env.deps.storage.save_run(&run).await.unwrap();
    let retrieved_run = env
        .deps
        .storage
        .get_run(run.id, "test_org")
        .await
        .unwrap();
    assert!(retrieved_run.is_some());
    assert_eq!(retrieved_run.unwrap().flow_name.as_str(), "test");
}

// ============================================================================
// CLI and Server Integration Tests
// ============================================================================

#[tokio::test]
async fn test_cli_operations_with_fresh_database() {
    use beemflow::core::OperationRegistry;
    use beemflow::utils::TestEnvironment;

    let env = TestEnvironment::new().await;
    let registry = OperationRegistry::new(env.deps);

    let ctx = create_test_context();

    beemflow::core::REQUEST_CONTEXT.scope(ctx, async {
        // Test saving a flow
        let save_result = registry.execute("save_flow", serde_json::json!({
            "name": "test_flow",
            "content": "name: test_flow\non: cli.manual\nsteps:\n  - id: test\n    use: core.echo\n    with:\n      text: test"
        })).await;
        assert!(save_result.is_ok(), "Should be able to save flow");

        // Test listing flows - just verify it succeeds
        let list_result = registry.execute("list_flows", serde_json::json!({})).await;
        assert!(list_result.is_ok(), "Should be able to list flows");

        // Test getting flow
        let get_result = registry
            .execute(
                "get_flow",
                serde_json::json!({
                    "name": "test_flow"
                }),
            )
            .await;
        assert!(get_result.is_ok(), "Should be able to get flow");
    }).await;
}

#[tokio::test]
async fn test_mcp_server_with_fresh_database() {
    use beemflow::core::OperationRegistry;
    use beemflow::mcp::McpServer;
    use beemflow::utils::TestEnvironment;
    use std::sync::Arc;

    let env = TestEnvironment::new().await;
    let registry = Arc::new(OperationRegistry::new(env.deps));

    // Create MCP server - if this succeeds, the database is functional
    let _server = McpServer::new(registry.clone());

    let ctx = create_test_context();

    beemflow::core::REQUEST_CONTEXT.scope(ctx, async {
        // Verify server can perform operations through registry
        let list_result = registry.execute("list_flows", serde_json::json!({})).await;
        assert!(
            list_result.is_ok(),
            "Fresh database should support list_flows"
        );

        // Test saving a flow through the registry (as MCP would)
        let save_result = registry.execute("save_flow", serde_json::json!({
            "name": "mcp_test_flow",
            "content": "name: mcp_test\non: cli.manual\nsteps:\n  - id: test\n    use: core.echo\n    with:\n      text: test"
        })).await;
        assert!(
            save_result.is_ok(),
            "MCP server should be able to save flows: {:?}",
            save_result.as_ref().err()
        );

        // Verify flow was saved
        let get_result = registry
            .execute(
                "get_flow",
                serde_json::json!({
                    "name": "mcp_test_flow"
                }),
            )
            .await;
        assert!(get_result.is_ok(), "Should be able to retrieve saved flow");
    }).await;
}

#[tokio::test]
async fn test_cli_reuses_existing_database() {
    use beemflow::storage::SqliteStorage;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("reuse.db");
    let db_path_str = db_path.to_str().unwrap();

    // First connection - create and populate database
    {
        let storage = SqliteStorage::new(db_path_str).await.unwrap();
        storage
            .deploy_flow_version(
                "test_org",
                "persisted_flow",
                "1.0.0",
                "content",
                "test_user",
            )
            .await
            .unwrap();
    }

    // Second connection - should reuse existing database
    {
        let storage = SqliteStorage::new(db_path_str).await.unwrap();
        let version = storage
            .get_deployed_version("test_org", "persisted_flow")
            .await
            .unwrap();
        assert_eq!(
            version,
            Some("1.0.0".to_string()),
            "Should find persisted flow"
        );
    }

    // Verify database file still exists
    assert!(db_path.exists(), "Database file should persist");
}

#[tokio::test]
async fn test_cli_with_missing_parent_directory() {
    use beemflow::storage::SqliteStorage;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let nested_path = temp_dir.path().join("level1").join("level2").join("cli.db");
    let nested_path_str = nested_path.to_str().unwrap();

    // Parent directories should not exist
    assert!(
        !nested_path.parent().unwrap().exists(),
        "Parent dirs should not exist"
    );

    // Create storage - should auto-create all parent directories
    let storage = SqliteStorage::new(nested_path_str).await.unwrap();

    // Verify parent directories were created
    assert!(
        nested_path.parent().unwrap().exists(),
        "Parent directories should be created"
    );
    assert!(nested_path.exists(), "Database should exist");

    // Verify it's functional - test with run operations instead
    use beemflow::model::{Run, RunStatus};
    let run = Run {
        id: uuid::Uuid::new_v4(),
        flow_name: "test".to_string().into(),
        event: std::collections::HashMap::new(),
        vars: std::collections::HashMap::new(),
        status: RunStatus::Running,
        started_at: chrono::Utc::now(),
        ended_at: None,
        steps: None,
        organization_id: "test_org".to_string(),
        triggered_by_user_id: "test_user".to_string(),
    };
    storage.save_run(&run).await.unwrap();
    let runs = storage.list_runs("test_org", 1000, 0).await.unwrap();
    assert_eq!(runs.len(), 1);
}

// ============================================================================
// Production-Safe Flow Deployment Tests
// ============================================================================

#[tokio::test]
async fn test_draft_vs_production_run() {
    use beemflow::core::OperationRegistry;
    use beemflow::utils::TestEnvironment;

    let env = TestEnvironment::new().await;
    let registry = OperationRegistry::new(env.deps);

    let ctx = create_test_context();

    beemflow::core::REQUEST_CONTEXT
        .scope(ctx, async {
            // Step 1: Save a draft flow to filesystem
            let flow_content = r#"name: draft_test
version: "1.0.0"
on: cli.manual
steps:
  - id: step1
    use: core.echo
    with:
      text: "Draft version""#;

            let save_result = registry
                .execute(
                    "save_flow",
                    serde_json::json!({
                        "name": "draft_test",
                        "content": flow_content
                    }),
                )
                .await;
            assert!(save_result.is_ok(), "Should save draft flow");

            // Step 2: Try to run WITHOUT --draft flag (should fail - not deployed)
            let run_production = registry
                .execute(
                    "start_run",
                    serde_json::json!({
                        "flow_name": "draft_test",
                        "event": {},
                        "draft": false
                    }),
                )
                .await;
            assert!(
                run_production.is_err(),
                "Should fail to run non-deployed flow without draft flag"
            );
            let err_msg = format!("{:?}", run_production.unwrap_err());
            assert!(
                err_msg.contains("use --draft") || err_msg.contains("Deployed flow"),
                "Error should suggest using --draft flag"
            );

            // Step 3: Run WITH --draft flag (should succeed from filesystem)
            let run_draft = registry
                .execute(
                    "start_run",
                    serde_json::json!({
                        "flow_name": "draft_test",
                        "event": {"run": 1},
                        "draft": true
                    }),
                )
                .await;
            assert!(run_draft.is_ok(), "Should run draft flow from filesystem");

            // Step 4: Deploy the flow to database
            let deploy_result = registry
                .execute(
                    "deploy_flow",
                    serde_json::json!({
                        "name": "draft_test"
                    }),
                )
                .await;
            assert!(deploy_result.is_ok(), "Should deploy flow");

            // Step 5: Now run WITHOUT --draft flag (should succeed from database)
            let run_production2 = registry
                .execute(
                    "start_run",
                    serde_json::json!({
                        "flow_name": "draft_test",
                        "event": {"run": 2},
                        "draft": false
                    }),
                )
                .await;
            assert!(
                run_production2.is_ok(),
                "Should run deployed flow from database: {:?}",
                run_production2.err()
            );

            // Step 6: Update draft flow with new content
            let updated_content = r#"name: draft_test
version: "1.1.0"
on: cli.manual
steps:
  - id: step1
    use: core.echo
    with:
      text: "Updated draft version""#;

            registry
                .execute(
                    "save_flow",
                    serde_json::json!({
                        "name": "draft_test",
                        "content": updated_content
                    }),
                )
                .await
                .unwrap();

            // Step 7: Run with --draft should use NEW version (1.1.0)
            let run_draft2 = registry
                .execute(
                    "start_run",
                    serde_json::json!({
                        "flow_name": "draft_test",
                        "event": {"run": 3},
                        "draft": true
                    }),
                )
                .await;
            assert!(
                run_draft2.is_ok(),
                "Should run updated draft from filesystem"
            );

            // Step 8: Run without --draft should still use OLD version (1.0.0)
            let run_production3 = registry
                .execute(
                    "start_run",
                    serde_json::json!({
                        "flow_name": "draft_test",
                        "event": {"run": 4}
                    }),
                )
                .await;
            assert!(
                run_production3.is_ok(),
                "Should run old deployed version from database"
            );
        })
        .await;
}

#[tokio::test]
async fn test_deploy_flow_without_version() {
    use beemflow::core::OperationRegistry;
    use beemflow::utils::TestEnvironment;

    let env = TestEnvironment::new().await;
    let registry = OperationRegistry::new(env.deps);

    let ctx = create_test_context();

    beemflow::core::REQUEST_CONTEXT
        .scope(ctx, async {
            // Save a flow WITHOUT version field
            let flow_content = r#"name: no_version_flow
on: cli.manual
steps:
  - id: step1
    use: core.echo
    with:
      text: "test""#;

            registry
                .execute(
                    "save_flow",
                    serde_json::json!({
                        "name": "no_version_flow",
                        "content": flow_content
                    }),
                )
                .await
                .unwrap();

            // Try to deploy - should fail
            let deploy_result = registry
                .execute(
                    "deploy_flow",
                    serde_json::json!({
                        "name": "no_version_flow"
                    }),
                )
                .await;

            assert!(
                deploy_result.is_err(),
                "Should fail to deploy flow without version"
            );
            let err_msg = format!("{:?}", deploy_result.unwrap_err());
            assert!(
                err_msg.contains("version"),
                "Error should mention missing version"
            );
        })
        .await;
}

#[tokio::test]
async fn test_rollback_workflow() {
    use beemflow::core::OperationRegistry;
    use beemflow::utils::TestEnvironment;

    let env = TestEnvironment::new().await;
    let storage = env.deps.storage.clone();
    let registry = OperationRegistry::new(env.deps);

    let ctx = create_test_context();

    beemflow::core::REQUEST_CONTEXT
        .scope(ctx, async {
            // Deploy version 1.0.0
            let v1_content = r#"name: rollback_flow
version: "1.0.0"
on: cli.manual
steps:
  - id: step1
    use: core.echo
    with:
      text: "Version 1.0.0""#;

            registry
                .execute(
                    "save_flow",
                    serde_json::json!({
                        "name": "rollback_flow",
                        "content": v1_content
                    }),
                )
                .await
                .unwrap();

            registry
                .execute(
                    "deploy_flow",
                    serde_json::json!({
                        "name": "rollback_flow"
                    }),
                )
                .await
                .unwrap();

            // Deploy version 2.0.0
            let v2_content = r#"name: rollback_flow
version: "2.0.0"
on: cli.manual
steps:
  - id: step1
    use: core.echo
    with:
      text: "Version 2.0.0""#;

            registry
                .execute(
                    "save_flow",
                    serde_json::json!({
                        "name": "rollback_flow",
                        "content": v2_content
                    }),
                )
                .await
                .unwrap();

            registry
                .execute(
                    "deploy_flow",
                    serde_json::json!({
                        "name": "rollback_flow"
                    }),
                )
                .await
                .unwrap();

            // Verify version 2.0.0 is deployed
            let version = storage
                .get_deployed_version("test_org", "rollback_flow")
                .await
                .unwrap();
            assert_eq!(version, Some("2.0.0".to_string()));

            // Rollback to version 1.0.0
            let rollback_result = registry
                .execute(
                    "rollback_flow",
                    serde_json::json!({
                        "name": "rollback_flow",
                        "version": "1.0.0"
                    }),
                )
                .await;
            assert!(
                rollback_result.is_ok(),
                "Should rollback successfully: {:?}",
                rollback_result.err()
            );

            // Verify version 1.0.0 is now deployed
            let version_after = storage
                .get_deployed_version("test_org", "rollback_flow")
                .await
                .unwrap();
            assert_eq!(version_after, Some("1.0.0".to_string()));

            // Try to rollback to non-existent version
            let bad_rollback = registry
                .execute(
                    "rollback_flow",
                    serde_json::json!({
                        "name": "rollback_flow",
                        "version": "99.99.99"
                    }),
                )
                .await;
            assert!(
                bad_rollback.is_err(),
                "Should fail to rollback to non-existent version"
            );
        })
        .await;
}

#[tokio::test]
async fn test_disable_enable_flow() {
    use beemflow::core::OperationRegistry;
    use beemflow::utils::TestEnvironment;

    let env = TestEnvironment::new().await;
    let storage = env.deps.storage.clone();
    let registry = OperationRegistry::new(env.deps);

    let ctx = create_test_context();

    beemflow::core::REQUEST_CONTEXT
        .scope(ctx, async {
            // Save and deploy a flow
            let flow_content = r#"name: disable_enable_test
version: "1.0.0"
on: cli.manual
steps:
  - id: step1
    use: core.echo
    with:
      text: "Test""#;

            registry
                .execute(
                    "save_flow",
                    serde_json::json!({
                        "name": "disable_enable_test",
                        "content": flow_content
                    }),
                )
                .await
                .unwrap();

            registry
                .execute(
                    "deploy_flow",
                    serde_json::json!({
                        "name": "disable_enable_test"
                    }),
                )
                .await
                .unwrap();

            // Verify deployed
            let version = storage
                .get_deployed_version("test_org", "disable_enable_test")
                .await
                .unwrap();
            assert_eq!(version, Some("1.0.0".to_string()));

            // Disable the flow
            let disable_result = registry
                .execute(
                    "disable_flow",
                    serde_json::json!({
                        "name": "disable_enable_test"
                    }),
                )
                .await;
            assert!(disable_result.is_ok(), "Should disable successfully");

            // Verify disabled
            let version_after_disable = storage
                .get_deployed_version("test_org", "disable_enable_test")
                .await
                .unwrap();
            assert_eq!(version_after_disable, None, "Should be disabled");

            // Try to disable again (should fail)
            let disable_again = registry
                .execute(
                    "disable_flow",
                    serde_json::json!({
                        "name": "disable_enable_test"
                    }),
                )
                .await;
            assert!(
                disable_again.is_err(),
                "Should fail to disable already disabled flow"
            );

            // Enable the flow
            let enable_result = registry
                .execute(
                    "enable_flow",
                    serde_json::json!({
                        "name": "disable_enable_test"
                    }),
                )
                .await;
            assert!(enable_result.is_ok(), "Should enable successfully");

            // Verify re-enabled with same version
            let version_after_enable = storage
                .get_deployed_version("test_org", "disable_enable_test")
                .await
                .unwrap();
            assert_eq!(
                version_after_enable,
                Some("1.0.0".to_string()),
                "Should restore to v1.0.0"
            );

            // Try to enable again (should fail)
            let enable_again = registry
                .execute(
                    "enable_flow",
                    serde_json::json!({
                        "name": "disable_enable_test"
                    }),
                )
                .await;
            assert!(
                enable_again.is_err(),
                "Should fail to enable already enabled flow"
            );
        })
        .await;
}

#[tokio::test]
async fn test_disable_enable_prevents_rollback() {
    use beemflow::core::OperationRegistry;
    use beemflow::utils::TestEnvironment;

    let env = TestEnvironment::new().await;
    let storage = env.deps.storage.clone();
    let registry = OperationRegistry::new(env.deps);

    let ctx = create_test_context();

    beemflow::core::REQUEST_CONTEXT
        .scope(ctx, async {
            // Deploy v1.0.0
            let v1_content = r#"name: no_rollback_test
version: "1.0.0"
on: cli.manual
steps:
  - id: step1
    use: core.echo
    with:
      text: "Version 1.0.0""#;

            registry
                .execute(
                    "save_flow",
                    serde_json::json!({
                        "name": "no_rollback_test",
                        "content": v1_content
                    }),
                )
                .await
                .unwrap();

            registry
                .execute(
                    "deploy_flow",
                    serde_json::json!({
                        "name": "no_rollback_test"
                    }),
                )
                .await
                .unwrap();

            // Small delay to ensure different timestamps
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

            // Deploy v2.0.0
            let v2_content = r#"name: no_rollback_test
version: "2.0.0"
on: cli.manual
steps:
  - id: step1
    use: core.echo
    with:
      text: "Version 2.0.0""#;

            registry
                .execute(
                    "save_flow",
                    serde_json::json!({
                        "name": "no_rollback_test",
                        "content": v2_content
                    }),
                )
                .await
                .unwrap();

            registry
                .execute(
                    "deploy_flow",
                    serde_json::json!({
                        "name": "no_rollback_test"
                    }),
                )
                .await
                .unwrap();

            // Verify v2.0.0 is deployed
            let version = storage
                .get_deployed_version("test_org", "no_rollback_test")
                .await
                .unwrap();
            assert_eq!(version, Some("2.0.0".to_string()));

            // Disable
            registry
                .execute(
                    "disable_flow",
                    serde_json::json!({
                        "name": "no_rollback_test"
                    }),
                )
                .await
                .unwrap();

            // Enable should restore v2.0.0 (most recent), NOT v1.0.0
            registry
                .execute(
                    "enable_flow",
                    serde_json::json!({
                        "name": "no_rollback_test"
                    }),
                )
                .await
                .unwrap();

            let version_after = storage
                .get_deployed_version("test_org", "no_rollback_test")
                .await
                .unwrap();
            assert_eq!(
                version_after,
                Some("2.0.0".to_string()),
                "Enable should restore most recent version (2.0.0), not oldest (1.0.0)"
            );
        })
        .await;
}

#[tokio::test]
async fn test_disable_draft_still_works() {
    use beemflow::core::OperationRegistry;
    use beemflow::utils::TestEnvironment;

    let env = TestEnvironment::new().await;
    let registry = OperationRegistry::new(env.deps);

    let ctx = create_test_context();

    beemflow::core::REQUEST_CONTEXT
        .scope(ctx, async {
            // Save, deploy, then disable
            let flow_content = r#"name: draft_works_test
version: "1.0.0"
on: cli.manual
steps:
  - id: step1
    use: core.echo
    with:
      text: "Test""#;

            registry
                .execute(
                    "save_flow",
                    serde_json::json!({
                        "name": "draft_works_test",
                        "content": flow_content
                    }),
                )
                .await
                .unwrap();

            registry
                .execute(
                    "deploy_flow",
                    serde_json::json!({
                        "name": "draft_works_test"
                    }),
                )
                .await
                .unwrap();

            registry
                .execute(
                    "disable_flow",
                    serde_json::json!({
                        "name": "draft_works_test"
                    }),
                )
                .await
                .unwrap();

            // Production run should fail
            let run_production = registry
                .execute(
                    "start_run",
                    serde_json::json!({
                        "flow_name": "draft_works_test",
                        "event": {"test": 1},
                        "draft": false
                    }),
                )
                .await;
            assert!(
                run_production.is_err(),
                "Production run should fail when disabled"
            );

            // Draft run should still work
            let run_draft = registry
                .execute(
                    "start_run",
                    serde_json::json!({
                        "flow_name": "draft_works_test",
                        "event": {"test": 2},
                        "draft": true
                    }),
                )
                .await;
            assert!(
                run_draft.is_ok(),
                "Draft run should work even when disabled: {:?}",
                run_draft.err()
            );
        })
        .await;
}

// ============================================================================
// Flow Restore Tests
// ============================================================================

#[tokio::test]
async fn test_restore_deployed_flow() {
    use beemflow::core::OperationRegistry;
    use beemflow::utils::TestEnvironment;

    let env = TestEnvironment::new().await;
    let registry = OperationRegistry::new(env.deps);

    let ctx = create_test_context();

    beemflow::core::REQUEST_CONTEXT
        .scope(ctx, async {
            // Save and deploy a flow
            let flow_content = r#"name: restore_test
version: "1.0.0"
on: cli.manual
steps:
  - id: step1
    use: core.echo
    with:
      text: "Test""#;

            registry
                .execute(
                    "save_flow",
                    serde_json::json!({
                        "name": "restore_test",
                        "content": flow_content
                    }),
                )
                .await
                .unwrap();

            registry
                .execute(
                    "deploy_flow",
                    serde_json::json!({
                        "name": "restore_test"
                    }),
                )
                .await
                .unwrap();

            // Delete draft from filesystem
            registry
                .execute(
                    "delete_flow",
                    serde_json::json!({
                        "name": "restore_test"
                    }),
                )
                .await
                .unwrap();

            // Verify draft is gone
            let get_result = registry
                .execute(
                    "get_flow",
                    serde_json::json!({
                        "name": "restore_test"
                    }),
                )
                .await;
            assert!(get_result.is_err(), "Draft should be deleted");

            // Restore from deployed version
            let restore_result = registry
                .execute(
                    "restore_flow",
                    serde_json::json!({
                        "name": "restore_test"
                    }),
                )
                .await;
            assert!(restore_result.is_ok(), "Should restore successfully");

            // Verify flow is back on filesystem
            let get_again = registry
                .execute(
                    "get_flow",
                    serde_json::json!({
                        "name": "restore_test"
                    }),
                )
                .await;
            assert!(get_again.is_ok(), "Should retrieve restored flow");
        })
        .await;
}

#[tokio::test]
async fn test_restore_disabled_flow() {
    use beemflow::core::OperationRegistry;
    use beemflow::utils::TestEnvironment;

    let env = TestEnvironment::new().await;
    let registry = OperationRegistry::new(env.deps);

    let ctx = create_test_context();

    beemflow::core::REQUEST_CONTEXT
        .scope(ctx, async {
            // Save, deploy, then disable
            let flow_content = r#"name: restore_disabled_test
version: "1.0.0"
on: cli.manual
steps:
  - id: step1
    use: core.echo
    with:
      text: "Test""#;

            registry
                .execute(
                    "save_flow",
                    serde_json::json!({
                        "name": "restore_disabled_test",
                        "content": flow_content
                    }),
                )
                .await
                .unwrap();

            registry
                .execute(
                    "deploy_flow",
                    serde_json::json!({
                        "name": "restore_disabled_test"
                    }),
                )
                .await
                .unwrap();

            registry
                .execute(
                    "disable_flow",
                    serde_json::json!({
                        "name": "restore_disabled_test"
                    }),
                )
                .await
                .unwrap();

            // Delete draft
            registry
                .execute(
                    "delete_flow",
                    serde_json::json!({
                        "name": "restore_disabled_test"
                    }),
                )
                .await
                .unwrap();

            // Restore should get latest from history
            let restore_result = registry
                .execute(
                    "restore_flow",
                    serde_json::json!({
                        "name": "restore_disabled_test"
                    }),
                )
                .await;
            assert!(
                restore_result.is_ok(),
                "Should restore from history even when disabled"
            );
        })
        .await;
}

#[tokio::test]
async fn test_restore_specific_version() {
    use beemflow::core::OperationRegistry;
    use beemflow::utils::TestEnvironment;

    let env = TestEnvironment::new().await;
    let registry = OperationRegistry::new(env.deps);

    let ctx = create_test_context();

    beemflow::core::REQUEST_CONTEXT
        .scope(ctx, async {
            // Deploy v1.0.0
            let v1_content = r#"name: restore_specific_test
version: "1.0.0"
on: cli.manual
steps:
  - id: step1
    use: core.echo
    with:
      text: "Version 1.0.0""#;

            registry
                .execute(
                    "save_flow",
                    serde_json::json!({
                        "name": "restore_specific_test",
                        "content": v1_content
                    }),
                )
                .await
                .unwrap();

            registry
                .execute(
                    "deploy_flow",
                    serde_json::json!({
                        "name": "restore_specific_test"
                    }),
                )
                .await
                .unwrap();

            // Small delay to ensure different timestamps
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

            // Deploy v2.0.0
            let v2_content = r#"name: restore_specific_test
version: "2.0.0"
on: cli.manual
steps:
  - id: step1
    use: core.echo
    with:
      text: "Version 2.0.0""#;

            registry
                .execute(
                    "save_flow",
                    serde_json::json!({
                        "name": "restore_specific_test",
                        "content": v2_content
                    }),
                )
                .await
                .unwrap();

            registry
                .execute(
                    "deploy_flow",
                    serde_json::json!({
                        "name": "restore_specific_test"
                    }),
                )
                .await
                .unwrap();

            // Delete draft
            registry
                .execute(
                    "delete_flow",
                    serde_json::json!({
                        "name": "restore_specific_test"
                    }),
                )
                .await
                .unwrap();

            // Restore specific version 1.0.0
            let restore_result = registry
                .execute(
                    "restore_flow",
                    serde_json::json!({
                        "name": "restore_specific_test",
                        "version": "1.0.0"
                    }),
                )
                .await;
            assert!(
                restore_result.is_ok(),
                "Should restore specific version: {:?}",
                restore_result.err()
            );

            // Verify restored content contains v1.0.0
            let get_result = registry
                .execute(
                    "get_flow",
                    serde_json::json!({
                        "name": "restore_specific_test"
                    }),
                )
                .await
                .unwrap();

            let content = get_result.get("content").unwrap().as_str().unwrap();
            assert!(
                content.contains("Version 1.0.0"),
                "Restored content should be v1.0.0"
            );
        })
        .await;
}

#[tokio::test]
async fn test_restore_nonexistent_flow() {
    use beemflow::core::OperationRegistry;
    use beemflow::utils::TestEnvironment;

    let env = TestEnvironment::new().await;
    let registry = OperationRegistry::new(env.deps);

    let ctx = create_test_context();

    beemflow::core::REQUEST_CONTEXT
        .scope(ctx, async {
            // Try to restore non-existent flow
            let restore_result = registry
                .execute(
                    "restore_flow",
                    serde_json::json!({
                        "name": "nonexistent_flow"
                    }),
                )
                .await;

            assert!(
                restore_result.is_err(),
                "Should fail to restore nonexistent flow"
            );
            let err_msg = format!("{:?}", restore_result.unwrap_err());
            assert!(
                err_msg.contains("deployment") || err_msg.contains("history"),
                "Error should mention deployment/history"
            );
        })
        .await;
}

#[tokio::test]
async fn test_restore_overwrites_draft() {
    use beemflow::core::OperationRegistry;
    use beemflow::utils::TestEnvironment;

    let env = TestEnvironment::new().await;
    let registry = OperationRegistry::new(env.deps);

    let ctx = create_test_context();

    beemflow::core::REQUEST_CONTEXT
        .scope(ctx, async {
            // Save and deploy original flow
            let original_content = r#"name: restore_overwrite_test
version: "1.0.0"
on: cli.manual
steps:
  - id: step1
    use: core.echo
    with:
      text: "Original""#;

            registry
                .execute(
                    "save_flow",
                    serde_json::json!({
                        "name": "restore_overwrite_test",
                        "content": original_content
                    }),
                )
                .await
                .unwrap();

            registry
                .execute(
                    "deploy_flow",
                    serde_json::json!({
                        "name": "restore_overwrite_test"
                    }),
                )
                .await
                .unwrap();

            // Update draft with different content
            let modified_content = r#"name: restore_overwrite_test
version: "1.1.0"
on: cli.manual
steps:
  - id: step1
    use: core.echo
    with:
      text: "Modified""#;

            registry
                .execute(
                    "save_flow",
                    serde_json::json!({
                        "name": "restore_overwrite_test",
                        "content": modified_content
                    }),
                )
                .await
                .unwrap();

            // Restore should overwrite the modified draft
            let restore_result = registry
                .execute(
                    "restore_flow",
                    serde_json::json!({
                        "name": "restore_overwrite_test"
                    }),
                )
                .await;
            assert!(restore_result.is_ok(), "Should restore and overwrite draft");

            // Verify restored content is original
            let get_result = registry
                .execute(
                    "get_flow",
                    serde_json::json!({
                        "name": "restore_overwrite_test"
                    }),
                )
                .await
                .unwrap();

            let content = get_result.get("content").unwrap().as_str().unwrap();
            assert!(
                content.contains("Original") && !content.contains("Modified"),
                "Restored content should be original, not modified"
            );
        })
        .await;
}

// ============================================================================
// Flow File Validation Tests
// ============================================================================

#[test]
fn test_all_flows_parse_and_validate() {
    // Quick parse and validate check for all flow files
    // Actual execution is covered by `make e2e` and `make integration`
    let flow_files = vec![
        // E2E flows
        "flows/e2e/fetch_and_summarize.flow.yaml",
        "flows/e2e/parallel_openai.flow.yaml",
        "flows/e2e/airtable_integration.flow.yaml",
        // Integration flows
        "flows/integration/http_patterns.flow.yaml",
        "flows/integration/nested_parallel.flow.yaml",
        "flows/integration/templating_system.flow.yaml",
        "flows/integration/parallel_execution.flow.yaml",
        "flows/integration/engine_comprehensive.flow.yaml",
        "flows/integration/spec_compliance_test.flow.yaml",
        "flows/integration/edge_cases.flow.yaml",
        // Example flows
        "flows/examples/hello_world.flow.yaml",
        "flows/examples/memory_demo.flow.yaml",
    ];

    let mut failed = vec![];
    for flow_file in &flow_files {
        match parse_file(flow_file, None) {
            Ok(flow) => {
                if let Err(e) = Validator::validate(&flow) {
                    failed.push(format!("{}: validation failed - {}", flow_file, e));
                }
            }
            Err(e) => {
                failed.push(format!("{}: parse failed - {}", flow_file, e));
            }
        }
    }

    if !failed.is_empty() {
        panic!("Flow validation failures:\n{}", failed.join("\n"));
    }
}

// ============================================================================
// Organizational Memory (runs.previous) Tests
// ============================================================================

#[tokio::test]
async fn test_organizational_memory_runs_previous() {
    let yaml = r#"
name: memory_test_flow
on: cli.manual
steps:
  - id: check_previous
    use: core.echo
    with:
      text: |
        {% if runs.previous.id %}
        Previous run: {{ runs.previous.id }}
        Previous message: {{ runs.previous.outputs.save_message.text | default("none") }}
        {% else %}
        This is the first run
        {% endif %}

  - id: save_message
    use: core.echo
    with:
      text: "Run at {{ timestamp }}"
"#;

    let flow = parse_string(yaml, None).unwrap();
    let engine = Engine::for_testing().await;

    // First run - should have no previous data
    // Pass unique event data to ensure different run IDs without sleep
    let mut event1 = HashMap::new();
    event1.insert("run_number".to_string(), serde_json::json!(1));
    let result1 = engine
        .execute(&flow, event1, "test_user", "test_org")
        .await
        .unwrap();
    let outputs1 = result1.outputs;

    assert!(outputs1.contains_key("check_previous"));
    assert!(outputs1.contains_key("save_message"));

    // Verify first run shows "This is the first run"
    let check_output1: HashMap<String, serde_json::Value> =
        serde_json::from_value(outputs1.get("check_previous").unwrap().clone()).unwrap();
    let text1 = check_output1.get("text").unwrap().as_str().unwrap();
    assert!(
        text1.contains("This is the first run"),
        "First run should have no previous data, got: {}",
        text1
    );

    // Second run - should access first run's data via runs.previous
    // Pass different event data to get a different run ID (no sleep needed)
    let mut event2 = HashMap::new();
    event2.insert("run_number".to_string(), serde_json::json!(2));
    let result2 = engine
        .execute(&flow, event2, "test_user", "test_org")
        .await
        .unwrap();
    let outputs2 = result2.outputs;

    let check_output2: HashMap<String, serde_json::Value> =
        serde_json::from_value(outputs2.get("check_previous").unwrap().clone()).unwrap();
    let text2 = check_output2.get("text").unwrap().as_str().unwrap();

    // Verify second run can access first run's data
    assert!(
        text2.contains("Previous run:"),
        "Second run should have previous run data, got: {}",
        text2
    );
    assert!(
        text2.contains(&result1.run_id.to_string()),
        "Second run should show first run's ID"
    );
    assert!(
        text2.contains("Run at"),
        "Second run should access previous run's save_message output"
    );
}
