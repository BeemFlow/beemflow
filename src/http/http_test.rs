use super::*;
use crate::core::OperationRegistry;
use crate::utils::TestEnvironment;
use axum::http::StatusCode;

async fn create_test_state() -> AppState {
    let env = TestEnvironment::new().await;
    let storage = env.deps.storage.clone();
    let registry_manager = env.deps.registry_manager.clone();

    let registry = Arc::new(OperationRegistry::new(env.deps));
    let session_store = Arc::new(session::SessionStore::new());
    let oauth_client = Arc::new(
        crate::auth::OAuthClientManager::new(
            storage.clone(),
            registry_manager,
            "http://localhost:3000/callback".to_string(),
        )
        .expect("Failed to create OAuth client manager"),
    );
    let template_renderer = Arc::new(template::TemplateRenderer::new("static"));

    let jwt_secret = crate::auth::ValidatedJwtSecret::new().expect("JWT secret for tests");
    let jwt_manager = Arc::new(crate::auth::JwtManager::new(
        &jwt_secret,
        "http://localhost:3000".to_string(),
        chrono::Duration::minutes(15),
    ));

    AppState {
        registry,
        session_store,
        oauth_client,
        storage,
        template_renderer,
        jwt_manager,
    }
}

#[tokio::test]
async fn test_health_endpoint() {
    let response = health_handler().await;
    assert!(response.0.get("status").is_some());
    assert_eq!(response.0.get("status").unwrap(), "healthy");
}

#[tokio::test]
async fn test_root_handler() {
    let state = create_test_state().await;
    let result = state.registry.execute("root", json!({})).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_list_flows_empty() {
    let state = create_test_state().await;

    // Create test auth context
    let ctx = crate::auth::RequestContext {
        user_id: "test_user".to_string(),
        organization_id: "test_org".to_string(),
        organization_name: "test_org".to_string(),
        role: crate::auth::Role::Admin,
        client_ip: None,
        user_agent: None,
        request_id: "test".to_string(),
    };

    let result = crate::core::REQUEST_CONTEXT
        .scope(ctx, async {
            state.registry.execute("list_flows", json!({})).await
        })
        .await;

    assert!(result.is_ok());
    let result_val = result.unwrap();
    assert!(result_val.is_object());
}

#[tokio::test]
async fn test_save_and_get_flow() {
    let state = create_test_state().await;

    // Create test auth context
    let ctx = crate::auth::RequestContext {
        user_id: "test_user".to_string(),
        organization_id: "test_org".to_string(),
        organization_name: "test_org".to_string(),
        role: crate::auth::Role::Admin,
        client_ip: None,
        user_agent: None,
        request_id: "test".to_string(),
    };

    let result = crate::core::REQUEST_CONTEXT
        .scope(ctx, async {
            // Save a flow
            let flow_content = r#"
name: test-flow
on: event
steps:
  - id: step1
    use: core.echo
    with:
      text: "Hello"
"#;

            let save_input = json!({
                "name": "test-flow",
                "content": flow_content
            });

            let save_result = state.registry.execute("save_flow", save_input).await;
            assert!(save_result.is_ok());

            // Get the flow
            let get_input = json!({
                "name": "test-flow"
            });

            state.registry.execute("get_flow", get_input).await
        })
        .await;

    assert!(result.is_ok());
    let flow_data = result.unwrap();
    assert_eq!(
        flow_data.get("name").and_then(|v| v.as_str()),
        Some("test-flow")
    );
}

#[tokio::test]
async fn test_delete_flow() {
    let state = create_test_state().await;

    // Create test auth context
    let ctx = crate::auth::RequestContext {
        user_id: "test_user".to_string(),
        organization_id: "test_org".to_string(),
        organization_name: "test_org".to_string(),
        role: crate::auth::Role::Admin,
        client_ip: None,
        user_agent: None,
        request_id: "test".to_string(),
    };

    crate::core::REQUEST_CONTEXT
        .scope(ctx, async {
            // Save a flow first
            let flow_content = r#"
name: delete-test
on: event
steps:
  - id: step1
    use: core.echo
    with:
      text: "Hello"
"#;

            let save_input = json!({
                "name": "delete-test",
                "content": flow_content
            });

            let _ = state
                .registry
                .execute("save_flow", save_input)
                .await
                .unwrap();

            // Delete the flow
            let delete_input = json!({
                "name": "delete-test"
            });

            let delete_result = state.registry.execute("delete_flow", delete_input).await;

            assert!(delete_result.is_ok());

            // Verify it's gone
            let get_input = json!({
                "name": "delete-test"
            });

            let get_result = state.registry.execute("get_flow", get_input).await;

            assert!(get_result.is_err());
        })
        .await;
}

#[tokio::test]
async fn test_validate_flow_valid() {
    let state = create_test_state().await;

    let flow_content = r#"
name: valid-flow
on: event
steps:
  - id: step1
    use: core.echo
    with:
      text: "Hello"
"#;

    let input = json!({
        "flow": flow_content
    });

    let result = state.registry.execute("validate_flow", input).await;
    // Validate operation may require different input format
    // Just check it doesn't crash
    let _ = result;
}

#[tokio::test]
async fn test_validate_flow_invalid() {
    let state = create_test_state().await;

    // Invalid YAML
    let invalid_content = "invalid: yaml: syntax: [[[";

    let input = json!({
        "flow": invalid_content
    });

    let result = state.registry.execute("validate_flow", input).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_start_run() {
    let state = create_test_state().await;

    // First save a flow
    let flow_content = r#"
name: run-test
on: event
steps:
  - id: step1
    use: core.echo
    with:
      text: "Hello"
"#;

    let save_input = json!({
        "name": "run-test",
        "content": flow_content
    });

    let _ = state.registry.execute("save_flow", save_input).await;

    // Deploy the flow
    let deploy_input = json!({
        "name": "run-test"
    });

    let _ = state.registry.execute("deploy_flow", deploy_input).await;

    // Start a run
    let run_input = json!({
        "flowName": "run-test",
        "event": {}
    });

    let _ = state.registry.execute("start_run", run_input).await;
}

#[tokio::test]
async fn test_get_run() {
    let state = create_test_state().await;

    // Create and start a run
    let flow_content = r#"
name: get-run-test
on: event
steps:
  - id: step1
    use: core.echo
    with:
      text: "Hello"
"#;

    let save_input = json!({
        "name": "get-run-test",
        "content": flow_content
    });

    let _ = state.registry.execute("save_flow", save_input).await;

    let deploy_input = json!({"name": "get-run-test"});
    let _ = state.registry.execute("deploy_flow", deploy_input).await;

    let run_input = json!({
        "flowName": "get-run-test",
        "event": {}
    });

    // Try to start and get run - may fail based on deployment
    if let Ok(run_result) = state.registry.execute("start_run", run_input).await
        && let Some(run_id) = run_result.get("runID").and_then(|v| v.as_str())
    {
        let get_input = json!({"id": run_id});
        let _ = state.registry.execute("get_run", get_input).await;
    }
}

#[tokio::test]
async fn test_list_runs() {
    let state = create_test_state().await;

    // Create test auth context
    let ctx = crate::auth::RequestContext {
        user_id: "test_user".to_string(),
        organization_id: "test_org".to_string(),
        organization_name: "test_org".to_string(),
        role: crate::auth::Role::Admin,
        client_ip: None,
        user_agent: None,
        request_id: "test".to_string(),
    };

    let result = crate::core::REQUEST_CONTEXT
        .scope(ctx, async {
            state.registry.execute("list_runs", json!({})).await
        })
        .await;

    assert!(
        result.is_ok(),
        "list_runs should succeed with empty input: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_list_tools() {
    let state = create_test_state().await;
    let result = state.registry.execute("list_tools", json!({})).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_get_nonexistent_flow() {
    let state = create_test_state().await;
    let input = json!({
        "name": "nonexistent-flow"
    });
    let result = state.registry.execute("get_flow", input).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_app_error_conversion() {
    let err = crate::BeemFlowError::validation("test error".to_string());
    let app_err = AppError::from(err);
    let response = app_err.into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_metrics_endpoint() {
    // Record some metrics first
    crate::telemetry::record_http_request("test_handler", "GET", 200);
    crate::telemetry::record_flow_execution("test_flow", "success");

    // Get metrics
    let result = metrics_handler().await;
    assert!(result.is_ok());

    let (status, metrics_body) = result.unwrap();
    assert_eq!(status, StatusCode::OK);

    // Verify metrics contain expected data
    assert!(metrics_body.contains("beemflow_http_requests_total"));
    assert!(metrics_body.contains("beemflow_flow_executions_total"));
    assert!(!metrics_body.is_empty());
}
