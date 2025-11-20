use super::*;
use crate::model::{Flow, Step, Trigger};
use std::collections::HashMap;

#[tokio::test]
async fn test_engine_creation() {
    let engine = Engine::for_testing().await;
    let adapters = engine.adapters.all();
    assert!(!adapters.is_empty());

    // Print all registered adapters for debugging
    for adapter in adapters {
        println!("Registered adapter: {}", adapter.id());
    }
}

#[test]
fn test_default_registry_loading() {
    // Test that we can parse the embedded JSON
    let data = include_str!("../registry/default.json");
    let entries: Vec<crate::registry::RegistryEntry> = serde_json::from_str(data).unwrap();

    println!("Total entries: {}", entries.len());

    let tools: Vec<_> = entries.iter().filter(|e| e.entry_type == "tool").collect();

    println!("Total tools: {}", tools.len());

    // Find http.fetch
    let http_fetch = entries.iter().find(|e| e.name == "http.fetch");
    assert!(http_fetch.is_some(), "http.fetch not found in registry");
    println!("Found http.fetch: {:?}", http_fetch.unwrap().name);
}

#[tokio::test]
async fn test_adapter_registration() {
    let secrets_provider: Arc<dyn crate::secrets::SecretsProvider> =
        Arc::new(crate::secrets::EnvSecretsProvider::new());

    // Create registry manager for testing
    let registry_manager = Arc::new(crate::registry::RegistryManager::standard(
        None,
        secrets_provider.clone(),
    ));

    let adapters = Arc::new(AdapterRegistry::new(registry_manager));
    let mcp_adapter = Arc::new(crate::adapter::McpAdapter::new(secrets_provider.clone()));
    Engine::load_default_registry_tools(&adapters, &mcp_adapter, &secrets_provider).await;

    // Print all registered
    let all = adapters.all();
    println!("Total registered adapters: {}", all.len());
    for adapter in all.iter().take(15) {
        println!("  - {}", adapter.id());
    }

    // Check that http.fetch was registered
    let http_fetch = adapters.get_or_load("http.fetch").await;
    assert!(http_fetch.is_some(), "http.fetch should be registered");
    println!("\n✓ http.fetch is registered!");

    // Check for other common tools
    assert!(
        adapters
            .get_or_load("openai.chat_completion")
            .await
            .is_some()
    );
    assert!(
        adapters
            .get_or_load("google_sheets.values.get")
            .await
            .is_some()
    );
    println!("✓ openai.chat_completion is registered!");
    println!("✓ google_sheets.values.get is registered!");
}

#[tokio::test]
async fn test_execute_minimal_valid_flow() {
    let engine = Engine::for_testing().await;
    let flow = Flow {
        name: "test".to_string().into(),
        description: None,
        version: None,
        on: Trigger::Single("cli.manual".to_string()),
        cron: None,
        vars: None,
        steps: vec![Step {
            id: "s1".to_string().into(),
            use_: Some("core.echo".to_string()),
            with: Some({
                let mut m = HashMap::new();
                m.insert("text".to_string(), serde_json::json!("hello"));
                m
            }),
            ..Default::default()
        }],
        catch: None,
    };

    let result = engine
        .execute(&flow, HashMap::new(), "test_user", "test_org")
        .await;
    assert!(
        result.is_ok(),
        "Minimal valid flow should execute successfully"
    );
}

#[tokio::test]
async fn test_execute_empty_steps() {
    let engine = Engine::for_testing().await;
    let flow = Flow {
        name: "empty".to_string().into(),
        description: None,
        version: None,
        on: Trigger::Single("cli.manual".to_string()),
        cron: None,
        vars: None,
        steps: vec![],
        catch: None,
    };

    let result = engine
        .execute(&flow, HashMap::new(), "test_user", "test_org")
        .await;
    assert!(result.is_ok(), "Flow with empty steps should succeed");
    assert_eq!(
        result.unwrap().outputs.len(),
        0,
        "Should return empty outputs"
    );
}

#[tokio::test]
async fn test_execute_with_event_data() {
    let engine = Engine::for_testing().await;
    let flow = Flow {
        name: "event_test".to_string().into(),
        description: None,
        version: None,
        on: Trigger::Single("cli.manual".to_string()),
        cron: None,
        vars: None,
        steps: vec![Step {
            id: "echo_event".to_string().into(),
            use_: Some("core.echo".to_string()),
            with: Some({
                let mut m = HashMap::new();
                m.insert(
                    "text".to_string(),
                    serde_json::json!("Event: {{ event.name }}"),
                );
                m
            }),
            ..Default::default()
        }],
        catch: None,
    };

    let mut event = HashMap::new();
    event.insert("name".to_string(), serde_json::json!("TestEvent"));

    let result = engine
        .execute(&flow, event, "test_user", "test_org")
        .await;
    assert!(result.is_ok(), "Flow with event data should succeed");
}

#[tokio::test]
async fn test_execute_with_vars() {
    let engine = Engine::for_testing().await;
    let flow = Flow {
        name: "vars_test".to_string().into(),
        description: None,
        version: None,
        on: Trigger::Single("cli.manual".to_string()),
        cron: None,
        vars: Some({
            let mut m = HashMap::new();
            m.insert("greeting".to_string(), serde_json::json!("Hello"));
            m.insert("name".to_string(), serde_json::json!("World"));
            m
        }),
        steps: vec![Step {
            id: "echo_vars".to_string().into(),
            use_: Some("core.echo".to_string()),
            with: Some({
                let mut m = HashMap::new();
                m.insert(
                    "text".to_string(),
                    serde_json::json!("{{ vars.greeting }} {{ vars.name }}"),
                );
                m
            }),
            ..Default::default()
        }],
        catch: None,
    };

    let result = engine
        .execute(&flow, HashMap::new(), "test_user", "test_org")
        .await;
    assert!(result.is_ok(), "Flow with vars should succeed");

    let outputs = result.unwrap();
    let echo_output = outputs.outputs.get("echo_vars").unwrap();
    let text = echo_output.get("text").unwrap().as_str().unwrap();
    assert_eq!(text, "Hello World", "Vars should be templated correctly");
}

#[tokio::test]
async fn test_execute_step_output_chaining() {
    let engine = Engine::for_testing().await;
    let flow = Flow {
        name: "chaining_test".to_string().into(),
        description: None,
        version: None,
        on: Trigger::Single("cli.manual".to_string()),
        cron: None,
        vars: None,
        steps: vec![
            Step {
                id: "step1".to_string().into(),
                use_: Some("core.echo".to_string()),
                with: Some({
                    let mut m = HashMap::new();
                    m.insert("text".to_string(), serde_json::json!("first output"));
                    m
                }),
                ..Default::default()
            },
            Step {
                id: "step2".to_string().into(),
                use_: Some("core.echo".to_string()),
                with: Some({
                    let mut m = HashMap::new();
                    m.insert(
                        "text".to_string(),
                        serde_json::json!("Second: {{ step1.text }}"),
                    );
                    m
                }),
                ..Default::default()
            },
        ],
        catch: None,
    };

    let result = engine
        .execute(&flow, HashMap::new(), "test_user", "test_org")
        .await;
    assert!(result.is_ok(), "Output chaining should work");

    let outputs = result.unwrap();
    let step2_output = outputs.outputs.get("step2").unwrap();
    let text = step2_output.get("text").unwrap().as_str().unwrap();
    assert_eq!(
        text, "Second: first output",
        "Output chaining should template correctly"
    );
}

#[tokio::test]
async fn test_execute_concurrent_flows() {
    let engine = Arc::new(Engine::for_testing().await);
    let flow = Arc::new(Flow {
        name: "concurrent".to_string().into(),
        description: None,
        version: None,
        on: Trigger::Single("cli.manual".to_string()),
        cron: None,
        vars: None,
        steps: vec![Step {
            id: "s1".to_string().into(),
            use_: Some("core.echo".to_string()),
            with: Some({
                let mut m = HashMap::new();
                m.insert("text".to_string(), serde_json::json!("concurrent"));
                m
            }),
            ..Default::default()
        }],
        catch: None,
    });

    // Spawn 5 concurrent executions
    let mut handles = vec![];
    for i in 0..5 {
        let engine_clone = engine.clone();
        let flow_clone = flow.clone();
        let handle = tokio::spawn(async move {
            let mut event = HashMap::new();
            event.insert("index".to_string(), serde_json::json!(i));
            engine_clone
                .execute(&flow_clone, event, "test_user", "test_org")
                .await
        });
        handles.push(handle);
    }

    // Wait for all to complete
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok(), "Concurrent execution should succeed");
    }
}

#[tokio::test]
async fn test_execute_catch_block() {
    let engine = Engine::for_testing().await;
    let flow = Flow {
        name: "catch_test".to_string().into(),
        description: None,
        version: None,
        on: Trigger::Single("cli.manual".to_string()),
        cron: None,
        vars: None,
        steps: vec![Step {
            id: "fail".to_string().into(),
            use_: Some("nonexistent.adapter".to_string()),
            with: None,
            ..Default::default()
        }],
        catch: Some(vec![
            Step {
                id: "catch1".to_string().into(),
                use_: Some("core.echo".to_string()),
                with: Some({
                    let mut m = HashMap::new();
                    m.insert("text".to_string(), serde_json::json!("caught!"));
                    m
                }),
                ..Default::default()
            },
            Step {
                id: "catch2".to_string().into(),
                use_: Some("core.echo".to_string()),
                with: Some({
                    let mut m = HashMap::new();
                    m.insert("text".to_string(), serde_json::json!("second!"));
                    m
                }),
                ..Default::default()
            },
        ]),
    };

    let result = engine
        .execute(&flow, HashMap::new(), "test_user", "test_org")
        .await;
    // Should error (fail step) but catch blocks should run
    assert!(result.is_err(), "Should error from fail step");

    // Verify catch block outputs are stored in the run
    let storage = engine.storage();
    let runs = storage
        .list_runs("test_org", 1000, 0)
        .await
        .expect("Failed to list runs");

    // Find the catch_test run
    let catch_run = runs
        .iter()
        .find(|r| r.flow_name.as_str() == "catch_test")
        .expect("Should have a catch_test run");

    // Fetch steps separately (they're in a separate table)
    let steps = storage
        .get_steps(catch_run.id)
        .await
        .expect("Failed to get steps");

    // Verify catch blocks were executed and recorded
    assert_eq!(steps.len(), 2, "Should have 2 catch block step records");

    // Verify catch1 step
    let catch1 = &steps
        .iter()
        .find(|s| s.step_name.as_str() == "catch1")
        .expect("Should have catch1 step record");
    assert_eq!(
        catch1.status,
        crate::model::StepStatus::Succeeded,
        "catch1 should succeed"
    );
    assert!(catch1.outputs.is_some(), "catch1 should have outputs");
    let catch1_outputs = catch1.outputs.as_ref().unwrap();
    assert_eq!(
        catch1_outputs.get("text").and_then(|v| v.as_str()),
        Some("caught!"),
        "catch1 output should contain 'caught!'"
    );

    // Verify catch2 step
    let catch2 = &steps
        .iter()
        .find(|s| s.step_name.as_str() == "catch2")
        .expect("Should have catch2 step record");
    assert_eq!(
        catch2.status,
        crate::model::StepStatus::Succeeded,
        "catch2 should succeed"
    );
    assert!(catch2.outputs.is_some(), "catch2 should have outputs");
    let catch2_outputs = catch2.outputs.as_ref().unwrap();
    assert_eq!(
        catch2_outputs.get("text").and_then(|v| v.as_str()),
        Some("second!"),
        "catch2 output should contain 'second!'"
    );
}

#[tokio::test]
async fn test_execute_secrets_injection() {
    let engine = Engine::for_testing().await;
    let flow = Flow {
        name: "secrets_test".to_string().into(),
        description: None,
        version: None,
        on: Trigger::Single("cli.manual".to_string()),
        cron: None,
        vars: None,
        steps: vec![Step {
            id: "s1".to_string().into(),
            use_: Some("core.echo".to_string()),
            with: Some({
                let mut m = HashMap::new();
                m.insert(
                    "text".to_string(),
                    serde_json::json!("{{ secrets.MY_SECRET }}"),
                );
                m
            }),
            ..Default::default()
        }],
        catch: None,
    };

    let mut event = HashMap::new();
    event.insert(
        "secrets".to_string(),
        serde_json::json!({
            "MY_SECRET": "shhh"
        }),
    );

    let result = engine
        .execute(&flow, event, "test_user", "test_org")
        .await;
    assert!(result.is_ok(), "Secrets injection should work");

    let outputs = result.unwrap();
    let s1_output = outputs.outputs.get("s1").unwrap();
    let text = s1_output.get("text").unwrap().as_str().unwrap();
    assert_eq!(text, "shhh", "Secret should be injected");
}

#[tokio::test]
async fn test_execute_secrets_dot_access() {
    let engine = Engine::for_testing().await;
    let flow = Flow {
        name: "secrets_dot".to_string().into(),
        description: None,
        version: None,
        on: Trigger::Single("cli.manual".to_string()),
        cron: None,
        vars: None,
        steps: vec![Step {
            id: "s1".to_string().into(),
            use_: Some("core.echo".to_string()),
            with: Some({
                let mut m = HashMap::new();
                m.insert(
                    "text".to_string(),
                    serde_json::json!("Secret: {{ secrets.API_KEY }}"),
                );
                m
            }),
            ..Default::default()
        }],
        catch: None,
    };

    let mut event = HashMap::new();
    event.insert(
        "secrets".to_string(),
        serde_json::json!({
            "API_KEY": "secret123"
        }),
    );

    let result = engine
        .execute(&flow, event, "test_user", "test_org")
        .await;
    assert!(result.is_ok(), "Secrets dot access should work");

    let outputs = result.unwrap();
    let text = outputs
        .outputs
        .get("s1")
        .unwrap()
        .get("text")
        .unwrap()
        .as_str()
        .unwrap();
    assert_eq!(
        text, "Secret: secret123",
        "Secret should be accessible via dot notation"
    );
}

#[tokio::test]
async fn test_execute_array_access_in_template() {
    let engine = Engine::for_testing().await;
    let flow = Flow {
        name: "array_access".to_string().into(),
        description: None,
        version: None,
        on: Trigger::Single("cli.manual".to_string()),
        cron: None,
        vars: None,
        steps: vec![Step {
            id: "s1".to_string().into(),
            use_: Some("core.echo".to_string()),
            with: Some({
                let mut m = HashMap::new();
                m.insert(
                    "text".to_string(),
                    serde_json::json!(
                        "First: {{ event.arr[0].val }}, Second: {{ event.arr[1].val }}"
                    ),
                );
                m
            }),
            ..Default::default()
        }],
        catch: None,
    };

    let mut event = HashMap::new();
    event.insert(
        "arr".to_string(),
        serde_json::json!([
            {"val": "a"},
            {"val": "b"}
        ]),
    );

    let result = engine
        .execute(&flow, event, "test_user", "test_org")
        .await;
    assert!(result.is_ok(), "Array access should work");

    let outputs = result.unwrap();
    let text = outputs
        .outputs
        .get("s1")
        .unwrap()
        .get("text")
        .unwrap()
        .as_str()
        .unwrap();
    assert_eq!(
        text, "First: a, Second: b",
        "Array access should work correctly"
    );
}

#[tokio::test]
async fn test_adapter_error_propagation() {
    let engine = Engine::for_testing().await;
    let flow = Flow {
        name: "adapter_error".to_string().into(),
        description: None,
        version: None,
        on: Trigger::Single("cli.manual".to_string()),
        cron: None,
        vars: None,
        steps: vec![Step {
            id: "s1".to_string().into(),
            use_: Some("core.echo".to_string()),
            with: Some(HashMap::new()), // Empty with - should not error
            ..Default::default()
        }],
        catch: None,
    };

    let result = engine
        .execute(&flow, HashMap::new(), "test_user", "test_org")
        .await;
    assert!(result.is_ok(), "Should not error with empty with map");

    let outputs = result.unwrap();
    assert!(outputs.outputs.contains_key("s1"), "Should have s1 output");
}

#[tokio::test]
async fn test_generate_deterministic_run_id() {
    let engine = Engine::for_testing().await;
    let flow_name = "test-flow";
    let event: HashMap<String, serde_json::Value> = {
        let mut m = HashMap::new();
        m.insert("key1".to_string(), serde_json::json!("value1"));
        m.insert("key2".to_string(), serde_json::json!(42));
        m.insert("key3".to_string(), serde_json::json!(true));
        m
    };

    // Same inputs should generate same UUID
    let id1 = engine.generate_deterministic_run_id(flow_name, &event);
    let id2 = engine.generate_deterministic_run_id(flow_name, &event);
    assert_eq!(id1, id2, "Same inputs should generate same UUID");

    // Different event values should generate different UUID
    let event2: HashMap<String, serde_json::Value> = {
        let mut m = HashMap::new();
        m.insert("key1".to_string(), serde_json::json!("value1"));
        m.insert("key2".to_string(), serde_json::json!(43)); // Different value
        m.insert("key3".to_string(), serde_json::json!(true));
        m
    };
    let id3 = engine.generate_deterministic_run_id(flow_name, &event2);
    assert_ne!(
        id1, id3,
        "Different event values should generate different UUID"
    );

    // Different flow name should generate different UUID
    let id4 = engine.generate_deterministic_run_id("different-flow", &event);
    assert_ne!(
        id1, id4,
        "Different flow name should generate different UUID"
    );

    // Key order shouldn't matter (keys are sorted)
    let event_reordered: HashMap<String, serde_json::Value> = {
        let mut m = HashMap::new();
        m.insert("key3".to_string(), serde_json::json!(true));
        m.insert("key1".to_string(), serde_json::json!("value1"));
        m.insert("key2".to_string(), serde_json::json!(42));
        m
    };
    let id5 = engine.generate_deterministic_run_id(flow_name, &event_reordered);
    assert_eq!(id1, id5, "Key order should not affect UUID");

    // Verify it's a valid UUID v5
    assert_eq!(id1.get_version_num(), 5, "Should be UUID v5");

    // Empty event should still work
    let empty_event: HashMap<String, serde_json::Value> = HashMap::new();
    let id_empty = engine.generate_deterministic_run_id(flow_name, &empty_event);
    assert_ne!(
        id_empty,
        Uuid::nil(),
        "Empty event should not generate nil UUID"
    );

    // Complex nested structures
    let complex_event: HashMap<String, serde_json::Value> = {
        let mut m = HashMap::new();
        m.insert("nested".to_string(), serde_json::json!({"deep": "value"}));
        m.insert("array".to_string(), serde_json::json!([1, 2, 3]));
        m
    };
    let id_complex1 = engine.generate_deterministic_run_id(flow_name, &complex_event);
    let id_complex2 = engine.generate_deterministic_run_id(flow_name, &complex_event);
    assert_eq!(
        id_complex1, id_complex2,
        "Complex event should be deterministic"
    );
}

#[tokio::test]
async fn test_generate_deterministic_run_id_time_window() {
    let engine = Engine::for_testing().await;
    // Verify that UUIDs within the same 30-second window are identical
    let flow_name = "test-flow";
    let event: HashMap<String, serde_json::Value> = {
        let mut m = HashMap::new();
        m.insert("key".to_string(), serde_json::json!("value"));
        m
    };

    let id1 = engine.generate_deterministic_run_id(flow_name, &event);

    // Sleep a tiny bit
    std::thread::sleep(std::time::Duration::from_millis(5));

    let id2 = engine.generate_deterministic_run_id(flow_name, &event);

    // Should still be the same (within 30-second window)
    assert_eq!(
        id1, id2,
        "UUIDs within same 30-second window should be identical"
    );
}

#[tokio::test]
async fn test_await_event_resume_roundtrip() {
    use crate::dsl::parse_string;

    // Load the await_resume_demo flow
    let flow_content = std::fs::read_to_string("flows/examples/await_resume_demo.flow.yaml")
        .expect("Failed to read await_resume_demo.flow.yaml");

    let flow = parse_string(&flow_content, None).expect("Failed to parse flow");

    // Create engine with default settings
    let engine = Arc::new(Engine::for_testing().await);

    // Start the flow with input
    let mut start_event = HashMap::new();
    start_event.insert("input".to_string(), serde_json::json!("hello world"));

    // Execute should pause at await_event
    let result = engine
        .execute(&flow, start_event, "test_user", "test_org")
        .await;

    // Should error with "waiting for event" message
    assert!(result.is_err(), "Should error/pause at await_event");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("waiting for event"),
        "Error should indicate waiting state, got: {}",
        err_msg
    );

    // Verify the paused run was stored in database
    let storage = engine.storage();
    let paused_runs = storage
        .load_paused_runs()
        .await
        .expect("Should load paused runs");
    assert_eq!(paused_runs.len(), 1, "Should have one paused run");

    // Get the auto-generated token
    let token = paused_runs.keys().next().unwrap();
    assert!(
        token.ends_with("-step-1"),
        "Token should be auto-generated with step-1, got: {}",
        token
    );

    // Verify we can query by source (webhook architecture)
    // The flow uses source: test (not webhook.test)
    let source_runs = storage
        .find_paused_runs_by_source("test")
        .await
        .expect("Should query by source");
    assert_eq!(source_runs.len(), 1, "Should find paused run by source");
    assert!(
        source_runs[0].0.ends_with("-step-1"),
        "Token from source query should be auto-generated"
    );

    // Simulate resume by calling engine.resume() directly
    let mut resume_event = HashMap::new();
    resume_event.insert("resume_value".to_string(), serde_json::json!("it worked!"));

    // Call resume directly with auto-generated token from database
    let resume_result = engine.resume(token, resume_event.clone()).await;
    assert!(resume_result.is_ok(), "Resume should succeed");

    // Verify the paused run was deleted after resume
    let paused_after = storage
        .load_paused_runs()
        .await
        .expect("Should load paused runs");
    assert_eq!(
        paused_after.len(),
        0,
        "Paused run should be removed after resume"
    );

    // Verify source query returns empty after resume
    let source_after = storage
        .find_paused_runs_by_source("test")
        .await
        .expect("Should query by source");
    assert_eq!(
        source_after.len(),
        0,
        "Source query should be empty after resume"
    );
}
