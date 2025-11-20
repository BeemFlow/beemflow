//! Dependency resolution and circular dependency tests
//!
//! These tests verify:
//! 1. Circular dependencies are detected during validation
//! 2. depends_on is optional
//! 3. Complex dependency graphs validate correctly
//! 4. Invalid dependencies (referencing non-existent steps) are caught

use beemflow::Engine;
use beemflow::dsl::{Validator, parse_file};
use std::collections::HashMap;

/// Helper to create event data with timestamp
fn create_test_event() -> HashMap<String, serde_json::Value> {
    let mut event = HashMap::new();
    event.insert(
        "timestamp".to_string(),
        serde_json::Value::String(chrono::Utc::now().timestamp().to_string()),
    );
    event
}

#[tokio::test]
async fn test_circular_dependency_detected() {
    // Create A → B → A cycle
    let yaml = r#"
name: circular_dependencies_test
on: cli.manual
steps:
  - id: step_a
    use: core.log
    with:
      message: "Step A"
    depends_on:
      - step_b
  - id: step_b
    use: core.log
    with:
      message: "Step B"
    depends_on:
      - step_a
"#;

    let flow = beemflow::dsl::parse_string(yaml, None).expect("Flow should parse");
    let validation_result = Validator::validate(&flow);

    assert!(
        validation_result.is_err(),
        "Circular dependency should be detected during validation"
    );

    let error = validation_result.unwrap_err().to_string();
    assert!(
        error.contains("Circular dependency"),
        "Error message should mention circular dependency, got: {}",
        error
    );
}

#[tokio::test]
async fn test_optional_dependencies() {
    let flow = parse_file("flows/integration/optional_dependencies.flow.yaml", None)
        .expect("Failed to parse optional_dependencies flow");

    // Validation should pass
    assert!(
        Validator::validate(&flow).is_ok(),
        "Flow with optional depends_on should validate successfully"
    );

    // Execution should work
    let engine = Engine::for_testing().await;
    let result = engine
        .execute(&flow, create_test_event(), "test_user", "test_org")
        .await;

    assert!(
        result.is_ok(),
        "Flow with optional depends_on should execute successfully: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_complex_dependencies_diamond_pattern() {
    let flow = parse_file("flows/integration/complex_dependencies.flow.yaml", None)
        .expect("Failed to parse complex_dependencies flow");

    // Validation should pass (no cycles in diamond pattern)
    assert!(
        Validator::validate(&flow).is_ok(),
        "Diamond dependency pattern should validate successfully"
    );

    // Execution should work
    let engine = Engine::for_testing().await;
    let result = engine
        .execute(&flow, create_test_event(), "test_user", "test_org")
        .await;

    assert!(
        result.is_ok(),
        "Diamond dependency pattern should execute: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_dependency_order_current_behavior() {
    // NOTE: This test documents the CURRENT behavior, not the ideal behavior
    // Currently, depends_on is validated but NOT enforced during execution
    // Steps run in YAML file order, not dependency order

    let flow = parse_file("flows/integration/dependency_order.flow.yaml", None)
        .expect("Failed to parse dependency_order flow");

    // Validation should pass
    assert!(
        Validator::validate(&flow).is_ok(),
        "Flow with valid dependencies should validate"
    );

    // Execution works (but steps may run in wrong order - this is current behavior)
    let engine = Engine::for_testing().await;
    let result = engine
        .execute(&flow, create_test_event(), "test_user", "test_org")
        .await;

    assert!(
        result.is_ok(),
        "Flow should execute (even though order may not respect dependencies): {:?}",
        result.err()
    );

    // TODO: When dependency resolution is implemented, add assertions
    // to verify execution order matches dependency order
}

#[tokio::test]
async fn test_invalid_dependency_reference() {
    // Create a flow with a dependency on a non-existent step
    let yaml = r#"
name: invalid_dependency_test
on: cli.manual
steps:
  - id: step1
    use: core.log
    with:
      message: "test"
    depends_on:
      - nonexistent_step
"#;

    let flow = beemflow::dsl::parse_string(yaml, None).expect("Flow should parse");
    let validation_result = Validator::validate(&flow);

    assert!(
        validation_result.is_err(),
        "Dependency on non-existent step should fail validation"
    );

    let error = validation_result.unwrap_err().to_string();
    assert!(
        error.contains("nonexistent_step"),
        "Error should mention the missing step, got: {}",
        error
    );
}

#[tokio::test]
async fn test_self_dependency() {
    // Create a flow where a step depends on itself
    let yaml = r#"
name: self_dependency_test
on: cli.manual
steps:
  - id: step1
    use: core.log
    with:
      message: "test"
    depends_on:
      - step1
"#;

    let flow = beemflow::dsl::parse_string(yaml, None).expect("Flow should parse");
    let validation_result = Validator::validate(&flow);

    assert!(
        validation_result.is_err(),
        "Self-dependency should fail validation (circular)"
    );

    let error = validation_result.unwrap_err().to_string();
    assert!(
        error.contains("Circular dependency"),
        "Error should mention circular dependency, got: {}",
        error
    );
}

#[tokio::test]
async fn test_three_step_circular_dependency() {
    // Create A → B → C → A cycle
    let yaml = r#"
name: three_step_cycle_test
on: cli.manual
steps:
  - id: step_a
    use: core.log
    with:
      message: "A"
    depends_on:
      - step_c
  - id: step_b
    use: core.log
    with:
      message: "B"
    depends_on:
      - step_a
  - id: step_c
    use: core.log
    with:
      message: "C"
    depends_on:
      - step_b
"#;

    let flow = beemflow::dsl::parse_string(yaml, None).expect("Flow should parse");
    let validation_result = Validator::validate(&flow);

    assert!(
        validation_result.is_err(),
        "Three-step circular dependency should be detected"
    );

    let error = validation_result.unwrap_err().to_string();
    assert!(
        error.contains("Circular dependency"),
        "Error should mention circular dependency, got: {}",
        error
    );
}

#[tokio::test]
async fn test_multiple_dependencies() {
    // Test step with multiple valid dependencies
    let yaml = r#"
name: multiple_deps_test
on: cli.manual
steps:
  - id: step1
    use: core.log
    with:
      message: "1"
  - id: step2
    use: core.log
    with:
      message: "2"
  - id: step3
    use: core.log
    with:
      message: "3"
    depends_on:
      - step1
      - step2
"#;

    let flow = beemflow::dsl::parse_string(yaml, None).expect("Flow should parse");

    assert!(
        Validator::validate(&flow).is_ok(),
        "Multiple valid dependencies should validate successfully"
    );
}

#[tokio::test]
async fn test_auto_dependency_detection() {
    // Test automatic dependency detection from template references
    let flow = parse_file(
        "flows/integration/auto_dependency_detection.flow.yaml",
        None,
    )
    .expect("Failed to parse auto_dependency_detection flow");

    // Validation should pass
    assert!(
        Validator::validate(&flow).is_ok(),
        "Flow with auto-detected dependencies should validate"
    );

    // Execute the flow - steps should run in correct order despite YAML order
    let engine = Engine::for_testing().await;
    let result = engine
        .execute(&flow, create_test_event(), "test_user", "test_org")
        .await;

    assert!(
        result.is_ok(),
        "Flow with auto-detected dependencies should execute: {:?}",
        result.err()
    );

    // Verify outputs exist and are correct
    let outputs = result.unwrap();

    assert!(
        outputs.outputs.contains_key("step_a"),
        "step_a should have executed"
    );
    assert!(
        outputs.outputs.contains_key("step_b"),
        "step_b should have executed"
    );
    assert!(
        outputs.outputs.contains_key("step_c"),
        "step_c should have executed"
    );

    // Verify step_c has the expected output (proves execution order was correct)
    if let Some(step_c_output) = outputs.outputs.get("step_c") {
        let text = step_c_output.get("text").and_then(|v| v.as_str());
        assert!(
            text.is_some() && text.unwrap().contains("Hello"),
            "step_c should contain text from step_a"
        );
        assert!(
            text.is_some() && text.unwrap().contains("World"),
            "step_c should contain text from step_b"
        );
    }
}

#[tokio::test]
async fn test_hybrid_dependencies() {
    // Test hybrid dependencies (manual depends_on + auto-detected)
    let flow = parse_file("flows/integration/hybrid_dependencies.flow.yaml", None)
        .expect("Failed to parse hybrid_dependencies flow");

    // Validation should pass
    assert!(
        Validator::validate(&flow).is_ok(),
        "Flow with hybrid dependencies should validate"
    );

    // Execute the flow
    let engine = Engine::for_testing().await;
    let result = engine
        .execute(&flow, create_test_event(), "test_user", "test_org")
        .await;

    assert!(
        result.is_ok(),
        "Flow with hybrid dependencies should execute: {:?}",
        result.err()
    );

    // Verify all steps executed
    let outputs = result.unwrap();
    assert!(
        outputs.outputs.contains_key("setup_step"),
        "setup_step should have executed"
    );
    assert!(
        outputs.outputs.contains_key("config_step"),
        "config_step should have executed"
    );
    assert!(
        outputs.outputs.contains_key("data_step"),
        "data_step should have executed"
    );
    assert!(
        outputs.outputs.contains_key("final_step"),
        "final_step should have executed"
    );
}
