use super::*;
use crate::adapter::{CoreAdapter, ExecutionContext};
use crate::constants::{CORE_CONVERT_OPENAPI, CORE_ECHO, CORE_LOG, CORE_WAIT, PARAM_SPECIAL_USE};
use crate::storage::SqliteStorage;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

// Helper to create test execution context
async fn test_context() -> ExecutionContext {
    let storage = Arc::new(
        SqliteStorage::new(":memory:")
            .await
            .expect("Failed to create in-memory SQLite storage"),
    );
    let secrets_provider: Arc<dyn crate::secrets::SecretsProvider> =
        Arc::new(crate::secrets::EnvSecretsProvider::new());
    let oauth_client =
        crate::auth::create_test_oauth_client(storage.clone(), secrets_provider.clone());

    ExecutionContext::new(storage, secrets_provider, oauth_client)
}

// ========================================
// BASIC FUNCTIONALITY TESTS
// ========================================

#[tokio::test]
async fn test_core_adapter_id() {
    let adapter = CoreAdapter::new();
    assert_eq!(adapter.id(), "core");
}

#[tokio::test]
async fn test_core_adapter_manifest() {
    let adapter = CoreAdapter::new();
    assert!(adapter.manifest().is_none());
}

#[tokio::test]
async fn test_core_echo_basic() {
    let adapter = CoreAdapter::new();
    let mut inputs = HashMap::new();
    inputs.insert(
        PARAM_SPECIAL_USE.to_string(),
        Value::String(CORE_ECHO.to_string()),
    );
    inputs.insert(
        "text".to_string(),
        Value::String("Hello, World!".to_string()),
    );

    let result = adapter
        .execute(inputs, &test_context().await)
        .await
        .unwrap();
    assert_eq!(
        result.get("text").unwrap().as_str().unwrap(),
        "Hello, World!"
    );
    assert!(!result.contains_key(PARAM_SPECIAL_USE));
}

#[tokio::test]
async fn test_core_echo_complex_object() {
    let adapter = CoreAdapter::new();
    let mut inputs = HashMap::new();
    inputs.insert(
        PARAM_SPECIAL_USE.to_string(),
        Value::String(CORE_ECHO.to_string()),
    );
    inputs.insert(
        "text".to_string(),
        serde_json::json!({"nested": "value", "count": 42}),
    );

    let result = adapter
        .execute(inputs, &test_context().await)
        .await
        .unwrap();
    assert!(result.get("text").unwrap().is_object());
}

#[tokio::test]
async fn test_core_echo_empty_text() {
    let adapter = CoreAdapter::new();
    let mut inputs = HashMap::new();
    inputs.insert(
        PARAM_SPECIAL_USE.to_string(),
        Value::String(CORE_ECHO.to_string()),
    );
    inputs.insert("text".to_string(), Value::String("".to_string()));

    let result = adapter
        .execute(inputs, &test_context().await)
        .await
        .unwrap();
    assert_eq!(result.get("text").unwrap().as_str().unwrap(), "");
}

#[tokio::test]
async fn test_core_echo_nil_text() {
    let adapter = CoreAdapter::new();
    let mut inputs = HashMap::new();
    inputs.insert(
        PARAM_SPECIAL_USE.to_string(),
        Value::String(CORE_ECHO.to_string()),
    );
    inputs.insert("text".to_string(), Value::Null);

    let result = adapter
        .execute(inputs, &test_context().await)
        .await
        .unwrap();
    assert!(result.get("text").unwrap().is_null());
}

#[tokio::test]
async fn test_core_echo_no_text() {
    let adapter = CoreAdapter::new();
    let mut inputs = HashMap::new();
    inputs.insert(
        PARAM_SPECIAL_USE.to_string(),
        Value::String(CORE_ECHO.to_string()),
    );
    inputs.insert("other".to_string(), Value::String("value".to_string()));

    let result = adapter
        .execute(inputs, &test_context().await)
        .await
        .unwrap();
    assert_eq!(result.get("other").unwrap().as_str().unwrap(), "value");
    assert!(!result.contains_key("text"));
}

#[tokio::test]
async fn test_core_echo_non_string_text() {
    let adapter = CoreAdapter::new();
    let mut inputs = HashMap::new();
    inputs.insert(
        PARAM_SPECIAL_USE.to_string(),
        Value::String(CORE_ECHO.to_string()),
    );
    inputs.insert("text".to_string(), Value::Number(123.into()));
    inputs.insert("other".to_string(), Value::String("value".to_string()));

    let result = adapter
        .execute(inputs, &test_context().await)
        .await
        .unwrap();
    assert_eq!(result.get("text").unwrap().as_u64().unwrap(), 123);
}

#[tokio::test]
async fn test_core_echo_only_use_field() {
    let adapter = CoreAdapter::new();
    let mut inputs = HashMap::new();
    inputs.insert(
        PARAM_SPECIAL_USE.to_string(),
        Value::String(CORE_ECHO.to_string()),
    );

    let result = adapter
        .execute(inputs, &test_context().await)
        .await
        .unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn test_core_wait_basic() {
    let adapter = CoreAdapter::new();
    let mut inputs = HashMap::new();
    inputs.insert(
        PARAM_SPECIAL_USE.to_string(),
        Value::String(CORE_WAIT.to_string()),
    );
    inputs.insert("seconds".to_string(), Value::Number(0.into())); // Wait 0 for fast test

    let start = std::time::Instant::now();
    let result = adapter
        .execute(inputs, &test_context().await)
        .await
        .unwrap();
    let _elapsed = start.elapsed();

    assert_eq!(result.get("waited_seconds").unwrap().as_u64().unwrap(), 0);
}

#[tokio::test]
async fn test_core_log_basic() {
    let adapter = CoreAdapter::new();
    let mut inputs = HashMap::new();
    inputs.insert(
        PARAM_SPECIAL_USE.to_string(),
        Value::String(CORE_LOG.to_string()),
    );
    inputs.insert("level".to_string(), Value::String("info".to_string()));
    inputs.insert(
        "message".to_string(),
        Value::String("Test message".to_string()),
    );
    inputs.insert("context".to_string(), serde_json::json!({"key": "value"}));

    let result = adapter
        .execute(inputs, &test_context().await)
        .await
        .unwrap();
    assert_eq!(result.get("level").unwrap().as_str().unwrap(), "info");
    assert_eq!(
        result.get("message").unwrap().as_str().unwrap(),
        "Test message"
    );
    assert!(result.contains_key("context"));
}

// ========================================
// ERROR HANDLING TESTS
// ========================================

#[tokio::test]
async fn test_missing_use_field() {
    let adapter = CoreAdapter::new();
    let mut inputs = HashMap::new();
    inputs.insert("text".to_string(), Value::String("hello".to_string()));

    let result = adapter.execute(inputs, &test_context().await).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("missing __use"));
}

#[tokio::test]
async fn test_empty_use_field() {
    let adapter = CoreAdapter::new();
    let mut inputs = HashMap::new();
    inputs.insert(PARAM_SPECIAL_USE.to_string(), Value::String("".to_string()));
    inputs.insert("text".to_string(), Value::String("hello".to_string()));

    let result = adapter.execute(inputs, &test_context().await).await;
    assert!(result.is_err());
    // The error could be "missing __use" or "unknown core tool: "
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("__use") || err_msg.contains("unknown core tool"));
}

#[tokio::test]
async fn test_invalid_use_type() {
    let adapter = CoreAdapter::new();
    let mut inputs = HashMap::new();
    inputs.insert(PARAM_SPECIAL_USE.to_string(), Value::Number(123.into()));

    let result = adapter.execute(inputs, &test_context().await).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_unknown_tool() {
    let adapter = CoreAdapter::new();
    let mut inputs = HashMap::new();
    inputs.insert(
        PARAM_SPECIAL_USE.to_string(),
        Value::String("core.unknown".to_string()),
    );

    let result = adapter.execute(inputs, &test_context().await).await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("unknown core tool")
    );
}

// ========================================
// REAL EXECUTION TESTS (Integration Style)
// ========================================

#[tokio::test]
async fn test_core_adapter_real_execution() {
    let adapter = CoreAdapter::new();

    type ValidationFn = Box<dyn Fn(&HashMap<String, Value>) -> bool>;

    struct TestCase {
        name: &'static str,
        inputs: HashMap<String, Value>,
        want_err: bool,
        validate: Option<ValidationFn>,
    }

    let test_cases = vec![
        TestCase {
            name: "core.echo with real text",
            inputs: {
                let mut m = HashMap::new();
                m.insert(
                    PARAM_SPECIAL_USE.to_string(),
                    Value::String(CORE_ECHO.to_string()),
                );
                m.insert(
                    "text".to_string(),
                    Value::String("Hello, integration test!".to_string()),
                );
                m
            },
            want_err: false,
            validate: Some(Box::new(|result| {
                result.get("text").and_then(|v| v.as_str()) == Some("Hello, integration test!")
            })),
        },
        TestCase {
            name: "core.echo with complex object",
            inputs: {
                let mut m = HashMap::new();
                m.insert(
                    PARAM_SPECIAL_USE.to_string(),
                    Value::String(CORE_ECHO.to_string()),
                );
                m.insert(
                    "text".to_string(),
                    serde_json::json!({"nested": "value", "count": 42}),
                );
                m
            },
            want_err: false,
            validate: Some(Box::new(|result| {
                result.get("text").map(|v| v.is_object()).unwrap_or(false)
            })),
        },
        TestCase {
            name: "invalid core operation",
            inputs: {
                let mut m = HashMap::new();
                m.insert(
                    PARAM_SPECIAL_USE.to_string(),
                    Value::String("core.nonexistent".to_string()),
                );
                m
            },
            want_err: true,
            validate: None,
        },
    ];

    for test in test_cases {
        let result = adapter.execute(test.inputs, &test_context().await).await;

        if test.want_err {
            assert!(result.is_err(), "Test '{}' should have failed", test.name);
        } else {
            assert!(result.is_ok(), "Test '{}' should have succeeded", test.name);
            if let Some(validate) = test.validate {
                assert!(
                    validate(&result.unwrap()),
                    "Test '{}' validation failed",
                    test.name
                );
            }
        }
    }
}

// ========================================
// OPENAPI CONVERSION TESTS
// ========================================

#[tokio::test]
async fn test_convert_openapi_json_string() {
    let adapter = CoreAdapter::new();
    let openapi_spec = r#"{
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "servers": [{"url": "https://api.test.com"}],
        "paths": {
            "/users": {
                "get": {"summary": "Get users"},
                "post": {"summary": "Create user"}
            }
        }
    }"#;

    let mut inputs = HashMap::new();
    inputs.insert(
        PARAM_SPECIAL_USE.to_string(),
        Value::String(CORE_CONVERT_OPENAPI.to_string()),
    );
    inputs.insert(
        "openapi".to_string(),
        Value::String(openapi_spec.to_string()),
    );
    inputs.insert("api_name".to_string(), Value::String("test".to_string()));
    inputs.insert(
        "base_url".to_string(),
        Value::String("https://custom.com".to_string()),
    );

    let result = adapter
        .execute(inputs, &test_context().await)
        .await
        .unwrap();

    assert_eq!(
        result.get("api_name").and_then(|v| v.as_str()),
        Some("test")
    );
    assert_eq!(
        result.get("base_url").and_then(|v| v.as_str()),
        Some("https://custom.com")
    );
    assert_eq!(result.get("count").and_then(|v| v.as_u64()), Some(2));

    let manifests = result.get("manifests").and_then(|v| v.as_array()).unwrap();
    assert_eq!(manifests.len(), 2);
}

#[tokio::test]
async fn test_convert_openapi_json_object() {
    let adapter = CoreAdapter::new();
    let openapi_spec = serde_json::json!({
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {
            "/test": {
                "get": {"summary": "Test endpoint"}
            }
        }
    });

    let mut inputs = HashMap::new();
    inputs.insert(
        PARAM_SPECIAL_USE.to_string(),
        Value::String(CORE_CONVERT_OPENAPI.to_string()),
    );
    inputs.insert("openapi".to_string(), openapi_spec);

    let result = adapter
        .execute(inputs, &test_context().await)
        .await
        .unwrap();
    assert_eq!(result.get("api_name").and_then(|v| v.as_str()), Some("api"));
}

#[tokio::test]
async fn test_convert_openapi_missing_openapi() {
    let adapter = CoreAdapter::new();
    let mut inputs = HashMap::new();
    inputs.insert(
        PARAM_SPECIAL_USE.to_string(),
        Value::String(CORE_CONVERT_OPENAPI.to_string()),
    );
    inputs.insert("api_name".to_string(), Value::String("test".to_string()));

    let result = adapter.execute(inputs, &test_context().await).await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("missing required field: openapi")
    );
}

#[tokio::test]
async fn test_convert_openapi_invalid_json() {
    let adapter = CoreAdapter::new();
    let mut inputs = HashMap::new();
    inputs.insert(
        PARAM_SPECIAL_USE.to_string(),
        Value::String(CORE_CONVERT_OPENAPI.to_string()),
    );
    inputs.insert(
        "openapi".to_string(),
        Value::String("invalid json{".to_string()),
    );

    let result = adapter.execute(inputs, &test_context().await).await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("invalid OpenAPI JSON")
    );
}

#[tokio::test]
async fn test_convert_openapi_no_paths() {
    let adapter = CoreAdapter::new();
    let mut inputs = HashMap::new();
    inputs.insert(
        PARAM_SPECIAL_USE.to_string(),
        Value::String(CORE_CONVERT_OPENAPI.to_string()),
    );
    inputs.insert(
        "openapi".to_string(),
        Value::String(r#"{"openapi": "3.0.0", "info": {"title": "Test"}}"#.to_string()),
    );

    let result = adapter.execute(inputs, &test_context().await).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("no paths found"));
}

#[tokio::test]
async fn test_convert_openapi_complex_spec() {
    let adapter = CoreAdapter::new();
    let complex_spec = r#"{
        "openapi": "3.0.0",
        "info": {"title": "Complex API", "version": "1.0.0"},
        "paths": {
            "/users/{id}": {
                "get": {
                    "summary": "Get user by ID",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "schema": {"type": "string"},
                            "description": "User ID"
                        },
                        {
                            "name": "include",
                            "in": "query",
                            "schema": {"type": "array", "items": {"type": "string"}},
                            "description": "Fields to include"
                        }
                    ]
                },
                "put": {
                    "summary": "Update user",
                    "requestBody": {
                        "content": {
                            "application/x-www-form-urlencoded": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "email": {"type": "string", "format": "email"}
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/complex-path/with-dashes": {
                "post": {
                    "description": "Complex endpoint with dashes"
                }
            }
        }
    }"#;

    let mut inputs = HashMap::new();
    inputs.insert(
        PARAM_SPECIAL_USE.to_string(),
        Value::String(CORE_CONVERT_OPENAPI.to_string()),
    );
    inputs.insert(
        "openapi".to_string(),
        Value::String(complex_spec.to_string()),
    );
    inputs.insert("api_name".to_string(), Value::String("complex".to_string()));

    let result = adapter
        .execute(inputs, &test_context().await)
        .await
        .unwrap();
    let manifests = result.get("manifests").and_then(|v| v.as_array()).unwrap();
    assert_eq!(manifests.len(), 3);

    // Check tool name generation for path parameters
    let names: Vec<String> = manifests
        .iter()
        .filter_map(|m| {
            m.get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect();

    assert!(names.contains(&"complex.users_by_id_get".to_string()));
    assert!(names.contains(&"complex.users_by_id_put".to_string()));
    assert!(names.contains(&"complex.complex_path_with_dashes_post".to_string()));
}

#[tokio::test]
async fn test_convert_openapi_default_base_url() {
    let adapter = CoreAdapter::new();
    let spec = r#"{
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "servers": [{"url": "https://extracted.com"}],
        "paths": {"/test": {"get": {"summary": "Test"}}}
    }"#;

    let mut inputs = HashMap::new();
    inputs.insert(
        PARAM_SPECIAL_USE.to_string(),
        Value::String(CORE_CONVERT_OPENAPI.to_string()),
    );
    inputs.insert("openapi".to_string(), Value::String(spec.to_string()));

    let result = adapter
        .execute(inputs, &test_context().await)
        .await
        .unwrap();
    assert_eq!(
        result.get("base_url").and_then(|v| v.as_str()),
        Some("https://extracted.com")
    );
}

#[tokio::test]
async fn test_convert_openapi_no_servers() {
    let adapter = CoreAdapter::new();
    let spec = r#"{
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {"/test": {"get": {"summary": "Test"}}}
    }"#;

    let mut inputs = HashMap::new();
    inputs.insert(
        PARAM_SPECIAL_USE.to_string(),
        Value::String(CORE_CONVERT_OPENAPI.to_string()),
    );
    inputs.insert("openapi".to_string(), Value::String(spec.to_string()));

    let result = adapter
        .execute(inputs, &test_context().await)
        .await
        .unwrap();
    assert_eq!(
        result.get("base_url").and_then(|v| v.as_str()),
        Some("https://api.example.com")
    );
}

#[tokio::test]
async fn test_convert_openapi_edge_cases() {
    let adapter = CoreAdapter::new();
    let spec = r#"{
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {
            "/test": {
                "get": {"summary": "Valid method"},
                "invalid": {"summary": "Invalid method"},
                "options": {"summary": "Invalid method"}
            }
        }
    }"#;

    let mut inputs = HashMap::new();
    inputs.insert(
        PARAM_SPECIAL_USE.to_string(),
        Value::String(CORE_CONVERT_OPENAPI.to_string()),
    );
    inputs.insert("openapi".to_string(), Value::String(spec.to_string()));

    let result = adapter
        .execute(inputs, &test_context().await)
        .await
        .unwrap();
    let manifests = result.get("manifests").and_then(|v| v.as_array()).unwrap();
    // Should only have 1 manifest (GET), invalid methods ignored
    assert_eq!(manifests.len(), 1);
}

#[tokio::test]
async fn test_convert_openapi_malformed_paths() {
    let adapter = CoreAdapter::new();
    let spec = r#"{
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {
            "/valid": {
                "get": {"summary": "Valid endpoint"}
            },
            "/invalid-path": "not an object",
            "/invalid-operation": {
                "get": "not an object",
                "post": {"summary": "Valid operation"}
            }
        }
    }"#;

    let mut inputs = HashMap::new();
    inputs.insert(
        PARAM_SPECIAL_USE.to_string(),
        Value::String(CORE_CONVERT_OPENAPI.to_string()),
    );
    inputs.insert("openapi".to_string(), Value::String(spec.to_string()));

    let result = adapter
        .execute(inputs, &test_context().await)
        .await
        .unwrap();
    let manifests = result.get("manifests").and_then(|v| v.as_array()).unwrap();
    // Should only have 2 valid manifests (GET /valid and POST /invalid-operation)
    assert_eq!(manifests.len(), 2);
}

// ========================================
// STRESS TESTS
// ========================================

#[tokio::test]
async fn test_adapter_concurrent_execution() {
    let adapter = std::sync::Arc::new(CoreAdapter::new());
    let mut handles = vec![];

    for i in 0..50 {
        let adapter_clone = adapter.clone();
        let handle = tokio::spawn(async move {
            let mut inputs = HashMap::new();
            inputs.insert(
                PARAM_SPECIAL_USE.to_string(),
                Value::String(CORE_ECHO.to_string()),
            );
            inputs.insert(
                "text".to_string(),
                Value::String(format!("concurrent {}", i)),
            );

            adapter_clone.execute(inputs, &test_context().await).await
        });
        handles.push(handle);
    }

    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }
}

// ========================================
// HELPER FUNCTION TESTS
// ========================================

#[test]
fn test_is_valid_http_method() {
    let adapter = CoreAdapter::new();

    assert!(adapter.is_valid_http_method("get"));
    assert!(adapter.is_valid_http_method("post"));
    assert!(adapter.is_valid_http_method("put"));
    assert!(adapter.is_valid_http_method("patch"));
    assert!(adapter.is_valid_http_method("delete"));
    assert!(adapter.is_valid_http_method("GET")); // case insensitive

    assert!(!adapter.is_valid_http_method("options"));
    assert!(!adapter.is_valid_http_method("head"));
    assert!(!adapter.is_valid_http_method("invalid"));
}

#[test]
fn test_generate_tool_name() {
    let adapter = CoreAdapter::new();

    assert_eq!(
        adapter.generate_tool_name("api", "/users", "get"),
        "api.users_get"
    );
    assert_eq!(
        adapter.generate_tool_name("api", "/users/{id}", "get"),
        "api.users_by_id_get"
    );
    assert_eq!(
        adapter.generate_tool_name("api", "/v1/orders/{orderId}/items", "post"),
        "api.v1_orders_by_id_items_post"
    );
    assert_eq!(
        adapter.generate_tool_name("api", "/complex-path/with-dashes", "get"),
        "api.complex_path_with_dashes_get"
    );
    assert_eq!(
        adapter.generate_tool_name("test", "/{id}/sub/{subId}", "get"),
        "test.by_id_sub_by_id_get"
    );
}

#[test]
fn test_extract_description() {
    let adapter = CoreAdapter::new();

    let operation1 = serde_json::json!({"summary": "Test summary"});
    let operation1_map = operation1.as_object().unwrap();
    assert_eq!(
        adapter.extract_description(operation1_map, "/test"),
        "Test summary"
    );

    let operation2 = serde_json::json!({"description": "Test description"});
    let operation2_map = operation2.as_object().unwrap();
    assert_eq!(
        adapter.extract_description(operation2_map, "/test"),
        "Test description"
    );

    let operation3 = serde_json::json!({});
    let operation3_map = operation3.as_object().unwrap();
    assert_eq!(
        adapter.extract_description(operation3_map, "/test"),
        "API endpoint: /test"
    );
}

//#[test]
//fn test_determine_content_type() {
//    let adapter = CoreAdapter::new();
//
//    let get_op = serde_json::json!({});
//    let get_op_map = get_op.as_object().unwrap();
//    assert_eq!(
//        adapter.determine_content_type(get_op_map, "GET"),
//        CONTENT_TYPE_JSON
//    );
//
//    let form_op = serde_json::json!({
//        "requestBody": {
//            "content": {
//                CONTENT_TYPE_FORM: {}
//            }
//        }
//    });
//    let form_op_map = form_op.as_object().unwrap();
//    assert_eq!(
//        adapter.determine_content_type(form_op_map, "POST"),
//        CONTENT_TYPE_FORM
//    );
//}
//}

#[tokio::test]
async fn test_convert_openapi_path_and_body_params() {
    // Test that path parameters and request body parameters are BOTH included
    let adapter = CoreAdapter::new();
    let spec_with_both = r#"{
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {
            "/accounts/{AccountSid}/messages": {
                "post": {
                    "summary": "Send message",
                    "parameters": [
                        {
                            "name": "AccountSid",
                            "in": "path",
                            "required": true,
                            "schema": {"type": "string"},
                            "description": "Account ID"
                        }
                    ],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "to": {"type": "string"},
                                        "body": {"type": "string"}
                                    },
                                    "required": ["to"]
                                }
                            }
                        }
                    }
                }
            }
        }
    }"#;

    let mut inputs = HashMap::new();
    inputs.insert(
        PARAM_SPECIAL_USE.to_string(),
        Value::String(CORE_CONVERT_OPENAPI.to_string()),
    );
    inputs.insert(
        "openapi".to_string(),
        Value::String(spec_with_both.to_string()),
    );
    inputs.insert("api_name".to_string(), Value::String("test".to_string()));

    let result = adapter
        .execute(inputs, &test_context().await)
        .await
        .unwrap();
    let manifests = result.get("manifests").and_then(|v| v.as_array()).unwrap();
    assert_eq!(manifests.len(), 1);

    let tool = &manifests[0];
    let params = tool.get("parameters").and_then(|v| v.as_object()).unwrap();
    let props = params
        .get("properties")
        .and_then(|v| v.as_object())
        .unwrap();

    // CRITICAL: Must have BOTH path param AND body params
    assert!(
        props.contains_key("AccountSid"),
        "Missing path parameter AccountSid"
    );
    assert!(props.contains_key("to"), "Missing body parameter to");
    assert!(props.contains_key("body"), "Missing body parameter body");

    let required = params.get("required").and_then(|v| v.as_array()).unwrap();
    assert!(
        required.iter().any(|v| v == "AccountSid"),
        "AccountSid not marked as required"
    );
    assert!(
        required.iter().any(|v| v == "to"),
        "to not marked as required"
    );
}
