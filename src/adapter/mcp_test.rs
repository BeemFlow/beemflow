use super::*;
use crate::adapter::ExecutionContext;
use crate::constants::ADAPTER_ID_MCP;
use crate::model::McpServerConfig;
use crate::storage::SqliteStorage;
use std::sync::Arc;

// Helper to create test execution context with organization context
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

    // MCP adapter requires organization_id for per-tenant server isolation
    ExecutionContext::new(
        storage,
        secrets_provider,
        oauth_client,
        Some("test_user".to_string()),
        Some("test_org".to_string()),
    )
}

// Helper to create test secrets provider
fn test_secrets_provider() -> Arc<dyn crate::secrets::SecretsProvider> {
    Arc::new(crate::secrets::EnvSecretsProvider::new())
}

#[test]
fn test_mcp_adapter_creation() {
    let adapter = McpAdapter::new(test_secrets_provider());
    assert_eq!(adapter.id(), ADAPTER_ID_MCP);
}

#[test]
fn test_mcp_adapter_config() {
    let adapter = McpAdapter::new(test_secrets_provider());
    adapter.register_server(
        "test".to_string(),
        McpServerConfig {
            command: "npx".to_string(),
            args: Some(vec!["-y".to_string(), "test-server".to_string()]),
            env: None,
            port: None,
            transport: Some("stdio".to_string()),
            endpoint: None,
        },
    );
    // Config is now internal to manager - just verify registration doesn't panic
}

#[test]
fn test_mcp_adapter_manifest() {
    let adapter = McpAdapter::new(test_secrets_provider());
    assert!(
        adapter.manifest().is_none(),
        "MCP adapter should not have manifest"
    );
}

#[tokio::test]
async fn test_mcp_adapter_missing_use() {
    let adapter = McpAdapter::new(test_secrets_provider());
    let inputs = {
        let mut m = HashMap::new();
        m.insert("test".to_string(), Value::String("value".to_string()));
        m
    };

    let result = adapter.execute(inputs, &test_context().await).await;
    assert!(result.is_err(), "Should error when __use is missing");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("missing __use") || err_msg.contains("__use"),
        "Error should mention missing __use"
    );
}

#[tokio::test]
async fn test_mcp_adapter_invalid_use_type() {
    let adapter = McpAdapter::new(test_secrets_provider());
    let inputs = {
        let mut m = HashMap::new();
        m.insert("__use".to_string(), Value::Number(123.into()));
        m
    };

    let result = adapter.execute(inputs, &test_context().await).await;
    assert!(result.is_err(), "Should error when __use is not a string");
}

#[tokio::test]
async fn test_mcp_adapter_invalid_format() {
    let adapter = McpAdapter::new(test_secrets_provider());

    let test_cases = vec![
        "invalid://format",
        "mcp://",
        "mcp://host",
        "mcp://host/",
        "mcp:///tool",
        "mcp://host/tool/extra",
    ];

    for test_case in test_cases {
        let inputs = {
            let mut m = HashMap::new();
            m.insert("__use".to_string(), Value::String(test_case.to_string()));
            m
        };

        let result = adapter.execute(inputs, &test_context().await).await;
        assert!(
            result.is_err(),
            "Should error for invalid format: {}",
            test_case
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("invalid mcp://") || err_msg.contains("format"),
            "Error should mention invalid format for {}",
            test_case
        );
    }
}

#[tokio::test]
async fn test_mcp_adapter_unconfigured_server() {
    let adapter = McpAdapter::new(test_secrets_provider());
    let inputs = {
        let mut m = HashMap::new();
        m.insert(
            "__use".to_string(),
            Value::String("mcp://unconfigured_server/tool".to_string()),
        );
        m
    };

    let result = adapter.execute(inputs, &test_context().await).await;
    assert!(result.is_err(), "Should error for unconfigured server");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not configured") || err_msg.contains("unconfigured"),
        "Error should mention server not configured"
    );
}

#[tokio::test]
async fn test_mcp_adapter_multiple_server_configs() {
    let adapter = McpAdapter::new(test_secrets_provider());

    // Register multiple servers
    adapter.register_server(
        "server1".to_string(),
        McpServerConfig {
            command: "npx".to_string(),
            args: Some(vec!["-y".to_string(), "server1-mcp".to_string()]),
            env: None,
            port: None,
            transport: Some("stdio".to_string()),
            endpoint: None,
        },
    );

    adapter.register_server(
        "server2".to_string(),
        McpServerConfig {
            command: "npx".to_string(),
            args: Some(vec!["-y".to_string(), "server2-mcp".to_string()]),
            env: None,
            port: None,
            transport: Some("stdio".to_string()),
            endpoint: None,
        },
    );

    adapter.register_server(
        "server3".to_string(),
        McpServerConfig {
            command: "python3".to_string(),
            args: Some(vec!["-m".to_string(), "server3".to_string()]),
            env: Some({
                let mut e = HashMap::new();
                e.insert("API_KEY".to_string(), "test_key".to_string());
                e
            }),
            port: None,
            transport: Some("stdio".to_string()),
            endpoint: None,
        },
    );
    // Config tracking is now internal to manager - just verify no panics
}

#[tokio::test]
async fn test_mcp_adapter_config_override() {
    let adapter = McpAdapter::new(test_secrets_provider());

    // Register server
    adapter.register_server(
        "test".to_string(),
        McpServerConfig {
            command: "npx".to_string(),
            args: Some(vec!["-y".to_string(), "old-server".to_string()]),
            env: None,
            port: None,
            transport: Some("stdio".to_string()),
            endpoint: None,
        },
    );

    // Override with new config
    adapter.register_server(
        "test".to_string(),
        McpServerConfig {
            command: "npx".to_string(),
            args: Some(vec!["-y".to_string(), "new-server".to_string()]),
            env: None,
            port: None,
            transport: Some("stdio".to_string()),
            endpoint: None,
        },
    );
    // Config management is now internal to manager - just verify no panics
}
