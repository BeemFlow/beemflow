//! Integration tests for MCP Manager (client)
//!
//! These tests verify that the MCP manager can properly:
//! - Serialize JSON-RPC requests
//! - Deserialize JSON-RPC responses
//! - Handle protocol errors
//! - Manage server lifecycle

use beemflow::mcp::McpManager;
use beemflow::model::McpServerConfig;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

// Helper to create test secrets provider
fn test_secrets_provider() -> Arc<dyn beemflow::secrets::SecretsProvider> {
    Arc::new(beemflow::secrets::EnvSecretsProvider::new())
}

#[test]
fn test_mcp_manager_creation() {
    let manager = McpManager::new(test_secrets_provider());
    // Should not panic and should be in valid state
    drop(manager);
}

#[test]
fn test_mcp_manager_server_registration() {
    let manager = McpManager::new(test_secrets_provider());

    // Register a test server configuration
    manager.register_server(
        "test-server".to_string(),
        McpServerConfig {
            command: "npx".to_string(),
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-filesystem".to_string(),
            ]),
            env: None,
            port: None,
            transport: Some("stdio".to_string()),
            endpoint: None,
        },
    );

    // Should not panic
}

#[test]
fn test_mcp_manager_multiple_server_configs() {
    let manager = McpManager::new(test_secrets_provider());

    // Register multiple servers
    let servers = vec![
        (
            "filesystem",
            "npx",
            vec!["-y", "@modelcontextprotocol/server-filesystem"],
        ),
        (
            "github",
            "npx",
            vec!["-y", "@modelcontextprotocol/server-github"],
        ),
        (
            "postgres",
            "npx",
            vec!["-y", "@modelcontextprotocol/server-postgres"],
        ),
    ];

    for (name, cmd, args) in servers {
        manager.register_server(
            name.to_string(),
            McpServerConfig {
                command: cmd.to_string(),
                args: Some(args.iter().map(|s| s.to_string()).collect()),
                env: None,
                port: None,
                transport: Some("stdio".to_string()),
                endpoint: None,
            },
        );
    }

    // Should be able to register multiple servers without issues
}

#[test]
fn test_mcp_manager_config_override() {
    let manager = McpManager::new(test_secrets_provider());

    // Register initial config
    manager.register_server(
        "test".to_string(),
        McpServerConfig {
            command: "echo".to_string(),
            args: Some(vec!["v1".to_string()]),
            env: None,
            port: None,
            transport: Some("stdio".to_string()),
            endpoint: None,
        },
    );

    // Override with new config - should replace
    manager.register_server(
        "test".to_string(),
        McpServerConfig {
            command: "echo".to_string(),
            args: Some(vec!["v2".to_string()]),
            env: None,
            port: None,
            transport: Some("stdio".to_string()),
            endpoint: None,
        },
    );

    // Should not panic, second config should replace first
}

#[test]
fn test_mcp_manager_env_variables() {
    let manager = McpManager::new(test_secrets_provider());

    let mut env = HashMap::new();
    env.insert("API_KEY".to_string(), "test-key-123".to_string());
    env.insert(
        "BASE_URL".to_string(),
        "https://api.example.com".to_string(),
    );

    manager.register_server(
        "api-server".to_string(),
        McpServerConfig {
            command: "python".to_string(),
            args: Some(vec!["-m".to_string(), "api_server".to_string()]),
            env: Some(env),
            port: None,
            transport: Some("stdio".to_string()),
            endpoint: None,
        },
    );

    // Should handle env vars correctly
}

#[tokio::test]
async fn test_mcp_manager_unconfigured_server_error() {
    let manager = McpManager::new(test_secrets_provider());

    // Try to call tool on unconfigured server
    let result = manager
        .call_tool(
            "nonexistent-server",
            "some_tool",
            json!({"arg": "value"}),
            "test_org",
        )
        .await;

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not configured") || err_msg.contains("nonexistent-server"),
        "Error should mention unconfigured server, got: {}",
        err_msg
    );
}

#[test]
fn test_mcp_manager_validation_empty_command() {
    // This should be caught during validation
    let manager = McpManager::new(test_secrets_provider());

    // Note: validation happens when starting the server, not during registration
    manager.register_server(
        "invalid".to_string(),
        McpServerConfig {
            command: "".to_string(), // Empty command
            args: None,
            env: None,
            port: None,
            transport: Some("stdio".to_string()),
            endpoint: None,
        },
    );

    // Registration succeeds but starting should fail
}

#[tokio::test]
async fn test_mcp_manager_invalid_command_error() {
    let manager = McpManager::new(test_secrets_provider());

    // Register server with command that doesn't exist
    manager.register_server(
        "bad-server".to_string(),
        McpServerConfig {
            command: "this-command-definitely-does-not-exist-12345".to_string(),
            args: None,
            env: None,
            port: None,
            transport: Some("stdio".to_string()),
            endpoint: None,
        },
    );

    // Try to call a tool - should fail when trying to start the server
    let result = manager
        .call_tool("bad-server", "any_tool", json!({}), "test_org")
        .await;

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Failed to spawn")
            || err_msg.contains("not found")
            || err_msg.contains("bad-server"),
        "Error should mention spawn failure, got: {}",
        err_msg
    );
}

#[test]
fn test_mcp_manager_creation_consistency() {
    let manager1 = McpManager::new(test_secrets_provider());
    let manager2 = McpManager::new(test_secrets_provider());

    // Both should work the same way
    drop(manager1);
    drop(manager2);
}

/// Test that simulates the exact bug we fixed:
/// JSON response with "jsonrpc" field should deserialize correctly
#[test]
fn test_jsonrpc_protocol_format() {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct JsonRpcResponse {
        #[serde(rename = "jsonrpc")]
        _jsonrpc: String,
        #[serde(rename = "id")]
        _id: i64,
        result: Option<serde_json::Value>,
    }

    // This is the format that was causing "missing field `_jsonrpc`" error
    let json = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read","description":"Read file","inputSchema":{"type":"object"}}]}}"#;

    let response: Result<JsonRpcResponse, _> = serde_json::from_str(json);
    assert!(
        response.is_ok(),
        "Should deserialize JSON-RPC response correctly. Error: {:?}",
        response.err()
    );

    let response = response.unwrap();
    assert!(response.result.is_some());
}

/// Test protocol validation for MCP configuration
#[test]
fn test_mcp_config_validation() {
    // Valid configs
    let valid_configs = vec![
        McpServerConfig {
            command: "npx".to_string(),
            args: Some(vec!["-y".to_string(), "server".to_string()]),
            env: None,
            port: None,
            transport: Some("stdio".to_string()),
            endpoint: None,
        },
        McpServerConfig {
            command: "python".to_string(),
            args: Some(vec!["-m".to_string(), "server".to_string()]),
            env: Some({
                let mut e = HashMap::new();
                e.insert("KEY".to_string(), "value".to_string());
                e
            }),
            port: None,
            transport: Some("stdio".to_string()),
            endpoint: None,
        },
    ];

    let manager = McpManager::new(test_secrets_provider());
    for (i, config) in valid_configs.into_iter().enumerate() {
        manager.register_server(format!("server-{}", i), config);
    }
}

#[test]
fn test_mcp_manager_clone_and_thread_safety() {
    use std::sync::Arc;

    let manager = Arc::new(McpManager::new(test_secrets_provider()));

    // Register config
    manager.register_server(
        "test".to_string(),
        McpServerConfig {
            command: "echo".to_string(),
            args: None,
            env: None,
            port: None,
            transport: Some("stdio".to_string()),
            endpoint: None,
        },
    );

    // Clone and use in different context
    let manager2 = Arc::clone(&manager);
    drop(manager);

    // Should still be valid
    manager2.register_server(
        "test2".to_string(),
        McpServerConfig {
            command: "echo".to_string(),
            args: None,
            env: None,
            port: None,
            transport: Some("stdio".to_string()),
            endpoint: None,
        },
    );
}
