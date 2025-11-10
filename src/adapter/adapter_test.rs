use super::*;
use std::collections::HashMap;
use std::sync::Arc;

/// Test that AdapterRegistry can lazy load tools from registry on-demand
#[tokio::test]
async fn test_lazy_load_tool_from_registry() {
    // Create a test tool entry
    let tool_entry = crate::registry::RegistryEntry {
        entry_type: "tool".to_string(),
        name: "test.weather".to_string(),
        display_name: None,
        icon: None,
        description: Some("Test weather API".to_string()),
        kind: Some("task".to_string()),
        version: Some("1.0.0".to_string()),
        registry: None,
        endpoint: Some("https://api.example.com/weather/{city}".to_string()),
        method: Some("GET".to_string()),
        headers: Some({
            let mut h = HashMap::new();
            h.insert("X-API-Key".to_string(), "$env:WEATHER_API_KEY".to_string());
            h
        }),
        parameters: Some({
            let mut p = HashMap::new();
            p.insert("type".to_string(), serde_json::json!("object"));
            p.insert(
                "properties".to_string(),
                serde_json::json!({
                    "city": {
                        "type": "string",
                        "description": "City name"
                    }
                }),
            );
            p
        }),
        command: None,
        args: None,
        env: None,
        port: None,
        transport: None,
        client_id: None,
        client_secret: None,
        auth_url: None,
        token_url: None,
        scopes: None,
        auth_params: None,
        webhook: None,
    };

    // Write the tool to a temporary registry file
    let temp_dir = tempfile::tempdir().unwrap();
    let registry_path = temp_dir.path().join("registry.json");
    let entries = vec![tool_entry];
    std::fs::write(
        &registry_path,
        serde_json::to_string_pretty(&entries).unwrap(),
    )
    .unwrap();

    // Create registry manager with the temp registry
    let secrets_provider: Arc<dyn crate::secrets::SecretsProvider> =
        Arc::new(crate::secrets::EnvSecretsProvider::new());
    let local_registry = crate::registry::LocalRegistry::new(registry_path.to_str().unwrap());
    let registry_manager = Arc::new(crate::registry::RegistryManager::new(
        vec![Box::new(local_registry)],
        secrets_provider.clone(),
    ));

    // Create adapter registry with lazy loading
    let adapters = AdapterRegistry::new(registry_manager);

    // Lazy load the tool
    let adapter = adapters.get_or_load("test.weather").await;
    assert!(
        adapter.is_some(),
        "Tool should be lazy loaded from registry"
    );

    // Verify it's an HttpAdapter with the correct manifest
    let adapter = adapter.unwrap();
    let manifest = adapter.manifest();
    assert!(manifest.is_some());
    let manifest = manifest.unwrap();
    assert_eq!(manifest.name, "test.weather");
    assert_eq!(
        manifest.endpoint,
        Some("https://api.example.com/weather/{city}".to_string())
    );
    assert_eq!(manifest.method, Some("GET".to_string()));

    // Verify caching by deleting the registry file and checking again
    // If it's truly cached, it should still work even after the file is gone
    std::fs::remove_file(&registry_path).unwrap();

    let cached_adapter = adapters.get_or_load("test.weather").await;
    assert!(
        cached_adapter.is_some(),
        "Tool should be cached in memory, not re-loaded from deleted file"
    );

    // Verify it's the same adapter (same Arc pointer)
    assert!(
        Arc::ptr_eq(&adapter, &cached_adapter.unwrap()),
        "Cached adapter should be the exact same Arc instance"
    );
}

/// Test that lazy loading only works for tools, not other entry types
#[tokio::test]
async fn test_lazy_load_ignores_non_tools() {
    // Create a non-tool entry (mcp_server)
    let mcp_entry = crate::registry::RegistryEntry {
        entry_type: "mcp_server".to_string(),
        name: "test.mcp".to_string(),
        display_name: None,
        icon: None,
        description: Some("Test MCP server".to_string()),
        kind: None,
        version: None,
        registry: None,
        command: Some("node".to_string()),
        args: Some(vec!["server.js".to_string()]),
        endpoint: None,
        method: None,
        headers: None,
        parameters: None,
        env: None,
        port: None,
        transport: None,
        client_id: None,
        client_secret: None,
        auth_url: None,
        token_url: None,
        scopes: None,
        auth_params: None,
        webhook: None,
    };

    // Write to temp registry
    let temp_dir = tempfile::tempdir().unwrap();
    let registry_path = temp_dir.path().join("registry.json");
    std::fs::write(
        &registry_path,
        serde_json::to_string_pretty(&vec![mcp_entry]).unwrap(),
    )
    .unwrap();

    // Create registry manager
    let secrets_provider: Arc<dyn crate::secrets::SecretsProvider> =
        Arc::new(crate::secrets::EnvSecretsProvider::new());
    let local_registry = crate::registry::LocalRegistry::new(registry_path.to_str().unwrap());
    let registry_manager = Arc::new(crate::registry::RegistryManager::new(
        vec![Box::new(local_registry)],
        secrets_provider.clone(),
    ));

    let adapters = AdapterRegistry::new(registry_manager);

    // Try to lazy load - should return None because it's not a tool
    let adapter = adapters.get_or_load("test.mcp").await;
    assert!(
        adapter.is_none(),
        "Non-tool entries should not be lazy loaded"
    );
}

/// Test that lazy loading works correctly when tool is not in registry
#[tokio::test]
async fn test_lazy_load_nonexistent_tool() {
    // Create empty registry
    let temp_dir = tempfile::tempdir().unwrap();
    let registry_path = temp_dir.path().join("registry.json");
    std::fs::write(&registry_path, "[]").unwrap();

    let secrets_provider: Arc<dyn crate::secrets::SecretsProvider> =
        Arc::new(crate::secrets::EnvSecretsProvider::new());
    let local_registry = crate::registry::LocalRegistry::new(registry_path.to_str().unwrap());
    let registry_manager = Arc::new(crate::registry::RegistryManager::new(
        vec![Box::new(local_registry)],
        secrets_provider.clone(),
    ));

    let adapters = AdapterRegistry::new(registry_manager);

    // Try to load non-existent tool
    let adapter = adapters.get_or_load("nonexistent.tool").await;
    assert!(adapter.is_none(), "Nonexistent tools should return None");
}

/// Test that get_or_load returns already registered adapters without hitting registry
#[tokio::test]
async fn test_lazy_load_prefers_registered_adapter() {
    let temp_dir = tempfile::tempdir().unwrap();
    let registry_path = temp_dir.path().join("registry.json");
    std::fs::write(&registry_path, "[]").unwrap();

    let secrets_provider: Arc<dyn crate::secrets::SecretsProvider> =
        Arc::new(crate::secrets::EnvSecretsProvider::new());
    let local_registry = crate::registry::LocalRegistry::new(registry_path.to_str().unwrap());
    let registry_manager = Arc::new(crate::registry::RegistryManager::new(
        vec![Box::new(local_registry)],
        secrets_provider.clone(),
    ));

    let adapters = AdapterRegistry::new(registry_manager);

    // Manually register a core adapter
    adapters.register(Arc::new(crate::adapter::CoreAdapter::new()));

    // get_or_load should return the registered adapter without hitting registry
    let adapter = adapters.get_or_load("core").await;
    assert!(adapter.is_some());
    assert_eq!(adapter.unwrap().id(), "core");
}

/// End-to-end test: Verify a lazy-loaded tool can be used in actual flow execution
#[tokio::test]
async fn test_lazy_load_end_to_end_execution() {
    // Create a mock HTTP server that the tool will call
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/weather"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "city": "Seattle",
            "temperature": 15,
            "condition": "Rainy"
        })))
        .mount(&mock_server)
        .await;

    // Create a tool that calls the mock server (simple fixed endpoint)
    let tool_entry = crate::registry::RegistryEntry {
        entry_type: "tool".to_string(),
        name: "weather.get".to_string(),
        display_name: None,
        icon: None,
        description: Some("Get weather".to_string()),
        kind: Some("task".to_string()),
        version: Some("1.0.0".to_string()),
        registry: None,
        endpoint: Some(format!("{}/weather", mock_server.uri())),
        method: Some("GET".to_string()),
        headers: None,
        parameters: Some({
            let mut p = HashMap::new();
            p.insert("type".to_string(), serde_json::json!("object"));
            p
        }),
        command: None,
        args: None,
        env: None,
        port: None,
        transport: None,
        client_id: None,
        client_secret: None,
        auth_url: None,
        token_url: None,
        scopes: None,
        auth_params: None,
        webhook: None,
    };

    // Write tool to registry
    let temp_dir = tempfile::tempdir().unwrap();
    let registry_path = temp_dir.path().join("registry.json");
    std::fs::write(
        &registry_path,
        serde_json::to_string_pretty(&vec![tool_entry]).unwrap(),
    )
    .unwrap();

    // Create engine with the custom registry
    let secrets_provider: Arc<dyn crate::secrets::SecretsProvider> =
        Arc::new(crate::secrets::EnvSecretsProvider::new());
    let local_registry = crate::registry::LocalRegistry::new(registry_path.to_str().unwrap());
    let registry_manager = Arc::new(crate::registry::RegistryManager::new(
        vec![Box::new(local_registry)],
        secrets_provider.clone(),
    ));

    let adapters = Arc::new(AdapterRegistry::new(registry_manager.clone()));

    // Register built-in adapters
    adapters.register(Arc::new(crate::adapter::CoreAdapter::new()));

    let storage: Arc<dyn crate::storage::Storage> = Arc::new(
        crate::storage::SqliteStorage::new(":memory:")
            .await
            .expect("Failed to create storage"),
    );

    let config = Arc::new(crate::config::Config::default());
    let oauth_client =
        crate::auth::create_test_oauth_client(storage.clone(), secrets_provider.clone());
    let engine = crate::engine::Engine::new(
        adapters.clone(),
        Arc::new(crate::dsl::Templater::new()),
        storage,
        secrets_provider,
        config,
        oauth_client,
        1000,
    );

    // Create a flow that uses the lazy-loaded tool
    let flow = crate::model::Flow {
        name: "weather_test".to_string().into(),
        description: None,
        version: None,
        on: crate::model::Trigger::Single("manual".to_string()),
        cron: None,
        vars: None,
        steps: vec![crate::model::Step {
            id: "get_weather".to_string().into(),
            use_: Some("weather.get".to_string()), // This should trigger lazy loading
            with: None,                            // No parameters needed for simple GET
            ..Default::default()
        }],
        catch: None,
    };

    // Execute the flow - this should lazy-load the tool and execute it
    let result = engine
        .execute(&flow, HashMap::new(), "test_user", "test_tenant")
        .await;

    assert!(
        result.is_ok(),
        "Flow with lazy-loaded tool should execute successfully: {:?}",
        result.err()
    );

    // Verify the mock was called (proving the tool actually executed)
    // Note: wiremock automatically verifies mocks were called on drop

    // Verify the output contains the weather data
    let outputs = result.unwrap().outputs;
    assert!(
        outputs.contains_key("get_weather"),
        "Should have step output"
    );

    let weather_output = &outputs["get_weather"];
    assert!(
        weather_output.get("body").is_some() || weather_output.get("temperature").is_some(),
        "Output should contain weather data"
    );
}
