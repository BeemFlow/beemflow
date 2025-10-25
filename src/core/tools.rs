//! Tool operations module
//!
//! All operations for managing tools and adapters.

use super::*;
use beemflow_core_macros::{operation, operation_group};
use schemars::JsonSchema;

#[operation_group(tools)]
pub mod tools {
    use super::*;

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Empty input (no parameters required)")]
    pub struct EmptyInput {}

    #[derive(Serialize)]
    pub struct ListOutput {
        pub tools: Vec<serde_json::Value>,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for retrieving a tool manifest")]
    pub struct GetManifestInput {
        #[schemars(description = "Name of the tool to retrieve")]
        pub name: String,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for searching tools")]
    pub struct SearchInput {
        #[schemars(description = "Search query (optional, returns all if omitted)")]
        pub query: Option<String>,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for installing a tool")]
    pub struct InstallInput {
        #[schemars(description = "Name of the tool to install from registry")]
        pub name: Option<String>,
        #[schemars(description = "Tool manifest as JSON (alternative to name)")]
        pub manifest: Option<Value>,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for converting OpenAPI specification to tools")]
    pub struct ConvertOpenAPIInput {
        #[schemars(description = "OpenAPI specification as JSON string")]
        pub openapi: String,
        #[schemars(description = "Custom API name (defaults to spec title)")]
        pub api_name: Option<String>,
        #[schemars(description = "Base URL for API (defaults to first server in spec)")]
        pub base_url: Option<String>,
    }

    /// List all tools
    #[operation(
        name = "list_tools",
        input = EmptyInput,
        http = "GET /tools",
        cli = "tools list",
        description = "List all tools"
    )]
    pub struct List {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for List {
        type Input = EmptyInput;
        type Output = ListOutput;

        async fn execute(&self, _input: Self::Input) -> Result<Self::Output> {
            let entries = self.deps.registry_manager.list_all_servers().await?;

            // Filter to just tools
            let tools: Vec<serde_json::Value> = entries
                .into_iter()
                .filter(|e| e.entry_type == "tool")
                .map(|e| serde_json::to_value(e).unwrap_or_default())
                .collect();

            Ok(ListOutput { tools })
        }
    }

    /// Get tool manifest
    #[operation(
        name = "get_tool_manifest",
        input = GetManifestInput,
        http = "GET /tools/{name}",
        cli = "tools get <NAME>",
        description = "Get tool manifest"
    )]
    pub struct GetManifest {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for GetManifest {
        type Input = GetManifestInput;
        type Output = Value;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            let entry = self
                .deps
                .registry_manager
                .get_server(&input.name)
                .await?
                .ok_or_else(|| not_found("Tool", &input.name))?;

            Ok(serde_json::to_value(entry)?)
        }
    }

    /// Search for tools
    #[operation(
        name = "search_tools",
        input = SearchInput,
        http = "GET /tools/search",
        cli = "tools search [<QUERY>]",
        description = "Search for tools"
    )]
    pub struct Search {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for Search {
        type Input = SearchInput;
        type Output = Value;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            let entries = self.deps.registry_manager.list_all_servers().await?;
            let tools = filter_by_query(entries.into_iter(), "tool", &input.query);

            Ok(serde_json::to_value(tools)?)
        }
    }

    /// Install a tool
    #[operation(
        name = "install_tool",
        input = InstallInput,
        http = "POST /tools/install",
        cli = "tools install <SOURCE>",
        description = "Install a tool"
    )]
    pub struct Install {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for Install {
        type Input = InstallInput;
        type Output = Value;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            match (input.name, input.manifest) {
                (Some(name), None) => {
                    // Install from registry by name
                    let tool_entry = self
                        .deps
                        .registry_manager
                        .get_server(&name)
                        .await?
                        .ok_or_else(|| not_found("Tool", &name))?;

                    if tool_entry.entry_type != "tool" {
                        return Err(type_mismatch(&name, "tool", &tool_entry.entry_type));
                    }

                    Ok(serde_json::json!({
                        "status": "installed",
                        "name": name,
                        "type": "tool",
                        "endpoint": tool_entry.endpoint
                    }))
                }
                (None, Some(manifest)) => {
                    // Install from manifest
                    let tool_name = manifest
                        .get("name")
                        .and_then(|n| n.as_str())
                        .ok_or_else(|| {
                            BeemFlowError::validation("Tool manifest must have a 'name' field")
                        })?
                        .to_string();

                    // Register the tool in the local registry
                    self.deps
                        .registry_manager
                        .register_tool_from_manifest(manifest)
                        .await?;

                    Ok(serde_json::json!({
                        "status": "installed",
                        "name": tool_name,
                        "type": "tool",
                        "source": "manifest"
                    }))
                }
                (Some(_), Some(_)) => Err(BeemFlowError::validation(
                    "Provide either 'name' or 'manifest', not both",
                )),
                (None, None) => Err(BeemFlowError::validation(
                    "Either 'name' or 'manifest' must be provided",
                )),
            }
        }
    }

    /// Convert OpenAPI to tools
    #[operation(
        name = "convert_openapi",
        input = ConvertOpenAPIInput,
        http = "POST /tools/convert",
        description = "Convert OpenAPI to tools"
    )]
    pub struct ConvertOpenAPI {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for ConvertOpenAPI {
        type Input = ConvertOpenAPIInput;
        type Output = Value;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            // Parse OpenAPI spec
            let spec: HashMap<String, Value> = serde_json::from_str(&input.openapi)?;

            // Extract API name: use provided value, or generate slug from title
            let api_name = input.api_name.unwrap_or_else(|| {
                let title = spec
                    .get("info")
                    .and_then(|info| info.get("title"))
                    .and_then(|title| title.as_str())
                    .unwrap_or("api");

                // Generate clean slug: lowercase, alphanumeric only, underscores for separators
                title
                    .to_lowercase()
                    .chars()
                    .map(|c| if c.is_alphanumeric() { c } else { '_' })
                    .collect::<String>()
                    .split('_')
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join("_")
            });

            // Extract base URL from spec or use provided value
            let base_url = input.base_url.unwrap_or_else(|| {
                spec.get("servers")
                    .and_then(|servers| servers.as_array())
                    .and_then(|servers| servers.first())
                    .and_then(|server| server.get("url"))
                    .and_then(|url| url.as_str())
                    .unwrap_or("https://api.example.com")
                    .to_string()
            });

            // Delegate to CoreAdapter for conversion (single source of truth)
            let adapter = crate::adapter::core::CoreAdapter::new();
            let manifests = adapter.convert_openapi_to_manifests(&spec, &api_name, &base_url)?;

            Ok(serde_json::json!({
                "status": "converted",
                "api_name": api_name,
                "base_url": base_url,
                "manifests": manifests,
                "count": manifests.len()
            }))
        }
    }
}
