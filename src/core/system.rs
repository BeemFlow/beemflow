//! System operations module
//!
//! All operations for system-level functionality.

use super::*;
use beemflow_core_macros::{operation, operation_group};
use schemars::JsonSchema;

#[operation_group(system)]
pub mod system {
    use super::*;

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Empty input (no parameters required)")]
    pub struct EmptyInput {}

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for retrieving OAuth provider configuration")]
    pub struct GetOAuthProviderInput {
        #[schemars(description = "Name of the OAuth provider")]
        pub name: String,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for triggering system-wide cron")]
    pub struct SystemCronInput {}

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for triggering a workflow cron")]
    pub struct WorkflowCronInput {
        #[schemars(description = "Name of the workflow to trigger")]
        pub workflow: String,
    }

    #[derive(Serialize, JsonSchema)]
    #[schemars(description = "Dashboard statistics")]
    pub struct DashboardStats {
        #[schemars(description = "Total number of flows")]
        pub total_flows: usize,
        #[schemars(description = "Total number of runs")]
        pub total_runs: usize,
        #[schemars(description = "Number of currently active runs")]
        pub active_runs: usize,
        #[schemars(description = "Number of runs awaiting events")]
        pub awaiting_events: usize,
        #[schemars(description = "Success rate (0.0 to 1.0)")]
        pub success_rate: f64,
        #[schemars(description = "Recent activity")]
        pub recent_activity: Vec<RecentActivity>,
    }

    #[derive(Serialize, JsonSchema)]
    #[schemars(description = "Recent activity item")]
    pub struct RecentActivity {
        pub timestamp: String,
        pub flow_name: String,
        pub status: String,
    }

    /// Show BeemFlow specification
    #[operation(
        name = "spec",
        input = EmptyInput,
        http = "GET /spec",
        cli = "spec",
        description = "Show BeemFlow specification"
    )]
    pub struct Spec {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for Spec {
        type Input = EmptyInput;
        type Output = Value;

        async fn execute(&self, _input: Self::Input) -> Result<Self::Output> {
            // Read the SPEC.md file from docs directory
            let spec_content = include_str!("../../docs/SPEC.md");

            Ok(serde_json::json!({
                "name": "BeemFlow",
                "version": env!("CARGO_PKG_VERSION"),
                "description": "GitHub Actions for every business process",
                "spec": spec_content
            }))
        }
    }

    /// Root greeting
    #[operation(name = "root", input = EmptyInput, http = "GET /", description = "Root greeting")]
    pub struct Root {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for Root {
        type Input = EmptyInput;
        type Output = String;

        async fn execute(&self, _input: Self::Input) -> Result<Self::Output> {
            Ok("Hi, I'm BeemBeem! :D".to_string())
        }
    }

    /// Get registry index
    #[operation(name = "registry_index", input = EmptyInput, description = "Get registry index")]
    pub struct RegistryIndex {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for RegistryIndex {
        type Input = EmptyInput;
        type Output = Value;

        async fn execute(&self, _input: Self::Input) -> Result<Self::Output> {
            let entries = self.deps.registry_manager.list_all_servers().await?;

            // Separate tools and MCP servers
            let tools: Vec<_> = entries
                .iter()
                .filter(|e| e.entry_type == "tool")
                .cloned()
                .collect();

            let mcp_servers: Vec<_> = entries
                .iter()
                .filter(|e| e.entry_type == "mcp_server")
                .cloned()
                .collect();

            Ok(serde_json::json!({
                "version": "1.0.0",
                "runtime": "beemflow",
                "tools": tools,
                "mcp_servers": mcp_servers,
                "stats": {
                    "total_tools": tools.len(),
                    "total_mcp_servers": mcp_servers.len()
                }
            }))
        }
    }

    /// Get OAuth provider configuration
    #[operation(
        name = "get_oauth_provider",
        input = GetOAuthProviderInput,
        description = "Get OAuth provider configuration"
    )]
    pub struct GetOAuthProvider {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for GetOAuthProvider {
        type Input = GetOAuthProviderInput;
        type Output = Value;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            // Get OAuth provider from registry
            let provider_entry = self
                .deps
                .registry_manager
                .get_server(&input.name)
                .await?
                .ok_or_else(|| not_found("OAuth provider", &input.name))?;

            if provider_entry.entry_type != "oauth_provider" {
                return Err(type_mismatch(
                    &input.name,
                    "OAuth provider",
                    &provider_entry.entry_type,
                ));
            }

            Ok(serde_json::to_value(provider_entry)?)
        }
    }

    /// Triggers all workflows with schedule.cron
    #[operation(
        name = "system_cron",
        input = SystemCronInput,
        description = "Triggers all workflows with schedule.cron"
    )]
    pub struct SystemCron {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for SystemCron {
        type Input = SystemCronInput;
        type Output = Value;

        async fn execute(&self, _input: Self::Input) -> Result<Self::Output> {
            Ok(serde_json::json!({
                "status": "success",
                "message": "System cron functionality not implemented yet",
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))
        }
    }

    /// Triggers a specific workflow
    #[operation(name = "workflow_cron", input = WorkflowCronInput, description = "Triggers a specific workflow")]
    pub struct WorkflowCron {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for WorkflowCron {
        type Input = WorkflowCronInput;
        type Output = Value;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            Ok(serde_json::json!({
                "status": "success",
                "workflow": input.workflow,
                "message": "Workflow cron functionality not implemented yet",
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))
        }
    }

    /// Get dashboard statistics
    #[operation(
        name = "dashboard_stats",
        input = EmptyInput,
        http = "GET /dashboard/stats",
        description = "Get dashboard statistics including flows, runs, and success rates"
    )]
    pub struct GetDashboardStats {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for GetDashboardStats {
        type Input = EmptyInput;
        type Output = DashboardStats;

        async fn execute(&self, _input: Self::Input) -> Result<Self::Output> {
            // Extract authenticated context - dashboard shows organization-specific stats
            let ctx = super::super::get_auth_context_or_default();

            let storage = &self.deps.storage;

            // Get total flows (deployed flows) for this organization
            let flows = storage
                .list_all_deployed_flows(&ctx.organization_id)
                .await?;
            let total_flows = flows.len();

            // Get all runs with a reasonable limit for stats (organization-scoped)
            let all_runs = storage.list_runs(&ctx.organization_id, 1000, 0).await?;
            let total_runs = all_runs.len();

            // Count active runs (running or pending)
            let active_runs = all_runs
                .iter()
                .filter(|r| {
                    matches!(
                        r.status,
                        crate::model::RunStatus::Running | crate::model::RunStatus::Pending
                    )
                })
                .count();

            // Count runs awaiting events
            let awaiting_events = all_runs
                .iter()
                .filter(|r| matches!(r.status, crate::model::RunStatus::Waiting))
                .count();

            // Calculate success rate
            let completed_runs = all_runs
                .iter()
                .filter(|r| {
                    matches!(
                        r.status,
                        crate::model::RunStatus::Succeeded | crate::model::RunStatus::Failed
                    )
                })
                .count();

            let successful_runs = all_runs
                .iter()
                .filter(|r| matches!(r.status, crate::model::RunStatus::Succeeded))
                .count();

            let success_rate = if completed_runs > 0 {
                successful_runs as f64 / completed_runs as f64
            } else {
                0.0
            };

            // Get recent activity (last 10 runs)
            let mut recent_runs = all_runs.clone();
            recent_runs.sort_by(|a, b| b.started_at.cmp(&a.started_at));
            let recent_activity: Vec<RecentActivity> = recent_runs
                .iter()
                .take(10)
                .map(|r| RecentActivity {
                    timestamp: r.started_at.to_rfc3339(),
                    flow_name: r.flow_name.to_string(),
                    status: format!("{:?}", r.status).to_lowercase(),
                })
                .collect();

            Ok(DashboardStats {
                total_flows,
                total_runs,
                active_runs,
                awaiting_events,
                success_rate,
                recent_activity,
            })
        }
    }

    /// Generate OpenAPI 3.0 specification from all operations
    #[operation(
        name = "generate_openapi",
        input = EmptyInput,
        http = "GET /openapi.json",
        cli = "openapi",
        description = "Generate OpenAPI 3.0 specification from all operations"
    )]
    pub struct GenerateOpenAPI {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for GenerateOpenAPI {
        type Input = EmptyInput;
        type Output = Value;

        async fn execute(&self, _input: Self::Input) -> Result<Self::Output> {
            // Get all operation metadata
            let registry = OperationRegistry::new((*self.deps).clone());
            let metadata = registry.get_all_metadata();

            // Build paths object and collect unique groups for tags
            let mut paths = serde_json::Map::new();
            let mut groups = std::collections::HashSet::new();

            for (op_name, meta) in metadata {
                groups.insert(meta.group);
                // Skip operations without HTTP endpoints
                let (Some(http_method), Some(http_path)) = (&meta.http_method, &meta.http_path)
                else {
                    continue;
                };

                let method = http_method.to_lowercase();
                let path = http_path;

                // Get or create path item
                #[allow(clippy::expect_used)] // Just inserted a JSON object, must be an object
                let path_item = paths
                    .entry(path.to_string())
                    .or_insert_with(|| serde_json::json!({}))
                    .as_object_mut()
                    .expect("just inserted a JSON object, must be an object");

                // Extract path parameters
                let parameters = extract_path_parameters(path);

                // Create operation object
                let operation = serde_json::json!({
                    "summary": meta.description,
                    "operationId": op_name,
                    "tags": [meta.group],
                    "parameters": parameters,
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {},
                                    "additionalProperties": true
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object"
                                    }
                                }
                            }
                        },
                        "400": {
                            "description": "Bad request",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/Error"
                                    }
                                }
                            }
                        },
                        "404": {
                            "description": "Not found",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/Error"
                                    }
                                }
                            }
                        },
                        "500": {
                            "description": "Internal server error",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/Error"
                                    }
                                }
                            }
                        }
                    }
                });

                path_item.insert(method, operation);
            }

            // Convert groups to tags with auto-generated descriptions
            let mut tags: Vec<_> = groups
                .into_iter()
                .map(|group| {
                    serde_json::json!({
                        "name": group,
                        "description": format!("{} operations", group)
                    })
                })
                .collect();
            tags.sort_by(|a, b| {
                a.get("name")
                    .and_then(|v| v.as_str())
                    .cmp(&b.get("name").and_then(|v| v.as_str()))
            });

            // Build full OpenAPI spec
            Ok(serde_json::json!({
                "openapi": "3.0.0",
                "info": {
                    "title": "BeemFlow API",
                    "version": env!("CARGO_PKG_VERSION"),
                    "description": "GitHub Actions for every business process - Complete REST API for workflow orchestration",
                    "contact": {
                        "name": "BeemFlow",
                        "url": "https://github.com/beemflow/beemflow"
                    }
                },
                "servers": [
                    {
                        "url": "http://localhost:3000",
                        "description": "Local development server"
                    }
                ],
                "paths": paths,
                "components": {
                    "schemas": {
                        "Error": {
                            "type": "object",
                            "properties": {
                                "error": {
                                    "type": "object",
                                    "properties": {
                                        "type": {
                                            "type": "string",
                                            "description": "Error type"
                                        },
                                        "message": {
                                            "type": "string",
                                            "description": "Error message"
                                        },
                                        "status": {
                                            "type": "integer",
                                            "description": "HTTP status code"
                                        }
                                    },
                                    "required": ["type", "message", "status"]
                                }
                            },
                            "required": ["error"]
                        }
                    }
                },
                "tags": tags
            }))
        }
    }
}

/// Extract path parameters from a path template
fn extract_path_parameters(path: &str) -> Vec<Value> {
    let mut params = Vec::new();

    for part in path.split('/') {
        if part.starts_with('{') && part.ends_with('}') {
            let param_name = &part[1..part.len() - 1];
            params.push(serde_json::json!({
                "name": param_name,
                "in": "path",
                "required": true,
                "schema": {
                    "type": "string"
                },
                "description": format!("The {}", param_name)
            }));
        }
    }

    params
}
