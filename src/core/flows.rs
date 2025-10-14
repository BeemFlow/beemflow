//! Flow operations module
//!
//! All operations for managing workflow definitions.

use super::*;
use crate::dsl::{Validator, parse_file, parse_string};
use crate::graph::GraphGenerator;
use beemflow_core_macros::{operation, operation_group};
use schemars::JsonSchema;

#[operation_group(flows)]
pub mod flows {
    use super::*;

    // Shared input/output types
    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Empty input (no parameters required)")]
    pub struct EmptyInput {}

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for retrieving a flow by name")]
    pub struct GetInput {
        #[schemars(description = "Name of the flow to retrieve")]
        pub name: String,
    }

    #[derive(Serialize)]
    pub struct GetOutput {
        pub name: String,
        pub content: String,
        pub version: Option<String>,
    }

    #[derive(Serialize)]
    pub struct ListOutput {
        pub flows: Vec<String>,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for saving or updating a flow definition")]
    pub struct SaveInput {
        #[schemars(description = "Name of the flow (optional, can be inferred from content)")]
        pub name: Option<String>,
        #[schemars(description = "YAML content of the flow definition")]
        pub content: String,
    }

    #[derive(Serialize)]
    pub struct SaveOutput {
        pub status: String,
        pub name: String,
        pub version: String,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for deleting a flow definition")]
    pub struct DeleteInput {
        #[schemars(description = "Name of the flow to delete")]
        pub name: String,
    }

    #[derive(Serialize)]
    pub struct DeleteOutput {
        pub status: String,
        pub name: String,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for deploying a flow to production")]
    pub struct DeployInput {
        #[schemars(description = "Name of the flow to deploy")]
        pub name: String,
    }

    #[derive(Serialize)]
    pub struct DeployOutput {
        pub flow: String,
        pub version: String,
        pub status: String,
        pub message: String,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for rolling back a flow to a specific version")]
    pub struct RollbackInput {
        #[schemars(description = "Name of the flow")]
        pub name: String,
        #[schemars(description = "Version to rollback to")]
        pub version: String,
    }

    #[derive(Serialize)]
    pub struct RollbackOutput {
        pub flow: String,
        pub from_version: Option<String>,
        pub to_version: String,
        pub status: String,
        pub message: String,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for disabling a flow")]
    pub struct DisableInput {
        #[schemars(description = "Name of the flow to disable")]
        pub name: String,
    }

    #[derive(Serialize)]
    pub struct DisableOutput {
        pub flow_name: String,
        pub version: String,
        pub message: String,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for enabling a flow")]
    pub struct EnableInput {
        #[schemars(description = "Name of the flow to enable")]
        pub name: String,
    }

    #[derive(Serialize)]
    pub struct EnableOutput {
        pub flow_name: String,
        pub version: String,
        pub message: String,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for restoring a flow from deployment history")]
    pub struct RestoreInput {
        #[schemars(description = "Name of the flow to restore")]
        pub name: String,
        #[schemars(
            description = "Specific version to restore (defaults to currently deployed or latest)"
        )]
        pub version: Option<String>,
    }

    #[derive(Serialize)]
    pub struct RestoreOutput {
        pub name: String,
        pub version: String,
        pub status: String,
        pub message: String,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for retrieving flow version history")]
    pub struct HistoryInput {
        #[schemars(description = "Name of the flow")]
        pub name: String,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for validating a flow")]
    pub struct ValidateInput {
        #[schemars(description = "Name of the flow (if loading from storage)")]
        pub name: Option<String>,
        #[schemars(description = "Path to flow file (if loading from file system)")]
        pub file: Option<String>,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for generating a Mermaid diagram")]
    pub struct GraphInput {
        #[schemars(description = "Name of the flow (if loading from storage)")]
        pub name: Option<String>,
        #[schemars(description = "Path to flow file (if loading from file system)")]
        pub file: Option<String>,
    }

    #[derive(Serialize)]
    pub struct GraphOutput {
        pub diagram: String,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for linting a flow file")]
    pub struct LintInput {
        #[schemars(description = "Path to the flow file to lint")]
        pub file: String,
    }

    // Operations

    /// List all available flows
    #[operation(
        name = "list_flows",
        input = EmptyInput,
        http = "GET /flows",
        cli = "list",
        description = "List all available workflow definitions"
    )]
    pub struct List {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for List {
        type Input = EmptyInput;
        type Output = ListOutput;

        async fn execute(&self, _input: Self::Input) -> Result<Self::Output> {
            let flows_dir = crate::config::get_flows_dir(&self.deps.config);
            let flows = crate::storage::flows::list_flows(&flows_dir).await?;
            Ok(ListOutput { flows })
        }
    }

    /// Get a flow by name
    #[operation(
        name = "get_flow",
        input = GetInput,
        http = "GET /flows/{name}",
        cli = "get <NAME>",
        description = "Get a flow by name"
    )]
    pub struct Get {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for Get {
        type Input = GetInput;
        type Output = GetOutput;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            let flows_dir = crate::config::get_flows_dir(&self.deps.config);
            let content = crate::storage::flows::get_flow(&flows_dir, &input.name)
                .await?
                .ok_or_else(|| not_found("Flow", &input.name))?;

            // Parse to get version
            let flow = parse_string(&content, None)?;

            Ok(GetOutput {
                name: input.name,
                content,
                version: flow.version,
            })
        }
    }

    /// Save or update a flow definition
    #[operation(
        name = "save_flow",
        input = SaveInput,
        http = "POST /flows",
        cli = "save <NAME> --file <FILE>",
        description = "Save or update a flow definition"
    )]
    pub struct Save {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for Save {
        type Input = SaveInput;
        type Output = SaveOutput;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            // Parse and validate the flow
            let flow = parse_string(&input.content, None)?;
            Validator::validate(&flow)?;

            // Determine flow name
            let name = input.name.unwrap_or_else(|| flow.name.to_string());
            if name.is_empty() {
                return Err(BeemFlowError::validation("Flow must have a name"));
            }

            let flows_dir = crate::config::get_flows_dir(&self.deps.config);

            // Save flow (returns true if file was updated, false if created new)
            let was_updated =
                crate::storage::flows::save_flow(&flows_dir, &name, &input.content).await?;

            let status = if was_updated { "updated" } else { "created" };
            let version = flow.version.unwrap_or_else(|| "1.0.0".to_string());

            Ok(SaveOutput {
                status: status.to_string(),
                name,
                version,
            })
        }
    }

    /// Delete a flow definition
    #[operation(
        name = "delete_flow",
        input = DeleteInput,
        http = "DELETE /flows/{name}",
        cli = "delete <NAME>",
        description = "Delete a flow definition"
    )]
    pub struct Delete {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for Delete {
        type Input = DeleteInput;
        type Output = DeleteOutput;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            let flows_dir = crate::config::get_flows_dir(&self.deps.config);
            crate::storage::flows::delete_flow(&flows_dir, &input.name).await?;

            Ok(DeleteOutput {
                status: "deleted".to_string(),
                name: input.name,
            })
        }
    }

    /// Deploy flow to production
    #[operation(
        name = "deploy_flow",
        input = DeployInput,
        http = "POST /flows/{name}/deploy",
        cli = "deploy <NAME>",
        description = "Deploy flow to production"
    )]
    pub struct Deploy {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for Deploy {
        type Input = DeployInput;
        type Output = DeployOutput;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            // Get flow content from filesystem (draft)
            let flows_dir = crate::config::get_flows_dir(&self.deps.config);
            let content = crate::storage::flows::get_flow(&flows_dir, &input.name)
                .await?
                .ok_or_else(|| not_found("Flow", &input.name))?;

            // Parse to get version
            let flow = parse_string(&content, None)?;
            let version = flow.version.ok_or_else(|| {
                BeemFlowError::validation("Flow must have a version field to deploy")
            })?;

            // Deploy the version to database
            self.deps
                .storage
                .deploy_flow_version(&input.name, &version, &content)
                .await?;

            let message = format!("Flow '{}' v{} deployed to production", input.name, version);

            Ok(DeployOutput {
                flow: input.name,
                version,
                status: "deployed".to_string(),
                message,
            })
        }
    }

    /// Rollback flow to specific version
    #[operation(
        name = "rollback_flow",
        input = RollbackInput,
        http = "POST /flows/{name}/rollback",
        cli = "rollback <NAME> <VERSION>",
        description = "Rollback flow to specific version"
    )]
    pub struct Rollback {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for Rollback {
        type Input = RollbackInput;
        type Output = RollbackOutput;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            // Get current deployed version
            let current_version = self.deps.storage.get_deployed_version(&input.name).await?;

            // Get the target version content
            let content = self
                .deps
                .storage
                .get_flow_version_content(&input.name, &input.version)
                .await?
                .ok_or_else(|| {
                    not_found(
                        &format!("Version {}", input.version),
                        "(must be previously deployed)",
                    )
                })?;

            // Deploy the target version
            self.deps
                .storage
                .deploy_flow_version(&input.name, &input.version, &content)
                .await?;

            let message = format!("Flow '{}' rolled back to v{}", input.name, input.version);

            Ok(RollbackOutput {
                flow: input.name,
                from_version: current_version,
                to_version: input.version,
                status: "rolled_back".to_string(),
                message,
            })
        }
    }

    /// Disable a flow from production
    #[operation(
        name = "disable_flow",
        input = DisableInput,
        http = "POST /flows/{name}/disable",
        cli = "disable <NAME>",
        description = "Disable a flow from production"
    )]
    pub struct Disable {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for Disable {
        type Input = DisableInput;
        type Output = DisableOutput;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            // Check if flow is currently deployed
            let deployed_version = self.deps.storage.get_deployed_version(&input.name).await?;

            let version = deployed_version.ok_or_else(|| {
                BeemFlowError::not_found(
                    "Deployed flow",
                    format!("{} (not currently deployed)", input.name),
                )
            })?;

            // Remove from production
            self.deps
                .storage
                .unset_deployed_version(&input.name)
                .await?;

            let message = format!(
                "Flow '{}' v{} disabled from production",
                input.name, version
            );

            Ok(DisableOutput {
                flow_name: input.name,
                version,
                message,
            })
        }
    }

    /// Enable a flow in production
    #[operation(
        name = "enable_flow",
        input = EnableInput,
        http = "POST /flows/{name}/enable",
        cli = "enable <NAME>",
        description = "Enable a flow in production"
    )]
    pub struct Enable {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for Enable {
        type Input = EnableInput;
        type Output = EnableOutput;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            // Check if already enabled
            if let Some(current) = self.deps.storage.get_deployed_version(&input.name).await? {
                return Err(BeemFlowError::validation(format!(
                    "Flow '{}' is already enabled (version {}). Use 'rollback' to change versions.",
                    input.name, current
                )));
            }

            // Find most recently deployed version from history
            let latest_version = self
                .deps
                .storage
                .get_latest_deployed_version_from_history(&input.name)
                .await?
                .ok_or_else(|| {
                    BeemFlowError::not_found(
                        "Flow history",
                        format!("{} (no versions have been deployed yet)", input.name),
                    )
                })?;

            // Re-deploy it
            self.deps
                .storage
                .set_deployed_version(&input.name, &latest_version)
                .await?;

            let message = format!(
                "Flow '{}' v{} enabled in production",
                input.name, latest_version
            );

            Ok(EnableOutput {
                flow_name: input.name,
                version: latest_version,
                message,
            })
        }
    }

    /// Restore a flow from deployment history to filesystem
    #[operation(
        name = "restore_flow",
        input = RestoreInput,
        http = "POST /flows/{name}/restore",
        cli = "restore <NAME> [--version <VERSION>]",
        description = "Restore a flow from deployment history to filesystem"
    )]
    pub struct Restore {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for Restore {
        type Input = RestoreInput;
        type Output = RestoreOutput;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            // Determine which version to restore
            let version = if let Some(v) = input.version {
                // Specific version requested
                v
            } else {
                // Get currently deployed version, or fall back to latest from history
                match self.deps.storage.get_deployed_version(&input.name).await? {
                    Some(v) => v,
                    None => {
                        // If no deployed version, get latest from history (for disabled flows)
                        self.deps
                            .storage
                            .get_latest_deployed_version_from_history(&input.name)
                            .await?
                            .ok_or_else(|| {
                                BeemFlowError::not_found(
                                    "Flow deployment",
                                    format!("{} (no deployment history found)", input.name),
                                )
                            })?
                    }
                }
            };

            // Fetch content from database
            let content = self
                .deps
                .storage
                .get_flow_version_content(&input.name, &version)
                .await?
                .ok_or_else(|| {
                    not_found(
                        &format!("Version {}", version),
                        "(not found in deployment history)",
                    )
                })?;

            // Write to filesystem
            let flows_dir = crate::config::get_flows_dir(&self.deps.config);
            crate::storage::flows::save_flow(&flows_dir, &input.name, &content).await?;

            let message = format!(
                "Flow '{}' v{} restored from deployment history to filesystem",
                input.name, version
            );

            Ok(RestoreOutput {
                name: input.name,
                version,
                status: "restored".to_string(),
                message,
            })
        }
    }

    /// Get flow version history
    #[operation(
        name = "flow_history",
        input = HistoryInput,
        http = "GET /flows/{name}/history",
        cli = "history <NAME>",
        description = "Get flow version history"
    )]
    pub struct History {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for History {
        type Input = HistoryInput;
        type Output = Value;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            let history = self.deps.storage.list_flow_versions(&input.name).await?;

            let result: Vec<_> = history
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "version": v.version,
                        "deployed_at": v.deployed_at.to_rfc3339(),
                        "flow_name": v.flow_name
                    })
                })
                .collect();

            Ok(serde_json::to_value(result)?)
        }
    }

    /// Validate a flow
    #[operation(
        name = "validate_flow",
        input = ValidateInput,
        http = "POST /flows/validate",
        cli = "validate <FILE>",
        description = "Validate a flow"
    )]
    pub struct Validate {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for Validate {
        type Input = ValidateInput;
        type Output = Value;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            let flow = super::load_flow_from_config(
                &self.deps.config,
                input.name.as_deref(),
                input.file.as_deref(),
            )
            .await?;
            Validator::validate(&flow)?;

            Ok(serde_json::json!({
                "status": "valid",
                "message": "Validation OK: flow is valid!"
            }))
        }
    }

    /// Generate Mermaid diagram
    #[operation(
        name = "graph_flow",
        input = GraphInput,
        http = "POST /flows/graph",
        cli = "graph <FILE> [--output <PATH>]",
        description = "Generate Mermaid diagram for a flow"
    )]
    pub struct Graph {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for Graph {
        type Input = GraphInput;
        type Output = GraphOutput;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            let flow = super::load_flow_from_config(
                &self.deps.config,
                input.name.as_deref(),
                input.file.as_deref(),
            )
            .await?;
            let diagram = GraphGenerator::generate(&flow)?;

            Ok(GraphOutput { diagram })
        }
    }

    /// Lint a flow file
    #[operation(
        name = "lint_flow",
        input = LintInput,
        http = "POST /flows/lint",
        cli = "lint <FILE>",
        description = "Lint a flow file"
    )]
    pub struct Lint {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for Lint {
        type Input = LintInput;
        type Output = Value;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            let flow = parse_file(&input.file, None)?;
            Validator::validate(&flow)?;

            Ok(serde_json::json!({
                "status": "valid",
                "message": "Lint OK: flow is valid!"
            }))
        }
    }

    /// Test a flow
    #[operation(name = "test_flow", input = EmptyInput, description = "Test a flow")]
    pub struct Test {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for Test {
        type Input = EmptyInput;
        type Output = Value;

        async fn execute(&self, _input: Self::Input) -> Result<Self::Output> {
            Ok(serde_json::json!({
                "status": "success",
                "message": "Test functionality not implemented yet"
            }))
        }
    }
}
