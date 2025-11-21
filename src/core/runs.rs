//! Run operations module
//!
//! All operations for managing flow executions.

use super::*;
use beemflow_core_macros::{operation, operation_group};
use schemars::JsonSchema;
use uuid::Uuid;

#[operation_group(runs)]
pub mod runs {
    use super::*;

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Empty input (no parameters required)")]
    pub struct EmptyInput {}

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for listing runs with pagination")]
    pub struct ListInput {
        #[schemars(description = "Maximum number of runs to return (default: 100, max: 10000)")]
        pub limit: Option<usize>,
        #[schemars(description = "Number of runs to skip (default: 0)")]
        pub offset: Option<usize>,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for starting a new flow run")]
    pub struct StartInput {
        #[schemars(description = "Name of the flow to execute")]
        pub flow_name: String,
        #[schemars(description = "Event data to pass to the flow")]
        pub event: Option<HashMap<String, Value>>,
        #[schemars(description = "Whether this is a draft run")]
        pub draft: Option<bool>,
    }

    #[derive(Serialize)]
    pub struct StartOutput {
        pub run_id: String,
        pub status: String,
        pub outputs: HashMap<String, Value>,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for retrieving run details")]
    pub struct GetInput {
        #[schemars(description = "UUID of the run to retrieve")]
        pub run_id: String,
    }

    #[derive(Deserialize, JsonSchema)]
    #[schemars(description = "Input for resuming a paused run")]
    pub struct ResumeInput {
        #[schemars(description = "Resume token from the paused run")]
        pub token: String,
        #[schemars(description = "Event data for resuming")]
        pub event: Option<HashMap<String, Value>>,
    }

    /// Start a new flow run
    #[operation(
        name = "start_run",
        input = StartInput,
        http = "POST /runs",
        cli = "runs start <FLOW_NAME> [--event <JSON>] [--draft]",
        description = "Start a new flow run"
    )]
    pub struct Start {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for Start {
        type Input = StartInput;
        type Output = StartOutput;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            // Extract RequestContext (always present via middleware)
            let ctx = super::super::get_auth_context_or_default();

            // Check RBAC permission
            crate::auth::check_permission(&ctx, crate::auth::Permission::RunsTrigger)?;

            // Delegate to engine.start() with authenticated user context
            let result = self
                .deps
                .engine
                .start(
                    &input.flow_name,
                    input.event.unwrap_or_default(),
                    input.draft.unwrap_or(false),
                    &ctx.user_id,
                    &ctx.organization_id,
                )
                .await?;

            // Format output for API
            Ok(StartOutput {
                run_id: result.run_id.to_string(),
                status: "completed".to_string(),
                outputs: result.outputs,
            })
        }
    }

    /// Get run details by ID
    #[operation(
        name = "get_run",
        input = GetInput,
        http = "GET /runs/{run_id}",
        cli = "runs get <RUN_ID>",
        description = "Get run details by ID"
    )]
    pub struct Get {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for Get {
        type Input = GetInput;
        type Output = Value;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            // Require authentication and check RBAC permission
            let ctx = super::super::get_auth_context_or_default();
            crate::auth::check_permission(&ctx, crate::auth::Permission::RunsRead)?;

            let run_id = Uuid::parse_str(&input.run_id)
                .map_err(|_| BeemFlowError::validation("Invalid run ID"))?;

            let mut run = self
                .deps
                .storage
                .get_run(run_id, &ctx.organization_id)
                .await?
                .ok_or_else(|| not_found("Run", &input.run_id))?;

            // Fetch step execution details
            let steps = self.deps.storage.get_steps(run_id).await?;
            run.steps = if steps.is_empty() { None } else { Some(steps) };

            Ok(serde_json::to_value(run)?)
        }
    }

    /// List all runs
    #[operation(
        name = "list_runs",
        input = ListInput,
        http = "GET /runs",
        cli = "runs list [--limit <LIMIT>] [--offset <OFFSET>]",
        description = "List all runs with pagination"
    )]
    pub struct List {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for List {
        type Input = ListInput;
        type Output = Value;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            // Require authentication and check RBAC permission
            let ctx = super::super::get_auth_context_or_default();
            crate::auth::check_permission(&ctx, crate::auth::Permission::RunsRead)?;

            // Use provided values or defaults (limit: 100, offset: 0)
            let limit = input.limit.unwrap_or(100);
            let offset = input.offset.unwrap_or(0);

            let runs = self
                .deps
                .storage
                .list_runs(&ctx.organization_id, limit, offset)
                .await?;
            Ok(serde_json::to_value(runs)?)
        }
    }

    /// Resume a paused run
    #[operation(
        name = "resume_run",
        input = ResumeInput,
        http = "POST /runs/resume/{token}",
        cli = "resume <TOKEN> [--event <JSON>]",
        description = "Resume a paused run"
    )]
    pub struct Resume {
        pub deps: Arc<Dependencies>,
    }

    #[async_trait]
    impl Operation for Resume {
        type Input = ResumeInput;
        type Output = Value;

        async fn execute(&self, input: Self::Input) -> Result<Self::Output> {
            // Extract RequestContext (always present via middleware)
            let ctx = super::super::get_auth_context_or_default();

            // Check RBAC permission
            crate::auth::check_permission(&ctx, crate::auth::Permission::RunsTrigger)?;

            let event = input.event.unwrap_or_default();

            // Resume the run using the engine
            // The token provides the run context, RBAC ensures user has permission
            self.deps.engine.resume(&input.token, event).await?;

            Ok(serde_json::json!({
                "status": "resumed",
                "token": input.token,
                "message": "Run resumed successfully"
            }))
        }
    }
}
