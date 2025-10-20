//! Execution engine for BeemFlow workflows
//!
//! The engine handles step execution, parallel processing, loops, conditionals,
//! state management, and durable waits.

pub mod context;
pub mod executor;

use crate::adapter::AdapterRegistry;
use crate::dsl::Templater;
use crate::storage::Storage;
use crate::{BeemFlowError, Flow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

pub use context::{RunsAccess, StepContext};
pub use executor::Executor;

/// Result of a flow execution
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub run_id: Uuid,
    pub outputs: HashMap<String, serde_json::Value>,
}

/// Paused run information for await_event
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PausedRun {
    pub flow: Flow,
    pub step_idx: usize,
    pub context: StepContext,
    pub outputs: HashMap<String, serde_json::Value>,
    pub token: String,
    pub run_id: Uuid,
}

/// BeemFlow execution engine
///
/// The engine should be initialized once via `core::create_dependencies()` and then
/// shared via Arc<Engine>. For unit tests, use `Engine::for_testing()`.
pub struct Engine {
    adapters: Arc<AdapterRegistry>,
    mcp_adapter: Arc<crate::adapter::McpAdapter>,
    templater: Arc<Templater>,
    storage: Arc<dyn Storage>,
    secrets_provider: Arc<dyn crate::secrets::SecretsProvider>,
    config: Arc<crate::config::Config>,
    oauth_client: Arc<crate::auth::OAuthClientManager>,
    max_concurrent_tasks: usize,
}

impl Engine {
    /// Create a new engine with all dependencies
    ///
    /// This is the internal constructor used by `core::create_dependencies()`.
    /// For production use, call `create_dependencies()` instead.
    /// For tests, use `Engine::for_testing()` or `TestEnvironment`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        adapters: Arc<AdapterRegistry>,
        mcp_adapter: Arc<crate::adapter::McpAdapter>,
        templater: Arc<Templater>,
        storage: Arc<dyn Storage>,
        secrets_provider: Arc<dyn crate::secrets::SecretsProvider>,
        config: Arc<crate::config::Config>,
        oauth_client: Arc<crate::auth::OAuthClientManager>,
        max_concurrent_tasks: usize,
    ) -> Self {
        Self {
            adapters,
            mcp_adapter,
            templater,
            storage,
            secrets_provider,
            config,
            oauth_client,
            max_concurrent_tasks,
        }
    }

    /// Load tools and MCP servers from default registry into adapter registry
    ///
    /// This method uses the secrets provider to expand environment variable references
    /// in MCP server configurations.
    pub async fn load_default_registry_tools(
        adapters: &Arc<AdapterRegistry>,
        mcp_adapter: &Arc<crate::adapter::McpAdapter>,
        secrets_provider: &Arc<dyn crate::secrets::SecretsProvider>,
    ) {
        // Load embedded default.json directly
        let data = include_str!("../registry/default.json");
        match serde_json::from_str::<Vec<crate::registry::RegistryEntry>>(data) {
            Ok(entries) => {
                let mut tool_count = 0;
                let mut mcp_count = 0;

                for entry in entries {
                    match entry.entry_type.as_str() {
                        "tool" => {
                            tool_count += 1;

                            // Create tool manifest
                            let manifest = crate::adapter::ToolManifest {
                                name: entry.name.clone(),
                                description: entry.description.clone().unwrap_or_default(),
                                kind: entry.kind.unwrap_or_else(|| "task".to_string()),
                                version: entry.version,
                                parameters: entry.parameters.unwrap_or_default(),
                                endpoint: entry.endpoint,
                                method: entry.method,
                                headers: entry.headers,
                            };

                            // Register as HTTP adapter
                            adapters.register(Arc::new(crate::adapter::HttpAdapter::new(
                                entry.name.clone(),
                                Some(manifest),
                            )));

                            tracing::debug!("Registered tool: {}", entry.name);
                        }

                        "mcp_server" => {
                            mcp_count += 1;

                            // Expand environment variables in env map using secrets provider
                            let env = if let Some(env_map) = entry.env {
                                let mut expanded_env = HashMap::new();
                                for (k, v) in env_map {
                                    match crate::secrets::expand_value(&v, secrets_provider).await {
                                        Ok(expanded) => {
                                            expanded_env.insert(k, expanded);
                                        }
                                        Err(e) => {
                                            tracing::warn!("Failed to expand env var {}: {}", k, e);
                                            expanded_env.insert(k, v);
                                        }
                                    }
                                }
                                Some(expanded_env)
                            } else {
                                None
                            };

                            // Create MCP server config
                            let config = crate::model::McpServerConfig {
                                command: entry.command.unwrap_or_default(),
                                args: entry.args,
                                env,
                                port: entry.port,
                                transport: entry.transport,
                                endpoint: entry.endpoint,
                            };

                            // Register with MCP adapter directly (no downcasting needed)
                            mcp_adapter.register_server(entry.name.clone(), config);
                            tracing::debug!("Registered MCP server: {}", entry.name);
                        }

                        _ => {
                            // Ignore other entry types (oauth_provider, etc.)
                        }
                    }
                }

                tracing::info!(
                    "Loaded {} tools and {} MCP servers from default registry",
                    tool_count,
                    mcp_count
                );
            }
            Err(e) => {
                tracing::error!("Failed to load default registry: {}", e);
            }
        }
    }

    /// Execute a flow with event data
    pub async fn execute(
        &self,
        flow: &Flow,
        event: HashMap<String, serde_json::Value>,
    ) -> Result<ExecutionResult> {
        if flow.steps.is_empty() {
            return Ok(ExecutionResult {
                run_id: Uuid::nil(),
                outputs: HashMap::new(),
            });
        }

        // Configure MCP servers if present in flow
        if let Some(ref mcp_servers) = flow.mcp_servers {
            for (name, config) in mcp_servers {
                self.mcp_adapter
                    .register_server(name.clone(), config.clone());
            }
        }

        // Setup execution context (returns error if duplicate run detected)
        let (step_ctx, run_id) = self.setup_execution_context(flow, event.clone()).await?;

        // Fetch previous run data for template access
        let runs_data = self.fetch_previous_run_data(&flow.name, run_id).await;

        // Create executor
        let executor = Executor::new(
            self.adapters.clone(),
            self.templater.clone(),
            self.storage.clone(),
            self.secrets_provider.clone(),
            self.oauth_client.clone(),
            runs_data,
            self.max_concurrent_tasks,
        );

        // Execute steps
        let result = executor.execute_steps(flow, &step_ctx, 0, run_id).await;

        // Finalize execution and return result with run_id
        let outputs = self.finalize_execution(flow, event, result, run_id).await?;

        Ok(ExecutionResult { run_id, outputs })
    }

    /// Start a new flow execution by name
    ///
    /// This is a high-level method that handles:
    /// - Loading flow from storage (deployed) or filesystem (draft)
    /// - Parsing YAML to Flow object
    /// - Executing the flow
    ///
    /// # Parameters
    /// - `flow_name`: Name of the flow to execute
    /// - `event`: Event data passed to the flow as {{ event.* }}
    /// - `is_draft`: If true, load from filesystem; if false, load from deployed_flows
    ///
    /// # Returns
    /// ExecutionResult with run_id and final outputs
    ///
    /// # Errors
    /// - Flow not found (either in filesystem or deployed_flows)
    /// - YAML parsing errors
    /// - Execution errors
    pub async fn start(
        &self,
        flow_name: &str,
        event: HashMap<String, serde_json::Value>,
        is_draft: bool,
    ) -> Result<ExecutionResult> {
        // Load flow content
        let content = self.load_flow_content(flow_name, is_draft).await?;

        // Parse YAML
        let flow = crate::dsl::parse_string(&content, None)?;

        // Execute flow (delegate to existing low-level method)
        self.execute(&flow, event).await
    }

    /// Load flow content from storage or filesystem
    ///
    /// Helper method that encapsulates the draft vs. deployed logic.
    async fn load_flow_content(&self, flow_name: &str, is_draft: bool) -> Result<String> {
        if is_draft {
            // Draft mode: load from filesystem
            let flows_dir = crate::config::get_flows_dir(&self.config);

            crate::storage::flows::get_flow(&flows_dir, flow_name)
                .await?
                .ok_or_else(|| {
                    crate::BeemFlowError::not_found("Flow", format!("{} (filesystem)", flow_name))
                })
        } else {
            // Production mode: load from deployed_flows
            let version = self
                .storage
                .get_deployed_version(flow_name)
                .await?
                .ok_or_else(|| {
                    crate::BeemFlowError::not_found(
                        "Deployed flow",
                        format!(
                            "{} (not deployed - use --draft to run from filesystem)",
                            flow_name
                        ),
                    )
                })?;

            self.storage
                .get_flow_version_content(flow_name, &version)
                .await?
                .ok_or_else(|| {
                    crate::BeemFlowError::not_found(
                        "Flow version",
                        format!("{} version {}", flow_name, version),
                    )
                })
        }
    }

    /// Resume a paused run
    pub async fn resume(
        &self,
        token: &str,
        resume_event: HashMap<String, serde_json::Value>,
    ) -> Result<()> {
        tracing::debug!(
            "Resume called for token {} with event: {:?}",
            token,
            resume_event
        );

        // Atomically fetch and delete paused run from storage
        let paused_json = self
            .storage
            .fetch_and_delete_paused_run(token)
            .await?
            .ok_or_else(|| {
                crate::BeemFlowError::config(format!("No paused run found for token: {}", token))
            })?;

        // Deserialize paused run from JSON
        let paused: PausedRun = serde_json::from_value(paused_json)?;

        // Merge resume event with existing event data and create new context
        let snapshot = paused.context.snapshot();
        let mut merged_event = snapshot.event;
        merged_event.extend(resume_event);

        let updated_ctx = StepContext::new(merged_event, snapshot.vars, snapshot.secrets);

        // Restore previous outputs
        for (k, v) in snapshot.outputs {
            updated_ctx.set_output(k, v);
        }

        // Fetch previous run data for template access
        let runs_data = self
            .fetch_previous_run_data(&paused.flow.name, paused.run_id)
            .await;

        // Create executor
        let executor = Executor::new(
            self.adapters.clone(),
            self.templater.clone(),
            self.storage.clone(),
            self.secrets_provider.clone(),
            self.oauth_client.clone(),
            runs_data,
            self.max_concurrent_tasks,
        );

        // Continue execution
        let _outputs = executor
            .execute_steps(
                &paused.flow,
                &updated_ctx,
                paused.step_idx + 1,
                paused.run_id,
            )
            .await
            .unwrap_or_else(|_| HashMap::new());

        // Note: Outputs are tracked in storage via StepContext, not in-memory
        Ok(())
    }

    /// Handle resume events (called when resume events are received)
    pub async fn handle_resume_event(
        &self,
        token: &str,
        event_data: serde_json::Value,
    ) -> Result<()> {
        tracing::info!("Handling resume event for token: {}", token);

        // Extract event data into HashMap
        let resume_event = if let Some(obj) = event_data.as_object() {
            obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        } else {
            HashMap::new()
        };

        // Resume the run
        self.resume(token, resume_event).await
    }

    /// Setup execution context
    async fn setup_execution_context(
        &self,
        flow: &Flow,
        event: HashMap<String, serde_json::Value>,
    ) -> Result<(StepContext, Uuid)> {
        // Collect secrets from event and secrets provider
        let secrets = self.collect_secrets(&event).await;

        // Create step context
        let step_ctx = StepContext::new(
            event.clone(),
            flow.vars.clone().unwrap_or_default(),
            secrets,
        );

        // Generate deterministic run ID
        let run_id = self.generate_deterministic_run_id(&flow.name, &event);

        // Create run
        let run = crate::model::Run {
            id: run_id,
            flow_name: flow.name.clone(),
            event: event.clone(),
            vars: flow.vars.clone().unwrap_or_default(),
            status: crate::model::RunStatus::Running,
            started_at: chrono::Utc::now(),
            ended_at: None,
            steps: None,
        };

        // Try to atomically insert run - returns false if already exists
        // Note: Deterministic UUID includes time bucket, so duplicates within
        // the same minute window will have the same ID
        if !self.storage.try_insert_run(&run).await? {
            tracing::info!(
                "Duplicate run detected for {}, run_id: {}",
                flow.name,
                run_id
            );
            return Err(crate::BeemFlowError::validation(format!(
                "Duplicate run detected for flow '{}' (run_id: {}). A run with the same event data was already executed within the current time window.",
                flow.name, run_id
            )));
        }

        Ok((step_ctx, run_id))
    }

    /// Finalize execution and update run status
    async fn finalize_execution(
        &self,
        flow: &Flow,
        event: HashMap<String, serde_json::Value>,
        result: std::result::Result<HashMap<String, serde_json::Value>, BeemFlowError>,
        run_id: Uuid,
    ) -> Result<HashMap<String, serde_json::Value>> {
        let (_outputs, status) = match &result {
            Ok(outputs) => (outputs.clone(), crate::model::RunStatus::Succeeded),
            Err(e)
                if e.to_string()
                    .contains(crate::constants::ERR_AWAIT_EVENT_PAUSE) =>
            {
                (HashMap::new(), crate::model::RunStatus::Waiting)
            }
            Err(_) => (HashMap::new(), crate::model::RunStatus::Failed),
        };

        // Clone event before moving
        let event_clone = event.clone();

        // Update run with final status
        let run = crate::model::Run {
            id: run_id,
            flow_name: flow.name.clone(),
            event,
            vars: flow.vars.clone().unwrap_or_default(),
            status,
            started_at: chrono::Utc::now(),
            ended_at: Some(chrono::Utc::now()),
            steps: None,
        };

        self.storage.save_run(&run).await?;

        // Handle catch blocks if there was an error
        if result.is_err() && flow.catch.is_some() {
            self.execute_catch_blocks(flow, &event_clone, run_id)
                .await?;
        }

        result
    }

    /// Execute catch blocks on error
    async fn execute_catch_blocks(
        &self,
        flow: &Flow,
        event: &HashMap<String, serde_json::Value>,
        run_id: Uuid,
    ) -> Result<HashMap<String, serde_json::Value>> {
        let catch_steps = flow
            .catch
            .as_ref()
            .ok_or_else(|| crate::BeemFlowError::validation("no catch blocks defined"))?;

        let secrets = self.collect_secrets(event).await;
        let step_ctx = StepContext::new(
            event.clone(),
            flow.vars.clone().unwrap_or_default(),
            secrets,
        );

        // Catch blocks don't have access to previous runs
        let executor = Executor::new(
            self.adapters.clone(),
            self.templater.clone(),
            self.storage.clone(),
            self.secrets_provider.clone(),
            self.oauth_client.clone(),
            None,
            self.max_concurrent_tasks,
        );

        // Execute catch steps and collect step records
        let mut catch_outputs = HashMap::new();
        let mut step_records = Vec::new();

        for step in catch_steps {
            let step_start = chrono::Utc::now();

            match executor
                .execute_single_step(step, &step_ctx, &step.id)
                .await
            {
                Ok(_) => {
                    let output = step_ctx.get_output(&step.id);
                    if let Some(ref output_value) = output {
                        catch_outputs.insert(step.id.to_string(), output_value.clone());
                    }

                    // Create successful step record
                    step_records.push(crate::model::StepRun {
                        id: Uuid::new_v4(),
                        run_id,
                        step_name: step.id.clone(),
                        status: crate::model::StepStatus::Succeeded,
                        started_at: step_start,
                        ended_at: Some(chrono::Utc::now()),
                        error: None,
                        outputs: output.and_then(|v| {
                            if let serde_json::Value::Object(map) = v {
                                Some(map.into_iter().collect())
                            } else {
                                None
                            }
                        }),
                    });
                }
                Err(e) => {
                    tracing::error!("Catch block step {} failed: {}", step.id, e);

                    // Create failed step record
                    step_records.push(crate::model::StepRun {
                        id: Uuid::new_v4(),
                        run_id,
                        step_name: step.id.clone(),
                        status: crate::model::StepStatus::Failed,
                        started_at: step_start,
                        ended_at: Some(chrono::Utc::now()),
                        error: Some(e.to_string()),
                        outputs: None,
                    });
                }
            }
        }

        // Save catch block step records to storage
        for step_record in step_records {
            if let Err(e) = self.storage.save_step(&step_record).await {
                tracing::error!(
                    "Failed to save catch block step {}: {}",
                    step_record.step_name,
                    e
                );
            }
        }

        Ok(catch_outputs)
    }

    /// Collect secrets from event data and secrets provider
    ///
    /// Priority:
    /// 1. Secrets from event.secrets object (highest priority)
    /// 2. Event keys starting with $env prefix
    /// 3. All environment variables from secrets provider (lowest priority)
    async fn collect_secrets(
        &self,
        event: &HashMap<String, serde_json::Value>,
    ) -> HashMap<String, serde_json::Value> {
        let mut secrets = HashMap::new();

        // 1. Get ALL environment variables from secrets provider (base layer)
        if let Ok(all_env_secrets) = self.secrets_provider.get_all_secrets().await {
            for (k, v) in all_env_secrets {
                secrets.insert(k, serde_json::Value::String(v));
            }
        } else {
            tracing::warn!("Failed to get secrets from provider");
        }

        // 2. Overlay event keys starting with $env prefix (higher priority)
        for (k, v) in event {
            if k.starts_with(crate::constants::ENV_VAR_PREFIX) {
                let env_var = k.trim_start_matches(crate::constants::ENV_VAR_PREFIX);
                secrets.insert(env_var.to_string(), v.clone());
            }
        }

        // 3. Overlay secrets from event.secrets object (highest priority)
        if let Some(event_secrets) = event
            .get(crate::constants::SECRETS_KEY)
            .and_then(|v| v.as_object())
        {
            for (k, v) in event_secrets {
                secrets.insert(k.clone(), v.clone());
            }
        }

        secrets
    }

    /// Generate deterministic run ID for deduplication
    ///
    /// Uses 30-second time windows to prevent duplicate executions while allowing
    /// high-frequency cron jobs (e.g., every minute) to execute reliably.
    fn generate_deterministic_run_id(
        &self,
        flow_name: &str,
        event: &HashMap<String, serde_json::Value>,
    ) -> Uuid {
        use sha2::Digest;
        use sha2::Sha256;

        let mut hasher = Sha256::new();

        // Add flow name
        hasher.update(flow_name.as_bytes());

        // Add time bucket (30-second windows for better granularity)
        // This prevents duplicate executions within 30s while allowing
        // 1-minute cron jobs to execute reliably (60s > 30s)
        let now = chrono::Utc::now();
        let time_bucket = now.timestamp() / 30 * 30; // truncate to 30-second intervals
        hasher.update(time_bucket.to_string().as_bytes());

        // Add event data in sorted order for determinism
        let mut keys: Vec<&String> = event.keys().collect();
        keys.sort();
        for key in keys {
            hasher.update(key.as_bytes());
            if let Ok(json) = serde_json::to_string(&event[key]) {
                hasher.update(json.as_bytes());
            }
        }

        let hash = hasher.finalize();
        Uuid::new_v5(&Uuid::NAMESPACE_DNS, &hash)
    }

    /// Fetch previous run data for template access
    async fn fetch_previous_run_data(
        &self,
        flow_name: &str,
        current_run_id: Uuid,
    ) -> Option<HashMap<String, serde_json::Value>> {
        tracing::debug!(
            "Fetching previous run data for flow '{}', current run: {}",
            flow_name,
            current_run_id
        );

        let runs_access = RunsAccess::new(
            self.storage.clone(),
            Some(current_run_id),
            flow_name.to_string(),
        );

        let prev_data = runs_access.previous().await;
        if !prev_data.is_empty() {
            tracing::debug!(
                "Found previous run data for '{}': {} fields",
                flow_name,
                prev_data.len()
            );
            // Wrap in "previous" key for template access as runs.previous.id, etc.
            let mut wrapped = HashMap::new();
            wrapped.insert(
                "previous".to_string(),
                serde_json::to_value(&prev_data).unwrap_or(serde_json::Value::Null),
            );
            Some(wrapped)
        } else {
            tracing::debug!("No previous run data found for '{}'", flow_name);
            None
        }
    }

    /// Create an engine for testing with in-memory SQLite storage
    ///
    /// This method should only be used in tests. For production, use `core::create_dependencies()`
    /// which initializes the engine with proper configuration.
    ///
    /// For tests that need isolated environments, use `beemflow::utils::TestEnvironment` instead.
    pub async fn for_testing() -> Self {
        let storage = crate::storage::SqliteStorage::new(":memory:")
            .await
            .expect("Failed to create in-memory SQLite storage");

        // Create secrets provider
        let secrets_provider: Arc<dyn crate::secrets::SecretsProvider> =
            Arc::new(crate::secrets::EnvSecretsProvider::new());

        // Create minimal config for testing
        let config = Arc::new(crate::config::Config::default());

        // Create registry manager for testing
        let registry_manager = Arc::new(crate::registry::RegistryManager::standard(
            None,
            secrets_provider.clone(),
        ));

        // Create adapter registry with lazy loading support
        let adapters = Arc::new(AdapterRegistry::new(registry_manager));

        // Register core adapters
        adapters.register(Arc::new(crate::adapter::CoreAdapter::new()));
        adapters.register(Arc::new(crate::adapter::HttpAdapter::new(
            crate::constants::HTTP_ADAPTER_ID.to_string(),
            None,
        )));

        // Create and register MCP adapter
        let mcp_adapter = Arc::new(crate::adapter::McpAdapter::new(secrets_provider.clone()));
        adapters.register(mcp_adapter.clone());

        // Load tools and MCP servers from default registry
        Self::load_default_registry_tools(&adapters, &mcp_adapter, &secrets_provider).await;

        // Wrap storage in Arc first for sharing between engine and oauth_client
        let storage_arc = Arc::new(storage);

        // Create OAuth client manager with test redirect URI
        let oauth_client =
            crate::auth::create_test_oauth_client(storage_arc.clone(), secrets_provider.clone());

        Self::new(
            adapters,
            mcp_adapter,
            Arc::new(Templater::new()),
            storage_arc,
            secrets_provider,
            config,
            oauth_client,
            1000, // Default max concurrent tasks for testing
        )
    }

    /// Get storage reference (for testing only)
    #[cfg(test)]
    pub fn storage(&self) -> &Arc<dyn Storage> {
        &self.storage
    }
}

#[cfg(test)]
mod context_test;
#[cfg(test)]
mod engine_test;
#[cfg(test)]
mod error_test;
#[cfg(test)]
mod executor_test;
