//! Step executor
//!
//! Handles execution of individual steps, parallel blocks, loops, and conditionals.

use super::{PausedRun, StepContext};
use crate::adapter::{Adapter, AdapterRegistry};
use crate::dsl::{DependencyAnalyzer, Templater};
use crate::storage::Storage;
use crate::{BeemFlowError, Flow, Result, Step};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Semaphore;
use uuid::Uuid;

// ============================================================================
// Helper Functions (used by both main executor and parallel tasks)
// ============================================================================

/// Resolve adapter for a tool name, with lazy loading support
///
/// This function resolves adapters in the following priority:
/// 1. Exact match (e.g., registered adapters)
/// 2. Prefix match for core.* and mcp:// tools
/// 3. Lazy load from registry (for dynamically installed tools)
/// 4. Fallback to generic HTTP adapter (legacy behavior)
async fn resolve_adapter(
    adapters: &Arc<AdapterRegistry>,
    tool_name: &str,
) -> Result<Arc<dyn Adapter>> {
    // Try exact match first (already registered adapters)
    if let Some(adapter) = adapters.get(tool_name) {
        return Ok(adapter);
    }

    // Try by prefix for core.* and mcp://* tools
    if tool_name.starts_with(crate::constants::ADAPTER_PREFIX_MCP) {
        if let Some(adapter) = adapters.get(crate::constants::ADAPTER_ID_MCP) {
            return Ok(adapter);
        }
        return Err(BeemFlowError::adapter("MCP adapter not registered"));
    }

    if tool_name.starts_with(crate::constants::ADAPTER_PREFIX_CORE) {
        if let Some(adapter) = adapters.get(crate::constants::ADAPTER_ID_CORE) {
            return Ok(adapter);
        }
        return Err(BeemFlowError::adapter("Core adapter not registered"));
    }

    // Try lazy loading from registry (for dynamically installed tools)
    if let Some(adapter) = adapters.get_or_load(tool_name).await {
        return Ok(adapter);
    }

    // Fallback to generic HTTP adapter (legacy behavior for backward compatibility)
    if let Some(adapter) = adapters.get(crate::constants::HTTP_ADAPTER_ID) {
        return Ok(adapter);
    }

    Err(BeemFlowError::adapter(format!(
        "adapter not found: {} (and HTTP adapter not available)",
        tool_name
    )))
}

/// Prepare inputs for tool execution
fn prepare_inputs(
    templater: &Arc<Templater>,
    step: &Step,
    step_ctx: &StepContext,
    runs_data: Option<&HashMap<String, Value>>,
) -> Result<HashMap<String, Value>> {
    let template_data = if let Some(runs) = runs_data {
        step_ctx.template_data_with_runs(Some(runs.clone()))
    } else {
        step_ctx.template_data()
    };

    step.with.as_ref().map_or_else(
        || Ok(HashMap::new()),
        |with| {
            with.iter()
                .map(|(k, v)| {
                    render_value(templater, v, &template_data).map(|rendered| (k.clone(), rendered))
                })
                .collect()
        },
    )
}

/// Render a JSON value recursively, expanding templates
fn render_value(
    templater: &Arc<Templater>,
    val: &Value,
    data: &HashMap<String, Value>,
) -> Result<Value> {
    match val {
        Value::String(s) => templater.render(s, data).map(Value::String),
        Value::Array(arr) => arr
            .iter()
            .map(|elem| render_value(templater, elem, data))
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        Value::Object(obj) => obj
            .iter()
            .map(|(k, v)| render_value(templater, v, data).map(|rendered| (k.clone(), rendered)))
            .collect::<Result<serde_json::Map<String, Value>>>()
            .map(Value::Object),
        _ => Ok(val.clone()),
    }
}

/// Add special __use parameter for core and MCP tools
fn add_special_use_param(inputs: &mut HashMap<String, Value>, use_: &str) {
    if use_.starts_with(crate::constants::ADAPTER_PREFIX_CORE)
        || use_.starts_with(crate::constants::ADAPTER_PREFIX_MCP)
    {
        inputs.insert(
            crate::constants::PARAM_SPECIAL_USE.to_string(),
            Value::String(use_.to_string()),
        );
    }
}

/// Create loop variables for foreach iterations
fn create_loop_vars(
    base_vars: HashMap<String, Value>,
    as_var: &str,
    item: Value,
    index: usize,
) -> HashMap<String, Value> {
    let mut vars = base_vars;
    vars.insert(as_var.to_string(), item);
    vars.insert(format!("{}_index", as_var), Value::Number(index.into()));
    vars.insert(format!("{}_row", as_var), Value::Number((index + 1).into()));
    vars
}

/// Step executor
pub struct Executor {
    adapters: Arc<AdapterRegistry>,
    templater: Arc<Templater>,
    storage: Arc<dyn Storage>,
    secrets_provider: Arc<dyn crate::secrets::SecretsProvider>,
    oauth_client: Arc<crate::auth::OAuthClientManager>,
    runs_data: Option<HashMap<String, Value>>,
    max_concurrent_tasks: usize,
}

impl Executor {
    /// Create a new executor
    pub fn new(
        adapters: Arc<AdapterRegistry>,
        templater: Arc<Templater>,
        storage: Arc<dyn Storage>,
        secrets_provider: Arc<dyn crate::secrets::SecretsProvider>,
        oauth_client: Arc<crate::auth::OAuthClientManager>,
        runs_data: Option<HashMap<String, Value>>,
        max_concurrent_tasks: usize,
    ) -> Self {
        Self {
            adapters,
            templater,
            storage,
            secrets_provider,
            oauth_client,
            runs_data,
            max_concurrent_tasks,
        }
    }

    /// Get template data with runs context if available
    fn get_template_data(&self, step_ctx: &StepContext) -> HashMap<String, Value> {
        if let Some(ref runs) = self.runs_data {
            step_ctx.template_data_with_runs(Some(runs.clone()))
        } else {
            step_ctx.template_data()
        }
    }

    /// Execute steps starting from a given index
    ///
    /// Steps are executed in dependency order (topological sort), not YAML order.
    /// Dependencies are detected from:
    /// 1. Template references: `{{ steps.foo.output }}`
    /// 2. Manual `depends_on` fields
    pub async fn execute_steps(
        &self,
        flow: &Flow,
        step_ctx: &StepContext,
        start_idx: usize,
        run_id: Uuid,
    ) -> Result<HashMap<String, Value>> {
        // Use dependency analyzer to determine execution order
        let analyzer = DependencyAnalyzer::new();
        let sorted_ids = analyzer.topological_sort(flow)?;

        // Create lookup map for steps
        let step_map: HashMap<String, &Step> =
            flow.steps.iter().map(|s| (s.id.to_string(), s)).collect();

        // Determine which step to start from
        // For fresh runs (start_idx=0), execute all steps in sorted order
        // For resumed runs, find the resume point in sorted order
        let sorted_start_idx = if start_idx == 0 {
            // Fresh run - start from beginning of sorted list
            0
        } else if start_idx < flow.steps.len() {
            // Resumed run - find the step to resume from in sorted order
            let start_step_id = &flow.steps[start_idx].id;
            sorted_ids
                .iter()
                .position(|id| id.as_str() == start_step_id.as_str())
                .unwrap_or(0)
        } else {
            return Ok(step_ctx.snapshot().outputs);
        };

        // Execute steps in dependency order (starting from start_idx)
        for step_id in sorted_ids.iter().skip(sorted_start_idx) {
            let step = step_map
                .get(step_id)
                .ok_or_else(|| BeemFlowError::adapter(format!("step not found: {}", step_id)))?;

            // Handle await_event steps
            if step.await_event.is_some() {
                // Find original index for await_event handling
                let idx = flow
                    .steps
                    .iter()
                    .position(|s| s.id.as_str() == step_id)
                    .unwrap();
                return self
                    .handle_await_event(step, flow, step_ctx, idx, run_id)
                    .await;
            }

            // Execute regular step
            self.execute_single_step(step, step_ctx, &step.id).await?;

            // Persist step result
            self.persist_step_result(step, step_ctx, run_id).await?;
        }

        Ok(step_ctx.snapshot().outputs)
    }

    /// Execute a single step (boxed to handle recursion)
    pub fn execute_single_step<'a>(
        &'a self,
        step: &'a Step,
        step_ctx: &'a StepContext,
        step_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            // Check condition first
            if let Some(ref condition) = step.if_
                && !self.evaluate_condition(condition, step_ctx).await?
            {
                tracing::debug!(
                    "Skipping step {} - condition not met: {}",
                    step_id,
                    condition
                );
                return Ok(());
            }

            // Handle different step types
            if step.parallel == Some(true) && step.steps.is_some() {
                return self.execute_parallel_block(step, step_ctx, step_id).await;
            }

            if step.foreach.is_some() {
                return self.execute_foreach_block(step, step_ctx, step_id).await;
            }

            if step.wait.is_some() {
                return self.execute_wait(step).await;
            }

            if let Some(ref use_) = step.use_ {
                return self.execute_tool_call(use_, step, step_ctx, step_id).await;
            }

            Ok(())
        })
    }

    /// Execute a parallel block
    pub async fn execute_parallel_block(
        &self,
        step: &Step,
        step_ctx: &StepContext,
        step_id: &str,
    ) -> Result<()> {
        let steps = step
            .steps
            .as_ref()
            .ok_or_else(|| BeemFlowError::validation("parallel block must have steps"))?;

        // Create semaphore to limit concurrent tasks
        let semaphore = Arc::new(Semaphore::new(self.max_concurrent_tasks));
        let mut handles = Vec::new();

        for child_step in steps {
            let child = child_step.clone();
            let step_ctx_clone = step_ctx.clone();
            let adapters = self.adapters.clone();
            let templater = self.templater.clone();
            let runs_data = self.runs_data.clone();
            let storage = self.storage.clone();
            let secrets_provider = self.secrets_provider.clone();
            let oauth_client = self.oauth_client.clone();
            let permit = semaphore.clone().acquire_owned().await.map_err(|e| {
                BeemFlowError::adapter(format!("Failed to acquire semaphore: {}", e))
            })?;

            let handle = tokio::spawn(async move {
                let _permit = permit; // Hold permit until task completes

                // Execute tool call directly for parallel steps (no nesting)
                if let Some(ref use_) = child.use_ {
                    let adapter = resolve_adapter(&adapters, use_).await?;
                    let mut inputs =
                        prepare_inputs(&templater, &child, &step_ctx_clone, runs_data.as_ref())?;
                    add_special_use_param(&mut inputs, use_);

                    // Create execution context for OAuth and secrets expansion
                    let exec_ctx = crate::adapter::ExecutionContext::new(
                        storage,
                        secrets_provider.clone(),
                        oauth_client.clone(),
                    );

                    let outputs = adapter.execute(inputs, &exec_ctx).await?;
                    step_ctx_clone.set_output(child.id.to_string(), serde_json::to_value(outputs)?);
                }
                Ok::<_, BeemFlowError>((child.id.to_string(), step_ctx_clone.get_output(&child.id)))
            });

            handles.push(handle);
        }

        // Wait for all tasks to complete
        let mut outputs = HashMap::new();
        for handle in handles {
            let (child_id, output) = match handle.await {
                Ok(result) => result?,
                Err(e) if e.is_panic() => {
                    tracing::error!("Parallel task panicked: {:?}", e);
                    return Err(BeemFlowError::adapter("parallel task panicked"));
                }
                Err(e) if e.is_cancelled() => {
                    tracing::warn!("Parallel task was cancelled");
                    return Err(BeemFlowError::adapter("parallel task cancelled"));
                }
                Err(e) => {
                    return Err(BeemFlowError::adapter(format!(
                        "parallel task failed: {}",
                        e
                    )));
                }
            };
            if let Some(output_val) = output {
                outputs.insert(child_id, output_val);
            }
        }

        step_ctx.set_output(step_id.to_string(), serde_json::to_value(outputs)?);
        Ok(())
    }

    /// Execute a foreach block
    pub async fn execute_foreach_block(
        &self,
        step: &Step,
        step_ctx: &StepContext,
        step_id: &str,
    ) -> Result<()> {
        // Extract required fields or return validation error
        let (foreach_expr, as_var, do_steps) = match (&step.foreach, &step.as_, &step.do_) {
            (Some(expr), Some(var), Some(steps)) => (expr, var, steps),
            (None, _, _) => return Err(BeemFlowError::validation("foreach expression missing")),
            (_, None, _) => return Err(BeemFlowError::validation("foreach must have 'as' field")),
            (_, _, None) => return Err(BeemFlowError::validation("foreach must have 'do' field")),
        };

        // Evaluate foreach expression
        let template_data = self.get_template_data(step_ctx);
        let list_val = self
            .templater
            .evaluate_expression(foreach_expr, &template_data)?;

        // Convert to array
        let list = list_val.as_array().ok_or_else(|| {
            BeemFlowError::validation(format!(
                "foreach expression did not evaluate to array: {:?}",
                list_val
            ))
        })?;

        if list.is_empty() {
            step_ctx.set_output(step_id.to_string(), Value::Object(serde_json::Map::new()));
            return Ok(());
        }

        // Execute in parallel or sequential
        if step.parallel == Some(true) {
            self.execute_foreach_parallel(list, as_var, do_steps, step_ctx)
                .await?;
        } else {
            self.execute_foreach_sequential(list, as_var, do_steps, step_ctx)
                .await?;
        }

        step_ctx.set_output(step_id.to_string(), Value::Object(serde_json::Map::new()));
        Ok(())
    }

    /// Execute foreach sequentially
    async fn execute_foreach_sequential(
        &self,
        list: &[Value],
        as_var: &str,
        do_steps: &[Step],
        step_ctx: &StepContext,
    ) -> Result<()> {
        for (index, item) in list.iter().enumerate() {
            // Create child context with loop variables
            let snapshot = step_ctx.snapshot();
            let iter_vars = create_loop_vars(snapshot.vars.clone(), as_var, item.clone(), index);
            let iter_ctx = StepContext::new(snapshot.event, iter_vars, snapshot.secrets);

            // Copy outputs to child context
            snapshot
                .outputs
                .into_iter()
                .for_each(|(k, v)| iter_ctx.set_output(k, v));

            // Execute all steps for this iteration
            for inner_step in do_steps {
                // Render step ID
                let template_data = self.get_template_data(&iter_ctx);
                let rendered_id = render_value(
                    &self.templater,
                    &Value::String(inner_step.id.to_string()),
                    &template_data,
                )?
                .as_str()
                .unwrap_or(inner_step.id.as_str())
                .to_string();

                self.execute_single_step(inner_step, &iter_ctx, &rendered_id)
                    .await?;
            }

            // Copy outputs back to parent context
            let iter_snapshot = iter_ctx.snapshot();
            for (k, v) in iter_snapshot.outputs {
                step_ctx.set_output(k, v);
            }
        }

        Ok(())
    }

    /// Execute foreach in parallel
    async fn execute_foreach_parallel(
        &self,
        list: &[Value],
        as_var: &str,
        do_steps: &[Step],
        step_ctx: &StepContext,
    ) -> Result<()> {
        // Create semaphore to limit concurrent tasks
        let semaphore = Arc::new(Semaphore::new(self.max_concurrent_tasks));
        let mut handles = Vec::new();

        for (index, item) in list.iter().enumerate() {
            let item = item.clone();
            let as_var = as_var.to_string();
            let do_steps = do_steps.to_vec();
            let snapshot = step_ctx.snapshot();
            let adapters = self.adapters.clone();
            let templater = self.templater.clone();
            let runs_data = self.runs_data.clone();
            let storage = self.storage.clone();
            let secrets_provider = self.secrets_provider.clone();
            let oauth_client = self.oauth_client.clone();
            let permit = semaphore.clone().acquire_owned().await.map_err(|e| {
                BeemFlowError::adapter(format!("Failed to acquire semaphore: {}", e))
            })?;

            let handle = tokio::spawn(async move {
                let _permit = permit; // Hold permit until task completes

                // Create iteration context with loop variables
                let iter_vars = create_loop_vars(snapshot.vars.clone(), &as_var, item, index);
                let iter_ctx = StepContext::new(snapshot.event, iter_vars, snapshot.secrets);

                // Copy existing outputs using iterator
                snapshot
                    .outputs
                    .into_iter()
                    .for_each(|(k, v)| iter_ctx.set_output(k, v));

                // Create execution context for OAuth expansion
                let exec_ctx = crate::adapter::ExecutionContext::new(
                    storage,
                    secrets_provider.clone(),
                    oauth_client.clone(),
                );

                // Execute steps - simple tool calls only in parallel foreach
                for inner_step in &do_steps {
                    if let Some(ref use_) = inner_step.use_ {
                        let adapter = resolve_adapter(&adapters, use_).await?;
                        let mut inputs =
                            prepare_inputs(&templater, inner_step, &iter_ctx, runs_data.as_ref())?;
                        add_special_use_param(&mut inputs, use_);

                        let outputs = adapter.execute(inputs, &exec_ctx).await?;
                        iter_ctx
                            .set_output(inner_step.id.to_string(), serde_json::to_value(outputs)?);
                    }
                }

                Ok::<_, BeemFlowError>(iter_ctx.snapshot())
            });

            handles.push(handle);
        }

        // Wait for all iterations
        for handle in handles {
            let snapshot = match handle.await {
                Ok(result) => result?,
                Err(e) if e.is_panic() => {
                    tracing::error!("Foreach parallel task panicked: {:?}", e);
                    return Err(BeemFlowError::adapter("foreach parallel task panicked"));
                }
                Err(e) if e.is_cancelled() => {
                    tracing::warn!("Foreach parallel task was cancelled");
                    return Err(BeemFlowError::adapter("foreach parallel task cancelled"));
                }
                Err(e) => {
                    return Err(BeemFlowError::adapter(format!(
                        "foreach parallel task failed: {}",
                        e
                    )));
                }
            };

            // Merge outputs back to main context using iterator
            snapshot
                .outputs
                .into_iter()
                .for_each(|(k, v)| step_ctx.set_output(k, v));
        }

        Ok(())
    }

    /// Execute a tool call
    async fn execute_tool_call(
        &self,
        use_: &str,
        step: &Step,
        step_ctx: &StepContext,
        step_id: &str,
    ) -> Result<()> {
        let adapter = resolve_adapter(&self.adapters, use_).await?;
        let mut inputs = prepare_inputs(&self.templater, step, step_ctx, self.runs_data.as_ref())?;
        add_special_use_param(&mut inputs, use_);

        // Create execution context with storage for OAuth and secrets expansion
        let ctx = crate::adapter::ExecutionContext::new(
            self.storage.clone(),
            self.secrets_provider.clone(),
            self.oauth_client.clone(),
        );

        // Execute with retry if configured
        let outputs = if let Some(ref retry) = step.retry {
            self.execute_with_retry(&adapter, inputs, &ctx, retry)
                .await?
        } else {
            adapter.execute(inputs, &ctx).await?
        };

        step_ctx.set_output(step_id.to_string(), serde_json::to_value(outputs)?);
        Ok(())
    }

    /// Execute with retry logic and exponential backoff
    async fn execute_with_retry(
        &self,
        adapter: &Arc<dyn Adapter>,
        inputs: HashMap<String, Value>,
        ctx: &crate::adapter::ExecutionContext,
        retry: &crate::model::RetrySpec,
    ) -> Result<HashMap<String, Value>> {
        let mut attempts = 0;
        let mut last_error = None;

        while attempts < retry.attempts {
            match adapter.execute(inputs.clone(), ctx).await {
                Ok(outputs) => {
                    if attempts > 0 {
                        tracing::info!(
                            "Step succeeded on attempt {} after {} retries",
                            attempts + 1,
                            attempts
                        );
                    }
                    return Ok(outputs);
                }
                Err(e) => {
                    attempts += 1;
                    last_error = Some(e);

                    if attempts < retry.attempts {
                        let delay = self.calculate_retry_delay(attempts, retry.delay_sec);
                        tracing::debug!(
                            "Retrying step in {} seconds (attempt {} of {})",
                            delay,
                            attempts + 1,
                            retry.attempts
                        );
                        tokio::time::sleep(tokio::time::Duration::from_secs(delay)).await;
                    }
                }
            }
        }

        tracing::error!("Step failed after {} attempts", retry.attempts);
        Err(last_error.unwrap_or_else(|| BeemFlowError::adapter("retry failed")))
    }

    /// Calculate retry delay with exponential backoff
    fn calculate_retry_delay(&self, attempt: u32, base_delay: u64) -> u64 {
        // Exponential backoff: base_delay * 2^(attempt-1)
        // For attempt 1: base_delay * 1
        // For attempt 2: base_delay * 2
        // For attempt 3: base_delay * 4
        // etc.
        // Cap at 5 minutes maximum
        let delay = base_delay * (2_u64.pow(attempt - 1));
        delay.min(300) // Max 5 minutes
    }

    /// Execute a wait step
    pub async fn execute_wait(&self, step: &Step) -> Result<()> {
        if let Some(ref wait) = step.wait
            && let Some(seconds) = wait.seconds
        {
            tokio::time::sleep(tokio::time::Duration::from_secs(seconds)).await;
        }
        Ok(())
    }

    /// Handle await_event step
    ///
    /// Pauses execution and stores state in database.
    /// Webhooks will later query for paused runs by source and resume them.
    async fn handle_await_event(
        &self,
        step: &Step,
        flow: &Flow,
        step_ctx: &StepContext,
        step_idx: usize,
        run_id: Uuid,
    ) -> Result<HashMap<String, Value>> {
        let await_spec = step
            .await_event
            .as_ref()
            .ok_or_else(|| BeemFlowError::validation("missing await_event specification"))?;

        // Generate resume token deterministically from run_id + step_index
        // This makes tokens predictable and eliminates user configuration
        let token = format!("{}-step-{}", run_id, step_idx);

        tracing::info!(
            "Pausing run {} at step '{}', waiting for event from source: {} (resume token: {})",
            run_id,
            step.id,
            await_spec.source,
            token
        );

        // Create paused run
        let paused = PausedRun {
            flow: flow.clone(),
            step_idx,
            context: step_ctx.clone(),
            outputs: step_ctx.snapshot().outputs,
            token: token.to_string(),
            run_id,
        };

        // Store paused run in storage with source metadata for webhook queries
        let paused_value = serde_json::to_value(&paused)?;
        self.storage
            .save_paused_run(&token, &await_spec.source, paused_value)
            .await?;

        Err(BeemFlowError::AwaitEventPause(format!(
            "step '{}' is waiting for event from source '{}'",
            step.id, await_spec.source
        )))
    }

    /// Evaluate a conditional expression
    pub async fn evaluate_condition(
        &self,
        condition: &str,
        step_ctx: &StepContext,
    ) -> Result<bool> {
        // Condition must be in {{ }} format
        let trimmed = condition.trim();
        if !trimmed.starts_with("{{") || !trimmed.ends_with("}}") {
            return Err(BeemFlowError::validation(format!(
                "condition must use template syntax: {{{{ expression }}}}, got: {}",
                condition
            )));
        }

        // Use templater's evaluate_expression to get the actual value
        let template_data = self.get_template_data(step_ctx);
        let value = self
            .templater
            .evaluate_expression(condition, &template_data)?;

        // Check if it's a boolean
        if let Some(b) = value.as_bool() {
            return Ok(b);
        }

        // If it's a string that looks like a boolean
        if let Some(s) = value.as_str() {
            match s.to_lowercase().as_str() {
                "true" => return Ok(true),
                "false" => return Ok(false),
                _ => {}
            }
        }

        // For numbers, non-zero is truthy
        if let Some(n) = value.as_f64() {
            return Ok(n != 0.0);
        }

        // For arrays/objects, non-empty is truthy
        if value.is_array() {
            return Ok(!value.as_array().map(|a| a.is_empty()).unwrap_or(true));
        }
        if value.is_object() {
            return Ok(!value.as_object().map(|o| o.is_empty()).unwrap_or(true));
        }

        // Null is falsy
        Ok(!value.is_null())
    }

    /// Persist step result to storage
    async fn persist_step_result(
        &self,
        step: &Step,
        step_ctx: &StepContext,
        run_id: Uuid,
    ) -> Result<()> {
        let outputs = step_ctx
            .get_output(&step.id)
            .and_then(|v| serde_json::from_value::<HashMap<String, Value>>(v).ok());

        let step_run = crate::model::StepRun {
            id: Uuid::new_v4(),
            run_id,
            step_name: step.id.clone(),
            status: crate::model::StepStatus::Succeeded,
            started_at: chrono::Utc::now(),
            ended_at: Some(chrono::Utc::now()),
            error: None,
            outputs,
        };

        self.storage.save_step(&step_run).await?;
        Ok(())
    }
}
