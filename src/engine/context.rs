//! Step execution context
//!
//! Manages event data, variables, outputs, and secrets during workflow execution.
//! Also provides template access to previous run outputs.
//!
//! Optimized for read-heavy workloads:
//! - Event, vars, and secrets are immutable after creation (Arc<HashMap>)
//! - Outputs use DashMap for lock-free concurrent writes

use crate::model::{RunStatus, StepStatus};
use crate::storage::Storage;
use dashmap::DashMap;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// Context for step execution
#[derive(Debug, Clone)]
pub struct StepContext {
    event: Arc<HashMap<String, Value>>,
    vars: Arc<HashMap<String, Value>>,
    outputs: Arc<DashMap<String, Value>>,
    secrets: Arc<HashMap<String, Value>>,
}

// Custom Serialize implementation for StepContext
impl serde::Serialize for StepContext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as a snapshot
        self.snapshot().serialize(serializer)
    }
}

// Custom Deserialize implementation for StepContext
impl<'de> serde::Deserialize<'de> for StepContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize from snapshot
        let snapshot = ContextSnapshot::deserialize(deserializer)?;
        Ok(Self::new(snapshot.event, snapshot.vars, snapshot.secrets))
    }
}

impl StepContext {
    /// Create a new step context
    pub fn new(
        event: HashMap<String, Value>,
        vars: HashMap<String, Value>,
        secrets: HashMap<String, Value>,
    ) -> Self {
        Self {
            event: Arc::new(event),
            vars: Arc::new(vars),
            outputs: Arc::new(DashMap::new()),
            secrets: Arc::new(secrets),
        }
    }

    /// Get an output value
    pub fn get_output(&self, key: &str) -> Option<Value> {
        self.outputs.get(key).map(|v| v.clone())
    }

    /// Set an output value
    pub fn set_output(&self, key: String, value: Value) {
        self.outputs.insert(key, value);
    }

    /// Get a snapshot of the context (cloned data)
    pub fn snapshot(&self) -> ContextSnapshot {
        ContextSnapshot {
            event: (*self.event).clone(),
            vars: (*self.vars).clone(),
            outputs: self
                .outputs
                .iter()
                .map(|r| (r.key().clone(), r.value().clone()))
                .collect(),
            secrets: (*self.secrets).clone(),
        }
    }

    /// Get template data for rendering
    pub fn template_data(&self) -> HashMap<String, Value> {
        self.template_data_with_runs(None)
    }

    /// Get template data with runs access for history
    pub fn template_data_with_runs(
        &self,
        runs_data: Option<HashMap<String, Value>>,
    ) -> HashMap<String, Value> {
        let snapshot = self.snapshot();
        let mut data = HashMap::new();

        // Add structured fields using a helper closure to avoid repetition
        let add_field =
            |data: &mut HashMap<String, Value>, key: &str, value: &HashMap<String, Value>| {
                // Safe: HashMap<String, Value> serialization to JSON Value should never fail
                // as it's already a valid JSON-compatible structure
                if let Ok(json_value) = serde_json::to_value(value) {
                    data.insert(key.to_string(), json_value);
                } else {
                    tracing::warn!(
                        "Failed to serialize field '{}' to JSON, using empty object",
                        key
                    );
                    data.insert(key.to_string(), Value::Object(serde_json::Map::new()));
                }
            };

        add_field(
            &mut data,
            crate::constants::TEMPLATE_FIELD_EVENT,
            &snapshot.event,
        );
        add_field(
            &mut data,
            crate::constants::TEMPLATE_FIELD_VARS,
            &snapshot.vars,
        );
        add_field(
            &mut data,
            crate::constants::TEMPLATE_FIELD_OUTPUTS,
            &snapshot.outputs,
        );
        add_field(
            &mut data,
            crate::constants::TEMPLATE_FIELD_SECRETS,
            &snapshot.secrets,
        );
        add_field(
            &mut data,
            crate::constants::TEMPLATE_FIELD_STEPS,
            &snapshot.outputs,
        );

        // Security: Environment variables are NOT exposed via the "env" namespace.
        // All environment variables are available through the "secrets" namespace,
        // which is populated by Engine::collect_secrets() via the SecretsProvider.
        // This provides a single, controlled interface for all secret access.

        // Add runs access if provided
        if let Some(runs) = runs_data {
            // Safe: HashMap<String, Value> serialization should never fail
            if let Ok(runs_value) = serde_json::to_value(&runs) {
                data.insert("runs".to_string(), runs_value);
            } else {
                tracing::warn!("Failed to serialize runs data, using empty object");
                data.insert("runs".to_string(), Value::Object(serde_json::Map::new()));
            }
        }

        // Add auto-generated variables
        let now = chrono::Utc::now();
        data.insert("now".to_string(), Value::String(now.to_rfc3339()));
        data.insert(
            "timestamp".to_string(),
            Value::Number(now.timestamp().into()),
        );

        // Flatten vars and event for easier access using extend
        data.extend(snapshot.vars);
        data.extend(snapshot.event);

        // Flatten outputs (only valid identifiers)
        data.extend(
            snapshot
                .outputs
                .into_iter()
                .filter(|(k, _)| is_valid_identifier(k)),
        );

        data
    }
}

/// Immutable snapshot of context data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContextSnapshot {
    pub event: HashMap<String, Value>,
    pub vars: HashMap<String, Value>,
    pub outputs: HashMap<String, Value>,
    pub secrets: HashMap<String, Value>,
}

/// Check if a string is a valid identifier (no template syntax)
pub fn is_valid_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    // Check for template syntax
    if s.contains("{{") || s.contains("}}") || s.contains("{%") || s.contains("%}") {
        return false;
    }

    // Safe: We already checked that s is not empty above
    let first = s
        .chars()
        .next()
        .expect("string is not empty after length check");
    if !first.is_alphabetic() && first != '_' {
        return false;
    }

    s.chars().all(|c| c.is_alphanumeric() || c == '_')
}

// ============================================================================
// Previous Run Access
// ============================================================================

/// Provides template access to previous run outputs
///
/// This helper allows accessing outputs from the most recent previous run
/// of the same workflow through the `runs.previous` template variable.
#[derive(Clone)]
pub struct RunsAccess {
    storage: Arc<dyn Storage>,
    current_run_id: Option<Uuid>,
    flow_name: String,
    organization_id: String,
}

impl RunsAccess {
    /// Create a new runs access helper
    pub fn new(
        storage: Arc<dyn Storage>,
        current_run_id: Option<Uuid>,
        flow_name: String,
        organization_id: String,
    ) -> Self {
        Self {
            storage,
            current_run_id,
            flow_name,
            organization_id,
        }
    }

    /// Get outputs from the most recent previous run of the same workflow
    ///
    /// Returns a map with:
    /// - id: Run ID as string
    /// - outputs: Map of step outputs
    /// - status: Run status
    /// - flow: Flow name
    ///
    /// Returns empty map if no previous run found.
    pub async fn previous(&self) -> HashMap<String, Value> {
        // Use optimized query to fetch only matching runs (database-level filtering)
        // Uses organization_id from the current execution context for organization isolation
        let runs = match self
            .storage
            .list_runs_by_flow_and_status(
                &self.organization_id,
                &self.flow_name,
                RunStatus::Succeeded,
                self.current_run_id,
                1, // Only need the most recent
            )
            .await
        {
            Ok(runs) => runs,
            Err(e) => {
                tracing::warn!("Failed to query previous runs: {}", e);
                return HashMap::new();
            }
        };

        // Take the first (most recent) run if available
        let run = match runs.first() {
            Some(run) => run,
            None => {
                tracing::debug!(
                    "No previous successful run found for flow '{}'",
                    self.flow_name
                );
                return HashMap::new();
            }
        };

        tracing::debug!(
            "Found previous successful run: id={}, flow={}",
            run.id,
            run.flow_name
        );

        // Get step outputs for this run
        let steps = match self.storage.get_steps(run.id).await {
            Ok(steps) => steps,
            Err(e) => {
                tracing::warn!("Failed to get steps for run {}: {}", run.id, e);
                return HashMap::new();
            }
        };

        // Aggregate step outputs
        let mut outputs = HashMap::new();
        for step in steps {
            if step.status == StepStatus::Succeeded
                && let Some(ref step_outputs) = step.outputs
            {
                outputs.insert(
                    step.step_name.clone(),
                    serde_json::to_value(step_outputs).unwrap_or(Value::Null),
                );
            }
        }

        tracing::debug!(
            "Returning previous run data with {} step outputs",
            outputs.len()
        );

        // Return the run data
        serde_json::json!({
            "id": run.id.to_string(),
            "outputs": outputs,
            "status": format!("{:?}", run.status),
            "flow": run.flow_name,
        })
        .as_object()
        .map(|obj| obj.clone().into_iter().collect())
        .unwrap_or_default()
    }
}
