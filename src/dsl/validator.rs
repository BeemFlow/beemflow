//! Flow validator with comprehensive validation rules
//!
//! Validates flow definitions according to the BeemFlow specification,
//! ensuring all required fields are present, step IDs are unique,
//! dependencies are valid, and step constraints are met.

use crate::{BeemFlowError, Flow, Result, Step};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashMap, HashSet};

/// Embedded BeemFlow JSON Schema
const BEEMFLOW_SCHEMA: &str = include_str!("../../docs/beemflow.schema.json");

/// Cached compiled JSON Schema
#[allow(clippy::expect_used)] // Static schema compilation should fail-fast on invalid schema
static SCHEMA: Lazy<jsonschema::Validator> = Lazy::new(|| {
    let schema_value: serde_json::Value =
        serde_json::from_str(BEEMFLOW_SCHEMA).expect("Failed to parse embedded BeemFlow schema");

    jsonschema::validator_for(&schema_value).expect("Failed to compile BeemFlow schema")
});

/// Cached identifier validation regex
#[allow(clippy::expect_used)] // Static regex compilation should fail-fast on invalid pattern
static IDENTIFIER_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]*$").expect("Hardcoded identifier regex pattern is invalid")
});

pub struct Validator;

impl Validator {
    /// Validate a flow for correctness
    ///
    /// Performs comprehensive validation including:
    /// - JSON Schema validation against BeemFlow schema
    /// - Required fields (name, steps)
    /// - Unique step IDs
    /// - Valid identifiers
    /// - Step constraints (parallel, foreach, etc.)
    /// - Dependencies (including circular detection)
    /// - Template syntax
    /// - Nested step validation
    pub fn validate(flow: &Flow) -> Result<()> {
        // First, validate against JSON Schema
        Self::validate_schema(flow)?;

        // Then perform additional Rust-specific validations
        Self::validate_required_fields(flow)?;
        Self::validate_step_ids_unique(flow)?;
        Self::validate_dependencies(flow)?;
        Self::detect_circular_dependencies(flow)?; // Detect cycles in dependency graph
        Self::validate_step_constraints(flow)?;
        Self::validate_nested_steps(flow)?;
        Ok(())
    }

    /// Validate flow against JSON Schema
    fn validate_schema(flow: &Flow) -> Result<()> {
        // Convert flow to JSON value for schema validation
        let flow_json = serde_json::to_value(flow)
            .map_err(|e| BeemFlowError::validation(format!("Failed to serialize flow: {}", e)))?;

        // Check if valid
        if !SCHEMA.is_valid(&flow_json) {
            // Collect all validation errors
            let error_messages: Vec<String> = SCHEMA
                .iter_errors(&flow_json)
                .map(|e| format!("{}: {}", e.instance_path, e))
                .collect();

            return Err(BeemFlowError::validation(format!(
                "Schema validation failed:\n  - {}",
                error_messages.join("\n  - ")
            )));
        }

        Ok(())
    }

    fn validate_required_fields(flow: &Flow) -> Result<()> {
        if flow.name.is_empty() {
            return Err(BeemFlowError::validation("Flow name is required"));
        }

        if flow.steps.is_empty() {
            return Err(BeemFlowError::validation(
                "Flow must have at least one step",
            ));
        }

        Ok(())
    }

    fn validate_step_ids_unique(flow: &Flow) -> Result<()> {
        let mut seen = HashSet::new();

        for step in &flow.steps {
            if !seen.insert(&step.id) {
                return Err(BeemFlowError::validation(format!(
                    "Duplicate step ID: {}",
                    step.id
                )));
            }
        }

        Ok(())
    }

    fn validate_dependencies(flow: &Flow) -> Result<()> {
        let step_ids: HashSet<_> = flow.steps.iter().map(|s| s.id.as_str()).collect();

        for step in &flow.steps {
            if let Some(deps) = &step.depends_on {
                for dep in deps {
                    if !step_ids.contains(dep.as_str()) {
                        return Err(BeemFlowError::validation(format!(
                            "Step '{}' depends on non-existent step '{}'",
                            step.id, dep
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    fn validate_step_constraints(flow: &Flow) -> Result<()> {
        for step in &flow.steps {
            Self::validate_single_step(step)?;
        }

        // Also validate catch blocks if present
        if let Some(catch_steps) = &flow.catch {
            for step in catch_steps {
                Self::validate_single_step(step)?;
            }
        }

        Ok(())
    }

    fn validate_single_step(step: &Step) -> Result<()> {
        // Step ID must be valid identifier
        Self::validate_identifier(&step.id)?;

        // Count primary actions
        let mut action_count = 0;

        if step.use_.is_some() {
            action_count += 1;
        }
        // Parallel block: parallel=true + steps (counts as an action)
        if step.parallel == Some(true) && step.steps.is_some() {
            action_count += 1;
        }
        // Foreach loop: foreach + do (parallel=true just makes it run in parallel, not a separate action)
        if step.foreach.is_some() {
            action_count += 1;
        }
        if step.await_event.is_some() {
            action_count += 1;
        }
        if step.wait.is_some() {
            action_count += 1;
        }

        // Step must have exactly ONE primary action (or none for sequential blocks)
        if step.steps.is_some() && step.parallel != Some(true) {
            // Sequential block - this is OK
        } else if action_count == 0 {
            return Err(BeemFlowError::validation(format!(
                "Step '{}' must have one of: use, parallel+steps, foreach+as+do, await_event, or wait",
                step.id
            )));
        } else if action_count > 1 {
            return Err(BeemFlowError::validation(format!(
                "Step '{}' can only have ONE of: use, parallel, foreach, await_event, or wait",
                step.id
            )));
        }

        // Parallel must have either steps (parallel block) or foreach+do (parallel foreach)
        if step.parallel == Some(true) {
            if step.steps.is_none() && step.foreach.is_none() {
                return Err(BeemFlowError::validation(format!(
                    "Parallel step '{}' must have either 'steps' (parallel block) or 'foreach'+'do' (parallel foreach)",
                    step.id
                )));
            }

            // Cannot have 'use' with parallel
            if step.use_.is_some() {
                return Err(BeemFlowError::validation(format!(
                    "Step '{}' cannot have both 'parallel' and 'use'",
                    step.id
                )));
            }
        }

        // Foreach must have 'as' and 'do'
        if let Some(foreach_expr) = &step.foreach {
            let Some(as_field) = &step.as_ else {
                return Err(BeemFlowError::validation(format!(
                    "Foreach step '{}' must have 'as' field",
                    step.id
                )));
            };
            if step.do_.is_none() {
                return Err(BeemFlowError::validation(format!(
                    "Foreach step '{}' must have 'do' field",
                    step.id
                )));
            }

            // Validate foreach expression is templated
            if !Self::is_template_syntax(foreach_expr) {
                return Err(BeemFlowError::validation(format!(
                    "Foreach expression in step '{}' should use template syntax: {{ }} ",
                    step.id
                )));
            }

            // Validate 'as' is a valid identifier
            Self::validate_identifier(as_field)?;

            // Cannot have 'use' with foreach
            if step.use_.is_some() {
                return Err(BeemFlowError::validation(format!(
                    "Step '{}' cannot have both 'foreach' and 'use'",
                    step.id
                )));
            }
        }

        // Validate conditional syntax if present
        if let Some(condition) = &step.if_
            && !Self::is_template_syntax(condition)
        {
            return Err(BeemFlowError::validation(format!(
                "Conditional in step '{}' must use template syntax: {{ }}",
                step.id
            )));
        }

        // Await event must have source and match
        if let Some(await_spec) = &step.await_event {
            if await_spec.source.is_empty() {
                return Err(BeemFlowError::validation(format!(
                    "Await event in step '{}' must have 'source' field",
                    step.id
                )));
            }
            if await_spec.match_.is_empty() {
                return Err(BeemFlowError::validation(format!(
                    "Await event in step '{}' must have 'match' field",
                    step.id
                )));
            }
        }

        // Wait must have seconds or until
        if let Some(wait_spec) = &step.wait
            && wait_spec.seconds.is_none()
            && wait_spec.until.is_none()
        {
            return Err(BeemFlowError::validation(format!(
                "Wait in step '{}' must have 'seconds' or 'until' field",
                step.id
            )));
        }

        Ok(())
    }

    fn validate_nested_steps(flow: &Flow) -> Result<()> {
        for step in &flow.steps {
            // Validate steps in parallel blocks
            if let Some(nested_steps) = &step.steps {
                for nested in nested_steps {
                    Self::validate_single_step(nested)?;
                }
            }

            // Validate steps in foreach blocks
            if let Some(do_steps) = &step.do_ {
                for nested in do_steps {
                    Self::validate_single_step(nested)?;
                }
            }
        }

        Ok(())
    }

    /// Validate that a string is a valid identifier (alphanumeric + underscore)
    fn validate_identifier(id: &str) -> Result<()> {
        if id.is_empty() {
            return Err(BeemFlowError::validation("Identifier cannot be empty"));
        }

        // Check for template syntax in ID (which would indicate dynamic IDs that need rendering)
        if id.contains("{{") || id.contains("}}") {
            // Dynamic IDs are OK - they'll be rendered at runtime
            return Ok(());
        }

        // For static IDs, validate they follow identifier rules
        if !IDENTIFIER_REGEX.is_match(id) {
            return Err(BeemFlowError::validation(format!(
                "Invalid identifier '{}': must start with letter or underscore, contain only alphanumeric and underscore",
                id
            )));
        }

        Ok(())
    }

    /// Check if a string contains template syntax
    fn is_template_syntax(s: &str) -> bool {
        s.contains("{{") && s.contains("}}")
    }

    /// Detect circular dependencies in steps
    fn detect_circular_dependencies(flow: &Flow) -> Result<()> {
        let mut graph: HashMap<String, Vec<String>> = HashMap::new();

        // Build dependency graph
        for step in &flow.steps {
            let deps = if let Some(depends_on) = &step.depends_on {
                depends_on.to_vec()
            } else {
                vec![]
            };
            graph.insert(step.id.to_string(), deps);
        }

        // Check for cycles using DFS
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();

        for step in &flow.steps {
            if !visited.contains(step.id.as_str())
                && Self::has_cycle(step.id.as_str(), &graph, &mut visited, &mut rec_stack)
            {
                return Err(BeemFlowError::validation(format!(
                    "Circular dependency detected involving step '{}'",
                    step.id
                )));
            }
        }

        Ok(())
    }

    fn has_cycle<'a>(
        step_id: &'a str,
        graph: &'a HashMap<String, Vec<String>>,
        visited: &mut HashSet<&'a str>,
        rec_stack: &mut HashSet<&'a str>,
    ) -> bool {
        visited.insert(step_id);
        rec_stack.insert(step_id);

        if let Some(deps) = graph.get(step_id) {
            for dep in deps {
                if !visited.contains(dep.as_str()) {
                    if Self::has_cycle(dep.as_str(), graph, visited, rec_stack) {
                        return true;
                    }
                } else if rec_stack.contains(dep.as_str()) {
                    return true;
                }
            }
        }

        rec_stack.remove(step_id);
        false
    }
}
