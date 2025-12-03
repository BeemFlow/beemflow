//! Pure minijinja templating engine
//!
//! This module provides Django/Jinja2-style templating using minijinja's native syntax.
//! BeemFlow-specific extensions:
//! - item_index/item_row: Available in foreach loops (set by executor)
//! - defined/undefined tests: For checking if variables exist

use crate::Result;
use crate::error::TemplateError;
use minijinja::{Environment, Value};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::sync::Arc;

/// Templater provides pure minijinja template rendering
pub struct Templater {
    env: Arc<Environment<'static>>,
}

impl Templater {
    /// Create a new templater with minijinja's built-in filters
    pub fn new() -> Self {
        let mut env = Environment::new();

        // Register ONLY BeemFlow-specific extensions
        Self::register_beemflow_extensions(&mut env);

        // Configure environment for template rendering
        env.set_auto_escape_callback(|_| minijinja::AutoEscape::None);

        // Set undefined behavior to chainable (allow chaining on undefined)
        // This allows {{nonexistent.field}} to return undefined instead of error
        env.set_undefined_behavior(minijinja::UndefinedBehavior::Chainable);

        // Security: Environment variables are NOT exposed as a global "env" object.
        // All environment variable access must go through the "secrets" namespace
        // which is populated by Engine::collect_secrets() via the SecretsProvider.

        Self { env: Arc::new(env) }
    }

    /// Register BeemFlow-specific extensions (NOT standard minijinja filters)
    ///
    /// Note: We do NOT register standard filters like upper, lower, length, join, etc.
    /// because minijinja already provides these with better implementations.
    ///
    /// BeemFlow extensions:
    /// - defined/undefined tests: Check if variables exist
    fn register_beemflow_extensions(env: &mut Environment<'static>) {
        // Add tests for checking if variables are defined
        // These are useful for workflow conditionals
        env.add_test("defined", |value: Value| !value.is_undefined());
        env.add_test("undefined", |value: Value| value.is_undefined());

        // Note: item_index and item_row are NOT filters - they're variables
        // injected by the executor during foreach loop execution
        // (see executor.rs:216-217, 256-257)
    }

    /// Render a template string with the provided data
    ///
    /// # Arguments
    /// * `template` - Template string with {{ }} syntax using minijinja
    /// * `data` - Context data for template rendering
    ///
    /// # Example
    /// ```no_run
    /// use std::collections::HashMap;
    /// use serde_json::json;
    /// use beemflow::dsl::Templater;
    ///
    /// let templater = Templater::new();
    /// let mut data = HashMap::new();
    /// data.insert("name".to_string(), json!("BeemFlow"));
    ///
    /// let result = templater.render("Hello, {{ name }}!", &data).unwrap();
    /// assert_eq!(result, "Hello, BeemFlow!");
    /// ```
    pub fn render(&self, template: &str, data: &HashMap<String, JsonValue>) -> Result<String> {
        // Convert HashMap<String, JsonValue> to minijinja context
        let context = self.json_to_minijinja_context(data);

        self.env
            .render_str(template, context)
            .map_err(|e| crate::BeemFlowError::from(TemplateError::Syntax(e.to_string())))
    }

    /// Evaluate a template expression and return the actual value (not rendered as string)
    ///
    /// This is crucial for foreach loops where we need the actual array/object,
    /// not a string representation.
    ///
    /// # Example
    /// ```rust
    /// use beemflow::dsl::Templater;
    /// use std::collections::HashMap;
    /// use serde_json::json;
    ///
    /// let templater = Templater::new();
    /// let mut data = HashMap::new();
    /// data.insert("items".to_string(), json!(["a", "b", "c"]));
    ///
    /// let result = templater.evaluate_expression("{{ items }}", &data).unwrap();
    /// assert!(result.is_array());
    /// ```
    pub fn evaluate_expression(
        &self,
        expr: &str,
        data: &HashMap<String, JsonValue>,
    ) -> Result<JsonValue> {
        let trimmed = expr.trim();

        // Handle simple variable expressions: {{ varname }} or {{ obj.field }}
        if trimmed.starts_with("{{") && trimmed.ends_with("}}") {
            let var_path = trimmed[2..trimmed.len() - 2].trim();

            // Skip if it has filters or complex logic
            if !var_path.contains('|')
                && !var_path.contains('(')
                && !var_path.contains('+')
                && !var_path.contains('-')
                && !var_path.contains('*')
                && !var_path.contains('/')
            {
                // Try direct lookup
                if let Some(val) = data.get(var_path) {
                    return Ok(val.clone());
                }

                // Try nested path lookup (e.g., "vars.items", "data.rows[0]")
                if var_path.contains('.')
                    && let Some(val) = self.lookup_nested_path(data, var_path)
                {
                    return Ok(val.clone());
                }
            }
        }

        // For complex expressions or when direct lookup fails, render and try to parse
        let rendered = self.render(expr, data)?;

        // Try to parse as JSON (could be array, object, etc.)
        if let Ok(value) = serde_json::from_str::<JsonValue>(&rendered) {
            return Ok(value);
        }

        // Return as string if not valid JSON
        Ok(JsonValue::String(rendered))
    }

    /// Lookup a nested path in data (e.g., "vars.items", "data.rows[0]", "array[0].name")
    ///
    /// Supports:
    /// - Object field access: data.field
    /// - Array index access: array[0], array[1]
    /// - Nested combinations: data.rows[0].name
    fn lookup_nested_path<'a>(
        &self,
        data: &'a HashMap<String, JsonValue>,
        path: &str,
    ) -> Option<&'a JsonValue> {
        let parts: Vec<&str> = path.split('.').collect();
        let (first, rest) = parts.split_first()?;
        let mut current = data.get(*first)?;

        for part in rest {
            // Try as object key
            if let Some(obj) = current.as_object()
                && let Some(val) = obj.get(*part)
            {
                current = val;
                continue;
            }

            // Try as array index
            if let Some(arr) = current.as_array()
                && let Ok(idx) = part.parse::<usize>()
            {
                current = arr.get(idx)?;
                continue;
            }

            // Path not found
            return None;
        }

        Some(current)
    }

    /// Convert JSON HashMap to minijinja Value
    fn json_to_minijinja_context(&self, data: &HashMap<String, JsonValue>) -> Value {
        // Convert to serde_json::Map first, then to minijinja Value
        let mut obj = serde_json::Map::new();

        for (key, value) in data {
            obj.insert(key.clone(), value.clone());
        }

        // minijinja can convert from serde_json::Value directly
        Value::from_serialize(JsonValue::Object(obj))
    }
}

impl Default for Templater {
    fn default() -> Self {
        Self::new()
    }
}
