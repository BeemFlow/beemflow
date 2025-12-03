//! Core adapter for built-in BeemFlow tools

use super::*;
use crate::constants::*;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;

/// Cached regex for matching path parameters in URLs
#[allow(clippy::expect_used)] // Static regex compilation should fail-fast on invalid pattern
static PATH_PARAM_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\{[^}]+\}").expect("Hardcoded path parameter regex pattern is invalid")
});

/// Core adapter handles built-in BeemFlow utilities
pub struct CoreAdapter;

impl Default for CoreAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl CoreAdapter {
    /// Create a new core adapter
    pub fn new() -> Self {
        Self
    }

    /// Execute echo tool - logs text and returns it in output
    async fn execute_echo(&self, inputs: HashMap<String, Value>) -> Result<HashMap<String, Value>> {
        let text = inputs.get("text").and_then(|v| v.as_str()).unwrap_or("");

        // Log to tracing (stderr) instead of stdout to avoid breaking MCP JSON-RPC
        tracing::info!("echo: {}", text);

        // Return inputs but filter out internal fields
        let mut result = HashMap::new();
        for (k, v) in inputs {
            if k != PARAM_SPECIAL_USE {
                result.insert(k, v);
            }
        }

        Ok(result)
    }

    /// Execute wait tool - sleeps for specified duration
    async fn execute_wait(&self, inputs: HashMap<String, Value>) -> Result<HashMap<String, Value>> {
        let seconds = inputs.get("seconds").and_then(|v| v.as_u64()).unwrap_or(1);

        tracing::debug!("Waiting for {} seconds", seconds);
        tokio::time::sleep(tokio::time::Duration::from_secs(seconds)).await;

        // Return the duration waited
        let mut result = HashMap::new();
        result.insert("waited_seconds".to_string(), Value::Number(seconds.into()));

        Ok(result)
    }

    /// Execute log tool - structured logging
    async fn execute_log(&self, inputs: HashMap<String, Value>) -> Result<HashMap<String, Value>> {
        let level = inputs
            .get("level")
            .and_then(|v| v.as_str())
            .unwrap_or("info");

        let message = inputs.get("message").and_then(|v| v.as_str()).unwrap_or("");

        let context = inputs.get("context");

        // Log using macro to consolidate duplicate code
        macro_rules! log_with_context {
            ($level:ident) => {
                if let Some(ctx) = context {
                    tracing::$level!("{} | context: {:?}", message, ctx);
                } else {
                    tracing::$level!("{}", message);
                }
            };
        }

        // Log based on level
        match level.to_lowercase().as_str() {
            "error" => log_with_context!(error),
            "warn" | "warning" => log_with_context!(warn),
            "debug" => log_with_context!(debug),
            _ => log_with_context!(info),
        }

        // Return log info
        let mut result = HashMap::new();
        result.insert("level".to_string(), Value::String(level.to_string()));
        result.insert("message".to_string(), Value::String(message.to_string()));
        if let Some(ctx) = context {
            result.insert("context".to_string(), ctx.clone());
        }

        Ok(result)
    }

    /// Execute convert OpenAPI tool
    async fn execute_convert_openapi(
        &self,
        inputs: HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>> {
        // Get required inputs
        let openapi_val = inputs
            .get("openapi")
            .ok_or_else(|| crate::BeemFlowError::validation("missing required field: openapi"))?;

        // Parse OpenAPI spec
        let spec: HashMap<String, Value> = if openapi_val.is_string() {
            let openapi_str = openapi_val.as_str().ok_or_else(|| {
                crate::BeemFlowError::validation("failed to extract OpenAPI string")
            })?;
            serde_json::from_str(openapi_str).map_err(|e| {
                crate::BeemFlowError::validation(format!("invalid OpenAPI JSON: {}", e))
            })?
        } else if openapi_val.is_object() {
            serde_json::from_value(openapi_val.clone()).map_err(|e| {
                crate::BeemFlowError::validation(format!("invalid OpenAPI JSON: {}", e))
            })?
        } else {
            return Err(crate::BeemFlowError::validation(
                "openapi must be JSON string or object",
            ));
        };

        // Get optional inputs
        let api_name = inputs
            .get("api_name")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_API_NAME);

        let mut base_url = inputs
            .get("base_url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Extract base URL from spec if not provided
        if base_url.is_empty() {
            if let Some(servers) = spec.get("servers").and_then(|v| v.as_array())
                && let Some(server) = servers.first().and_then(|v| v.as_object())
                && let Some(url) = server.get("url").and_then(|v| v.as_str())
            {
                base_url = url.to_string();
            }
            if base_url.is_empty() {
                base_url = DEFAULT_BASE_URL.to_string();
            }
        }

        // Convert OpenAPI paths to BeemFlow tool manifests
        let manifests = self.convert_openapi_to_manifests(&spec, api_name, &base_url)?;

        let mut result = HashMap::new();
        result.insert(
            "manifests".to_string(),
            serde_json::to_value(manifests.clone())?,
        );
        result.insert("count".to_string(), Value::Number(manifests.len().into()));
        result.insert("api_name".to_string(), Value::String(api_name.to_string()));
        result.insert("base_url".to_string(), Value::String(base_url.to_string()));

        Ok(result)
    }

    /// Extract authentication header from OpenAPI security schemes
    ///
    /// Only generates a header when the spec has exactly one HTTP-based auth scheme.
    /// Returns None for API keys, OAuth, or when multiple schemes exist (conservative).
    ///
    /// # Examples
    ///
    /// - HTTP Basic: `Some("Basic $env:TWILIO_AUTH_BASIC")`
    /// - HTTP Bearer: `Some("Bearer $env:STRIPE_API_KEY")`
    /// - Multiple schemes: `None` (conservative - unclear which to use)
    pub fn extract_auth_header(spec: &HashMap<String, Value>, api_name: &str) -> Option<String> {
        // Navigate to components.securitySchemes
        let schemes = spec
            .get("components")?
            .as_object()?
            .get("securitySchemes")?
            .as_object()?;

        // Find all HTTP-based auth schemes
        let http_schemes: Vec<_> = schemes
            .values()
            .filter_map(|v| v.as_object())
            .filter(|scheme| scheme.get("type").and_then(|v| v.as_str()) == Some("http"))
            .collect();

        // Only auto-configure if exactly one HTTP scheme (unambiguous)
        if let Some(&scheme) = http_schemes.first() {
            if http_schemes.len() != 1 {
                // Multiple HTTP schemes - ambiguous, skip auto-config
                return None;
            }
            // api_name is already clean (slugified or user-provided), just uppercase it
            let env_name = api_name.to_uppercase();

            match scheme.get("scheme").and_then(|v| v.as_str()) {
                Some("basic") => {
                    tracing::debug!(
                        "Detected HTTP Basic auth for {} (env var: {}_AUTH_BASIC)",
                        api_name,
                        env_name
                    );
                    Some(format!("Basic $env:{}_AUTH_BASIC", env_name))
                }
                Some("bearer") => {
                    tracing::debug!(
                        "Detected HTTP Bearer auth for {} (env var: {}_API_KEY)",
                        api_name,
                        env_name
                    );
                    Some(format!("Bearer $env:{}_API_KEY", env_name))
                }
                Some(other) => {
                    tracing::warn!("Unsupported HTTP auth scheme '{}' for {}", other, api_name);
                    None
                }
                None => None,
            }
        } else {
            tracing::debug!(
                "Found {} HTTP auth schemes for {}, not auto-configuring auth header",
                http_schemes.len(),
                api_name
            );
            None
        }
    }

    /// Convert OpenAPI spec to BeemFlow tool manifests
    ///
    /// This is the single source of truth for OpenAPI conversion.
    /// Used by both the operation (HTTP/MCP/CLI) and adapter (flow execution).
    pub fn convert_openapi_to_manifests(
        &self,
        spec: &HashMap<String, Value>,
        api_name: &str,
        base_url: &str,
    ) -> Result<Vec<HashMap<String, Value>>> {
        let paths = spec
            .get("paths")
            .and_then(|v| v.as_object())
            .ok_or_else(|| crate::BeemFlowError::validation("no paths found in OpenAPI spec"))?;

        let mut manifests = Vec::new();

        for (path, path_item) in paths {
            // Skip malformed path items
            let Some(path_obj) = path_item.as_object() else {
                tracing::warn!("Skipping malformed path item: {}", path);
                continue;
            };

            for (method, operation) in path_obj {
                if !self.is_valid_http_method(method) {
                    continue;
                }

                // Skip malformed operations
                let Some(op_obj) = operation.as_object() else {
                    tracing::warn!("Skipping malformed operation: {} {}", method, path);
                    continue;
                };

                // Generate tool name
                let tool_name = self.generate_tool_name(api_name, path, method);

                // Extract description
                let description = self.extract_description(op_obj, path);

                // Extract parameters schema
                let parameters = self.extract_parameters(op_obj, method)?;

                // Create manifest
                let mut manifest = HashMap::new();
                manifest.insert("name".to_string(), Value::String(tool_name));
                manifest.insert("description".to_string(), Value::String(description));
                manifest.insert("kind".to_string(), Value::String("task".to_string()));
                manifest.insert("parameters".to_string(), serde_json::to_value(parameters)?);
                manifest.insert(
                    "endpoint".to_string(),
                    Value::String(format!("{}{}", base_url, path)),
                );
                manifest.insert("method".to_string(), Value::String(method.to_uppercase()));

                // Add headers
                let mut headers = HashMap::new();
                headers.insert(
                    HEADER_CONTENT_TYPE.to_string(),
                    self.determine_content_type(op_obj, method),
                );

                // Auto-detect auth from OpenAPI spec
                if let Some(auth_header) = Self::extract_auth_header(spec, api_name) {
                    headers.insert(HEADER_AUTHORIZATION.to_string(), auth_header);
                }

                manifest.insert("headers".to_string(), serde_json::to_value(headers)?);

                manifests.push(manifest);
            }
        }

        Ok(manifests)
    }

    pub fn is_valid_http_method(&self, method: &str) -> bool {
        matches!(
            method.to_lowercase().as_str(),
            "get" | "post" | "put" | "patch" | "delete"
        )
    }

    pub fn generate_tool_name(&self, api_name: &str, path: &str, method: &str) -> String {
        // Clean path
        let mut clean_path = path.trim_start_matches('/').to_string();
        clean_path = clean_path.replace('/', "_");

        // Replace path parameters {param} with _by_id
        clean_path = PATH_PARAM_REGEX
            .replace_all(&clean_path, "_by_id")
            .to_string();

        // Remove non-alphanumeric characters except underscores
        clean_path = clean_path
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();

        // Remove duplicate and trailing underscores
        while clean_path.contains("__") {
            clean_path = clean_path.replace("__", "_");
        }
        clean_path = clean_path.trim_matches('_').to_string();

        // Add method suffix
        let method_suffix = method.to_lowercase();

        if clean_path.is_empty() {
            format!("{}.{}", api_name, method_suffix)
        } else {
            format!("{}.{}_{}", api_name, clean_path, method_suffix)
        }
    }

    pub fn extract_description(
        &self,
        operation: &serde_json::Map<String, Value>,
        path: &str,
    ) -> String {
        operation
            .get("summary")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                operation
                    .get("description")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
            })
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("API endpoint: {}", path))
    }

    /// Extract parameters from an OpenAPI operation
    ///
    /// Combines parameters from both:
    /// - `parameters` array (path, query, header params)
    /// - `requestBody.content[...].schema` (body params for POST/PUT/PATCH)
    ///
    /// Returns a JSON Schema object with merged properties and required fields.
    fn extract_parameters(
        &self,
        operation: &serde_json::Map<String, Value>,
        method: &str,
    ) -> Result<HashMap<String, Value>> {
        let mut all_properties = HashMap::new();
        let mut all_required = Vec::new();

        // Step 1: Extract path/query/header parameters from parameters array
        if let Some(params) = operation.get("parameters").and_then(|v| v.as_array()) {
            self.extract_parameter_array(params, &mut all_properties, &mut all_required)?;
        }

        // Step 2: Extract request body parameters (for POST/PUT/PATCH)
        if method.to_uppercase() != HTTP_METHOD_GET
            && let Some(request_body) = operation.get("requestBody").and_then(|v| v.as_object())
        {
            self.extract_request_body(request_body, &mut all_properties, &mut all_required)?;
        }

        // Step 3: Build final schema
        let mut result = HashMap::new();
        result.insert("type".to_string(), Value::String("object".to_string()));
        result.insert(
            "properties".to_string(),
            serde_json::to_value(all_properties)?,
        );
        result.insert("required".to_string(), Value::Array(all_required));

        Ok(result)
    }

    /// Extract parameters from OpenAPI `parameters` array (path, query, header)
    fn extract_parameter_array(
        &self,
        params: &[Value],
        properties: &mut HashMap<String, Value>,
        required: &mut Vec<Value>,
    ) -> Result<()> {
        for param in params {
            let Some(param_obj) = param.as_object() else {
                continue;
            };

            let Some(name) = param_obj.get("name").and_then(|v| v.as_str()) else {
                continue;
            };

            // Build property schema
            let mut prop = HashMap::new();
            prop.insert("type".to_string(), Value::String("string".to_string()));

            if let Some(desc) = param_obj.get("description").and_then(|v| v.as_str()) {
                prop.insert("description".to_string(), Value::String(desc.to_string()));
            }

            // Extract type and constraints from schema
            if let Some(schema) = param_obj.get("schema").and_then(|v| v.as_object()) {
                if let Some(param_type) = schema.get("type").and_then(|v| v.as_str()) {
                    prop.insert("type".to_string(), Value::String(param_type.to_string()));
                }
                if let Some(enum_vals) = schema.get("enum") {
                    prop.insert("enum".to_string(), enum_vals.clone());
                }
                if let Some(format) = schema.get("format") {
                    prop.insert("format".to_string(), format.clone());
                }
                // Copy other schema properties (pattern, minLength, maxLength, etc.)
                for (key, value) in schema {
                    if !prop.contains_key(key) && key != "type" {
                        prop.insert(key.clone(), value.clone());
                    }
                }
            }

            properties.insert(name.to_string(), serde_json::to_value(prop)?);

            // Check if required
            if param_obj
                .get("required")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                required.push(Value::String(name.to_string()));
            }
        }

        Ok(())
    }

    /// Extract parameters from OpenAPI requestBody
    fn extract_request_body(
        &self,
        request_body: &serde_json::Map<String, Value>,
        properties: &mut HashMap<String, Value>,
        required: &mut Vec<Value>,
    ) -> Result<()> {
        let Some(content) = request_body.get("content").and_then(|v| v.as_object()) else {
            return Ok(());
        };

        // Try application/json first, then application/x-www-form-urlencoded
        let schema = content
            .get(CONTENT_TYPE_JSON)
            .or_else(|| content.get(CONTENT_TYPE_FORM))
            .and_then(|v| v.as_object())
            .and_then(|c| c.get("schema"));

        let Some(schema) = schema else {
            return Ok(());
        };

        // Extract properties from schema
        if let Some(schema_props) = schema.get("properties").and_then(|v| v.as_object()) {
            for (key, value) in schema_props {
                // Don't overwrite path parameters with body parameters
                if !properties.contains_key(key) {
                    properties.insert(key.clone(), value.clone());
                } else {
                    tracing::warn!(
                        "Parameter '{}' defined in both path/query and request body; using path/query definition",
                        key
                    );
                }
            }
        }

        // Extract required fields from schema
        if let Some(schema_required) = schema.get("required").and_then(|v| v.as_array()) {
            for req in schema_required {
                if let Some(req_str) = req.as_str() {
                    // Don't duplicate required fields
                    if !required.iter().any(|v| v.as_str() == Some(req_str)) {
                        required.push(Value::String(req_str.to_string()));
                    }
                }
            }
        }

        Ok(())
    }

    fn determine_content_type(
        &self,
        operation: &serde_json::Map<String, Value>,
        method: &str,
    ) -> String {
        if method.to_uppercase() == HTTP_METHOD_GET {
            return CONTENT_TYPE_JSON.to_string();
        }

        // Check if requestBody specifies form data
        if let Some(request_body) = operation.get("requestBody").and_then(|v| v.as_object())
            && let Some(content) = request_body.get("content").and_then(|v| v.as_object())
            && content.contains_key(CONTENT_TYPE_FORM)
        {
            return CONTENT_TYPE_FORM.to_string();
        }

        CONTENT_TYPE_JSON.to_string()
    }
}

#[async_trait]
impl Adapter for CoreAdapter {
    fn id(&self) -> &str {
        ADAPTER_CORE
    }

    async fn execute(
        &self,
        inputs: HashMap<String, Value>,
        _ctx: &super::ExecutionContext,
    ) -> Result<HashMap<String, Value>> {
        // CoreAdapter doesn't currently use ExecutionContext, but it's available for
        // future features like:
        // - Persisting logs to storage (core.log)
        // - Loading secrets for template expansion
        // - User-specific rate limiting

        let use_field = inputs
            .get(PARAM_SPECIAL_USE)
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::BeemFlowError::adapter("missing __use for CoreAdapter"))?;

        match use_field {
            CORE_ECHO => self.execute_echo(inputs).await,
            CORE_WAIT => self.execute_wait(inputs).await,
            CORE_LOG => self.execute_log(inputs).await,
            CORE_CONVERT_OPENAPI => self.execute_convert_openapi(inputs).await,
            _ => Err(crate::BeemFlowError::adapter(format!(
                "unknown core tool: {}",
                use_field
            ))),
        }
    }

    fn manifest(&self) -> Option<ToolManifest> {
        None
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
