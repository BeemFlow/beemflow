//! HTTP adapter for making HTTP requests

use super::*;
use crate::constants::*;
use reqwest::{Client, Method};
use std::str::FromStr;

/// Type alias for HTTP request components (method, url, headers, body)
type HttpRequestComponents = (String, String, HashMap<String, String>, Option<Value>);

/// HTTP adapter for generic HTTP requests and registry tools
pub struct HttpAdapter {
    adapter_id: String,
    tool_manifest: Option<ToolManifest>,
    client: Client,
}

impl HttpAdapter {
    /// Create a new HTTP adapter
    pub fn new(adapter_id: String, tool_manifest: Option<ToolManifest>) -> Self {
        Self {
            adapter_id,
            tool_manifest,
            client: Client::new(),
        }
    }

    /// Execute HTTP request based on manifest or generic http call
    ///
    /// Secrets ($env:) and OAuth tokens ($oauth:) in headers are automatically expanded:
    /// - $env: patterns are expanded using the ExecutionContext's secrets_provider
    /// - $oauth: patterns are expanded using the ExecutionContext's storage
    async fn execute_request(
        &self,
        inputs: HashMap<String, Value>,
        ctx: &super::ExecutionContext,
    ) -> Result<HashMap<String, Value>> {
        // Build request based on manifest or inputs
        let (url, method, mut headers, body) = if let Some(manifest) = &self.tool_manifest {
            // If manifest has endpoint, use it; otherwise fall back to inputs
            if manifest.endpoint.is_some() {
                self.build_from_manifest(manifest, &inputs, &ctx.secrets_provider)
                    .await?
            } else {
                // Manifest exists but no endpoint - generic HTTP like http.fetch
                self.build_from_inputs(&inputs)?
            }
        } else {
            self.build_from_inputs(&inputs)?
        };

        // Expand OAuth tokens in headers with automatic refresh
        self.expand_oauth_in_headers(&mut headers, &ctx.oauth_client)
            .await;

        // Create request
        let method_str = method.clone(); // Keep for error messages
        let method = Method::from_str(&method)
            .map_err(|e| crate::BeemFlowError::adapter(format!("invalid HTTP method: {}", e)))?;

        let mut request = self.client.request(method, &url);

        // Add headers with validation
        for (k, v) in &headers {
            // Validate header value - reqwest rejects invalid characters
            Self::validate_header_value(k, v)?;
            request = request.header(k, v);
        }

        // Add body if present
        if let Some(body_val) = body {
            request = Self::encode_request_body(request, &headers, &body_val)?;
        }

        // Execute request
        let response = request.send().await.map_err(|e| {
            crate::BeemFlowError::Network(crate::error::NetworkError::Http(e.to_string()))
        })?;

        // Check status code
        let status = response.status();

        // Extract response body
        let body_text = response.text().await.map_err(|e| {
            crate::BeemFlowError::Network(crate::error::NetworkError::Http(e.to_string()))
        })?;

        // Return error for non-2xx status codes
        if !status.is_success() {
            return Err(crate::BeemFlowError::Network(
                crate::error::NetworkError::Http(format!(
                    "HTTP {} {}: status {}: {}",
                    method_str,
                    url,
                    status.as_u16(),
                    body_text
                )),
            ));
        }

        // Try to parse as JSON
        if let Ok(json_value) = serde_json::from_str::<Value>(&body_text) {
            // For JSON objects, return the object directly (unwrapped)
            if let Some(obj) = json_value.as_object() {
                return Ok(obj.clone().into_iter().collect());
            }
            // For JSON arrays or primitives, wrap in body
            let mut result = HashMap::new();
            result.insert("body".to_string(), json_value);
            return Ok(result);
        }

        // For non-JSON responses, wrap in body
        let mut result = HashMap::new();
        result.insert("body".to_string(), Value::String(body_text));
        Ok(result)
    }

    async fn build_from_manifest(
        &self,
        manifest: &ToolManifest,
        inputs: &HashMap<String, Value>,
        secrets_provider: &Arc<dyn crate::secrets::SecretsProvider>,
    ) -> Result<HttpRequestComponents> {
        let mut url = manifest
            .endpoint
            .as_ref()
            .ok_or_else(|| crate::BeemFlowError::adapter("manifest missing endpoint"))?
            .clone();

        let method = manifest
            .method
            .as_ref()
            .unwrap_or(&HTTP_METHOD_GET.to_string())
            .clone();

        // Track which parameters are used in the URL path
        let mut path_params = std::collections::HashSet::new();

        // Render URL template with input parameters
        // Replace {param} with values from inputs
        for (key, value) in inputs {
            let placeholder = format!("{{{}}}", key);
            if url.contains(&placeholder) {
                path_params.insert(key.clone());
                let value_str = match value {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => serde_json::to_string(value)?,
                };
                url = url.replace(&placeholder, &value_str);
            }
        }

        // Process headers with secret expansion
        let mut headers = HashMap::new();
        if let Some(ref manifest_headers) = manifest.headers {
            for (k, v) in manifest_headers {
                let expanded = self.expand_header_value(v, secrets_provider).await?;
                headers.insert(k.clone(), expanded);
            }
        }

        // Build body from inputs for non-GET requests
        let body = if method.to_uppercase() != HTTP_METHOD_GET {
            // Filter out path parameters from the body
            let body_inputs: HashMap<String, Value> = inputs
                .iter()
                .filter(|(k, _)| !path_params.contains(*k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();

            if !body_inputs.is_empty() {
                Some(serde_json::to_value(body_inputs)?)
            } else {
                None
            }
        } else {
            None
        };

        Ok((url, method, headers, body))
    }

    /// Expand $env: references in header values using the secrets provider
    ///
    /// This uses the centralized secrets::expand_value() function to ensure:
    /// - Consistent secret expansion across the codebase (DRY)
    /// - Support for future secret backends (AWS, Vault)
    /// - Proper error handling for missing secrets
    ///
    /// OAuth expansion ($oauth:) is deferred to execution time via expand_oauth_in_headers().
    /// Automatically trims whitespace from expanded values.
    async fn expand_header_value(
        &self,
        value: &str,
        secrets_provider: &Arc<dyn crate::secrets::SecretsProvider>,
    ) -> Result<String> {
        // OAuth expansion is deferred to execution time - just pass through
        if value.starts_with("$oauth:") {
            return Ok(value.to_string());
        }

        // Use centralized secret expansion for $env: patterns
        let expanded = crate::secrets::expand_value(value, secrets_provider).await?;

        // Strict validation: ensure all $env: patterns were fully expanded
        // This is critical for auth headers - fail fast if secrets are missing
        if expanded.contains("$env:") {
            return Err(crate::BeemFlowError::adapter(format!(
                "Failed to expand all secrets in header value: '{}'. \
                Ensure all referenced environment variables are set in your .env file or environment.",
                value
            )));
        }

        // Trim whitespace/newlines (common issue with secrets from CI/CD)
        Ok(expanded.trim().to_string())
    }

    /// Expand OAuth tokens in headers at execution time with automatic refresh
    ///
    /// Searches for headers with `$oauth:provider:integration` placeholders and replaces
    /// them with actual OAuth access tokens, automatically refreshing expired tokens. For example:
    ///
    /// ```text
    /// Authorization: $oauth:github:default
    /// ```
    ///
    /// Becomes:
    ///
    /// ```text
    /// Authorization: Bearer ghp_abc123...
    /// ```
    ///
    /// This allows registry tool definitions to specify OAuth requirements without
    /// hardcoding credentials. Tokens are automatically refreshed if expired (with 5-minute buffer).
    async fn expand_oauth_in_headers(
        &self,
        headers: &mut HashMap<String, String>,
        oauth_client: &Arc<crate::auth::OAuthClientManager>,
    ) {
        let oauth_headers: Vec<_> = headers
            .iter()
            .filter(|(_, v)| v.starts_with("$oauth:"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        for (key, value) in oauth_headers {
            if let Some(token) = self.expand_oauth_token(&value, oauth_client).await {
                headers.insert(key, format!("Bearer {}", token));
            }
        }
    }

    /// Expand a single OAuth token reference with automatic refresh
    ///
    /// Parses the OAuth reference and uses OAuthClientManager.get_token() which:
    /// - Checks if the token is expired (with 5-minute buffer)
    /// - Automatically refreshes the token using the refresh token if needed
    /// - Updates storage with the new access token
    /// - Returns the valid (possibly refreshed) access token
    ///
    /// This ensures OAuth API calls always use fresh tokens without manual intervention.
    async fn expand_oauth_token(
        &self,
        value: &str,
        oauth_client: &Arc<crate::auth::OAuthClientManager>,
    ) -> Option<String> {
        let oauth_ref = value.trim_start_matches("$oauth:");
        let mut parts = oauth_ref.split(':');
        let (provider, integration) = (parts.next()?, parts.next()?);

        match oauth_client.get_token(provider, integration).await {
            Ok(token) => Some(token),
            Err(e) => {
                tracing::error!(
                    "Failed to get OAuth token for {}:{} - {}",
                    provider,
                    integration,
                    e
                );
                None
            }
        }
    }

    fn build_from_inputs(&self, inputs: &HashMap<String, Value>) -> Result<HttpRequestComponents> {
        let url = inputs
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::BeemFlowError::adapter("missing url for HTTP request"))?
            .to_string();

        let method = self.extract_method(inputs);
        let headers = self.extract_headers(inputs);
        let body = inputs.get("body").cloned();

        Ok((url, method, headers, body))
    }

    // ========================================
    // HELPER METHODS (used by tests)
    // ========================================

    /// Extract headers from inputs
    fn extract_headers(&self, inputs: &HashMap<String, Value>) -> HashMap<String, String> {
        inputs
            .get("headers")
            .and_then(|v| {
                if let Some(obj) = v.as_object() {
                    let mut headers = HashMap::new();
                    for (k, v) in obj {
                        if let Some(s) = v.as_str() {
                            headers.insert(k.clone(), s.to_string());
                        }
                    }
                    Some(headers)
                } else {
                    None
                }
            })
            .unwrap_or_default()
    }

    /// Extract method from inputs, default to GET
    fn extract_method(&self, inputs: &HashMap<String, Value>) -> String {
        inputs
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or(HTTP_METHOD_GET)
            .to_string()
    }

    /// Validate header value doesn't contain control characters
    fn validate_header_value(name: &str, value: &str) -> Result<()> {
        if value.chars().any(|c| c.is_control() && c != '\t') {
            return Err(crate::BeemFlowError::adapter(format!(
                "Header '{}' contains invalid control characters (length: {} chars). \
                This usually means the environment variable has trailing newlines. \
                Check the secret configuration in GitHub Actions or your .env file.",
                name,
                value.len()
            )));
        }
        Ok(())
    }

    /// Encode request body based on Content-Type header
    ///
    /// Supports:
    /// - `application/x-www-form-urlencoded`: Form encoding for APIs like Twilio
    /// - `application/json`: JSON encoding (default for objects/arrays)
    /// - Plain text: Direct string body
    fn encode_request_body(
        request: reqwest::RequestBuilder,
        headers: &HashMap<String, String>,
        body: &Value,
    ) -> Result<reqwest::RequestBuilder> {
        // Check if Content-Type indicates form encoding
        let is_form_encoded = headers
            .get("Content-Type")
            .or_else(|| headers.get("content-type"))
            .map(|ct| {
                ct.to_lowercase()
                    .contains("application/x-www-form-urlencoded")
            })
            .unwrap_or(false);

        match (is_form_encoded, body) {
            // Form-encoded object
            (true, Value::Object(obj)) => {
                let form_data: Vec<(String, String)> = obj
                    .iter()
                    .map(|(k, v)| (k.clone(), Self::json_value_to_string(v)))
                    .collect();
                Ok(request.form(&form_data))
            }
            // JSON for objects and arrays
            (false, Value::Object(_)) | (false, Value::Array(_)) => Ok(request.json(body)),
            // Plain string body
            (_, Value::String(s)) => Ok(request.body(s.clone())),
            // Everything else: attempt JSON encoding
            _ => Ok(request.json(body)),
        }
    }

    /// Convert a JSON value to a string representation for form encoding
    fn json_value_to_string(value: &Value) -> String {
        match value {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Null => String::new(),
            other => serde_json::to_string(other).unwrap_or_default(),
        }
    }

    /// Enrich inputs with defaults from manifest parameters
    ///
    /// Expands $env: patterns in default values using the secrets provider.
    /// This ensures consistent secret handling across all parameter sources.
    async fn enrich_inputs_with_defaults(
        &self,
        mut inputs: HashMap<String, Value>,
        secrets_provider: &Arc<dyn crate::secrets::SecretsProvider>,
    ) -> HashMap<String, Value> {
        if let Some(manifest) = &self.tool_manifest
            && let Some(properties) = manifest
                .parameters
                .get("properties")
                .and_then(|v| v.as_object())
        {
            for (key, prop_def) in properties {
                // Only set default if input doesn't already have this key
                if !inputs.contains_key(key)
                    && let Some(prop_obj) = prop_def.as_object()
                    && let Some(default) = prop_obj.get("default")
                {
                    // Handle environment variable expansion in defaults
                    if let Some(default_str) = default.as_str() {
                        if default_str.starts_with("$env:") {
                            let var_name = default_str.trim_start_matches("$env:");
                            // Use secrets provider for consistent secret access
                            if let Ok(Some(secret_val)) =
                                secrets_provider.get_secret(var_name).await
                            {
                                inputs.insert(key.clone(), Value::String(secret_val));
                            }
                            // If secret not found, don't insert default (parameter remains unset)
                        } else {
                            inputs.insert(key.clone(), default.clone());
                        }
                    } else {
                        inputs.insert(key.clone(), default.clone());
                    }
                }
            }
        }
        inputs
    }
}

#[async_trait]
impl Adapter for HttpAdapter {
    fn id(&self) -> &str {
        &self.adapter_id
    }

    async fn execute(
        &self,
        inputs: HashMap<String, Value>,
        ctx: &super::ExecutionContext,
    ) -> Result<HashMap<String, Value>> {
        // Enrich inputs with defaults from manifest if present
        // This uses secrets_provider to expand $env: patterns in default values
        let enriched_inputs = self
            .enrich_inputs_with_defaults(inputs, &ctx.secrets_provider)
            .await;
        self.execute_request(enriched_inputs, ctx).await
    }

    fn manifest(&self) -> Option<ToolManifest> {
        self.tool_manifest.clone()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
