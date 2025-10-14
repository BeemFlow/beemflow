//! MCP adapter - Routes workflow mcp:// tool calls to MCP manager

use super::*;
use crate::constants::*;
use crate::mcp::McpManager;
use crate::model::McpServerConfig;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// MCP adapter routes mcp://server/tool calls to the MCP manager
pub struct McpAdapter {
    manager: Arc<McpManager>,
}

impl McpAdapter {
    pub fn new() -> Self {
        Self {
            manager: Arc::new(McpManager::new()),
        }
    }

    pub fn register_server(&self, name: String, config: McpServerConfig) {
        self.manager.register_server(name, config);
    }

    async fn execute_mcp_call(
        &self,
        tool_use: &str,
        inputs: HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>> {
        if !tool_use.starts_with(ADAPTER_PREFIX_MCP) {
            return Err(crate::BeemFlowError::adapter(format!(
                "invalid mcp:// format: {} (expected mcp://server/tool)",
                tool_use
            )));
        }

        let stripped = tool_use.trim_start_matches(ADAPTER_PREFIX_MCP);
        let parts: Vec<&str> = stripped.splitn(2, '/').collect();

        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            return Err(crate::BeemFlowError::adapter(format!(
                "invalid mcp:// format: {} (expected mcp://server/tool)",
                tool_use
            )));
        }

        let server_name = parts[0];
        let tool_name = parts[1];

        if tool_name.contains('/') {
            return Err(crate::BeemFlowError::adapter(format!(
                "invalid mcp:// format: {} (expected mcp://server/tool, no extra segments)",
                tool_use
            )));
        }

        let result = self
            .manager
            .call_tool(server_name, tool_name, serde_json::to_value(&inputs)?)
            .await?;

        let mut outputs = HashMap::new();
        if let Some(content) = result.get("content") {
            outputs.insert("content".to_string(), content.clone());
        } else {
            outputs.insert("result".to_string(), result);
        }

        Ok(outputs)
    }
}

impl Default for McpAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Adapter for McpAdapter {
    fn id(&self) -> &str {
        ADAPTER_ID_MCP
    }

    async fn execute(
        &self,
        inputs: HashMap<String, Value>,
        _ctx: &super::ExecutionContext,
    ) -> Result<HashMap<String, Value>> {
        // McpAdapter doesn't currently use ExecutionContext, but it's available for
        // future features like:
        // - Passing OAuth credentials to MCP servers
        // - User-specific server instances (multi-tenancy)
        // - Rate limiting per user

        let tool_use = inputs
            .get(PARAM_SPECIAL_USE)
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::BeemFlowError::adapter("missing __use for MCPAdapter"))?
            .to_string();

        self.execute_mcp_call(&tool_use, inputs).await
    }

    fn manifest(&self) -> Option<ToolManifest> {
        None
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
