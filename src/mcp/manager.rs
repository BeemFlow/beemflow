//! MCP Manager - Uses rmcp client instead of custom JSON-RPC

use crate::{BeemFlowError, Result, model::McpServerConfig};
use parking_lot::RwLock;
use rmcp::{
    model::{CallToolRequestParam, Tool},
    service::{RoleClient, RunningService, ServiceExt},
    transport::TokioChildProcess,
};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::process::Command;

pub struct McpServer {
    service: RunningService<RoleClient, ()>,
    tools: Arc<RwLock<HashMap<String, Tool>>>,
}

impl McpServer {
    /// Start an MCP server with organization context for multi-tenant isolation
    ///
    /// Each organization gets its own server instances, with BEEMFLOW_ORGANIZATION_ID
    /// injected as an environment variable. This enables:
    /// - Per-tenant isolation of MCP server state
    /// - Organization-scoped credential access within MCP tools
    /// - Audit trail per organization
    pub async fn start(
        name: &str,
        config: &McpServerConfig,
        secrets_provider: &Arc<dyn crate::secrets::SecretsProvider>,
        organization_id: &str,
    ) -> Result<Self> {
        if config.command.trim().is_empty() {
            return Err(BeemFlowError::validation("MCP command cannot be empty"));
        }

        tracing::debug!(
            "Starting MCP server '{}' for organization '{}': {}",
            name,
            organization_id,
            config.command
        );

        let mut cmd = Command::new(&config.command);
        if let Some(ref args) = config.args {
            cmd.args(args);
        }

        // Inject organization context as environment variable for tenant isolation
        cmd.env("BEEMFLOW_ORGANIZATION_ID", organization_id);

        if let Some(ref env) = config.env {
            for (k, v) in env {
                // Use centralized secret expansion for $env: patterns
                // This ensures consistency with the rest of the runtime codebase
                let expanded = crate::secrets::expand_value(v, secrets_provider).await?;
                if !v.starts_with("$env:") || expanded != *v {
                    cmd.env(k, expanded);
                }
            }
        }

        let transport = TokioChildProcess::new(cmd).map_err(|e| {
            BeemFlowError::adapter(format!("Failed to create transport for '{}': {}", name, e))
        })?;

        let service = ().serve(transport).await.map_err(|e| {
            BeemFlowError::adapter(format!("Failed to connect to '{}': {}", name, e))
        })?;

        let server = Self {
            service,
            tools: Arc::new(RwLock::new(HashMap::new())),
        };

        server.discover_tools().await?;

        tracing::info!(
            "Started MCP server '{}' for organization '{}' with {} tools",
            name,
            organization_id,
            server.tools.read().len()
        );

        Ok(server)
    }

    async fn discover_tools(&self) -> Result<()> {
        let tools_result = self
            .service
            .list_tools(Default::default())
            .await
            .map_err(|e| BeemFlowError::adapter(format!("Failed to list tools: {}", e)))?;

        let mut tools = self.tools.write();
        for tool in tools_result.tools {
            tools.insert(tool.name.to_string(), tool);
        }
        Ok(())
    }

    pub async fn call_tool(&self, tool_name: &str, arguments: Value) -> Result<Value> {
        let result = self
            .service
            .call_tool(CallToolRequestParam {
                name: tool_name.to_string().into(),
                arguments: arguments.as_object().cloned(),
            })
            .await
            .map_err(|e| BeemFlowError::adapter(format!("Tool '{}' failed: {}", tool_name, e)))?;

        // Return the full result structure
        serde_json::to_value(&result)
            .map_err(|e| BeemFlowError::adapter(format!("Serialize error: {}", e)))
    }
}

/// MCP Manager with per-organization server isolation
///
/// Each organization gets its own set of MCP server instances, ensuring:
/// - Complete isolation of server state between tenants
/// - Organization-specific environment variables injected into servers
/// - Separate process pools per organization
pub struct McpManager {
    /// Per-organization server instances: (organization_id, server_name) -> server
    servers: Arc<RwLock<HashMap<(String, String), Arc<McpServer>>>>,
    /// Server configurations (shared across organizations)
    configs: Arc<RwLock<HashMap<String, McpServerConfig>>>,
    secrets_provider: Arc<dyn crate::secrets::SecretsProvider>,
}

impl McpManager {
    pub fn new(secrets_provider: Arc<dyn crate::secrets::SecretsProvider>) -> Self {
        Self {
            servers: Arc::new(RwLock::new(HashMap::new())),
            configs: Arc::new(RwLock::new(HashMap::new())),
            secrets_provider,
        }
    }

    pub fn register_server(&self, name: String, config: McpServerConfig) {
        self.configs.write().insert(name, config);
    }

    /// Get or start an MCP server for a specific organization
    ///
    /// Each organization gets its own server instances to ensure complete isolation.
    /// Servers are cached per (organization_id, server_name) tuple.
    pub async fn get_or_start_server(
        &self,
        server_name: &str,
        organization_id: &str,
    ) -> Result<Arc<McpServer>> {
        let key = (organization_id.to_string(), server_name.to_string());

        {
            let servers = self.servers.read();
            if let Some(server) = servers.get(&key) {
                return Ok(server.clone());
            }
        }

        let config = self
            .configs
            .read()
            .get(server_name)
            .cloned()
            .ok_or_else(|| {
                BeemFlowError::adapter(format!("MCP server '{}' not configured", server_name))
            })?;

        tracing::info!(
            server = %server_name,
            organization = %organization_id,
            "Starting isolated MCP server for organization"
        );

        let server = Arc::new(
            McpServer::start(
                server_name,
                &config,
                &self.secrets_provider,
                organization_id,
            )
            .await?,
        );

        self.servers.write().insert(key, server.clone());
        Ok(server)
    }

    /// Call a tool on an organization's MCP server
    pub async fn call_tool(
        &self,
        server_name: &str,
        tool_name: &str,
        arguments: Value,
        organization_id: &str,
    ) -> Result<Value> {
        let server = self
            .get_or_start_server(server_name, organization_id)
            .await?;
        server.call_tool(tool_name, arguments).await
    }

    /// Shutdown all servers for an organization (cleanup on org delete/disable)
    #[allow(dead_code)]
    pub fn shutdown_organization(&self, organization_id: &str) {
        let mut servers = self.servers.write();
        servers.retain(|(org, _), _| org != organization_id);
        tracing::info!(
            organization = %organization_id,
            "Shut down all MCP servers for organization"
        );
    }
}

#[cfg(test)]
#[path = "manager_test.rs"]
mod tests;
