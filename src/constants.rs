//! Constants used throughout BeemFlow
//!
//! This module contains all constant values used in the BeemFlow runtime,
//! including configuration paths, adapter identifiers, and interface definitions.

use once_cell::sync::Lazy;

// ============================================================================
// CONFIGURATION
// ============================================================================

/// Get the home directory with fallback to current directory
pub fn get_home_dir() -> &'static str {
    static HOME_DIR: Lazy<String> = Lazy::new(|| {
        std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string())
    });
    &HOME_DIR
}

/// Default config directory (~/.beemflow)
/// Can be overridden with BEEMFLOW_HOME environment variable
pub fn default_config_dir() -> &'static str {
    static CONFIG_DIR: Lazy<String> = Lazy::new(|| {
        std::env::var("BEEMFLOW_HOME").unwrap_or_else(|_| format!("{}/.beemflow", get_home_dir()))
    });
    &CONFIG_DIR
}

/// Default blob directory (~/.beemflow/files)
pub fn default_blob_dir() -> &'static str {
    static BLOB_DIR: Lazy<String> = Lazy::new(|| format!("{}/files", default_config_dir()));
    &BLOB_DIR
}

/// Default SQLite DSN (~/.beemflow/flow.db)
pub fn default_sqlite_dsn() -> &'static str {
    static SQLITE_DSN: Lazy<String> = Lazy::new(|| format!("{}/flow.db", default_config_dir()));
    &SQLITE_DSN
}

/// Default local registry path (~/.beemflow/registry.json)
pub fn default_local_registry_path() -> &'static str {
    static REGISTRY_PATH: Lazy<String> =
        Lazy::new(|| format!("{}/registry.json", default_config_dir()));
    &REGISTRY_PATH
}

/// Default flows directory (~/.beemflow/flows)
pub fn default_flows_dir() -> &'static str {
    static FLOWS_DIR: Lazy<String> = Lazy::new(|| format!("{}/flows", default_config_dir()));
    &FLOWS_DIR
}

/// File permission for created files (0644)
pub const FILE_PERMISSION: u32 = 0o644;

/// Directory permission for created directories (0755)
pub const DIR_PERMISSION: u32 = 0o755;

/// Configuration file name
pub const CONFIG_FILE_NAME: &str = "flow.config.json";

/// BeemFlow JSON schema file
pub const BEEMFLOW_SCHEMA_FILE: &str = "beemflow.schema.json";

/// MCP servers configuration key
pub const MCP_SERVERS_KEY: &str = "mcp_servers";

/// Tools configuration key
pub const TOOLS_KEY: &str = "tools";

/// Smithery configuration key
pub const SMITHERY_KEY: &str = "smithery";

/// Storage driver: SQLite
pub const STORAGE_DRIVER_SQLITE: &str = "sqlite";

/// Storage driver: PostgreSQL
pub const STORAGE_DRIVER_POSTGRES: &str = "postgres";

/// Environment variable: Debug mode
pub const ENV_DEBUG: &str = "BEEMFLOW_DEBUG";

/// Environment variable: Smithery API key
pub const ENV_SMITHERY_KEY: &str = "SMITHERY_API_KEY";

/// Environment variable: Registry path
pub const ENV_REGISTRY_PATH: &str = "BEEMFLOW_REGISTRY";

// ============================================================================
// ADAPTERS & TOOLS
// ============================================================================

/// Core adapter name
pub const ADAPTER_CORE: &str = "core";

/// MCP adapter name
pub const ADAPTER_MCP: &str = "mcp";

/// HTTP adapter name
pub const ADAPTER_HTTP: &str = "http";

/// HTTP adapter identifier
pub const HTTP_ADAPTER_ID: &str = "http";

/// Local registry type
pub const LOCAL_REGISTRY_TYPE: &str = "local";

/// MCP adapter prefix
pub const ADAPTER_PREFIX_MCP: &str = "mcp://";

/// Core adapter prefix
pub const ADAPTER_PREFIX_CORE: &str = "core.";

/// Special parameter: use
pub const PARAM_SPECIAL_USE: &str = "__use";

/// Core tool: echo
pub const CORE_ECHO: &str = "core.echo";

/// Core tool: wait
pub const CORE_WAIT: &str = "core.wait";

/// Core tool: log
pub const CORE_LOG: &str = "core.log";

/// Core tool: convert OpenAPI
pub const CORE_CONVERT_OPENAPI: &str = "core.convert_openapi";

// ============================================================================
// CLI COMMANDS & DESCRIPTIONS
// ============================================================================

/// Command: run
pub const CMD_RUN: &str = "run";

/// Command: serve
pub const CMD_SERVE: &str = "serve";

/// Command: mcp
pub const CMD_MCP: &str = "mcp";

/// Command: tools
pub const CMD_TOOLS: &str = "tools";

/// Command: search
pub const CMD_SEARCH: &str = "search";

/// Command: install
pub const CMD_INSTALL: &str = "install";

/// Command: list
pub const CMD_LIST: &str = "list";

/// Command: get
pub const CMD_GET: &str = "get";

/// Description: Run a flow
pub const DESC_RUN_FLOW: &str = "Run a flow from a YAML file";

/// Description: MCP commands
pub const DESC_MCP_COMMANDS: &str = "MCP server management commands";

/// Description: Tools commands
pub const DESC_TOOLS_COMMANDS: &str = "Tool manifest management commands";

/// Description: Search servers
pub const DESC_SEARCH_SERVERS: &str = "Search for MCP servers in the registry";

/// Description: Search tools
pub const DESC_SEARCH_TOOLS: &str = "Search for tool manifests in the registry";

/// Description: Install server
pub const DESC_INSTALL_SERVER: &str = "Install an MCP server from the registry";

/// Description: Install tool
pub const DESC_INSTALL_TOOL: &str = "Install a tool manifest from the registry";

/// Description: List servers
pub const DESC_LIST_SERVERS: &str = "List installed MCP servers";

/// Description: List tools
pub const DESC_LIST_TOOLS: &str = "List installed tool manifests";

/// Description: Get tool
pub const DESC_GET_TOOL: &str = "Get a tool manifest by name";

/// Description: MCP serve
pub const DESC_MCP_SERVE: &str = "Start MCP server for BeemFlow tools";

// CLI Messages
pub const MSG_FLOW_EXECUTED: &str = "Flow executed successfully";
pub const MSG_STEP_OUTPUTS: &str = "Step outputs: %s";
pub const MSG_SERVER_INSTALLED: &str = "Server %s installed to %s";
pub const MSG_TOOL_INSTALLED: &str = "Tool %s installed to %s";
pub const HEADER_SERVERS: &str = "%-20s %-40s %s";
pub const HEADER_TOOLS: &str = "%-20s %-40s %s";
pub const HEADER_MCP_LIST: &str = "%-10s %-20s %-30s %-10s %s";
pub const HEADER_TOOLS_LIST: &str = "%-10s %-20s %-30s %-10s %s";
pub const FORMAT_THREE_COLUMNS: &str = "%-20s %-40s %s";
pub const FORMAT_FIVE_COLUMNS: &str = "%-10s %-20s %-30s %-10s %s";

// ============================================================================
// HTTP & API
// ============================================================================

/// Maximum request body size (5MB) - prevents DoS via large payloads
pub const MAX_REQUEST_BODY_SIZE: usize = 5 * 1024 * 1024;

/// HTTP method: GET
pub const HTTP_METHOD_GET: &str = "GET";

/// HTTP method: POST
pub const HTTP_METHOD_POST: &str = "POST";

/// HTTP method: PUT
pub const HTTP_METHOD_PUT: &str = "PUT";

/// HTTP method: DELETE
pub const HTTP_METHOD_DELETE: &str = "DELETE";

/// HTTP method: PATCH
pub const HTTP_METHOD_PATCH: &str = "PATCH";

/// HTTP path: root
pub const HTTP_PATH_ROOT: &str = "/";

/// HTTP path: spec
pub const HTTP_PATH_SPEC: &str = "/spec";

/// HTTP path: health
pub const HTTP_PATH_HEALTH: &str = "/health";

/// HTTP path: flows
pub const HTTP_PATH_FLOWS: &str = "/flows";

/// HTTP path: validate
pub const HTTP_PATH_VALIDATE: &str = "/validate";

/// HTTP path: graph
pub const HTTP_PATH_GRAPH: &str = "/graph";

/// HTTP path: runs
pub const HTTP_PATH_RUNS: &str = "/runs";

/// HTTP path: runs inline
pub const HTTP_PATH_RUNS_INLINE: &str = "/runs/inline";

/// HTTP path: runs by ID
pub const HTTP_PATH_RUNS_BY_ID: &str = "/runs/{id}";

/// HTTP path: runs resume
pub const HTTP_PATH_RUNS_RESUME: &str = "/runs/{id}/resume";

/// HTTP path: events
pub const HTTP_PATH_EVENTS: &str = "/events";

/// HTTP path: tools
pub const HTTP_PATH_TOOLS: &str = "/tools";

/// HTTP path: tools manifest
pub const HTTP_PATH_TOOLS_MANIFEST: &str = "/tools/manifest";

/// HTTP path: convert
pub const HTTP_PATH_CONVERT: &str = "/convert";

/// HTTP path: lint
pub const HTTP_PATH_LINT: &str = "/lint";

/// HTTP path: test
pub const HTTP_PATH_TEST: &str = "/test";

/// Content type: JSON
pub const CONTENT_TYPE_JSON: &str = "application/json";

/// Content type: text
pub const CONTENT_TYPE_TEXT: &str = "text/plain";

/// Content type: YAML
pub const CONTENT_TYPE_YAML: &str = "application/x-yaml";

/// Content type: form
pub const CONTENT_TYPE_FORM: &str = "application/x-www-form-urlencoded";

/// HTTP status message: OK
pub const HTTP_STATUS_OK: &str = "OK";

/// HTTP status message: Not Found
pub const HTTP_STATUS_NOT_FOUND: &str = "Not Found";

/// HTTP status message: Internal Server Error
pub const HTTP_STATUS_INTERNAL_ERROR: &str = "Internal Server Error";

/// Header: Content-Type
pub const HEADER_CONTENT_TYPE: &str = "Content-Type";

/// Header: Authorization
pub const HEADER_AUTHORIZATION: &str = "Authorization";

/// Header: Accept
pub const HEADER_ACCEPT: &str = "Accept";

/// Default API name
pub const DEFAULT_API_NAME: &str = "api";

/// Default base URL
pub const DEFAULT_BASE_URL: &str = "https://api.example.com";

/// Default JSON accept header
pub const DEFAULT_JSON_ACCEPT: &str = "application/json";

// ============================================================================
// MCP (Model Context Protocol)
// ============================================================================

/// MCP tool: spec
pub const MCP_TOOL_SPEC: &str = "spec";

/// MCP tool: convert OpenAPI spec
pub const MCP_TOOL_CONVERT_OPENAPI: &str = "convertOpenAPISpec";

/// MCP parameter: openapi
pub const MCP_PARAM_OPENAPI: &str = "openapi";

/// MCP parameter: api_name
pub const MCP_PARAM_API_NAME: &str = "api_name";

/// MCP parameter: base_url
pub const MCP_PARAM_BASE_URL: &str = "base_url";

/// Default HTTP port
pub const DEFAULT_HTTP_PORT: u16 = 3330;

/// Default MCP port (over HTTP)
pub const DEFAULT_MCP_PORT: u16 = 3331;

/// Default MCP address
pub const DEFAULT_MCP_ADDR: &str = "localhost:3001";

/// Default Vite dev server port (first choice)
pub const DEFAULT_VITE_DEV_PORT: u16 = 5173;

/// Alternative Vite dev server port (if 5173 is taken)
pub const DEFAULT_VITE_DEV_PORT_ALT: u16 = 5174;

/// Default MCP page size
pub const DEFAULT_MCP_PAGE_SIZE: usize = 50;

// ============================================================================
// TRIGGERS
// ============================================================================

/// Trigger type: schedule.cron (for cron-scheduled flows)
pub const TRIGGER_SCHEDULE_CRON: &str = "schedule.cron";

/// Trigger type: cli.manual (for manually-executed flows via CLI/API)
pub const TRIGGER_CLI_MANUAL: &str = "cli.manual";

// ============================================================================
// ENGINE & EXECUTION
// ============================================================================

/// Default tool page size
pub const DEFAULT_TOOL_PAGE_SIZE: usize = 100;

/// Default retry count
pub const DEFAULT_RETRY_COUNT: u32 = 3;

/// Default timeout in seconds
pub const DEFAULT_TIMEOUT_SEC: u64 = 30;

/// Template field: event
pub const TEMPLATE_FIELD_EVENT: &str = "event";

/// Template field: vars
pub const TEMPLATE_FIELD_VARS: &str = "vars";

/// Template field: outputs
pub const TEMPLATE_FIELD_OUTPUTS: &str = "outputs";

/// Template field: secrets
pub const TEMPLATE_FIELD_SECRETS: &str = "secrets";

/// Template field: steps
pub const TEMPLATE_FIELD_STEPS: &str = "steps";

/// Template field: env
pub const TEMPLATE_FIELD_ENV: &str = "env";

/// Error: await event pause
pub const ERR_AWAIT_EVENT_PAUSE: &str = "step is waiting for event";

/// Error: save run failed
pub const ERR_SAVE_RUN_FAILED: &str = "failed to save run";

/// Error: failed to persist step
pub const ERR_FAILED_TO_PERSIST_STEP: &str = "failed to persist step";

/// Error: await event missing token
pub const ERR_AWAIT_EVENT_MISSING_TOKEN: &str = "await_event step missing token in match";

/// Error: failed to render token
pub const ERR_FAILED_TO_RENDER_TOKEN: &str = "failed to render token: %v";

/// Error: step waiting for event
pub const ERR_STEP_WAITING_FOR_EVENT: &str = "step '%s' is waiting for event";

/// Error: failed to delete paused run
pub const ERR_FAILED_TO_DELETE_PAUSED_RUN: &str = "failed to delete paused run";

/// Error: MCP adapter not registered
pub const ERR_MCP_ADAPTER_NOT_REGISTERED: &str = "MCPAdapter not registered";

/// Error: core adapter not registered
pub const ERR_CORE_ADAPTER_NOT_REGISTERED: &str = "CoreAdapter not registered";

/// Error: adapter not found
pub const ERR_ADAPTER_NOT_FOUND: &str = "adapter not found: %s";

/// Error: step failed
pub const ERR_STEP_FAILED: &str = "step %s failed: %w";

/// Error: template error
pub const ERR_TEMPLATE_ERROR: &str = "template error in step %s: %w";

/// Error: template error in step ID
pub const ERR_TEMPLATE_ERROR_STEP_ID: &str = "template error in step ID %s: %w";

/// Error: foreach not list
pub const ERR_FOREACH_NOT_LIST: &str = "foreach expression did not evaluate to a list, got: %T";

/// Error: template error in foreach
pub const ERR_TEMPLATE_ERROR_FOREACH: &str = "template error in foreach expression: %w";

/// Match key: token
pub const MATCH_KEY_TOKEN: &str = "token";

/// Event topic: resume prefix
pub const EVENT_TOPIC_RESUME_PREFIX: &str = "resume.";

/// Adapter ID: MCP
pub const ADAPTER_ID_MCP: &str = "mcp";

/// Adapter ID: Core
pub const ADAPTER_ID_CORE: &str = "core";

/// Secrets key
pub const SECRETS_KEY: &str = "secrets";

/// Field equality operator
pub const FIELD_EQUALITY_OPERATOR: &str = "=";

/// Empty string
pub const EMPTY_STRING: &str = "";

/// JSON indent
pub const JSON_INDENT: &str = "  ";

// ============================================================================
// INTERFACE DESCRIPTIONS
// ============================================================================

/// Interface description: HTTP
pub const INTERFACE_DESC_HTTP: &str = "HTTP API for BeemFlow operations";

/// Interface description: MCP
pub const INTERFACE_DESC_MCP: &str = "MCP tools for flow operations";

/// Interface description: CLI
pub const INTERFACE_DESC_CLI: &str = "Command-line interface";

/// Interface description: List flows
pub const INTERFACE_DESC_LIST_FLOWS: &str = "List all available flows";

/// Interface description: Get flow
pub const INTERFACE_DESC_GET_FLOW: &str = "Get a specific flow by name";

/// Interface description: Validate flow
pub const INTERFACE_DESC_VALIDATE_FLOW: &str = "Validate a flow definition";

/// Interface description: Graph flow
pub const INTERFACE_DESC_GRAPH_FLOW: &str = "Generate a graph representation of a flow";

/// Interface description: Start run
pub const INTERFACE_DESC_START_RUN: &str = "Start a new flow run";

/// Interface description: Get run
pub const INTERFACE_DESC_GET_RUN: &str = "Get details of a specific run";

/// Interface description: List runs
pub const INTERFACE_DESC_LIST_RUNS: &str = "List all flow runs";

/// Interface description: Publish event
pub const INTERFACE_DESC_PUBLISH_EVENT: &str = "Publish an event to the event bus";

/// Interface description: Resume run
pub const INTERFACE_DESC_RESUME_RUN: &str = "Resume a paused flow run";

/// Interface description: List tools
pub const INTERFACE_DESC_LIST_TOOLS: &str = "List all available tools";

/// Interface description: Get tool manifest
pub const INTERFACE_DESC_GET_TOOL_MANIFEST: &str = "Get tool manifest information";

/// Interface description: Convert OpenAPI
pub const INTERFACE_DESC_CONVERT_OPENAPI: &str = "Convert OpenAPI spec to BeemFlow tools";

/// Interface description: Lint flow
pub const INTERFACE_DESC_LINT_FLOW: &str = "Lint and validate flow syntax";

/// Interface description: Test flow
pub const INTERFACE_DESC_TEST_FLOW: &str = "Test flow execution";

/// Interface ID: Start run
pub const INTERFACE_ID_START_RUN: &str = "startRun";

/// Interface ID: Get run
pub const INTERFACE_ID_GET_RUN: &str = "getRun";

/// Interface ID: Resume run
pub const INTERFACE_ID_RESUME_RUN: &str = "resumeRun";

/// Interface ID: Graph flow
pub const INTERFACE_ID_GRAPH_FLOW: &str = "graphFlow";

/// Interface ID: Validate flow
pub const INTERFACE_ID_VALIDATE_FLOW: &str = "validateFlow";

/// Interface ID: Test flow
pub const INTERFACE_ID_TEST_FLOW: &str = "testFlow";

/// Interface ID: Inline run
pub const INTERFACE_ID_INLINE_RUN: &str = "inlineRun";

/// Interface ID: List tools
pub const INTERFACE_ID_LIST_TOOLS: &str = "listTools";

/// Interface ID: Get tool manifest
pub const INTERFACE_ID_GET_TOOL_MANIFEST: &str = "getToolManifest";

/// Interface ID: List runs
pub const INTERFACE_ID_LIST_RUNS: &str = "listRuns";

/// Interface ID: Publish event
pub const INTERFACE_ID_PUBLISH_EVENT: &str = "publishEvent";

/// Interface ID: List flows
pub const INTERFACE_ID_LIST_FLOWS: &str = "listFlows";

/// Interface ID: Get flow
pub const INTERFACE_ID_GET_FLOW: &str = "getFlow";

/// Interface ID: Spec
pub const INTERFACE_ID_SPEC: &str = "spec";

/// Interface ID: Convert OpenAPI
pub const INTERFACE_ID_CONVERT_OPENAPI: &str = "convertOpenAPI";

/// Interface ID: Lint flow
pub const INTERFACE_ID_LINT_FLOW: &str = "lintFlow";

// ============================================================================
// REGISTRY & RESPONSES
// ============================================================================

/// Registry: local
pub const REGISTRY_LOCAL: &str = "local";

/// Registry: smithery
pub const REGISTRY_SMITHERY: &str = "smithery";

/// Registry: default
pub const REGISTRY_DEFAULT: &str = "default";

/// Response: success
pub const RESPONSE_SUCCESS: &str = "success";

/// Response: error
pub const RESPONSE_ERROR: &str = "error";

/// Status: running
pub const STATUS_RUNNING: &str = "running";

/// Status: completed
pub const STATUS_COMPLETED: &str = "completed";

/// Status: failed
pub const STATUS_FAILED: &str = "failed";

/// Status: paused
pub const STATUS_PAUSED: &str = "paused";

// ============================================================================
// OUTPUT FORMATTING
// ============================================================================

/// Output key: text
pub const OUTPUT_KEY_TEXT: &str = "text";

/// Output key: choices
pub const OUTPUT_KEY_CHOICES: &str = "choices";

/// Output key: message
pub const OUTPUT_KEY_MESSAGE: &str = "message";

/// Output key: content
pub const OUTPUT_KEY_CONTENT: &str = "content";

/// Output key: body
pub const OUTPUT_KEY_BODY: &str = "body";

/// Output preview limit
pub const OUTPUT_PREVIEW_LIMIT: usize = 200;

/// Output JSON size limit
pub const OUTPUT_JSON_SIZE_LIMIT: usize = 1000;

// ============================================================================
// API & EXECUTION
// ============================================================================

/// Run ID key
pub const RUN_ID_KEY: &str = "run_id";

/// MCP server kind
pub const MCP_SERVER_KIND: &str = "mcp_server";

/// Tool type
pub const TOOL_TYPE: &str = "tool";

/// Flow file extension
pub const FLOW_FILE_EXTENSION: &str = ".flow.yaml";

// ============================================================================
// ENGINE TEMPLATE CONSTANTS
// ============================================================================

/// Template open delimiter
pub const TEMPLATE_OPEN_DELIM: &str = "{{";

/// Template close delimiter
pub const TEMPLATE_CLOSE_DELIM: &str = "}}";

/// Template control open delimiter
pub const TEMPLATE_CONTROL_OPEN: &str = "{%";

/// Template control close delimiter
pub const TEMPLATE_CONTROL_CLOSE: &str = "%}";

/// Paused run key: flow
pub const PAUSED_RUN_KEY_FLOW: &str = "flow";

/// Paused run key: step_idx
pub const PAUSED_RUN_KEY_STEP_IDX: &str = "step_idx";

/// Paused run key: step_ctx
pub const PAUSED_RUN_KEY_STEP_CTX: &str = "step_ctx";

/// Paused run key: outputs
pub const PAUSED_RUN_KEY_OUTPUTS: &str = "outputs";

/// Paused run key: token
pub const PAUSED_RUN_KEY_TOKEN: &str = "token";

/// Paused run key: run_id
pub const PAUSED_RUN_KEY_RUN_ID: &str = "run_id";

/// Environment variable prefix
pub const ENV_VAR_PREFIX: &str = "$env";

/// Default key: properties
pub const DEFAULT_KEY_PROPERTIES: &str = "properties";

/// Default key: required
pub const DEFAULT_KEY_REQUIRED: &str = "required";

/// Default key: default
pub const DEFAULT_KEY_DEFAULT: &str = "default";

// ============================================================================
// OUTPUT PREFIXES
// ============================================================================

/// Output prefix: AI (robot emoji)
pub const OUTPUT_PREFIX_AI: &str = "🤖 ";

/// Output prefix: MCP (satellite emoji)
pub const OUTPUT_PREFIX_MCP: &str = "📡 ";

/// Output prefix: HTTP (globe emoji)
pub const OUTPUT_PREFIX_HTTP: &str = "🌐 ";

/// Output prefix: JSON (clipboard emoji)
pub const OUTPUT_PREFIX_JSON: &str = "📋 ";

// ============================================================================
// AUTHENTICATION & MULTI-ORGANIZATION CONSTANTS
// ============================================================================

/// System user ID for automated/unauthenticated operations (cron, webhooks)
pub const SYSTEM_USER_ID: &str = "system";

/// Default user ID for fallback when deployer is unknown
pub const DEFAULT_USER_ID: &str = "default";

/// Default organization ID for local development and single-user mode
pub const DEFAULT_ORGANIZATION_ID: &str = "default";
