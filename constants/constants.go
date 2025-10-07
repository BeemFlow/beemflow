package constants

import (
	"errors"
	"fmt"
)

// ============================================================================
// CONFIGURATION
// ============================================================================

// Configuration Files
const (
	ConfigFileName     = "flow.config.json"
	BeemflowSchemaFile = "beemflow.schema.json"
)

// Configuration Schema Keys
const (
	MCPServersKey = "mcp_servers"
	ToolsKey      = "tools"
	SmitheryKey   = "smithery"
)

// Storage Drivers
const (
	StorageDriverSQLite   = "sqlite"
	StorageDriverPostgres = "postgres"
)

// Environment Variables
const (
	EnvDebug        = "BEEMFLOW_DEBUG"
	EnvSmitheryKey  = "SMITHERY_API_KEY"
	EnvRegistryPath = "BEEMFLOW_REGISTRY"
)

// ============================================================================
// ADAPTERS & TOOLS
// ============================================================================

// Adapter Names
const (
	AdapterCore = "core"
	AdapterMCP  = "mcp"
	AdapterHTTP = "http"
)

// Adapter IDs
const (
	HTTPAdapterID = "http"
)

// Registry Types
const (
	LocalRegistryType = "local"
)

// Adapter Prefixes
const (
	AdapterPrefixMCP  = "mcp://"
	AdapterPrefixCore = "core."
)

// Special Parameters
const (
	ParamSpecialUse = "__use"
)

// Core Tools
const (
	CoreEcho           = "core.echo"
	CoreConvertOpenAPI = "core.convert_openapi"
)

// ============================================================================
// CLI COMMANDS & DESCRIPTIONS
// ============================================================================

// Command names
const (
	CmdRun     = "run"
	CmdServe   = "serve"
	CmdMCP     = "mcp"
	CmdTools   = "tools"
	CmdSearch  = "search"
	CmdInstall = "install"
	CmdList    = "list"
	CmdGet     = "get"
)

// Command descriptions
const (
	DescRunFlow       = "Run a flow from a CUE file"
	DescMCPCommands   = "MCP server management commands"
	DescToolsCommands = "Tool manifest management commands"
	DescSearchServers = "Search for MCP servers in the registry"
	DescSearchTools   = "Search for tool manifests in the registry"
	DescInstallServer = "Install an MCP server from the registry"
	DescInstallTool   = "Install a tool manifest from the registry"
	DescListServers   = "List installed MCP servers"
	DescListTools     = "List installed tool manifests"
	DescGetTool       = "Get a tool manifest by name"
	DescMCPServe      = "Start MCP server for BeemFlow tools"
)

// CLI Messages
const (
	StubFlowRun        = "flow run (stub)"
	MsgFlowExecuted    = "Flow executed successfully"
	MsgStepOutputs     = "Step outputs: %s"
	MsgServerInstalled = "Server %s installed to %s"
	MsgToolInstalled   = "Tool %s installed to %s"
	HeaderServers      = "%-20s %-40s %s"
	HeaderTools        = "%-20s %-40s %s"
	HeaderMCPList      = "%-10s %-20s %-30s %-10s %s"
	HeaderToolsList    = "%-10s %-20s %-30s %-10s %s"
	FormatThreeColumns = "%-20s %-40s %s"
	FormatFiveColumns  = "%-10s %-20s %-30s %-10s %s"
)

// CLI Error messages
const (
	ErrFlowExecutionFailed = "Flow execution failed: %v"
	ErrEnvVarRequired      = "environment variable %s is required but not set"
	ErrConfigParseFailed   = "failed to parse config file %s: %v"
	ErrConfigWriteFailed   = "failed to write config file %s: %v"
)

// ============================================================================
// HTTP & API
// ============================================================================

// HTTP Methods
const (
	HTTPMethodGET    = "GET"
	HTTPMethodPOST   = "POST"
	HTTPMethodPUT    = "PUT"
	HTTPMethodDELETE = "DELETE"
	HTTPMethodPATCH  = "PATCH"
)

// HTTP Paths
const (
	HTTPPathRoot          = "/"
	HTTPPathSpec          = "/spec"
	HTTPPathHealth        = "/health"
	HTTPPathFlows         = "/flows"
	HTTPPathValidate      = "/validate"
	HTTPPathGraph         = "/graph"
	HTTPPathRuns          = "/runs"
	HTTPPathRunsInline    = "/runs/inline"
	HTTPPathRunsByID      = "/runs/{id}"
	HTTPPathRunsResume    = "/runs/{id}/resume"
	HTTPPathEvents        = "/events"
	HTTPPathTools         = "/tools"
	HTTPPathToolsManifest = "/tools/manifest"
	HTTPPathConvert       = "/convert"
	HTTPPathLint          = "/lint"
	HTTPPathTest          = "/test"
)

// HTTP Status Messages
const (
	HTTPStatusOK            = "OK"
	HTTPStatusNotFound      = "Not Found"
	HTTPStatusInternalError = "Internal Server Error"
	HealthCheckResponse     = "OK"
)

// Content Types
const (
	ContentTypeJSON = "application/json"
	ContentTypeText = "text/plain"
	ContentTypeForm = "application/x-www-form-urlencoded"
)

// HTTP Headers
const (
	HeaderContentType   = "Content-Type"
	HeaderAuthorization = "Authorization"
	HeaderAccept        = "Accept"
)

// HTTP Defaults
const (
	DefaultAPIName    = "api"
	DefaultBaseURL    = "https://api.example.com"
	DefaultJSONAccept = "application/json"
)

// ============================================================================
// MCP (Model Context Protocol)
// ============================================================================

// MCP Tool Names
const (
	MCPToolSpec           = "spec"
	MCPToolConvertOpenAPI = "convertOpenAPISpec"
)

// MCP Parameter Names
const (
	MCPParamOpenAPI = "openapi"
	MCPParamAPIName = "api_name"
	MCPParamBaseURL = "base_url"
	MCPMissingParam = "missing required parameter: %s"
)

// Environment Variables
const (
	EnvHTTPServerPort = "BEEMFLOW_HTTP_PORT"
	EnvMCPServerPort  = "BEEMFLOW_MCP_PORT"
	EnvMCPTransport   = "BEEMFLOW_MCP_TRANSPORT" // "stdio" or "http"
)

// Server Configuration Defaults
const (
	DefaultHTTPServerPort = 3330
	DefaultMCPServerPort  = 3331
	DefaultMCPTransport   = "stdio"
	DefaultServerHost     = "localhost"
)

// ============================================================================
// ENGINE & EXECUTION
// ============================================================================

// Engine defaults
const (
	DefaultToolPageSize = 100
	DefaultRetryCount   = 3
	DefaultTimeoutSec   = 30
)

// Engine error messages
const (
	ErrSaveRunFailed           = "failed to save run"
	ErrFailedToPersistStep     = "failed to persist step"
	ErrAwaitEventMissingToken  = "await_event step missing token in match"
	ErrFailedToRenderToken     = "failed to render token: %v"
	ErrFailedToDeletePausedRun = "failed to delete paused run"
	// New engine error messages
	ErrMCPAdapterNotRegistered  = "MCPAdapter not registered"
	ErrCoreAdapterNotRegistered = "CoreAdapter not registered"
	ErrAdapterNotFound          = "adapter not found: %s"
	ErrStepFailed               = "step %s failed: %w"
	ErrTemplateError            = "template error in step %s: %w"
	ErrTemplateErrorStepID      = "template error in step ID %s: %w"
	ErrForeachNotList           = "foreach expression did not evaluate to a list, got: %T"
	ErrTemplateErrorForeach     = "template error in foreach expression: %w"
	ErrTemplateResolutionFailed = "template resolution failed for: %s"
)

// AwaitEventPauseError is a sentinel error type for await_event pauses
type AwaitEventPauseError struct {
	StepID string
	Token  string
}

func (e *AwaitEventPauseError) Error() string {
	return fmt.Sprintf("step '%s' is waiting for event (token: %s)", e.StepID, e.Token)
}

// NewAwaitEventPauseError creates a new AwaitEventPauseError
func NewAwaitEventPauseError(stepID, token string) error {
	return &AwaitEventPauseError{
		StepID: stepID,
		Token:  token,
	}
}

// IsAwaitEventPause checks if an error is an await_event pause
func IsAwaitEventPause(err error) bool {
	if err == nil {
		return false
	}
	var pauseErr *AwaitEventPauseError
	return errors.As(err, &pauseErr)
}

// Engine constants
const (
	MatchKeyToken          = "token"
	EventTopicResumePrefix = "resume."
	// New engine constants
	AdapterIDMCP          = "mcp"
	AdapterIDCore         = "core"
	SecretsKey            = "secrets"
	FieldEqualityOperator = "="
	EmptyString           = ""
)

// JSON formatting
const (
	JSONIndent = "  "
)

// File permissions
const (
	FilePermission = 0644
	DirPermission  = 0755
)

// ============================================================================
// INTERFACE DESCRIPTIONS
// ============================================================================

// Interface descriptions
const (
	InterfaceDescHTTP            = "HTTP API for BeemFlow operations"
	InterfaceDescMCP             = "MCP tools for flow operations"
	InterfaceDescCLI             = "Command-line interface"
	InterfaceDescSpec            = "Generate OpenAPI specification"
	InterfaceDescHealthCheck     = "Health check endpoint"
	InterfaceDescStaticAssets    = "Static asset serving"
	InterfaceDescListFlows       = "List all available flows"
	InterfaceDescGetFlow         = "Get a specific flow by name"
	InterfaceDescValidateFlow    = "Validate a flow definition"
	InterfaceDescGraphFlow       = "Generate a graph representation of a flow"
	InterfaceDescStartRun        = "Start a new flow run"
	InterfaceDescGetRun          = "Get details of a specific run"
	InterfaceDescListRuns        = "List all flow runs"
	InterfaceDescPublishEvent    = "Publish an event to the event bus"
	InterfaceDescResumeRun       = "Resume a paused flow run"
	InterfaceDescListTools       = "List all available tools"
	InterfaceDescGetToolManifest = "Get tool manifest information"
	InterfaceDescConvertOpenAPI  = "Convert OpenAPI spec to BeemFlow tools"
	InterfaceDescLintFlow        = "Lint and validate flow syntax"
	InterfaceDescTestFlow        = "Test flow execution"
)

// Interface IDs
const (
	InterfaceIDStartRun        = "startRun"
	InterfaceIDGetRun          = "getRun"
	InterfaceIDResumeRun       = "resumeRun"
	InterfaceIDGraphFlow       = "graphFlow"
	InterfaceIDValidateFlow    = "validateFlow"
	InterfaceIDTestFlow        = "testFlow"
	InterfaceIDInlineRun       = "inlineRun"
	InterfaceIDListTools       = "listTools"
	InterfaceIDGetToolManifest = "getToolManifest"
	InterfaceIDListRuns        = "listRuns"
	InterfaceIDPublishEvent    = "publishEvent"
	InterfaceIDListFlows       = "listFlows"
	InterfaceIDGetFlow         = "getFlow"
	InterfaceIDSpec            = "spec"
	InterfaceIDConvertOpenAPI  = "convertOpenAPI"
	InterfaceIDLintFlow        = "lintFlow"
)

// ============================================================================
// REGISTRY & RESPONSES
// ============================================================================

// Registry constants
const (
	RegistryLocal    = "local"
	RegistrySmithery = "smithery"
	RegistryDefault  = "default"
)

// Common response messages
const (
	ResponseSuccess = "success"
	ResponseError   = "error"
)

// Status constants
const (
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
	StatusPaused    = "paused"
)

// ============================================================================
// OUTPUT FORMATTING
// ============================================================================

// Output format keys
const (
	OutputKeyText    = "text"
	OutputKeyChoices = "choices"
	OutputKeyMessage = "message"
	OutputKeyContent = "content"
	OutputKeyBody    = "body"
)

// Output prefixes
const (
	OutputPrefixAI   = "🤖 "
	OutputPrefixMCP  = "📡 "
	OutputPrefixHTTP = "🌐 "
	OutputPrefixJSON = "📋 "
)

// Output limits
const (
	OutputPreviewLimit     = 200
	OutputJSONSizeLimit    = 1000
	OutputTruncationSuffix = "..."
	OutputTooLargeMessage  = "[output too large to display]"
)

// Logging Messages
const (
	LogFailedWriteHealthCheck = "Failed to write health check response"
)

// ============================================================================
// API & EXECUTION
// ============================================================================

// Error patterns and identifiers
const (
	RunIDKey      = "run_id"
	MCPServerKind = "mcp_server"
	ToolType      = "tool"
)

// Flow file extensions
const (
	FlowFileExtension = ".flow.cue"
)

// ============================================================================
// ENGINE TEMPLATE CONSTANTS
// ============================================================================

// Paused run map keys
const (
	PausedRunKeyFlow    = "flow"
	PausedRunKeyStepIdx = "step_idx"
	PausedRunKeyStepCtx = "step_ctx"
	PausedRunKeyOutputs = "outputs"
	PausedRunKeyToken   = "token"
	PausedRunKeyRunID   = "run_id"
)

// Environment variable handling
const (
	EnvVarPrefix = "$env"
)

// Default parameter sources
const (
	DefaultKeyProperties = "properties"
	DefaultKeyRequired   = "required"
	DefaultKeyDefault    = "default"
)
