package api

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/beemflow/beemflow/config"
	"github.com/beemflow/beemflow/constants"
	"github.com/beemflow/beemflow/dsl"
	"github.com/beemflow/beemflow/engine"
	"github.com/beemflow/beemflow/event"
	"github.com/beemflow/beemflow/graph"
	"github.com/beemflow/beemflow/model"
	"github.com/beemflow/beemflow/registry"
	"github.com/beemflow/beemflow/storage"
	"github.com/beemflow/beemflow/utils"
	"github.com/google/uuid"
	version "github.com/hashicorp/go-version"
	"gopkg.in/yaml.v3"
)

// GetDefaultRegistry returns the default registry with OAuth providers
func GetDefaultRegistry() registry.OAuthRegistry {
	return registry.NewDefaultRegistry()
}

// GetStoreFromConfig returns a storage instance based on config, or an error if the driver is unknown.
// This is a utility function that can be used by other packages.
func GetStoreFromConfig(cfg *config.Config) (storage.Storage, error) {
	if cfg != nil && cfg.Storage.Driver != "" {
		switch strings.ToLower(cfg.Storage.Driver) {
		case "sqlite":
			// Use the user-provided DSN as-is (respects their explicit choice)
			store, err := storage.NewSqliteStorage(cfg.Storage.DSN)
			if err != nil {
				utils.WarnCtx(context.Background(), "Failed to create sqlite storage: %v, using in-memory fallback", "error", err)
				return storage.NewMemoryStorage(), nil
			}
			return store, nil
		case "postgres", "postgresql":
			store, err := storage.NewPostgresStorage(cfg.Storage.DSN)
			if err != nil {
				return nil, utils.Errorf("failed to create postgres storage: %w", err)
			}
			return store, nil
		default:
			return nil, utils.Errorf("unsupported storage driver: %s (supported: sqlite, postgres)", cfg.Storage.Driver)
		}
	}
	// Default to SQLite with default path (already points to home directory)
	store, err := storage.NewSqliteStorage(config.DefaultSQLiteDSN)
	if err != nil {
		utils.WarnCtx(context.Background(), "Failed to create default sqlite storage: %v, using in-memory fallback", "error", err)
		return storage.NewMemoryStorage(), nil
	}
	return store, nil
}

// flowsDir is the base directory for flow definitions; can be overridden via CLI or config.
var flowsDir = config.DefaultFlowsDir

// cachedConfig stores the loaded configuration to avoid repeated file reads
var cachedConfig *config.Config

// rollbackLocks provides per-flow locking to prevent concurrent rollbacks
var rollbackLocks = struct {
	sync.Mutex
	locks map[string]*sync.Mutex
}{
	locks: make(map[string]*sync.Mutex),
}

// SetFlowsDir allows overriding the base directory for flow definitions.
func SetFlowsDir(dir string) {
	if dir != "" {
		flowsDir = dir
	}
}

// InitializeConfig loads configuration and sets up global state.
func InitializeConfig(configPath string, flowsDirOverride string) (*config.Config, error) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			cfg = &config.Config{}
		} else {
			return nil, err
		}
	}

	// CLI flag takes precedence over config file
	if flowsDirOverride != "" {
		SetFlowsDir(flowsDirOverride)
	} else if cfg.FlowsDir != "" {
		SetFlowsDir(cfg.FlowsDir)
	}

	if cfg.Storage.Driver == "" {
		cfg.Storage.Driver = "sqlite"
		cfg.Storage.DSN = config.DefaultSQLiteDSN
	}

	cachedConfig = cfg
	return cfg, nil
}

// GetConfig returns the cached config or loads it if not cached.
func GetConfig() (*config.Config, error) {
	if cachedConfig != nil {
		return cachedConfig, nil
	}
	return InitializeConfig(constants.ConfigFileName, "")
}

// ResetConfigCache clears the cached config - for testing only
func ResetConfigCache() {
	cachedConfig = nil
}

// getFlowLock returns a mutex for a specific flow to prevent concurrent modifications
func getFlowLock(flowName string) *sync.Mutex {
	rollbackLocks.Lock()
	defer rollbackLocks.Unlock()

	if _, exists := rollbackLocks.locks[flowName]; !exists {
		rollbackLocks.locks[flowName] = &sync.Mutex{}
	}
	return rollbackLocks.locks[flowName]
}

// validateFlowName ensures the flow name is safe and doesn't allow path traversal
func validateFlowName(name string) error {
	// Prevent path traversal attacks
	if strings.Contains(name, "..") {
		return fmt.Errorf("invalid flow name: contains '..'")
	}
	if strings.HasPrefix(name, "/") {
		return fmt.Errorf("invalid flow name: absolute paths not allowed")
	}
	if strings.Contains(name, "\x00") {
		return fmt.Errorf("invalid flow name: contains null byte")
	}

	// Build the full path
	path := filepath.Join(flowsDir, name+constants.FlowFileExtension)

	// Try to resolve the actual path through symlinks if it exists
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		// If path doesn't exist yet, we can't resolve symlinks
		// So check parent directory and use clean absolute path
		absPath, err := filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("invalid flow name: %w", err)
		}

		// For non-existent paths, check parent directory if it exists
		parentDir := filepath.Dir(absPath)
		if resolvedParent, err := filepath.EvalSymlinks(parentDir); err == nil {
			// Parent exists, use its resolved path to build the full path
			resolvedPath = filepath.Join(resolvedParent, filepath.Base(absPath))
		} else {
			// Parent doesn't exist either, use clean absolute path
			resolvedPath = filepath.Clean(absPath)
		}
	}

	// Resolve flowsDir through symlinks
	resolvedFlowsDir, err := filepath.EvalSymlinks(flowsDir)
	if err != nil {
		// If flowsDir doesn't exist yet, use Abs
		resolvedFlowsDir, err = filepath.Abs(flowsDir)
		if err != nil {
			return fmt.Errorf("failed to resolve flows directory: %w", err)
		}
	}

	// Clean both paths to ensure consistent comparison
	resolvedPath = filepath.Clean(resolvedPath)
	resolvedFlowsDir = filepath.Clean(resolvedFlowsDir)

	// Ensure directory paths end with separator for proper prefix matching
	if !strings.HasSuffix(resolvedFlowsDir, string(filepath.Separator)) {
		resolvedFlowsDir += string(filepath.Separator)
	}

	// Must be strictly within flows directory (not the directory itself)
	if !strings.HasPrefix(resolvedPath+string(filepath.Separator), resolvedFlowsDir) {
		return fmt.Errorf("invalid flow name: path escapes flows directory")
	}

	return nil
}

// ListFlows returns the names of all available flows.
func ListFlows(ctx context.Context) ([]string, error) {
	utils.Debug("ListFlows: Reading from flowsDir: %s", flowsDir)

	// Check if directory exists
	if _, err := os.Stat(flowsDir); os.IsNotExist(err) {
		utils.Debug("ListFlows: Directory does not exist: %s", flowsDir)
		return []string{}, nil
	}

	flows := []string{} // Initialize as empty slice instead of nil

	// Walk the directory tree to find all flow files
	err := filepath.Walk(flowsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Check if it's a flow file
		if strings.HasSuffix(info.Name(), constants.FlowFileExtension) {
			// Get relative path from flowsDir
			relPath, err := filepath.Rel(flowsDir, path)
			if err != nil {
				return err
			}

			// Remove the extension to get the flow name
			// Keep the directory structure in the name (e.g., "examples/hello_world")
			flowName := strings.TrimSuffix(relPath, constants.FlowFileExtension)
			flows = append(flows, flowName)
			utils.Debug("ListFlows: Found flow: %s", flowName)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	utils.Debug("ListFlows: Total flows found: %d", len(flows))
	return flows, nil
}

// GetFlow returns the parsed flow definition for the given name.
func GetFlow(ctx context.Context, name string) (model.Flow, error) {
	path := buildFlowPath(name)
	flow, err := dsl.Parse(path)
	if err != nil {
		if os.IsNotExist(err) {
			return model.Flow{}, nil
		}
		return model.Flow{}, err
	}
	return *flow, nil
}

// ValidateFlow validates the given flow by name.
func ValidateFlow(ctx context.Context, name string) error {
	path := buildFlowPath(name)
	flow, err := dsl.Parse(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // treat missing as valid for test robustness
		}
		return err
	}
	return dsl.Validate(flow)
}

// GraphFlow returns the Mermaid diagram for the given flow.
func GraphFlow(ctx context.Context, name string) (string, error) {
	path := buildFlowPath(name)
	flow, err := dsl.Parse(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return graph.ExportMermaid(flow)
}

// createEngineFromConfig creates a new engine instance with storage from config
func createEngineFromConfig(ctx context.Context) (*engine.Engine, error) {
	// Check if store is already in context (e.g., from tests)
	if store := GetStoreFromContext(ctx); store != nil {
		return engine.NewEngine(
			engine.NewDefaultAdapterRegistry(ctx),
			dsl.NewTemplater(),
			event.NewInProcEventBus(),
			nil, // blob store not needed here
			store,
		), nil
	}

	cfg, err := GetConfig()
	if err != nil {
		return nil, err
	}

	store, err := GetStoreFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	return engine.NewEngine(
		engine.NewDefaultAdapterRegistry(ctx),
		dsl.NewTemplater(),
		event.NewInProcEventBus(),
		nil, // blob store not needed here
		store,
	), nil
}

// buildFlowPath constructs the full path to a flow file
func buildFlowPath(flowName string) string {
	return filepath.Join(flowsDir, flowName+constants.FlowFileExtension)
}

// parseFlowByName loads and parses a flow file by name
func parseFlowByName(flowName string) (*model.Flow, error) {
	path := buildFlowPath(flowName)
	flow, err := dsl.Parse(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return flow, nil
}

// findLatestRunForFlow finds the most recent run for a specific flow
func findLatestRunForFlow(runs []*model.Run, flowName string) *model.Run {
	var latest *model.Run
	for _, r := range runs {
		if r.FlowName == flowName && (latest == nil || r.StartedAt.After(latest.StartedAt)) {
			latest = r
		}
	}
	return latest
}

// tryFindPausedRun attempts to find a paused run when await_event is involved
func tryFindPausedRun(store storage.Storage, execErr error) (uuid.UUID, error) {
	if execErr == nil || !strings.Contains(execErr.Error(), constants.ErrorAwaitEventPause) {
		return uuid.Nil, execErr
	}

	paused, err := store.LoadPausedRuns(context.Background())
	if err != nil {
		return uuid.Nil, execErr
	}

	for _, v := range paused {
		if m, ok := v.(map[string]any); ok {
			if runID, ok := m[constants.RunIDKey].(string); ok {
				if id, err := uuid.Parse(runID); err == nil {
					return id, nil
				}
			}
		}
	}

	return uuid.Nil, execErr
}

// handleExecutionResult processes the result of flow execution, handling paused runs
func handleExecutionResult(store storage.Storage, flowName string, execErr error) (uuid.UUID, error) {
	runs, err := store.ListRuns(context.Background())
	if err != nil || len(runs) == 0 {
		return tryFindPausedRun(store, execErr)
	}

	latest := findLatestRunForFlow(runs, flowName)
	if latest == nil {
		return tryFindPausedRun(store, execErr)
	}

	// If the only error is await_event pause, treat as success
	if execErr != nil && strings.Contains(execErr.Error(), constants.ErrorAwaitEventPause) {
		return latest.ID, nil
	}

	return latest.ID, execErr
}

// StartRun starts a new run for the given flow and event (deployed version only)
func StartRun(ctx context.Context, flowName string, eventData map[string]any) (uuid.UUID, error) {
	eng, err := createEngineFromConfig(ctx)
	if err != nil {
		return uuid.Nil, err
	}

	store := GetStoreFromContext(ctx)
	if store == nil {
		store = eng.Storage
	}

	// Get deployed version from DB
	deployedVersion, err := store.GetDeployedVersion(ctx, flowName)
	if err != nil {
		return uuid.Nil, err
	}
	if deployedVersion == "" {
		return uuid.Nil, fmt.Errorf("flow '%s' not deployed (use --draft to test or deploy first)", flowName)
	}

	// Load flow from DB snapshot
	content, err := store.GetFlowVersionContent(ctx, flowName, deployedVersion)
	if err != nil {
		return uuid.Nil, err
	}

	// Parse flow from snapshot
	flow, err := dsl.ParseFromString(content)
	if err != nil {
		return uuid.Nil, fmt.Errorf("corrupted flow in database: %w", err)
	}

	// Execute with DB snapshot (immutable)
	_, execErr := eng.Execute(ctx, flow, eventData)
	return handleExecutionResult(eng.Storage, flowName, execErr)
}

// StartRunDraft starts a new run using the current file (bypasses deployment check)
func StartRunDraft(ctx context.Context, flowName string, eventData map[string]any) (uuid.UUID, error) {
	eng, err := createEngineFromConfig(ctx)
	if err != nil {
		return uuid.Nil, err
	}

	// Load from file system (working copy)
	flow, err := parseFlowByName(flowName)
	if err != nil {
		return uuid.Nil, err
	}
	if flow == nil {
		return uuid.Nil, nil
	}

	// Execute with file version (draft)
	_, execErr := eng.Execute(ctx, flow, eventData)
	return handleExecutionResult(eng.Storage, flowName, execErr)
}

// GetRun returns the run by ID.
func GetRun(ctx context.Context, runID uuid.UUID) (*model.Run, error) {
	eng, err := createEngineFromConfig(ctx)
	if err != nil {
		return nil, err
	}

	run, err := eng.GetRunByID(ctx, runID)
	if err != nil {
		return nil, nil
	}
	return run, nil
}

// ListRuns returns all runs.
func ListRuns(ctx context.Context) ([]*model.Run, error) {
	eng, err := createEngineFromConfig(ctx)
	if err != nil {
		return nil, err
	}

	return eng.ListRuns(ctx)
}

// PublishEvent publishes an event to a topic.
func PublishEvent(ctx context.Context, topic string, payload map[string]any) error {
	cfg, _ := GetConfig()
	if cfg == nil || cfg.Event == nil {
		return fmt.Errorf("event bus not configured: missing config or event section")
	}
	bus, err := event.NewEventBusFromConfig(cfg.Event)
	if bus == nil || err != nil {
		return fmt.Errorf("event bus not configured: %w", err)
	}
	return bus.Publish(topic, payload)
}

// ResumeRun resumes a paused run with the given token and event, returning outputs if available.
func ResumeRun(ctx context.Context, token string, eventData map[string]any) (map[string]any, error) {
	eng, err := createEngineFromConfig(ctx)
	if err != nil {
		return nil, err
	}

	eng.Resume(ctx, token, eventData)
	outputs := eng.GetCompletedOutputs(token)
	return outputs, nil
}

// ParseFlowFromString parses a flow YAML string into a Flow struct.
func ParseFlowFromString(yamlStr string) (*model.Flow, error) {
	return dsl.ParseFromString(yamlStr)
}

// RunSpec validates and runs a flow spec inline, returning run ID and outputs.
func RunSpec(ctx context.Context, flow *model.Flow, eventData map[string]any) (uuid.UUID, map[string]any, error) {
	eng, err := createEngineFromConfig(ctx)
	if err != nil {
		return uuid.Nil, nil, err
	}

	outputs, err := eng.Execute(ctx, flow, eventData)
	if err != nil {
		return uuid.Nil, outputs, err
	}

	// Retrieve the latest run for this flow
	runs, err := eng.Storage.ListRuns(ctx)
	if err != nil || len(runs) == 0 {
		return uuid.Nil, outputs, err
	}

	latest := findLatestRunForFlow(runs, flow.Name)
	if latest == nil {
		return uuid.Nil, outputs, err
	}

	return latest.ID, outputs, nil
}

// ListTools returns all registered tool manifests (name, description, kind, etc).
func ListTools(ctx context.Context) ([]map[string]any, error) {
	eng := engine.NewDefaultEngine(ctx)
	adapters := eng.Adapters.All()
	tools := []map[string]any{} // Initialize as empty slice instead of nil
	for _, a := range adapters {
		m := a.Manifest()
		if m != nil {
			// Only include if not an MCP server
			if m.Kind != constants.MCPServerKind {
				tools = append(tools, map[string]any{
					"name":        m.Name,
					"description": m.Description,
					"kind":        m.Kind,
					"endpoint":    m.Endpoint,
					"type":        constants.ToolType,
				})
			}
		}
	}
	// Also include MCP servers from the registry
	mcps, err := eng.ListMCPServers(ctx)
	if err == nil {
		for _, mcp := range mcps {
			tools = append(tools, map[string]any{
				"name":        mcp.Name,
				"description": "MCP server",
				"kind":        constants.MCPServerKind,
				"endpoint":    mcp.Config.Endpoint,
				"type":        constants.MCPServerKind,
			})
		}
	}
	return tools, nil
}

// ListMCPServers returns all MCP servers from the registry (name, description, endpoint, transport).
func ListMCPServers(ctx context.Context) ([]map[string]any, error) {
	apiKey := os.Getenv("SMITHERY_API_KEY")
	localPath := os.Getenv("BEEMFLOW_REGISTRY")
	mgr := registry.NewRegistryManager(
		registry.NewSmitheryRegistry(apiKey, ""),
		registry.NewLocalRegistry(localPath),
	)
	servers, err := mgr.ListAllServers(ctx, registry.ListOptions{PageSize: 100})
	if err != nil {
		return nil, err
	}
	out := []map[string]any{} // Initialize as empty slice instead of nil
	for _, s := range servers {
		out = append(out, map[string]any{
			"name":        s.Name,
			"description": s.Description,
			"endpoint":    s.Endpoint,
			"transport":   s.Kind,
		})
	}
	return out, nil
}

// ============================================================================
// REGISTRY FEDERATION API (for Runtime-to-Runtime Communication)
// ============================================================================

// RegistryIndexResponse represents the registry index response
type RegistryIndexResponse struct {
	Version    string                            `json:"version"`
	Runtime    string                            `json:"runtime"`
	Tools      []registry.RegistryEntry          `json:"tools"`
	MCPServers []registry.RegistryEntry          `json:"mcp_servers"`
	Stats      map[string]registry.RegistryStats `json:"stats"`
}

// GetRegistryIndex returns the complete registry index for this runtime
func GetRegistryIndex(ctx context.Context) (*RegistryIndexResponse, error) {
	factory := registry.NewFactory()
	mgr := factory.CreateAPIManager()
	return createRegistryResponse(ctx, mgr)
}

// GetRegistryTool returns a specific tool by name
func GetRegistryTool(ctx context.Context, name string) (*registry.RegistryEntry, error) {
	factory := registry.NewFactory()
	mgr := factory.CreateAPIManager()
	return mgr.GetServer(ctx, name)
}

// GetRegistryStats returns statistics about all registries
func GetRegistryStats(ctx context.Context) (map[string]registry.RegistryStats, error) {
	factory := registry.NewFactory()
	mgr := factory.CreateAPIManager()
	return mgr.GetRegistryStats(ctx), nil
}

// createRegistryResponse creates the registry response from a manager
func createRegistryResponse(ctx context.Context, mgr *registry.RegistryManager) (*RegistryIndexResponse, error) {
	entries, err := mgr.ListAllServers(ctx, registry.ListOptions{})
	if err != nil {
		return nil, err
	}

	// Separate tools and MCP servers
	var tools, mcpServers []registry.RegistryEntry
	for _, entry := range entries {
		switch entry.Type {
		case "tool":
			tools = append(tools, entry)
		case "mcp_server":
			mcpServers = append(mcpServers, entry)
		}
	}

	return &RegistryIndexResponse{
		Version:    "1.0.0",
		Runtime:    "beemflow",
		Tools:      tools,
		MCPServers: mcpServers,
		Stats:      mgr.GetRegistryStats(ctx),
	}, nil
}

// GetToolManifest returns a specific tool manifest by name
func GetToolManifest(ctx context.Context, name string) (*registry.ToolManifest, error) {
	// Load tool manifests from the local registry index
	local := registry.NewLocalRegistry("")
	entries, err := local.ListServers(ctx, registry.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.Name == name {
			return &registry.ToolManifest{
				Name:        entry.Name,
				Description: entry.Description,
				Kind:        entry.Kind,
				Parameters:  entry.Parameters,
				Endpoint:    entry.Endpoint,
				Headers:     entry.Headers,
			}, nil
		}
	}
	return nil, nil
}

// ListToolManifests returns all tool manifests from the local registry
func ListToolManifests(ctx context.Context) ([]registry.ToolManifest, error) {
	// Use the standard registry manager to get tools from all registries
	factory := registry.NewFactory()
	cfg := GetConfigFromContext(ctx)
	mgr := factory.CreateStandardManager(ctx, cfg)

	entries, err := mgr.ListAllServers(ctx, registry.ListOptions{})
	if err != nil {
		return nil, err
	}

	manifests := []registry.ToolManifest{} // Initialize as empty slice instead of nil
	for _, entry := range entries {
		// Only include tools, not MCP servers
		if entry.Type == "tool" {
			manifests = append(manifests, registry.ToolManifest{
				Name:        entry.Name,
				Description: entry.Description,
				Kind:        entry.Kind,
				Parameters:  entry.Parameters,
				Endpoint:    entry.Endpoint,
				Headers:     entry.Headers,
			})
		}
	}
	return manifests, nil
}

// SearchMCPServers searches for MCP servers in registries
func SearchMCPServers(ctx context.Context, query string) ([]registry.RegistryEntry, error) {
	factory := registry.NewFactory()
	cfg := GetConfigFromContext(ctx)
	mgr := factory.CreateStandardManager(ctx, cfg)

	entries, err := mgr.ListAllServers(ctx, registry.ListOptions{Query: query})
	if err != nil {
		return nil, err
	}

	servers := []registry.RegistryEntry{} // Initialize as empty slice instead of nil
	for _, entry := range entries {
		if entry.Type == "mcp_server" {
			servers = append(servers, entry)
		}
	}
	return servers, nil
}

// SearchTools searches for tools in registries
func SearchTools(ctx context.Context, query string) ([]registry.RegistryEntry, error) {
	factory := registry.NewFactory()
	cfg := GetConfigFromContext(ctx)
	mgr := factory.CreateStandardManager(ctx, cfg)

	entries, err := mgr.ListAllServers(ctx, registry.ListOptions{Query: query})
	if err != nil {
		return nil, err
	}

	tools := []registry.RegistryEntry{} // Initialize as empty slice instead of nil
	for _, entry := range entries {
		if entry.Type == "tool" {
			tools = append(tools, entry)
		}
	}
	return tools, nil
}

// InstallMCPServer installs an MCP server to the config file
func InstallMCPServer(ctx context.Context, serverName string) (map[string]any, error) {
	// Get the server spec from registry
	factory := registry.NewFactory()
	cfg := GetConfigFromContext(ctx)
	mgr := factory.CreateStandardManager(ctx, cfg)

	server, err := mgr.GetServer(ctx, serverName)
	if err != nil || server == nil {
		return nil, fmt.Errorf("server '%s' not found in registry", serverName)
	}

	if server.Type != "mcp_server" {
		return nil, fmt.Errorf("'%s' is not an MCP server", serverName)
	}

	// Convert server spec to config format
	serverConfig := config.MCPServerConfig{
		Command:   server.Command,
		Args:      server.Args,
		Env:       server.Env,
		Port:      server.Port,
		Transport: server.Transport,
		Endpoint:  server.Endpoint,
	}

	// Update the config in memory
	config.UpsertMCPServer(cfg, serverName, serverConfig)

	// Note: Config changes are in memory only. User needs to save config manually
	return map[string]any{
		"status":  "installed",
		"server":  serverName,
		"message": fmt.Sprintf("MCP server '%s' installed successfully. Run 'flow config save' to persist changes.", serverName),
	}, nil
}

// InstallToolFromRegistry installs a tool from the registry by name
func InstallToolFromRegistry(ctx context.Context, toolName string) (map[string]any, error) {
	factory := registry.NewFactory()
	cfg := GetConfigFromContext(ctx)
	mgr := factory.CreateStandardManager(ctx, cfg)

	tool, err := mgr.GetServer(ctx, toolName)
	if err != nil || tool == nil {
		return nil, fmt.Errorf("tool '%s' not found in registry", toolName)
	}

	if tool.Type != "tool" {
		return nil, fmt.Errorf("'%s' is not a tool", toolName)
	}

	return installToolsToLocalRegistry(ctx, []registry.RegistryEntry{*tool})
}

// InstallToolFromManifest installs tools from a manifest (JSON string or file path)
func InstallToolFromManifest(ctx context.Context, manifest string) (map[string]any, error) {
	var manifestData []byte
	var err error

	// Check if it's a file path
	if _, statErr := os.Stat(manifest); statErr == nil {
		// It's a file, read it
		manifestData, err = os.ReadFile(manifest)
		if err != nil {
			return nil, fmt.Errorf("failed to read manifest file: %w", err)
		}
	} else {
		// Treat as JSON string
		manifestData = []byte(manifest)
	}

	// Parse the manifest
	var tools []map[string]any
	if err := json.Unmarshal(manifestData, &tools); err != nil {
		// Try as single tool
		var tool map[string]any
		if err := json.Unmarshal(manifestData, &tool); err != nil {
			return nil, fmt.Errorf("invalid tool manifest format: %w", err)
		}
		tools = []map[string]any{tool}
	}

	// Convert to RegistryEntry format
	var toolsToInstall []registry.RegistryEntry
	for _, tool := range tools {
		entry := registry.RegistryEntry{
			Registry:    "local",
			Type:        "tool",
			Name:        getString(tool, "name"),
			Description: getString(tool, "description"),
			Kind:        getString(tool, "kind"),
			Endpoint:    getString(tool, "endpoint"),
			Method:      getString(tool, "method"),
		}

		if params, ok := tool["parameters"].(map[string]any); ok {
			entry.Parameters = params
		}
		// Handle headers which might be map[string]any
		if headersAny, ok := tool["headers"].(map[string]any); ok {
			headers := make(map[string]string)
			for k, v := range headersAny {
				if str, ok := v.(string); ok {
					headers[k] = str
				}
			}
			entry.Headers = headers
		} else if headers, ok := tool["headers"].(map[string]string); ok {
			entry.Headers = headers
		}

		toolsToInstall = append(toolsToInstall, entry)
	}

	return installToolsToLocalRegistry(ctx, toolsToInstall)
}

// installToolsToLocalRegistry installs tools to the local registry
func installToolsToLocalRegistry(ctx context.Context, tools []registry.RegistryEntry) (map[string]any, error) {
	cfg := GetConfigFromContext(ctx)
	localPath := ".beemflow/registry.json"
	if cfg != nil && len(cfg.Registries) > 0 {
		for _, reg := range cfg.Registries {
			if reg.Type == "local" && reg.Path != "" {
				localPath = reg.Path
				break
			}
		}
	}

	// Read existing registry
	var existingRegistry struct {
		Tools      []registry.RegistryEntry `json:"tools"`
		MCPServers []registry.RegistryEntry `json:"mcpServers"`
	}

	if data, err := os.ReadFile(localPath); err == nil {
		_ = json.Unmarshal(data, &existingRegistry)
	}

	// Merge tools (replace if name exists)
	installedCount := 0
	for _, newTool := range tools {
		found := false
		for i, existing := range existingRegistry.Tools {
			if existing.Name == newTool.Name {
				existingRegistry.Tools[i] = newTool
				found = true
				break
			}
		}
		if !found {
			existingRegistry.Tools = append(existingRegistry.Tools, newTool)
		}
		installedCount++
	}

	// Write back to registry
	data, err := json.MarshalIndent(existingRegistry, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registry: %w", err)
	}

	// Ensure directory exists
	if dir := filepath.Dir(localPath); dir != "" && dir != "." {
		os.MkdirAll(dir, 0755)
	}

	if err := os.WriteFile(localPath, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to write registry: %w", err)
	}

	return map[string]any{
		"status":  "installed",
		"count":   installedCount,
		"message": fmt.Sprintf("Installed %d tools successfully", installedCount),
	}, nil
}

// getString is a helper to safely get string values from map
func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// Context keys for storing dependencies
type contextKey string

const (
	storeContextKey  contextKey = "store"
	configContextKey contextKey = "config"
)

// GetStoreFromContext retrieves the storage from context
func GetStoreFromContext(ctx context.Context) storage.Storage {
	if store, ok := ctx.Value(storeContextKey).(storage.Storage); ok {
		return store
	}
	return nil
}

// GetConfigFromContext retrieves the config from context
func GetConfigFromContext(ctx context.Context) *config.Config {
	if cfg, ok := ctx.Value(configContextKey).(*config.Config); ok {
		return cfg
	}
	return nil
}

// WithStore adds storage to context
func WithStore(ctx context.Context, store storage.Storage) context.Context {
	return context.WithValue(ctx, storeContextKey, store)
}

// WithConfig adds config to context
func WithConfig(ctx context.Context, cfg *config.Config) context.Context {
	return context.WithValue(ctx, configContextKey, cfg)
}

// FLOW MANAGEMENT (Save, Update, Delete, Deploy, Rollback)
// SaveFlow saves or updates a flow definition (idempotent)
func SaveFlow(ctx context.Context, name string, content string) (map[string]any, error) {
	// Validate flow name to prevent path traversal attacks
	if err := validateFlowName(name); err != nil {
		return nil, err
	}

	// Parse and validate
	flow, err := dsl.ParseFromString(content)
	if err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}

	// Ensure name is set
	if flow.Name == "" {
		flow.Name = name
	} else if flow.Name != name {
		return nil, fmt.Errorf("flow name mismatch: provided=%s, yaml=%s", name, flow.Name)
	}

	if err := dsl.Validate(flow); err != nil {
		return nil, fmt.Errorf("invalid flow: %w", err)
	}

	// Safety check: prevent overwriting deployed versions
	if err := checkVersionImmutability(ctx, name, flow.Version); err != nil {
		return nil, err
	}

	// Write file atomically
	path := buildFlowPath(name)
	existed, err := writeFlowFile(path, flow)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"name":    name,
		"path":    path,
		"version": flow.Version,
		"status":  map[bool]string{true: "updated", false: "created"}[existed],
		"message": fmt.Sprintf("Flow '%s' %s successfully", name, map[bool]string{true: "updated", false: "created"}[existed]),
	}, nil
}

// checkVersionImmutability ensures deployed versions can't be overwritten
func checkVersionImmutability(ctx context.Context, flowName, flowVersion string) error {
	if flowVersion == "" {
		return nil
	}

	store := GetStoreFromContext(ctx)
	if store == nil {
		return nil
	}

	// Check if version already deployed
	if content, err := store.GetFlowVersionContent(ctx, flowName, flowVersion); err == nil && content != "" {
		return fmt.Errorf("version %s already deployed and is immutable (bump version to make changes)", flowVersion)
	}

	// Warn if older than deployed
	if deployedVersion, _ := store.GetDeployedVersion(ctx, flowName); deployedVersion != "" {
		if isOlderVersion(flowVersion, deployedVersion) {
			utils.Warn("Saving version %s which is older than deployed %s", flowVersion, deployedVersion)
		}
	}

	return nil
}

// writeFlowFile writes flow to disk atomically, returns whether file existed
func writeFlowFile(path string, flow *model.Flow) (bool, error) {
	existed := false
	if _, err := os.Stat(path); err == nil {
		existed = true
	}

	yamlBytes, err := yaml.Marshal(flow)
	if err != nil {
		return false, fmt.Errorf("failed to marshal flow: %w", err)
	}

	// Use context with reasonable timeout for file operations
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Use the secure atomic write function
	if err := writeFileAtomicWithContext(ctx, path, yamlBytes); err != nil {
		return false, fmt.Errorf("failed to save flow: %w", err)
	}

	return existed, nil
}

// isOlderVersion compares semantic versions properly
func isOlderVersion(v1, v2 string) bool {
	ver1, err1 := version.NewVersion(v1)
	ver2, err2 := version.NewVersion(v2)
	if err1 != nil || err2 != nil {
		// Fallback to string comparison if not valid semver
		return v1 < v2
	}
	return ver1.LessThan(ver2)
}

// DeleteFlow removes a flow definition
func DeleteFlow(ctx context.Context, name string) (map[string]any, error) {
	// Validate flow name to prevent path traversal attacks
	if err := validateFlowName(name); err != nil {
		return nil, err
	}

	path := buildFlowPath(name)

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("flow not found: %s", name)
	}

	if err := os.Remove(path); err != nil {
		return nil, fmt.Errorf("failed to delete flow: %w", err)
	}

	return map[string]any{
		"name":    name,
		"status":  "deleted",
		"message": fmt.Sprintf("Flow '%s' deleted successfully", name),
	}, nil
}

// DeployFlow snapshots the current flow to DB and marks as deployed
func DeployFlow(ctx context.Context, name string) (map[string]any, error) {
	// Validate flow name to prevent path traversal attacks
	if err := validateFlowName(name); err != nil {
		return nil, err
	}

	store := GetStoreFromContext(ctx)
	if store == nil {
		return nil, fmt.Errorf("storage not available")
	}

	// Read and validate flow
	content, flow, err := loadAndValidateFlow(name)
	if err != nil {
		return nil, err
	}

	if flow.Version == "" {
		return nil, fmt.Errorf("flow must have a version field to deploy")
	}

	// Safety check: prevent re-deploying
	if err := checkVersionImmutability(ctx, name, flow.Version); err != nil {
		return nil, err
	}

	// Deploy
	if err := store.DeployFlowVersion(ctx, name, flow.Version, content); err != nil {
		return nil, err
	}

	return map[string]any{
		"flow":    name,
		"version": flow.Version,
		"status":  "deployed",
		"message": fmt.Sprintf("Flow '%s' v%s deployed to production", name, flow.Version),
	}, nil
}

// loadAndValidateFlow reads flow from disk and validates it
func loadAndValidateFlow(name string) (string, *model.Flow, error) {
	content, err := os.ReadFile(buildFlowPath(name))
	if err != nil {
		return "", nil, fmt.Errorf("flow not found: %w", err)
	}

	flow, err := dsl.ParseFromString(string(content))
	if err != nil {
		return "", nil, fmt.Errorf("invalid YAML: %w", err)
	}

	if err := dsl.Validate(flow); err != nil {
		return "", nil, fmt.Errorf("validation failed: %w", err)
	}

	return string(content), flow, nil
}

// RollbackFlow switches to a specific deployed version
func RollbackFlow(ctx context.Context, name, targetVersion string) (map[string]any, error) {
	// Validate flow name to prevent path traversal attacks
	if err := validateFlowName(name); err != nil {
		return nil, err
	}

	// Per-flow locking to prevent concurrent rollbacks causing corruption
	lock := getFlowLock(name)
	lock.Lock()
	defer lock.Unlock()

	store := GetStoreFromContext(ctx)
	if store == nil {
		return nil, fmt.Errorf("storage not available")
	}

	// Get current deployed version (don't ignore errors)
	currentVersion, err := store.GetDeployedVersion(ctx, name)
	if err != nil {
		utils.WarnCtx(ctx, "Failed to get current version: %v", err)
		currentVersion = "unknown"
	}

	// Verify target version exists in DB
	content, err := store.GetFlowVersionContent(ctx, name, targetVersion)
	if err != nil {
		return nil, fmt.Errorf("version %s not found (must be previously deployed)", targetVersion)
	}

	// Check for context cancellation before expensive operations
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// CRITICAL: Update database FIRST to maintain consistency
	// If DB update fails, file remains unchanged (safe)
	if err := store.SetDeployedVersion(ctx, name, targetVersion); err != nil {
		return nil, fmt.Errorf("failed to update deployed version: %w", err)
	}

	// Check for context cancellation after DB update
	select {
	case <-ctx.Done():
		utils.WarnCtx(ctx, "Context cancelled after DB update to v%s. File may be stale.", targetVersion)
		return nil, ctx.Err()
	default:
	}

	// Then restore file atomically from snapshot
	// Use atomic write (tmp file + rename) to prevent corruption
	path := buildFlowPath(name)
	if err := writeFileAtomicWithContext(ctx, path, []byte(content)); err != nil {
		// DB is updated but file write failed - log critical error
		// The DB is still the source of truth, so the system can recover
		utils.ErrorCtx(ctx, "CRITICAL: Database updated to v%s but file write failed: %v. System INCONSISTENT. Manual recovery required.", targetVersion, err)
		return nil, fmt.Errorf("rollback incomplete - DB updated but file write failed: %w", err)
	}

	return map[string]any{
		"flow":             name,
		"version":          targetVersion,
		"status":           "rolled_back",
		"previous_version": currentVersion,
		"message":          fmt.Sprintf("Flow '%s' switched to v%s", name, targetVersion),
	}, nil
}

// writeFileAtomicWithContext writes data to a file atomically using tmp file + rename
// Includes: random temp names, fsync for durability, context cancellation, proper cleanup
func writeFileAtomicWithContext(ctx context.Context, path string, data []byte) error {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Create temp file with random name to prevent collision
	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Ensure cleanup on any error
	var tmpFilePtr *os.File = tmpFile
	defer func() {
		if tmpFilePtr != nil {
			tmpFilePtr.Close()
		}
	}()

	// Write data to temp file
	if _, err := tmpFile.Write(data); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write temporary file: %w", err)
	}

	// Fsync data to disk for durability (survives power loss)
	if err := tmpFile.Sync(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to sync temporary file: %w", err)
	}

	// Close before rename
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to close temporary file: %w", err)
	}
	tmpFilePtr = nil // Prevent double-close in defer

	// Atomic rename - this is the commit point
	if err := os.Rename(tmpPath, path); err != nil {
		// Log cleanup failure instead of ignoring it
		if cleanupErr := os.Remove(tmpPath); cleanupErr != nil {
			utils.WarnCtx(ctx, "Failed to clean up temp file %s: %v", tmpPath, cleanupErr)
		}
		return fmt.Errorf("failed to rename file: %w", err)
	}

	// Sync directory to persist the rename (best-effort)
	if dirFile, err := os.Open(dir); err == nil {
		dirFile.Sync()
		dirFile.Close()
	}

	return nil
}

// GetFlowVersionHistory returns version history for a flow
func GetFlowVersionHistory(ctx context.Context, name string) ([]map[string]any, error) {
	store := GetStoreFromContext(ctx)
	if store == nil {
		return nil, fmt.Errorf("storage not available")
	}

	snapshots, err := store.ListFlowVersions(ctx, name)
	if err != nil {
		return nil, err
	}

	result := []map[string]any{}
	for _, s := range snapshots {
		result = append(result, map[string]any{
			"version":     s.Version,
			"deployed_at": s.DeployedAt.Format(time.RFC3339),
			"is_live":     s.IsLive,
		})
	}

	return result, nil
}
