package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"sync"

	"github.com/beemflow/beemflow/config"
	"github.com/beemflow/beemflow/constants"
	mcpmanager "github.com/beemflow/beemflow/mcp"
	"github.com/beemflow/beemflow/registry"
	"github.com/beemflow/beemflow/utils"
	mcp "github.com/metoro-io/mcp-golang"
	mcpstdio "github.com/metoro-io/mcp-golang/transport/stdio"
)

// MCPAdapter implements Adapter for mcp://server/tool URIs.
type MCPAdapter struct {
	clients map[string]*mcp.Client
	// For stdio support:
	processes map[string]*exec.Cmd // MCP server processes per host
	pipes     map[string]struct {
		stdin  io.WriteCloser
		stdout io.ReadCloser
	}
	mu     sync.Mutex // protects clients, processes, pipes
	closed bool       // tracks if Close has been called
}

// NewMCPAdapter creates a new MCPAdapter with an empty client cache.
func NewMCPAdapter() *MCPAdapter {
	return &MCPAdapter{
		clients:   make(map[string]*mcp.Client),
		processes: make(map[string]*exec.Cmd),
		pipes: make(map[string]struct {
			stdin  io.WriteCloser
			stdout io.ReadCloser
		}),
	}
}

// ID returns the adapter ID.
func (a *MCPAdapter) ID() string {
	return "mcp"
}

var mcpRe = regexp.MustCompile(`^mcp://([^/]+)/([\w.-]+)$`)

// Helper to resolve MCP server config from environment/config file.
func getMCPServerConfig(host string) (config.MCPServerConfig, error) {
	cfgPath := constants.ConfigFileName
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		return config.MCPServerConfig{}, err
	}
	return config.GetMergedMCPServerConfig(cfg, host)
}

// validateMCPRequest validates and parses the MCP request format.
func (a *MCPAdapter) validateMCPRequest(inputs map[string]any) (host, tool string, err error) {
	use, ok := inputs["__use"].(string)
	if !ok {
		return "", "", fmt.Errorf("missing __use for MCPAdapter")
	}
	matches := mcpRe.FindStringSubmatch(use)
	if len(matches) != 3 {
		return "", "", fmt.Errorf("invalid mcp:// identifier: %s", use)
	}
	return matches[1], matches[2], nil
}

// setupHTTPClient creates an HTTP-based MCP client and calls the tool.
func (a *MCPAdapter) setupHTTPClient(cfg config.MCPServerConfig, tool string, inputs map[string]any) (map[string]any, error) {
	// List tools first to validate tool exists
	if err := a.validateHTTPTool(cfg.Endpoint, tool); err != nil {
		return nil, err
	}

	// Call the tool
	return a.callHTTPTool(cfg.Endpoint, tool, inputs)
}

// validateHTTPTool checks if a tool exists on the HTTP MCP server.
func (a *MCPAdapter) validateHTTPTool(endpoint, tool string) error {
	listReq := map[string]any{"method": "tools/list", "params": []any{}, "id": 1}
	bodyBytes, err := json.Marshal(listReq)
	if err != nil {
		return fmt.Errorf("failed to marshal tools/list request: %w", err)
	}

	resp, err := http.Post(endpoint, constants.ContentTypeJSON, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to list tools: %w", err)
	}
	defer resp.Body.Close()

	var listResp struct{ Tools []struct{ Name string } }
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return fmt.Errorf("failed to decode tools list: %w", err)
	}

	for _, t := range listResp.Tools {
		if t.Name == tool {
			return nil
		}
	}
	return fmt.Errorf("tool %s not found on MCP server", tool)
}

// callHTTPTool executes a tool call via HTTP.
func (a *MCPAdapter) callHTTPTool(endpoint, tool string, inputs map[string]any) (map[string]any, error) {
	callReq := map[string]any{
		"method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": inputs},
		"id":     1,
	}

	callBytes, err := json.Marshal(callReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tools/call request: %w", err)
	}

	resp, err := http.Post(endpoint, constants.ContentTypeJSON, bytes.NewReader(callBytes))
	if err != nil {
		return nil, fmt.Errorf("MCP CallTool failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			utils.Warn("Failed to close MCP HTTP response body: %v", closeErr)
		}
	}()

	var callResp struct{ Result map[string]any }
	if err := json.NewDecoder(resp.Body).Decode(&callResp); err != nil {
		return nil, fmt.Errorf("failed to decode call response: %w", err)
	}

	return callResp.Result, nil
}

// setupStdioClient creates or retrieves a stdio-based MCP client.
func (a *MCPAdapter) setupStdioClient(ctx context.Context, host string, cfg config.MCPServerConfig) (*mcp.Client, error) {
	// Check if process is already running
	a.mu.Lock()
	cmd := a.processes[host]
	pipes := a.pipes[host]
	a.mu.Unlock()

	if cmd == nil {
		var err error
		_, pipes, err = a.startMCPProcess(host, cfg)
		if err != nil {
			return nil, err
		}
	}

	transport := mcpstdio.NewStdioServerTransportWithIO(pipes.stdout, pipes.stdin)
	client := mcp.NewClient(transport)

	if _, err := client.Initialize(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize MCP stdio client: %w", err)
	}

	a.mu.Lock()
	a.clients[host] = client
	a.mu.Unlock()

	return client, nil
}

// startMCPProcess starts a new MCP server process and sets up pipes.
func (a *MCPAdapter) startMCPProcess(host string, cfg config.MCPServerConfig) (*exec.Cmd, struct {
	stdin  io.WriteCloser
	stdout io.ReadCloser
}, error) {
	cmd := mcpmanager.NewMCPCommand(cfg)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, struct {
			stdin  io.WriteCloser
			stdout io.ReadCloser
		}{}, fmt.Errorf("failed to get stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, struct {
			stdin  io.WriteCloser
			stdout io.ReadCloser
		}{}, fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	cmd.Stderr = &utils.LoggerWriter{Fn: utils.Error, Prefix: "[MCP " + host + " ERR] "}

	if err := cmd.Start(); err != nil {
		return nil, struct {
			stdin  io.WriteCloser
			stdout io.ReadCloser
		}{}, fmt.Errorf("failed to start MCP server %s: %w", host, err)
	}

	pipes := struct {
		stdin  io.WriteCloser
		stdout io.ReadCloser
	}{stdin, stdout}

	a.mu.Lock()
	a.processes[host] = cmd
	a.pipes[host] = pipes
	a.mu.Unlock()

	return cmd, pipes, nil
}

// validateStdioTool checks if a tool exists on the stdio MCP server.
func (a *MCPAdapter) validateStdioTool(ctx context.Context, client *mcp.Client, tool, host string) error {
	toolsResp, err := client.ListTools(ctx, new(string))
	if err != nil {
		return fmt.Errorf("MCP ListTools failed: %w", err)
	}

	for _, t := range toolsResp.Tools {
		if t.Name == tool {
			return nil
		}
	}
	return fmt.Errorf("tool %s not found on MCP server %s", tool, host)
}

// prepareToolArgs extracts tool arguments from inputs, excluding metadata.
func (a *MCPAdapter) prepareToolArgs(inputs map[string]any) map[string]any {
	args := make(map[string]any, len(inputs))
	for k, v := range inputs {
		if k != "__use" {
			args[k] = v
		}
	}
	return args
}

// formatMCPResponse converts MCP response to a standardized format.
func (a *MCPAdapter) formatMCPResponse(resp interface{}) (map[string]any, error) {
	// Flatten simple text responses
	if respMap, ok := resp.(map[string]any); ok {
		if content, exists := respMap["content"].([]interface{}); exists && len(content) > 0 {
			if textContent, ok := content[0].(map[string]any); ok {
				if textData, exists := textContent["text"].(string); exists {
					return map[string]any{"text": textData}, nil
				}
			}
		}
	}

	// Handle complex responses
	b, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal MCP response: %w", err)
	}

	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("failed to unmarshal MCP response: %w", err)
	}

	return out, nil
}

// Execute calls a tool on the specified MCP server.
// Supports both HTTP and stdio transports with clean separation of concerns.
func (a *MCPAdapter) Execute(ctx context.Context, inputs map[string]any) (map[string]any, error) {
	// Parse and validate request
	host, tool, err := a.validateMCPRequest(inputs)
	if err != nil {
		return nil, err
	}

	// Check for existing client
	a.mu.Lock()
	client, exists := a.clients[host]
	a.mu.Unlock()

	if !exists {
		// Load server configuration
		cfg, err := getMCPServerConfig(host)
		if err != nil {
			return nil, err
		}

		// Route to appropriate transport
		switch {
		case cfg.Transport == "http" && cfg.Endpoint != "":
			return a.setupHTTPClient(cfg, tool, inputs)

		case cfg.Command != "":
			client, err = a.setupStdioClient(ctx, host, cfg)
			if err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("MCP server '%s' config is missing 'command' or 'http' transport config", host)
		}
	}

	// Validate tool exists on stdio server
	if err := a.validateStdioTool(ctx, client, tool, host); err != nil {
		return nil, err
	}

	// Prepare arguments and call tool
	args := a.prepareToolArgs(inputs)
	resp, err := client.CallTool(ctx, tool, args)
	if err != nil {
		return nil, fmt.Errorf("MCP CallTool failed: %w", err)
	}

	// Format and return response
	return a.formatMCPResponse(resp)
}

func (a *MCPAdapter) Manifest() *registry.ToolManifest {
	return nil
}

// Close terminates all started stdio MCP server processes and closes their pipes.
func (a *MCPAdapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	var firstErr error
	for host, cmd := range a.processes {
		if cmd.Process != nil {
			if err := cmd.Process.Kill(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if pipes, ok := a.pipes[host]; ok {
			if err := pipes.stdin.Close(); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("failed to close stdin for %s: %w", host, err)
			}
			if err := pipes.stdout.Close(); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("failed to close stdout for %s: %w", host, err)
			}
		}
		delete(a.processes, host)
		delete(a.pipes, host)
		delete(a.clients, host)
	}
	return firstErr
}
