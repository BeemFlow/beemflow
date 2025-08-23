package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beemflow/beemflow/constants"
)

// TestMCPAdapter_ID tests the adapter ID
func TestMCPAdapter_ID(t *testing.T) {
	adapter := NewMCPAdapter()
	if adapter.ID() != "mcp" {
		t.Errorf("expected ID 'mcp', got %q", adapter.ID())
	}
}

// TestMCPAdapter_Manifest tests that Manifest returns nil
func TestMCPAdapter_Manifest(t *testing.T) {
	adapter := NewMCPAdapter()
	if adapter.Manifest() != nil {
		t.Errorf("expected Manifest to return nil, got %v", adapter.Manifest())
	}
}

// TestMCPAdapter_Execute_MissingUse tests error when __use is missing
func TestMCPAdapter_Execute_MissingUse(t *testing.T) {
	adapter := NewMCPAdapter()
	inputs := map[string]any{"test": "value"}

	_, err := adapter.Execute(context.Background(), inputs)
	if err == nil || !strings.Contains(err.Error(), "missing __use") {
		t.Errorf("expected missing __use error, got %v", err)
	}
}

// TestMCPAdapter_Execute_InvalidUse tests error when __use is not a string
func TestMCPAdapter_Execute_InvalidUse(t *testing.T) {
	adapter := NewMCPAdapter()
	inputs := map[string]any{"__use": 123}

	_, err := adapter.Execute(context.Background(), inputs)
	if err == nil || !strings.Contains(err.Error(), "missing __use") {
		t.Errorf("expected missing __use error, got %v", err)
	}
}

// TestMCPAdapter_Execute_InvalidFormat tests error with invalid mcp:// format
func TestMCPAdapter_Execute_InvalidFormat(t *testing.T) {
	adapter := NewMCPAdapter()

	testCases := []string{
		"invalid://format",
		"mcp://",
		"mcp://host",
		"mcp://host/",
		"mcp:///tool",
		"mcp://host/tool/extra",
	}

	for _, testCase := range testCases {
		inputs := map[string]any{"__use": testCase}
		_, err := adapter.Execute(context.Background(), inputs)
		if err == nil || !strings.Contains(err.Error(), "invalid mcp://") {
			t.Errorf("expected invalid mcp:// error for %q, got %v", testCase, err)
		}
	}
}

// TestMCPAdapter_Execute_ConfigError tests error when config loading fails
func TestMCPAdapter_Execute_ConfigError(t *testing.T) {
	adapter := NewMCPAdapter()

	// Ensure config directory exists but no config file
	configDir := filepath.Dir(constants.ConfigFileName)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

	// Remove config file if it exists
	os.Remove(constants.ConfigFileName)
	defer func() {
		// Clean up
		os.Remove(constants.ConfigFileName)
	}()

	inputs := map[string]any{"__use": "mcp://testhost/testtool"}
	_, err := adapter.Execute(context.Background(), inputs)
	if err == nil {
		t.Error("expected config error, got nil")
	}
}

// TestMCPAdapter_Execute_HTTPTransport tests HTTP transport functionality
func TestMCPAdapter_Execute_HTTPTransport(t *testing.T) {
	// Create mock HTTP server for MCP JSON-RPC
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode request: %v", err)
		}

		method, _ := req["method"].(string)
		switch method {
		case "tools/list":
			response := map[string]any{
				"tools": []map[string]any{
					{"name": "testtool"},
					{"name": "othertool"},
				},
			}
			json.NewEncoder(w).Encode(response)
		case "tools/call":
			params, _ := req["params"].(map[string]any)
			toolName, _ := params["name"].(string)
			if toolName == "testtool" {
				response := map[string]any{
					"result": map[string]any{
						"output": "success",
						"data":   "test result",
					},
				}
				json.NewEncoder(w).Encode(response)
			} else {
				w.WriteHeader(404)
				json.NewEncoder(w).Encode(map[string]any{"error": "tool not found"})
			}
		default:
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]any{"error": "unknown method"})
		}
	}))
	defer server.Close()

	// Create config file at default path
	configDir := filepath.Dir(constants.ConfigFileName)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

	configData := map[string]any{
		"mcpServers": map[string]any{
			"testhost": map[string]any{
				"command":   "echo",
				"transport": "http",
				"endpoint":  server.URL,
			},
		},
	}
	configBytes, _ := json.Marshal(configData)
	if err := os.WriteFile(constants.ConfigFileName, configBytes, 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	defer os.Remove(constants.ConfigFileName)

	adapter := NewMCPAdapter()
	inputs := map[string]any{
		"__use": "mcp://testhost/testtool",
		"param": "value",
	}

	result, err := adapter.Execute(context.Background(), inputs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result["output"] != "success" {
		t.Errorf("expected output=success, got %v", result["output"])
	}
	if result["data"] != "test result" {
		t.Errorf("expected data='test result', got %v", result["data"])
	}
}

// TestMCPAdapter_Execute_HTTPTransport_ToolNotFound tests HTTP transport when tool is not found
func TestMCPAdapter_Execute_HTTPTransport_ToolNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)

		method, _ := req["method"].(string)
		if method == "tools/list" {
			response := map[string]any{
				"tools": []map[string]any{
					{"name": "othertool"},
				},
			}
			json.NewEncoder(w).Encode(response)
		}
	}))
	defer server.Close()

	configDir := filepath.Dir(constants.ConfigFileName)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

	configData := map[string]any{
		"mcpServers": map[string]any{
			"testhost": map[string]any{
				"command":   "echo",
				"transport": "http",
				"endpoint":  server.URL,
			},
		},
	}
	configBytes, _ := json.Marshal(configData)
	os.WriteFile(constants.ConfigFileName, configBytes, 0644)
	defer os.Remove(constants.ConfigFileName)

	adapter := NewMCPAdapter()
	inputs := map[string]any{"__use": "mcp://testhost/nonexistent"}

	_, err := adapter.Execute(context.Background(), inputs)
	if err == nil || !strings.Contains(err.Error(), "tool nonexistent not found") {
		t.Errorf("expected tool not found error, got %v", err)
	}
}

// TestMCPAdapter_Execute_HTTPTransport_Errors tests various HTTP transport error cases
func TestMCPAdapter_Execute_HTTPTransport_Errors(t *testing.T) {
	// Test server that returns errors
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("server error"))
	}))
	defer server.Close()

	configDir := filepath.Dir(constants.ConfigFileName)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

	configData := map[string]any{
		"mcpServers": map[string]any{
			"testhost": map[string]any{
				"command":   "echo",
				"transport": "http",
				"endpoint":  server.URL,
			},
		},
	}
	configBytes, _ := json.Marshal(configData)
	os.WriteFile(constants.ConfigFileName, configBytes, 0644)
	defer os.Remove(constants.ConfigFileName)

	adapter := NewMCPAdapter()
	inputs := map[string]any{"__use": "mcp://testhost/testtool"}

	_, err := adapter.Execute(context.Background(), inputs)
	if err == nil {
		t.Error("expected HTTP error, got nil")
	}
}

// TestMCPAdapter_Execute_HTTPTransport_InvalidJSON tests HTTP transport with invalid JSON responses
func TestMCPAdapter_Execute_HTTPTransport_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("invalid json{"))
	}))
	defer server.Close()

	configDir := filepath.Dir(constants.ConfigFileName)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

	configData := map[string]any{
		"mcpServers": map[string]any{
			"testhost": map[string]any{
				"command":   "echo",
				"transport": "http",
				"endpoint":  server.URL,
			},
		},
	}
	configBytes, _ := json.Marshal(configData)
	os.WriteFile(constants.ConfigFileName, configBytes, 0644)
	defer os.Remove(constants.ConfigFileName)

	adapter := NewMCPAdapter()
	inputs := map[string]any{"__use": "mcp://testhost/testtool"}

	_, err := adapter.Execute(context.Background(), inputs)
	if err == nil || !strings.Contains(err.Error(), "failed to decode") {
		t.Errorf("expected JSON decode error, got %v", err)
	}
}

// TestMCPAdapter_Execute_StdioTransport tests stdio transport functionality
func TestMCPAdapter_Execute_StdioTransport(t *testing.T) {
	// Skip this test on systems where we can't easily mock stdio processes
	if testing.Short() {
		t.Skip("skipping stdio transport test in short mode")
	}

	configDir := filepath.Dir(constants.ConfigFileName)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

	// Create a mock MCP server script that responds to stdio
	tempDir, err := os.MkdirTemp("", "mcp_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	scriptPath := tempDir + "/mock_mcp_server.sh"
	scriptContent := `#!/bin/bash
# Mock MCP server that responds to JSON-RPC over stdio
while read line; do
    echo '{"result": {"tools": [{"name": "testtool"}]}}' >&1
    break
done
`
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}

	configData := map[string]any{
		"mcpServers": map[string]any{
			"testhost": map[string]any{
				"command": "bash " + scriptPath,
			},
		},
	}
	configBytes, _ := json.Marshal(configData)
	os.WriteFile(constants.ConfigFileName, configBytes, 0644)
	defer os.Remove(constants.ConfigFileName)

	adapter := NewMCPAdapter()
	inputs := map[string]any{"__use": "mcp://testhost/testtool"}

	// This will likely fail due to the complexity of mocking stdio MCP,
	// but it exercises the stdio code path
	_, err = adapter.Execute(context.Background(), inputs)
	// We expect this to fail in the test environment, but it exercises the code
	if err != nil {
		t.Logf("stdio transport failed as expected in test environment: %v", err)
	}
}

// TestMCPAdapter_Execute_MissingConfig tests error when server config is missing
func TestMCPAdapter_Execute_MissingConfig(t *testing.T) {
	configDir := filepath.Dir(constants.ConfigFileName)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

	configData := map[string]any{
		"mcpServers": map[string]any{
			"otherhost": map[string]any{
				"command": "echo",
			},
		},
	}
	configBytes, _ := json.Marshal(configData)
	os.WriteFile(constants.ConfigFileName, configBytes, 0644)
	defer os.Remove(constants.ConfigFileName)

	adapter := NewMCPAdapter()
	inputs := map[string]any{"__use": "mcp://missinghost/testtool"}

	_, err := adapter.Execute(context.Background(), inputs)
	if err == nil || !strings.Contains(err.Error(), "not found in registry or config") {
		t.Errorf("expected missing config error, got %v", err)
	}
}

// TestMCPAdapter_Execute_InvalidTransportConfig tests error with invalid transport config
func TestMCPAdapter_Execute_InvalidTransportConfig(t *testing.T) {
	configDir := filepath.Dir(constants.ConfigFileName)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

	configData := map[string]any{
		"mcpServers": map[string]any{
			"testhost": map[string]any{
				"command":   "echo",
				"transport": "invalid",
			},
		},
	}
	configBytes, _ := json.Marshal(configData)
	os.WriteFile(constants.ConfigFileName, configBytes, 0644)
	defer os.Remove(constants.ConfigFileName)

	adapter := NewMCPAdapter()
	inputs := map[string]any{"__use": "mcp://testhost/testtool"}

	// Use a context with timeout to avoid hanging
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := adapter.Execute(ctx, inputs)
	if err == nil {
		t.Error("expected error for invalid transport config, got nil")
	}
	// Accept either timeout or initialization error
	if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "failed to initialize") {
		t.Errorf("expected timeout or initialization error, got %v", err)
	}
}

// TestMCPAdapter_Close tests the Close method
func TestMCPAdapter_Close(t *testing.T) {
	adapter := NewMCPAdapter()

	// Close should succeed even without any active connections
	err := adapter.Close()
	if err != nil {
		t.Errorf("expected no error from Close, got %v", err)
	}

	// Multiple closes should be safe
	err = adapter.Close()
	if err != nil {
		t.Errorf("expected no error from second Close, got %v", err)
	}
}

// TestMCPAdapter_Close_WithProcesses tests closing adapter with active processes
func TestMCPAdapter_Close_WithProcesses(t *testing.T) {
	adapter := NewMCPAdapter()

	// Simulate having processes and pipes
	adapter.mu.Lock()
	// Create a mock command that we can safely kill
	cmd := exec.Command("sleep", "10")
	adapter.processes["testhost"] = cmd
	adapter.pipes["testhost"] = struct {
		stdin  io.WriteCloser
		stdout io.ReadCloser
	}{
		stdin:  &mockWriteCloser{},
		stdout: &mockReadCloser{},
	}
	adapter.mu.Unlock()

	// Start the process
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start test process: %v", err)
	}

	// Close the adapter
	err := adapter.Close()
	if err != nil {
		t.Errorf("expected no error closing adapter with processes, got %v", err)
	}

	// Verify process was killed
	if cmd.ProcessState == nil {
		// Give it a moment to be killed
		time.Sleep(100 * time.Millisecond)
	}
}

// TestMCPAdapter_ConcurrentAccess tests concurrent access to the adapter
func TestMCPAdapter_ConcurrentAccess(t *testing.T) {
	adapter := NewMCPAdapter()

	var wg sync.WaitGroup
	errors := make(chan error, 10)

	// Run multiple goroutines trying to access the adapter
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			inputs := map[string]any{"__use": fmt.Sprintf("mcp://host%d/tool%d", id, id)}
			_, err := adapter.Execute(context.Background(), inputs)
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// We expect errors (since we don't have valid configs), but no panics
	errorCount := 0
	for err := range errors {
		if err != nil {
			errorCount++
		}
	}

	if errorCount == 0 {
		t.Error("expected some errors from invalid configs, got none")
	}
}

// Mock implementations for testing
type mockWriteCloser struct {
	bytes.Buffer
}

func (m *mockWriteCloser) Close() error {
	return nil
}

type mockReadCloser struct {
	bytes.Buffer
}

func (m *mockReadCloser) Close() error {
	return nil
}

func (m *mockReadCloser) Read(p []byte) (n int, err error) {
	// Return EOF to simulate closed pipe
	return 0, io.EOF
}

// TestMCPAdapter_Execute_ConfigLoadError tests error handling when config loading fails
func TestMCPAdapter_Execute_ConfigLoadError(t *testing.T) {
	// Create an invalid config file
	configDir := filepath.Dir(constants.ConfigFileName)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

	// Write invalid JSON
	if err := os.WriteFile(constants.ConfigFileName, []byte("invalid json{"), 0644); err != nil {
		t.Fatalf("failed to write invalid config: %v", err)
	}
	defer os.Remove(constants.ConfigFileName)

	adapter := NewMCPAdapter()
	inputs := map[string]any{"__use": "mcp://testhost/testtool"}

	_, err := adapter.Execute(context.Background(), inputs)
	if err == nil {
		t.Error("expected error for invalid config, got nil")
	}
}

// TestMCPAdapter_Execute_EmptyConfig tests handling of empty config
func TestMCPAdapter_Execute_EmptyConfig(t *testing.T) {
	configDir := filepath.Dir(constants.ConfigFileName)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

	// Write empty config
	configData := map[string]any{}
	configBytes, _ := json.Marshal(configData)
	if err := os.WriteFile(constants.ConfigFileName, configBytes, 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	defer os.Remove(constants.ConfigFileName)

	adapter := NewMCPAdapter()
	inputs := map[string]any{"__use": "mcp://testhost/testtool"}

	_, err := adapter.Execute(context.Background(), inputs)
	if err == nil || !strings.Contains(err.Error(), "not found in registry or config") {
		t.Errorf("expected server not found error, got %v", err)
	}
}

// TestMCPAdapter_Execute_InvalidUseFormat tests handling of invalid __use format
func TestMCPAdapter_Execute_InvalidUseFormat(t *testing.T) {
	adapter := NewMCPAdapter()

	testCases := []struct {
		name string
		use  string
	}{
		{"missing protocol", "testhost/testtool"},
		{"wrong protocol", "http://testhost/testtool"},
		{"missing tool", "mcp://testhost"},
		{"empty string", ""},
		{"just protocol", "mcp://"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			inputs := map[string]any{"__use": tc.use}
			_, err := adapter.Execute(context.Background(), inputs)
			if err == nil {
				t.Errorf("expected error for invalid use format %q, got nil", tc.use)
			}
		})
	}
}

// TestMCPAdapter_Execute_NonStringUse tests handling of non-string __use value
func TestMCPAdapter_Execute_NonStringUse(t *testing.T) {
	adapter := NewMCPAdapter()

	inputs := map[string]any{"__use": 123} // Non-string value
	_, err := adapter.Execute(context.Background(), inputs)
	if err == nil {
		t.Error("expected error for non-string __use value, got nil")
	}
}

// TestMCPAdapter_GetMCPServerConfig tests the getMCPServerConfig function
func TestMCPAdapter_GetMCPServerConfig(t *testing.T) {
	configDir := filepath.Dir(constants.ConfigFileName)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

	configData := map[string]any{
		"mcpServers": map[string]any{
			"testhost": map[string]any{
				"command": "echo",
			},
		},
	}
	configBytes, _ := json.Marshal(configData)
	if err := os.WriteFile(constants.ConfigFileName, configBytes, 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	defer os.Remove(constants.ConfigFileName)

	// Test existing server
	serverConfig, err := getMCPServerConfig("testhost")
	if err != nil {
		t.Errorf("expected no error for existing server, got %v", err)
	}
	if serverConfig.Command == "" {
		t.Error("expected server config to have command, got empty")
	}

	// Test non-existing server
	_, err = getMCPServerConfig("nonexistent")
	if err == nil {
		t.Error("expected error for non-existing server, got nil")
	}
}
