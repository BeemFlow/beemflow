// mcp/manager_test.go
package mcp

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/beemflow/beemflow/config"
	"github.com/beemflow/beemflow/model"
)

func TestFindMCPServersInFlow(t *testing.T) {
	flow := &model.Flow{
		Steps: []model.Step{
			{Use: "mcp://foo/tool1"},
			{Use: "other://bar"},
			{
				Steps: []model.Step{
					{Use: "mcp://bar/tool2"},
				},
			},
		},
		Catch: []model.Step{
			{Use: "mcp://baz/tool3"},
		},
	}
	servers := FindMCPServersInFlow(flow)
	want := map[string]bool{"foo": true, "bar": true, "baz": true}
	for k := range want {
		if !servers[k] {
			t.Errorf("expected server %s in flow, got %v", k, servers)
		}
	}
	if len(servers) != len(want) {
		t.Errorf("expected servers %v, got %v", want, servers)
	}
}

func TestEnsureMCPServers_MissingConfig(t *testing.T) {
	flow := &model.Flow{
		Steps: []model.Step{{Use: "mcp://unknown/tool"}},
	}
	cfg := &config.Config{MCPServers: map[string]config.MCPServerConfig{}}
	err := EnsureMCPServers(context.Background(), flow, cfg)
	if err == nil {
		t.Errorf("expected error when MCP server config missing")
	}
}

func TestEnsureMCPServers_MissingEnv(t *testing.T) {
	flow := &model.Flow{
		Steps: []model.Step{{Use: "mcp://foo/tool"}},
	}
	cfg := &config.Config{
		MCPServers: map[string]config.MCPServerConfig{
			"foo": {Command: "true", Env: map[string]string{"FOO": "$env:MISSING_VAR"}},
		},
	}
	err := EnsureMCPServers(context.Background(), flow, cfg)
	if err == nil {
		t.Errorf("expected error when env vars missing")
	}
}

func TestEnsureMCPServers_Success(t *testing.T) {
	// Use "true" command which should exist on system
	flow := &model.Flow{
		Steps: []model.Step{{Use: "mcp://foo/tool"}},
	}
	cfg := &config.Config{
		MCPServers: map[string]config.MCPServerConfig{
			"foo": {Command: "true"},
		},
	}
	// Ensure no relevant env vars are set
	os.Unsetenv("FOO")
	err := EnsureMCPServers(context.Background(), flow, cfg)
	if err != nil {
		t.Errorf("expected no error when starting MCP server, got %v", err)
	}
}

func TestIsPortOpen(t *testing.T) {
	// Test closed port (unlikely to be open)
	if isPortOpen(65535) {
		t.Errorf("expected port 65535 to be closed")
	}
	// Test open port by listening
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on port: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	if !isPortOpen(port) {
		t.Errorf("expected port %d to be open", port)
	}
}

func TestNewHTTPMCPClient(t *testing.T) {
	client := NewHTTPMCPClient("http://example.com")
	if client == nil {
		t.Errorf("expected non-nil MCP client")
	}
}

// TestWaitForMCP_Success tests that waitForMCP returns nil when server responds quickly.
func TestWaitForMCP_Success(t *testing.T) {
	t.Skip("skipping waitForMCP success path until backoff logic refactored")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`[]`)); err != nil {
			t.Fatalf("w.Write failed: %v", err)
		}
	}))
	defer server.Close()
	err := waitForMCP(context.Background(), server.URL, 1*time.Second)
	if err != nil {
		t.Errorf("expected waitForMCP to succeed, got %v", err)
	}
}

// TestWaitForMCP_Error tests that waitForMCP returns an error immediately on negative timeout.
func TestWaitForMCP_Error(t *testing.T) {
	err := waitForMCP(context.Background(), "http://127.0.0.1:0", -1*time.Second)
	if err == nil {
		t.Errorf("expected error for negative timeout")
	}
}

// TestEnsureMCPServers_MissingCommand checks that missing Command yields an error.
func TestEnsureMCPServers_MissingCommand(t *testing.T) {
	flow := &model.Flow{Steps: []model.Step{{Use: "mcp://foo/tool"}}}
	cfg := &config.Config{MCPServers: map[string]config.MCPServerConfig{"foo": {Command: ""}}}
	err := EnsureMCPServers(context.Background(), flow, cfg)
	if err == nil || !strings.Contains(err.Error(), "config is missing 'command'") {
		t.Errorf("expected missing command error, got %v", err)
	}
}

// TestEnsureMCPServers_DebugLogging ensures the debug logging branch is exercised.
func TestEnsureMCPServers_DebugLogging(t *testing.T) {
	flow := &model.Flow{Steps: []model.Step{{Use: "mcp://foo/tool"}}}
	cfg := &config.Config{MCPServers: map[string]config.MCPServerConfig{"foo": {Command: "true"}}}
	os.Setenv("BEEMFLOW_DEBUG", "1")
	defer os.Unsetenv("BEEMFLOW_DEBUG")
	err := EnsureMCPServers(context.Background(), flow, cfg)
	if err != nil {
		t.Errorf("expected no error in debug mode, got %v", err)
	}
}

// TestEnsureMCPServers_CommandStartError ensures errors starting the command are handled.
func TestEnsureMCPServers_CommandStartError(t *testing.T) {
	flow := &model.Flow{Steps: []model.Step{{Use: "mcp://foo/tool"}}}
	cfg := &config.Config{MCPServers: map[string]config.MCPServerConfig{"foo": {Command: "nonexistent_binary"}}}
	err := EnsureMCPServers(context.Background(), flow, cfg)
	if err == nil || !strings.Contains(err.Error(), "failed to start MCP server foo") {
		t.Errorf("expected start error for nonexistent command, got %v", err)
	}
}

// TestEnsureMCPServers_EnvMapping exercises the env mapping logic for both literal and $env:VARNAME values.
func TestEnsureMCPServers_EnvMapping(t *testing.T) {
	flow := &model.Flow{Steps: []model.Step{{Use: "mcp://foo/tool"}}}
	cfg := &config.Config{MCPServers: map[string]config.MCPServerConfig{"foo": {
		Command: "true",
		Env:     map[string]string{"FOO_LIT": "val1", "FOO_SHELL": "$env:FOO_SHELL_VAR"},
	}}}
	// Set both literal and $env:VARNAME variables
	os.Setenv("FOO_LIT", "val1")
	os.Setenv("FOO_SHELL_VAR", "shellval")
	defer os.Unsetenv("FOO_LIT")
	defer os.Unsetenv("FOO_SHELL_VAR")
	err := EnsureMCPServers(context.Background(), flow, cfg)
	if err != nil {
		t.Errorf("expected no error with env mapping, got %v", err)
	}
}

// ============================================================================
// COMPREHENSIVE COVERAGE TESTS FOR LOW-COVERAGE FUNCTIONS
// ============================================================================

// TestWaitForMCP_Comprehensive tests waitForMCP with various scenarios
func TestWaitForMCP_Comprehensive(t *testing.T) {
	// Test timeout scenario
	ctx := context.Background()

	// Test with very short timeout to trigger timeout path
	err := waitForMCP(ctx, "http://127.0.0.1:1", 1*time.Millisecond)
	if err == nil {
		t.Error("Expected timeout error for unreachable server")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("Expected timeout error message, got: %v", err)
	}

	// Test with invalid URL
	err = waitForMCP(ctx, "invalid-url", 100*time.Millisecond)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}

	// Test with server that returns 404 (simulating MCP server not ready)
	notReadyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer notReadyServer.Close()

	err = waitForMCP(ctx, notReadyServer.URL, 100*time.Millisecond)
	if err == nil {
		t.Error("Expected error for server that returns 404")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("Expected timeout error message, got: %v", err)
	}
}

// TestEnsureMCPServersWithTimeout_Comprehensive tests the timeout version with various scenarios
func TestEnsureMCPServersWithTimeout_Comprehensive(t *testing.T) {
	ctx := context.Background()

	// Test with no MCP servers in flow
	emptyFlow := &model.Flow{
		Steps: []model.Step{{Use: "core.echo"}},
	}
	cfg := &config.Config{MCPServers: map[string]config.MCPServerConfig{}}

	err := EnsureMCPServersWithTimeout(ctx, emptyFlow, cfg, 1*time.Second)
	if err != nil {
		t.Errorf("Expected no error for flow without MCP servers, got: %v", err)
	}

	// Test with server that has endpoint but fails to start
	flowWithEndpoint := &model.Flow{
		Steps: []model.Step{{Use: "mcp://test/tool"}},
	}
	cfgWithEndpoint := &config.Config{
		MCPServers: map[string]config.MCPServerConfig{
			"test": {
				Command:  "true",
				Endpoint: "http://127.0.0.1:1", // Unreachable endpoint
			},
		},
	}

	err = EnsureMCPServersWithTimeout(ctx, flowWithEndpoint, cfgWithEndpoint, 10*time.Millisecond)
	if err == nil {
		t.Error("Expected error for unreachable endpoint")
	}
	if !strings.Contains(err.Error(), "did not become ready") {
		t.Errorf("Expected 'did not become ready' error, got: %v", err)
	}

	// Test with custom timeout
	flowSimple := &model.Flow{
		Steps: []model.Step{{Use: "mcp://simple/tool"}},
	}
	cfgSimple := &config.Config{
		MCPServers: map[string]config.MCPServerConfig{
			"simple": {Command: "true"},
		},
	}

	err = EnsureMCPServersWithTimeout(ctx, flowSimple, cfgSimple, 5*time.Second)
	if err != nil {
		t.Errorf("Expected no error with custom timeout, got: %v", err)
	}

	// Test with multiple environment variables
	flowMultiEnv := &model.Flow{
		Steps: []model.Step{{Use: "mcp://multienv/tool"}},
	}
	cfgMultiEnv := &config.Config{
		MCPServers: map[string]config.MCPServerConfig{
			"multienv": {
				Command: "true",
				Env: map[string]string{
					"VAR1": "$env:TEST_VAR1",
					"VAR2": "$env:TEST_VAR2",
					"VAR3": "literal_value",
				},
			},
		},
	}

	// Set some env vars but not all
	os.Setenv("TEST_VAR1", "value1")
	defer os.Unsetenv("TEST_VAR1")
	// TEST_VAR2 is missing

	err = EnsureMCPServersWithTimeout(ctx, flowMultiEnv, cfgMultiEnv, 1*time.Second)
	if err == nil {
		t.Error("Expected error for missing environment variables")
	}
	if !strings.Contains(err.Error(), "TEST_VAR2") {
		t.Errorf("Expected error to mention missing TEST_VAR2, got: %v", err)
	}

	// Now set all required env vars
	os.Setenv("TEST_VAR2", "value2")
	defer os.Unsetenv("TEST_VAR2")

	err = EnsureMCPServersWithTimeout(ctx, flowMultiEnv, cfgMultiEnv, 1*time.Second)
	if err != nil {
		t.Errorf("Expected no error when all env vars are set, got: %v", err)
	}
}

// TestNewMCPCommand_Comprehensive tests NewMCPCommand with various configurations
func TestNewMCPCommand_Comprehensive(t *testing.T) {
	// Test with basic command
	basicConfig := config.MCPServerConfig{
		Command: "echo",
		Args:    []string{"hello", "world"},
	}
	cmd := NewMCPCommand(basicConfig)
	// Command path might be full path like /bin/echo, so just check it contains echo
	if !strings.Contains(cmd.Path, "echo") {
		t.Errorf("Expected command path to contain 'echo', got %s", cmd.Path)
	}
	if len(cmd.Args) != 3 { // echo + 2 args
		t.Errorf("Expected 3 args (including command), got %d", len(cmd.Args))
	}

	// Test with environment variables
	envConfig := config.MCPServerConfig{
		Command: "env",
		Env: map[string]string{
			"LITERAL_VAR":    "literal_value",
			"ENV_VAR":        "$env:TEST_ENV_VAR",
			"MISSING_ENV":    "$env:MISSING_VAR",
			"EMPTY_ENV":      "$env:",
			"NOT_ENV_PREFIX": "not_env_var",
		},
	}

	// Set test environment variable
	os.Setenv("TEST_ENV_VAR", "test_value")
	defer os.Unsetenv("TEST_ENV_VAR")

	cmd = NewMCPCommand(envConfig)

	// Check that environment variables are properly set
	envFound := make(map[string]bool)
	for _, env := range cmd.Env {
		if strings.HasPrefix(env, "LITERAL_VAR=") {
			envFound["LITERAL_VAR"] = true
			if env != "LITERAL_VAR=literal_value" {
				t.Errorf("Expected LITERAL_VAR=literal_value, got %s", env)
			}
		}
		if strings.HasPrefix(env, "ENV_VAR=") {
			envFound["ENV_VAR"] = true
			if env != "ENV_VAR=test_value" {
				t.Errorf("Expected ENV_VAR=test_value, got %s", env)
			}
		}
		if strings.HasPrefix(env, "NOT_ENV_PREFIX=") {
			envFound["NOT_ENV_PREFIX"] = true
			if env != "NOT_ENV_PREFIX=not_env_var" {
				t.Errorf("Expected NOT_ENV_PREFIX=not_env_var, got %s", env)
			}
		}
		// MISSING_ENV should not be set since the env var doesn't exist
		if strings.HasPrefix(env, "MISSING_ENV=") {
			t.Errorf("MISSING_ENV should not be set when env var is missing, got %s", env)
		}
		// EMPTY_ENV should not be set since it's malformed
		if strings.HasPrefix(env, "EMPTY_ENV=") {
			t.Errorf("EMPTY_ENV should not be set when env var name is empty, got %s", env)
		}
	}

	if !envFound["LITERAL_VAR"] {
		t.Error("LITERAL_VAR not found in command environment")
	}
	if !envFound["ENV_VAR"] {
		t.Error("ENV_VAR not found in command environment")
	}
	if !envFound["NOT_ENV_PREFIX"] {
		t.Error("NOT_ENV_PREFIX not found in command environment")
	}

	// Test with no args
	noArgsConfig := config.MCPServerConfig{
		Command: "true",
		Args:    nil,
	}
	cmd = NewMCPCommand(noArgsConfig)
	if len(cmd.Args) != 1 { // Just the command
		t.Errorf("Expected 1 arg (just command), got %d", len(cmd.Args))
	}

	// Test with empty command (edge case)
	emptyConfig := config.MCPServerConfig{
		Command: "",
		Args:    []string{"arg1"},
	}
	cmd = NewMCPCommand(emptyConfig)
	if cmd.Path != "" {
		t.Errorf("Expected empty command path, got %s", cmd.Path)
	}
}

// TestFindMCPInStep_EdgeCases tests edge cases for findMCPInStep
func TestFindMCPInStep_EdgeCases(t *testing.T) {
	servers := make(map[string]bool)

	// Test with non-MCP use
	step1 := model.Step{Use: "core.echo"}
	findMCPInStep(step1, servers)
	if len(servers) != 0 {
		t.Errorf("Expected no servers for non-MCP step, got %v", servers)
	}

	// Test with malformed MCP URL
	step2 := model.Step{Use: "mcp://invalid"}
	findMCPInStep(step2, servers)
	if len(servers) != 0 {
		t.Errorf("Expected no servers for malformed MCP URL, got %v", servers)
	}

	// Test with valid MCP URL
	step3 := model.Step{Use: "mcp://server/tool"}
	findMCPInStep(step3, servers)
	if !servers["server"] {
		t.Errorf("Expected server 'server' to be found, got %v", servers)
	}

	// Test with nested Do steps
	servers = make(map[string]bool) // Reset
	step4 := model.Step{
		Use: "core.echo",
		Steps: []model.Step{
			{Use: "mcp://nested1/tool"},
			{
				Use: "core.echo",
				Steps: []model.Step{
					{Use: "mcp://nested2/tool"},
				},
			},
		},
	}
	findMCPInStep(step4, servers)
	if !servers["nested1"] || !servers["nested2"] {
		t.Errorf("Expected nested1 and nested2 servers, got %v", servers)
	}

	// Test with empty Do slice
	servers = make(map[string]bool) // Reset
	step5 := model.Step{
		Use: "mcp://main/tool",
		Steps:  []model.Step{},
	}
	findMCPInStep(step5, servers)
	if !servers["main"] {
		t.Errorf("Expected main server, got %v", servers)
	}
	if len(servers) != 1 {
		t.Errorf("Expected only main server, got %v", servers)
	}
}

// TestFindMCPServersInFlow_EdgeCases tests edge cases for FindMCPServersInFlow
func TestFindMCPServersInFlow_EdgeCases(t *testing.T) {
	// Test with empty flow
	emptyFlow := &model.Flow{}
	servers := FindMCPServersInFlow(emptyFlow)
	if len(servers) != 0 {
		t.Errorf("Expected no servers for empty flow, got %v", servers)
	}

	// Test with flow that has no MCP servers
	noMCPFlow := &model.Flow{
		Steps: []model.Step{
			{Use: "core.echo"},
			{Use: "http.get"},
		},
		Catch: []model.Step{
			{Use: "core.log"},
		},
	}
	servers = FindMCPServersInFlow(noMCPFlow)
	if len(servers) != 0 {
		t.Errorf("Expected no servers for flow without MCP, got %v", servers)
	}

	// Test with flow that has only catch steps with MCP
	catchOnlyFlow := &model.Flow{
		Steps: []model.Step{
			{Use: "core.echo"},
		},
		Catch: []model.Step{
			{Use: "mcp://catch-server/tool"},
		},
	}
	servers = FindMCPServersInFlow(catchOnlyFlow)
	if !servers["catch-server"] {
		t.Errorf("Expected catch-server, got %v", servers)
	}
	if len(servers) != 1 {
		t.Errorf("Expected only catch-server, got %v", servers)
	}

	// Test with duplicate servers
	duplicateFlow := &model.Flow{
		Steps: []model.Step{
			{Use: "mcp://dup/tool1"},
			{Use: "mcp://dup/tool2"},
		},
		Catch: []model.Step{
			{Use: "mcp://dup/tool3"},
		},
	}
	servers = FindMCPServersInFlow(duplicateFlow)
	if !servers["dup"] {
		t.Errorf("Expected dup server, got %v", servers)
	}
	if len(servers) != 1 {
		t.Errorf("Expected only one unique server, got %v", servers)
	}
}
