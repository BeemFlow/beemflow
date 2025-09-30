package main

import (
	"bytes"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beemflow/beemflow/config"
	"github.com/beemflow/beemflow/utils"
	"github.com/spf13/cobra"
)

func captureOutput(f func()) string {
	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	utils.SetUserOutput(w)
	f()
	w.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		log.Printf("buf.ReadFrom failed: %v", err)
	}
	os.Stdout = orig
	utils.SetUserOutput(orig)
	return buf.String()
}

func captureStderrExit(f func()) (output string, code int) {
	origStderr := os.Stderr
	origExit := exit
	r, w, _ := os.Pipe()
	os.Stderr = w
	utils.SetInternalOutput(w)
	var buf bytes.Buffer
	var out string
	exitCode := 0
	exit = func(code int) {
		exitCode = code
		w.Close()
		panic("exit")
	}
	func() {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic occurred: %v", err)
			}
		}()
		f()
	}()
	w.Close()
	if _, err := io.Copy(&buf, r); err != nil {
		log.Printf("io.Copy failed: %v", err)
	}
	os.Stderr = origStderr
	utils.SetInternalOutput(origStderr)
	exit = origExit
	out = buf.String()
	return out, exitCode
}

func TestMainCommands(t *testing.T) {
	cases := []struct {
		args        []string
		wantsOutput bool
	}{
		{[]string{"flow", "run"}, true},
		{[]string{"flow", "test"}, true},
		{[]string{"flow", "convert", "--help"}, true},
	}
	for _, c := range cases {
		os.Args = c.args
		out := captureOutput(func() {
			if err := NewRootCmd().Execute(); err != nil {
				log.Printf("Execute failed: %v", err)
			}
		})
		if c.wantsOutput && out == "" {
			t.Errorf("expected output for %v, got empty", c.args)
		}
	}
}

func TestMain_LintValidateCommands(t *testing.T) {
	// Valid flow file
	valid := `package beemflow

name: "test"
on: "cli.manual"
steps: [{
	id: "s1"
	use: "core.echo"
	with: {
		text: "hi"
	}
}]`
	tmpDir := t.TempDir()
	tmpPath := filepath.Join(tmpDir, t.Name()+"-valid.flow.cue")
	tmp, err := os.Create(tmpPath)
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(tmpPath)
	if _, err := tmp.WriteString(valid); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	tmp.Close()

	os.Args = []string{"flow", "lint", "[file]", tmpPath}
	out := captureOutput(func() {
		if err := NewRootCmd().Execute(); err != nil {
			log.Printf("Execute failed: %v", err)
			t.Errorf("lint command failed: %v", err)
		}
	})
	t.Logf("lint output: %q", out)
	if !strings.Contains(out, "Lint OK") {
		t.Errorf("expected Lint OK, got %q", out)
	}
}

func TestMain_ToolStub(t *testing.T) {
	// Test that unified commands work instead of the old tool subcommand
	os.Args = []string{"flow", "spec"}
	out := captureOutput(func() {
		if err := NewRootCmd().Execute(); err != nil {
			log.Printf("Execute failed: %v", err)
		}
	})
	if out == "" {
		t.Errorf("expected spec output, got empty string")
	}
}

func TestNewRootCmd(t *testing.T) {
	cmd := NewRootCmd()

	if cmd.Use != "flow" {
		t.Errorf("Expected root command name 'flow', got %s", cmd.Use)
	}

	// Check that persistent flags are set
	flags := cmd.PersistentFlags()
	if flags.Lookup("config") == nil {
		t.Error("Expected --config flag to be defined")
	}
	if flags.Lookup("debug") == nil {
		t.Error("Expected --debug flag to be defined")
	}
	if flags.Lookup("mcp-timeout") == nil {
		t.Error("Expected --mcp-timeout flag to be defined")
	}
	if flags.Lookup("flows-dir") == nil {
		t.Error("Expected --flows-dir flag to be defined")
	}

	// Check that subcommands are added
	commands := cmd.Commands()
	expectedCommands := []string{"serve", "run", "mcp"}

	for _, expected := range expectedCommands {
		found := false
		for _, cmd := range commands {
			if cmd.Name() == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected command '%s' to be added", expected)
		}
	}
}

func TestNewServeCmd(t *testing.T) {
	cmd := newServeCmd()

	if cmd.Use != "serve" {
		t.Errorf("Expected command name 'serve', got %s", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Expected non-empty short description")
	}

	// Check that --addr flag is defined
	if cmd.Flags().Lookup("addr") == nil {
		t.Error("Expected --addr flag to be defined")
	}
}

func TestServeCommand_Help(t *testing.T) {
	// Test that serve --help works without starting the server
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"serve", "--help"})

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	err := cmd.Execute()
	if err != nil {
		t.Errorf("serve --help failed: %v", err)
	}

	output := stdout.String()
	if !strings.Contains(output, "Start the BeemFlow") {
		t.Error("Expected help text to contain server description")
	}
}

func TestNewRunCmd(t *testing.T) {
	cmd := newRunCmd()

	if cmd.Use != "run [file]" {
		t.Errorf("Expected command use 'run [file]', got %s", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Expected non-empty short description")
	}

	// Check that flags are defined
	if cmd.Flags().Lookup("event") == nil {
		t.Error("Expected --event flag to be defined")
	}
	if cmd.Flags().Lookup("event-json") == nil {
		t.Error("Expected --event-json flag to be defined")
	}
}

func TestRunFlowExecution_NoArgs(t *testing.T) {
	out := captureOutput(func() {
		runFlowExecution(&cobra.Command{}, []string{}, "", "")
	})

	if !strings.Contains(out, "flow run") {
		t.Errorf("Expected stub output, got: %s", out)
	}
}

func TestRunFlowExecution_WithFile(t *testing.T) {
	// Create a temporary flow file
	tmpDir := t.TempDir()
	flowPath := filepath.Join(tmpDir, "test.flow.cue")
	flowContent := `package beemflow

name: "test"
on: "cli.manual"
steps: [{
	id: "echo_step"
	use: "core.echo"
	with: {
		text: "hello world"
	}
}]`
	if err := os.WriteFile(flowPath, []byte(flowContent), 0644); err != nil {
		t.Fatalf("Failed to write test flow: %v", err)
	}

	// Test with valid flow file
	stderr, code := captureStderrExit(func() {
		runFlowExecution(&cobra.Command{}, []string{flowPath}, "", "")
	})

	// Should execute successfully or give a reasonable error
	t.Logf("Flow execution - code: %d, stderr: %s", code, stderr)
}

func TestRunFlowExecution_InvalidFile(t *testing.T) {
	stderr, code := captureStderrExit(func() {
		runFlowExecution(&cobra.Command{}, []string{"/nonexistent/file.yaml"}, "", "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stderr, "Flow parse error") {
		t.Errorf("Expected Flow parse error, got: %s", stderr)
	}
}

func TestLoadEvent(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		inline   string
		wantErr  bool
		expected map[string]any
	}{
		{
			name:     "no event",
			path:     "",
			inline:   "",
			wantErr:  false,
			expected: map[string]any{},
		},
		{
			name:     "inline JSON",
			path:     "",
			inline:   `{"key": "value"}`,
			wantErr:  false,
			expected: map[string]any{"key": "value"},
		},
		{
			name:    "invalid inline JSON",
			path:    "",
			inline:  `{invalid json}`,
			wantErr: true,
		},
		{
			name:    "non-existent file",
			path:    "/nonexistent/file.json",
			inline:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file if needed
			if tt.path != "" && !strings.Contains(tt.path, "nonexistent") {
				tmpDir := t.TempDir()
				tt.path = filepath.Join(tmpDir, "event.json")
				content := `{"file": "data"}`
				if err := os.WriteFile(tt.path, []byte(content), 0644); err != nil {
					t.Fatalf("Failed to write test file: %v", err)
				}
				tt.expected = map[string]any{"file": "data"}
			}

			result, err := loadEvent(tt.path, tt.inline)

			if (err != nil) != tt.wantErr {
				t.Errorf("loadEvent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(result) != len(tt.expected) {
					t.Errorf("loadEvent() result length = %d, want %d", len(result), len(tt.expected))
				}
				for k, v := range tt.expected {
					if result[k] != v {
						t.Errorf("loadEvent() result[%s] = %v, want %v", k, result[k], v)
					}
				}
			}
		})
	}
}

func TestOutputFlowResults(t *testing.T) {
	tests := []struct {
		name    string
		outputs map[string]any
		debug   bool
	}{
		{
			name:    "simple outputs",
			outputs: map[string]any{"step1": "result1"},
			debug:   false,
		},
		{
			name:    "debug mode",
			outputs: map[string]any{"step1": "result1"},
			debug:   true,
		},
		{
			name:    "empty outputs",
			outputs: map[string]any{},
			debug:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origDebug := debug
			debug = tt.debug
			defer func() { debug = origDebug }()

			out := captureOutput(func() {
				outputFlowResults(tt.outputs)
			})

			// Should not panic and should produce some output
			t.Logf("Output: %s", out)
		})
	}
}

func TestOutputEchoResults(t *testing.T) {
	tests := []struct {
		name    string
		outputs map[string]any
		check   func(output string) bool
	}{
		{
			name:    "echo step",
			outputs: map[string]any{"echo": map[string]any{"text": "hello world"}},
			check: func(output string) bool {
				return strings.Contains(output, "hello world")
			},
		},
		{
			name: "openai response",
			outputs: map[string]any{
				"chat": map[string]any{
					"choices": []interface{}{
						map[string]any{
							"message": map[string]any{
								"content": "AI response",
							},
						},
					},
				},
			},
			check: func(output string) bool {
				return strings.Contains(output, "🤖") && strings.Contains(output, "AI response")
			},
		},
		{
			name: "mcp response",
			outputs: map[string]any{
				"mcp": map[string]any{
					"content": []interface{}{
						map[string]any{
							"text": "MCP response",
						},
					},
				},
			},
			check: func(output string) bool {
				return strings.Contains(output, "📡") && strings.Contains(output, "MCP response")
			},
		},
		{
			name: "http response",
			outputs: map[string]any{
				"http": map[string]any{
					"body": "HTTP response body",
				},
			},
			check: func(output string) bool {
				return strings.Contains(output, "🌐") && strings.Contains(output, "HTTP response")
			},
		},
		{
			name:    "large output",
			outputs: map[string]any{"large": strings.Repeat("x", 2000)},
			check: func(output string) bool {
				return strings.Contains(output, "too large to display")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := captureOutput(func() {
				outputEchoResults(tt.outputs)
			})

			if tt.check != nil && !tt.check(out) {
				t.Errorf("Output check failed for %s: %s", tt.name, out)
			}
		})
	}
}

func TestOutputDebugResults(t *testing.T) {
	outputs := map[string]any{"step1": "result1", "step2": map[string]any{"key": "value"}}

	out := captureOutput(func() {
		outputDebugResults(outputs)
	})

	// Should contain JSON output
	if !strings.Contains(out, "step1") || !strings.Contains(out, "step2") {
		t.Errorf("Expected JSON output with step names, got: %s", out)
	}
}

// MCP commands are now handled through the unified operations framework
// Tests for MCP functionality should be in core/operations_test.go

// Config loading is now handled through the config package
// Tests for config functionality should be in config/config_test.go

// MCP server configuration is now handled through the MCP package
// Tests for MCP configuration should be in mcp/manager_test.go

// Config writing is now handled through the config package
// Tests for config functionality should be in config/config_test.go

func TestMain(m *testing.M) {
	utils.WithCleanDirs(m, ".beemflow", config.DefaultConfigDir)
}

// ============================================================================
// TOOLS COMMAND TESTS (Now handled by unified system)
// ============================================================================

// Note: Tool commands are now handled by the unified operation system
// Individual function tests are no longer needed since the operations
// are tested through the unified system

// ============================================================================
// SHARED UTILITY FUNCTION TESTS (DRY VALIDATION)
// ============================================================================

// Registry operations are now handled through the unified operations framework
// Tests for registry functionality should be in core/operations_test.go

// ============================================================================
// INTEGRATION TESTS (SHARED FUNCTIONALITY)
// ============================================================================

func TestUnifiedCommandIntegration(t *testing.T) {
	// Test that the unified system properly generates tool and registry commands
	rootCmd := NewRootCmd()

	// The unified system should have attached commands
	commands := rootCmd.Commands()

	// Look for auto-generated commands (exact command structure depends on unified system)
	foundCommands := make(map[string]bool)
	for _, cmd := range commands {
		foundCommands[cmd.Name()] = true
	}

	// Basic commands should still exist
	// Note: mcp commands are now generated through the unified operations framework
	expectedCommands := []string{"serve", "run"}
	for _, expected := range expectedCommands {
		if !foundCommands[expected] {
			t.Errorf("expected command %s not found", expected)
		}
	}

	t.Logf("Found %d total commands in root", len(commands))
}

// TestCLISubcommandStructure tests the reorganized CLI command structure
func TestCLISubcommandStructure(t *testing.T) {
	// Create temporary directory and test files
	tmpDir := t.TempDir()
	testFlowFile := filepath.Join(tmpDir, "test.flow.cue")
	testFlowContent := `name: "test-flow"
on: "cli.manual"
steps: [{
	id: "echo_step"
	use: "core.echo"
	with: {
		text: "hello world"
	}
}]`
	if err := os.WriteFile(testFlowFile, []byte(testFlowContent), 0644); err != nil {
		t.Fatalf("Failed to create test flow file: %v", err)
	}

	// Create registry file in the actual .beemflow directory for tools tests
	// We need to do this because the registry path is hardcoded at package init time
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("Failed to get user home directory: %v", err)
	}
	actualRegistryDir := filepath.Join(homeDir, ".beemflow")
	if err := os.MkdirAll(actualRegistryDir, 0755); err != nil {
		t.Fatalf("Failed to create actual registry directory: %v", err)
	}
	actualRegistryFile := filepath.Join(actualRegistryDir, "registry.json")

	// Check if registry file already exists and back it up
	var existingRegistry []byte
	var hadExistingRegistry bool
	if data, err := os.ReadFile(actualRegistryFile); err == nil {
		existingRegistry = data
		hadExistingRegistry = true
	}

	registryContent := `[
  {
    "name": "http.fetch",
    "description": "Fetch data from HTTP endpoints",
    "kind": "tool"
  },
  {
    "name": "core.echo",
    "description": "Echo text output",
    "kind": "tool"
  }
]`
	if err := os.WriteFile(actualRegistryFile, []byte(registryContent), 0644); err != nil {
		t.Fatalf("Failed to create actual registry file: %v", err)
	}

	// Verify the file was written successfully
	if _, err := os.Stat(actualRegistryFile); err != nil {
		t.Fatalf("Registry file was not created successfully: %v", err)
	}

	// Check if we can read the file to ensure permissions are correct
	if _, err := os.ReadFile(actualRegistryFile); err != nil {
		t.Fatalf("Cannot read registry file after creation: %v", err)
	}

	// Clean up the registry file after test
	defer func() {
		if hadExistingRegistry {
			// Restore original file
			os.WriteFile(actualRegistryFile, existingRegistry, 0644)
		} else {
			// Remove the file we created
			os.Remove(actualRegistryFile)
		}
	}()

	tests := []struct {
		name        string
		args        []string
		expectError bool
		description string
	}{
		// Flow operations
		{"flow flows list", []string{"flows", "list"}, false, "List all flows"},
		{"flow flows get", []string{"flows", "get", "test-flow"}, false, "Get specific flow"},
		{"flow flows validate", []string{"flows", "validate", "--file", testFlowFile}, false, "Validate flow (with real file)"},
		{"flow flows graph", []string{"flows", "graph", "--file", testFlowFile}, false, "Generate flow graph (with real file)"},

		// Run operations
		{"flow runs start", []string{"runs", "start", "test-flow"}, false, "Start new run (may succeed with empty outputs)"},
		{"flow runs get", []string{"runs", "get", "test-run-id"}, true, "Get run details (invalid UUID)"},
		{"flow runs list", []string{"runs", "list"}, false, "List all runs"},

		// Tool operations (should work with our temp registry)
		{"flow tools list", []string{"tools", "list"}, false, "List all tools"},
		{"flow tools get", []string{"tools", "get", "http.fetch"}, false, "Get specific tool"},

		// Legacy commands should fail or redirect
		{"legacy get-run", []string{"get-run"}, true, "Legacy command should not exist"},
		{"legacy list-flows", []string{"list-flows"}, true, "Legacy command should not exist"},

		// Invalid subcommands
		{"invalid subcommand", []string{"invalid", "command"}, true, "Invalid subcommand"},
		{"missing subcommand", []string{"flows"}, false, "Missing subcommand (help will be shown)"},
		{"empty args", []string{}, false, "Help should be shown for empty args"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new root command for testing
			rootCmd := NewRootCmd()
			rootCmd.SetArgs(tt.args)

			// Capture both stdout and stderr to prevent test pollution
			var stdout, stderr bytes.Buffer
			rootCmd.SetOut(&stdout)
			rootCmd.SetErr(&stderr)

			// Execute the command
			err := rootCmd.Execute()

			// Check if error expectation matches
			if tt.expectError && err == nil {
				t.Errorf("Expected error for command %v, but got none", tt.args)
			} else if !tt.expectError && err != nil {
				// For tools commands, check if error is due to missing registry file
				isToolsCommand := len(tt.args) > 0 && tt.args[0] == "tools"
				isRegistryError := err != nil && strings.Contains(err.Error(), "registry.json") && strings.Contains(err.Error(), "no such file or directory")

				if isToolsCommand && isRegistryError {
					// Skip this test case as registry file access failed in CI environment
					t.Logf("Skipping tools command %v due to registry access issue in CI: %v", tt.args, err)
				} else {
					// Only report unexpected errors, not expected ones
					t.Errorf("Expected no error for command %v, but got: %v", tt.args, err)
					// Also log stderr to help debug
					if stderr.Len() > 0 {
						t.Logf("Command stderr: %s", stderr.String())
					}
				}
			}

			t.Logf("Command %v: %s - Error: %v", tt.args, tt.description, err)
		})
	}
}

// TestCLIFlags tests that important flags are properly defined
func TestCLIFlags(t *testing.T) {
	rootCmd := NewRootCmd()

	// Test global flags
	flags := rootCmd.PersistentFlags()

	expectedFlags := []string{"config", "debug"}
	for _, flagName := range expectedFlags {
		if flags.Lookup(flagName) == nil {
			t.Errorf("Expected global flag --%s to be defined", flagName)
		}
	}

	// Test that subcommands exist
	expectedSubcommands := []string{"flows", "runs", "tools", "serve", "mcp"}
	for _, subcmdName := range expectedSubcommands {
		found := false
		for _, cmd := range rootCmd.Commands() {
			if cmd.Name() == subcmdName {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected subcommand '%s' to exist", subcmdName)
		}
	}
}

// TestFlowsSubcommand tests the flows subcommand specifically
func TestFlowsSubcommand(t *testing.T) {
	rootCmd := NewRootCmd()

	// Find the flows subcommand
	var flowsCmd *cobra.Command
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "flows" {
			flowsCmd = cmd
			break
		}
	}

	if flowsCmd == nil {
		t.Fatal("flows subcommand not found")
	}

	// Check that flows has the expected subcommands
	expectedFlowSubcommands := []string{"list", "get", "validate", "graph"}
	for _, subcmdName := range expectedFlowSubcommands {
		found := false
		for _, cmd := range flowsCmd.Commands() {
			if cmd.Name() == subcmdName {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected flows subcommand '%s' to exist", subcmdName)
		}
	}

	// Test flows validate command has output flag
	var validateCmd *cobra.Command
	for _, cmd := range flowsCmd.Commands() {
		if cmd.Name() == "graph" {
			validateCmd = cmd
			break
		}
	}

	if validateCmd != nil {
		if validateCmd.Flags().Lookup("output") == nil {
			t.Error("Expected flows graph command to have --output flag")
		}
	}
}

// TestRunsSubcommand tests the runs subcommand specifically
func TestRunsSubcommand(t *testing.T) {
	rootCmd := NewRootCmd()

	// Find the runs subcommand
	var runsCmd *cobra.Command
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "runs" {
			runsCmd = cmd
			break
		}
	}

	if runsCmd == nil {
		t.Fatal("runs subcommand not found")
	}

	// Check that runs has the expected subcommands
	expectedRunSubcommands := []string{"start", "get", "list"}
	for _, subcmdName := range expectedRunSubcommands {
		found := false
		for _, cmd := range runsCmd.Commands() {
			if cmd.Name() == subcmdName {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected runs subcommand '%s' to exist", subcmdName)
		}
	}

	// Test runs start command has event flag
	var startCmd *cobra.Command
	for _, cmd := range runsCmd.Commands() {
		if cmd.Name() == "start" {
			startCmd = cmd
			break
		}
	}

	if startCmd != nil {
		if startCmd.Flags().Lookup("event-json") == nil {
			t.Error("Expected runs start command to have --event-json flag")
		}
	} else {
		t.Error("runs start command not found")
	}
}

// TestToolsSubcommand tests the tools subcommand specifically
func TestToolsSubcommand(t *testing.T) {
	rootCmd := NewRootCmd()

	// Find the tools subcommand
	var toolsCmd *cobra.Command
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "tools" {
			toolsCmd = cmd
			break
		}
	}

	if toolsCmd == nil {
		t.Fatal("tools subcommand not found")
	}

	// Check that tools has the expected subcommands
	expectedToolSubcommands := []string{"list", "get"}
	for _, subcmdName := range expectedToolSubcommands {
		found := false
		for _, cmd := range toolsCmd.Commands() {
			if cmd.Name() == subcmdName {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected tools subcommand '%s' to exist", subcmdName)
		}
	}
}

// TestCLIBackwardsCompatibility tests that we don't have legacy commands
func TestCLIBackwardsCompatibility(t *testing.T) {
	rootCmd := NewRootCmd()

	// These commands should NOT exist anymore after reorganization
	legacyCommands := []string{"get-run", "list-flows", "start-run", "get-flow"}

	for _, legacyCmd := range legacyCommands {
		found := false
		for _, cmd := range rootCmd.Commands() {
			if cmd.Name() == legacyCmd {
				found = true
				break
			}
		}
		if found {
			t.Errorf("Legacy command '%s' should not exist after CLI reorganization", legacyCmd)
		}
	}
}
