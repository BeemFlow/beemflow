package api

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestLooksLikeFilePath tests the looksLikeFilePath helper function comprehensively
func TestLooksLikeFilePath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
		setup    func() string // Optional setup function that returns a cleanup path
	}{
		// File extension based detection
		{"YAML extension", "myflow.yaml", true, nil},
		{"YML extension", "myflow.yml", true, nil},
		{"JSON extension", "config.json", true, nil},
		{"No extension", "flowname", false, nil},
		{"Executable extension", "script.exe", false, nil},
		{"Text extension", "readme.txt", false, nil},

		// Path separator detection
		{"Unix absolute path", "/home/user/flow.yaml", true, nil},
		{"Unix relative path", "flows/myflow.yaml", true, nil},
		{"Windows absolute path", "C:\\flows\\myflow.yaml", true, nil},
		{"Windows relative path", "flows\\myflow.yaml", true, nil},
		{"Just slash", "/", true, nil},
		{"Just backslash", "\\", true, nil},

		// File existence based detection
		{"Existing file", "", true, func() string {
			tmpFile, err := os.CreateTemp("", "test-flow-*.yaml")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			tmpFile.Close()
			return tmpFile.Name()
		}},
		{"Non-existent file path", "definitely/does/not/exist.yaml", true, nil},
		{"Non-existent simple name", "doesnotexist", false, nil},

		// Edge cases
		{"Empty string", "", false, nil},
		{"Hidden file", ".hidden.yaml", true, nil},
		{"Space in name", "my flow.yaml", true, nil},
		{"Special characters", "flow@#$.yaml", true, nil},
		{"Very long name", "verylongflownamewithoutextension", false, nil},
		{"Mixed separators", "flows\\mixed/path.yaml", true, nil},

		// Complex path scenarios
		{"Relative with parent", "../parent/flow.yaml", true, nil},
		{"Current dir reference", "./flow.yaml", true, nil},
		{"Multiple extensions", "flow.config.yaml", true, nil},
		{"Numeric flow name", "flow123", false, nil},
		{"Alphanumeric with underscore", "my_flow_v2", false, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := tt.input
			var cleanup string

			// Handle setup function
			if tt.setup != nil {
				cleanup = tt.setup()
				if cleanup != "" {
					input = cleanup
					defer os.Remove(cleanup)
				}
			}

			result := looksLikeFilePath(input)
			if result != tt.expected {
				t.Errorf("looksLikeFilePath(%q) = %v, expected %v", input, result, tt.expected)
			}
		})
	}
}

// TestLooksLikeFilePath_FileExistence tests the file existence detection specifically
func TestLooksLikeFilePath_FileExistence(t *testing.T) {
	// Create a temporary directory for our tests
	tempDir, err := os.MkdirTemp("", "test-file-detection-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create various test files
	testFiles := []struct {
		name     string
		expected bool
	}{
		{"existing.yaml", true},
		{"existing.yml", true},
		{"existing.json", true},
		{"existing-no-ext", true}, // File exists, so should be detected as file path
	}

	for _, tf := range testFiles {
		filePath := filepath.Join(tempDir, tf.name)
		if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", tf.name, err)
		}

		result := looksLikeFilePath(filePath)
		if result != tf.expected {
			t.Errorf("looksLikeFilePath(%q) = %v, expected %v", filePath, result, tf.expected)
		}
	}

	// Test non-existent files in the temp dir
	nonExistentPath := filepath.Join(tempDir, "does-not-exist.yaml")
	if looksLikeFilePath(nonExistentPath) != true {
		t.Error("Non-existent file with .yaml extension should be detected as file path")
	}

	nonExistentNoExt := filepath.Join(tempDir, "does-not-exist")
	if looksLikeFilePath(nonExistentNoExt) != true {
		t.Error("Non-existent file with path separators should be detected as file path")
	}
}

// TestLooksLikeFilePath_CrossPlatform tests cross-platform path detection
func TestLooksLikeFilePath_CrossPlatform(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// Windows-style paths
		{"Windows drive path", "C:\\Users\\flow.yaml", true},
		{"Windows UNC path", "\\\\server\\share\\flow.yaml", true},
		{"Windows relative", "folder\\flow.yaml", true},

		// Unix-style paths
		{"Unix absolute", "/home/user/flow.yaml", true},
		{"Unix relative", "folder/flow.yaml", true},
		{"Unix hidden", "/home/user/.config/flow.yaml", true},

		// Mixed separators (some tools normalize these)
		{"Mixed separators 1", "folder\\file/flow.yaml", true},
		{"Mixed separators 2", "folder/file\\flow.yaml", true},

		// Simple names (should not be file paths)
		{"Simple flow name", "my_flow", false},
		{"Simple with numbers", "flow123", false},
		{"Simple with underscores", "my_flow_v2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := looksLikeFilePath(tt.path)
			if result != tt.expected {
				t.Errorf("looksLikeFilePath(%q) = %v, expected %v", tt.path, result, tt.expected)
			}
		})
	}
}

// TestLooksLikeFilePath_EdgeCases tests edge cases and error conditions
func TestLooksLikeFilePath_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
		setup    func() string // Optional setup function that returns a cleanup path
	}{
		// Boundary conditions
		{"Single character", "a", false, nil},
		{"Single dot", ".", true, nil},         // This is a valid path (current directory)
		{"Double dot", "..", true, nil},        // This is a valid path (parent directory)
		{"Just extension", ".yaml", true, nil}, // This has an extension so should be treated as file
		{"Extension only", "yaml", false, nil},

		// Unicode and special characters
		{"Unicode filename", "フロー.yaml", true, nil},
		{"Emoji filename", "🚀flow.yaml", true, nil},
		{"Special chars", "flow@#$%^&*().yaml", true, nil},

		// URL-like strings (should be treated as file paths because they contain separators)
		{"HTTP URL", "http://example.com/flow.yaml", true, nil},   // Contains path separators
		{"HTTPS URL", "https://example.com/flow.yaml", true, nil}, // Contains path separators
		{"FTP URL", "ftp://server/flow.yaml", true, nil},          // Contains path separators

		// Very long paths
		{"Long path", filepath.Join(
			"very", "long", "path", "with", "many", "components",
			"that", "goes", "on", "and", "on", "flow.yaml"), true, nil},
		{"Long filename", "very_long_filename_that_might_be_problematic.yaml", true, nil},

		// Whitespace scenarios
		{"Leading space", " flow.yaml", true, nil},
		{"Trailing space", "flow.yaml ", false, nil}, // Doesn't match yaml regex due to space
		{"Internal spaces", "my flow file.yaml", true, nil},
		{"Tab character", "flow\t.yaml", true, nil},
		{"Newline character", "flow\n.yaml", true, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := tt.input
			var cleanup string

			// Handle setup function
			if tt.setup != nil {
				cleanup = tt.setup()
				if cleanup != "" {
					input = cleanup
					defer os.Remove(cleanup)
				}
			}

			result := looksLikeFilePath(input)
			if result != tt.expected {
				t.Errorf("looksLikeFilePath(%q) = %v, expected %v", input, result, tt.expected)
			}
		})
	}
}

// TestGetOperation tests the operation registry functions
func TestGetOperation(t *testing.T) {
	// Test getting an existing operation
	op, exists := GetOperation("listFlows")
	if !exists {
		t.Error("Expected listFlows operation to exist")
	}
	if op == nil {
		t.Error("Expected non-nil operation")
	}

	// Test getting a non-existent operation
	op, exists = GetOperation("nonexistent")
	if exists {
		t.Error("Expected nonexistent operation to not exist")
	}
	if op != nil {
		t.Error("Expected nil operation for non-existent key")
	}

}

// TestGetAllOperations tests the operation registry
func TestGetAllOperations(t *testing.T) {
	ops := GetAllOperations()
	if ops == nil {
		t.Error("Expected non-nil operations map")
	}

	// Should have some operations registered
	if len(ops) == 0 {
		t.Error("Expected some operations to be registered")
	}

	// Check for key operations we know should exist
	expectedOps := []string{"listFlows", "getFlow", "validateFlow", "startRun"}
	for _, expectedOp := range expectedOps {
		if _, exists := ops[expectedOp]; !exists {
			t.Errorf("Expected operation %s to exist", expectedOp)
		}
	}
}

// TestRegisterOperation tests operation registration
func TestRegisterOperation(t *testing.T) {
	// Create a test operation
	testOp := &OperationDefinition{
		ID:          "testOperation",
		Name:        "Test Operation",
		Description: "A test operation",
		Group:       "system",
		Handler: func(ctx context.Context, args any) (any, error) {
			return "test result", nil
		},
	}

	// Register it
	RegisterOperation(testOp)

	// Verify it was registered
	registered, exists := GetOperation("testOperation")
	if !exists {
		t.Error("Expected test operation to be registered")
	}
	if registered.ID != "testOperation" {
		t.Errorf("Expected operation ID 'testOperation', got %s", registered.ID)
	}
	if registered.MCPName != "testOperation" {
		t.Errorf("Expected MCPName to default to ID, got %s", registered.MCPName)
	}

	// Test with custom MCP name
	testOp2 := &OperationDefinition{
		ID:      "testOperation2",
		Group:   "system",
		MCPName: "custom_mcp_name",
		Handler: func(ctx context.Context, args any) (any, error) {
			return "test", nil
		},
	}

	RegisterOperation(testOp2)
	registered2, _ := GetOperation("testOperation2")
	if registered2.MCPName != "custom_mcp_name" {
		t.Errorf("Expected custom MCP name to be preserved, got %s", registered2.MCPName)
	}
}

// TestGetOperationsMapByGroups tests the group-based filtering
func TestGetOperationsMapByGroups(t *testing.T) {
	// Test with no groups (should return all)
	allOps := GetOperationsMapByGroups(nil)
	if len(allOps) == 0 {
		t.Error("Expected some operations when no groups specified")
	}

	// Test with empty slice (should return all)
	allOps2 := GetOperationsMapByGroups([]string{})
	if len(allOps2) != len(allOps) {
		t.Error("Empty slice should return same as nil")
	}

	// Test with specific groups
	flowsOps := GetOperationsMapByGroups([]string{"flows"})
	if len(flowsOps) == 0 {
		t.Error("Expected some flows operations")
	}

	runsOps := GetOperationsMapByGroups([]string{"runs"})
	if len(runsOps) == 0 {
		t.Error("Expected some runs operations")
	}

	// Verify we get different results for different groups
	if len(flowsOps) == len(runsOps) && len(flowsOps) == len(allOps) {
		t.Error("Groups should filter to different subsets")
	}

	// Test with multiple groups
	multiOps := GetOperationsMapByGroups([]string{"flows", "runs"})
	expectedCount := len(flowsOps) + len(runsOps)
	if len(multiOps) != expectedCount {
		t.Errorf("Expected %d operations for flows+runs, got %d", expectedCount, len(multiOps))
	}

	// Test with non-existent group
	noneOps := GetOperationsMapByGroups([]string{"nonexistent"})
	if len(noneOps) != 0 {
		t.Error("Expected no operations for non-existent group")
	}

	// Test with whitespace in group names
	trimOps := GetOperationsMapByGroups([]string{" flows ", "runs "})
	if len(trimOps) != expectedCount {
		t.Error("Should handle whitespace in group names")
	}
}

// TestGetOperationsByGroups tests the slice version of group filtering
func TestGetOperationsByGroups(t *testing.T) {
	// Test with flows group
	flowsOps := GetOperationsByGroups([]string{"flows"})
	if len(flowsOps) == 0 {
		t.Error("Expected some flows operations")
	}

	// Verify all returned operations have the correct group
	for _, op := range flowsOps {
		if op.Group != "flows" {
			t.Errorf("Expected operation %s to have group 'flows', got '%s'", op.ID, op.Group)
		}
	}

	// Test with system group
	systemOps := GetOperationsByGroups([]string{"system"})
	if len(systemOps) == 0 {
		t.Error("Expected some system operations")
	}

	for _, op := range systemOps {
		if op.Group != "system" {
			t.Errorf("Expected operation %s to have group 'system', got '%s'", op.ID, op.Group)
		}
	}
}

// TestOperationGroups verifies that all operations have valid groups assigned
func TestOperationGroups(t *testing.T) {
	allOps := GetAllOperations()
	validGroups := map[string]bool{
		"flows":  true,
		"runs":   true,
		"events": true,
		"tools":  true,
		"mcp":    true,
		"system": true,
	}

	for id, op := range allOps {
		if op.Group == "" {
			t.Errorf("Operation %s has no group assigned", id)
		}

		if !validGroups[op.Group] {
			t.Errorf("Operation %s has invalid group '%s'", id, op.Group)
		}
	}
}
