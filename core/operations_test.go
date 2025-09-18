package api

import (
	"context"
	"testing"
)

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
	if len(flowsOps) == len(runsOps) || len(flowsOps) == len(allOps) {
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
		"oauth":  true,
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
