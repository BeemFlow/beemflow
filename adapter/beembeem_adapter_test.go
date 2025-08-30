package adapter

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/awantoch/beemflow/config"
)

func TestBeemBeemAdapter_ID(t *testing.T) {
	adapter := &BeemBeemAdapter{}
	if adapter.ID() != "beembeem" {
		t.Errorf("expected ID 'beembeem', got %s", adapter.ID())
	}
}

func TestBeemBeemAdapter_Manifest(t *testing.T) {
	adapter := &BeemBeemAdapter{}
	manifest := adapter.Manifest()
	if manifest == nil {
		t.Error("expected manifest to be non-nil")
	}
	if manifest.Name != "beembeem" {
		t.Errorf("expected manifest name 'beembeem', got %s", manifest.Name)
	}
}

func TestBeemBeemAdapter_ExecuteWorkflowValidate(t *testing.T) {
	adapter := &BeemBeemAdapter{}
	ctx := context.Background()

	// Test valid workflow
	validWorkflow := `name: test_workflow
on: cli.manual
steps:
  - id: echo
    use: core.echo
    with:
      text: "Hello World"`

	result, err := adapter.Execute(ctx, map[string]any{
		"__use":         "beembeem.validate_workflow",
		"workflow_yaml": validWorkflow,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["valid"] != true {
		t.Errorf("expected valid=true, got %v", result["valid"])
	}
	if result["name"] != "test_workflow" {
		t.Errorf("expected name='test_workflow', got %v", result["name"])
	}

	// Test invalid workflow
	invalidWorkflow := `invalid yaml: [}`

	result, err = adapter.Execute(ctx, map[string]any{
		"__use":         "beembeem.validate_workflow",
		"workflow_yaml": invalidWorkflow,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["valid"] != false {
		t.Errorf("expected valid=false, got %v", result["valid"])
	}
	if result["error"] == nil {
		t.Error("expected error message for invalid workflow")
	}
}

func TestBeemBeemAdapter_ExecuteWorkflowSave(t *testing.T) {
	adapter := &BeemBeemAdapter{}
	ctx := context.Background()

	// Create temp directory for test
	tempDir := t.TempDir()
	oldFlowsDir := config.DefaultFlowsDir
	config.DefaultFlowsDir = tempDir
	defer func() { config.DefaultFlowsDir = oldFlowsDir }()

	validWorkflow := `name: test_save_workflow
on: cli.manual
steps:
  - id: echo
    use: core.echo
    with:
      text: "Hello World"`

	result, err := adapter.Execute(ctx, map[string]any{
		"__use":         "beembeem.save_workflow",
		"name":          "test_save_workflow",
		"workflow_yaml": validWorkflow,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["success"] != true {
		t.Errorf("expected success=true, got %v", result["success"])
	}
	if result["name"] != "test_save_workflow" {
		t.Errorf("expected name='test_save_workflow', got %v", result["name"])
	}

	// Verify file was created
	expectedPath := filepath.Join(tempDir, "test_save_workflow.flow.yaml")
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Errorf("expected file to be created at %s", expectedPath)
	}
}

func TestBeemBeemAdapter_ExecuteWorkflowList(t *testing.T) {
	adapter := &BeemBeemAdapter{}
	ctx := context.Background()

	// Create temp directory for test
	tempDir := t.TempDir()
	oldFlowsDir := config.DefaultFlowsDir
	config.DefaultFlowsDir = tempDir
	defer func() { config.DefaultFlowsDir = oldFlowsDir }()

	// Create test workflow files
	testFiles := []string{"workflow1.flow.yaml", "workflow2.flow.yaml", "not_a_workflow.txt"}
	for _, file := range testFiles {
		err := os.WriteFile(filepath.Join(tempDir, file), []byte("test content"), 0644)
		if err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
	}

	result, err := adapter.Execute(ctx, map[string]any{
		"__use": "beembeem.list_workflows",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	workflows, ok := result["workflows"].([]string)
	if !ok {
		t.Fatalf("expected workflows to be []string, got %T", result["workflows"])
	}

	if len(workflows) != 2 {
		t.Errorf("expected 2 workflows, got %d", len(workflows))
	}

	// Check that only .flow.yaml files are included
	expectedWorkflows := map[string]bool{"workflow1": true, "workflow2": true}
	for _, workflow := range workflows {
		if !expectedWorkflows[workflow] {
			t.Errorf("unexpected workflow in list: %s", workflow)
		}
	}
}

func TestBeemBeemAdapter_ExecuteUnknownTool(t *testing.T) {
	adapter := &BeemBeemAdapter{}
	ctx := context.Background()

	_, err := adapter.Execute(ctx, map[string]any{
		"__use": "beembeem.unknown_tool",
	})
	if err == nil {
		t.Error("expected error for unknown tool")
	}
	if err.Error() != "unknown beembeem tool: beembeem.unknown_tool" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestBeemBeemAdapter_ExecuteMissingUse(t *testing.T) {
	adapter := &BeemBeemAdapter{}
	ctx := context.Background()

	_, err := adapter.Execute(ctx, map[string]any{
		"name": "test",
	})
	if err == nil {
		t.Error("expected error for missing __use")
	}
	if err.Error() != "missing __use for BeemBeemAdapter" {
		t.Errorf("unexpected error message: %v", err)
	}
}