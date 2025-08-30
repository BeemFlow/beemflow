package adapter

import (
    "context"
    "fmt"
    "os"
    "path/filepath"
    "strings"

    "github.com/awantoch/beemflow/config"
    "github.com/awantoch/beemflow/constants"
    "github.com/awantoch/beemflow/dsl"
    "github.com/awantoch/beemflow/registry"
)

// BeemBeemAdapter provides workflow management utilities for BeemBeem.
// It follows the established adapter pattern of simple, focused operations.
type BeemBeemAdapter struct{}

func (b *BeemBeemAdapter) ID() string { return "beembeem" }

func (b *BeemBeemAdapter) Execute(ctx context.Context, inputs map[string]any) (map[string]any, error) {
    use, ok := inputs["__use"].(string)
    if !ok {
        return nil, fmt.Errorf("missing __use for BeemBeemAdapter")
    }

    switch use {
    case "beembeem.save_workflow":
        return b.executeWorkflowSave(ctx, inputs)
    case "beembeem.validate_workflow":
        return b.executeWorkflowValidate(ctx, inputs)
    case "beembeem.list_workflows":
        return b.executeWorkflowList(ctx, inputs)
    default:
        return nil, fmt.Errorf("unknown beembeem tool: %s", use)
    }
}

func (b *BeemBeemAdapter) executeWorkflowSave(ctx context.Context, inputs map[string]any) (map[string]any, error) {
    yamlStr, ok := inputs["workflow_yaml"].(string)
    if !ok || yamlStr == "" {
        return nil, fmt.Errorf("missing required field: workflow_yaml")
    }
    
    name, ok := inputs["name"].(string)
    if !ok || name == "" {
        return nil, fmt.Errorf("missing required field: name")
    }

    // Validate using existing BeemFlow validation
    flow, err := dsl.ParseFromString(yamlStr)
    if err != nil {
        return map[string]any{
            "success": false,
            "error":   fmt.Sprintf("Parse error: %v", err),
        }, nil
    }
    
    if err := dsl.Validate(flow); err != nil {
        return map[string]any{
            "success": false,
            "error":   fmt.Sprintf("Validation error: %v", err),
        }, nil
    }

    // Generate filename following BeemFlow conventions
    filename := b.generateFilename(name)
    path := filepath.Join(config.DefaultFlowsDir, filename)
    
    // Ensure directory exists
    if err := os.MkdirAll(config.DefaultFlowsDir, 0755); err != nil {
        return nil, fmt.Errorf("failed to create flows directory: %v", err)
    }
    
    if err := os.WriteFile(path, []byte(yamlStr), 0644); err != nil {
        return nil, fmt.Errorf("failed to save workflow: %v", err)
    }

    return map[string]any{
        "success": true,
        "path":    path,
        "name":    name,
    }, nil
}

func (b *BeemBeemAdapter) executeWorkflowValidate(ctx context.Context, inputs map[string]any) (map[string]any, error) {
    yamlStr, ok := inputs["workflow_yaml"].(string)
    if !ok || yamlStr == "" {
        return nil, fmt.Errorf("missing required field: workflow_yaml")
    }

    // Parse and validate
    flow, err := dsl.ParseFromString(yamlStr)
    if err != nil {
        return map[string]any{
            "valid": false,
            "error": fmt.Sprintf("Parse error: %v", err),
        }, nil
    }
    
    if err := dsl.Validate(flow); err != nil {
        return map[string]any{
            "valid": false,
            "error": fmt.Sprintf("Validation error: %v", err),
        }, nil
    }

    return map[string]any{
        "valid": true,
        "name":  flow.Name,
    }, nil
}

func (b *BeemBeemAdapter) executeWorkflowList(ctx context.Context, inputs map[string]any) (map[string]any, error) {
    // List workflows from the flows directory directly
    entries, err := os.ReadDir(config.DefaultFlowsDir)
    if err != nil {
        if os.IsNotExist(err) {
            return map[string]any{"workflows": []string{}}, nil
        }
        return nil, fmt.Errorf("failed to read flows directory: %v", err)
    }
    
    var workflows []string
    for _, entry := range entries {
        if entry.IsDir() {
            continue
        }
        name := entry.Name()
        if strings.HasSuffix(name, constants.FlowFileExtension) {
            base := strings.TrimSuffix(name, constants.FlowFileExtension)
            workflows = append(workflows, base)
        }
    }
    
    return map[string]any{"workflows": workflows}, nil
}

// generateFilename creates a valid filename from a workflow name
func (b *BeemBeemAdapter) generateFilename(name string) string {
    // Convert to lowercase and replace spaces with underscores
    filename := strings.ToLower(strings.ReplaceAll(name, " ", "_"))
    
    // Remove non-alphanumeric characters except underscores
    var result strings.Builder
    for _, r := range filename {
        if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
            result.WriteRune(r)
        }
    }
    
    return result.String() + constants.FlowFileExtension
}

func (b *BeemBeemAdapter) Manifest() *registry.ToolManifest {
    return &registry.ToolManifest{
        Name:        "beembeem",
        Description: "BeemBeem workflow management utilities",
        Kind:        "task",
    }
}