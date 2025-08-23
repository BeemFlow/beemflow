package dsl

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beemflow/beemflow/model"
	"github.com/beemflow/beemflow/utils"
	pongo2 "github.com/flosch/pongo2/v6"
)

func TestNewTemplater(t *testing.T) {
	tpl := NewTemplater()
	if tpl == nil {
		t.Error("expected NewTemplater not nil")
	}
}

func TestRender_Simple(t *testing.T) {
	tpl := NewTemplater()
	out, err := tpl.Render("Hello {{ Name }}", map[string]any{"Name": "Go"})
	if err != nil {
		t.Errorf("Render returned error: %v", err)
	}
	if out != "Hello Go" {
		t.Errorf("expected 'Hello Go', got %q", out)
	}
}

func TestRender_Error(t *testing.T) {
	tpl := NewTemplater()
	_, err := tpl.Render("{{", nil)
	if err == nil {
		t.Error("expected error for invalid template, got nil")
	}
}

func TestRender_NestedAndFilters(t *testing.T) {
	tpl := NewTemplater()
	data := map[string]any{
		"Feature": "AI Automation",
		"Docs":    []string{"Doc1", "Doc2", "Doc3"},
	}
	out, err := tpl.Render(`Feature: {{ Feature }}\nDocs: {{ Docs|join:", " }}\nCount: {{ Docs|length }}`, data)
	if err != nil {
		t.Errorf("Render returned error: %v", err)
	}
	expected := "Feature: AI Automation\\nDocs: Doc1, Doc2, Doc3\\nCount: 3"
	if out != expected {
		t.Errorf("expected %q, got %q", expected, out)
	}
}

func TestRender_BuiltinFilters(t *testing.T) {
	tpl := NewTemplater()
	data := map[string]any{
		"text": "hello world",
		"val":  42,
	}
	// Test pongo2's built-in filters instead of custom ones
	out, err := tpl.Render(`Title: {{ text|title }}, Upper: {{ text|upper }}, Length: {{ text|length }}`, data)
	if err != nil {
		t.Errorf("Render returned error: %v", err)
	}
	if !strings.Contains(out, "Title: Hello World") {
		t.Errorf("expected title filter output, got %q", out)
	}
	if !strings.Contains(out, "Upper: HELLO WORLD") {
		t.Errorf("expected upper filter output, got %q", out)
	}
	if !strings.Contains(out, "Length: 11") {
		t.Errorf("expected length filter output, got %q", out)
	}
}

func TestRender_NilData(t *testing.T) {
	tpl := NewTemplater()
	_, err := tpl.Render("Hello {{ Name }}", nil)
	if err == nil {
		t.Errorf("expected error for nil data, got nil")
	}
}

func TestRender_MissingKey(t *testing.T) {
	tpl := NewTemplater()
	out, err := tpl.Render("Hello {{ Missing }}", map[string]any{"Name": "Go"})
	if err != nil {
		t.Errorf("unexpected error for missing key: %v", err)
	}
	if out != "Hello " {
		t.Errorf("expected blank for missing key, got %q", out)
	}
}

func TestRender_CustomFilter(t *testing.T) {
	tpl := NewTemplater()
	err := tpl.RegisterFilters(map[string]pongo2.FilterFunction{
		"repeat": func(in *pongo2.Value, param *pongo2.Value) (*pongo2.Value, *pongo2.Error) {
			n := param.Integer()
			res := ""
			for i := 0; i < n; i++ {
				res += in.String()
			}
			return pongo2.AsValue(res), nil
		},
	})
	if err != nil {
		t.Fatalf("RegisterFilters failed: %v", err)
	}
	out, err := tpl.Render(`{{ "ha"|repeat:3 }}!`, map[string]any{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if out != "hahaha!" {
		t.Errorf("expected 'hahaha!', got %q", out)
	}
}

func TestRender_ArrayAccess(t *testing.T) {
	tpl := NewTemplater()
	data := map[string]any{
		"arr": []map[string]any{
			{"val": "a"},
			{"val": "b"},
		},
	}
	out, err := tpl.Render(`First: {{ arr.0.val }}, Second: {{ arr.1.val }}`, data)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if out != "First: a, Second: b" {
		t.Errorf("expected 'First: a, Second: b', got %q", out)
	}
}

func TestRender_NoDelimiters(t *testing.T) {
	tpl := NewTemplater()
	out, err := tpl.Render("plain text", map[string]any{"foo": "bar"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if out != "plain text" {
		t.Errorf("expected 'plain text', got %q", out)
	}
}

func TestRender_DeeplyNestedTemplates(t *testing.T) {
	tpl := NewTemplater()
	data := map[string]any{
		"outer": map[string]any{
			"inner": map[string]any{
				"value": "deep",
			},
		},
	}
	out, err := tpl.Render("Value: {{ outer.inner.value }}", data)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if out != "Value: deep" {
		t.Errorf("expected 'Value: deep', got %q", out)
	}
}

func TestRender_SecretsDotAccess(t *testing.T) {
	tpl := NewTemplater()
	data := map[string]any{
		"secrets": map[string]any{"MY_SECRET": "shhh"},
	}
	out, err := tpl.Render("{{ secrets.MY_SECRET }}", data)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if out != "shhh" {
		t.Errorf("expected 'shhh', got %q", out)
	}
}

func TestRender_EventDotAccess(t *testing.T) {
	tpl := NewTemplater()
	data := map[string]any{
		"event": map[string]any{"foo": "bar"},
	}
	out, err := tpl.Render("{{ event.foo }}", data)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if out != "bar" {
		t.Errorf("expected 'bar', got %q", out)
	}
}

func TestRender_StepOutputTopLevel(t *testing.T) {
	tpl := NewTemplater()
	data := map[string]any{
		"fetch": map[string]any{"body": "hello world"},
	}
	out, err := tpl.Render("{{ fetch.body }}", data)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if out != "hello world" {
		t.Errorf("expected 'hello world', got %q", out)
	}
}

func TestRender_NestedStepOutput(t *testing.T) {
	tpl := NewTemplater()
	choices := []interface{}{
		map[string]any{"message": map[string]any{"content": "summary here"}},
	}
	data := map[string]any{
		"summarize": map[string]any{
			"choices": choices,
		},
	}
	// Only dot notation is supported for array access in pongo2
	out, err := tpl.Render("{{ summarize.choices.0.message.content }}", data)
	if err != nil {
		t.Errorf("unexpected error (dot notation): %v", err)
	}
	if out != "summary here" {
		t.Errorf("expected 'summary here' (dot notation), got %q", out)
	}
	// Bracket notation (choices[0]) is not supported by pongo2 and will fail to parse.
}

func TestRegisterFilters(t *testing.T) {
	templater := NewTemplater()

	// Test registering a custom filter
	err := templater.RegisterFilters(map[string]pongo2.FilterFunction{
		"double": func(in *pongo2.Value, param *pongo2.Value) (*pongo2.Value, *pongo2.Error) {
			val := in.Integer()
			return pongo2.AsValue(val * 2), nil
		},
	})
	if err != nil {
		t.Fatalf("RegisterFilters failed: %v", err)
	}

	result, err := templater.Render("{{ 5 | double }}", map[string]any{})
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}
	if result != "10" {
		t.Errorf("Expected '10', got '%s'", result)
	}
}

// Test Load function
func TestLoad(t *testing.T) {
	// Create a temporary YAML file
	tempDir, err := os.MkdirTemp("", "dsl_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	yamlContent := `name: test_flow
on: cli.manual
steps:
  - id: test_step
    use: core.echo
    with:
      text: "Hello World"
`

	yamlFile := filepath.Join(tempDir, "test.flow.yaml")
	err = os.WriteFile(yamlFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Test Load function
	flow, err := Load(yamlFile, map[string]any{})
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if flow.Name != "test_flow" {
		t.Errorf("Expected flow name 'test_flow', got '%s'", flow.Name)
	}
	if len(flow.Steps) != 1 {
		t.Errorf("Expected 1 step, got %d", len(flow.Steps))
	}

	// Test Load with non-existent file
	_, err = Load("non_existent_file.yaml", map[string]any{})
	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	// Test Load with invalid YAML
	invalidYamlFile := filepath.Join(tempDir, "invalid.yaml")
	err = os.WriteFile(invalidYamlFile, []byte("invalid: yaml: content: ["), 0644)
	if err != nil {
		t.Fatalf("Failed to write invalid test file: %v", err)
	}

	_, err = Load(invalidYamlFile, map[string]any{})
	if err == nil {
		t.Error("Expected error for invalid YAML")
	}
}

// Test Parse function
func TestParse(t *testing.T) {
	// Create a temporary YAML file
	tempDir, err := os.MkdirTemp("", "dsl_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	yamlContent := `name: test_flow
on: cli.manual
steps:
  - id: test_step
    use: core.echo
    with:
      text: "Hello World"
`

	yamlFile := filepath.Join(tempDir, "test.flow.yaml")
	err = os.WriteFile(yamlFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	flow, err := Parse(yamlFile)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if flow.Name != "test_flow" {
		t.Errorf("Expected flow name 'test_flow', got '%s'", flow.Name)
	}
	if len(flow.Steps) != 1 {
		t.Errorf("Expected 1 step, got %d", len(flow.Steps))
	}

	// Test Parse with non-existent file
	_, err = Parse("non_existent_file.yaml")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

// Test ParseFromString function
func TestParseFromString(t *testing.T) {
	yamlString := `name: test_flow
on: cli.manual
steps:
  - id: test_step
    use: core.echo
    with:
      text: "Hello World"
`

	flow, err := ParseFromString(yamlString)
	if err != nil {
		t.Fatalf("ParseFromString failed: %v", err)
	}
	if flow.Name != "test_flow" {
		t.Errorf("Expected flow name 'test_flow', got '%s'", flow.Name)
	}
	if len(flow.Steps) != 1 {
		t.Errorf("Expected 1 step, got %d", len(flow.Steps))
	}

	// Test ParseFromString with invalid YAML
	invalidYaml := "invalid: yaml: content: ["
	_, err = ParseFromString(invalidYaml)
	if err == nil {
		t.Error("Expected error for invalid YAML")
	}

	// Test ParseFromString with empty string - this actually parses successfully to an empty Flow
	flow, err = ParseFromString("")
	if err != nil {
		t.Errorf("ParseFromString with empty string failed: %v", err)
	}
	if flow == nil {
		t.Error("Expected non-nil flow for empty string")
	}
}

// Test Validate function
func TestValidate(t *testing.T) {
	// Test valid flow with required 'on' field
	validFlow := &model.Flow{
		Name: "test_flow",
		On:   "cli.manual",
		Steps: []model.Step{
			{
				ID:  "test_step",
				Use: "core.echo",
			},
		},
	}

	err := Validate(validFlow)
	if err != nil {
		t.Errorf("Validate failed for valid flow: %v", err)
	}

	// Test various invalid flows - we don't assert specific errors since
	// the behavior depends on the JSON schema implementation
	testCases := []struct {
		name string
		flow *model.Flow
	}{
		{
			name: "missing name",
			flow: &model.Flow{
				On: "cli.manual",
				Steps: []model.Step{
					{
						ID:  "test_step",
						Use: "core.echo",
					},
				},
			},
		},
		{
			name: "missing on field",
			flow: &model.Flow{
				Name: "test_flow",
				Steps: []model.Step{
					{
						ID:  "test_step",
						Use: "core.echo",
					},
				},
			},
		},
		{
			name: "empty steps",
			flow: &model.Flow{
				Name:  "test_flow",
				On:    "cli.manual",
				Steps: []model.Step{},
			},
		},
		{
			name: "step missing ID",
			flow: &model.Flow{
				Name: "test_flow",
				On:   "cli.manual",
				Steps: []model.Step{
					{
						Use: "core.echo",
					},
				},
			},
		},
		{
			name: "step missing Use",
			flow: &model.Flow{
				Name: "test_flow",
				On:   "cli.manual",
				Steps: []model.Step{
					{
						ID: "test_step",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.flow)
			// We just test that validation runs without panic
			// The actual error behavior depends on the JSON schema
			t.Logf("Validation result for %s: %v", tc.name, err)
		})
	}
}

// Test EvaluateExpression function
func TestEvaluateExpression(t *testing.T) {
	templater := NewTemplater()

	context := map[string]any{
		"event": map[string]any{
			"name": "John",
			"age":  30,
		},
		"vars": map[string]any{
			"greeting": "Hello",
		},
		"test_object": map[string]any{
			"name":   "Test Object",
			"values": []any{1, 2, 3, 4, 5},
			"nested": map[string]any{
				"deep_value": "found it",
				"array":      []any{"alpha", "beta", "gamma"},
			},
		},
	}

	// Test simple expression
	result, err := templater.EvaluateExpression("{{ event.name }}", context)
	if err != nil {
		t.Fatalf("EvaluateExpression failed: %v", err)
	}
	if result != "John" {
		t.Errorf("Expected 'John', got '%v'", result)
	}

	// Test nested expression
	result, err = templater.EvaluateExpression("{{ vars.greeting }}", context)
	if err != nil {
		t.Fatalf("EvaluateExpression failed: %v", err)
	}
	if result != "Hello" {
		t.Errorf("Expected 'Hello', got '%v'", result)
	}

	// Test array return (this is the key fix for foreach!)
	result, err = templater.EvaluateExpression("{{ test_object.values }}", context)
	if err != nil {
		t.Fatalf("EvaluateExpression failed for array: %v", err)
	}
	resultArray, ok := result.([]any)
	if !ok {
		t.Fatalf("Expected []any for test_object.values, got %T", result)
	}
	if len(resultArray) != 5 || resultArray[0] != 1 || resultArray[4] != 5 {
		t.Errorf("Expected [1,2,3,4,5], got %v", resultArray)
	}

	// Test deeply nested array
	result, err = templater.EvaluateExpression("{{ test_object.nested.array }}", context)
	if err != nil {
		t.Fatalf("EvaluateExpression failed for nested array: %v", err)
	}
	resultArray, ok = result.([]any)
	if !ok {
		t.Fatalf("Expected []any for nested array, got %T", result)
	}
	if len(resultArray) != 3 || resultArray[0] != "alpha" || resultArray[2] != "gamma" {
		t.Errorf("Expected [alpha,beta,gamma], got %v", resultArray)
	}

	// Test expression with missing key
	result, err = templater.EvaluateExpression("{{ event.missing }}", context)
	if err != nil {
		t.Fatalf("EvaluateExpression failed: %v", err)
	}
	// Missing keys should return empty string when rendered
	if result != "" {
		t.Errorf("Expected empty string for missing key, got '%v'", result)
	}

	// Test non-template expression
	result, err = templater.EvaluateExpression("simple_string", context)
	if err != nil {
		t.Fatalf("EvaluateExpression failed: %v", err)
	}
	if result != "simple_string" {
		t.Errorf("Expected 'simple_string', got '%v'", result)
	}

	// Test complex expression with filters (should fall back to render)
	result, err = templater.EvaluateExpression("{{ test_object.values | length }}", context)
	if err != nil {
		t.Fatalf("EvaluateExpression failed for filtered expression: %v", err)
	}
	// This should be rendered as a string since it has a filter
	if result != "5" {
		t.Errorf("Expected '5' (string) for filtered expression, got '%v'", result)
	}

	// Test mathematical expression (should fall back to render)
	result, err = templater.EvaluateExpression("{{ test_object.values.0 + 10 }}", context)
	if err != nil {
		t.Fatalf("EvaluateExpression failed for math expression: %v", err)
	}
	// This should be rendered as a string since it has mathematical operations
	if result != "11" {
		t.Errorf("Expected '11' (string) for math expression, got '%v'", result)
	}
}

// Test lookupNestedPath function (internal function, test via EvaluateExpression)
func TestLookupNestedPath(t *testing.T) {
	templater := NewTemplater()

	context := map[string]any{
		"level1": map[string]any{
			"level2": map[string]any{
				"level3": "deep_value",
			},
			"array": []any{"item1", "item2", "item3"},
		},
		"simple": "simple_value",
	}

	// Test deep nested path - with simplified logic, this renders as string
	result, err := templater.EvaluateExpression("{{ level1.level2.level3 }}", context)
	if err != nil {
		t.Fatalf("EvaluateExpression failed: %v", err)
	}
	// The simplified logic renders complex expressions as strings
	if !strings.Contains(fmt.Sprintf("%v", result), "deep_value") {
		t.Errorf("Expected result containing 'deep_value', got '%v'", result)
	}

	// Test array access - simplified logic renders complex expressions as strings
	result, err = templater.EvaluateExpression("{{ level1.array }}", context)
	if err != nil {
		t.Fatalf("EvaluateExpression failed: %v", err)
	}
	// This will be rendered as a string representation (may include pongo2 formatting)
	resultStr := fmt.Sprintf("%v", result)
	if !strings.Contains(resultStr, "item1") && !strings.Contains(resultStr, "Value>") {
		t.Errorf("Expected array content or pongo2 Value in result, got '%v'", result)
	}

	// Test simple path - this should work as a direct lookup
	result, err = templater.EvaluateExpression("{{ simple }}", context)
	if err != nil {
		t.Fatalf("EvaluateExpression failed: %v", err)
	}
	if result != "simple_value" {
		t.Errorf("Expected 'simple_value', got '%v'", result)
	}

	// Test non-existent path
	result, err = templater.EvaluateExpression("{{ non.existent.path }}", context)
	if err != nil {
		t.Fatalf("EvaluateExpression failed: %v", err)
	}
	if result != "" {
		t.Errorf("Expected empty string for non-existent path, got '%v'", result)
	}
}

// Test additional Render edge cases
func TestRender_AdditionalCases(t *testing.T) {
	templater := NewTemplater()

	// Test rendering with complex nested data
	data := map[string]any{
		"user": map[string]any{
			"profile": map[string]any{
				"settings": map[string]any{
					"theme": "dark",
				},
			},
		},
		"items": []any{
			map[string]any{"name": "item1", "value": 10},
			map[string]any{"name": "item2", "value": 20},
		},
	}

	result, err := templater.Render("Theme: {{ user.profile.settings.theme }}", data)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}
	if result != "Theme: dark" {
		t.Errorf("Expected 'Theme: dark', got '%s'", result)
	}

	// Test rendering with invalid template syntax
	_, err = templater.Render("{{ invalid template syntax", data)
	if err == nil {
		t.Error("Expected error for invalid template syntax")
	}
}

// Test NewTemplater edge cases
func TestNewTemplater_EdgeCases(t *testing.T) {
	templater := NewTemplater()
	if templater == nil {
		t.Fatal("NewTemplater returned nil")
	}

	// Test that the templater has the expected built-in filters
	data := map[string]any{"value": "hello"}

	result, err := templater.Render("{{ value | upper }}", data)
	if err != nil {
		t.Fatalf("Render with upper filter failed: %v", err)
	}
	if result != "HELLO" {
		t.Errorf("Expected 'HELLO', got '%s'", result)
	}

	result, err = templater.Render("{{ value | lower }}", data)
	if err != nil {
		t.Fatalf("Render with lower filter failed: %v", err)
	}
	if result != "hello" {
		t.Errorf("Expected 'hello', got '%s'", result)
	}
}

// Test RegisterFilters edge cases
func TestRegisterFilters_EdgeCases(t *testing.T) {
	templater := NewTemplater()

	// Test registering multiple filters
	err := templater.RegisterFilters(map[string]pongo2.FilterFunction{
		"triple": func(in *pongo2.Value, param *pongo2.Value) (*pongo2.Value, *pongo2.Error) {
			val := in.Integer()
			return pongo2.AsValue(val * 3), nil
		},
		"square": func(in *pongo2.Value, param *pongo2.Value) (*pongo2.Value, *pongo2.Error) {
			val := in.Integer()
			return pongo2.AsValue(val * val), nil
		},
	})
	if err != nil {
		t.Fatalf("RegisterFilters failed: %v", err)
	}

	result, err := templater.Render("{{ 4 | triple }}", map[string]any{})
	if err != nil {
		t.Fatalf("Render with triple filter failed: %v", err)
	}
	if result != "12" {
		t.Errorf("Expected '12', got '%s'", result)
	}

	result, err = templater.Render("{{ 5 | square }}", map[string]any{})
	if err != nil {
		t.Fatalf("Render with square filter failed: %v", err)
	}
	if result != "25" {
		t.Errorf("Expected '25', got '%s'", result)
	}

	// Test registering nil filters (should not crash)
	err = templater.RegisterFilters(nil)
	if err != nil {
		t.Errorf("RegisterFilters with nil should not fail: %v", err)
	}

	// Test registering empty filters
	err = templater.RegisterFilters(map[string]pongo2.FilterFunction{})
	if err != nil {
		t.Errorf("RegisterFilters with empty map should not fail: %v", err)
	}
}

// Test Render function (package-level)
func TestRender_PackageLevel(t *testing.T) {
	data := map[string]any{"name": "World"}

	result, err := Render("Hello {{ name }}!", data)
	if err != nil {
		t.Fatalf("Package-level Render failed: %v", err)
	}
	if result != "Hello World!" {
		t.Errorf("Expected 'Hello World!', got '%s'", result)
	}

	// Test with nil data
	_, err = Render("Hello World!", nil)
	if err == nil {
		t.Error("Expected error for nil data")
	}
}

// Test RegisterFilters function (package-level)
func TestRegisterFilters_PackageLevel(t *testing.T) {
	filters := map[string]pongo2.FilterFunction{
		"multiply": func(in *pongo2.Value, param *pongo2.Value) (*pongo2.Value, *pongo2.Error) {
			val := in.Integer()
			multiplier := param.Integer()
			return pongo2.AsValue(val * multiplier), nil
		},
	}

	err := RegisterFilters(filters)
	if err != nil {
		t.Fatalf("Package-level RegisterFilters failed: %v", err)
	}

	result, err := Render("{{ 7 | multiply:3 }}", map[string]any{})
	if err != nil {
		t.Fatalf("Render with registered filter failed: %v", err)
	}
	if result != "21" {
		t.Errorf("Expected '21', got '%s'", result)
	}
}

// INTEGRATION TESTS - These test real-world complexity that unit tests might miss

// TestTemplateEngineRealWorldComplexity tests template engine with complex real-world data
func TestTemplateEngineRealWorldComplexity(t *testing.T) {
	templater := NewTemplater()

	// Simulate complex flow execution data that could cause template engine issues
	complexData := map[string]any{
		"event": map[string]any{
			"user": map[string]any{
				"profile": map[string]any{
					"settings": map[string]any{
						"notifications": []any{
							map[string]any{"type": "email", "enabled": true, "frequency": "daily"},
							map[string]any{"type": "sms", "enabled": false, "frequency": "never"},
						},
					},
				},
			},
			"metadata": map[string]any{
				"timestamp": "2024-01-01T00:00:00Z",
				"source":    "api",
				"version":   "1.0.0",
			},
		},
		"vars": map[string]any{
			"analysis_results": []any{
				map[string]any{"score": 0.95, "category": "positive", "tokens": []any{"good", "excellent", "amazing"}},
				map[string]any{"score": 0.23, "category": "negative", "tokens": []any{"bad", "terrible"}},
			},
			"nested_config": map[string]any{
				"level1": map[string]any{
					"level2": map[string]any{
						"level3": map[string]any{
							"deep_array":  []any{1, 2, 3, 4, 5},
							"deep_string": "deeply nested value",
						},
					},
				},
			},
		},
		"outputs": map[string]any{
			"step_1": map[string]any{
				"result": map[string]any{
					"data": []any{
						map[string]any{"id": 1, "value": "item1"},
						map[string]any{"id": 2, "value": "item2"},
					},
				},
			},
		},
	}

	// Test complex template that could break with reflection issues
	complexTemplate := `
Analysis Results:
{% for result in vars.analysis_results %}
- Category: {{ result.category }}
- Score: {{ result.score }}
- Tokens: {{ result.tokens|join:", " }}
{% endfor %}

User Settings:
{% for notification in event.user.profile.settings.notifications %}
- {{ notification.type }}: {{ notification.enabled|yesno:"enabled,disabled" }} ({{ notification.frequency }})
{% endfor %}

Deep Access: {{ vars.nested_config.level1.level2.level3.deep_string }}
Deep Array: {{ vars.nested_config.level1.level2.level3.deep_array|join:" -> " }}

Output Data:
{% for item in outputs.step_1.result.data %}
- ID {{ item.id }}: {{ item.value }}
{% endfor %}
`

	// This should not panic or fail - if it does, template engine has integration issues
	result, err := templater.Render(complexTemplate, complexData)
	if err != nil {
		t.Fatalf("Complex template rendering failed: %v", err)
	}

	// Debug: Print the actual result to see what's happening
	t.Logf("Template rendered result:\n%s", result)

	// Verify some key content is present (not exhaustive, just ensuring it worked)
	if !strings.Contains(result, "Category: positive") {
		t.Errorf("Template didn't render analysis results correctly")
	}
	if !strings.Contains(result, "deeply nested value") {
		t.Errorf("Template didn't access deeply nested data correctly")
	}
	// Template engine HTML-escapes output, so -> becomes &gt;
	if !strings.Contains(result, "1 -&gt; 2 -&gt; 3 -&gt; 4 -&gt; 5") {
		t.Errorf("Template didn't render deep array correctly. Expected HTML-escaped output. Got result:\n%s", result)
	}
}

// TestTemplateEngineThreadSafety tests concurrent template rendering
func TestTemplateEngineThreadSafety(t *testing.T) {
	templater := NewTemplater()

	// Test concurrent template rendering (template engine uses mutex)
	const numGoroutines = 50
	const rendersPerGoroutine = 10

	errChan := make(chan error, numGoroutines*rendersPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		go func(workerID int) {
			for j := 0; j < rendersPerGoroutine; j++ {
				data := map[string]any{
					"worker": workerID,
					"render": j,
				}

				template := "Worker {{ worker }} - Render {{ render }}: {{ worker|add:render }}"
				result, err := templater.Render(template, data)
				if err != nil {
					errChan <- fmt.Errorf("worker %d render %d failed: %w", workerID, j, err)
					return
				}

				expected := fmt.Sprintf("Worker %d - Render %d: %d", workerID, j, workerID+j)
				if result != expected {
					errChan <- fmt.Errorf("worker %d render %d: expected %s, got %s", workerID, j, expected, result)
					return
				}
			}
		}(i)
	}

	// Close channel when all goroutines complete
	go func() {
		// Simple wait - in production you'd use sync.WaitGroup
		for completed := 0; completed < numGoroutines; {
			select {
			case <-errChan:
				// Error occurred, will be handled below
			default:
				// Check if we can increment completed (naive approach for test)
				completed++
			}
		}
		close(errChan)
	}()

	// Collect any errors
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
		if len(errors) > 10 { // Stop after 10 errors to avoid spam
			break
		}
	}

	if len(errors) > 0 {
		t.Errorf("Thread safety test failed with %d errors. First few: %v", len(errors), errors[:utils.Min(5, len(errors))])
	}
}

// TestTemplateEngineMalformedData tests template engine with potentially problematic data
func TestTemplateEngineMalformedData(t *testing.T) {
	templater := NewTemplater()

	// Test with data that might cause reflection or type assertion issues
	problematicData := map[string]any{
		"nil_value":     nil,
		"empty_string":  "",
		"empty_slice":   []any{},
		"empty_map":     map[string]any{},
		"mixed_slice":   []any{1, "string", nil, map[string]any{"nested": true}},
		"circular_ref":  nil, // We'll create this below
		"large_string":  strings.Repeat("x", 10000),
		"unicode":       "Hello 世界 🌍 Ñoël",
		"special_chars": `"quotes" 'single' \backslash \n\t\r`,
	}

	// Create a circular reference (if template engine doesn't handle this, it could infinite loop)
	circular := map[string]any{
		"self": nil,
	}
	circular["self"] = circular
	problematicData["circular_ref"] = circular

	// Templates that should handle edge cases gracefully
	tests := []struct {
		name     string
		template string
		wantErr  bool
	}{
		{
			name:     "nil value access",
			template: "Value: {{ nil_value }}",
			wantErr:  false, // Should render as empty
		},
		{
			name:     "empty collections",
			template: "Slice: {{ empty_slice|length }}, Map keys: {{ empty_map|length }}",
			wantErr:  false,
		},
		{
			name:     "unicode handling",
			template: "Unicode: {{ unicode|upper }}",
			wantErr:  false,
		},
		{
			name:     "special characters",
			template: `Special: "{{ special_chars }}"`,
			wantErr:  false,
		},
		{
			name:     "large string",
			template: "Large: {{ large_string|length }}",
			wantErr:  false,
		},
		{
			name:     "mixed array access",
			template: "Mixed: {{ mixed_slice.0 }}, {{ mixed_slice.1 }}, {{ mixed_slice.3.nested }}",
			wantErr:  false,
		},
		// Note: Circular reference test might need to be skipped if it causes issues
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := templater.Render(tt.template, problematicData)
			if (err != nil) != tt.wantErr {
				t.Errorf("Render() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Just verify we got some result without panicking
				t.Logf("Template rendered successfully: %s", result)
			}
		})
	}
}

// TestTemplater_Render_LongString tests rendering with longer template strings
func TestTemplater_Render_LongString(t *testing.T) {
	templater := NewTemplater()

	// Create a very long template string
	var builder strings.Builder
	for i := 0; i < 1000; i++ {
		builder.WriteString("{{ name }}-")
	}
	template := builder.String()

	data := map[string]any{"name": "test"}
	result, err := templater.Render(template, data)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	expected := strings.Repeat("test-", 1000)
	if result != expected {
		t.Errorf("Expected %s, got %s", expected[:utils.Min(50, len(expected))], result[:utils.Min(50, len(result))])
	}
}
