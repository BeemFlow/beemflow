package adapter

import (
	"context"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/beemflow/beemflow/constants"
	"github.com/beemflow/beemflow/utils"
)

// TestCoreAdapter tests that CoreAdapter prints text and returns inputs.
func TestCoreAdapter(t *testing.T) {
	a := &CoreAdapter{}
	// Set debug mode
	os.Setenv("BEEMFLOW_DEBUG", "1")
	defer os.Unsetenv("BEEMFLOW_DEBUG")
	// capture logger output
	r, w, _ := os.Pipe()
	orig := os.Stderr
	utils.SetInternalOutput(w)

	in := map[string]any{"__use": "core.echo", "text": "echoed"}
	out, err := a.Execute(context.Background(), in)
	w.Close()
	utils.SetInternalOutput(orig)

	buf, _ := io.ReadAll(r)
	if len(buf) == 0 || string(buf) == "\n" {
		t.Errorf("expected echoed in logger output, got %q", buf)
	}

	// Expected output should be the input without the __use field
	expected := map[string]any{"text": "echoed"}
	if !reflect.DeepEqual(out, expected) || err != nil {
		t.Errorf("expected inputs returned without __use field, got %v, missing __use for CoreAdapter", out)
	}
}

// TestCoreAdapter_ID tests the adapter ID
func TestCoreAdapter_ID(t *testing.T) {
	a := &CoreAdapter{}
	if a.ID() != "core" {
		t.Errorf("expected ID 'core', got %q", a.ID())
	}
}

// TestCoreAdapter_Manifest tests that Manifest returns nil
func TestCoreAdapter_Manifest(t *testing.T) {
	a := &CoreAdapter{}
	if a.Manifest() != nil {
		t.Errorf("expected Manifest to return nil, got %v", a.Manifest())
	}
}

// TestCoreAdapter_Execute_MissingUse tests error when __use is missing
func TestCoreAdapter_Execute_MissingUse(t *testing.T) {
	a := &CoreAdapter{}
	inputs := map[string]any{"text": "test"}

	_, err := a.Execute(context.Background(), inputs)
	if err == nil || !strings.Contains(err.Error(), "missing __use") {
		t.Errorf("expected missing __use error, got %v", err)
	}
}

// TestCoreAdapter_Execute_InvalidUse tests error when __use is not a string
func TestCoreAdapter_Execute_InvalidUse(t *testing.T) {
	a := &CoreAdapter{}
	inputs := map[string]any{"__use": 123}

	_, err := a.Execute(context.Background(), inputs)
	if err == nil || !strings.Contains(err.Error(), "missing __use") {
		t.Errorf("expected missing __use error, got %v", err)
	}
}

// TestCoreAdapter_Execute_UnknownTool tests error for unknown tool
func TestCoreAdapter_Execute_UnknownTool(t *testing.T) {
	a := &CoreAdapter{}
	inputs := map[string]any{"__use": "core.unknown"}

	_, err := a.Execute(context.Background(), inputs)
	if err == nil || !strings.Contains(err.Error(), "unknown core tool") {
		t.Errorf("expected unknown core tool error, got %v", err)
	}
}

// TestCoreAdapter_Echo_NoDebug tests echo without debug mode
func TestCoreAdapter_Echo_NoDebug(t *testing.T) {
	a := &CoreAdapter{}
	// Ensure debug mode is off
	os.Unsetenv("BEEMFLOW_DEBUG")

	inputs := map[string]any{"__use": "core.echo", "text": "test", "other": "value"}
	result, err := a.Execute(context.Background(), inputs)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	expected := map[string]any{"text": "test", "other": "value"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

// TestCoreAdapter_Echo_NoText tests echo without text field
func TestCoreAdapter_Echo_NoText(t *testing.T) {
	a := &CoreAdapter{}
	inputs := map[string]any{"__use": "core.echo", "other": "value"}

	result, err := a.Execute(context.Background(), inputs)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	expected := map[string]any{"other": "value"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

// TestCoreAdapter_Echo_NonStringText tests echo with non-string text field
func TestCoreAdapter_Echo_NonStringText(t *testing.T) {
	a := &CoreAdapter{}
	inputs := map[string]any{"__use": "core.echo", "text": 123, "other": "value"}

	result, err := a.Execute(context.Background(), inputs)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	expected := map[string]any{"text": 123, "other": "value"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

// TestCoreAdapter_Echo_EmptyInputs tests echo with only __use field
func TestCoreAdapter_Echo_EmptyInputs(t *testing.T) {
	a := &CoreAdapter{}
	inputs := map[string]any{"__use": "core.echo"}

	result, err := a.Execute(context.Background(), inputs)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	expected := map[string]any{}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

// ========== OpenAPI Conversion Tests ==========

// TestCoreAdapter_ConvertOpenAPI_JSONString tests OpenAPI conversion with JSON string
func TestCoreAdapter_ConvertOpenAPI_JSONString(t *testing.T) {
	a := &CoreAdapter{}

	openAPISpec := `{
		"openapi": "3.0.0",
		"info": {"title": "Test API", "version": "1.0.0"},
		"servers": [{"url": "https://api.test.com"}],
		"paths": {
			"/users": {
				"get": {"summary": "Get users"},
				"post": {"summary": "Create user"}
			}
		}
	}`

	inputs := map[string]any{
		"__use":    "core.convert_openapi",
		"openapi":  openAPISpec,
		"api_name": "test",
		"base_url": "https://custom.com",
	}

	result, err := a.Execute(context.Background(), inputs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify result structure
	if result["api_name"] != "test" {
		t.Errorf("expected api_name 'test', got %v", result["api_name"])
	}
	if result["base_url"] != "https://custom.com" {
		t.Errorf("expected base_url 'https://custom.com', got %v", result["base_url"])
	}
	if result["count"] != 2 {
		t.Errorf("expected count 2, got %v", result["count"])
	}

	manifests, ok := result["manifests"].([]map[string]any)
	if !ok {
		t.Fatalf("expected manifests to be []map[string]any, got %T", result["manifests"])
	}
	if len(manifests) != 2 {
		t.Errorf("expected 2 manifests, got %d", len(manifests))
	}
}

// TestCoreAdapter_ConvertOpenAPI_JSONObject tests OpenAPI conversion with JSON object
func TestCoreAdapter_ConvertOpenAPI_JSONObject(t *testing.T) {
	a := &CoreAdapter{}

	openAPISpec := map[string]any{
		"openapi": "3.0.0",
		"info":    map[string]any{"title": "Test API", "version": "1.0.0"},
		"paths": map[string]any{
			"/test": map[string]any{
				"get": map[string]any{"summary": "Test endpoint"},
			},
		},
	}

	inputs := map[string]any{
		"__use":   "core.convert_openapi",
		"openapi": openAPISpec,
	}

	result, err := a.Execute(context.Background(), inputs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should use default api_name
	if result["api_name"] != "api" {
		t.Errorf("expected default api_name 'api', got %v", result["api_name"])
	}
}

// TestCoreAdapter_ConvertOpenAPI_MissingOpenAPI tests error when openapi field is missing
func TestCoreAdapter_ConvertOpenAPI_MissingOpenAPI(t *testing.T) {
	a := &CoreAdapter{}
	inputs := map[string]any{
		"__use":    "core.convert_openapi",
		"api_name": "test",
	}

	_, err := a.Execute(context.Background(), inputs)
	if err == nil || !strings.Contains(err.Error(), "missing required field: openapi") {
		t.Errorf("expected missing openapi error, got %v", err)
	}
}

// TestCoreAdapter_ConvertOpenAPI_InvalidJSON tests error with invalid JSON
func TestCoreAdapter_ConvertOpenAPI_InvalidJSON(t *testing.T) {
	a := &CoreAdapter{}
	inputs := map[string]any{
		"__use":   "core.convert_openapi",
		"openapi": "invalid json{",
	}

	_, err := a.Execute(context.Background(), inputs)
	if err == nil || !strings.Contains(err.Error(), "invalid OpenAPI JSON") {
		t.Errorf("expected invalid JSON error, got %v", err)
	}
}

// TestCoreAdapter_ConvertOpenAPI_NoPaths tests error when no paths in spec
func TestCoreAdapter_ConvertOpenAPI_NoPaths(t *testing.T) {
	a := &CoreAdapter{}
	inputs := map[string]any{
		"__use":   "core.convert_openapi",
		"openapi": `{"openapi": "3.0.0", "info": {"title": "Test"}}`,
	}

	_, err := a.Execute(context.Background(), inputs)
	if err == nil || !strings.Contains(err.Error(), "no paths found") {
		t.Errorf("expected no paths error, got %v", err)
	}
}

// TestCoreAdapter_ConvertOpenAPI_ComplexSpec tests conversion with complex OpenAPI spec
func TestCoreAdapter_ConvertOpenAPI_ComplexSpec(t *testing.T) {
	a := &CoreAdapter{}

	complexSpec := `{
		"openapi": "3.0.0",
		"info": {"title": "Complex API", "version": "1.0.0"},
		"paths": {
			"/users/{id}": {
				"get": {
					"summary": "Get user by ID",
					"parameters": [
						{
							"name": "id",
							"in": "path",
							"required": true,
							"schema": {"type": "string"},
							"description": "User ID"
						},
						{
							"name": "include",
							"in": "query",
							"schema": {"type": "array", "items": {"type": "string"}},
							"description": "Fields to include"
						}
					]
				},
				"put": {
					"summary": "Update user",
					"requestBody": {
						"content": {
							"application/x-www-form-urlencoded": {
								"schema": {
									"type": "object",
									"properties": {
										"name": {"type": "string"},
										"email": {"type": "string", "format": "email"}
									}
								}
							}
						}
					}
				}
			},
			"/complex-path/with-dashes": {
				"post": {
					"description": "Complex endpoint with dashes"
				}
			}
		}
	}`

	inputs := map[string]any{
		"__use":    "core.convert_openapi",
		"openapi":  complexSpec,
		"api_name": "complex",
	}

	result, err := a.Execute(context.Background(), inputs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	manifests, ok := result["manifests"].([]map[string]any)
	if !ok {
		t.Fatalf("expected manifests to be []map[string]any, got %T", result["manifests"])
	}

	// Should have 3 manifests: GET /users/{id}, PUT /users/{id}, POST /complex-path/with-dashes
	if len(manifests) != 3 {
		t.Errorf("expected 3 manifests, got %d", len(manifests))
	}

	// Check tool name generation for path parameters
	foundUsersByIDGet := false
	foundUsersByIDPut := false
	foundComplexPath := false
	for _, manifest := range manifests {
		name, _ := manifest["name"].(string)
		if name == "complex.users_by_id_get" {
			foundUsersByIDGet = true
		}
		if name == "complex.users_by_id_put" {
			foundUsersByIDPut = true
		}
		if name == "complex.complex_path_with_dashes_post" {
			foundComplexPath = true
		}
	}

	if !foundUsersByIDGet {
		t.Error("expected to find manifest with name 'complex.users_by_id_get'")
	}
	if !foundUsersByIDPut {
		t.Error("expected to find manifest with name 'complex.users_by_id_put'")
	}
	if !foundComplexPath {
		t.Error("expected to find manifest with name 'complex.complex_path_with_dashes_post'")
	}
}

// TestCoreAdapter_ConvertOpenAPI_DefaultBaseURL tests base URL extraction from servers
func TestCoreAdapter_ConvertOpenAPI_DefaultBaseURL(t *testing.T) {
	a := &CoreAdapter{}

	spec := `{
		"openapi": "3.0.0",
		"info": {"title": "Test API", "version": "1.0.0"},
		"servers": [{"url": "https://extracted.com"}],
		"paths": {"/test": {"get": {"summary": "Test"}}}
	}`

	inputs := map[string]any{
		"__use":   "core.convert_openapi",
		"openapi": spec,
	}

	result, err := a.Execute(context.Background(), inputs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result["base_url"] != "https://extracted.com" {
		t.Errorf("expected base_url 'https://extracted.com', got %v", result["base_url"])
	}
}

// TestCoreAdapter_ConvertOpenAPI_NoServers tests fallback base URL
func TestCoreAdapter_ConvertOpenAPI_NoServers(t *testing.T) {
	a := &CoreAdapter{}

	spec := `{
		"openapi": "3.0.0",
		"info": {"title": "Test API", "version": "1.0.0"},
		"paths": {"/test": {"get": {"summary": "Test"}}}
	}`

	inputs := map[string]any{
		"__use":   "core.convert_openapi",
		"openapi": spec,
	}

	result, err := a.Execute(context.Background(), inputs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result["base_url"] != "https://api.example.com" {
		t.Errorf("expected fallback base_url 'https://api.example.com', got %v", result["base_url"])
	}
}

// TestCoreAdapter_ConvertOpenAPI_EdgeCases tests various edge cases
func TestCoreAdapter_ConvertOpenAPI_EdgeCases(t *testing.T) {
	a := &CoreAdapter{}

	// Test with invalid HTTP methods (should be ignored)
	spec := `{
		"openapi": "3.0.0",
		"info": {"title": "Test API", "version": "1.0.0"},
		"paths": {
			"/test": {
				"get": {"summary": "Valid method"},
				"invalid": {"summary": "Invalid method"},
				"options": {"summary": "Invalid method"}
			}
		}
	}`

	inputs := map[string]any{
		"__use":   "core.convert_openapi",
		"openapi": spec,
	}

	result, err := a.Execute(context.Background(), inputs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	manifests, ok := result["manifests"].([]map[string]any)
	if !ok {
		t.Fatalf("expected manifests to be []map[string]any, got %T", result["manifests"])
	}

	// Should only have 1 manifest (GET), invalid methods ignored
	if len(manifests) != 1 {
		t.Errorf("expected 1 manifest, got %d", len(manifests))
	}
}

// TestCoreAdapter_ConvertOpenAPI_MalformedPaths tests handling of malformed path items
func TestCoreAdapter_ConvertOpenAPI_MalformedPaths(t *testing.T) {
	a := &CoreAdapter{}

	// Test with malformed path items and operations
	spec := `{
		"openapi": "3.0.0",
		"info": {"title": "Test API", "version": "1.0.0"},
		"paths": {
			"/valid": {
				"get": {"summary": "Valid endpoint"}
			},
			"/invalid-path": "not an object",
			"/invalid-operation": {
				"get": "not an object",
				"post": {"summary": "Valid operation"}
			}
		}
	}`

	inputs := map[string]any{
		"__use":   "core.convert_openapi",
		"openapi": spec,
	}

	result, err := a.Execute(context.Background(), inputs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	manifests, ok := result["manifests"].([]map[string]any)
	if !ok {
		t.Fatalf("expected manifests to be []map[string]any, got %T", result["manifests"])
	}

	// Should only have 2 valid manifests (GET /valid and POST /invalid-operation)
	// The malformed path and operation should be skipped
	if len(manifests) != 2 {
		t.Errorf("expected 2 manifests (skipping malformed), got %d", len(manifests))
	}
}

// TestCoreAdapter_ConvertOpenAPI_HelperFunctions tests the individual helper functions
func TestCoreAdapter_ConvertOpenAPI_HelperFunctions(t *testing.T) {
	a := &CoreAdapter{}

	// Test isValidHTTPMethod
	tests := []struct {
		method string
		valid  bool
	}{
		{"get", true},
		{"post", true},
		{"put", true},
		{"patch", true},
		{"delete", true},
		{"GET", true}, // case insensitive
		{"options", false},
		{"head", false},
		{"invalid", false},
	}

	for _, test := range tests {
		result := a.isValidHTTPMethod(test.method)
		if result != test.valid {
			t.Errorf("isValidHTTPMethod(%q) = %v, expected %v", test.method, result, test.valid)
		}
	}

	// Test generateToolName
	nameTests := []struct {
		apiName  string
		path     string
		method   string
		expected string
	}{
		{"api", "/users", "get", "api.users_get"},
		{"api", "/users/{id}", "get", "api.users_by_id_get"},
		{"api", "/v1/orders/{orderId}/items", "post", "api.v1_orders_by_id_items_post"},
		{"api", "/complex-path/with-dashes", "get", "api.complex_path_with_dashes_get"},
		{"test", "/{id}/sub/{subId}", "get", "test.by_id_sub_by_id_get"},
	}

	for _, test := range nameTests {
		result := a.generateToolName(test.apiName, test.path, test.method)
		if result != test.expected {
			t.Errorf("generateToolName(%q, %q, %q) = %q, expected %q",
				test.apiName, test.path, test.method, result, test.expected)
		}
	}

	// Test extractDescription
	operation1 := map[string]any{"summary": "Test summary"}
	if desc := a.extractDescription(operation1, "/test"); desc != "Test summary" {
		t.Errorf("expected 'Test summary', got %q", desc)
	}

	operation2 := map[string]any{"description": "Test description"}
	if desc := a.extractDescription(operation2, "/test"); desc != "Test description" {
		t.Errorf("expected 'Test description', got %q", desc)
	}

	operation3 := map[string]any{}
	if desc := a.extractDescription(operation3, "/test"); desc != "API endpoint: /test" {
		t.Errorf("expected 'API endpoint: /test', got %q", desc)
	}

	// Test determineContentType
	getOp := map[string]any{}
	if ct := a.determineContentType(getOp, "GET"); ct != constants.ContentTypeJSON {
		t.Errorf("expected '%s' for GET, got %q", constants.ContentTypeJSON, ct)
	}

	formOp := map[string]any{
		"requestBody": map[string]any{
			"content": map[string]any{
				constants.ContentTypeForm: map[string]any{},
			},
		},
	}
	if ct := a.determineContentType(formOp, "POST"); ct != constants.ContentTypeForm {
		t.Errorf("expected '%s', got %q", constants.ContentTypeForm, ct)
	}
}

// TestCoreAdapter_ExtractParameters_Comprehensive tests parameter extraction edge cases
func TestCoreAdapter_ExtractParameters_Comprehensive(t *testing.T) {
	a := &CoreAdapter{}

	// Test POST with JSON requestBody
	postOpJSON := map[string]any{
		"requestBody": map[string]any{
			"content": map[string]any{
				constants.ContentTypeJSON: map[string]any{
					"schema": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"name": map[string]any{"type": "string"},
							"age":  map[string]any{"type": "integer"},
						},
						"required": []any{"name"},
					},
				},
			},
		},
	}

	params := a.extractParameters(postOpJSON, "POST")
	if params["type"] != "object" {
		t.Errorf("expected type 'object', got %v", params["type"])
	}

	// Test GET with query parameters
	getOpParams := map[string]any{
		"parameters": []any{
			map[string]any{
				"name":        "limit",
				"in":          "query",
				"required":    true,
				"description": "Max results",
				"schema":      map[string]any{"type": "integer"},
			},
			map[string]any{
				"name":   "filter",
				"in":     "query",
				"schema": map[string]any{"type": "string", "enum": []any{"active", "inactive"}},
			},
		},
	}

	params = a.extractParameters(getOpParams, "GET")
	properties, ok := params["properties"].(map[string]any)
	if !ok {
		t.Fatalf("expected properties to be map, got %T", params["properties"])
	}

	if len(properties) != 2 {
		t.Errorf("expected 2 properties, got %d", len(properties))
	}

	required, ok := params["required"].([]string)
	if !ok {
		t.Fatalf("expected required to be []string, got %T", params["required"])
	}

	if len(required) != 1 || required[0] != "limit" {
		t.Errorf("expected required=['limit'], got %v", required)
	}

	// Test operation with no parameters or requestBody
	emptyOp := map[string]any{}
	params = a.extractParameters(emptyOp, "GET")
	if params["type"] != "object" {
		t.Errorf("expected default type 'object', got %v", params["type"])
	}

	// Test malformed parameters (should be ignored)
	malformedOp := map[string]any{
		"parameters": []any{
			"invalid parameter", // not a map
			map[string]any{},    // missing name
		},
	}
	params = a.extractParameters(malformedOp, "GET")
	properties, ok = params["properties"].(map[string]any)
	if !ok || len(properties) != 0 {
		t.Errorf("expected empty properties for malformed parameters, got %v", properties)
	}
}

// ========== N8N Conversion Tests ==========

// TestCoreAdapter_ConvertN8N_JSONString tests n8n conversion with JSON string
func TestCoreAdapter_ConvertN8N_JSONString(t *testing.T) {
	a := &CoreAdapter{}

	simpleN8N := `{
		"name": "Simple HTTP Workflow",
		"nodes": [
			{
				"id": "http_request_1",
				"type": "n8n-nodes-base.httpRequest",
				"parameters": {
					"method": "GET",
					"url": "https://api.example.com/data"
				}
			},
			{
				"id": "openai_1",
				"type": "n8n-nodes-base.openAi",
				"parameters": {
					"model": "gpt-4o",
					"prompt": "Summarize this data: {{ $json.body }}"
				}
			}
		],
		"connections": {
			"http_request_1": {
				"main": [
					[{"node": "openai_1", "type": "main", "index": 0}]
				]
			}
		}
	}`

	inputs := map[string]any{
		"__use":     "core.convert_n8n",
		"n8n":       simpleN8N,
		"flow_name": "test_workflow",
	}

	result, err := a.Execute(context.Background(), inputs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	flow, ok := result["flow"].(map[string]any)
	if !ok {
		t.Fatalf("expected flow to be map[string]any, got %T", result["flow"])
	}

	// Check flow structure
	if flow["name"] != "test_workflow" {
		t.Errorf("expected flow name 'test_workflow', got %v", flow["name"])
	}

	if flow["on"] != "cli.manual" {
		t.Errorf("expected trigger 'cli.manual', got %v", flow["on"])
	}

	steps, ok := flow["steps"].([]map[string]any)
	if !ok {
		t.Fatalf("expected steps to be []map[string]any, got %T", flow["steps"])
	}

	if len(steps) != 2 {
		t.Errorf("expected 2 steps, got %d", len(steps))
	}

	// Check HTTP step
	httpStep := steps[0]
	if httpStep["id"] != "http_request_1" {
		t.Errorf("expected step ID 'http_request_1', got %v", httpStep["id"])
	}
	if httpStep["use"] != "http" {
		t.Errorf("expected use 'http', got %v", httpStep["use"])
	}

	// Check OpenAI step
	openaiStep := steps[1]
	if openaiStep["id"] != "openai_1" {
		t.Errorf("expected step ID 'openai_1', got %v", openaiStep["id"])
	}
	if openaiStep["use"] != "openai.chat_completion" {
		t.Errorf("expected use 'openai.chat_completion', got %v", openaiStep["use"])
	}
}

// TestCoreAdapter_ConvertN8N_JSONObject tests n8n conversion with JSON object
func TestCoreAdapter_ConvertN8N_JSONObject(t *testing.T) {
	a := &CoreAdapter{}

	simpleN8N := map[string]any{
		"name": "Simple Workflow",
		"nodes": []any{
			map[string]any{
				"id": "wait_1",
				"type": "n8n-nodes-base.wait",
				"parameters": map[string]any{
					"waitType": "seconds",
					"seconds":  5.0,
				},
			},
		},
	}

	inputs := map[string]any{
		"__use": "core.convert_n8n",
		"n8n":   simpleN8N,
	}

	result, err := a.Execute(context.Background(), inputs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	flow, ok := result["flow"].(map[string]any)
	if !ok {
		t.Fatalf("expected flow to be map[string]any, got %T", result["flow"])
	}

	steps, ok := flow["steps"].([]map[string]any)
	if !ok {
		t.Fatalf("expected steps to be []map[string]any, got %T", flow["steps"])
	}

	if len(steps) != 1 {
		t.Errorf("expected 1 step, got %d", len(steps))
	}

	// Check wait step
	waitStep := steps[0]
	if waitStep["id"] != "wait_1" {
		t.Errorf("expected step ID 'wait_1', got %v", waitStep["id"])
	}

	wait, ok := waitStep["wait"].(map[string]any)
	if !ok {
		t.Fatalf("expected wait to be map[string]any, got %T", waitStep["wait"])
	}

	if wait["seconds"] != 5 {
		t.Errorf("expected wait seconds 5, got %v", wait["seconds"])
	}
}

// TestCoreAdapter_ConvertN8N_MissingN8N tests error when n8n field is missing
func TestCoreAdapter_ConvertN8N_MissingN8N(t *testing.T) {
	a := &CoreAdapter{}

	inputs := map[string]any{
		"__use": "core.convert_n8n",
		// Missing n8n field
	}

	_, err := a.Execute(context.Background(), inputs)
	if err == nil {
		t.Fatal("expected error for missing n8n field")
	}

	if !strings.Contains(err.Error(), "missing required field: n8n") {
		t.Errorf("expected error about missing n8n field, got: %v", err)
	}
}

// TestCoreAdapter_ConvertN8N_InvalidJSON tests error with invalid JSON
func TestCoreAdapter_ConvertN8N_InvalidJSON(t *testing.T) {
	a := &CoreAdapter{}

	inputs := map[string]any{
		"__use": "core.convert_n8n",
		"n8n":   "invalid json {",
	}

	_, err := a.Execute(context.Background(), inputs)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}

	if !strings.Contains(err.Error(), "invalid n8n JSON") {
		t.Errorf("expected error about invalid JSON, got: %v", err)
	}
}

// TestCoreAdapter_ConvertN8N_NoNodes tests error when no nodes in workflow
func TestCoreAdapter_ConvertN8N_NoNodes(t *testing.T) {
	a := &CoreAdapter{}

	invalidN8N := `{
		"name": "Invalid Workflow",
		"connections": {}
	}`

	inputs := map[string]any{
		"__use": "core.convert_n8n",
		"n8n":   invalidN8N,
	}

	_, err := a.Execute(context.Background(), inputs)
	if err == nil {
		t.Fatal("expected error for missing nodes")
	}

	if !strings.Contains(err.Error(), "no nodes found in n8n workflow") {
		t.Errorf("expected error about missing nodes, got: %v", err)
	}
}

// TestCoreAdapter_ConvertN8N_ComplexWorkflow tests conversion with complex n8n workflow
func TestCoreAdapter_ConvertN8N_ComplexWorkflow(t *testing.T) {
	a := &CoreAdapter{}

	complexN8N := `{
		"name": "Complex Workflow",
		"nodes": [
			{
				"id": "http_get",
				"type": "n8n-nodes-base.httpRequest",
				"parameters": {
					"method": "GET",
					"url": "https://api.example.com/users",
					"headers": {
						"Authorization": "Bearer {{ $env.API_KEY }}"
					}
				}
			},
			{
				"id": "if_check",
				"type": "n8n-nodes-base.if",
				"parameters": {
					"conditions": {
						"conditions": [
							{
								"leftValue": "{{ $json.length }}",
								"operator": ">",
								"rightValue": "0"
							}
						]
					}
				}
			},
			{
				"id": "set_vars",
				"type": "n8n-nodes-base.set",
				"parameters": {
					"values": {
						"user_count": "{{ $json.length }}",
						"timestamp": "{{ $now }}"
					}
				}
			},
			{
				"id": "code_node",
				"type": "n8n-nodes-base.code",
				"parameters": {
					"code": "return { json: { processed: true, data: $input.all()[0].json } };"
				}
			}
		],
		"connections": {
			"http_get": {
				"main": [
					[{"node": "if_check", "type": "main", "index": 0}]
				]
			},
			"if_check": {
				"main": [
					[{"node": "set_vars", "type": "main", "index": 0}]
				]
			},
			"set_vars": {
				"main": [
					[{"node": "code_node", "type": "main", "index": 0}]
				]
			}
		},
		"settings": {
			"variables": {
				"API_BASE_URL": "https://api.example.com",
				"DEFAULT_TIMEOUT": "30"
			}
		}
	}`

	inputs := map[string]any{
		"__use":     "core.convert_n8n",
		"n8n":       complexN8N,
		"flow_name": "complex_workflow",
	}

	result, err := a.Execute(context.Background(), inputs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	flow, ok := result["flow"].(map[string]any)
	if !ok {
		t.Fatalf("expected flow to be map[string]any, got %T", result["flow"])
	}

	// Check flow structure
	if flow["name"] != "complex_workflow" {
		t.Errorf("expected flow name 'complex_workflow', got %v", flow["name"])
	}

	// Check variables
	vars, ok := flow["vars"].(map[string]any)
	if !ok {
		t.Fatalf("expected vars to be map[string]any, got %T", flow["vars"])
	}

	if vars["API_BASE_URL"] != "https://api.example.com" {
		t.Errorf("expected API_BASE_URL variable, got %v", vars["API_BASE_URL"])
	}

	steps, ok := flow["steps"].([]map[string]any)
	if !ok {
		t.Fatalf("expected steps to be []map[string]any, got %T", flow["steps"])
	}

	if len(steps) != 4 {
		t.Errorf("expected 4 steps, got %d", len(steps))
	}

	// Check HTTP step
	httpStep := steps[0]
	if httpStep["id"] != "http_get" {
		t.Errorf("expected step ID 'http_get', got %v", httpStep["id"])
	}
	if httpStep["use"] != "http" {
		t.Errorf("expected use 'http', got %v", httpStep["use"])
	}

	// Check IF step
	ifStep := steps[1]
	if ifStep["id"] != "if_check" {
		t.Errorf("expected step ID 'if_check', got %v", ifStep["id"])
	}
	if ifStep["if"] == "" {
		t.Error("expected if condition to be set")
	}

	// Check SET step
	setStep := steps[2]
	if setStep["id"] != "set_vars" {
		t.Errorf("expected step ID 'set_vars', got %v", setStep["id"])
	}
	if setStep["use"] != "core.echo" {
		t.Errorf("expected use 'core.echo', got %v", setStep["use"])
	}

	// Check CODE step
	codeStep := steps[3]
	if codeStep["id"] != "code_node" {
		t.Errorf("expected step ID 'code_node', got %v", codeStep["id"])
	}
	if codeStep["use"] != "core.echo" {
		t.Errorf("expected use 'core.echo', got %v", codeStep["use"])
	}
}

// TestCoreAdapter_ConvertN8N_HelperFunctions tests the individual helper functions
func TestCoreAdapter_ConvertN8N_HelperFunctions(t *testing.T) {
	a := &CoreAdapter{}

	// Test convertHTTPRequestNode
	t.Run("convertHTTPRequestNode", func(t *testing.T) {
		step := map[string]any{"id": "test"}
		parameters := map[string]any{
			"method":  "POST",
			"url":     "https://api.example.com",
			"headers": map[string]any{"Content-Type": "application/json"},
			"body":    "{\"test\": true}",
		}

		result, err := a.convertHTTPRequestNode(step, parameters)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result["use"] != "http" {
			t.Errorf("expected use 'http', got %v", result["use"])
		}

		with, ok := result["with"].(map[string]any)
		if !ok {
			t.Fatalf("expected with to be map[string]any, got %T", result["with"])
		}

		if with["url"] != "https://api.example.com" {
			t.Errorf("expected url 'https://api.example.com', got %v", with["url"])
		}

		if with["method"] != "POST" {
			t.Errorf("expected method 'POST', got %v", with["method"])
		}
	})

	// Test convertOpenAINode
	t.Run("convertOpenAINode", func(t *testing.T) {
		step := map[string]any{"id": "test"}
		parameters := map[string]any{
			"model":  "gpt-4o",
			"prompt": "Test prompt",
		}

		result, err := a.convertOpenAINode(step, parameters)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result["use"] != "openai.chat_completion" {
			t.Errorf("expected use 'openai.chat_completion', got %v", result["use"])
		}

		with, ok := result["with"].(map[string]any)
		if !ok {
			t.Fatalf("expected with to be map[string]any, got %T", result["with"])
		}

		if with["model"] != "gpt-4o" {
			t.Errorf("expected model 'gpt-4o', got %v", with["model"])
		}
	})

	// Test convertWaitNode
	t.Run("convertWaitNode", func(t *testing.T) {
		step := map[string]any{"id": "test"}
		parameters := map[string]any{
			"waitType": "seconds",
			"seconds":  10.0,
		}

		result, err := a.convertWaitNode(step, parameters)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		wait, ok := result["wait"].(map[string]any)
		if !ok {
			t.Fatalf("expected wait to be map[string]any, got %T", result["wait"])
		}

		if wait["seconds"] != 10 {
			t.Errorf("expected seconds 10, got %v", wait["seconds"])
		}
	})

	// Test buildConditionExpression
	t.Run("buildConditionExpression", func(t *testing.T) {
		condition := map[string]any{
			"conditions": []any{
				map[string]any{
					"leftValue": "count",
					"operator":  ">",
					"rightValue": "0",
				},
			},
		}

		result := a.buildConditionExpression(condition)
		expected := "{{ count > 0 }}"
		if result != expected {
			t.Errorf("expected condition '%s', got '%s'", expected, result)
		}
	})

	// Test extractN8NVariables
	t.Run("extractN8NVariables", func(t *testing.T) {
		workflow := map[string]any{
			"settings": map[string]any{
				"variables": map[string]any{
					"API_KEY": "secret123",
					"BASE_URL": "https://api.example.com",
				},
			},
		}

		result := a.extractN8NVariables(workflow)
		if len(result) != 2 {
			t.Errorf("expected 2 variables, got %d", len(result))
		}

		if result["API_KEY"] != "secret123" {
			t.Errorf("expected API_KEY 'secret123', got %v", result["API_KEY"])
		}
	})
}

// TestCoreAdapter_ConvertN8N_EdgeCases tests various edge cases
func TestCoreAdapter_ConvertN8N_EdgeCases(t *testing.T) {
	a := &CoreAdapter{}

	t.Run("missing node id", func(t *testing.T) {
		nodes := []any{
			map[string]any{
				"type": "n8n-nodes-base.httpRequest",
				// Missing id
			},
		}

		_, err := a.convertN8NNodesToSteps(nodes, nil)
		if err == nil {
			t.Fatal("expected error for missing node id")
		}
	})

	t.Run("missing URL in HTTP request", func(t *testing.T) {
		step := map[string]any{"id": "test"}
		parameters := map[string]any{
			"method": "GET",
			// Missing url
		}

		_, err := a.convertHTTPRequestNode(step, parameters)
		if err == nil {
			t.Fatal("expected error for missing URL")
		}
	})

	t.Run("missing prompt in OpenAI", func(t *testing.T) {
		step := map[string]any{"id": "test"}
		parameters := map[string]any{
			"model": "gpt-4o",
			// Missing prompt
		}

		_, err := a.convertOpenAINode(step, parameters)
		if err == nil {
			t.Fatal("expected error for missing prompt")
		}
	})

	t.Run("missing conditions in IF", func(t *testing.T) {
		step := map[string]any{"id": "test"}
		parameters := map[string]any{
			// Missing conditions
		}

		_, err := a.convertIfNode(step, parameters, nil, nil)
		if err == nil {
			t.Fatal("expected error for missing conditions")
		}
	})

	t.Run("missing values in SET", func(t *testing.T) {
		step := map[string]any{"id": "test"}
		parameters := map[string]any{
			// Missing values
		}

		_, err := a.convertSetNode(step, parameters)
		if err == nil {
			t.Fatal("expected error for missing values")
		}
	})

	t.Run("missing code in CODE", func(t *testing.T) {
		step := map[string]any{"id": "test"}
		parameters := map[string]any{
			// Missing code
		}

		_, err := a.convertCodeNode(step, parameters)
		if err == nil {
			t.Fatal("expected error for missing code")
		}
	})
}
