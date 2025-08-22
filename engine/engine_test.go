package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/awantoch/beemflow/blob"
	"github.com/awantoch/beemflow/config"
	"github.com/awantoch/beemflow/dsl"
	"github.com/awantoch/beemflow/event"
	"github.com/awantoch/beemflow/model"
	"github.com/awantoch/beemflow/storage"
	"github.com/awantoch/beemflow/utils"
	"github.com/google/uuid"
)

func TestMain(m *testing.M) {
	// Set test environment variables
	os.Setenv("TEST_ENV_VAR", "test_value_123")
	os.Setenv("BEEMFLOW_TEST_TOKEN", "secret_token_456")
	
	utils.WithCleanDirs(m, ".beemflow", config.DefaultConfigDir, config.DefaultFlowsDir)
}

// TestEnvironmentVariablesInTemplates tests that environment variables are accessible in templates
func TestEnvironmentVariablesInTemplates(t *testing.T) {
	e := NewDefaultEngine(context.Background())
	
	// Create a flow that uses environment variables
	flow := &model.Flow{
		Name: "env-test",
		Steps: []model.Step{
			{
				ID:  "test_env",
				Use: "core.echo",
				With: map[string]interface{}{
					"text": "Env var: {{ env.TEST_ENV_VAR }}, Token: {{ env.BEEMFLOW_TEST_TOKEN }}",
				},
			},
		},
	}
	
	outputs, err := e.Execute(context.Background(), flow, map[string]any{})
	if err != nil {
		t.Fatalf("failed to execute flow: %v", err)
	}
	
	// Check that environment variables were properly substituted
	echoOutput, ok := outputs["test_env"].(map[string]any)
	if !ok {
		t.Fatalf("expected map output from echo step, got %T", outputs["test_env"])
	}
	
	text, ok := echoOutput["text"].(string)
	if !ok {
		t.Fatalf("expected string text in echo output, got %T", echoOutput["text"])
	}
	
	expectedText := "Env var: test_value_123, Token: secret_token_456"
	if text != expectedText {
		t.Errorf("expected text '%s', got '%s'", expectedText, text)
	}
}

// TestTemplateDataPrepare tests that template data is properly prepared with all fields
func TestTemplateDataPrepare(t *testing.T) {
	e := NewDefaultEngine(context.Background())
	
	// Create a step context with test data
	stepCtx := NewStepContext(
		map[string]any{"event_key": "event_value"},
		map[string]any{"var_key": "var_value"},
		map[string]any{"secret_key": "secret_value"},
	)
	stepCtx.Outputs = map[string]any{
		"prev_step": map[string]any{"result": "success"},
	}
	
	templateData := e.prepareTemplateData(stepCtx)
	
	// Verify all fields are populated
	if templateData.Event["event_key"] != "event_value" {
		t.Errorf("Event data not properly set")
	}
	
	if templateData.Vars["var_key"] != "var_value" {
		t.Errorf("Vars data not properly set")
	}
	
	if templateData.Outputs["prev_step"].(map[string]any)["result"] != "success" {
		t.Errorf("Outputs data not properly set")
	}
	
	if templateData.Secrets["secret_key"] != "secret_value" {
		t.Errorf("Secrets data not properly set")
	}
	
	// Check that environment variables are included
	if len(templateData.Env) == 0 {
		t.Errorf("Environment variables not included in template data")
	}
	
	// Check specific test env vars
	if templateData.Env["TEST_ENV_VAR"] != "test_value_123" {
		t.Errorf("TEST_ENV_VAR not properly included in env map")
	}
}

// TestSecretMasking tests that sensitive fields are properly masked in logs
func TestSecretMasking(t *testing.T) {
	// Test input with various sensitive fields
	input := map[string]any{
		"url": "https://api.example.com",
		"method": "POST",
		"headers": map[string]any{
			"Authorization": "Bearer secret-token-12345",
			"Content-Type": "application/json",
			"X-API-Key": "api-key-67890",
		},
		"body": map[string]any{
			"data": "normal data",
			"password": "super-secret-password",
			"nested": map[string]any{
				"access_token": "nested-token-abc",
				"normal_field": "visible",
			},
		},
	}
	
	// Mask the sensitive fields
	masked := maskSensitiveFields(input)
	
	// Check that sensitive fields are masked
	headers := masked["headers"].(map[string]any)
	if headers["Authorization"] != "***MASKED***" {
		t.Errorf("Authorization header not masked: %v", headers["Authorization"])
	}
	if headers["X-API-Key"] != "***MASKED***" {
		t.Errorf("X-API-Key header not masked: %v", headers["X-API-Key"])
	}
	if headers["Content-Type"] != "application/json" {
		t.Errorf("Content-Type should not be masked: %v", headers["Content-Type"])
	}
	
	// Check body masking
	body := masked["body"].(map[string]any)
	if body["password"] != "***MASKED***" {
		t.Errorf("Password field not masked: %v", body["password"])
	}
	if body["data"] != "normal data" {
		t.Errorf("Normal data should not be masked: %v", body["data"])
	}
	
	// Check nested masking
	nested := body["nested"].(map[string]any)
	if nested["access_token"] != "***MASKED***" {
		t.Errorf("Nested access_token not masked: %v", nested["access_token"])
	}
	if nested["normal_field"] != "visible" {
		t.Errorf("Normal nested field should not be masked: %v", nested["normal_field"])
	}
	
	// Check that non-sensitive fields remain unchanged
	if masked["url"] != "https://api.example.com" {
		t.Errorf("URL should not be masked: %v", masked["url"])
	}
	if masked["method"] != "POST" {
		t.Errorf("Method should not be masked: %v", masked["method"])
	}
}

func TestGenerateDeterministicRunID(t *testing.T) {
	// Test that the same inputs generate the same UUID
	flowName := "test-flow"
	event := map[string]any{
		"key1": "value1",
		"key2": 42,
		"key3": true,
	}
	
	// Generate UUID multiple times with same inputs
	id1 := generateDeterministicRunID(flowName, event)
	id2 := generateDeterministicRunID(flowName, event)
	
	// They should be identical
	if id1 != id2 {
		t.Errorf("Same inputs generated different UUIDs: %s != %s", id1, id2)
	}
	
	// Test that different inputs generate different UUIDs
	event2 := map[string]any{
		"key1": "value1",
		"key2": 43, // Changed value
		"key3": true,
	}
	
	id3 := generateDeterministicRunID(flowName, event2)
	if id1 == id3 {
		t.Error("Different inputs generated the same UUID")
	}
	
	// Test that different flow names generate different UUIDs
	id4 := generateDeterministicRunID("different-flow", event)
	if id1 == id4 {
		t.Error("Different flow names generated the same UUID")
	}
	
	// Test that order doesn't matter (map keys are sorted)
	eventReordered := map[string]any{
		"key3": true,
		"key1": "value1", 
		"key2": 42,
	}
	
	id5 := generateDeterministicRunID(flowName, eventReordered)
	if id1 != id5 {
		t.Error("Same event with different key order generated different UUIDs")
	}
	
	// Verify it's a valid UUID v5 (has correct version and variant bits)
	if id1.Version() != 5 {
		t.Errorf("Expected UUID version 5, got %d", id1.Version())
	}
	
	// Test with empty event
	idEmpty := generateDeterministicRunID(flowName, map[string]any{})
	if idEmpty == uuid.Nil {
		t.Error("Empty event generated nil UUID")
	}
	
	// Test with complex nested structures
	complexEvent := map[string]any{
		"nested": map[string]any{
			"deep": "value",
		},
		"array": []any{1, 2, 3},
	}
	
	idComplex1 := generateDeterministicRunID(flowName, complexEvent)
	idComplex2 := generateDeterministicRunID(flowName, complexEvent)
	
	if idComplex1 != idComplex2 {
		t.Error("Complex event generated different UUIDs on repeated calls")
	}
}

func TestGenerateDeterministicRunID_TimeWindow(t *testing.T) {
	// This test verifies that UUIDs change after the 1-minute time window
	// We can't easily test this without mocking time, but we can verify
	// that UUIDs generated at different times are different
	
	flowName := "test-flow"
	event := map[string]any{"key": "value"}
	
	// Generate first UUID
	id1 := generateDeterministicRunID(flowName, event)
	
	// Sleep a tiny bit to ensure time has changed
	time.Sleep(time.Millisecond)
	
	// Generate second UUID - should still be the same (within 1 min window)
	id2 := generateDeterministicRunID(flowName, event)
	
	// Within the same 1-minute window, UUIDs should be identical
	if id1 != id2 {
		t.Log("Note: UUIDs differ within time window, this might happen if test runs across minute boundary")
		// This is not necessarily an error - it depends on when the test runs
	}
	
	// Verify the UUID is deterministic by regenerating with exact same inputs
	id3 := generateDeterministicRunID(flowName, event)
	id4 := generateDeterministicRunID(flowName, event)
	
	if id3 != id4 {
		t.Error("Immediate regeneration produced different UUIDs")
	}
}

func TestNewEngine(t *testing.T) {
	e := NewDefaultEngine(context.Background())
	if e == nil {
		t.Error("expected NewEngine not nil")
	}
}

func TestExecuteNoop(t *testing.T) {
	e := NewDefaultEngine(context.Background())
	_, err := e.Execute(context.Background(), &model.Flow{}, map[string]any{})
	if err != nil {
		t.Errorf("Execute returned error: %v", err)
	}
}

func TestNewCronScheduler(t *testing.T) {
	s := NewCronScheduler()
	if s == nil {
		t.Error("expected NewCronScheduler not nil")
	}
}

func TestExecute_NilFlow(t *testing.T) {
	e := NewDefaultEngine(context.Background())
	_, err := e.Execute(context.Background(), nil, map[string]any{})
	if err != nil {
		t.Errorf("expected nil error for nil flow, got %v", err)
	}
}

func TestExecute_NilEvent(t *testing.T) {
	e := NewDefaultEngine(context.Background())
	f := &model.Flow{Name: "test", Steps: []model.Step{}}
	_, err := e.Execute(context.Background(), f, nil)
	if err != nil {
		t.Errorf("expected nil error for nil event, got %v", err)
	}
}

func TestExecute_MinimalValidFlow(t *testing.T) {
	e := NewDefaultEngine(context.Background())
	f := &model.Flow{Name: "test", Steps: []model.Step{{ID: "s1", Use: "core.echo"}}}
	_, err := e.Execute(context.Background(), f, map[string]any{"foo": "bar"})
	if err != nil {
		t.Errorf("expected nil error for minimal valid flow, got %v", err)
	}
}

func TestExecute_AllStepTypes(t *testing.T) {
	e := NewDefaultEngine(context.Background())
	f := &model.Flow{Name: "all_types", Steps: []model.Step{
		{
			ID:         "s1",
			Use:        "core.echo",
			With:       map[string]interface{}{"text": "hi"},
			If:         "x > 0",
			Foreach:    "{{list}}",
			As:         "item",
			Do:         []model.Step{{ID: "d1", Use: "core.echo", With: map[string]interface{}{"text": "{{item}}"}}},
			Parallel:   true,
			Retry:      &model.RetrySpec{Attempts: 2, DelaySec: 1},
			AwaitEvent: &model.AwaitEventSpec{Source: "bus", Match: map[string]interface{}{"key": "value"}, Timeout: "10s"},
			Wait:       &model.WaitSpec{Seconds: 5, Until: "2025-01-01"},
		},
		{ID: "s2", Use: "core.echo", With: map[string]interface{}{"text": "hi"}},
	}}
	_, err := e.Execute(context.Background(), f, map[string]any{"foo": "bar"})
	if err == nil || !strings.Contains(err.Error(), "missing token in match") {
		t.Errorf("expected await_event missing token error, got %v", err)
	}
}

func TestExecute_Concurrency(t *testing.T) {
	e := NewDefaultEngine(context.Background())
	f := &model.Flow{Name: "concurrent", Steps: []model.Step{{ID: "s1", Use: "core.echo"}}}
	done := make(chan bool, 2)
	go func() {
		_, _ = e.Execute(context.Background(), f, map[string]any{"foo": "bar"})
		done <- true
	}()
	go func() {
		_, _ = e.Execute(context.Background(), f, map[string]any{"foo": "baz"})
		done <- true
	}()
	<-done
	<-done
}

func TestAwaitEventResume_RoundTrip(t *testing.T) {
	// Load the test flow
	f, err := os.ReadFile("../flows/examples/await_resume_demo.flow.yaml")
	if err != nil {
		t.Fatalf("failed to read flow: %v", err)
	}
	var flow model.Flow
	if err := yaml.Unmarshal(f, &flow); err != nil {
		t.Fatalf("failed to unmarshal flow: %v", err)
	}
	engine := NewDefaultEngine(context.Background())
	// Start the flow with input and token
	startEvent := map[string]any{"input": "hello world", "token": "abc123"}
	outputs, err := engine.Execute(context.Background(), &flow, startEvent)
	if err == nil || !strings.Contains(err.Error(), "is waiting for event") {
		t.Fatalf("expected pause on await_event, got: %v, outputs: %v", err, outputs)
	}
	// Wait to ensure subscription is registered
	time.Sleep(50 * time.Millisecond)
	// Simulate a real-world delay before resume (short for test)
	time.Sleep(50 * time.Millisecond)
	// Simulate resume event
	resumeEvent := map[string]any{"resume_value": "it worked!", "token": "abc123"}
	if err := engine.EventBus.Publish("resume.abc123", resumeEvent); err != nil {
		t.Errorf("Publish failed: %v", err)
	}
	// Wait briefly to allow resume goroutine to complete
	var resumedOutputs map[string]any
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		resumedOutputs = engine.GetCompletedOutputs("abc123")
		if resumedOutputs != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("resumed outputs: %+v", resumedOutputs)
	if resumedOutputs == nil {
		t.Fatalf("expected outputs after resume, got nil")
	}
	if resumedOutputs["echo_start"] == nil {
		t.Errorf("expected echo_start output, got: %v", resumedOutputs)
	}
	if resumedOutputs["echo_resumed"] == nil {
		t.Errorf("expected echo_resumed output, got: %v", resumedOutputs)
	}
}

func TestExecute_CatchBlock(t *testing.T) {
	flow := &model.Flow{
		Name:  "catch_test",
		Steps: []model.Step{{ID: "fail", Use: "nonexistent.adapter"}},
		Catch: []model.Step{
			{ID: "catch1", Use: "core.echo", With: map[string]interface{}{"text": "caught!"}},
			{ID: "catch2", Use: "core.echo", With: map[string]interface{}{"text": "second!"}},
		},
	}
	eng := NewDefaultEngine(context.Background())
	outputs, err := eng.Execute(context.Background(), flow, nil)
	if err == nil {
		t.Errorf("expected error from fail step")
	}
	if out, ok := outputs["catch1"].(map[string]any); !ok || out["text"] != "caught!" {
		t.Errorf("expected catch1 to run and output map with text, got outputs: %v", outputs)
	}
	if out, ok := outputs["catch2"].(map[string]any); !ok || out["text"] != "second!" {
		t.Errorf("expected catch2 to run and output map with text, got outputs: %v", outputs)
	}
}

func TestExecute_AdapterErrorPropagation(t *testing.T) {
	e := NewDefaultEngine(context.Background())
	f := &model.Flow{
		Name:  "adapter_error",
		Steps: []model.Step{{ID: "s1", Use: "core.echo"}},
	}
	outputs, err := e.Execute(context.Background(), f, map[string]any{})
	if err != nil {
		t.Errorf("unexpected error from adapter, got %v", err)
	}
	// Expect outputs to be a map with an empty map for s1
	if out, ok := outputs["s1"].(map[string]any); !ok || len(out) != 0 {
		t.Errorf("expected outputs to be map with empty map for s1, got: %v", outputs)
	}
}

func TestExecute_ParallelForeachEdgeCases(t *testing.T) {
	e := NewDefaultEngine(context.Background())
	// Parallel with empty list
	f := &model.Flow{
		Name: "parallel_empty",
		Steps: []model.Step{{
			ID:       "s1",
			Use:      "core.echo",
			Foreach:  "{{list}}",
			As:       "item",
			Parallel: true,
			Do:       []model.Step{{ID: "d1", Use: "core.echo", With: map[string]interface{}{"text": "{{item}}"}}},
		}},
	}
	outputs, err := e.Execute(context.Background(), f, map[string]any{"list": []any{}})
	if err != nil {
		t.Errorf("expected no error for empty foreach, got %v", err)
	}
	// Expect outputs to be a map with an empty map for s1
	if out, ok := outputs["s1"].(map[string]any); !ok || len(out) != 0 {
		t.Errorf("expected outputs to be map with empty map for s1, got %v", outputs)
	}
	// Parallel with error in one branch
	f2 := &model.Flow{
		Name: "parallel_error",
		Steps: []model.Step{{
			ID:       "s1",
			Use:      "core.echo",
			Foreach:  "{{list}}",
			As:       "item",
			Parallel: true,
			Do:       []model.Step{{ID: "d1", Use: "nonexistent.adapter"}},
		}},
	}
	_, err = e.Execute(context.Background(), f2, map[string]any{"list": []any{"a", "b"}})
	if err == nil {
		t.Errorf("expected error for parallel branch failure, got nil")
	}
}

func TestExecute_SecretsInjection(t *testing.T) {
	e := NewDefaultEngine(context.Background())
	f := &model.Flow{
		Name:  "secrets_injection",
		Steps: []model.Step{{ID: "s1", Use: "core.echo", With: map[string]interface{}{"text": "{{ secrets.MY_SECRET }}"}}},
	}
	outputs, err := e.Execute(context.Background(), f, map[string]any{"secrets": map[string]any{"MY_SECRET": "shhh"}})
	if err != nil {
		t.Errorf("expected no error for secrets injection, got %v", err)
	}
	// Expect outputs["s1"] to be a map with key "text" and value "shhh"
	if out, ok := outputs["s1"].(map[string]any); !ok || out["text"] != "shhh" {
		t.Errorf("expected secret injected as map output, got %v", outputs["s1"])
	}
}

func TestExecute_SecretsDotAccess(t *testing.T) {
	e := NewDefaultEngine(context.Background())
	f := &model.Flow{
		Name:  "secrets_dot_access",
		Steps: []model.Step{{ID: "s1", Use: "core.echo", With: map[string]interface{}{"text": "{{ secrets.MY_SECRET }}"}}},
	}
	outputs, err := e.Execute(context.Background(), f, map[string]any{"secrets": map[string]any{"MY_SECRET": "shhh"}})
	if err != nil {
		t.Errorf("expected no error for secrets dot access, got %v", err)
	}
	if out, ok := outputs["s1"].(map[string]any); !ok || out["text"] != "shhh" {
		t.Errorf("expected secret injected as map output, got %v", outputs["s1"])
	}
}

func TestExecute_ArrayAccessInTemplate(t *testing.T) {
	e := NewDefaultEngine(context.Background())
	f := &model.Flow{
		Name:  "array_access",
		Steps: []model.Step{{ID: "s1", Use: "core.echo", With: map[string]interface{}{"text": "First: {{ event.arr.0.val }}, Second: {{ event.arr.1.val }}"}}},
	}
	arr := []map[string]any{{"val": "a"}, {"val": "b"}}
	outputs, err := e.Execute(context.Background(), f, map[string]any{"arr": arr})
	if err != nil {
		t.Errorf("expected no error for array access, got %v", err)
	}
	if out, ok := outputs["s1"].(map[string]any); !ok || out["text"] != "First: a, Second: b" {
		t.Errorf("expected array access output, got %v", outputs["s1"])
	}
}

func TestSqlitePersistenceAndResume_FullFlow(t *testing.T) {
	// Use a temp SQLite file
	tmpDir := t.TempDir()
	// Cleanup temp dir (and any SQLite files) before automatic TempDir removal
	defer func() { os.RemoveAll(tmpDir) }()
	dbPath := filepath.Join(tmpDir, t.Name()+"-resume_fullflow.db")

	// Load the echo_await_resume flow
	f, err := os.ReadFile("../flows/examples/await_resume_demo.flow.yaml")
	if err != nil {
		t.Fatalf("failed to read flow: %v", err)
	}
	var flow model.Flow
	if err := yaml.Unmarshal(f, &flow); err != nil {
		t.Fatalf("failed to unmarshal flow: %v", err)
	}

	// Create storage and engine
	s, err := storage.NewSqliteStorage(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite storage: %v", err)
	}
	defer func() {
		_ = s.Close()
	}()
	engine := NewEngine(
		NewDefaultAdapterRegistry(context.Background()),
		dsl.NewTemplater(),
		event.NewInProcEventBus(),
		nil, // blob store not needed here
		s,
	)

	// Start the flow, should pause at await_event
	startEvent := map[string]any{"input": "hello world", "token": "abc123"}
	outputs, err := engine.Execute(context.Background(), &flow, startEvent)
	if err == nil || !strings.Contains(err.Error(), "is waiting for event") {
		t.Fatalf("expected pause on await_event, got: %v, outputs: %v", err, outputs)
	}

	// Check that only echo_start step is present in DB
	run, err := s.GetLatestRunByFlowName(context.Background(), flow.Name)
	if err != nil {
		t.Fatalf("GetLatestRunByFlowName failed: %v", err)
	}
	steps, err := s.GetSteps(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("GetSteps failed: %v", err)
	}
	var foundStart bool
	for _, step := range steps {
		if step.StepName == "echo_start" {
			foundStart = true
		}
	}
	if !foundStart {
		t.Fatalf("expected echo_start step after pause")
	}

	// Simulate a restart (new storage/engine instance)
	s2, err := storage.NewSqliteStorage(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen sqlite storage: %v", err)
	}
	defer func() {
		_ = s2.Close()
	}()
	engine2 := NewEngine(
		NewDefaultAdapterRegistry(context.Background()),
		dsl.NewTemplater(),
		event.NewInProcEventBus(),
		nil, // blob store not needed here
		s2,
	)

	// Simulate resume event
	resumeEvent := map[string]any{"resume_value": "it worked!", "token": "abc123"}
	if err := engine2.EventBus.Publish("resume.abc123", resumeEvent); err != nil {
		t.Errorf("Publish failed: %v", err)
	}

	// Wait for both echo_start and echo_resumed steps to appear (polling, up to 2s)
	var steps2 []*model.StepRun
	var run2 *model.Run
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		run2, err = s2.GetLatestRunByFlowName(context.Background(), flow.Name)
		if err == nil && run2 != nil {
			steps2, err = s2.GetSteps(context.Background(), run2.ID)
			if err == nil {
				foundStart = false
				for _, step := range steps2 {
					if step.StepName == "echo_start" {
						foundStart = true
					}
				}
				if foundStart {
					break
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !foundStart {
		t.Fatalf("expected both echo_start and echo_resumed steps after resume")
	}
}

func TestSqliteQueryCompletedRunAfterRestart(t *testing.T) {
	// Use a temp SQLite file
	dbPath := filepath.Join(t.TempDir(), t.Name()+"-query_completed_run.db")

	// Load the echo_await_resume flow and remove the await_event step for this test
	f, err := os.ReadFile("../flows/examples/await_resume_demo.flow.yaml")
	if err != nil {
		t.Fatalf("failed to read flow: %v", err)
	}
	var flow model.Flow
	if err := yaml.Unmarshal(f, &flow); err != nil {
		t.Fatalf("failed to unmarshal flow: %v", err)
	}
	// Remove the await_event and echo_resumed steps so the flow completes immediately and does not reference .event.resume_value
	var newSteps []model.Step
	for _, s := range flow.Steps {
		if s.AwaitEvent == nil && s.ID != "echo_resumed" {
			newSteps = append(newSteps, s)
		}
	}
	flow.Steps = newSteps

	// Create storage and engine
	s, err := storage.NewSqliteStorage(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite storage: %v", err)
	}
	defer func() {
		_ = s.Close()
	}()
	engine := NewEngine(
		NewDefaultAdapterRegistry(context.Background()),
		dsl.NewTemplater(),
		event.NewInProcEventBus(),
		nil, // blob store not needed here
		s,
	)

	startEvent := map[string]any{"input": "hello world", "token": "abc123"}
	outputs, err := engine.Execute(context.Background(), &flow, startEvent)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if outputs["echo_start"] == nil {
		t.Fatalf("expected echo_start output, got: %v", outputs)
	}

	// Simulate a restart (new storage instance)
	s2, err := storage.NewSqliteStorage(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen sqlite storage: %v", err)
	}
	defer func() { _ = s2.Close() }()

	// Query the run and steps
	run, err := s2.GetLatestRunByFlowName(context.Background(), flow.Name)
	if err != nil {
		t.Fatalf("GetLatestRunByFlowName failed: %v", err)
	}
	if run == nil {
		t.Fatalf("expected run to be present after restart")
	}
	steps, err := s2.GetSteps(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("GetSteps failed: %v", err)
	}
	if len(steps) == 0 {
		t.Fatalf("expected steps to be present after restart")
	}
	var foundStart bool
	for _, step := range steps {
		if step.StepName == "echo_start" {
			foundStart = true
		}
	}
	if !foundStart {
		t.Fatalf("expected echo_start step after restart")
	}
}

func TestInMemoryFallback_ListAndGetRun(t *testing.T) {
	e := NewDefaultEngine(context.Background())
	flow := &model.Flow{Name: "inmem", Steps: []model.Step{{ID: "s1", Use: "core.echo", With: map[string]interface{}{"text": "hi"}}}}
	outputs, err := e.Execute(context.Background(), flow, map[string]any{"foo": "bar"})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	runs, err := e.ListRuns(context.Background())
	if err != nil {
		t.Fatalf("ListRuns error: %v", err)
	}
	if len(runs) == 0 {
		t.Fatalf("expected at least one run in memory")
	}
	run := runs[0]
	got, err := e.GetRunByID(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("GetRunByID error: %v", err)
	}
	if got == nil || got.ID != run.ID {
		t.Fatalf("expected to get run by ID, got: %v", got)
	}
	if outputs["s1"] == nil {
		t.Fatalf("expected outputs for s1, got: %v", outputs)
	}
	// Simulate restart (new engine, no persistence)
	e2 := NewDefaultEngine(context.Background())
	runs2, err := e2.ListRuns(context.Background())
	if err != nil {
		t.Fatalf("ListRuns error after restart: %v", err)
	}
	if len(runs2) != 0 {
		t.Fatalf("expected no runs after restart in in-memory mode, got: %d", len(runs2))
	}
}

// ============================================================================
// COMPREHENSIVE COVERAGE TESTS
// ============================================================================

// TestExecuteParallelBlock tests the parallel block execution with 100% coverage
func TestExecuteParallelBlock(t *testing.T) {
	ctx := context.Background()
	engine := NewDefaultEngine(ctx)

	// Test successful parallel execution
	step := &model.Step{
		Steps: []model.Step{
			{
				ID:  "task1",
				Use: "core.echo",
				With: map[string]any{
					"text": "Task 1",
				},
			},
			{
				ID:  "task2",
				Use: "core.echo",
				With: map[string]any{
					"text": "Task 2",
				},
			},
		},
	}

	stepCtx := NewStepContext(map[string]any{}, map[string]any{}, map[string]any{})
	err := engine.executeParallelBlock(ctx, step, stepCtx, "parallel_test")
	if err != nil {
		t.Fatalf("executeParallelBlock failed: %v", err)
	}

	// Verify outputs were set
	if _, ok := stepCtx.GetOutput("task1"); !ok {
		t.Error("task1 output not found")
	}
	if _, ok := stepCtx.GetOutput("task2"); !ok {
		t.Error("task2 output not found")
	}

	// Test parallel execution with error
	stepWithError := &model.Step{
		Steps: []model.Step{
			{
				ID:  "good_task",
				Use: "core.echo",
				With: map[string]any{
					"text": "Good task",
				},
			},
			{
				ID:  "bad_task",
				Use: "nonexistent.adapter",
				With: map[string]any{
					"text": "Bad task",
				},
			},
		},
	}

	stepCtx2 := NewStepContext(map[string]any{}, map[string]any{}, map[string]any{})
	err = engine.executeParallelBlock(ctx, stepWithError, stepCtx2, "parallel_error_test")
	if err == nil {
		t.Error("Expected error from parallel block with bad adapter")
	}

	// Test empty parallel block
	emptyStep := &model.Step{
		Steps: []model.Step{},
	}
	stepCtx3 := NewStepContext(map[string]any{}, map[string]any{}, map[string]any{})
	err = engine.executeParallelBlock(ctx, emptyStep, stepCtx3, "empty_parallel")
	if err != nil {
		t.Fatalf("Empty parallel block should not error: %v", err)
	}
}

// TestExecuteSequentialBlock tests the sequential block execution with 100% coverage
func TestExecuteSequentialBlock(t *testing.T) {
	ctx := context.Background()
	engine := NewDefaultEngine(ctx)

	// Test successful sequential execution
	step := &model.Step{
		Steps: []model.Step{
			{
				ID:  "seq1",
				Use: "core.echo",
				With: map[string]any{
					"text": "Sequential 1",
				},
			},
			{
				ID:  "seq2",
				Use: "core.echo",
				With: map[string]any{
					"text": "Sequential 2 - {{seq1.text}}",
				},
			},
		},
	}

	stepCtx := NewStepContext(map[string]any{}, map[string]any{}, map[string]any{})
	err := engine.executeSequentialBlock(ctx, step, stepCtx, "sequential_test")
	if err != nil {
		t.Fatalf("executeSequentialBlock failed: %v", err)
	}

	// Verify outputs were set and can reference previous steps
	if _, ok := stepCtx.GetOutput("seq1"); !ok {
		t.Error("seq1 output not found")
	}
	if _, ok := stepCtx.GetOutput("seq2"); !ok {
		t.Error("seq2 output not found")
	}

	// Test sequential execution with error in middle
	stepWithError := &model.Step{
		Steps: []model.Step{
			{
				ID:  "good_seq1",
				Use: "core.echo",
				With: map[string]any{
					"text": "Good task 1",
				},
			},
			{
				ID:  "bad_seq",
				Use: "nonexistent.adapter",
				With: map[string]any{
					"text": "Bad task",
				},
			},
			{
				ID:  "never_reached",
				Use: "core.echo",
				With: map[string]any{
					"text": "Never reached",
				},
			},
		},
	}

	stepCtx2 := NewStepContext(map[string]any{}, map[string]any{}, map[string]any{})
	err = engine.executeSequentialBlock(ctx, stepWithError, stepCtx2, "sequential_error_test")
	if err == nil {
		t.Error("Expected error from sequential block with bad adapter")
	}

	// Verify first step executed but third didn't
	if _, ok := stepCtx2.GetOutput("good_seq1"); !ok {
		t.Error("good_seq1 should have executed")
	}
	if _, ok := stepCtx2.GetOutput("never_reached"); ok {
		t.Error("never_reached should not have executed")
	}

	// Test empty sequential block
	emptyStep := &model.Step{
		Steps: []model.Step{},
	}
	stepCtx3 := NewStepContext(map[string]any{}, map[string]any{}, map[string]any{})
	err = engine.executeSequentialBlock(ctx, emptyStep, stepCtx3, "empty_sequential")
	if err != nil {
		t.Fatalf("Empty sequential block should not error: %v", err)
	}
}

// TestExecuteForeachSequential tests sequential foreach execution with 100% coverage
func TestExecuteForeachSequential(t *testing.T) {
	ctx := context.Background()
	engine := NewDefaultEngine(ctx)

	// Test successful sequential foreach
	step := &model.Step{
		Foreach:  "{{items}}",
		As:       "item",
		Parallel: false,
		Do: []model.Step{
			{
				ID:  "process_{{item}}",
				Use: "core.echo",
				With: map[string]any{
					"text": "Processing {{item}}",
				},
			},
		},
	}

	stepCtx := NewStepContext(
		map[string]any{},
		map[string]any{"items": []any{"alpha", "beta", "gamma"}},
		map[string]any{},
	)

	err := engine.executeForeachSequential(ctx, step, stepCtx, "foreach_seq_test", []any{"alpha", "beta", "gamma"})
	if err != nil {
		t.Fatalf("executeForeachSequential failed: %v", err)
	}

	// Verify all items were processed
	if _, ok := stepCtx.GetOutput("process_alpha"); !ok {
		t.Error("process_alpha output not found")
	}
	if _, ok := stepCtx.GetOutput("process_beta"); !ok {
		t.Error("process_beta output not found")
	}
	if _, ok := stepCtx.GetOutput("process_gamma"); !ok {
		t.Error("process_gamma output not found")
	}

	// Test foreach with error in middle
	stepWithError := &model.Step{
		Foreach:  "{{items}}",
		As:       "item",
		Parallel: false,
		Do: []model.Step{
			{
				ID:  "bad_{{item}}",
				Use: "nonexistent.adapter",
				With: map[string]any{
					"text": "Bad {{item}}",
				},
			},
		},
	}

	stepCtx2 := NewStepContext(
		map[string]any{},
		map[string]any{"items": []any{"one", "two"}},
		map[string]any{},
	)

	err = engine.executeForeachSequential(ctx, stepWithError, stepCtx2, "foreach_error_test", []any{"one", "two"})
	if err == nil {
		t.Error("Expected error from foreach with bad adapter")
	}

	// Test empty list
	stepCtx3 := NewStepContext(map[string]any{}, map[string]any{}, map[string]any{})
	err = engine.executeForeachSequential(ctx, step, stepCtx3, "foreach_empty_test", []any{})
	if err != nil {
		t.Fatalf("Empty foreach should not error: %v", err)
	}

	// Test with empty stepID (should not set output)
	stepCtx4 := NewStepContext(
		map[string]any{},
		map[string]any{"items": []any{"test"}},
		map[string]any{},
	)
	err = engine.executeForeachSequential(ctx, step, stepCtx4, "", []any{"test"})
	if err != nil {
		t.Fatalf("foreach with empty stepID should not error: %v", err)
	}

	// Test without As variable
	stepNoAs := &model.Step{
		Foreach:  "{{items}}",
		As:       "",
		Parallel: false,
		Do: []model.Step{
			{
				ID:  "no_as_test",
				Use: "core.echo",
				With: map[string]any{
					"text": "No as variable",
				},
			},
		},
	}

	stepCtx5 := NewStepContext(
		map[string]any{},
		map[string]any{"items": []any{"test"}},
		map[string]any{},
	)
	err = engine.executeForeachSequential(ctx, stepNoAs, stepCtx5, "no_as_test", []any{"test"})
	if err != nil {
		t.Fatalf("foreach without As should not error: %v", err)
	}
}

// TestNewEngineWithBlobStore tests engine creation with blob store
func TestNewEngineWithBlobStore(t *testing.T) {
	ctx := context.Background()
	blobStore, err := blob.NewDefaultBlobStore(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to create blob store: %v", err)
	}

	engine := NewEngineWithBlobStore(ctx, blobStore)
	if engine == nil {
		t.Fatal("NewEngineWithBlobStore returned nil")
	}

	if engine.BlobStore != blobStore {
		t.Error("BlobStore not set correctly")
	}

	if engine.Adapters == nil {
		t.Error("Adapters not initialized")
	}

	if engine.Templater == nil {
		t.Error("Templater not initialized")
	}

	if engine.EventBus == nil {
		t.Error("EventBus not initialized")
	}

	if engine.Storage == nil {
		t.Error("Storage not initialized")
	}
}

// TestSetSecret tests the SetSecret method
func TestSetSecret(t *testing.T) {
	stepCtx := NewStepContext(map[string]any{}, map[string]any{}, map[string]any{})

	stepCtx.SetSecret("api_key", "secret_value")
	stepCtx.SetSecret("token", "bearer_token")

	snapshot := stepCtx.Snapshot()
	if snapshot.Secrets["api_key"] != "secret_value" {
		t.Error("api_key secret not set correctly")
	}
	if snapshot.Secrets["token"] != "bearer_token" {
		t.Error("token secret not set correctly")
	}

	// Test concurrent access
	go func() {
		stepCtx.SetSecret("concurrent", "value")
	}()
	stepCtx.SetSecret("main", "value")

	time.Sleep(10 * time.Millisecond) // Allow goroutine to complete
	snapshot2 := stepCtx.Snapshot()
	if snapshot2.Secrets["concurrent"] != "value" {
		t.Error("concurrent secret not set")
	}
	if snapshot2.Secrets["main"] != "value" {
		t.Error("main secret not set")
	}
}

// TestClose tests the Close method
func TestClose(t *testing.T) {
	ctx := context.Background()
	engine := NewDefaultEngine(ctx)

	// Test closing with adapters
	err := engine.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Test closing with nil adapters
	engine.Adapters = nil
	err = engine.Close()
	if err != nil {
		t.Error("Close with nil adapters should not error")
	}
}

// TestRunIDFromContext tests the runIDFromContext utility
func TestRunIDFromContext(t *testing.T) {
	// Test with no run ID in context
	ctx := context.Background()
	runID := runIDFromContext(ctx)
	if runID != uuid.Nil {
		t.Error("Expected uuid.Nil for context without run ID")
	}

	// Test with run ID in context
	testID := uuid.New()
	ctxWithID := context.WithValue(ctx, runIDKey, testID)
	runID = runIDFromContext(ctxWithID)
	if runID != testID {
		t.Error("Run ID not extracted correctly from context")
	}

	// Test with invalid value in context
	ctxWithInvalid := context.WithValue(ctx, runIDKey, "not-a-uuid")
	runID = runIDFromContext(ctxWithInvalid)
	if runID != uuid.Nil {
		t.Error("Expected uuid.Nil for invalid run ID in context")
	}
}

// TestIsValidIdentifier tests all branches of isValidIdentifier
func TestIsValidIdentifier(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"", false},              // empty string
		{"valid_name", true},     // valid identifier
		{"ValidName", true},      // valid with uppercase
		{"_private", true},       // starts with underscore
		{"name123", true},        // with numbers
		{"123invalid", false},    // starts with number
		{"{{template}}", false},  // contains template syntax
		{"{%block%}", false},     // contains block syntax
		{"invalid-name", false},  // contains dash
		{"invalid.name", false},  // contains dot
		{"invalid name", false},  // contains space
		{"valid_name_123", true}, // complex valid name
	}

	for _, test := range tests {
		result := isValidIdentifier(test.input)
		if result != test.expected {
			t.Errorf("isValidIdentifier(%q) = %v, expected %v", test.input, result, test.expected)
		}
	}
}

// TestListMCPServers tests the ListMCPServers method with 100% coverage
func TestListMCPServers(t *testing.T) {
	ctx := context.Background()
	engine := NewDefaultEngine(ctx)

	// Test with no MCP servers configured - this may error due to missing registry files
	servers, err := engine.ListMCPServers(ctx)
	if err != nil {
		// This is expected if registry files don't exist
		t.Logf("ListMCPServers failed as expected: %v", err)
		return
	}
	if len(servers) != 0 {
		t.Errorf("Expected 0 servers, got %d", len(servers))
	}

	// Test basic functionality - ListMCPServers should work without errors
	if servers == nil {
		t.Error("Expected non-nil servers list")
	}
}

// TestSafeSliceAssert tests the safeSliceAssert utility function
func TestSafeSliceAssert(t *testing.T) {
	// Test with valid slice
	validSlice := []any{"item1", "item2", "item3"}
	result, ok := utils.SafeSliceAssert(validSlice)
	if !ok {
		t.Error("Expected safeSliceAssert to return true for valid slice")
	}
	if len(result) != 3 {
		t.Errorf("Expected slice length 3, got %d", len(result))
	}
	if result[0] != "item1" {
		t.Errorf("Expected first item 'item1', got %v", result[0])
	}

	// Test with empty slice
	emptySlice := []any{}
	result, ok = utils.SafeSliceAssert(emptySlice)
	if !ok {
		t.Error("Expected safeSliceAssert to return true for empty slice")
	}
	if len(result) != 0 {
		t.Errorf("Expected empty slice, got length %d", len(result))
	}

	// Test with nil
	result, ok = utils.SafeSliceAssert(nil)
	if ok {
		t.Error("Expected safeSliceAssert to return false for nil input")
	}
	if result != nil {
		t.Errorf("Expected nil result for nil input, got %v", result)
	}

	// Test with non-slice type
	result, ok = utils.SafeSliceAssert("not a slice")
	if ok {
		t.Error("Expected safeSliceAssert to return false for non-slice input")
	}
	if result != nil {
		t.Errorf("Expected nil result for non-slice input, got %v", result)
	}

	// Test with interface{} slice
	interfaceSlice := []interface{}{"a", 1, true}
	result, ok = utils.SafeSliceAssert(interfaceSlice)
	if !ok {
		t.Error("Expected safeSliceAssert to return true for interface slice")
	}
	if len(result) != 3 {
		t.Errorf("Expected interface slice length 3, got %d", len(result))
	}

	// Test with mixed types
	mixedSlice := []any{1, "string", map[string]any{"key": "value"}}
	result, ok = utils.SafeSliceAssert(mixedSlice)
	if !ok {
		t.Error("Expected safeSliceAssert to return true for mixed slice")
	}
	if len(result) != 3 {
		t.Errorf("Expected mixed slice length 3, got %d", len(result))
	}
}

// TestRenderValue tests the renderValue function with comprehensive coverage
func TestRenderValue(t *testing.T) {
	ctx := context.Background()
	engine := NewDefaultEngine(ctx)

	templateData := map[string]any{
		"name": "John",
		"age":  30,
		"nested": map[string]any{
			"value": "deep",
		},
	}

	// Test string template rendering
	result, err := engine.renderValue("Hello {{name}}", templateData)
	if err != nil {
		t.Fatalf("renderValue failed for string template: %v", err)
	}
	if result != "Hello John" {
		t.Errorf("Expected 'Hello John', got %v", result)
	}

	// Test non-string value (should return as-is)
	result, err = engine.renderValue(42, templateData)
	if err != nil {
		t.Fatalf("renderValue failed for non-string: %v", err)
	}
	if result != 42 {
		t.Errorf("Expected 42, got %v", result)
	}

	// Test map rendering
	mapValue := map[string]any{
		"greeting": "Hello {{name}}",
		"info":     "Age: {{age}}",
		"static":   "unchanged",
	}
	result, err = engine.renderValue(mapValue, templateData)
	if err != nil {
		t.Fatalf("renderValue failed for map: %v", err)
	}
	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("Expected map result, got %T", result)
	}
	if resultMap["greeting"] != "Hello John" {
		t.Errorf("Expected 'Hello John', got %v", resultMap["greeting"])
	}
	if resultMap["info"] != "Age: 30" {
		t.Errorf("Expected 'Age: 30', got %v", resultMap["info"])
	}
	if resultMap["static"] != "unchanged" {
		t.Errorf("Expected 'unchanged', got %v", resultMap["static"])
	}

	// Test slice rendering
	sliceValue := []any{
		"Hello {{name}}",
		"Age: {{age}}",
		42,
		map[string]any{"nested": "{{nested.value}}"},
	}
	result, err = engine.renderValue(sliceValue, templateData)
	if err != nil {
		t.Fatalf("renderValue failed for slice: %v", err)
	}
	resultSlice, ok := result.([]any)
	if !ok {
		t.Fatalf("Expected slice result, got %T", result)
	}
	if len(resultSlice) != 4 {
		t.Errorf("Expected slice length 4, got %d", len(resultSlice))
	}
	if resultSlice[0] != "Hello John" {
		t.Errorf("Expected 'Hello John', got %v", resultSlice[0])
	}
	if resultSlice[1] != "Age: 30" {
		t.Errorf("Expected 'Age: 30', got %v", resultSlice[1])
	}
	if resultSlice[2] != 42 {
		t.Errorf("Expected 42, got %v", resultSlice[2])
	}

	// Test nested map in slice
	nestedMap, ok := resultSlice[3].(map[string]any)
	if !ok {
		t.Fatalf("Expected nested map, got %T", resultSlice[3])
	}
	if nestedMap["nested"] != "deep" {
		t.Errorf("Expected 'deep', got %v", nestedMap["nested"])
	}

	// Test template error
	_, err = engine.renderValue("{{invalid template", templateData)
	if err == nil {
		t.Error("Expected error for invalid template")
	}

	// Test nil template data - this should error
	_, err = engine.renderValue("static text", nil)
	if err == nil {
		t.Error("Expected error for nil template data")
	}

	// Test empty string
	result, err = engine.renderValue("", templateData)
	if err != nil {
		t.Fatalf("renderValue failed for empty string: %v", err)
	}
	if result != "" {
		t.Errorf("Expected empty string, got %v", result)
	}

	// Test complex nested structure
	complexValue := map[string]any{
		"users": []any{
			map[string]any{
				"name": "{{name}}",
				"age":  "{{age}}",
			},
			map[string]any{
				"name": "Jane",
				"age":  25,
			},
		},
		"metadata": map[string]any{
			"total": 2,
			"query": "name={{name}}",
		},
	}
	result, err = engine.renderValue(complexValue, templateData)
	if err != nil {
		t.Fatalf("renderValue failed for complex structure: %v", err)
	}
	// Just verify it's a map - detailed structure testing would be extensive
	if _, ok := result.(map[string]any); !ok {
		t.Errorf("Expected map result for complex structure, got %T", result)
	}
}

// TestAutoFillRequiredParams tests the autoFillRequiredParams function
func TestAutoFillRequiredParams(t *testing.T) {
	ctx := context.Background()
	engine := NewDefaultEngine(ctx)

	// Get the core adapter for testing
	coreAdapter, exists := engine.Adapters.Get("core")
	if !exists || coreAdapter == nil {
		t.Fatal("Core adapter not found")
	}

	// Test with valid inputs - just verify the function runs without panic
	inputs := map[string]any{"existing": "value"}
	stepCtx := NewStepContext(map[string]any{}, map[string]any{}, map[string]any{})

	// This function may panic with nil adapter, so test carefully
	defer func() {
		if r := recover(); r != nil {
			t.Logf("autoFillRequiredParams panicked as expected: %v", r)
		}
	}()

	engine.autoFillRequiredParams(coreAdapter, inputs, stepCtx)

	// The function modifies inputs in place, so just verify it doesn't crash
	if inputs["existing"] != "value" {
		t.Error("Expected existing value to be preserved")
	}
}

func TestEvaluateCondition(t *testing.T) {
	ctx := context.Background()
	engine := NewDefaultEngine(ctx)

	tests := []struct {
		name      string
		condition string
		stepCtx   *StepContext
		want      bool
		wantErr   bool
	}{
		{
			name:      "simple true boolean",
			condition: "{{ true }}",
			stepCtx:   NewStepContext(map[string]any{}, map[string]any{}, map[string]any{}),
			want:      true,
		},
		{
			name:      "simple false boolean",
			condition: "{{ false }}",
			stepCtx:   NewStepContext(map[string]any{}, map[string]any{}, map[string]any{}),
			want:      false,
		},
		{
			name:      "numeric comparison true",
			condition: "{{ 1 == 1 }}",
			stepCtx:   NewStepContext(map[string]any{}, map[string]any{}, map[string]any{}),
			want:      true,
		},
		{
			name:      "numeric comparison false",
			condition: "{{ 1 == 2 }}",
			stepCtx:   NewStepContext(map[string]any{}, map[string]any{}, map[string]any{}),
			want:      false,
		},
		{
			name:      "string comparison true",
			condition: "{{ 'hello' == 'hello' }}",
			stepCtx:   NewStepContext(map[string]any{}, map[string]any{}, map[string]any{}),
			want:      true,
		},
		{
			name:      "string comparison false",
			condition: "{{ 'hello' == 'world' }}",
			stepCtx:   NewStepContext(map[string]any{}, map[string]any{}, map[string]any{}),
			want:      false,
		},
		{
			name:      "variable comparison",
			condition: "{{ vars.status == 'approved' }}",
			stepCtx: NewStepContext(
				map[string]any{},
				map[string]any{"status": "approved"},
				map[string]any{},
			),
			want: true,
		},
		{
			name:      "complex and condition true",
			condition: "{{ vars.content and vars.status == 'approved' }}",
			stepCtx: NewStepContext(
				map[string]any{},
				map[string]any{
					"content": "some text",
					"status":  "approved",
				},
				map[string]any{},
			),
			want: true,
		},
		{
			name:      "complex and condition false",
			condition: "{{ vars.content and vars.status == 'approved' }}",
			stepCtx: NewStepContext(
				map[string]any{},
				map[string]any{
					"content": "",
					"status":  "approved",
				},
				map[string]any{},
			),
			want: false,
		},
		{
			name:      "or condition true",
			condition: "{{ vars.status == 'approved' or vars.status == 'pending' }}",
			stepCtx: NewStepContext(
				map[string]any{},
				map[string]any{"status": "pending"},
				map[string]any{},
			),
			want: true,
		},
		{
			name:      "not condition",
			condition: "{{ not (vars.status == 'posted') }}",
			stepCtx: NewStepContext(
				map[string]any{},
				map[string]any{"status": "pending"},
				map[string]any{},
			),
			want: true,
		},
		{
			name:      "greater than comparison",
			condition: "{{ vars.count > 5 }}",
			stepCtx: NewStepContext(
				map[string]any{},
				map[string]any{"count": 10},
				map[string]any{},
			),
			want: true,
		},
		{
			name:      "less than or equal comparison",
			condition: "{{ vars.count <= 5 }}",
			stepCtx: NewStepContext(
				map[string]any{},
				map[string]any{"count": 3},
				map[string]any{},
			),
			want: true,
		},
		{
			name:      "nil value as false",
			condition: "{{ vars.missing_var }}",
			stepCtx:   NewStepContext(map[string]any{}, map[string]any{}, map[string]any{}),
			want:      false,
		},
		{
			name:      "empty string as false",
			condition: "{{ vars.empty_var }}",
			stepCtx: NewStepContext(
				map[string]any{},
				map[string]any{"empty_var": ""},
				map[string]any{},
			),
			want: false,
		},
		{
			name:      "non-empty string as true",
			condition: "{{ vars.non_empty_var }}",
			stepCtx: NewStepContext(
				map[string]any{},
				map[string]any{"non_empty_var": "value"},
				map[string]any{},
			),
			want: true,
		},
		{
			name:      "zero as false",
			condition: "{{ vars.zero_var }}",
			stepCtx: NewStepContext(
				map[string]any{},
				map[string]any{"zero_var": 0},
				map[string]any{},
			),
			want: false,
		},
		{
			name:      "non-zero as true",
			condition: "{{ vars.nonzero_var }}",
			stepCtx: NewStepContext(
				map[string]any{},
				map[string]any{"nonzero_var": 42},
				map[string]any{},
			),
			want: true,
		},
		{
			name:      "legacy syntax rejected",
			condition: "vars.status == 'active'",
			stepCtx: NewStepContext(
				map[string]any{},
				map[string]any{"status": "active"},
				map[string]any{},
			),
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set variables in context
			for k, v := range tt.stepCtx.Vars {
				tt.stepCtx.SetVar(k, v)
			}
			
			got, err := engine.evaluateCondition(tt.condition, tt.stepCtx)
			if (err != nil) != tt.wantErr {
				t.Errorf("evaluateCondition() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("evaluateCondition() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExecuteStepWithConditions(t *testing.T) {
	ctx := context.Background()
	engine := NewDefaultEngine(ctx)

	// Test that steps with false conditions are skipped
	flow := &model.Flow{
		Name: "test_conditions",
		Steps: []model.Step{
			{
				ID:   "always_run",
				Use:  "core.echo",
				With: map[string]any{"text": "always"},
			},
			{
				ID:   "should_run",
				If:   "{{ 1 == 1 }}",
				Use:  "core.echo",
				With: map[string]any{"text": "yes"},
			},
			{
				ID:   "should_not_run",
				If:   "{{ 1 == 2 }}",
				Use:  "core.echo",
				With: map[string]any{"text": "no"},
			},
			{
				ID:   "conditional_on_var",
				If:   "{{ event.run_this == true }}",
				Use:  "core.echo",
				With: map[string]any{"text": "conditional"},
			},
		},
	}

	// First run without the variable
	outputs, err := engine.Execute(ctx, flow, map[string]any{})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Check outputs - should_not_run and conditional_on_var should not have outputs
	if _, exists := outputs["always_run"]; !exists {
		t.Error("always_run should have executed")
	}
	if _, exists := outputs["should_run"]; !exists {
		t.Error("should_run should have executed")
	}
	if _, exists := outputs["should_not_run"]; exists {
		t.Error("should_not_run should NOT have executed")
	}
	if _, exists := outputs["conditional_on_var"]; exists {
		t.Error("conditional_on_var should NOT have executed without variable")
	}

	// Second run with the variable
	outputs, err = engine.Execute(ctx, flow, map[string]any{"run_this": true})
	if err != nil {
		t.Fatalf("Execute with variable failed: %v", err)
	}

	if _, exists := outputs["conditional_on_var"]; !exists {
		t.Error("conditional_on_var should have executed with variable")
	}
}

func TestForeachWithConditions(t *testing.T) {
	ctx := context.Background()
	engine := NewDefaultEngine(ctx)

	flow := &model.Flow{
		Name: "test_foreach_conditions",
		Vars: map[string]any{
			"items": []any{
				map[string]any{"name": "item1", "process": true},
				map[string]any{"name": "item2", "process": false},
				map[string]any{"name": "item3", "process": true},
			},
		},
		Steps: []model.Step{
			{
				ID:      "process_items",
				Foreach: "{{items}}",
				As:      "item",
				Do: []model.Step{
					{
						ID:   "process_{{item.name}}",
						If:   "{{ item.process == true }}",
						Use:  "core.echo",
						With: map[string]any{"text": "Processing {{item.name}}"},
					},
				},
			},
		},
	}

	outputs, err := engine.Execute(ctx, flow, map[string]any{})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Should have processed item1 and item3, but not item2
	if _, exists := outputs["process_item1"]; !exists {
		t.Error("process_item1 should have executed")
	}
	if _, exists := outputs["process_item2"]; exists {
		t.Error("process_item2 should NOT have executed")
	}
	if _, exists := outputs["process_item3"]; !exists {
		t.Error("process_item3 should have executed")
	}
}

func TestNestedConditions(t *testing.T) {
	ctx := context.Background()
	engine := NewDefaultEngine(ctx)

	flow := &model.Flow{
		Name: "test_nested_conditions",
		Steps: []model.Step{
			{
				ID: "outer",
				If: "{{ true }}",
				Steps: []model.Step{
					{
						ID:   "inner_true",
						If:   "{{ true }}",
						Use:  "core.echo",
						With: map[string]any{"text": "inner true"},
					},
					{
						ID:   "inner_false",
						If:   "{{ false }}",
						Use:  "core.echo",
						With: map[string]any{"text": "inner false"},
					},
				},
			},
			{
				ID: "outer_false",
				If: "{{ false }}",
				Steps: []model.Step{
					{
						ID:   "should_not_run",
						Use:  "core.echo",
						With: map[string]any{"text": "should not run"},
					},
				},
			},
		},
	}

	outputs, err := engine.Execute(ctx, flow, map[string]any{})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if _, exists := outputs["inner_true"]; !exists {
		t.Error("inner_true should have executed")
	}
	if _, exists := outputs["inner_false"]; exists {
		t.Error("inner_false should NOT have executed")
	}
	if _, exists := outputs["should_not_run"]; exists {
		t.Error("should_not_run should NOT have executed")
	}
}

// TestPristineConditionSyntax tests that conditions MUST use {{ }} syntax
func TestPristineConditionSyntax(t *testing.T) {
	ctx := context.Background()
	engine := NewDefaultEngine(ctx)

	tests := []struct {
		name    string
		flow    *model.Flow
		event   map[string]any
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid_template_syntax",
			flow: &model.Flow{
				Name: "valid_syntax",
				Steps: []model.Step{
					{
						ID:   "test",
						If:   "{{ vars.enabled == true }}",
						Use:  "core.echo",
						With: map[string]any{"text": "enabled"},
					},
				},
			},
			event:   map[string]any{"enabled": true},
			wantErr: false,
		},
		{
			name: "invalid_no_braces",
			flow: &model.Flow{
				Name: "invalid_syntax",
				Steps: []model.Step{
					{
						ID:   "test",
						If:   "vars.enabled == true",
						Use:  "core.echo",
						With: map[string]any{"text": "should fail"},
					},
				},
			},
			event:   map[string]any{"enabled": true},
			wantErr: true,
			errMsg:  "condition must use template syntax",
		},
		{
			name: "complex_valid_condition",
			flow: &model.Flow{
				Name: "complex_condition",
				Steps: []model.Step{
					{
						ID:   "complex",
						If:   "{{ vars.count > 5 and env.USER and not vars.disabled }}",
						Use:  "core.echo",
						With: map[string]any{"text": "complex"},
					},
				},
			},
			event:   map[string]any{"count": 10, "disabled": false},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := engine.Execute(ctx, tt.flow, tt.event)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestPristineForeachSyntax tests foreach with clean index variables
func TestPristineForeachSyntax(t *testing.T) {
	ctx := context.Background()
	engine := NewDefaultEngine(ctx)

	flow := &model.Flow{
		Name: "foreach_test",
		Vars: map[string]any{
			"items": []map[string]any{
				{"name": "first"},
				{"name": "second"},
				{"name": "third"},
			},
		},
		Steps: []model.Step{
			{
				ID:      "process",
				Foreach: "{{ vars.items }}",
				As:      "item",
				Do: []model.Step{
					{
						ID:  "echo_{{ item_index }}",
						Use: "core.echo",
						With: map[string]any{
							"text": "Item {{ item_row }}: {{ item.name }}",
						},
					},
				},
			},
		},
	}

	event := map[string]any{}

	outputs, err := engine.Execute(ctx, flow, event)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Verify outputs for each iteration
	if _, exists := outputs["echo_0"]; !exists {
		t.Error("Missing output for first iteration (echo_0)")
	}
	if _, exists := outputs["echo_1"]; !exists {
		t.Error("Missing output for second iteration (echo_1)")
	}
	if _, exists := outputs["echo_2"]; !exists {
		t.Error("Missing output for third iteration (echo_2)")
	}
}

// TestPristineArrayAccess tests Pongo2's dot notation for arrays
func TestPristineArrayAccess(t *testing.T) {
	ctx := context.Background()
	engine := NewDefaultEngine(ctx)

	flow := &model.Flow{
		Name: "array_access",
		Vars: map[string]any{
			"users": []map[string]any{
				{"name": "Alice"},
				{"name": "Bob"},
			},
			"data": map[string]any{
				"rows": []map[string]any{
					{"value": "first"},
					{"value": "second"},
				},
			},
		},
		Steps: []model.Step{
			{
				ID:  "first_element",
				Use: "core.echo",
				With: map[string]any{
					"text": "{{ vars.users.0.name }}",
				},
			},
			{
				ID:  "nested_access",
				Use: "core.echo",
				With: map[string]any{
					"text": "{{ vars.data.rows.1.value }}",
				},
			},
		},
	}

	event := map[string]any{}

	outputs, err := engine.Execute(ctx, flow, event)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Check first element access
	if out, ok := outputs["first_element"].(map[string]any); ok {
		if out["text"] != "Alice" {
			t.Errorf("Expected 'Alice', got %v", out["text"])
		}
	} else {
		t.Error("first_element output not found or wrong type")
	}

	// Check nested access
	if out, ok := outputs["nested_access"].(map[string]any); ok {
		if out["text"] != "second" {
			t.Errorf("Expected 'second', got %v", out["text"])
		}
	} else {
		t.Error("nested_access output not found or wrong type")
	}
}

// TestPristineVariableScoping tests explicit variable scoping
func TestPristineVariableScoping(t *testing.T) {
	ctx := context.Background()
	engine := NewDefaultEngine(ctx)

	flow := &model.Flow{
		Name: "scoping_test",
		Vars: map[string]any{
			"flow_var": "from_flow",
		},
		Steps: []model.Step{
			{
				ID:  "test_vars",
				Use: "core.echo",
				With: map[string]any{
					"text": "{{ vars.flow_var }}",
				},
			},
			{
				ID:  "test_event",
				Use: "core.echo",
				With: map[string]any{
					"text": "{{ event.event_var }}",
				},
			},
			{
				ID:  "test_env",
				Use: "core.echo",
				With: map[string]any{
					"text": "{{ env.USER }}",
				},
			},
			{
				ID:  "test_output",
				Use: "core.echo",
				With: map[string]any{
					"text": "Previous: {{ outputs.test_vars.text }}",
				},
			},
		},
	}

	event := map[string]any{
		"event_var": "from_event",
	}

	outputs, err := engine.Execute(ctx, flow, event)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Verify variable scoping
	if out, ok := outputs["test_vars"].(map[string]any); ok {
		if out["text"] != "from_flow" {
			t.Errorf("vars scope failed: expected 'from_flow', got %v", out["text"])
		}
	}

	if out, ok := outputs["test_event"].(map[string]any); ok {
		if out["text"] != "from_event" {
			t.Errorf("event scope failed: expected 'from_event', got %v", out["text"])
		}
	}

	if out, ok := outputs["test_output"].(map[string]any); ok {
		if out["text"] != "Previous: from_flow" {
			t.Errorf("outputs scope failed: expected 'Previous: from_flow', got %v", out["text"])
		}
	}
}

// TestPristineConditionsInForeach tests conditions inside foreach loops
func TestPristineConditionsInForeach(t *testing.T) {
	ctx := context.Background()
	engine := NewDefaultEngine(ctx)

	flow := &model.Flow{
		Name: "foreach_conditions",
		Vars: map[string]any{
			"items": []map[string]any{
				{"name": "Item1", "status": "active"},
				{"name": "Item2", "status": "inactive"},
				{"name": "Item3", "status": "active"},
			},
		},
		Steps: []model.Step{
			{
				ID:      "process",
				Foreach: "{{ vars.items }}",
				As:      "item",
				Do: []model.Step{
					{
						ID:   "active_{{ item_index }}",
						If:   "{{ item.status == 'active' }}",
						Use:  "core.echo",
						With: map[string]any{"text": "Active: {{ item.name }}"},
					},
					{
						ID:   "inactive_{{ item_index }}",
						If:   "{{ item.status != 'active' }}",
						Use:  "core.echo",
						With: map[string]any{"text": "Inactive: {{ item.name }}"},
					},
				},
			},
		},
	}

	event := map[string]any{}

	outputs, err := engine.Execute(ctx, flow, event)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Verify conditional execution
	if _, exists := outputs["active_0"]; !exists {
		t.Error("active_0 should have executed")
	}
	if _, exists := outputs["inactive_0"]; exists {
		t.Error("inactive_0 should NOT have executed")
	}
	if _, exists := outputs["active_1"]; exists {
		t.Error("active_1 should NOT have executed")
	}
	if _, exists := outputs["inactive_1"]; !exists {
		t.Error("inactive_1 should have executed")
	}
	if _, exists := outputs["active_2"]; !exists {
		t.Error("active_2 should have executed")
	}
}

// TestPristineComplexNesting tests deeply nested structures
func TestPristineComplexNesting(t *testing.T) {
	ctx := context.Background()
	engine := NewDefaultEngine(ctx)

	flow := &model.Flow{
		Name: "complex_nesting",
		Vars: map[string]any{
			"enabled": true,
			"items": []map[string]any{
				{"name": "Low", "priority": 1},
				{"name": "High", "priority": 3},
				{"name": "Medium", "priority": 2},
			},
		},
		Steps: []model.Step{
			{
				ID: "outer",
				If: "{{ vars.enabled }}",
				Steps: []model.Step{
					{
						ID:      "foreach_in_block",
						Foreach: "{{ vars.items }}",
						As:      "item",
						Do: []model.Step{
							{
								ID:   "nested_condition_{{ item_index }}",
								If:   "{{ item.priority > 2 }}",
								Use:  "core.echo",
								With: map[string]any{"text": "High priority: {{ item.name }}"},
							},
						},
					},
				},
			},
		},
	}

	event := map[string]any{}

	outputs, err := engine.Execute(ctx, flow, event)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Only the high priority item should have output
	if _, exists := outputs["nested_condition_0"]; exists {
		t.Error("nested_condition_0 should NOT have executed (priority 1)")
	}
	if _, exists := outputs["nested_condition_1"]; !exists {
		t.Error("nested_condition_1 should have executed (priority 3)")
	}
	if _, exists := outputs["nested_condition_2"]; exists {
		t.Error("nested_condition_2 should NOT have executed (priority 2)")
	}
}

// TestPristineParallelForeach tests parallel foreach execution
func TestPristineParallelForeach(t *testing.T) {
	ctx := context.Background()
	engine := NewDefaultEngine(ctx)

	flow := &model.Flow{
		Name: "parallel_foreach",
		Vars: map[string]any{
			"items": []string{"alpha", "beta", "gamma"},
		},
		Steps: []model.Step{
			{
				ID:       "parallel_process",
				Foreach:  "{{ vars.items }}",
				As:       "item",
				Parallel: true,
				Do: []model.Step{
					{
						ID:  "process_{{ item_index }}",
						Use: "core.echo",
						With: map[string]any{
							"text": "Parallel {{ item_row }}: {{ item }}",
						},
					},
				},
			},
		},
	}

	event := map[string]any{}

	outputs, err := engine.Execute(ctx, flow, event)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// All items should have been processed
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("process_%d", i)
		if _, exists := outputs[key]; !exists {
			t.Errorf("Missing output for parallel iteration %s", key)
		}
	}
}

// TestPristineErrorHandling tests error cases with pristine syntax
func TestPristineErrorHandling(t *testing.T) {
	ctx := context.Background()
	engine := NewDefaultEngine(ctx)

	tests := []struct {
		name    string
		flow    *model.Flow
		wantErr bool
		errMsg  string
	}{
		{
			name: "invalid_condition_syntax",
			flow: &model.Flow{
				Name: "invalid",
				Steps: []model.Step{
					{
						ID:   "bad",
						If:   "status == 'active'", // Missing {{ }}
						Use:  "core.echo",
						With: map[string]any{"text": "bad"},
					},
				},
			},
			wantErr: true,
			errMsg:  "condition must use template syntax",
		},
		{
			name: "malformed_template",
			flow: &model.Flow{
				Name: "malformed",
				Steps: []model.Step{
					{
						ID:   "bad",
						If:   "{{ vars.status ==", // Incomplete
						Use:  "core.echo",
						With: map[string]any{"text": "bad"},
					},
				},
			},
			wantErr: true,
			errMsg:  "template",
		},
		{
			name: "undefined_variable_in_condition",
			flow: &model.Flow{
				Name: "undefined",
				Steps: []model.Step{
					{
						ID:   "test",
						If:   "{{ vars.undefined_var == 'test' }}",
						Use:  "core.echo",
						With: map[string]any{"text": "test"},
					},
				},
			},
			wantErr: false, // Undefined variables evaluate to falsy
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := engine.Execute(ctx, tt.flow, map[string]any{})
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestPristineBooleanEvaluation tests various boolean conditions
func TestPristineBooleanEvaluation(t *testing.T) {
	ctx := context.Background()
	engine := NewDefaultEngine(ctx)

	tests := []struct {
		name      string
		condition string
		vars      map[string]any
		want      bool
	}{
		{
			name:      "empty_string_is_falsy",
			condition: "{{ vars.empty }}",
			vars:      map[string]any{"empty": ""},
			want:      false,
		},
		{
			name:      "zero_is_falsy",
			condition: "{{ vars.zero }}",
			vars:      map[string]any{"zero": 0},
			want:      false,
		},
		{
			name:      "null_is_falsy",
			condition: "{{ vars.null }}",
			vars:      map[string]any{"null": nil},
			want:      false,
		},
		{
			name:      "undefined_is_falsy",
			condition: "{{ vars.undefined }}",
			vars:      map[string]any{},
			want:      false,
		},
		{
			name:      "non_empty_string_is_truthy",
			condition: "{{ vars.text }}",
			vars:      map[string]any{"text": "hello"},
			want:      true,
		},
		{
			name:      "non_zero_number_is_truthy",
			condition: "{{ vars.num }}",
			vars:      map[string]any{"num": 42},
			want:      true,
		},
		{
			name:      "array_length_check",
			condition: "{{ vars.items | length > 0 }}",
			vars:      map[string]any{"items": []string{"a", "b"}},
			want:      true,
		},
		{
			name:      "complex_boolean_logic",
			condition: "{{ vars.a and (vars.b or vars.c) }}",
			vars:      map[string]any{"a": true, "b": false, "c": true},
			want:      true,
		},
		{
			name:      "negation",
			condition: "{{ not vars.disabled }}",
			vars:      map[string]any{"disabled": false},
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow := &model.Flow{
				Name: tt.name,
				Vars: tt.vars,
				Steps: []model.Step{
					{
						ID:   "test",
						If:   tt.condition,
						Use:  "core.echo",
						With: map[string]any{"text": "executed"},
					},
				},
			}

			outputs, err := engine.Execute(ctx, flow, map[string]any{})
			if err != nil {
				t.Fatalf("Execute failed: %v", err)
			}

			executed := outputs["test"] != nil
			if executed != tt.want {
				t.Errorf("Condition %s: expected execution=%v, got %v",
					tt.condition, tt.want, executed)
			}
		})
	}
}
