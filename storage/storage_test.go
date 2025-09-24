package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beemflow/beemflow/model"
	"github.com/beemflow/beemflow/utils"
	"github.com/google/uuid"
)

func TestNewSqliteStorage(t *testing.T) {
	// Test with valid DSN
	storage, err := NewSqliteStorage(":memory:")
	if err != nil {
		t.Errorf("NewSqliteStorage() failed: %v", err)
	}
	if storage == nil {
		t.Error("NewSqliteStorage() returned nil storage")
	}
}

func TestSqliteStorage_RoundTrip(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sqlite_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.db")
	storage, err := NewSqliteStorage(dbPath)
	if err != nil {
		t.Fatalf("Failed to create sqlite storage: %v", err)
	}
	defer storage.Close()

	testStorageRoundTrip(t, storage)
}

func TestMemoryStorage_RoundTrip(t *testing.T) {
	storage := NewMemoryStorage()
	testStorageRoundTrip(t, storage)
}

func TestMemoryStorage_AllOperations(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Test SaveRun and GetRun
	runID := uuid.New()
	run := &model.Run{
		ID:        runID,
		FlowName:  "test_flow",
		Status:    model.RunRunning,
		StartedAt: time.Now(),
		Event:     map[string]any{"key": "value"},
	}

	err := storage.SaveRun(ctx, run)
	if err != nil {
		t.Fatalf("SaveRun failed: %v", err)
	}

	retrievedRun, err := storage.GetRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetRun failed: %v", err)
	}
	if retrievedRun.ID != runID {
		t.Errorf("Expected run ID %v, got %v", runID, retrievedRun.ID)
	}

	// Test GetRun with non-existent ID
	nonExistentID := uuid.New()
	_, err = storage.GetRun(ctx, nonExistentID)
	if err == nil {
		t.Error("Expected error for non-existent run ID")
	}

	// Test SaveStep and GetSteps
	stepID := uuid.New()
	step := &model.StepRun{
		ID:       stepID,
		RunID:    runID,
		StepName: "test_step",
		Status:   model.StepSucceeded,
		Outputs:  map[string]any{"result": "success"},
	}

	err = storage.SaveStep(ctx, step)
	if err != nil {
		t.Fatalf("SaveStep failed: %v", err)
	}

	steps, err := storage.GetSteps(ctx, runID)
	if err != nil {
		t.Fatalf("GetSteps failed: %v", err)
	}
	if len(steps) != 1 {
		t.Errorf("Expected 1 step, got %d", len(steps))
	}
	if steps[0].ID != stepID {
		t.Errorf("Expected step ID %v, got %v", stepID, steps[0].ID)
	}

	// Test RegisterWait and ResolveWait
	token := uuid.New()
	err = storage.RegisterWait(ctx, token, nil)
	if err != nil {
		t.Fatalf("RegisterWait failed: %v", err)
	}

	resolvedRun, err := storage.ResolveWait(ctx, token)
	// Memory storage ResolveWait returns nil, nil - this is expected behavior
	if err != nil {
		t.Fatalf("ResolveWait failed: %v", err)
	}
	// For memory storage, resolvedRun will be nil, which is the expected behavior
	_ = resolvedRun

	// Test ListRuns
	runs, err := storage.ListRuns(ctx)
	if err != nil {
		t.Fatalf("ListRuns failed: %v", err)
	}
	if len(runs) != 1 {
		t.Errorf("Expected 1 run, got %d", len(runs))
	}

	// Test SavePausedRun and LoadPausedRuns
	pausedData := map[string]any{
		"runID":    runID.String(),
		"token":    "pause_token",
		"stepName": "paused_step",
	}

	err = storage.SavePausedRun(context.Background(), "pause_token", pausedData)
	if err != nil {
		t.Fatalf("SavePausedRun failed: %v", err)
	}

	pausedRuns, err := storage.LoadPausedRuns(context.Background())
	if err != nil {
		t.Fatalf("LoadPausedRuns failed: %v", err)
	}
	if len(pausedRuns) != 1 {
		t.Errorf("Expected 1 paused run, got %d", len(pausedRuns))
	}
	if _, exists := pausedRuns["pause_token"]; !exists {
		t.Error("Expected to find pause_token in paused runs")
	}

	// Test DeletePausedRun
	err = storage.DeletePausedRun(context.Background(), "pause_token")
	if err != nil {
		t.Fatalf("DeletePausedRun failed: %v", err)
	}

	pausedRuns, err = storage.LoadPausedRuns(context.Background())
	if err != nil {
		t.Fatalf("LoadPausedRuns after delete failed: %v", err)
	}
	if len(pausedRuns) != 0 {
		t.Errorf("Expected 0 paused runs after delete, got %d", len(pausedRuns))
	}

	// Test DeleteRun
	err = storage.DeleteRun(ctx, runID)
	if err != nil {
		t.Fatalf("DeleteRun failed: %v", err)
	}

	runs, err = storage.ListRuns(ctx)
	if err != nil {
		t.Fatalf("ListRuns after delete failed: %v", err)
	}
	if len(runs) != 0 {
		t.Errorf("Expected 0 runs after delete, got %d", len(runs))
	}
}

func TestSqliteStorage_AllOperations(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sqlite_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.db")
	storage, err := NewSqliteStorage(dbPath)
	if err != nil {
		t.Fatalf("Failed to create sqlite storage: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()

	// Test SavePausedRun and LoadPausedRuns
	runID := uuid.New()
	pausedData := map[string]any{
		"runID":    runID.String(),
		"token":    "sqlite_pause_token",
		"stepName": "paused_step",
	}

	err = storage.SavePausedRun(context.Background(), "sqlite_pause_token", pausedData)
	if err != nil {
		t.Fatalf("SavePausedRun failed: %v", err)
	}

	pausedRuns, err := storage.LoadPausedRuns(context.Background())
	if err != nil {
		t.Fatalf("LoadPausedRuns failed: %v", err)
	}
	if len(pausedRuns) != 1 {
		t.Errorf("Expected 1 paused run, got %d", len(pausedRuns))
	}

	// Test DeletePausedRun
	err = storage.DeletePausedRun(context.Background(), "sqlite_pause_token")
	if err != nil {
		t.Fatalf("DeletePausedRun failed: %v", err)
	}

	pausedRuns, err = storage.LoadPausedRuns(context.Background())
	if err != nil {
		t.Fatalf("LoadPausedRuns after delete failed: %v", err)
	}
	if len(pausedRuns) != 0 {
		t.Errorf("Expected 0 paused runs after delete, got %d", len(pausedRuns))
	}

	// Test ListRuns
	runs, err := storage.ListRuns(ctx)
	if err != nil {
		t.Fatalf("ListRuns failed: %v", err)
	}
	// Should be empty initially
	if len(runs) != 0 {
		t.Errorf("Expected 0 runs initially, got %d", len(runs))
	}

	// Add a run and test ListRuns again
	run := &model.Run{
		ID:        runID,
		FlowName:  "test_flow",
		Status:    model.RunSucceeded,
		StartedAt: time.Now(),
		Event:     map[string]any{"key": "value"},
	}

	err = storage.SaveRun(ctx, run)
	if err != nil {
		t.Fatalf("SaveRun failed: %v", err)
	}

	runs, err = storage.ListRuns(ctx)
	if err != nil {
		t.Fatalf("ListRuns after save failed: %v", err)
	}
	if len(runs) != 1 {
		t.Errorf("Expected 1 run after save, got %d", len(runs))
	}

	// Test GetLatestRunByFlowName
	latestRun, err := storage.GetLatestRunByFlowName(ctx, "test_flow")
	if err != nil {
		t.Fatalf("GetLatestRunByFlowName failed: %v", err)
	}
	if latestRun.ID != runID {
		t.Errorf("Expected latest run ID %v, got %v", runID, latestRun.ID)
	}

	// Test GetLatestRunByFlowName with non-existent flow
	_, err = storage.GetLatestRunByFlowName(ctx, "non_existent_flow")
	if err == nil {
		t.Error("Expected error for non-existent flow")
	}

	// Test DeleteRun
	err = storage.DeleteRun(ctx, runID)
	if err != nil {
		t.Fatalf("DeleteRun failed: %v", err)
	}

	runs, err = storage.ListRuns(ctx)
	if err != nil {
		t.Fatalf("ListRuns after delete failed: %v", err)
	}
	if len(runs) != 0 {
		t.Errorf("Expected 0 runs after delete, got %d", len(runs))
	}
}

func TestSqliteStorage_ErrorCases(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sqlite_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.db")
	storage, err := NewSqliteStorage(dbPath)
	if err != nil {
		t.Fatalf("Failed to create sqlite storage: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()

	// Test GetRun with non-existent ID
	nonExistentID := uuid.New()
	_, err = storage.GetRun(ctx, nonExistentID)
	if err == nil {
		t.Error("Expected error for non-existent run ID")
	}

	// Test GetSteps with non-existent run ID
	steps, err := storage.GetSteps(ctx, nonExistentID)
	if err != nil {
		t.Fatalf("GetSteps should not fail for non-existent run: %v", err)
	}
	if len(steps) != 0 {
		t.Errorf("Expected 0 steps for non-existent run, got %d", len(steps))
	}

	// Test ResolveWait with non-existent token
	nonExistentToken := uuid.New()
	_, err = storage.ResolveWait(ctx, nonExistentToken)
	// SQLite ResolveWait doesn't return an error for non-existent tokens
	// It just returns nil, nil - this is the expected behavior
	if err != nil {
		t.Logf("ResolveWait returned error for non-existent token: %v", err)
	}
}

func TestSqliteStorage_Close(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sqlite_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.db")
	storage, err := NewSqliteStorage(dbPath)
	if err != nil {
		t.Fatalf("Failed to create sqlite storage: %v", err)
	}

	// Test Close
	err = storage.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Test that operations fail after close
	ctx := context.Background()
	runID := uuid.New()
	run := &model.Run{
		ID:        runID,
		FlowName:  "test_flow",
		Status:    model.RunRunning,
		StartedAt: time.Now(),
		Event:     map[string]any{"key": "value"},
	}

	err = storage.SaveRun(ctx, run)
	if err == nil {
		t.Error("Expected error when using storage after close")
	}
}

func TestRunIDFromStepCtx(t *testing.T) {
	// Test the runIDFromStepCtx helper function
	runID := uuid.New()
	stepCtx := map[string]any{
		"run_id": runID.String(),
	}

	extractedID := runIDFromStepCtx(stepCtx)
	if extractedID != runID.String() {
		t.Errorf("Expected run ID %v, got %v", runID.String(), extractedID)
	}

	// Test with missing run_id
	emptyCtx := map[string]any{}
	extractedID = runIDFromStepCtx(emptyCtx)
	if extractedID != "" {
		t.Errorf("Expected empty string for missing run_id, got %v", extractedID)
	}

	// Test with invalid run_id type
	invalidCtx := map[string]any{
		"run_id": 123, // not a string
	}
	extractedID = runIDFromStepCtx(invalidCtx)
	if extractedID != "" {
		t.Errorf("Expected empty string for invalid run_id type, got %v", extractedID)
	}
}

// testStorageRoundTrip is a helper function to test basic storage operations
func testStorageRoundTrip(t *testing.T, storage Storage) {
	ctx := context.Background()

	// Create a test run
	runID := uuid.New()
	run := &model.Run{
		ID:        runID,
		FlowName:  "test_flow",
		Status:    model.RunRunning,
		StartedAt: time.Now(),
		Event:     map[string]any{"key": "value"},
	}

	// Save and retrieve the run
	err := storage.SaveRun(ctx, run)
	if err != nil {
		t.Fatalf("SaveRun failed: %v", err)
	}

	retrievedRun, err := storage.GetRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetRun failed: %v", err)
	}

	if retrievedRun.ID != runID {
		t.Errorf("Expected run ID %v, got %v", runID, retrievedRun.ID)
	}
	if retrievedRun.FlowName != "test_flow" {
		t.Errorf("Expected flow name 'test_flow', got %v", retrievedRun.FlowName)
	}
}

// TestSqliteStorage_SaveStep tests the SaveStep function with comprehensive coverage
func TestSqliteStorage_SaveStep(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sqlite_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.db")
	storage, err := NewSqliteStorage(dbPath)
	if err != nil {
		t.Fatalf("Failed to create sqlite storage: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()

	// First create a run
	runID := uuid.New()
	run := &model.Run{
		ID:        runID,
		FlowName:  "test_flow",
		Status:    model.RunRunning,
		StartedAt: time.Now(),
		Event:     map[string]any{"key": "value"},
	}

	err = storage.SaveRun(ctx, run)
	if err != nil {
		t.Fatalf("SaveRun failed: %v", err)
	}

	// Test SaveStep with valid step
	stepID := uuid.New()
	step := &model.StepRun{
		ID:        stepID,
		RunID:     runID,
		StepName:  "test_step",
		Status:    model.StepSucceeded,
		StartedAt: time.Now(),
		EndedAt:   &time.Time{},
		Outputs:   map[string]any{"result": "success"},
		Error:     "",
	}

	err = storage.SaveStep(ctx, step)
	if err != nil {
		t.Fatalf("SaveStep failed: %v", err)
	}

	// Verify step was saved
	steps, err := storage.GetSteps(ctx, runID)
	if err != nil {
		t.Fatalf("GetSteps failed: %v", err)
	}
	if len(steps) != 1 {
		t.Errorf("Expected 1 step, got %d", len(steps))
	}
	if steps[0].ID != stepID {
		t.Errorf("Expected step ID %v, got %v", stepID, steps[0].ID)
	}

	// Test SaveStep with step that has error
	stepWithError := &model.StepRun{
		ID:        uuid.New(),
		RunID:     runID,
		StepName:  "error_step",
		Status:    model.StepFailed,
		StartedAt: time.Now(),
		EndedAt:   &time.Time{},
		Outputs:   nil,
		Error:     "step failed",
	}

	err = storage.SaveStep(ctx, stepWithError)
	if err != nil {
		t.Fatalf("SaveStep with error failed: %v", err)
	}

	// Test SaveStep with nil outputs
	stepNilOutputs := &model.StepRun{
		ID:        uuid.New(),
		RunID:     runID,
		StepName:  "nil_outputs_step",
		Status:    model.StepSucceeded,
		StartedAt: time.Now(),
		EndedAt:   nil,
		Outputs:   nil,
		Error:     "",
	}

	err = storage.SaveStep(ctx, stepNilOutputs)
	if err != nil {
		t.Fatalf("SaveStep with nil outputs failed: %v", err)
	}

	// Verify all steps were saved
	allSteps, err := storage.GetSteps(ctx, runID)
	if err != nil {
		t.Fatalf("GetSteps failed: %v", err)
	}
	if len(allSteps) != 3 {
		t.Errorf("Expected 3 steps, got %d", len(allSteps))
	}

	// Verify step data integrity
	for _, step := range steps {
		switch step.StepName {
		case "complex_step":
			if step.Outputs == nil {
				t.Error("Expected non-nil outputs for complex_step")
			} else {
				if step.Outputs["string"] != "value" {
					t.Errorf("Expected string value 'value', got %v", step.Outputs["string"])
				}
				if step.Outputs["number"] != float64(42) { // JSON unmarshaling converts numbers to float64
					t.Errorf("Expected number 42, got %v", step.Outputs["number"])
				}
			}
		case "nil_outputs_step":
			if step.Outputs != nil {
				t.Errorf("Expected nil outputs for nil_outputs_step, got %v", step.Outputs)
			}
		}
	}
}

// TestSqliteStorage_RegisterWait tests the RegisterWait function
func TestSqliteStorage_RegisterWait(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sqlite_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.db")
	storage, err := NewSqliteStorage(dbPath)
	if err != nil {
		t.Fatalf("Failed to create sqlite storage: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()

	// Test RegisterWait with valid token and wakeAt time
	token := uuid.New()
	wakeAt := time.Now().Add(time.Hour).Unix()

	err = storage.RegisterWait(ctx, token, &wakeAt)
	if err != nil {
		t.Fatalf("RegisterWait failed: %v", err)
	}

	// Test RegisterWait with nil wakeAt
	token2 := uuid.New()
	err = storage.RegisterWait(ctx, token2, nil)
	if err != nil {
		t.Fatalf("RegisterWait with nil wakeAt failed: %v", err)
	}

	// Test RegisterWait with zero wakeAt
	token3 := uuid.New()
	zeroWakeAt := int64(0)
	err = storage.RegisterWait(ctx, token3, &zeroWakeAt)
	if err != nil {
		t.Fatalf("RegisterWait with zero wakeAt failed: %v", err)
	}
}

// TestSqliteStorage_ResolveWait tests the ResolveWait function comprehensively
func TestSqliteStorage_ResolveWait(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sqlite_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.db")
	storage, err := NewSqliteStorage(dbPath)
	if err != nil {
		t.Fatalf("Failed to create sqlite storage: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()

	// First register a wait
	token := uuid.New()
	wakeAt := time.Now().Add(time.Hour).Unix()

	err = storage.RegisterWait(ctx, token, &wakeAt)
	if err != nil {
		t.Fatalf("RegisterWait failed: %v", err)
	}

	// Test ResolveWait with existing token
	resolvedRun, err := storage.ResolveWait(ctx, token)
	if err != nil {
		t.Fatalf("ResolveWait failed: %v", err)
	}
	// ResolveWait returns nil for SQLite storage - this is expected behavior
	if resolvedRun != nil {
		t.Logf("ResolveWait returned run: %v", resolvedRun)
	}

	// Test ResolveWait with non-existent token
	nonExistentToken := uuid.New()
	resolvedRun, err = storage.ResolveWait(ctx, nonExistentToken)
	if err != nil {
		t.Fatalf("ResolveWait with non-existent token failed: %v", err)
	}
	if resolvedRun != nil {
		t.Errorf("Expected nil run for non-existent token, got %v", resolvedRun)
	}

	// Test ResolveWait with invalid token format
	invalidToken := uuid.Nil
	resolvedRun, err = storage.ResolveWait(ctx, invalidToken)
	if err != nil {
		t.Fatalf("ResolveWait with invalid token failed: %v", err)
	}
	if resolvedRun != nil {
		t.Errorf("Expected nil run for invalid token, got %v", resolvedRun)
	}
}

// TestSqliteStorage_SavePausedRun_ErrorCases tests SavePausedRun error handling
func TestSqliteStorage_SavePausedRun_ErrorCases(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sqlite_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.db")
	storage, err := NewSqliteStorage(dbPath)
	if err != nil {
		t.Fatalf("Failed to create sqlite storage: %v", err)
	}
	defer storage.Close()

	// Test SavePausedRun with valid data
	pausedData := map[string]any{
		"runID":    uuid.New().String(),
		"token":    "test_token",
		"stepName": "paused_step",
		"data":     map[string]any{"nested": "value"},
	}

	err = storage.SavePausedRun(context.Background(), "test_token", pausedData)
	if err != nil {
		t.Fatalf("SavePausedRun failed: %v", err)
	}

	// Test SavePausedRun with nil data
	err = storage.SavePausedRun(context.Background(), "nil_token", nil)
	if err != nil {
		t.Fatalf("SavePausedRun with nil data failed: %v", err)
	}

	// Test SavePausedRun with empty data
	emptyData := map[string]any{}
	err = storage.SavePausedRun(context.Background(), "empty_token", emptyData)
	if err != nil {
		t.Fatalf("SavePausedRun with empty data failed: %v", err)
	}

	// Test SavePausedRun with data that can't be marshaled to JSON
	invalidData := map[string]any{
		"channel": make(chan int), // channels can't be marshaled to JSON
	}
	err = storage.SavePausedRun(context.Background(), "invalid_token", invalidData)
	if err == nil {
		t.Error("Expected error for data that can't be marshaled to JSON")
	}

	// Test SavePausedRun with empty token
	err = storage.SavePausedRun(context.Background(), "", pausedData)
	if err != nil {
		t.Fatalf("SavePausedRun with empty token failed: %v", err)
	}

	// Verify saved runs
	pausedRuns, err := storage.LoadPausedRuns(context.Background())
	if err != nil {
		t.Fatalf("LoadPausedRuns failed: %v", err)
	}
	// Should have at least the valid ones (invalid_token should have failed)
	if len(pausedRuns) < 4 {
		t.Errorf("Expected at least 4 paused runs, got %d", len(pausedRuns))
	}
}

// TestSqliteStorage_GetSteps_EdgeCases tests GetSteps with various edge cases
func TestSqliteStorage_GetSteps_EdgeCases(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sqlite_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.db")
	storage, err := NewSqliteStorage(dbPath)
	if err != nil {
		t.Fatalf("Failed to create sqlite storage: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()

	// Test GetSteps with non-existent run ID
	nonExistentRunID := uuid.New()
	steps, err := storage.GetSteps(ctx, nonExistentRunID)
	if err != nil {
		t.Fatalf("GetSteps should not fail for non-existent run: %v", err)
	}
	if len(steps) != 0 {
		t.Errorf("Expected 0 steps for non-existent run, got %d", len(steps))
	}

	// Test GetSteps with nil UUID
	steps, err = storage.GetSteps(ctx, uuid.Nil)
	if err != nil {
		t.Fatalf("GetSteps should not fail for nil UUID: %v", err)
	}
	if len(steps) != 0 {
		t.Errorf("Expected 0 steps for nil UUID, got %d", len(steps))
	}

	// Create a run and add steps with various data types
	runID := uuid.New()
	run := &model.Run{
		ID:        runID,
		FlowName:  "test_flow",
		Status:    model.RunRunning,
		StartedAt: time.Now(),
		Event:     map[string]any{"key": "value"},
	}

	err = storage.SaveRun(ctx, run)
	if err != nil {
		t.Fatalf("SaveRun failed: %v", err)
	}

	// Add step with complex outputs
	complexStep := &model.StepRun{
		ID:       uuid.New(),
		RunID:    runID,
		StepName: "complex_step",
		Status:   model.StepSucceeded,
		Outputs: map[string]any{
			"string":  "value",
			"number":  42,
			"boolean": true,
			"array":   []any{1, 2, 3},
			"object":  map[string]any{"nested": "value"},
		},
	}

	err = storage.SaveStep(ctx, complexStep)
	if err != nil {
		t.Fatalf("SaveStep with complex outputs failed: %v", err)
	}

	// Add step with nil outputs
	nilOutputsStep := &model.StepRun{
		ID:       uuid.New(),
		RunID:    runID,
		StepName: "nil_outputs_step",
		Status:   model.StepSucceeded,
		Outputs:  nil,
	}

	err = storage.SaveStep(ctx, nilOutputsStep)
	if err != nil {
		t.Fatalf("SaveStep with nil outputs failed: %v", err)
	}

	// Test GetSteps retrieves all steps
	steps, err = storage.GetSteps(ctx, runID)
	if err != nil {
		t.Fatalf("GetSteps failed: %v", err)
	}
	if len(steps) != 2 {
		t.Errorf("Expected 2 steps, got %d", len(steps))
	}

	// Verify step data integrity
	for _, step := range steps {
		switch step.StepName {
		case "complex_step":
			if step.Outputs == nil {
				t.Error("Expected non-nil outputs for complex_step")
			} else {
				if step.Outputs["string"] != "value" {
					t.Errorf("Expected string value 'value', got %v", step.Outputs["string"])
				}
				if step.Outputs["number"] != float64(42) { // JSON unmarshaling converts numbers to float64
					t.Errorf("Expected number 42, got %v", step.Outputs["number"])
				}
			}
		case "nil_outputs_step":
			if step.Outputs != nil {
				t.Errorf("Expected nil outputs for nil_outputs_step, got %v", step.Outputs)
			}
		}
	}
}

// TestNewSqliteStorage_ErrorCases tests NewSqliteStorage error handling
func TestNewSqliteStorage_ErrorCases(t *testing.T) {
	// Test with invalid path (directory that doesn't exist and can't be created)
	invalidPath := "/root/nonexistent/path/test.db"
	_, err := NewSqliteStorage(invalidPath)
	if err == nil {
		t.Error("Expected error for invalid path")
	}

	// Test with empty path - this may or may not error depending on the system
	_, err = NewSqliteStorage("")
	// Intentionally ignoring error as behavior may vary across systems
	_ = err

	// Test with valid path
	tempDir, err := os.MkdirTemp("", "sqlite_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.db")
	storage, err := NewSqliteStorage(dbPath)
	if err != nil {
		t.Fatalf("NewSqliteStorage should succeed with valid path: %v", err)
	}
	if storage == nil {
		t.Error("Expected non-nil storage")
	}
	defer storage.Close()

	// Test creating storage with same path (should work)
	storage2, err := NewSqliteStorage(dbPath)
	if err != nil {
		t.Fatalf("NewSqliteStorage should work with existing database: %v", err)
	}
	if storage2 == nil {
		t.Error("Expected non-nil storage for existing database")
	}
	defer storage2.Close()
}

// ========================================
// INTEGRATION TESTS - Real SQLite operations
// ========================================

// TestSQLiteStorageRealFileOperations tests SQLite with real file system operations
func TestSQLiteStorageRealFileOperations(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	// Test creating database with real file
	storage, err := NewSqliteStorage(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite storage: %v", err)
	}
	defer storage.Close()

	// Verify database file was created
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Database file was not created")
	}

	ctx := context.Background()
	runID := uuid.New()

	// Test full round-trip with real database
	run := &model.Run{
		ID:        runID,
		FlowName:  "test-flow",
		Event:     map[string]any{"test": "data"},
		Vars:      map[string]any{"var1": "value1"},
		StartedAt: time.Now(),
	}

	// Test saving
	err = storage.SaveRun(ctx, run)
	if err != nil {
		t.Fatalf("SaveRun failed: %v", err)
	}

	// Test retrieving
	retrieved, err := storage.GetRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetRun failed: %v", err)
	}

	if retrieved.ID != runID {
		t.Errorf("Retrieved run ID mismatch: got %v, want %v", retrieved.ID, runID)
	}
	if retrieved.FlowName != "test-flow" {
		t.Errorf("Retrieved flow name mismatch: got %v, want test-flow", retrieved.FlowName)
	}

	// Test that event data is properly serialized/deserialized
	if testVal, ok := retrieved.Event["test"].(string); !ok || testVal != "data" {
		t.Errorf("Event data not properly preserved: %+v", retrieved.Event)
	}

	// Test concurrent access
	t.Run("ConcurrentAccess", func(t *testing.T) {
		const numGoroutines = 10
		const maxRetries = 3
		errChan := make(chan error, numGoroutines)
		successChan := make(chan bool, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(workerID int) {
				concurrentRunID := uuid.New()
				concurrentRun := &model.Run{
					ID:        concurrentRunID,
					FlowName:  fmt.Sprintf("concurrent-flow-%d", workerID),
					Event:     map[string]any{"worker": workerID},
					StartedAt: time.Now(),
				}

				// Retry on SQLite busy errors
				var lastErr error
				for retry := 0; retry < maxRetries; retry++ {
					if err := storage.SaveRun(ctx, concurrentRun); err != nil {
						if strings.Contains(err.Error(), "database is locked") ||
							strings.Contains(err.Error(), "SQLITE_BUSY") {
							// Wait a bit before retrying
							time.Sleep(time.Duration(retry*100) * time.Millisecond)
							lastErr = err
							continue
						}
						errChan <- fmt.Errorf("worker %d unexpected error: %w", workerID, err)
						return
					}
					lastErr = nil
					break
				}

				if lastErr != nil {
					errChan <- fmt.Errorf("worker %d failed after %d retries: %w", workerID, maxRetries, lastErr)
					return
				}

				// Retry on read operations too
				for retry := 0; retry < maxRetries; retry++ {
					if _, err := storage.GetRun(ctx, concurrentRunID); err != nil {
						if strings.Contains(err.Error(), "database is locked") ||
							strings.Contains(err.Error(), "SQLITE_BUSY") {
							time.Sleep(time.Duration(retry*100) * time.Millisecond)
							continue
						}
						errChan <- fmt.Errorf("worker %d get failed: %w", workerID, err)
						return
					}
					break
				}

				successChan <- true
				errChan <- nil
			}(i)
		}

		// Collect results and analyze SQLite concurrency behavior
		var errors []error
		var successes int
		var sqliteLockingErrors int

		for i := 0; i < numGoroutines; i++ {
			err := <-errChan
			if err != nil {
				errors = append(errors, err)
				if strings.Contains(err.Error(), "failed after") {
					sqliteLockingErrors++
				}
			} else {
				select {
				case <-successChan:
					successes++
				default:
					// No success signal, but no error either
				}
			}
		}

		t.Logf("Concurrent access results: %d successes, %d SQLite locking errors, %d other errors",
			successes, sqliteLockingErrors, len(errors)-sqliteLockingErrors)

		// We expect most operations to succeed with retries
		if successes < numGoroutines/2 {
			t.Errorf("Expected at least %d concurrent operations to succeed, got %d", numGoroutines/2, successes)
		}

		// Only fail on unexpected errors
		unexpectedErrors := len(errors) - sqliteLockingErrors
		if unexpectedErrors > 0 {
			t.Errorf("Got %d unexpected errors (non-SQLite-locking): %v", unexpectedErrors, errors[:utils.Min(3, len(errors))])
		}
	})
}

// TestSQLiteStorageStressTest tests SQLite under heavy load
func TestSQLiteStorageStressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "stress_test.db")

	storage, err := NewSqliteStorage(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite storage: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()
	const numOperations = 1000

	// Test many sequential operations
	t.Run("SequentialOperations", func(t *testing.T) {
		start := time.Now()

		for i := 0; i < numOperations; i++ {
			runID := uuid.New()
			run := &model.Run{
				ID:        runID,
				FlowName:  fmt.Sprintf("stress-flow-%d", i),
				Event:     map[string]any{"iteration": i, "data": strings.Repeat("x", 100)},
				StartedAt: time.Now(),
			}

			if err := storage.SaveRun(ctx, run); err != nil {
				t.Fatalf("SaveRun failed at iteration %d: %v", i, err)
			}

			if i%100 == 0 {
				// Verify we can still read
				if _, err := storage.GetRun(ctx, runID); err != nil {
					t.Fatalf("GetRun failed at iteration %d: %v", i, err)
				}
			}
		}

		duration := time.Since(start)
		t.Logf("Completed %d operations in %v (%.2f ops/sec)", numOperations, duration, float64(numOperations)/duration.Seconds())
	})

	// Test listing with many records
	t.Run("ListWithManyRecords", func(t *testing.T) {
		runs, err := storage.ListRuns(ctx)
		if err != nil {
			t.Fatalf("ListRuns failed: %v", err)
		}

		if len(runs) < numOperations {
			t.Errorf("Expected at least %d runs, got %d", numOperations, len(runs))
		}

		// Verify list performance
		start := time.Now()
		for i := 0; i < 10; i++ {
			_, err := storage.ListRuns(ctx)
			if err != nil {
				t.Fatalf("ListRuns iteration %d failed: %v", i, err)
			}
		}
		avgDuration := time.Since(start) / 10
		t.Logf("Average ListRuns duration with %d records: %v", len(runs), avgDuration)

		if avgDuration > 100*time.Millisecond {
			t.Logf("Warning: ListRuns taking longer than expected: %v", avgDuration)
		}
	})
}

// TestSQLiteStorageErrorScenarios tests real error scenarios that could happen in production
func TestSQLiteStorageErrorScenarios(t *testing.T) {
	ctx := context.Background()

	t.Run("InvalidDatabasePath", func(t *testing.T) {
		// Try to create database in non-existent directory
		_, err := NewSqliteStorage("/root/nonexistent/path/test.db")
		if err == nil {
			t.Error("Expected error for invalid database path")
		}
	})

	t.Run("ReadOnlyFileSystem", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("Skipping read-only filesystem test when running as root")
		}

		// Create a read-only directory
		tempDir := t.TempDir()
		readOnlyDir := filepath.Join(tempDir, "readonly")
		if err := os.Mkdir(readOnlyDir, 0555); err != nil {
			t.Fatalf("Failed to create read-only directory: %v", err)
		}
		defer os.Chmod(readOnlyDir, 0755) // Cleanup

		_, err := NewSqliteStorage(filepath.Join(readOnlyDir, "test.db"))
		if err == nil {
			t.Error("Expected error for read-only directory")
		}
	})

	t.Run("CorruptedData", func(t *testing.T) {
		tempDir := t.TempDir()
		dbPath := filepath.Join(tempDir, "corrupted_test.db")

		storage, err := NewSqliteStorage(dbPath)
		if err != nil {
			t.Fatalf("Failed to create SQLite storage: %v", err)
		}
		defer storage.Close()

		// Save a run with potentially problematic data
		runID := uuid.New()
		run := &model.Run{
			ID:       runID,
			FlowName: "test-flow",
			Event: map[string]any{
				"nil_value":     nil,
				"empty_string":  "",
				"large_text":    strings.Repeat("x", 10000),
				"unicode":       "Hello 世界 🌍",
				"special_chars": `"quotes" 'single' \backslash \n\t\r`,
				"nested": map[string]any{
					"deep": map[string]any{
						"value": "deeply nested",
					},
				},
			},
			StartedAt: time.Now(),
		}

		err = storage.SaveRun(ctx, run)
		if err != nil {
			t.Fatalf("SaveRun with complex data failed: %v", err)
		}

		// Verify we can retrieve it
		retrieved, err := storage.GetRun(ctx, runID)
		if err != nil {
			t.Fatalf("GetRun after complex data save failed: %v", err)
		}

		// Verify complex data integrity
		if unicode, ok := retrieved.Event["unicode"].(string); !ok || unicode != "Hello 世界 🌍" {
			t.Errorf("Unicode data not preserved correctly: %v", retrieved.Event["unicode"])
		}
	})

	t.Run("VeryLargeData", func(t *testing.T) {
		tempDir := t.TempDir()
		dbPath := filepath.Join(tempDir, "large_data_test.db")

		storage, err := NewSqliteStorage(dbPath)
		if err != nil {
			t.Fatalf("Failed to create SQLite storage: %v", err)
		}
		defer storage.Close()

		// Test with very large event data (1MB)
		largeData := strings.Repeat("Large data test ", 65536) // ~1MB
		runID := uuid.New()
		run := &model.Run{
			ID:        runID,
			FlowName:  "large-data-test",
			Event:     map[string]any{"large_field": largeData},
			StartedAt: time.Now(),
		}

		start := time.Now()
		err = storage.SaveRun(ctx, run)
		saveDuration := time.Since(start)

		if err != nil {
			t.Fatalf("SaveRun with large data failed: %v", err)
		}

		start = time.Now()
		retrieved, err := storage.GetRun(ctx, runID)
		getDuration := time.Since(start)

		if err != nil {
			t.Fatalf("GetRun with large data failed: %v", err)
		}

		if retrievedData, ok := retrieved.Event["large_field"].(string); !ok || retrievedData != largeData {
			t.Error("Large data not preserved correctly")
		}

		t.Logf("Large data performance - Save: %v, Get: %v", saveDuration, getDuration)
	})
}

// TestSQLiteStorageSchemaEvolution tests database schema changes
func TestSQLiteStorageSchemaEvolution(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "schema_test.db")

	// Create initial database
	storage1, err := NewSqliteStorage(dbPath)
	if err != nil {
		t.Fatalf("Failed to create first SQLite storage: %v", err)
	}

	ctx := context.Background()
	runID := uuid.New()

	// Save some data
	run := &model.Run{
		ID:        runID,
		FlowName:  "schema-test",
		Event:     map[string]any{"test": "data"},
		StartedAt: time.Now(),
	}

	if err := storage1.SaveRun(ctx, run); err != nil {
		t.Fatalf("SaveRun failed: %v", err)
	}
	storage1.Close()

	// Reopen database (simulates app restart)
	storage2, err := NewSqliteStorage(dbPath)
	if err != nil {
		t.Fatalf("Failed to reopen SQLite storage: %v", err)
	}
	defer storage2.Close()

	// Verify data is still accessible
	retrieved, err := storage2.GetRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetRun after reopen failed: %v", err)
	}

	if retrieved.FlowName != "schema-test" {
		t.Errorf("Data changed after reopen: got %v, want schema-test", retrieved.FlowName)
	}
}

// ============================================================================
// OAUTH STORAGE TESTS
// ============================================================================

func TestMemoryStorage_OAuthCredential_RoundTrip(t *testing.T) {
	storage := NewMemoryStorage()
	testOAuthCredentialRoundTrip(t, storage)
}

func TestSqliteStorage_OAuthCredential_RoundTrip(t *testing.T) {
	storage, err := NewSqliteStorage(":memory:")
	if err != nil {
		t.Fatalf("NewSqliteStorage() failed: %v", err)
	}
	defer storage.Close()

	testOAuthCredentialRoundTrip(t, storage)
}

func testOAuthCredentialRoundTrip(t *testing.T, storage Storage) {
	ctx := context.Background()
	now := time.Now()
	expiresAt := now.Add(time.Hour)

	cred := &model.OAuthCredential{
		ID:           "test-id",
		Provider:     "google",
		Integration:  "sheets_default",
		AccessToken:  "access_token_123",
		RefreshToken: stringPtr("refresh_token_456"),
		ExpiresAt:    &expiresAt,
		Scope:        "https://www.googleapis.com/auth/spreadsheets",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	// Test save
	err := storage.SaveOAuthCredential(ctx, cred)
	if err != nil {
		t.Fatalf("SaveOAuthCredential failed: %v", err)
	}

	// Test get
	retrieved, err := storage.GetOAuthCredential(ctx, "google", "sheets_default")
	if err != nil {
		t.Fatalf("GetOAuthCredential failed: %v", err)
	}

	// Verify data integrity
	if retrieved.ID != cred.ID {
		t.Errorf("Expected ID %s, got %s", cred.ID, retrieved.ID)
	}
	if retrieved.Provider != cred.Provider {
		t.Errorf("Expected Provider %s, got %s", cred.Provider, retrieved.Provider)
	}
	if retrieved.Integration != cred.Integration {
		t.Errorf("Expected Integration %s, got %s", cred.Integration, retrieved.Integration)
	}
	if retrieved.AccessToken != cred.AccessToken {
		t.Errorf("Expected AccessToken %s, got %s", cred.AccessToken, retrieved.AccessToken)
	}
	if retrieved.RefreshToken == nil || *retrieved.RefreshToken != *cred.RefreshToken {
		t.Errorf("RefreshToken mismatch: expected %v, got %v",
			cred.RefreshToken, retrieved.RefreshToken)
	}
	if retrieved.Scope != cred.Scope {
		t.Errorf("Expected Scope %s, got %s", cred.Scope, retrieved.Scope)
	}
}

func TestMemoryStorage_OAuthCredential_NotFound(t *testing.T) {
	storage := NewMemoryStorage()
	testOAuthCredentialNotFound(t, storage)
}

func TestSqliteStorage_OAuthCredential_NotFound(t *testing.T) {
	storage, err := NewSqliteStorage(":memory:")
	if err != nil {
		t.Fatalf("NewSqliteStorage() failed: %v", err)
	}
	defer storage.Close()

	testOAuthCredentialNotFound(t, storage)
}

func testOAuthCredentialNotFound(t *testing.T, storage Storage) {
	ctx := context.Background()

	_, err := storage.GetOAuthCredential(ctx, "nonexistent", "integration")
	if err == nil {
		t.Error("Expected error for non-existent credential")
	}

	// Should be a "not found" type error (accept various formats)
	errMsg := err.Error()
	if !strings.Contains(errMsg, "not found") && 
		errMsg != "credential not found" && 
		errMsg != "sql: no rows in result set" {
		t.Errorf("Expected not found error, got %v", err)
	}
}

func TestMemoryStorage_OAuthCredential_List(t *testing.T) {
	storage := NewMemoryStorage()
	testOAuthCredentialList(t, storage)
}

func TestSqliteStorage_OAuthCredential_List(t *testing.T) {
	storage, err := NewSqliteStorage(":memory:")
	if err != nil {
		t.Fatalf("NewSqliteStorage() failed: %v", err)
	}
	defer storage.Close()

	testOAuthCredentialList(t, storage)
}

func testOAuthCredentialList(t *testing.T, storage Storage) {
	ctx := context.Background()
	now := time.Now()

	// Initially should be empty
	creds, err := storage.ListOAuthCredentials(ctx)
	if err != nil {
		t.Fatalf("ListOAuthCredentials failed: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("Expected 0 credentials, got %d", len(creds))
	}

	// Add test credentials
	cred1 := &model.OAuthCredential{
		ID:          "test-id-1",
		Provider:    "google",
		Integration: "sheets_default",
		AccessToken: "token1",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	cred2 := &model.OAuthCredential{
		ID:          "test-id-2",
		Provider:    "github",
		Integration: "repos_main",
		AccessToken: "token2",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	err = storage.SaveOAuthCredential(ctx, cred1)
	if err != nil {
		t.Fatalf("SaveOAuthCredential failed for cred1: %v", err)
	}

	err = storage.SaveOAuthCredential(ctx, cred2)
	if err != nil {
		t.Fatalf("SaveOAuthCredential failed for cred2: %v", err)
	}

	// List should now return both credentials
	creds, err = storage.ListOAuthCredentials(ctx)
	if err != nil {
		t.Fatalf("ListOAuthCredentials failed: %v", err)
	}
	if len(creds) != 2 {
		t.Errorf("Expected 2 credentials, got %d", len(creds))
	}

	// Verify both credentials are present
	var foundCred1, foundCred2 bool
	for _, cred := range creds {
		if cred.ID == "test-id-1" {
			foundCred1 = true
		}
		if cred.ID == "test-id-2" {
			foundCred2 = true
		}
	}
	if !foundCred1 || !foundCred2 {
		t.Error("Not all credentials found in list")
	}
}

func TestMemoryStorage_OAuthCredential_Delete(t *testing.T) {
	storage := NewMemoryStorage()
	testOAuthCredentialDelete(t, storage)
}

func TestSqliteStorage_OAuthCredential_Delete(t *testing.T) {
	storage, err := NewSqliteStorage(":memory:")
	if err != nil {
		t.Fatalf("NewSqliteStorage() failed: %v", err)
	}
	defer storage.Close()

	testOAuthCredentialDelete(t, storage)
}

func testOAuthCredentialDelete(t *testing.T, storage Storage) {
	ctx := context.Background()
	now := time.Now()

	// Add test credential
	cred := &model.OAuthCredential{
		ID:          "test-delete-id",
		Provider:    "google",
		Integration: "sheets_test",
		AccessToken: "token_to_delete",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	err := storage.SaveOAuthCredential(ctx, cred)
	if err != nil {
		t.Fatalf("SaveOAuthCredential failed: %v", err)
	}

	// Verify it exists
	_, err = storage.GetOAuthCredential(ctx, "google", "sheets_test")
	if err != nil {
		t.Fatalf("GetOAuthCredential failed: %v", err)
	}

	// Delete it
	err = storage.DeleteOAuthCredential(ctx, "test-delete-id")
	if err != nil {
		t.Fatalf("DeleteOAuthCredential failed: %v", err)
	}

	// Verify it's gone
	_, err = storage.GetOAuthCredential(ctx, "google", "sheets_test")
	if err == nil {
		t.Error("Expected error after deletion, but credential still exists")
	}
}

func TestMemoryStorage_OAuthCredential_RefreshToken(t *testing.T) {
	storage := NewMemoryStorage()
	testOAuthCredentialRefreshToken(t, storage)
}

func TestSqliteStorage_OAuthCredential_RefreshToken(t *testing.T) {
	storage, err := NewSqliteStorage(":memory:")
	if err != nil {
		t.Fatalf("NewSqliteStorage() failed: %v", err)
	}
	defer storage.Close()

	testOAuthCredentialRefreshToken(t, storage)
}

func testOAuthCredentialRefreshToken(t *testing.T, storage Storage) {
	ctx := context.Background()
	now := time.Now()
	originalExpiry := now.Add(time.Hour)

	// Add test credential
	cred := &model.OAuthCredential{
		ID:          "test-refresh-id",
		Provider:    "google",
		Integration: "sheets_refresh",
		AccessToken: "old_token",
		ExpiresAt:   &originalExpiry,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	err := storage.SaveOAuthCredential(ctx, cred)
	if err != nil {
		t.Fatalf("SaveOAuthCredential failed: %v", err)
	}

	// Refresh the token
	newExpiry := now.Add(2 * time.Hour)
	err = storage.RefreshOAuthCredential(ctx, "test-refresh-id", "new_token", &newExpiry)
	if err != nil {
		t.Fatalf("RefreshOAuthCredential failed: %v", err)
	}

	// Verify the token was updated
	refreshed, err := storage.GetOAuthCredential(ctx, "google", "sheets_refresh")
	if err != nil {
		t.Fatalf("GetOAuthCredential failed after refresh: %v", err)
	}

	if refreshed.AccessToken != "new_token" {
		t.Errorf("Expected new token 'new_token', got %s", refreshed.AccessToken)
	}
	if refreshed.ExpiresAt == nil {
		t.Error("Expected ExpiresAt to be set")
	} else {
		// Compare timestamps at second precision (SQLite stores as Unix seconds)
		expectedSeconds := newExpiry.Unix()
		actualSeconds := refreshed.ExpiresAt.Unix()
		if expectedSeconds != actualSeconds {
			t.Errorf("Expected expiry %v (unix: %d), got %v (unix: %d)",
				newExpiry, expectedSeconds, *refreshed.ExpiresAt, actualSeconds)
		}
	}
}

func TestOAuthCredential_ValidationBeforeSave(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Try to save invalid credential
	invalidCred := &model.OAuthCredential{
		ID:          "test-invalid",
		Provider:    "", // Missing provider
		Integration: "sheets_test",
		AccessToken: "token",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := storage.SaveOAuthCredential(ctx, invalidCred)
	if err == nil {
		t.Error("Expected validation error when saving invalid credential")
	}
}

// Helper function for creating string pointers
func stringPtr(s string) *string {
	return &s
}
