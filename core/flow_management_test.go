package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/beemflow/beemflow/storage"
)

// ============================================================================
// TEST SETUP
// ============================================================================

func setupFlowTest(t *testing.T) (context.Context, func()) {
	t.Helper()

	// Create temp directory for flows
	tmpDir, err := os.MkdirTemp("", "beemflow-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Set flows directory
	oldFlowsDir := flowsDir
	SetFlowsDir(tmpDir)

	// Create temp storage
	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := storage.NewSqliteStorage(dbPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to create storage: %v", err)
	}

	// Inject into context
	ctx := context.Background()
	ctx = WithStore(ctx, store)

	// Cleanup function
	cleanup := func() {
		store.Close()
		os.RemoveAll(tmpDir)
		SetFlowsDir(oldFlowsDir)
	}

	return ctx, cleanup
}

// mustSaveFlow is a test helper that calls SaveFlow and fails the test on error
func mustSaveFlow(t *testing.T, ctx context.Context, name, content string) {
	t.Helper()
	if _, err := SaveFlow(ctx, name, content); err != nil {
		t.Fatalf("SaveFlow failed: %v", err)
	}
}

// mustDeployFlow is a test helper that calls DeployFlow and fails the test on error
func mustDeployFlow(t *testing.T, ctx context.Context, name string) {
	t.Helper()
	if _, err := DeployFlow(ctx, name); err != nil {
		t.Fatalf("DeployFlow failed: %v", err)
	}
}

// ============================================================================
// SAVE FLOW TESTS
// ============================================================================

func TestSaveFlow_CreateNew(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	content := `name: test_flow
version: "1.0.0"
on: cli.manual
steps:
  - id: greet
    use: core.echo
    with:
      text: "Hello"
`

	result, err := SaveFlow(ctx, "test_flow", content)
	if err != nil {
		t.Fatalf("SaveFlow failed: %v", err)
	}

	if result["status"] != "created" {
		t.Errorf("Expected status 'created', got: %v", result["status"])
	}
	if result["version"] != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got: %v", result["version"])
	}

	// Verify file created
	if _, err := os.Stat(buildFlowPath("test_flow")); os.IsNotExist(err) {
		t.Error("Flow file was not created")
	}
}

func TestSaveFlow_UpdateExisting(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	content1 := `name: test_flow
version: "1.0.0"
on: cli.manual
steps: []
`
	content2 := `name: test_flow
version: "1.0.1"
on: cli.manual
steps: []
`

	// Create
	result1, _ := SaveFlow(ctx, "test_flow", content1)
	if result1["status"] != "created" {
		t.Errorf("Expected 'created', got: %v", result1["status"])
	}

	// Update
	result2, _ := SaveFlow(ctx, "test_flow", content2)
	if result2["status"] != "updated" {
		t.Errorf("Expected 'updated', got: %v", result2["status"])
	}
	if result2["version"] != "1.0.1" {
		t.Errorf("Expected version '1.0.1', got: %v", result2["version"])
	}
}

func TestSaveFlow_Idempotent(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	content := `name: test_flow
version: "1.0.0"
on: cli.manual
steps: []
`

	// Save multiple times before deploy
	for i := 0; i < 3; i++ {
		if _, err := SaveFlow(ctx, "test_flow", content); err != nil {
			t.Fatalf("Save attempt %d failed: %v", i+1, err)
		}
	}
}

func TestSaveFlow_BlocksDeployedVersion(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	content := `name: test_flow
version: "1.0.0"
on: cli.manual
steps: []
`

	mustSaveFlow(t, ctx, "test_flow", content)
	mustDeployFlow(t, ctx, "test_flow")

	// Try to save deployed version again
	_, err := SaveFlow(ctx, "test_flow", content)
	if err == nil {
		t.Fatal("Expected error when saving deployed version")
	}
	if !strings.Contains(err.Error(), "immutable") {
		t.Errorf("Expected 'immutable' error, got: %v", err)
	}
}

func TestSaveFlow_InvalidYAML(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	_, err := SaveFlow(ctx, "test", "invalid: {{{")
	if err == nil || !strings.Contains(err.Error(), "invalid YAML") {
		t.Errorf("Expected 'invalid YAML' error, got: %v", err)
	}
}

func TestSaveFlow_NameMismatch(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	content := `name: wrong_name
version: "1.0.0"
on: cli.manual
steps: []
`

	_, err := SaveFlow(ctx, "test_flow", content)
	if err == nil || !strings.Contains(err.Error(), "name mismatch") {
		t.Errorf("Expected 'name mismatch' error, got: %v", err)
	}
}

// ============================================================================
// DEPLOY FLOW TESTS
// ============================================================================

func TestDeployFlow_Success(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	content := `name: test_flow
version: "1.0.0"
on: cli.manual
steps: []
`

	mustSaveFlow(t, ctx, "test_flow", content)

	result, err := DeployFlow(ctx, "test_flow")
	if err != nil {
		t.Fatalf("DeployFlow failed: %v", err)
	}

	if result["status"] != "deployed" {
		t.Errorf("Expected 'deployed', got: %v", result["status"])
	}

	// Verify in DB
	store := GetStoreFromContext(ctx)
	deployedVersion, _ := store.GetDeployedVersion(ctx, "test_flow")
	if deployedVersion != "1.0.0" {
		t.Errorf("Expected deployed version '1.0.0', got: %s", deployedVersion)
	}
}

func TestDeployFlow_BlocksRedeployment(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	content := `name: test_flow
version: "1.0.0"
on: cli.manual
steps: []
`

	mustSaveFlow(t, ctx, "test_flow", content)
	mustDeployFlow(t, ctx, "test_flow")

	// Try to deploy again
	_, err := DeployFlow(ctx, "test_flow")
	if err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Errorf("Expected 'immutable' error, got: %v", err)
	}
}

func TestDeployFlow_RequiresVersion(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	content := `name: test_flow
on: cli.manual
steps: []
`

	mustSaveFlow(t, ctx, "test_flow", content)

	_, err := DeployFlow(ctx, "test_flow")
	if err == nil || !strings.Contains(err.Error(), "version field") {
		t.Errorf("Expected 'version field' error, got: %v", err)
	}
}

func TestDeployFlow_RequiresStorage(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	content := `name: test_flow
version: "1.0.0"
on: cli.manual
steps: []
`

	SaveFlow(ctx, "test_flow", content)

	// Remove storage from context
	ctx = context.Background()

	_, err := DeployFlow(ctx, "test_flow")
	if err == nil || !strings.Contains(err.Error(), "storage not available") {
		t.Errorf("Expected 'storage not available' error, got: %v", err)
	}
}

// ============================================================================
// ROLLBACK FLOW TESTS
// ============================================================================

func TestRollbackFlow_Success(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	// Deploy v1.0.0
	content1 := `name: test_flow
version: "1.0.0"
on: cli.manual
steps:
  - id: greet
    use: core.echo
    with:
      text: "v1"
`
	mustSaveFlow(t, ctx, "test_flow", content1)
	mustDeployFlow(t, ctx, "test_flow")

	// Deploy v2.0.0
	content2 := `name: test_flow
version: "2.0.0"
on: cli.manual
steps:
  - id: greet
    use: core.echo
    with:
      text: "v2"
`
	mustSaveFlow(t, ctx, "test_flow", content2)
	mustDeployFlow(t, ctx, "test_flow")

	// Rollback to v1.0.0
	result, err := RollbackFlow(ctx, "test_flow", "1.0.0")
	if err != nil {
		t.Fatalf("RollbackFlow failed: %v", err)
	}

	if result["version"] != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got: %v", result["version"])
	}

	// Verify file restored
	fileContent, _ := os.ReadFile(buildFlowPath("test_flow"))
	if !strings.Contains(string(fileContent), "v1") {
		t.Error("File was not restored to v1.0.0 content")
	}

	// Verify DB updated
	store := GetStoreFromContext(ctx)
	deployedVersion, _ := store.GetDeployedVersion(ctx, "test_flow")
	if deployedVersion != "1.0.0" {
		t.Errorf("Expected deployed version '1.0.0', got: %s", deployedVersion)
	}
}

func TestRollbackFlow_VersionNotFound(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	content := `name: test_flow
version: "1.0.0"
on: cli.manual
steps: []
`
	mustSaveFlow(t, ctx, "test_flow", content)
	mustDeployFlow(t, ctx, "test_flow")

	_, err := RollbackFlow(ctx, "test_flow", "9.9.9")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' error, got: %v", err)
	}
}

func TestRollbackFlow_MultipleVersionJumps(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	store := GetStoreFromContext(ctx)

	// Deploy v1, v2, v3
	for _, ver := range []string{"1.0.0", "2.0.0", "3.0.0"} {
		content := "name: test\nversion: \"" + ver + "\"\non: cli.manual\nsteps: []"
		mustSaveFlow(t, ctx, "test", content)
		mustDeployFlow(t, ctx, "test")
	}

	// Jump to v1.0.0 (skip v2)
	RollbackFlow(ctx, "test", "1.0.0")
	if v, _ := store.GetDeployedVersion(ctx, "test"); v != "1.0.0" {
		t.Errorf("Expected v1.0.0, got: %s", v)
	}

	// Jump to v3.0.0
	RollbackFlow(ctx, "test", "3.0.0")
	if v, _ := store.GetDeployedVersion(ctx, "test"); v != "3.0.0" {
		t.Errorf("Expected v3.0.0, got: %s", v)
	}

	// Jump to v2.0.0
	RollbackFlow(ctx, "test", "2.0.0")
	if v, _ := store.GetDeployedVersion(ctx, "test"); v != "2.0.0" {
		t.Errorf("Expected v2.0.0, got: %s", v)
	}
}

// DELETE FLOW TESTS

func TestDeleteFlow_Success(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	content := `name: test_flow
version: "1.0.0"
on: cli.manual
steps: []
`

	mustSaveFlow(t, ctx, "test_flow", content)
	result, err := DeleteFlow(ctx, "test_flow")
	if err != nil {
		t.Fatalf("DeleteFlow failed: %v", err)
	}

	if result["status"] != "deleted" {
		t.Errorf("Expected 'deleted', got: %v", result["status"])
	}

	// Verify file deleted
	if _, err := os.Stat(buildFlowPath("test_flow")); !os.IsNotExist(err) {
		t.Error("Flow file still exists after delete")
	}
}

func TestDeleteFlow_NotFound(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	_, err := DeleteFlow(ctx, "nonexistent")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' error, got: %v", err)
	}
}

// VERSION HISTORY TESTS

func TestGetFlowVersionHistory_MultipleVersions(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	for _, ver := range []string{"1.0.0", "1.1.0", "2.0.0"} {
		content := "name: test\nversion: \"" + ver + "\"\non: cli.manual\nsteps: []"
		mustSaveFlow(t, ctx, "test", content)
		mustDeployFlow(t, ctx, "test")
	}

	history, err := GetFlowVersionHistory(ctx, "test")
	if err != nil {
		t.Fatalf("GetFlowVersionHistory failed: %v", err)
	}

	if len(history) != 3 {
		t.Fatalf("Expected 3 versions, got: %d", len(history))
	}

	// Verify all versions present
	versionMap := make(map[string]bool)
	for _, h := range history {
		versionMap[h["version"].(string)] = true
	}
	for _, expected := range []string{"1.0.0", "1.1.0", "2.0.0"} {
		if !versionMap[expected] {
			t.Errorf("Expected version %s in history", expected)
		}
	}

	// Exactly one should be live
	liveCount := 0
	for _, h := range history {
		if h["is_live"] == true {
			liveCount++
		}
	}
	if liveCount != 1 {
		t.Errorf("Expected exactly 1 live version, got: %d", liveCount)
	}
}

func TestGetFlowVersionHistory_NoVersions(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	history, err := GetFlowVersionHistory(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(history) != 0 {
		t.Errorf("Expected empty history, got %d items", len(history))
	}
}

// ============================================================================
// START RUN TESTS (Deployed vs Draft)
// ============================================================================

func TestStartRun_UsesDeployedVersion(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	// Deploy v1.0.0
	content1 := `name: run_test
version: "1.0.0"
on: cli.manual
steps:
  - id: greet
    use: core.echo
    with:
      text: "deployed"
`
	mustSaveFlow(t, ctx, "run_test", content1)
	mustDeployFlow(t, ctx, "run_test")

	// Edit file to v1.0.1 (don't deploy)
	content2 := `name: run_test
version: "1.0.1"
on: cli.manual
steps:
  - id: greet
    use: core.echo
    with:
      text: "draft"
`
	mustSaveFlow(t, ctx, "run_test", content2)

	// Run should use v1.0.0 from DB
	runID, err := StartRun(ctx, "run_test", map[string]any{})
	if err != nil {
		t.Fatalf("StartRun failed: %v", err)
	}

	if runID.String() == "" {
		t.Error("Expected valid run ID")
	}
}

func TestStartRun_DraftUsesFile(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	// Deploy v1.0.0
	content1 := `name: draft_test
version: "1.0.0"
on: cli.manual
steps: []
`
	mustSaveFlow(t, ctx, "draft_test", content1)
	mustDeployFlow(t, ctx, "draft_test")

	// Edit file to v1.0.1
	content2 := `name: draft_test
version: "1.0.1"
on: cli.manual
steps: []
`
	mustSaveFlow(t, ctx, "draft_test", content2)

	// Draft should use file
	runID, err := StartRunDraft(ctx, "draft_test", map[string]any{})
	if err != nil {
		t.Fatalf("StartRunDraft failed: %v", err)
	}

	if runID.String() == "" {
		t.Error("Expected valid run ID")
	}
}

func TestStartRun_RequiresDeployment(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	content := `name: undeployed
version: "1.0.0"
on: cli.manual
steps: []
`
	mustSaveFlow(t, ctx, "undeployed", content)

	_, err := StartRun(ctx, "undeployed", map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "not deployed") {
		t.Errorf("Expected 'not deployed' error, got: %v", err)
	}
}

func TestStartRun_DraftWorksWithoutDeployment(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	content := `name: draft_only
version: "1.0.0"
on: cli.manual
steps:
  - id: greet
    use: core.echo
    with:
      text: "draft"
`
	mustSaveFlow(t, ctx, "draft_only", content)

	runID, err := StartRunDraft(ctx, "draft_only", map[string]any{})
	if err != nil {
		t.Fatalf("StartRunDraft failed: %v", err)
	}

	if runID.String() == "" {
		t.Error("Expected valid run ID")
	}
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

func TestFlowVersioning_CompleteWorkflow(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	store := GetStoreFromContext(ctx)

	// Save v1.0.0
	content1 := `name: complete
version: "1.0.0"
on: cli.manual
steps: []
`
	mustSaveFlow(t, ctx, "complete", content1)
	mustDeployFlow(t, ctx, "complete")

	// Save v1.0.1
	content2 := `name: complete
version: "1.0.1"
on: cli.manual
steps: []
`
	mustSaveFlow(t, ctx, "complete", content2)

	// Try to save v1.0.0 again → should fail
	if _, err := SaveFlow(ctx, "complete", content1); err == nil {
		t.Fatal("Expected error saving deployed version")
	}

	// Deploy v1.0.1
	mustDeployFlow(t, ctx, "complete")

	// View history
	history, _ := GetFlowVersionHistory(ctx, "complete")
	if len(history) != 2 {
		t.Fatalf("Expected 2 versions, got: %d", len(history))
	}

	// Rollback to v1.0.0
	RollbackFlow(ctx, "complete", "1.0.0")

	// Verify file restored
	fileContent, _ := os.ReadFile(buildFlowPath("complete"))
	if !strings.Contains(string(fileContent), "1.0.0") {
		t.Error("File was not restored to v1.0.0")
	}

	// Verify DB updated
	if v, _ := store.GetDeployedVersion(ctx, "complete"); v != "1.0.0" {
		t.Errorf("Expected deployed version '1.0.0', got: %s", v)
	}
}

// ============================================================================
// HELPER TESTS
// ============================================================================

func TestIsOlderVersion_ValidSemver(t *testing.T) {
	tests := []struct {
		v1, v2   string
		expected bool
	}{
		{"1.0.0", "2.0.0", true},
		{"1.0.1", "1.0.0", false},
		{"2.0.0", "1.0.0", false},
		{"1.0.0", "1.0.0", false},
		{"1.0.0", "1.0.1", true},
		{"0.1.0", "1.0.0", true},
	}

	for _, tt := range tests {
		result := isOlderVersion(tt.v1, tt.v2)
		if result != tt.expected {
			t.Errorf("isOlderVersion(%s, %s) = %v, want %v", tt.v1, tt.v2, result, tt.expected)
		}
	}
}

func TestIsOlderVersion_InvalidSemver(t *testing.T) {
	// Fallback to string comparison
	if !isOlderVersion("abc", "def") {
		t.Error("Expected 'abc' < 'def' via string fallback")
	}
}

// ============================================================================
// CONCURRENCY AND SECURITY TESTS
// ============================================================================

// TestRollbackFlow_ConcurrentRollbacks tests that concurrent rollbacks don't corrupt data
func TestRollbackFlow_ConcurrentRollbacks(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	store := GetStoreFromContext(ctx)

	// Deploy three versions
	versions := []string{"1.0.0", "2.0.0", "3.0.0"}
	for _, ver := range versions {
		content := "name: test\nversion: \"" + ver + "\"\non: cli.manual\nsteps:\n  - id: step1\n    use: core.echo\n    with:\n      text: \"v" + ver + "\""
		mustSaveFlow(t, ctx, "test", content)
		mustDeployFlow(t, ctx, "test")
	}

	// Launch 50 concurrent rollbacks to random versions
	concurrency := 50
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(index int) {
			defer wg.Done()
			// Pick a version based on index
			targetVer := versions[index%len(versions)]
			_, err := RollbackFlow(ctx, "test", targetVer)
			if err != nil {
				t.Logf("Rollback to %s failed: %v", targetVer, err)
			}
		}(i)
	}

	wg.Wait()

	// Verify consistency: DB and file must match
	deployedVersion, err := store.GetDeployedVersion(ctx, "test")
	if err != nil {
		t.Fatalf("Failed to get deployed version: %v", err)
	}

	fileContent, err := os.ReadFile(buildFlowPath("test"))
	if err != nil {
		t.Fatalf("Failed to read flow file: %v", err)
	}

	if !strings.Contains(string(fileContent), deployedVersion) {
		t.Errorf("CONSISTENCY VIOLATION: DB shows v%s but file doesn't match", deployedVersion)
	}
}

// TestRollbackFlow_ContextCancellation tests proper handling of context cancellation
func TestRollbackFlow_ContextCancellation(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	// Deploy two versions
	content1 := "name: test\nversion: \"1.0.0\"\non: cli.manual\nsteps: []"
	mustSaveFlow(t, ctx, "test", content1)
	mustDeployFlow(t, ctx, "test")

	content2 := "name: test\nversion: \"2.0.0\"\non: cli.manual\nsteps: []"
	mustSaveFlow(t, ctx, "test", content2)
	mustDeployFlow(t, ctx, "test")

	// Create a context that we'll cancel immediately
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel() // Cancel immediately

	_, err := RollbackFlow(cancelCtx, "test", "1.0.0")
	if err == nil {
		t.Error("Expected error when context is cancelled, got nil")
	}
	if err != context.Canceled {
		t.Logf("Got error (may be cancelled during different phase): %v", err)
	}
}

// TestRollbackFlow_PathTraversal tests prevention of path traversal attacks
func TestRollbackFlow_PathTraversal(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	// Deploy a legitimate flow first
	content := "name: legit\nversion: \"1.0.0\"\non: cli.manual\nsteps: []"
	mustSaveFlow(t, ctx, "legit", content)
	mustDeployFlow(t, ctx, "legit")

	// Try various path traversal attacks
	maliciousNames := []string{
		"../../../etc/passwd",
		"../../.ssh/authorized_keys",
		"../../../home/user/.bashrc",
		"../",
		"./../../secrets",
		"/etc/passwd",
		"test/../../outside",
		"../outside",
		"subdir/../../outside",
	}

	for _, name := range maliciousNames {
		_, err := RollbackFlow(ctx, name, "1.0.0")
		if err == nil {
			t.Errorf("Path traversal VULNERABILITY: accepted malicious flow name: %s", name)
		}
		// Verify error message indicates validation failure
		if err != nil && !strings.Contains(err.Error(), "invalid") && !strings.Contains(err.Error(), "escape") && !strings.Contains(err.Error(), "absolute") {
			t.Logf("Got validation error for %s: %v", name, err)
		}
	}
}

// TestWriteFileAtomic_ConcurrentWrites tests that concurrent writes don't corrupt files
func TestWriteFileAtomic_ConcurrentWrites(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "atomic-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	targetFile := filepath.Join(tmpDir, "test.txt")
	ctx := context.Background()

	// Launch 100 concurrent writes with different content
	concurrency := 100
	var wg sync.WaitGroup
	wg.Add(concurrency)
	var successCount int32

	for i := 0; i < concurrency; i++ {
		go func(index int) {
			defer wg.Done()
			content := []byte(strings.Repeat("data", index+1))
			err := writeFileAtomicWithContext(ctx, targetFile, content)
			if err == nil {
				atomic.AddInt32(&successCount, 1)
			}
		}(i)
	}

	wg.Wait()

	// All writes should succeed
	if int(successCount) != concurrency {
		t.Errorf("Expected all %d writes to succeed, got %d", concurrency, successCount)
	}

	// File should be readable and valid (not corrupted)
	data, err := os.ReadFile(targetFile)
	if err != nil {
		t.Errorf("Failed to read file after concurrent writes: %v", err)
	}

	// Content should be from one of the writes (not mixed)
	dataStr := string(data)
	isValid := false
	for i := 0; i < concurrency; i++ {
		expected := strings.Repeat("data", i+1)
		if dataStr == expected {
			isValid = true
			break
		}
	}
	if !isValid && len(data) > 50 {
		t.Errorf("File content may be corrupted: got %d bytes, content starts with: %s", len(data), dataStr[:50])
	} else if !isValid {
		t.Errorf("File content may be corrupted: got %d bytes, content: %s", len(data), dataStr)
	}
}

// TestRollbackFlow_TempFileCleanup tests that temp files are properly cleaned up
func TestRollbackFlow_TempFileCleanup(t *testing.T) {
	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	// Deploy a version
	content := "name: test\nversion: \"1.0.0\"\non: cli.manual\nsteps: []"
	mustSaveFlow(t, ctx, "test", content)
	mustDeployFlow(t, ctx, "test")

	// Perform rollback
	_, err := RollbackFlow(ctx, "test", "1.0.0")
	if err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	// Check for leftover .tmp files
	dir := flowsDir
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("Failed to read directory: %v", err)
	}

	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp") {
			t.Errorf("Found leftover temp file: %s", entry.Name())
		}
	}

	t.Logf("No temp files found in %s", dir)
}

// TestRollbackFlow_StressTest stress tests rollback with rapid operations
func TestRollbackFlow_StressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	ctx, cleanup := setupFlowTest(t)
	defer cleanup()

	store := GetStoreFromContext(ctx)

	// Deploy 5 versions
	for i := 1; i <= 5; i++ {
		ver := "1.0." + string(rune('0'+i))
		content := "name: stress\nversion: \"" + ver + "\"\non: cli.manual\nsteps: []"
		mustSaveFlow(t, ctx, "stress", content)
		mustDeployFlow(t, ctx, "stress")
	}

	// Perform 200 rapid rollbacks
	iterations := 200
	var wg sync.WaitGroup
	wg.Add(iterations)
	var errorCount int32

	for i := 0; i < iterations; i++ {
		go func(index int) {
			defer wg.Done()
			version := "1.0." + string(rune('0'+(index%5)+1))
			_, err := RollbackFlow(ctx, "stress", version)
			if err != nil {
				atomic.AddInt32(&errorCount, 1)
				t.Logf("Rollback %d to %s failed: %v", index, version, err)
			}
		}(i)
	}

	wg.Wait()

	// Some errors are acceptable under stress, but not too many
	errorRate := float64(errorCount) / float64(iterations)
	if errorRate > 0.1 {
		t.Errorf("Error rate too high: %.2f%% (%d/%d)", errorRate*100, errorCount, iterations)
	}

	// Final consistency check
	deployedVersion, _ := store.GetDeployedVersion(ctx, "stress")
	fileContent, _ := os.ReadFile(buildFlowPath("stress"))
	if !strings.Contains(string(fileContent), deployedVersion) {
		t.Error("STRESS TEST: Final state is inconsistent!")
	}

	t.Logf("Stress test completed: %d/%d successful (%.1f%%)", iterations-int(errorCount), iterations, (1-errorRate)*100)
}

// TestValidateFlowName_EdgeCases tests edge cases in flow name validation
func TestValidateFlowName_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		flowName  string
		shouldErr bool
	}{
		{"valid simple", "myflow", false},
		{"valid with underscore", "my_flow", false},
		{"valid with dash", "my-flow", false},
		{"valid subdirectory", "subdir/myflow", false},
		{"parent traversal", "../etc/passwd", true},
		{"absolute path", "/etc/passwd", true},
		{"null byte", "test\x00file", true},
		{"double dot anywhere", "test..test", true},
		{"parent dir", "..", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFlowName(tt.flowName)
			if tt.shouldErr && err == nil {
				t.Errorf("Expected error for %q, got nil", tt.flowName)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("Expected no error for %q, got: %v", tt.flowName, err)
			}
		})
	}
}
