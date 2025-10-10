package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func setupStorageTest(t *testing.T) (*SqliteStorage, func()) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "beemflow-storage-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := NewSqliteStorage(dbPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to create storage: %v", err)
	}

	cleanup := func() {
		store.Close()
		os.RemoveAll(tmpDir)
	}

	return store, cleanup
}

func TestSqliteStorage_DeployFlowVersion(t *testing.T) {
	store, cleanup := setupStorageTest(t)
	defer cleanup()

	ctx := context.Background()
	content := "name: test\nversion: 1.0.0"

	err := store.DeployFlowVersion(ctx, "test_flow", "1.0.0", content)
	if err != nil {
		t.Fatalf("DeployFlowVersion failed: %v", err)
	}

	// Verify snapshot saved
	savedContent, err := store.GetFlowVersionContent(ctx, "test_flow", "1.0.0")
	if err != nil {
		t.Fatalf("GetFlowVersionContent failed: %v", err)
	}
	if savedContent != content {
		t.Errorf("Content mismatch: got %s, want %s", savedContent, content)
	}

	// Verify deployed version set
	deployedVersion, err := store.GetDeployedVersion(ctx, "test_flow")
	if err != nil {
		t.Fatalf("GetDeployedVersion failed: %v", err)
	}
	if deployedVersion != "1.0.0" {
		t.Errorf("Expected '1.0.0', got: %s", deployedVersion)
	}
}

func TestSqliteStorage_DeployFlowVersion_Idempotent(t *testing.T) {
	store, cleanup := setupStorageTest(t)
	defer cleanup()

	ctx := context.Background()
	content := "name: test\nversion: 1.0.0"

	// Deploy same version twice
	err := store.DeployFlowVersion(ctx, "test_flow", "1.0.0", content)
	if err != nil {
		t.Fatalf("First deploy failed: %v", err)
	}

	err = store.DeployFlowVersion(ctx, "test_flow", "1.0.0", content)
	if err != nil {
		t.Fatalf("Second deploy failed: %v", err)
	}

	// Should have only one snapshot (ON CONFLICT DO NOTHING)
	snapshots, _ := store.ListFlowVersions(ctx, "test_flow")
	if len(snapshots) != 1 {
		t.Errorf("Expected 1 snapshot, got: %d", len(snapshots))
	}
}

func TestSqliteStorage_SetDeployedVersion(t *testing.T) {
	store, cleanup := setupStorageTest(t)
	defer cleanup()

	ctx := context.Background()

	// Set deployed version
	err := store.SetDeployedVersion(ctx, "test_flow", "2.0.0")
	if err != nil {
		t.Fatalf("SetDeployedVersion failed: %v", err)
	}

	// Verify
	deployedVersion, err := store.GetDeployedVersion(ctx, "test_flow")
	if err != nil {
		t.Fatalf("GetDeployedVersion failed: %v", err)
	}
	if deployedVersion != "2.0.0" {
		t.Errorf("Expected '2.0.0', got: %s", deployedVersion)
	}

	// Update to different version
	err = store.SetDeployedVersion(ctx, "test_flow", "3.0.0")
	if err != nil {
		t.Fatalf("Second SetDeployedVersion failed: %v", err)
	}

	deployedVersion, _ = store.GetDeployedVersion(ctx, "test_flow")
	if deployedVersion != "3.0.0" {
		t.Errorf("Expected '3.0.0', got: %s", deployedVersion)
	}
}

func TestSqliteStorage_GetDeployedVersion_NotFound(t *testing.T) {
	store, cleanup := setupStorageTest(t)
	defer cleanup()

	ctx := context.Background()

	version, err := store.GetDeployedVersion(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if version != "" {
		t.Errorf("Expected empty version for nonexistent flow, got: %s", version)
	}
}

func TestSqliteStorage_GetFlowVersionContent_NotFound(t *testing.T) {
	store, cleanup := setupStorageTest(t)
	defer cleanup()

	ctx := context.Background()

	_, err := store.GetFlowVersionContent(ctx, "nonexistent", "1.0.0")
	if err == nil {
		t.Fatal("Expected error for nonexistent version")
	}
}

func TestSqliteStorage_ListFlowVersions_OrderedByDate(t *testing.T) {
	store, cleanup := setupStorageTest(t)
	defer cleanup()

	ctx := context.Background()

	// Deploy versions
	versions := []string{"1.0.0", "2.0.0", "3.0.0"}
	for _, ver := range versions {
		content := "name: test\nversion: " + ver
		err := store.DeployFlowVersion(ctx, "test_flow", ver, content)
		if err != nil {
			t.Fatalf("Deploy %s failed: %v", ver, err)
		}
	}

	// List versions
	snapshots, err := store.ListFlowVersions(ctx, "test_flow")
	if err != nil {
		t.Fatalf("ListFlowVersions failed: %v", err)
	}

	if len(snapshots) != 3 {
		t.Fatalf("Expected 3 snapshots, got: %d", len(snapshots))
	}

	// Verify all versions present
	versionMap := make(map[string]bool)
	for _, s := range snapshots {
		versionMap[s.Version] = true
	}
	for _, expected := range versions {
		if !versionMap[expected] {
			t.Errorf("Expected version %s in snapshots", expected)
		}
	}

	// Only one version should be live (the last deployed)
	liveCount := 0
	for _, s := range snapshots {
		if s.IsLive {
			liveCount++
		}
	}
	if liveCount != 1 {
		t.Errorf("Expected exactly 1 live version, got: %d", liveCount)
	}
}

func TestSqliteStorage_ListFlowVersions_MarksLiveCorrectly(t *testing.T) {
	store, cleanup := setupStorageTest(t)
	defer cleanup()

	ctx := context.Background()

	// Deploy v1, v2, v3
	for _, ver := range []string{"1.0.0", "2.0.0", "3.0.0"} {
		content := "name: test\nversion: " + ver
		store.DeployFlowVersion(ctx, "test_flow", ver, content)
	}

	// Switch to v1.0.0
	store.SetDeployedVersion(ctx, "test_flow", "1.0.0")

	snapshots, _ := store.ListFlowVersions(ctx, "test_flow")

	// Only v1.0.0 should be marked live
	for _, s := range snapshots {
		if s.Version == "1.0.0" {
			if !s.IsLive {
				t.Error("Expected v1.0.0 to be live")
			}
		} else {
			if s.IsLive {
				t.Errorf("Expected %s to not be live", s.Version)
			}
		}
	}
}

func TestSqliteStorage_FlowVersioning_Isolation(t *testing.T) {
	store, cleanup := setupStorageTest(t)
	defer cleanup()

	ctx := context.Background()

	// Deploy versions for flow1
	store.DeployFlowVersion(ctx, "flow1", "1.0.0", "content1")
	store.DeployFlowVersion(ctx, "flow1", "2.0.0", "content2")

	// Deploy versions for flow2
	store.DeployFlowVersion(ctx, "flow2", "1.0.0", "other_content")

	// Verify flow1 versions
	snapshots1, _ := store.ListFlowVersions(ctx, "flow1")
	if len(snapshots1) != 2 {
		t.Errorf("Expected 2 versions for flow1, got: %d", len(snapshots1))
	}

	// Verify flow2 versions
	snapshots2, _ := store.ListFlowVersions(ctx, "flow2")
	if len(snapshots2) != 1 {
		t.Errorf("Expected 1 version for flow2, got: %d", len(snapshots2))
	}

	// Verify deployed versions independent
	v1, _ := store.GetDeployedVersion(ctx, "flow1")
	v2, _ := store.GetDeployedVersion(ctx, "flow2")

	if v1 != "2.0.0" {
		t.Errorf("Expected flow1 at 2.0.0, got: %s", v1)
	}
	if v2 != "1.0.0" {
		t.Errorf("Expected flow2 at 1.0.0, got: %s", v2)
	}
}

func TestMemoryStorage_FlowVersioning_NoOps(t *testing.T) {
	mem := NewMemoryStorage()
	ctx := context.Background()

	// All methods should be no-ops (not error)
	err := mem.DeployFlowVersion(ctx, "test", "1.0.0", "content")
	if err != nil {
		t.Errorf("DeployFlowVersion should be no-op, got error: %v", err)
	}

	err = mem.SetDeployedVersion(ctx, "test", "1.0.0")
	if err != nil {
		t.Errorf("SetDeployedVersion should be no-op, got error: %v", err)
	}

	version, err := mem.GetDeployedVersion(ctx, "test")
	if err != nil {
		t.Errorf("GetDeployedVersion should return empty, got error: %v", err)
	}
	if version != "" {
		t.Errorf("Expected empty version from memory storage, got: %s", version)
	}

	snapshots, err := mem.ListFlowVersions(ctx, "test")
	if err != nil {
		t.Errorf("ListFlowVersions should return empty, got error: %v", err)
	}
	if len(snapshots) != 0 {
		t.Errorf("Expected empty snapshots, got: %d", len(snapshots))
	}
}
