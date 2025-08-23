package storage

import (
	"context"
	"database/sql"
	"maps"
	"sort"
	"sync"

	"github.com/beemflow/beemflow/model"
	"github.com/google/uuid"
)

// MemoryStorage implements Storage in-memory (for fallback/dev mode).
type MemoryStorage struct {
	runs   map[uuid.UUID]*model.Run
	steps  map[uuid.UUID][]*model.StepRun // runID -> steps
	mu     sync.RWMutex                   // RWMutex is sufficient for most use cases; consider context-aware primitives if high concurrency or cancellation is needed.
	paused map[string]any                 // token -> paused run
}

var _ Storage = (*MemoryStorage)(nil)

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		runs:   make(map[uuid.UUID]*model.Run),
		steps:  make(map[uuid.UUID][]*model.StepRun),
		paused: make(map[string]any),
	}
}

func (m *MemoryStorage) SaveRun(ctx context.Context, run *model.Run) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs[run.ID] = run
	return nil
}

func (m *MemoryStorage) GetRun(ctx context.Context, id uuid.UUID) (*model.Run, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	run, ok := m.runs[id]
	if !ok {
		return nil, sql.ErrNoRows
	}
	return run, nil
}

func (m *MemoryStorage) SaveStep(ctx context.Context, step *model.StepRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.steps[step.RunID] = append(m.steps[step.RunID], step)
	return nil
}

func (m *MemoryStorage) GetSteps(ctx context.Context, runID uuid.UUID) ([]*model.StepRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.steps[runID], nil
}

func (m *MemoryStorage) RegisterWait(ctx context.Context, token uuid.UUID, wakeAt *int64) error {
	return nil
}

func (m *MemoryStorage) ResolveWait(ctx context.Context, token uuid.UUID) (*model.Run, error) {
	return nil, nil
}

func (m *MemoryStorage) ListRuns(ctx context.Context) ([]*model.Run, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []*model.Run{} // Initialize as empty slice instead of nil
	for _, run := range m.runs {
		out = append(out, run)
	}
	// Sort by StartedAt DESC to match SQL implementations
	sort.Slice(out, func(i, j int) bool {
		return out[i].StartedAt.After(out[j].StartedAt)
	})
	return out, nil
}

func (m *MemoryStorage) SavePausedRun(ctx context.Context, token string, paused any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.paused[token] = paused
	return nil
}

func (m *MemoryStorage) LoadPausedRuns(ctx context.Context) (map[string]any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]any, len(m.paused))
	maps.Copy(out, m.paused)
	return out, nil
}

func (m *MemoryStorage) DeletePausedRun(ctx context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.paused, token)
	return nil
}

func (m *MemoryStorage) DeleteRun(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.runs, id)
	delete(m.steps, id)
	return nil
}

// GetLatestRunByFlowName retrieves the most recent run for a given flow name
func (m *MemoryStorage) GetLatestRunByFlowName(ctx context.Context, flowName string) (*model.Run, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var latest *model.Run
	for _, run := range m.runs {
		if run.FlowName == flowName {
			if latest == nil || run.StartedAt.After(latest.StartedAt) {
				latest = run
			}
		}
	}

	if latest == nil {
		return nil, sql.ErrNoRows
	}
	return latest, nil
}
