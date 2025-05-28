package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/awantoch/beemflow/model"
	"github.com/awantoch/beemflow/utils"
	"github.com/google/uuid"
)

// SqliteStorage implements Storage using SQLite as the backend.
type SqliteStorage struct {
	db *sql.DB
}

var _ Storage = (*SqliteStorage)(nil)

type PausedRunPersist struct {
	Flow    *model.Flow    `json:"flow"`
	StepIdx int            `json:"step_idx"`
	StepCtx map[string]any `json:"step_ctx"`
	Outputs map[string]any `json:"outputs"`
	Token   string         `json:"token"`
	RunID   string         `json:"run_id"`
}

func runIDFromStepCtx(ctx map[string]any) string {
	if v, ok := ctx["run_id"]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func NewSqliteStorage(dsn string) (*SqliteStorage, error) {
	// Only create parent directories if not using in-memory SQLite (":memory:").
	if dsn != ":memory:" && dsn != "" {
		dir := filepath.Dir(dsn)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, utils.Errorf("failed to create db directory %q: %w", dir, err)
		}
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// Create tables if not exist
	sqlStmt := `
CREATE TABLE IF NOT EXISTS runs (
	id TEXT PRIMARY KEY,
	flow_name TEXT,
	event JSON,
	vars JSON,
	status TEXT,
	started_at INTEGER,
	ended_at INTEGER
);
CREATE TABLE IF NOT EXISTS steps (
	id TEXT PRIMARY KEY,
	run_id TEXT,
	step_name TEXT,
	status TEXT,
	started_at INTEGER,
	ended_at INTEGER,
	outputs JSON,
	error TEXT
);
CREATE TABLE IF NOT EXISTS waits (
	token TEXT PRIMARY KEY,
	wake_at INTEGER
);
CREATE TABLE IF NOT EXISTS paused_runs (
	token TEXT PRIMARY KEY,
	flow JSON,
	step_idx INTEGER,
	step_ctx JSON,
	outputs JSON
);
`
	_, err = db.Exec(sqlStmt)
	if err != nil {
		return nil, err
	}
	return &SqliteStorage{db: db}, nil
}

func (s *SqliteStorage) SaveRun(ctx context.Context, run *model.Run) error {
	event, err := json.Marshal(run.Event)
	if err != nil {
		return fmt.Errorf("failed to marshal run event: %w", err)
	}
	vars, err := json.Marshal(run.Vars)
	if err != nil {
		return fmt.Errorf("failed to marshal run vars: %w", err)
	}
	var endedAt any
	if run.EndedAt != nil {
		endedAt = run.EndedAt.Unix()
	} else {
		endedAt = nil
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO runs (id, flow_name, event, vars, status, started_at, ended_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET flow_name=excluded.flow_name, event=excluded.event, vars=excluded.vars, status=excluded.status, started_at=excluded.started_at, ended_at=excluded.ended_at
`, run.ID.String(), run.FlowName, event, vars, run.Status, run.StartedAt.Unix(), endedAt)
	return err
}

func (s *SqliteStorage) GetRun(ctx context.Context, id uuid.UUID) (*model.Run, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, flow_name, event, vars, status, started_at, ended_at FROM runs WHERE id=?`, id.String())
	var run model.Run
	var event, vars []byte
	var startedAt, endedAtInt int64
	var endedAtPtr *time.Time
	var endedAt sql.NullInt64
	if err := row.Scan(&run.ID, &run.FlowName, &event, &vars, &run.Status, &startedAt, &endedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(event, &run.Event); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(vars, &run.Vars); err != nil {
		return nil, err
	}
	run.StartedAt = time.Unix(startedAt, 0)
	if endedAt.Valid {
		endedAtInt = endedAt.Int64
		t := time.Unix(endedAtInt, 0)
		endedAtPtr = &t
	}
	run.EndedAt = endedAtPtr
	return &run, nil
}

func (s *SqliteStorage) SaveStep(ctx context.Context, step *model.StepRun) error {
	outputs, err := json.Marshal(step.Outputs)
	if err != nil {
		return fmt.Errorf("failed to marshal step outputs: %w", err)
	}
	var endedAt any
	if step.EndedAt != nil {
		endedAt = step.EndedAt.Unix()
	} else {
		endedAt = nil
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO steps (id, run_id, step_name, status, started_at, ended_at, outputs, error)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET run_id=excluded.run_id, step_name=excluded.step_name, status=excluded.status, started_at=excluded.started_at, ended_at=excluded.ended_at, outputs=excluded.outputs, error=excluded.error
`, step.ID.String(), step.RunID.String(), step.StepName, step.Status, step.StartedAt.Unix(), endedAt, outputs, step.Error)
	return err
}

func (s *SqliteStorage) GetSteps(ctx context.Context, runID uuid.UUID) ([]*model.StepRun, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, run_id, step_name, status, started_at, ended_at, outputs, error FROM steps WHERE run_id=?`, runID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var steps []*model.StepRun
	for rows.Next() {
		var srun model.StepRun
		var runIDStr string
		var outputs []byte
		var startedAt, endedAtInt int64
		var endedAt sql.NullInt64
		var endedAtPtr *time.Time
		if err := rows.Scan(&srun.ID, &runIDStr, &srun.StepName, &srun.Status, &startedAt, &endedAt, &outputs, &srun.Error); err != nil {
			continue
		}
		if parsedID, err := uuid.Parse(runIDStr); err == nil {
			srun.RunID = parsedID
		}
		if err := json.Unmarshal(outputs, &srun.Outputs); err != nil {
			return nil, err
		}
		srun.StartedAt = time.Unix(startedAt, 0)
		if endedAt.Valid {
			endedAtInt = endedAt.Int64
			t := time.Unix(endedAtInt, 0)
			endedAtPtr = &t
		}
		srun.EndedAt = endedAtPtr
		steps = append(steps, &srun)
	}
	return steps, nil
}

func (s *SqliteStorage) RegisterWait(ctx context.Context, token uuid.UUID, wakeAt *int64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO waits (token, wake_at) VALUES (?, ?) ON CONFLICT(token) DO UPDATE SET wake_at=excluded.wake_at`, token.String(), wakeAt)
	return err
}

func (s *SqliteStorage) ResolveWait(ctx context.Context, token uuid.UUID) (*model.Run, error) {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM waits WHERE token=?`, token.String()); err != nil {
		// Log the cleanup error but don't fail the operation
		// The wait token cleanup is not critical to the main operation
		fmt.Printf("Warning: failed to cleanup wait token %s: %v\n", token.String(), err)
	}
	return nil, nil
}

// PausedRunPersist and helpers

func (s *SqliteStorage) SavePausedRun(token string, paused any) error {
	b, err := json.Marshal(paused)
	if err != nil {
		return err
	}
	var persist PausedRunPersist
	if err := json.Unmarshal(b, &persist); err != nil {
		return err
	}
	flowBytes, err := json.Marshal(persist.Flow)
	if err != nil {
		return err
	}
	stepCtxBytes, err := json.Marshal(persist.StepCtx)
	if err != nil {
		return err
	}
	outputsBytes, err := json.Marshal(persist.Outputs)
	if err != nil {
		return err
	}
	if v, ok := persist.StepCtx["run_id"]; ok {
		if s, ok := v.(string); ok {
			persist.RunID = s
		}
	}
	_, err = s.db.Exec(`
	INSERT INTO paused_runs (token, flow, step_idx, step_ctx, outputs)
	VALUES (?, ?, ?, ?, ?)
	ON CONFLICT(token) DO UPDATE SET flow=excluded.flow, step_idx=excluded.step_idx, step_ctx=excluded.step_ctx, outputs=excluded.outputs
	`, token, flowBytes, persist.StepIdx, stepCtxBytes, outputsBytes)
	return err
}

func (s *SqliteStorage) LoadPausedRuns() (map[string]any, error) {
	rows, err := s.db.Query(`SELECT token, flow, step_idx, step_ctx, outputs FROM paused_runs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]any)
	for rows.Next() {
		var token string
		var flowBytes, stepCtxBytes, outputsBytes []byte
		var stepIdx int
		if err := rows.Scan(&token, &flowBytes, &stepIdx, &stepCtxBytes, &outputsBytes); err != nil {
			continue
		}
		var flow model.Flow
		var stepCtx map[string]any
		var outputs map[string]any
		if err := json.Unmarshal(flowBytes, &flow); err != nil {
			continue
		}
		if err := json.Unmarshal(stepCtxBytes, &stepCtx); err != nil {
			continue
		}
		if err := json.Unmarshal(outputsBytes, &outputs); err != nil {
			continue
		}
		result[token] = PausedRunPersist{
			Flow:    &flow,
			StepIdx: stepIdx,
			StepCtx: stepCtx,
			Outputs: outputs,
			Token:   token,
			RunID:   runIDFromStepCtx(stepCtx),
		}
	}
	return result, nil
}

func (s *SqliteStorage) DeletePausedRun(token string) error {
	_, err := s.db.Exec(`DELETE FROM paused_runs WHERE token=?`, token)
	return err
}

func (s *SqliteStorage) GetLatestRunByFlowName(ctx context.Context, flowName string) (*model.Run, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, flow_name, event, vars, status, started_at, ended_at FROM runs WHERE flow_name = ? ORDER BY started_at DESC LIMIT 1`, flowName)
	var run model.Run
	var event, vars []byte
	var startedAt, endedAtInt int64
	var endedAtPtr *time.Time
	var endedAt sql.NullInt64
	if err := row.Scan(&run.ID, &run.FlowName, &event, &vars, &run.Status, &startedAt, &endedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(event, &run.Event); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(vars, &run.Vars); err != nil {
		return nil, err
	}
	run.StartedAt = time.Unix(startedAt, 0)
	if endedAt.Valid {
		endedAtInt = endedAt.Int64
		t := time.Unix(endedAtInt, 0)
		endedAtPtr = &t
	}
	run.EndedAt = endedAtPtr
	return &run, nil
}

func (s *SqliteStorage) ListRuns(ctx context.Context) ([]*model.Run, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, flow_name, event, vars, status, started_at, ended_at FROM runs ORDER BY started_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var runs []*model.Run
	for rows.Next() {
		var run model.Run
		var event, vars []byte
		var startedAt, endedAtInt int64
		var endedAtPtr *time.Time
		var endedAt sql.NullInt64
		if err := rows.Scan(&run.ID, &run.FlowName, &event, &vars, &run.Status, &startedAt, &endedAt); err != nil {
			continue
		}
		if err := json.Unmarshal(event, &run.Event); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(vars, &run.Vars); err != nil {
			return nil, err
		}
		run.StartedAt = time.Unix(startedAt, 0)
		if endedAt.Valid {
			endedAtInt = endedAt.Int64
			t := time.Unix(endedAtInt, 0)
			endedAtPtr = &t
		}
		run.EndedAt = endedAtPtr
		runs = append(runs, &run)
	}
	return runs, nil
}

func (s *SqliteStorage) DeleteRun(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM steps WHERE run_id=?`, id.String())
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM runs WHERE id=?`, id.String())
	return err
}

// Close closes the underlying SQL database connection.
func (s *SqliteStorage) Close() error {
	return s.db.Close()
}
