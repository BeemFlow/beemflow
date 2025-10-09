package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/beemflow/beemflow/model"
	"github.com/beemflow/beemflow/utils"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// PostgresStorage implements Storage using PostgreSQL as the backend.
// OAuth methods are not implemented - use SQLite storage for OAuth in development.
type PostgresStorage struct {
	db *sql.DB
}

var _ Storage = (*PostgresStorage)(nil)

// NewPostgresStorage creates a new PostgreSQL storage instance.
func NewPostgresStorage(dsn string) (*PostgresStorage, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	if err := createPostgresTables(db); err != nil {
		return nil, err
	}

	return &PostgresStorage{db: db}, nil
}

func createPostgresTables(db *sql.DB) error {
	sqlStmt := `
CREATE TABLE IF NOT EXISTS runs (
	id UUID PRIMARY KEY,
	flow_name TEXT NOT NULL,
	event JSONB,
	vars JSONB,
	status TEXT NOT NULL,
	started_at TIMESTAMPTZ NOT NULL,
	ended_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS steps (
	id UUID PRIMARY KEY,
	run_id UUID NOT NULL,
	step_name TEXT NOT NULL,
	status TEXT NOT NULL,
	started_at TIMESTAMPTZ NOT NULL,
	ended_at TIMESTAMPTZ,
	outputs JSONB,
	error TEXT,
	FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS waits (
	token UUID PRIMARY KEY,
	wake_at BIGINT
);

CREATE TABLE IF NOT EXISTS paused_runs (
	token TEXT PRIMARY KEY,
	flow JSONB NOT NULL,
	step_idx INTEGER NOT NULL,
	step_ctx JSONB NOT NULL,
	outputs JSONB NOT NULL
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_runs_flow_name ON runs(flow_name);
CREATE INDEX IF NOT EXISTS idx_runs_started_at ON runs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_steps_run_id ON steps(run_id);
CREATE INDEX IF NOT EXISTS idx_steps_started_at ON steps(started_at DESC);
`
	_, err := db.Exec(sqlStmt)
	return err
}

func (s *PostgresStorage) SaveRun(ctx context.Context, run *model.Run) error {
	event, vars, err := marshalRunFields(run)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, `
INSERT INTO runs (id, flow_name, event, vars, status, started_at, ended_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT(id) DO UPDATE SET 
	flow_name = EXCLUDED.flow_name,
	event = EXCLUDED.event,
	vars = EXCLUDED.vars,
	status = EXCLUDED.status,
	started_at = EXCLUDED.started_at,
	ended_at = EXCLUDED.ended_at
`, run.ID, run.FlowName, event, vars, run.Status, run.StartedAt, run.EndedAt)
	return err
}

func (s *PostgresStorage) GetRun(ctx context.Context, id uuid.UUID) (*model.Run, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, flow_name, event, vars, status, started_at, ended_at 
FROM runs WHERE id = $1`, id)

	var run model.Run
	var event, vars []byte
	err := row.Scan(&run.ID, &run.FlowName, &event, &vars, &run.Status, &run.StartedAt, &run.EndedAt)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(event, &run.Event); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event: %w", err)
	}
	if err := json.Unmarshal(vars, &run.Vars); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vars: %w", err)
	}

	return &run, nil
}

func (s *PostgresStorage) SaveStep(ctx context.Context, step *model.StepRun) error {
	outputs, err := marshalStepOutputs(step)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, `
INSERT INTO steps (id, run_id, step_name, status, started_at, ended_at, outputs, error)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT(id) DO UPDATE SET 
	run_id = EXCLUDED.run_id,
	step_name = EXCLUDED.step_name,
	status = EXCLUDED.status,
	started_at = EXCLUDED.started_at,
	ended_at = EXCLUDED.ended_at,
	outputs = EXCLUDED.outputs,
	error = EXCLUDED.error
`, step.ID, step.RunID, step.StepName, step.Status, step.StartedAt, step.EndedAt, outputs, step.Error)
	return err
}

func (s *PostgresStorage) GetSteps(ctx context.Context, runID uuid.UUID) ([]*model.StepRun, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, run_id, step_name, status, started_at, ended_at, outputs, error 
FROM steps WHERE run_id = $1 ORDER BY started_at`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var steps []*model.StepRun
	for rows.Next() {
		var step model.StepRun
		var outputs []byte
		if err := rows.Scan(&step.ID, &step.RunID, &step.StepName, &step.Status,
			&step.StartedAt, &step.EndedAt, &outputs, &step.Error); err != nil {
			continue
		}
		if err := unmarshalStepOutputs(outputs, &step); err != nil {
			return nil, err
		}
		steps = append(steps, &step)
	}
	return steps, nil
}

func (s *PostgresStorage) RegisterWait(ctx context.Context, token uuid.UUID, wakeAt *int64) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO waits (token, wake_at) VALUES ($1, $2) 
ON CONFLICT(token) DO UPDATE SET wake_at = EXCLUDED.wake_at`, token, wakeAt)
	return err
}

func (s *PostgresStorage) ResolveWait(ctx context.Context, token uuid.UUID) (*model.Run, error) {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM waits WHERE token = $1`, token); err != nil {
		utils.Warn("Failed to cleanup wait token %s: %v", token.String(), err)
	}
	return nil, nil
}

func (s *PostgresStorage) SavePausedRun(ctx context.Context, token string, paused any) error {
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

	_, err = s.db.ExecContext(ctx, `
INSERT INTO paused_runs (token, flow, step_idx, step_ctx, outputs)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT(token) DO UPDATE SET
	flow = EXCLUDED.flow,
	step_idx = EXCLUDED.step_idx,
	step_ctx = EXCLUDED.step_ctx,
	outputs = EXCLUDED.outputs
`, token, flowBytes, persist.StepIdx, stepCtxBytes, outputsBytes)
	return err
}

func (s *PostgresStorage) LoadPausedRuns(ctx context.Context) (map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT token, flow, step_idx, step_ctx, outputs FROM paused_runs`)
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

		result[token] = map[string]any{
			"flow":     &flow,
			"step_idx": stepIdx,
			"step_ctx": stepCtx,
			"outputs":  outputs,
			"token":    token,
		}
	}
	return result, nil
}

func (s *PostgresStorage) DeletePausedRun(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM paused_runs WHERE token = $1`, token)
	return err
}

func (s *PostgresStorage) ListRuns(ctx context.Context) ([]*model.Run, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, flow_name, event, vars, status, started_at, ended_at 
FROM runs ORDER BY started_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var runs []*model.Run
	for rows.Next() {
		var run model.Run
		var event, vars []byte
		if err := rows.Scan(&run.ID, &run.FlowName, &event, &vars, &run.Status, &run.StartedAt, &run.EndedAt); err != nil {
			continue
		}
		if err := json.Unmarshal(event, &run.Event); err != nil {
			return nil, fmt.Errorf("failed to unmarshal event: %w", err)
		}
		if err := json.Unmarshal(vars, &run.Vars); err != nil {
			return nil, fmt.Errorf("failed to unmarshal vars: %w", err)
		}
		runs = append(runs, &run)
	}
	return runs, nil
}

func (s *PostgresStorage) DeleteRun(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM runs WHERE id = $1`, id)
	return err
}

// GetLatestRunByFlowName retrieves the most recent run for a given flow name
func (s *PostgresStorage) GetLatestRunByFlowName(ctx context.Context, flowName string) (*model.Run, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, flow_name, event, vars, status, started_at, ended_at 
FROM runs 
WHERE flow_name = $1 
ORDER BY started_at DESC 
LIMIT 1`, flowName)

	var run model.Run
	var event, vars []byte
	err := row.Scan(&run.ID, &run.FlowName, &event, &vars, &run.Status, &run.StartedAt, &run.EndedAt)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(event, &run.Event); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event: %w", err)
	}
	if err := json.Unmarshal(vars, &run.Vars); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vars: %w", err)
	}

	return &run, nil
}

// OAuth methods not implemented for PostgreSQL - use SQLite for local development
func (s *PostgresStorage) SaveOAuthCredential(ctx context.Context, cred *model.OAuthCredential) error {
	return errOAuthNotImpl
}
func (s *PostgresStorage) GetOAuthCredential(ctx context.Context, provider, integration string) (*model.OAuthCredential, error) {
	return nil, errOAuthNotImpl
}
func (s *PostgresStorage) ListOAuthCredentials(ctx context.Context) ([]*model.OAuthCredential, error) {
	return nil, errOAuthNotImpl
}
func (s *PostgresStorage) DeleteOAuthCredential(ctx context.Context, id string) error {
	return errOAuthNotImpl
}
func (s *PostgresStorage) RefreshOAuthCredential(ctx context.Context, id string, newToken string, expiresAt *time.Time) error {
	return errOAuthNotImpl
}
func (s *PostgresStorage) SaveOAuthProvider(ctx context.Context, provider *model.OAuthProvider) error {
	return errOAuthNotImpl
}
func (s *PostgresStorage) GetOAuthProvider(ctx context.Context, id string) (*model.OAuthProvider, error) {
	return nil, errOAuthNotImpl
}
func (s *PostgresStorage) ListOAuthProviders(ctx context.Context) ([]*model.OAuthProvider, error) {
	return nil, errOAuthNotImpl
}
func (s *PostgresStorage) DeleteOAuthProvider(ctx context.Context, id string) error {
	return errOAuthNotImpl
}
func (s *PostgresStorage) SaveOAuthClient(ctx context.Context, client *model.OAuthClient) error {
	return errOAuthNotImpl
}
func (s *PostgresStorage) GetOAuthClient(ctx context.Context, id string) (*model.OAuthClient, error) {
	return nil, errOAuthNotImpl
}
func (s *PostgresStorage) ListOAuthClients(ctx context.Context) ([]*model.OAuthClient, error) {
	return nil, errOAuthNotImpl
}
func (s *PostgresStorage) DeleteOAuthClient(ctx context.Context, id string) error {
	return errOAuthNotImpl
}
func (s *PostgresStorage) SaveOAuthToken(ctx context.Context, token *model.OAuthToken) error {
	return errOAuthNotImpl
}
func (s *PostgresStorage) GetOAuthTokenByCode(ctx context.Context, code string) (*model.OAuthToken, error) {
	return nil, errOAuthNotImpl
}
func (s *PostgresStorage) GetOAuthTokenByAccess(ctx context.Context, access string) (*model.OAuthToken, error) {
	return nil, errOAuthNotImpl
}
func (s *PostgresStorage) GetOAuthTokenByRefresh(ctx context.Context, refresh string) (*model.OAuthToken, error) {
	return nil, errOAuthNotImpl
}
func (s *PostgresStorage) DeleteOAuthTokenByCode(ctx context.Context, code string) error {
	return errOAuthNotImpl
}
func (s *PostgresStorage) DeleteOAuthTokenByAccess(ctx context.Context, access string) error {
	return errOAuthNotImpl
}
func (s *PostgresStorage) DeleteOAuthTokenByRefresh(ctx context.Context, refresh string) error {
	return errOAuthNotImpl
}

var errOAuthNotImpl = utils.Errorf("OAuth not implemented for PostgreSQL - use SQLite or memory storage")

// Close closes the underlying PostgreSQL database connection.
func (s *PostgresStorage) Close() error {
	return s.db.Close()
}
