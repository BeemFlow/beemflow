package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/beemflow/beemflow/model"
	"github.com/beemflow/beemflow/utils"
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

	// Configure SQLite for better concurrent access
	_, err = db.Exec(`
		PRAGMA journal_mode = WAL;
		PRAGMA synchronous = NORMAL;
		PRAGMA busy_timeout = 5000;
		PRAGMA foreign_keys = ON;
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to configure SQLite: %w", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(1) // SQLite only supports one writer at a time
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)

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
CREATE TABLE IF NOT EXISTS oauth_credentials (
	id TEXT PRIMARY KEY,
	provider TEXT NOT NULL,
	integration TEXT NOT NULL,
	access_token TEXT NOT NULL,
	refresh_token TEXT,
	expires_at INTEGER,
	scope TEXT,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	UNIQUE(provider, integration)
);
CREATE TABLE IF NOT EXISTS oauth_providers (
	id TEXT PRIMARY KEY,
	client_id TEXT NOT NULL,
	client_secret TEXT NOT NULL,
	auth_url TEXT NOT NULL,
	token_url TEXT NOT NULL,
	scopes JSON,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_clients (
	id TEXT PRIMARY KEY,
	secret TEXT NOT NULL,
	name TEXT NOT NULL,
	redirect_uris TEXT NOT NULL, -- JSON array
	grant_types TEXT NOT NULL, -- JSON array
	response_types TEXT NOT NULL, -- JSON array
	scope TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
	id TEXT PRIMARY KEY,
	client_id TEXT NOT NULL,
	user_id TEXT,
	redirect_uri TEXT,
	scope TEXT,
	code TEXT UNIQUE,
	code_create_at INTEGER,
	code_expires_in INTEGER,
	access TEXT UNIQUE,
	access_create_at INTEGER,
	access_expires_in INTEGER,
	refresh TEXT UNIQUE,
	refresh_create_at INTEGER,
	refresh_expires_in INTEGER,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS deployed_flows (
	flow_name TEXT PRIMARY KEY,
	deployed_version TEXT NOT NULL,
	deployed_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS flow_versions (
	flow_name TEXT NOT NULL,
	version TEXT NOT NULL,
	content TEXT NOT NULL,
	deployed_at INTEGER NOT NULL,
	PRIMARY KEY (flow_name, version)
);
CREATE INDEX IF NOT EXISTS idx_flow_versions_name ON flow_versions(flow_name, deployed_at DESC);
`
	_, err = db.Exec(sqlStmt)
	if err != nil {
		db.Close()
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
		utils.Warn("Failed to cleanup wait token %s: %v", token.String(), err)
	}
	return nil, nil
}

// PausedRunPersist and helpers

func (s *SqliteStorage) SavePausedRun(ctx context.Context, token string, paused any) error {
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
	_, err = s.db.ExecContext(ctx, `
	INSERT INTO paused_runs (token, flow, step_idx, step_ctx, outputs)
	VALUES (?, ?, ?, ?, ?)
	ON CONFLICT(token) DO UPDATE SET flow=excluded.flow, step_idx=excluded.step_idx, step_ctx=excluded.step_ctx, outputs=excluded.outputs
	`, token, flowBytes, persist.StepIdx, stepCtxBytes, outputsBytes)
	return err
}

func (s *SqliteStorage) LoadPausedRuns(ctx context.Context) (map[string]any, error) {
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

func (s *SqliteStorage) DeletePausedRun(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM paused_runs WHERE token=?`, token)
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
	runs := []*model.Run{} // Initialize as empty slice instead of nil
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

// OAuth credential methods

func (s *SqliteStorage) SaveOAuthCredential(ctx context.Context, cred *model.OAuthCredential) error {
	if err := cred.Validate(); err != nil {
		return utils.Errorf("invalid credential: %w", err)
	}

	// Encrypt sensitive token data before storage
	// No encryption yet - store tokens as-is

	var expiresAt *int64
	if cred.ExpiresAt != nil {
		timestamp := cred.ExpiresAt.Unix()
		expiresAt = &timestamp
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO oauth_credentials
		(id, provider, integration, access_token, refresh_token, expires_at, scope, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cred.ID, cred.Provider, cred.Integration, cred.AccessToken, cred.RefreshToken,
		expiresAt, cred.Scope, cred.CreatedAt.Unix(), cred.UpdatedAt.Unix())

	if err != nil {
		return utils.Errorf("failed to save OAuth credential: %w", err)
	}
	return nil
}

func (s *SqliteStorage) GetOAuthCredential(ctx context.Context, provider, integration string) (*model.OAuthCredential, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, provider, integration, access_token, refresh_token, expires_at, scope, created_at, updated_at
		FROM oauth_credentials 
		WHERE provider = ? AND integration = ?`,
		provider, integration)

	var cred model.OAuthCredential
	var refreshToken sql.NullString
	var expiresAt sql.NullInt64
	var createdAt, updatedAt int64

	err := row.Scan(&cred.ID, &cred.Provider, &cred.Integration, &cred.AccessToken,
		&refreshToken, &expiresAt, &cred.Scope, &createdAt, &updatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		return nil, utils.Errorf("failed to get OAuth credential: %w", err)
	}

	if refreshToken.Valid {
		cred.RefreshToken = &refreshToken.String
	}

	if expiresAt.Valid {
		t := time.Unix(expiresAt.Int64, 0)
		cred.ExpiresAt = &t
	}
	cred.CreatedAt = time.Unix(createdAt, 0)
	cred.UpdatedAt = time.Unix(updatedAt, 0)

	return &cred, nil
}

func (s *SqliteStorage) ListOAuthCredentials(ctx context.Context) ([]*model.OAuthCredential, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, provider, integration, access_token, refresh_token, expires_at, scope, created_at, updated_at
		FROM oauth_credentials 
		ORDER BY created_at DESC`)

	if err != nil {
		return nil, utils.Errorf("failed to list OAuth credentials: %w", err)
	}
	defer rows.Close()

	var creds []*model.OAuthCredential
	for rows.Next() {
		var cred model.OAuthCredential
		var refreshToken sql.NullString
		var expiresAt sql.NullInt64
		var createdAt, updatedAt int64

		err := rows.Scan(&cred.ID, &cred.Provider, &cred.Integration, &cred.AccessToken,
			&refreshToken, &expiresAt, &cred.Scope, &createdAt, &updatedAt)

		if err != nil {
			continue
		}

		if refreshToken.Valid {
			cred.RefreshToken = &refreshToken.String
		}

		if expiresAt.Valid {
			t := time.Unix(expiresAt.Int64, 0)
			cred.ExpiresAt = &t
		}
		cred.CreatedAt = time.Unix(createdAt, 0)
		cred.UpdatedAt = time.Unix(updatedAt, 0)

		creds = append(creds, &cred)
	}

	return creds, nil
}

func (s *SqliteStorage) DeleteOAuthCredential(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM oauth_credentials WHERE id = ?`, id)
	if err != nil {
		return utils.Errorf("failed to delete OAuth credential: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return utils.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

func (s *SqliteStorage) RefreshOAuthCredential(ctx context.Context, id string, newToken string, expiresAt *time.Time) error {
	var expiresAtUnix *int64
	if expiresAt != nil {
		timestamp := expiresAt.Unix()
		expiresAtUnix = &timestamp
	}

	result, err := s.db.ExecContext(ctx, `
		UPDATE oauth_credentials
		SET access_token = ?, expires_at = ?, updated_at = ?
		WHERE id = ?`,
		newToken, expiresAtUnix, time.Now().Unix(), id)

	if err != nil {
		return utils.Errorf("failed to refresh OAuth credential: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return utils.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// OAuth provider methods

func (s *SqliteStorage) SaveOAuthProvider(ctx context.Context, provider *model.OAuthProvider) error {
	if err := provider.Validate(); err != nil {
		return utils.Errorf("invalid provider: %w", err)
	}

	scopesJSON, err := json.Marshal(provider.Scopes)
	if err != nil {
		return utils.Errorf("failed to marshal scopes: %w", err)
	}

	now := time.Now().Unix()
	_, err = s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO oauth_providers 
		(id, client_id, client_secret, auth_url, token_url, scopes, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		provider.ID, provider.ClientID, provider.ClientSecret, provider.AuthURL, provider.TokenURL,
		string(scopesJSON), now, now)

	if err != nil {
		return utils.Errorf("failed to save OAuth provider: %w", err)
	}
	return nil
}

func (s *SqliteStorage) GetOAuthProvider(ctx context.Context, id string) (*model.OAuthProvider, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, client_id, client_secret, auth_url, token_url, scopes, created_at, updated_at
		FROM oauth_providers 
		WHERE id = ?`, id)

	var provider model.OAuthProvider
	var scopesJSON string
	var createdAt, updatedAt int64

	err := row.Scan(&provider.ID, &provider.ClientID, &provider.ClientSecret,
		&provider.AuthURL, &provider.TokenURL, &scopesJSON, &createdAt, &updatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		return nil, utils.Errorf("failed to get OAuth provider: %w", err)
	}

	if err := json.Unmarshal([]byte(scopesJSON), &provider.Scopes); err != nil {
		return nil, utils.Errorf("failed to unmarshal scopes: %w", err)
	}

	return &provider, nil
}

func (s *SqliteStorage) ListOAuthProviders(ctx context.Context) ([]*model.OAuthProvider, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, client_id, client_secret, auth_url, token_url, scopes, created_at, updated_at
		FROM oauth_providers 
		ORDER BY created_at DESC`)

	if err != nil {
		return nil, utils.Errorf("failed to list OAuth providers: %w", err)
	}
	defer rows.Close()

	var providers []*model.OAuthProvider
	for rows.Next() {
		var provider model.OAuthProvider
		var scopesJSON string
		var createdAt, updatedAt int64

		err := rows.Scan(&provider.ID, &provider.ClientID, &provider.ClientSecret,
			&provider.AuthURL, &provider.TokenURL, &scopesJSON, &createdAt, &updatedAt)

		if err != nil {
			continue
		}

		if err := json.Unmarshal([]byte(scopesJSON), &provider.Scopes); err != nil {
			continue
		}

		providers = append(providers, &provider)
	}

	return providers, nil
}

func (s *SqliteStorage) DeleteOAuthProvider(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM oauth_providers WHERE id = ?`, id)
	if err != nil {
		return utils.Errorf("failed to delete OAuth provider: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return utils.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// OAuth client methods
func (s *SqliteStorage) SaveOAuthClient(ctx context.Context, client *model.OAuthClient) error {
	redirectURIsJSON, err := json.Marshal(client.RedirectURIs)
	if err != nil {
		return utils.Errorf("failed to marshal redirect URIs: %w", err)
	}
	grantTypesJSON, err := json.Marshal(client.GrantTypes)
	if err != nil {
		return utils.Errorf("failed to marshal grant types: %w", err)
	}
	responseTypesJSON, err := json.Marshal(client.ResponseTypes)
	if err != nil {
		return utils.Errorf("failed to marshal response types: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO oauth_clients
		(id, secret, name, redirect_uris, grant_types, response_types, scope, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		client.ID, client.Secret, client.Name, string(redirectURIsJSON),
		string(grantTypesJSON), string(responseTypesJSON), client.Scope,
		client.CreatedAt.Unix(), time.Now().Unix())

	if err != nil {
		return utils.Errorf("failed to save OAuth client: %w", err)
	}
	return nil
}

func (s *SqliteStorage) GetOAuthClient(ctx context.Context, id string) (*model.OAuthClient, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, secret, name, redirect_uris, grant_types, response_types, scope, created_at, updated_at
		FROM oauth_clients WHERE id = ?`, id)

	var client model.OAuthClient
	var redirectURIsJSON, grantTypesJSON, responseTypesJSON string
	var createdAt, updatedAt int64

	err := row.Scan(&client.ID, &client.Secret, &client.Name, &redirectURIsJSON,
		&grantTypesJSON, &responseTypesJSON, &client.Scope, &createdAt, &updatedAt)
	if err != nil {
		return nil, utils.Errorf("failed to get OAuth client: %w", err)
	}

	if err := json.Unmarshal([]byte(redirectURIsJSON), &client.RedirectURIs); err != nil {
		return nil, utils.Errorf("failed to unmarshal redirect URIs: %w", err)
	}
	if err := json.Unmarshal([]byte(grantTypesJSON), &client.GrantTypes); err != nil {
		return nil, utils.Errorf("failed to unmarshal grant types: %w", err)
	}
	if err := json.Unmarshal([]byte(responseTypesJSON), &client.ResponseTypes); err != nil {
		return nil, utils.Errorf("failed to unmarshal response types: %w", err)
	}

	client.CreatedAt = time.Unix(createdAt, 0)
	client.UpdatedAt = time.Unix(updatedAt, 0)

	return &client, nil
}

func (s *SqliteStorage) ListOAuthClients(ctx context.Context) ([]*model.OAuthClient, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, secret, name, redirect_uris, grant_types, response_types, scope, created_at, updated_at
		FROM oauth_clients ORDER BY created_at DESC`)

	if err != nil {
		return nil, utils.Errorf("failed to list OAuth clients: %w", err)
	}
	defer rows.Close()

	var clients []*model.OAuthClient
	for rows.Next() {
		var client model.OAuthClient
		var redirectURIsJSON, grantTypesJSON, responseTypesJSON string
		var createdAt, updatedAt int64

		err := rows.Scan(&client.ID, &client.Secret, &client.Name, &redirectURIsJSON,
			&grantTypesJSON, &responseTypesJSON, &client.Scope, &createdAt, &updatedAt)
		if err != nil {
			return nil, utils.Errorf("failed to scan OAuth client: %w", err)
		}

		if err := json.Unmarshal([]byte(redirectURIsJSON), &client.RedirectURIs); err != nil {
			return nil, utils.Errorf("failed to unmarshal redirect URIs: %w", err)
		}
		if err := json.Unmarshal([]byte(grantTypesJSON), &client.GrantTypes); err != nil {
			return nil, utils.Errorf("failed to unmarshal grant types: %w", err)
		}
		if err := json.Unmarshal([]byte(responseTypesJSON), &client.ResponseTypes); err != nil {
			return nil, utils.Errorf("failed to unmarshal response types: %w", err)
		}

		client.CreatedAt = time.Unix(createdAt, 0)
		client.UpdatedAt = time.Unix(updatedAt, 0)

		clients = append(clients, &client)
	}

	return clients, nil
}

func (s *SqliteStorage) DeleteOAuthClient(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM oauth_clients WHERE id = ?`, id)
	if err != nil {
		return utils.Errorf("failed to delete OAuth client: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return utils.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// OAuth token methods
func (s *SqliteStorage) SaveOAuthToken(ctx context.Context, token *model.OAuthToken) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO oauth_tokens
		(id, client_id, user_id, redirect_uri, scope, code, code_create_at, code_expires_in,
		 access, access_create_at, access_expires_in, refresh, refresh_create_at, refresh_expires_in,
		 created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		token.ID, token.ClientID, token.UserID, token.RedirectURI, token.Scope,
		token.Code, token.CodeCreateAt.Unix(), int64(token.CodeExpiresIn),
		token.Access, token.AccessCreateAt.Unix(), int64(token.AccessExpiresIn),
		token.Refresh, token.RefreshCreateAt.Unix(), int64(token.RefreshExpiresIn),
		time.Now().Unix(), time.Now().Unix())

	if err != nil {
		return utils.Errorf("failed to save OAuth token: %w", err)
	}
	return nil
}

func (s *SqliteStorage) GetOAuthTokenByCode(ctx context.Context, code string) (*model.OAuthToken, error) {
	return s.getOAuthTokenByField(ctx, "code", code)
}

func (s *SqliteStorage) GetOAuthTokenByAccess(ctx context.Context, access string) (*model.OAuthToken, error) {
	return s.getOAuthTokenByField(ctx, "access", access)
}

func (s *SqliteStorage) GetOAuthTokenByRefresh(ctx context.Context, refresh string) (*model.OAuthToken, error) {
	return s.getOAuthTokenByField(ctx, "refresh", refresh)
}

func (s *SqliteStorage) getOAuthTokenByField(ctx context.Context, field, value string) (*model.OAuthToken, error) {
	row := s.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT id, client_id, user_id, redirect_uri, scope, code, code_create_at, code_expires_in,
			access, access_create_at, access_expires_in, refresh, refresh_create_at, refresh_expires_in
		FROM oauth_tokens WHERE %s = ?`, field), value)

	var token model.OAuthToken
	var codeCreateAt, accessCreateAt, refreshCreateAt int64
	var codeExpiresIn, accessExpiresIn, refreshExpiresIn int64

	err := row.Scan(&token.ID, &token.ClientID, &token.UserID, &token.RedirectURI, &token.Scope,
		&token.Code, &codeCreateAt, &codeExpiresIn,
		&token.Access, &accessCreateAt, &accessExpiresIn,
		&token.Refresh, &refreshCreateAt, &refreshExpiresIn)
	if err != nil {
		return nil, utils.Errorf("failed to get OAuth token: %w", err)
	}

	token.CodeCreateAt = time.Unix(codeCreateAt, 0)
	token.CodeExpiresIn = time.Duration(codeExpiresIn)
	token.AccessCreateAt = time.Unix(accessCreateAt, 0)
	token.AccessExpiresIn = time.Duration(accessExpiresIn)
	token.RefreshCreateAt = time.Unix(refreshCreateAt, 0)
	token.RefreshExpiresIn = time.Duration(refreshExpiresIn)

	return &token, nil
}

func (s *SqliteStorage) DeleteOAuthTokenByCode(ctx context.Context, code string) error {
	return s.deleteOAuthTokenByField(ctx, "code", code)
}

func (s *SqliteStorage) DeleteOAuthTokenByAccess(ctx context.Context, access string) error {
	return s.deleteOAuthTokenByField(ctx, "access", access)
}

func (s *SqliteStorage) DeleteOAuthTokenByRefresh(ctx context.Context, refresh string) error {
	return s.deleteOAuthTokenByField(ctx, "refresh", refresh)
}

func (s *SqliteStorage) deleteOAuthTokenByField(ctx context.Context, field, value string) error {
	result, err := s.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM oauth_tokens WHERE %s = ?`, field), value)
	if err != nil {
		return utils.Errorf("failed to delete OAuth token: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return utils.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// Flow versioning methods

func (s *SqliteStorage) DeployFlowVersion(ctx context.Context, flowName, version, content string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return utils.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Save snapshot (idempotent - ON CONFLICT DO NOTHING)
	_, err = tx.ExecContext(ctx, `
		INSERT INTO flow_versions (flow_name, version, content, deployed_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(flow_name, version) DO NOTHING
	`, flowName, version, content, time.Now().Unix())
	if err != nil {
		return utils.Errorf("failed to save snapshot: %w", err)
	}

	// Update deployed version pointer
	_, err = tx.ExecContext(ctx, `
		INSERT INTO deployed_flows (flow_name, deployed_version, deployed_at)
		VALUES (?, ?, ?)
		ON CONFLICT(flow_name) DO UPDATE SET 
			deployed_version=excluded.deployed_version,
			deployed_at=excluded.deployed_at
	`, flowName, version, time.Now().Unix())
	if err != nil {
		return utils.Errorf("failed to update deployed version: %w", err)
	}

	return tx.Commit()
}

func (s *SqliteStorage) SetDeployedVersion(ctx context.Context, flowName, version string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO deployed_flows (flow_name, deployed_version, deployed_at)
		VALUES (?, ?, ?)
		ON CONFLICT(flow_name) DO UPDATE SET 
			deployed_version=excluded.deployed_version,
			deployed_at=excluded.deployed_at
	`, flowName, version, time.Now().Unix())
	if err != nil {
		return utils.Errorf("failed to set deployed version: %w", err)
	}
	return nil
}

func (s *SqliteStorage) GetDeployedVersion(ctx context.Context, flowName string) (string, error) {
	var version string
	err := s.db.QueryRowContext(ctx,
		"SELECT deployed_version FROM deployed_flows WHERE flow_name = ?",
		flowName,
	).Scan(&version)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return version, err
}

func (s *SqliteStorage) GetFlowVersionContent(ctx context.Context, flowName, version string) (string, error) {
	var content string
	err := s.db.QueryRowContext(ctx,
		"SELECT content FROM flow_versions WHERE flow_name = ? AND version = ?",
		flowName, version,
	).Scan(&content)
	if err == sql.ErrNoRows {
		return "", utils.Errorf("version %s not found for flow %s", version, flowName)
	}
	return content, err
}

func (s *SqliteStorage) ListFlowVersions(ctx context.Context, flowName string) ([]FlowSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT v.version, v.deployed_at,
			CASE WHEN d.deployed_version = v.version THEN 1 ELSE 0 END as is_live
		FROM flow_versions v
		LEFT JOIN deployed_flows d ON v.flow_name = d.flow_name
		WHERE v.flow_name = ?
		ORDER BY v.deployed_at DESC
	`, flowName)
	if err != nil {
		return nil, utils.Errorf("failed to list versions: %w", err)
	}
	defer rows.Close()

	var snapshots []FlowSnapshot
	for rows.Next() {
		var s FlowSnapshot
		var deployedAt int64
		var isLive int
		if err := rows.Scan(&s.Version, &deployedAt, &isLive); err != nil {
			continue
		}
		s.FlowName = flowName
		s.DeployedAt = time.Unix(deployedAt, 0)
		s.IsLive = (isLive == 1)
		snapshots = append(snapshots, s)
	}
	return snapshots, nil
}

// Close closes the underlying SQL database connection.
func (s *SqliteStorage) Close() error {
	return s.db.Close()
}
