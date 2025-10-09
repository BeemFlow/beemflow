package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/beemflow/beemflow/model"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

type Storage interface {
	SaveRun(ctx context.Context, run *model.Run) error
	GetRun(ctx context.Context, id uuid.UUID) (*model.Run, error)
	SaveStep(ctx context.Context, step *model.StepRun) error
	GetSteps(ctx context.Context, runID uuid.UUID) ([]*model.StepRun, error)
	RegisterWait(ctx context.Context, token uuid.UUID, wakeAt *int64) error
	ResolveWait(ctx context.Context, token uuid.UUID) (*model.Run, error)
	ListRuns(ctx context.Context) ([]*model.Run, error)
	SavePausedRun(ctx context.Context, token string, paused any) error
	LoadPausedRuns(ctx context.Context) (map[string]any, error)
	DeletePausedRun(ctx context.Context, token string) error
	DeleteRun(ctx context.Context, id uuid.UUID) error

	// OAuth credential methods
	SaveOAuthCredential(ctx context.Context, cred *model.OAuthCredential) error
	GetOAuthCredential(ctx context.Context, provider, integration string) (*model.OAuthCredential, error)
	ListOAuthCredentials(ctx context.Context) ([]*model.OAuthCredential, error)
	DeleteOAuthCredential(ctx context.Context, id string) error
	RefreshOAuthCredential(ctx context.Context, id string, newToken string, expiresAt *time.Time) error

	// OAuth provider methods
	SaveOAuthProvider(ctx context.Context, provider *model.OAuthProvider) error
	GetOAuthProvider(ctx context.Context, id string) (*model.OAuthProvider, error)
	ListOAuthProviders(ctx context.Context) ([]*model.OAuthProvider, error)
	DeleteOAuthProvider(ctx context.Context, id string) error

	// OAuth client methods (for dynamic client registration)
	SaveOAuthClient(ctx context.Context, client *model.OAuthClient) error
	GetOAuthClient(ctx context.Context, id string) (*model.OAuthClient, error)
	ListOAuthClients(ctx context.Context) ([]*model.OAuthClient, error)
	DeleteOAuthClient(ctx context.Context, id string) error

	// OAuth token methods (for token storage)
	SaveOAuthToken(ctx context.Context, token *model.OAuthToken) error
	GetOAuthTokenByCode(ctx context.Context, code string) (*model.OAuthToken, error)
	GetOAuthTokenByAccess(ctx context.Context, access string) (*model.OAuthToken, error)
	GetOAuthTokenByRefresh(ctx context.Context, refresh string) (*model.OAuthToken, error)
	DeleteOAuthTokenByCode(ctx context.Context, code string) error
	DeleteOAuthTokenByAccess(ctx context.Context, access string) error
	DeleteOAuthTokenByRefresh(ctx context.Context, refresh string) error
}

// Package-private SQL marshaling helpers (shared by sqlite and postgres)

func marshalRunFields(run *model.Run) (eventJSON, varsJSON []byte, err error) {
	eventJSON, err = json.Marshal(run.Event)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal event: %w", err)
	}
	varsJSON, err = json.Marshal(run.Vars)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal vars: %w", err)
	}
	return eventJSON, varsJSON, nil
}

func marshalStepOutputs(step *model.StepRun) ([]byte, error) {
	return json.Marshal(step.Outputs)
}

func unmarshalStepOutputs(outputsJSON []byte, step *model.StepRun) error {
	return json.Unmarshal(outputsJSON, &step.Outputs)
}
