package storage

import (
	"context"
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

	// Flow versioning methods
	DeployFlowVersion(ctx context.Context, flowName, version, content string) error
	SetDeployedVersion(ctx context.Context, flowName, version string) error
	GetDeployedVersion(ctx context.Context, flowName string) (string, error)
	GetFlowVersionContent(ctx context.Context, flowName, version string) (string, error)
	ListFlowVersions(ctx context.Context, flowName string) ([]FlowSnapshot, error)
}

// FlowSnapshot represents a deployed flow version
type FlowSnapshot struct {
	FlowName   string    `json:"flow_name"`
	Version    string    `json:"version"`
	DeployedAt time.Time `json:"deployed_at"`
	IsLive     bool      `json:"is_live"`
}
