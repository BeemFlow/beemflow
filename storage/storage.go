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
}
