package storage

import (
	"context"

	"github.com/awantoch/beemflow/model"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

type Storage interface {
	SaveRun(ctx context.Context, run *model.Run) error
	GetRun(ctx context.Context, id uuid.UUID) (*model.Run, error)
	SaveStep(ctx context.Context, step *model.StepRun) error
	GetSteps(ctx context.Context, runID uuid.UUID) ([]*model.StepRun, error)
	RegisterWait(ctx context.Context, token uuid.UUID, wakeAt *int64) error
	ResolveWait(ctx context.Context, token uuid.UUID) (*model.Run, error)
	ListRuns(ctx context.Context) ([]*model.Run, error)
	SavePausedRun(token string, paused any) error
	LoadPausedRuns() (map[string]any, error)
	DeletePausedRun(token string) error
	DeleteRun(ctx context.Context, id uuid.UUID) error
}
