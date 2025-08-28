package model

import (
	"time"

	"github.com/google/uuid"
)

type Flow struct {
	Name        string         `yaml:"name" json:"name"`
	Description string         `yaml:"description,omitempty" json:"description,omitempty"`
	Version     string         `yaml:"version,omitempty" json:"version,omitempty"`
	On          any            `yaml:"on" json:"on,omitempty"`
	Cron        string         `yaml:"cron,omitempty" json:"cron,omitempty"` // Cron expression for schedule.cron
	Vars        map[string]any `yaml:"vars,omitempty" json:"vars,omitempty"`
	Steps       []Step         `yaml:"steps" json:"steps"`
	Catch       []Step         `yaml:"catch,omitempty" json:"catch,omitempty"`
}

type Step struct {
	ID         string          `yaml:"id" json:"id"`
	Use        string          `yaml:"use,omitempty" json:"use,omitempty"`
	With       map[string]any  `yaml:"with,omitempty" json:"with,omitempty"`
	DependsOn  []string        `yaml:"depends_on,omitempty" json:"depends_on,omitempty"`
	Parallel   bool            `yaml:"parallel,omitempty" json:"parallel,omitempty"`
	If         string          `yaml:"if,omitempty" json:"if,omitempty"`
	Foreach    string          `yaml:"foreach,omitempty" json:"foreach,omitempty"`
	As         string          `yaml:"as,omitempty" json:"as,omitempty"`
	Do         []Step          `yaml:"do,omitempty" json:"do,omitempty"`
	Steps      []Step          `yaml:"steps,omitempty" json:"steps,omitempty"`
	Retry      *RetrySpec      `yaml:"retry,omitempty" json:"retry,omitempty"`
	AwaitEvent *AwaitEventSpec `yaml:"await_event,omitempty" json:"await_event,omitempty"`
	Wait       *WaitSpec       `yaml:"wait,omitempty" json:"wait,omitempty"`
}

type RetrySpec struct {
	Attempts int `yaml:"attempts" json:"attempts"`
	DelaySec int `yaml:"delay_sec" json:"delay_sec"`
}

type AwaitEventSpec struct {
	Source  string         `yaml:"source" json:"source"`
	Match   map[string]any `yaml:"match" json:"match"`
	Timeout string         `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

type WaitSpec struct {
	Seconds int    `yaml:"seconds,omitempty" json:"seconds,omitempty"`
	Until   string `yaml:"until,omitempty" json:"until,omitempty"`
}

type Run struct {
	ID        uuid.UUID      `json:"id"`
	FlowName  string         `json:"flowName"`
	Event     map[string]any `json:"event"`
	Vars      map[string]any `json:"vars"`
	Status    RunStatus      `json:"status"`
	StartedAt time.Time      `json:"startedAt"`
	EndedAt   *time.Time     `json:"endedAt,omitempty"`
	Steps     []StepRun      `json:"steps,omitempty"`
}

type StepRun struct {
	ID        uuid.UUID      `json:"id"`
	RunID     uuid.UUID      `json:"runId"`
	StepName  string         `json:"stepName"`
	Status    StepStatus     `json:"status"`
	StartedAt time.Time      `json:"startedAt"`
	EndedAt   *time.Time     `json:"endedAt,omitempty"`
	Error     string         `json:"error,omitempty"`
	Outputs   map[string]any `json:"outputs,omitempty"`
}

type RunStatus string

type StepStatus string

const (
	RunPending   RunStatus = "PENDING"
	RunRunning   RunStatus = "RUNNING"
	RunSucceeded RunStatus = "SUCCEEDED"
	RunFailed    RunStatus = "FAILED"
	RunWaiting   RunStatus = "WAITING"
	RunSkipped   RunStatus = "SKIPPED"

	StepPending   StepStatus = "PENDING"
	StepRunning   StepStatus = "RUNNING"
	StepSucceeded StepStatus = "SUCCEEDED"
	StepFailed    StepStatus = "FAILED"
	StepWaiting   StepStatus = "WAITING"
)
