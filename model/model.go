package model

import (
	"fmt"
	"time"

	"github.com/beemflow/beemflow/utils"
	"github.com/google/uuid"
)

type Flow struct {
	Name    string         `yaml:"name" json:"name"`
	Version string         `yaml:"version,omitempty" json:"version,omitempty"`
	On      any            `yaml:"on" json:"on,omitempty"`
	Cron    string         `yaml:"cron,omitempty" json:"cron,omitempty"` // Cron expression for schedule.cron
	Vars    map[string]any `yaml:"vars,omitempty" json:"vars,omitempty"`
	Steps   []Step         `yaml:"steps" json:"steps"`
	Catch   []Step         `yaml:"catch,omitempty" json:"catch,omitempty"`
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

// OAuth types for managing OAuth2.0 credentials
type OAuthCredential struct {
	ID           string     `json:"id"`
	Provider     string     `json:"provider"`     // "google", "github", etc.
	Integration  string     `json:"integration"`  // "sheets_default", etc.
	AccessToken  string     `json:"access_token"` // encrypted at storage layer
	RefreshToken *string    `json:"refresh_token,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	Scope        string     `json:"scope,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type OAuthProvider struct {
	ID           string   `json:"id"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"` // encrypted at storage layer
	AuthURL      string   `json:"auth_url"`
	TokenURL     string   `json:"token_url"`
	Scopes       []string `json:"scopes"`
}

// Validate checks if the OAuth credential has all required fields
func (c *OAuthCredential) Validate() error {
	if c.Provider == "" {
		return utils.Errorf("provider is required")
	}
	if c.Integration == "" {
		return utils.Errorf("integration is required")
	}
	if c.AccessToken == "" {
		return utils.Errorf("access_token is required")
	}
	return nil
}

// IsExpired checks if the OAuth credential has expired
func (c *OAuthCredential) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*c.ExpiresAt) || time.Now().Equal(*c.ExpiresAt)
}

// UniqueKey returns a unique key for the credential based on provider and integration
func (c *OAuthCredential) UniqueKey() string {
	return fmt.Sprintf("%s:%s", c.Provider, c.Integration)
}

// Validate checks if the OAuth provider has all required fields
func (p *OAuthProvider) Validate() error {
	if p.ClientID == "" {
		return utils.Errorf("client_id is required")
	}
	if p.ClientSecret == "" {
		return utils.Errorf("client_secret is required")
	}
	if p.AuthURL == "" {
		return utils.Errorf("auth_url is required")
	}
	if p.TokenURL == "" {
		return utils.Errorf("token_url is required")
	}
	return nil
}
