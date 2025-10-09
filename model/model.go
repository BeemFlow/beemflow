package model

import (
	"fmt"
	"time"

	"github.com/beemflow/beemflow/utils"
	"github.com/google/uuid"
)

type Flow struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Version     string         `json:"version,omitempty"`
	On          any            `json:"on,omitempty"`
	Cron        string         `json:"cron,omitempty"` // Cron expression for schedule.cron
	Vars        map[string]any `json:"vars,omitempty"`
	Steps       []Step         `json:"steps"`
	Catch       []Step         `json:"catch,omitempty"`
}

type Step struct {
	ID         string          `json:"id"`
	Use        string          `json:"use,omitempty"`
	With       map[string]any  `json:"with,omitempty"`
	DependsOn  []string        `json:"depends_on,omitempty"`
	Parallel   bool            `json:"parallel,omitempty"`
	If         string          `json:"if,omitempty"`
	Foreach    string          `json:"foreach,omitempty"`
	As         string          `json:"as,omitempty"`
	Steps      []Step          `json:"steps,omitempty"`
	Retry      *RetrySpec      `json:"retry,omitempty"`
	AwaitEvent *AwaitEventSpec `json:"await_event,omitempty"`
	Wait       *WaitSpec       `json:"wait,omitempty"`
}

type RetrySpec struct {
	Attempts int `json:"attempts"`
	DelaySec int `json:"delay_sec"`
}

type AwaitEventSpec struct {
	Source  string         `json:"source"`
	Match   map[string]any `json:"match"`
	Timeout string         `json:"timeout,omitempty"`
}

type WaitSpec struct {
	Seconds int    `json:"seconds,omitempty"`
	Until   string `json:"until,omitempty"`
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
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"` // encrypted at storage layer
	AuthURL      string    `json:"auth_url"`
	TokenURL     string    `json:"token_url"`
	Scopes       []string  `json:"scopes"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// OAuthClient represents a registered OAuth client
type OAuthClient struct {
	ID            string    `json:"id"`
	Secret        string    `json:"secret"` // encrypted at storage layer
	Name          string    `json:"name"`
	RedirectURIs  []string  `json:"redirect_uris"`
	GrantTypes    []string  `json:"grant_types"`
	ResponseTypes []string  `json:"response_types"`
	Scope         string    `json:"scope"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// OAuthToken represents an OAuth token
type OAuthToken struct {
	ID               string        `json:"id"`
	ClientID         string        `json:"client_id"`
	UserID           string        `json:"user_id"`
	RedirectURI      string        `json:"redirect_uri"`
	Scope            string        `json:"scope"`
	Code             string        `json:"code"`
	CodeCreateAt     time.Time     `json:"code_create_at"`
	CodeExpiresIn    time.Duration `json:"code_expires_in"`
	Access           string        `json:"access"`
	AccessCreateAt   time.Time     `json:"access_create_at"`
	AccessExpiresIn  time.Duration `json:"access_expires_in"`
	Refresh          string        `json:"refresh"`
	RefreshCreateAt  time.Time     `json:"refresh_create_at"`
	RefreshExpiresIn time.Duration `json:"refresh_expires_in"`
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
