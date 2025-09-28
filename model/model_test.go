package model_test

import (
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/beemflow/beemflow/model"
)

func TestFlowModel_UnmarshalAllFields(t *testing.T) {
	yamlData := `
name: all_fields
on: cli.manual
vars:
  num: 1
steps:
  - id: s1
    use: core.echo
    with:
      key: val
    if: "x > 0"
    foreach: "{{list}}"
    as: item
    do:
      - id: d1
        use: core.echo
        with:
          text: "{{item}}"
    parallel: true
    retry:
      attempts: 3
      delay_sec: 2
    await_event:
      source: bus
      match:
        key: "value"
      timeout: "30s"
    wait:
      seconds: 5
      until: "2025-01-01"
catch:
  - id: e1
    use: core.echo
    with:
      text: "err"
`

	var f model.Flow
	if err := yaml.Unmarshal([]byte(yamlData), &f); err != nil {
		t.Fatalf("yaml.Unmarshal failed: %v", err)
	}

	if f.Name != "all_fields" {
		t.Errorf("expected Name 'all_fields', got '%s'", f.Name)
	}
	if onStr, ok := f.On.(string); !ok || onStr != "cli.manual" {
		t.Errorf("expected On 'cli.manual', got %#v", f.On)
	}
	if len(f.Vars) != 1 {
		t.Errorf("expected Vars len 1, got %d", len(f.Vars))
	}

	if len(f.Steps) == 0 {
		t.Fatalf("expected step 's1' in Steps, got keys: %#v", f.Steps)
	}
	var step model.Step
	for _, s := range f.Steps {
		if s.ID == "s1" {
			step = s
			break
		}
	}
	if step.ID != "s1" {
		t.Fatalf("expected step 's1' in Steps, got keys: %#v", f.Steps)
	}
	if step.Use != "core.echo" {
		t.Errorf("expected step.Use 'core.echo', got '%s'", step.Use)
	}
	if step.If != "x > 0" {
		t.Errorf("expected step.If 'x > 0', got '%s'", step.If)
	}
	if step.Foreach != "{{list}}" {
		t.Errorf("expected step.Foreach '{{list}}', got '%s'", step.Foreach)
	}
	if step.As != "item" {
		t.Errorf("expected step.As 'item', got '%s'", step.As)
	}
	if len(step.Do) != 1 {
		t.Errorf("expected step.Do len 1, got %d", len(step.Do))
	} else if step.Do[0].Use != "core.echo" {
		t.Errorf("expected Do[0].Use 'core.echo', got '%s'", step.Do[0].Use)
	}
	if !step.Parallel {
		t.Errorf("expected step.Parallel true, got false")
	}
	if step.Retry == nil || step.Retry.Attempts != 3 || step.Retry.DelaySec != 2 {
		t.Errorf("expected Retry{3,2}, got %#v", step.Retry)
	}
	if step.AwaitEvent == nil || step.AwaitEvent.Source != "bus" {
		t.Errorf("expected AwaitEvent.Source 'bus', got %#v", step.AwaitEvent)
	} else {
		if val, ok := step.AwaitEvent.Match["key"]; !ok || val != "value" {
			t.Errorf("expected AwaitEvent.Match['key']='value', got %#v", step.AwaitEvent.Match)
		}
		if step.AwaitEvent.Timeout != "30s" {
			t.Errorf("expected AwaitEvent.Timeout '30s', got '%s'", step.AwaitEvent.Timeout)
		}
	}
	if step.Wait == nil || step.Wait.Seconds != 5 || step.Wait.Until != "2025-01-01" {
		t.Errorf("expected Wait{5,'2025-01-01'}, got %#v", step.Wait)
	}
	if len(f.Catch) != 1 || f.Catch[0].Use != "core.echo" {
		t.Errorf("expected one catch step with Use 'core.echo', got: %+v", f.Catch)
	}
}

func TestStep_AllFieldsSet(t *testing.T) {
	s := model.Step{
		ID:         "s1",
		Use:        "core.echo",
		With:       map[string]interface{}{"text": "hi"},
		If:         "x > 0",
		Foreach:    "{{list}}",
		As:         "item",
		Do:         []model.Step{{ID: "d1", Use: "core.echo", With: map[string]interface{}{"text": "{{item}}"}}},
		Parallel:   true,
		Retry:      &model.RetrySpec{Attempts: 2, DelaySec: 1},
		AwaitEvent: &model.AwaitEventSpec{Source: "bus", Match: map[string]interface{}{"key": "value"}, Timeout: "10s"},
		Wait:       &model.WaitSpec{Seconds: 5, Until: "2025-01-01"},
	}
	if s.Use != "core.echo" || s.With["text"] != "hi" || s.If != "x > 0" || s.Foreach != "{{list}}" || s.As != "item" {
		t.Errorf("step fields not set correctly: %+v", s)
	}
	if len(s.Do) != 1 {
		if s.Do[0].Use != "core.echo" {
			t.Errorf("step.Do not set correctly: %+v", s.Do)
		}
	}
	if !s.Parallel {
		t.Errorf("step.Parallel not set correctly: %+v", s.Parallel)
	}
	if s.Retry == nil || s.Retry.Attempts != 2 || s.Retry.DelaySec != 1 {
		t.Errorf("step.Retry not set correctly: %+v", s.Retry)
	}
	if s.AwaitEvent == nil || s.AwaitEvent.Source != "bus" || s.AwaitEvent.Match["key"] != "value" || s.AwaitEvent.Timeout != "10s" {
		t.Errorf("step.AwaitEvent not set correctly: %+v", s.AwaitEvent)
	}
	if s.Wait == nil || s.Wait.Seconds != 5 || s.Wait.Until != "2025-01-01" {
		t.Errorf("step.Wait not set correctly: %+v", s.Wait)
	}
}

func TestStep_OnlyRequiredFields(t *testing.T) {
	s := model.Step{ID: "s1", Use: "core.echo"}
	if s.Use != "core.echo" {
		t.Errorf("expected Use 'core.echo', got '%s'", s.Use)
	}
}

func TestStep_UnknownFieldsIgnored(t *testing.T) {
	// This is a compile-time struct, so unknown fields are not possible in Go,
	// but YAML/JSON unmarshal should ignore them (see parser tests).
}

func TestFlow_EmptyStepsCatch(t *testing.T) {
	f := model.Flow{Name: "empty", Steps: []model.Step{}, Catch: []model.Step{}}
	if len(f.Steps) != 0 {
		t.Errorf("expected 0 steps, got %d", len(f.Steps))
	}
	if len(f.Catch) != 0 {
		t.Errorf("expected 0 catch, got %d", len(f.Catch))
	}
}

func TestStep_NilAndEmptySubfields(t *testing.T) {
	s := model.Step{}
	if s.With != nil {
		t.Errorf("expected With nil, got %+v", s.With)
	}
	if len(s.Do) != 0 {
		t.Errorf("expected Do nil or empty, got %+v", s.Do)
	}
	// Parallel is a bool, so no nil/len check needed
}

func TestRetryAwaitWait_EdgeCases(t *testing.T) {
	r := &model.RetrySpec{}
	if r.Attempts != 0 || r.DelaySec != 0 {
		t.Errorf("expected zero values, got %+v", r)
	}
	a := &model.AwaitEventSpec{}
	if a.Source != "" || a.Timeout != "" || a.Match != nil {
		t.Errorf("expected zero values, got %+v", a)
	}
	w := &model.WaitSpec{}
	if w.Seconds != 0 || w.Until != "" {
		t.Errorf("expected zero values, got %+v", w)
	}
}

// ============================================================================
// OAUTH MODEL TESTS
// ============================================================================

func TestOAuthCredential_Validate(t *testing.T) {
	tests := []struct {
		name      string
		cred      *model.OAuthCredential
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid credential",
			cred: &model.OAuthCredential{
				ID:          "test-id",
				Provider:    "google",
				Integration: "sheets_default",
				AccessToken: "token123",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
			wantError: false,
		},
		{
			name: "missing provider",
			cred: &model.OAuthCredential{
				ID:          "test-id",
				Integration: "sheets_default",
				AccessToken: "token123",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
			wantError: true,
			errorMsg:  "provider is required",
		},
		{
			name: "missing integration",
			cred: &model.OAuthCredential{
				ID:          "test-id",
				Provider:    "google",
				AccessToken: "token123",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
			wantError: true,
			errorMsg:  "integration is required",
		},
		{
			name: "missing access token",
			cred: &model.OAuthCredential{
				ID:          "test-id",
				Provider:    "google",
				Integration: "sheets_default",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
			wantError: true,
			errorMsg:  "access_token is required",
		},
		{
			name: "empty provider",
			cred: &model.OAuthCredential{
				ID:          "test-id",
				Provider:    "",
				Integration: "sheets_default",
				AccessToken: "token123",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
			wantError: true,
			errorMsg:  "provider is required",
		},
		{
			name: "empty integration",
			cred: &model.OAuthCredential{
				ID:          "test-id",
				Provider:    "google",
				Integration: "",
				AccessToken: "token123",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
			wantError: true,
			errorMsg:  "integration is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cred.Validate()
			if tt.wantError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %v", tt.errorMsg, err)
				}
			} else if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestOAuthCredential_IsExpired(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name      string
		expiresAt *time.Time
		expected  bool
	}{
		{
			name:      "no expiry",
			expiresAt: nil,
			expected:  false,
		},
		{
			name:      "expired",
			expiresAt: &[]time.Time{now.Add(-time.Hour)}[0],
			expected:  true,
		},
		{
			name:      "not expired",
			expiresAt: &[]time.Time{now.Add(time.Hour)}[0],
			expected:  false,
		},
		{
			name:      "expires exactly now",
			expiresAt: &now,
			expected:  true, // Should be considered expired if exactly at expiry time
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred := &model.OAuthCredential{ExpiresAt: tt.expiresAt}
			if got := cred.IsExpired(); got != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestOAuthCredential_UniqueKey(t *testing.T) {
	tests := []struct {
		name     string
		cred     *model.OAuthCredential
		expected string
	}{
		{
			name: "basic key",
			cred: &model.OAuthCredential{
				Provider:    "google",
				Integration: "sheets_default",
			},
			expected: "google:sheets_default",
		},
		{
			name: "different provider",
			cred: &model.OAuthCredential{
				Provider:    "github",
				Integration: "repos_main",
			},
			expected: "github:repos_main",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cred.UniqueKey(); got != tt.expected {
				t.Errorf("UniqueKey() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestOAuthProvider_Validate(t *testing.T) {
	tests := []struct {
		name      string
		provider  *model.OAuthProvider
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid provider",
			provider: &model.OAuthProvider{
				ID:           "google",
				ClientID:     "client123",
				ClientSecret: "secret456",
				AuthURL:      "https://accounts.google.com/o/oauth2/auth",
				TokenURL:     "https://oauth2.googleapis.com/token",
				Scopes:       []string{"https://www.googleapis.com/auth/spreadsheets"},
			},
			wantError: false,
		},
		{
			name: "missing client id",
			provider: &model.OAuthProvider{
				ID:           "google",
				ClientSecret: "secret456",
				AuthURL:      "https://accounts.google.com/o/oauth2/auth",
				TokenURL:     "https://oauth2.googleapis.com/token",
			},
			wantError: true,
			errorMsg:  "client_id is required",
		},
		{
			name: "missing client secret",
			provider: &model.OAuthProvider{
				ID:       "google",
				ClientID: "client123",
				AuthURL:  "https://accounts.google.com/o/oauth2/auth",
				TokenURL: "https://oauth2.googleapis.com/token",
			},
			wantError: true,
			errorMsg:  "client_secret is required",
		},
		{
			name: "missing auth url",
			provider: &model.OAuthProvider{
				ID:           "google",
				ClientID:     "client123",
				ClientSecret: "secret456",
				TokenURL:     "https://oauth2.googleapis.com/token",
			},
			wantError: true,
			errorMsg:  "auth_url is required",
		},
		{
			name: "missing token url",
			provider: &model.OAuthProvider{
				ID:           "google",
				ClientID:     "client123",
				ClientSecret: "secret456",
				AuthURL:      "https://accounts.google.com/o/oauth2/auth",
			},
			wantError: true,
			errorMsg:  "token_url is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.provider.Validate()
			if tt.wantError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %v", tt.errorMsg, err)
				}
			} else if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}
