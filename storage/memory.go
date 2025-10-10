package storage

import (
	"context"
	"database/sql"
	"maps"
	"sort"
	"sync"
	"time"

	"github.com/beemflow/beemflow/model"
	"github.com/beemflow/beemflow/utils"
	"github.com/google/uuid"
)

// MemoryStorage implements Storage in-memory (for fallback/dev mode).
type MemoryStorage struct {
	runs           map[uuid.UUID]*model.Run
	steps          map[uuid.UUID][]*model.StepRun    // runID -> steps
	mu             sync.RWMutex                      // RWMutex is sufficient for most use cases; consider context-aware primitives if high concurrency or cancellation is needed.
	paused         map[string]any                    // token -> paused run
	oauthCreds     map[string]*model.OAuthCredential // provider:integration -> credential
	oauthProviders map[string]*model.OAuthProvider   // id -> provider
	oauthClients   map[string]*model.OAuthClient     // id -> client
	oauthTokens    map[string]*model.OAuthToken      // id -> token
}

var _ Storage = (*MemoryStorage)(nil)

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		runs:           make(map[uuid.UUID]*model.Run),
		steps:          make(map[uuid.UUID][]*model.StepRun),
		paused:         make(map[string]any),
		oauthCreds:     make(map[string]*model.OAuthCredential),
		oauthProviders: make(map[string]*model.OAuthProvider),
		oauthClients:   make(map[string]*model.OAuthClient),
		oauthTokens:    make(map[string]*model.OAuthToken),
	}
}

func (m *MemoryStorage) SaveRun(ctx context.Context, run *model.Run) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs[run.ID] = run
	return nil
}

func (m *MemoryStorage) GetRun(ctx context.Context, id uuid.UUID) (*model.Run, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	run, ok := m.runs[id]
	if !ok {
		return nil, sql.ErrNoRows
	}
	return run, nil
}

func (m *MemoryStorage) SaveStep(ctx context.Context, step *model.StepRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.steps[step.RunID] = append(m.steps[step.RunID], step)
	return nil
}

func (m *MemoryStorage) GetSteps(ctx context.Context, runID uuid.UUID) ([]*model.StepRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.steps[runID], nil
}

func (m *MemoryStorage) RegisterWait(ctx context.Context, token uuid.UUID, wakeAt *int64) error {
	return nil
}

func (m *MemoryStorage) ResolveWait(ctx context.Context, token uuid.UUID) (*model.Run, error) {
	return nil, nil
}

func (m *MemoryStorage) ListRuns(ctx context.Context) ([]*model.Run, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []*model.Run{} // Initialize as empty slice instead of nil
	for _, run := range m.runs {
		out = append(out, run)
	}
	// Sort by StartedAt DESC to match SQL implementations
	sort.Slice(out, func(i, j int) bool {
		return out[i].StartedAt.After(out[j].StartedAt)
	})
	return out, nil
}

func (m *MemoryStorage) SavePausedRun(ctx context.Context, token string, paused any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.paused[token] = paused
	return nil
}

func (m *MemoryStorage) LoadPausedRuns(ctx context.Context) (map[string]any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]any, len(m.paused))
	maps.Copy(out, m.paused)
	return out, nil
}

func (m *MemoryStorage) DeletePausedRun(ctx context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.paused, token)
	return nil
}

func (m *MemoryStorage) DeleteRun(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.runs, id)
	delete(m.steps, id)
	return nil
}

// GetLatestRunByFlowName retrieves the most recent run for a given flow name
func (m *MemoryStorage) GetLatestRunByFlowName(ctx context.Context, flowName string) (*model.Run, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var latest *model.Run
	for _, run := range m.runs {
		if run.FlowName == flowName {
			if latest == nil || run.StartedAt.After(latest.StartedAt) {
				latest = run
			}
		}
	}

	if latest == nil {
		return nil, sql.ErrNoRows
	}
	return latest, nil
}

// OAuth credential methods

func (m *MemoryStorage) SaveOAuthCredential(ctx context.Context, cred *model.OAuthCredential) error {
	if err := cred.Validate(); err != nil {
		return utils.Errorf("invalid credential: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := cred.UniqueKey()
	m.oauthCreds[key] = cred
	return nil
}

func (m *MemoryStorage) GetOAuthCredential(ctx context.Context, provider, integration string) (*model.OAuthCredential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := provider + ":" + integration
	cred, ok := m.oauthCreds[key]
	if !ok {
		return nil, sql.ErrNoRows
	}

	return cred, nil
}

func (m *MemoryStorage) ListOAuthCredentials(ctx context.Context) ([]*model.OAuthCredential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*model.OAuthCredential, 0, len(m.oauthCreds))
	for _, cred := range m.oauthCreds {
		out = append(out, cred)
	}

	// Sort by CreatedAt DESC to match SQL implementations
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})

	return out, nil
}

func (m *MemoryStorage) DeleteOAuthCredential(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find and delete by ID
	for key, cred := range m.oauthCreds {
		if cred.ID == id {
			delete(m.oauthCreds, key)
			return nil
		}
	}

	return sql.ErrNoRows
}

func (m *MemoryStorage) RefreshOAuthCredential(ctx context.Context, id string, newToken string, expiresAt *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find credential by ID
	for key, cred := range m.oauthCreds {
		if cred.ID == id {
			cred.AccessToken = newToken
			cred.ExpiresAt = expiresAt
			cred.UpdatedAt = time.Now()
			m.oauthCreds[key] = cred
			return nil
		}
	}

	return sql.ErrNoRows
}

// OAuth provider methods

func (m *MemoryStorage) SaveOAuthProvider(ctx context.Context, provider *model.OAuthProvider) error {
	if err := provider.Validate(); err != nil {
		return utils.Errorf("invalid provider: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.oauthProviders[provider.ID] = provider
	return nil
}

func (m *MemoryStorage) GetOAuthProvider(ctx context.Context, id string) (*model.OAuthProvider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	provider, ok := m.oauthProviders[id]
	if !ok {
		return nil, sql.ErrNoRows
	}
	return provider, nil
}

func (m *MemoryStorage) ListOAuthProviders(ctx context.Context) ([]*model.OAuthProvider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var providers []*model.OAuthProvider
	for _, provider := range m.oauthProviders {
		providers = append(providers, provider)
	}

	// Sort by ID for consistent output
	sort.Slice(providers, func(i, j int) bool {
		return providers[i].ID < providers[j].ID
	})

	return providers, nil
}

func (m *MemoryStorage) DeleteOAuthProvider(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.oauthProviders[id]; !ok {
		return sql.ErrNoRows
	}

	delete(m.oauthProviders, id)
	return nil
}

// OAuth client methods
func (m *MemoryStorage) SaveOAuthClient(ctx context.Context, client *model.OAuthClient) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	client.UpdatedAt = time.Now()
	if client.CreatedAt.IsZero() {
		client.CreatedAt = time.Now()
	}

	m.oauthClients[client.ID] = client
	return nil
}

func (m *MemoryStorage) GetOAuthClient(ctx context.Context, id string) (*model.OAuthClient, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	client, ok := m.oauthClients[id]
	if !ok {
		return nil, sql.ErrNoRows
	}

	return client, nil
}

func (m *MemoryStorage) ListOAuthClients(ctx context.Context) ([]*model.OAuthClient, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	clients := make([]*model.OAuthClient, 0, len(m.oauthClients))
	for _, client := range m.oauthClients {
		clients = append(clients, client)
	}

	// Sort by ID for consistent output
	sort.Slice(clients, func(i, j int) bool {
		return clients[i].ID < clients[j].ID
	})

	return clients, nil
}

func (m *MemoryStorage) DeleteOAuthClient(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.oauthClients[id]; !ok {
		return sql.ErrNoRows
	}

	delete(m.oauthClients, id)
	return nil
}

// OAuth token methods
func (m *MemoryStorage) SaveOAuthToken(ctx context.Context, token *model.OAuthToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.oauthTokens[token.ID] = token
	return nil
}

func (m *MemoryStorage) GetOAuthTokenByCode(ctx context.Context, code string) (*model.OAuthToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, token := range m.oauthTokens {
		if token.Code == code {
			return token, nil
		}
	}

	return nil, sql.ErrNoRows
}

func (m *MemoryStorage) GetOAuthTokenByAccess(ctx context.Context, access string) (*model.OAuthToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, token := range m.oauthTokens {
		if token.Access == access {
			return token, nil
		}
	}

	return nil, sql.ErrNoRows
}

func (m *MemoryStorage) GetOAuthTokenByRefresh(ctx context.Context, refresh string) (*model.OAuthToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, token := range m.oauthTokens {
		if token.Refresh == refresh {
			return token, nil
		}
	}

	return nil, sql.ErrNoRows
}

func (m *MemoryStorage) DeleteOAuthTokenByCode(ctx context.Context, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, token := range m.oauthTokens {
		if token.Code == code {
			delete(m.oauthTokens, id)
			return nil
		}
	}

	return sql.ErrNoRows
}

func (m *MemoryStorage) DeleteOAuthTokenByAccess(ctx context.Context, access string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, token := range m.oauthTokens {
		if token.Access == access {
			delete(m.oauthTokens, id)
			return nil
		}
	}

	return sql.ErrNoRows
}

func (m *MemoryStorage) DeleteOAuthTokenByRefresh(ctx context.Context, refresh string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, token := range m.oauthTokens {
		if token.Refresh == refresh {
			delete(m.oauthTokens, id)
			return nil
		}
	}

	return sql.ErrNoRows
}

// Flow versioning methods (in-memory stubs for dev/test)

func (m *MemoryStorage) DeployFlowVersion(ctx context.Context, flowName, version, content string) error {
	// In-memory storage doesn't persist flows - this is a no-op
	// Production should use SQLite/Postgres
	return nil
}

func (m *MemoryStorage) SetDeployedVersion(ctx context.Context, flowName, version string) error {
	// In-memory storage doesn't track deployments
	return nil
}

func (m *MemoryStorage) GetDeployedVersion(ctx context.Context, flowName string) (string, error) {
	// In-memory storage doesn't track deployments
	return "", nil
}

func (m *MemoryStorage) GetFlowVersionContent(ctx context.Context, flowName, version string) (string, error) {
	// In-memory storage doesn't store flow content
	return "", sql.ErrNoRows
}

func (m *MemoryStorage) ListFlowVersions(ctx context.Context, flowName string) ([]FlowSnapshot, error) {
	// In-memory storage doesn't track versions
	return []FlowSnapshot{}, nil
}
