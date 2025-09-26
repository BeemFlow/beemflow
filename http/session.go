package http

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"

	"github.com/beemflow/beemflow/utils"
)

// Session represents a user session for OAuth flows
type Session struct {
	ID        string                 `json:"id"`
	UserID    string                 `json:"user_id"`
	CreatedAt time.Time              `json:"created_at"`
	ExpiresAt time.Time              `json:"expires_at"`
	Data      map[string]interface{} `json:"data"`
}

// SessionStore manages user sessions
type SessionStore struct {
	sessions map[string]*Session
	mu       sync.RWMutex
	done     chan struct{}
}

// NewSessionStore creates a new session store
func NewSessionStore() *SessionStore {
	store := &SessionStore{
		sessions: make(map[string]*Session),
		done:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go store.cleanupExpiredSessions()

	return store
}

// Close stops the cleanup goroutine
func (s *SessionStore) Close() {
	close(s.done)
}

// CreateSession creates a new session for a user
func (s *SessionStore) CreateSession(userID string, ttl time.Duration) (*Session, error) {
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, utils.Errorf("failed to generate session ID: %w", err)
	}

	session := &Session{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ttl),
		Data:      make(map[string]interface{}),
	}

	s.mu.Lock()
	s.sessions[sessionID] = session
	s.mu.Unlock()

	utils.Debug("Created session %s for user %s", sessionID, userID)
	return session, nil
}

// GetSession retrieves a session by ID
func (s *SessionStore) GetSession(sessionID string) (*Session, bool) {
	s.mu.RLock()
	session, exists := s.sessions[sessionID]
	s.mu.RUnlock()

	if !exists {
		return nil, false
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		s.mu.Lock()
		delete(s.sessions, sessionID)
		s.mu.Unlock()
		return nil, false
	}

	return session, true
}

// UpdateSession updates session data
func (s *SessionStore) UpdateSession(sessionID string, key string, value interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return utils.Errorf("session not found: %s", sessionID)
	}

	if session.Data == nil {
		session.Data = make(map[string]interface{})
	}

	session.Data[key] = value
	utils.Debug("Updated session %s with key %s", sessionID, key)
	return nil
}

// DeleteSession removes a session
func (s *SessionStore) DeleteSession(sessionID string) {
	s.mu.Lock()
	delete(s.sessions, sessionID)
	s.mu.Unlock()
	utils.Debug("Deleted session %s", sessionID)
}

// GenerateCSRFToken generates a CSRF token for the given session
func (s *SessionStore) GenerateCSRFToken(sessionID string) (string, error) {
	token, err := generateSecureToken()
	if err != nil {
		return "", err
	}

	err = s.UpdateSession(sessionID, "csrf_token", token)
	if err != nil {
		return "", err
	}

	return token, nil
}

// ValidateCSRFToken validates a CSRF token for the given session
func (s *SessionStore) ValidateCSRFToken(sessionID, token string) bool {
	s.mu.RLock()
	session, exists := s.sessions[sessionID]
	s.mu.RUnlock()

	if !exists {
		return false
	}

	storedToken, exists := session.Data["csrf_token"]
	if !exists {
		return false
	}

	return storedToken == token
}

// cleanupExpiredSessions runs in a goroutine to clean up expired sessions
func (s *SessionStore) cleanupExpiredSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for id, session := range s.sessions {
				if now.After(session.ExpiresAt) {
					delete(s.sessions, id)
				}
			}
			s.mu.Unlock()
		case <-s.done:
			return
		}
	}
}

// generateSecureToken generates a secure random token for CSRF protection
func generateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// generateSessionID generates a secure random session ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// SessionMiddleware provides HTTP middleware for session management
type SessionMiddleware struct {
	store      *SessionStore
	cookieName string
}

// NewSessionMiddleware creates session middleware
func NewSessionMiddleware(store *SessionStore) *SessionMiddleware {
	return &SessionMiddleware{
		store:      store,
		cookieName: "beemflow_session",
	}
}

// Middleware wraps an HTTP handler with session management
func (m *SessionMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get session ID from cookie
		cookie, err := r.Cookie(m.cookieName)
		if err != nil {
			// No session cookie, continue without session
			next.ServeHTTP(w, r)
			return
		}

		// Validate session
		session, exists := m.store.GetSession(cookie.Value)
		if !exists {
			// Invalid/expired session, clear cookie
			http.SetCookie(w, &http.Cookie{
				Name:     m.cookieName,
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
				Secure:   r.TLS != nil,
				SameSite: http.SameSiteLaxMode,
			})
			next.ServeHTTP(w, r)
			return
		}

		// Add session to request context
		ctx := context.WithValue(r.Context(), "session", session)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// GetSessionFromRequest extracts session from request context
func GetSessionFromRequest(r *http.Request) (*Session, bool) {
	session, ok := r.Context().Value("session").(*Session)
	return session, ok
}

// RequireSession middleware that requires a valid session
func (m *SessionMiddleware) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, exists := GetSessionFromRequest(r)
		if !exists {
			// Redirect to login or show error
			http.Redirect(w, r, "/oauth/login", http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// SetSessionCookie sets a session cookie for the given session
func (m *SessionMiddleware) SetSessionCookie(w http.ResponseWriter, r *http.Request, session *Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    session.ID,
		Path:     "/",
		Expires:  session.ExpiresAt,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie clears the session cookie
func (m *SessionMiddleware) ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}
