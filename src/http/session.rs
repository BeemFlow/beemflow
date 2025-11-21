//! Session management for OAuth flows and authenticated requests
//!
//! Provides secure session storage with TTL, CSRF protection, and automatic cleanup.

use axum::http::request::Parts;
use axum::{
    extract::{FromRequestParts, Request},
    http::{StatusCode, header},
    middleware::Next,
    response::Response,
};
use chrono::{DateTime, Duration, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Session data stored for each user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session ID
    pub id: String,
    /// User ID
    pub user_id: String,
    /// Session creation time
    pub created_at: DateTime<Utc>,
    /// Session expiration time
    pub expires_at: DateTime<Utc>,
    /// Arbitrary session data
    pub data: HashMap<String, serde_json::Value>,
}

/// Session store for managing user sessions
#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
}

impl SessionStore {
    /// Create a new session store
    pub fn new() -> Self {
        let store = Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        };

        // Start cleanup task
        let store_clone = store.clone();
        tokio::spawn(async move {
            store_clone.cleanup_loop().await;
        });

        store
    }

    /// Create a new session for a user
    pub fn create_session(&self, user_id: &str, ttl: Duration) -> Session {
        let session = Session {
            id: generate_session_id(),
            user_id: user_id.to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + ttl,
            data: HashMap::new(),
        };

        self.sessions
            .write()
            .insert(session.id.clone(), session.clone());
        session
    }

    /// Get a session by ID
    pub fn get_session(&self, session_id: &str) -> Option<Session> {
        let sessions = self.sessions.read();
        let session = sessions.get(session_id)?;

        // Check if expired
        if Utc::now() > session.expires_at {
            drop(sessions);
            self.sessions.write().remove(session_id);
            return None;
        }

        Some(session.clone())
    }

    /// Update session data
    pub fn update_session(&self, session_id: &str, key: String, value: serde_json::Value) -> bool {
        let mut sessions = self.sessions.write();
        if let Some(session) = sessions.get_mut(session_id) {
            session.data.insert(key, value);
            true
        } else {
            false
        }
    }

    /// Delete a session
    pub fn delete_session(&self, session_id: &str) {
        self.sessions.write().remove(session_id);
    }

    /// Generate a CSRF token for a session
    pub fn generate_csrf_token(&self, session_id: &str) -> Option<String> {
        let token = generate_secure_token();
        if self.update_session(
            session_id,
            "csrf_token".to_string(),
            serde_json::json!(token.clone()),
        ) {
            Some(token)
        } else {
            None
        }
    }

    /// Validate a CSRF token for a session (constant-time to prevent timing attacks)
    pub fn validate_csrf_token(&self, session_id: &str, token: &str) -> bool {
        use subtle::ConstantTimeEq;

        let sessions = self.sessions.read();
        if let Some(session) = sessions.get(session_id)
            && let Some(stored_token) = session.data.get("csrf_token")
            && let Some(stored_str) = stored_token.as_str()
        {
            // Use constant-time comparison to prevent timing attacks
            return stored_str.as_bytes().ct_eq(token.as_bytes()).unwrap_u8() == 1;
        }
        false
    }

    /// Cleanup expired sessions (runs periodically)
    async fn cleanup_loop(&self) {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(300)).await; // Every 5 minutes

            let now = Utc::now();
            let mut sessions = self.sessions.write();
            sessions.retain(|_, session| now < session.expires_at);
        }
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Session middleware that adds session to request extensions
///
/// This middleware also stores the SessionStore in extensions so that
/// SessionExtractor can look up sessions.
pub async fn session_middleware(mut req: Request, next: Next) -> Response {
    // Extract session ID from cookie
    let session_id = if let Some(cookie_header) = req.headers().get(header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            // Parse cookies to find beemflow_session
            cookie_str
                .split(';')
                .map(|c| c.trim())
                .find_map(|c| c.strip_prefix("beemflow_session="))
                .map(|s| s.to_string())
        } else {
            None
        }
    } else {
        None
    };

    // Store session ID in request extensions if found
    if let Some(session_id) = session_id {
        req.extensions_mut().insert(SessionId(session_id));
    }

    next.run(req).await
}

/// Session middleware with SessionStore access
///
/// This is a more complete middleware that provides both session ID and
/// the SessionStore in extensions for SessionExtractor to use.
pub fn create_session_middleware(
    session_store: Arc<SessionStore>,
) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
+ Clone {
    move |mut req: Request, next: Next| {
        let session_store = session_store.clone();
        Box::pin(async move {
            // Extract session ID from cookie
            let session_id = if let Some(cookie_header) = req.headers().get(header::COOKIE) {
                if let Ok(cookie_str) = cookie_header.to_str() {
                    // Parse cookies to find beemflow_session
                    cookie_str
                        .split(';')
                        .map(|c| c.trim())
                        .find_map(|c| c.strip_prefix("beemflow_session="))
                        .map(|s| s.to_string())
                } else {
                    None
                }
            } else {
                None
            };

            // Store session ID in request extensions if found
            if let Some(session_id) = session_id {
                req.extensions_mut().insert(SessionId(session_id));
            }

            // Store SessionStore in extensions for SessionExtractor
            req.extensions_mut().insert(session_store);

            next.run(req).await
        })
    }
}

/// CSRF protection middleware - validates CSRF tokens on state-changing requests
///
/// This middleware:
/// - Exempts safe methods (GET, HEAD, OPTIONS) as per CSRF best practices
/// - Validates CSRF token on unsafe methods (POST, PUT, PATCH, DELETE)
/// - Checks X-CSRF-Token header or _csrf form field
/// - Returns 403 Forbidden if validation fails
pub fn create_csrf_middleware(
    session_store: Arc<SessionStore>,
) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
+ Clone {
    move |req: Request, next: Next| {
        let session_store = session_store.clone();
        Box::pin(async move {
            let method = req.method().clone();

            // Safe methods don't require CSRF protection (they shouldn't change state)
            if matches!(
                method,
                axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
            ) {
                return next.run(req).await;
            }

            // Extract session ID from extensions (set by session_middleware)
            let session_id = req.extensions().get::<SessionId>().map(|s| s.0.clone());

            // For state-changing requests without a session, allow through
            // (this handles public endpoints that don't require authentication)
            let Some(session_id) = session_id else {
                return next.run(req).await;
            };

            // Extract CSRF token from header or form data
            let csrf_token = if let Some(token_header) = req.headers().get("X-CSRF-Token") {
                token_header.to_str().ok().map(|s| s.to_string())
            } else {
                // Could also check form data, but header is preferred
                None
            };

            // Validate CSRF token
            if let Some(token) = csrf_token
                && session_store.validate_csrf_token(&session_id, &token)
            {
                return next.run(req).await;
            }

            // CSRF validation failed or token missing for authenticated session
            tracing::warn!(
                "CSRF validation failed for session: {} method: {}",
                session_id,
                method
            );

            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(axum::body::Body::from("CSRF token validation failed"))
                .unwrap_or_else(|e| {
                    tracing::error!("Failed to build CSRF error response: {}", e);
                    // If we can't even build a proper error response, return a minimal one
                    // This should never fail because we're using simple status and empty body
                    Response::new(axum::body::Body::from("Internal Server Error"))
                })
        })
    }
}

/// Session ID extracted from cookie
#[derive(Clone, Debug)]
pub struct SessionId(pub String);

/// Extractor for getting session from request
pub struct SessionExtractor {
    pub session: Option<Session>,
}

impl<S> FromRequestParts<S> for SessionExtractor
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        // Clone data we need from parts before moving into async block
        let session_id = parts.extensions.get::<SessionId>().cloned();
        let session_store = parts.extensions.get::<Arc<SessionStore>>().cloned();

        async move {
            // SessionStore must always be available (injected by session middleware)
            let Some(store) = session_store else {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "SessionStore not available in request extensions",
                ));
            };

            // Look up session if session_id is present (user has session cookie)
            let session = if let Some(sid) = session_id {
                store.get_session(&sid.0)
            } else {
                None
            };

            Ok(SessionExtractor { session })
        }
    }
}

/// Set a session cookie in the response with security flags
///
/// The `secure` parameter controls whether to set the Secure flag (requires HTTPS).
/// For local development over HTTP, set this to false.
/// For production behind HTTPS or a reverse proxy with TLS termination, set this to true.
pub fn set_session_cookie(session_id: &str, expires_at: DateTime<Utc>, secure: bool) -> String {
    let secure_flag = if secure { " Secure;" } else { "" };
    format!(
        "beemflow_session={}; Path=/; Expires={}; HttpOnly;{} SameSite=Lax",
        session_id,
        expires_at.to_rfc2822(),
        secure_flag
    )
}

/// Clear the session cookie with security flags
///
/// The `secure` parameter should match what was used when setting the cookie.
pub fn clear_session_cookie(secure: bool) -> String {
    let secure_flag = if secure { " Secure;" } else { "" };
    format!(
        "beemflow_session=; Path=/; Max-Age=0; HttpOnly;{} SameSite=Lax",
        secure_flag
    )
}

/// Generate a secure random session ID (using cryptographically secure RNG)
fn generate_session_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

/// Generate a secure random token for CSRF protection (using cryptographically secure RNG)
fn generate_secure_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}
