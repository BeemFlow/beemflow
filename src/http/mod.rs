//! HTTP server for BeemFlow
//!
//! Provides REST API for all BeemFlow operations with complete parity
//! with CLI and MCP interfaces.

pub mod frontend;
pub mod session;
pub mod template;
pub mod webhook;

use self::webhook::{WebhookManagerState, create_webhook_routes};
use crate::auth::{
    OAuthConfig, OAuthServerState,
    client::{
        OAuthClientState, create_protected_oauth_client_routes, create_public_oauth_client_routes,
    },
    create_oauth_routes,
};
use crate::config::{Config, HttpConfig};
use crate::core::OperationRegistry;
use crate::mcp::{McpServerState, create_mcp_metadata_routes, create_mcp_routes};
use crate::{BeemFlowError, Result};
use axum::{
    Router,
    extract::{Json, Path as AxumPath, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
};
use parking_lot::RwLock;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    LatencyUnit,
    cors::CorsLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
};

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    registry: Arc<OperationRegistry>,
    session_store: Arc<session::SessionStore>,
    oauth_client: Arc<crate::auth::OAuthClientManager>,
    storage: Arc<dyn crate::storage::Storage>,
    template_renderer: Arc<template::TemplateRenderer>,
}

/// Configuration for which server interfaces to enable
#[derive(Debug, Clone)]
pub struct ServerInterfaces {
    pub http_api: bool,
    pub mcp: bool,
    pub oauth_server: bool,
}

impl Default for ServerInterfaces {
    fn default() -> Self {
        Self {
            http_api: true,
            mcp: true,
            oauth_server: false, // Opt-in
        }
    }
}

/// Error type for HTTP handlers with enhanced error details
#[derive(Debug)]
pub struct AppError(BeemFlowError);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_type, message) = match &self.0 {
            BeemFlowError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, "validation_error", msg.clone())
            }
            BeemFlowError::Storage(e) => match e {
                crate::error::StorageError::NotFound { entity, id } => (
                    StatusCode::NOT_FOUND,
                    "not_found",
                    format!("{} not found: {}", entity, id),
                ),
                _ => {
                    // Log full error details internally
                    tracing::error!("Storage error: {:?}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "storage_error",
                        "An internal storage error occurred".to_string(),
                    )
                }
            },
            BeemFlowError::StepExecution { step_id, message } => {
                // Log full error details internally
                tracing::error!("Step execution failed: {} - {}", step_id, message);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "execution_error",
                    "A step execution error occurred".to_string(),
                )
            }
            BeemFlowError::OAuth(msg) => (StatusCode::UNAUTHORIZED, "auth_error", msg.clone()),
            BeemFlowError::Adapter(msg) => (StatusCode::BAD_GATEWAY, "adapter_error", msg.clone()),
            BeemFlowError::Mcp(msg) => (StatusCode::BAD_GATEWAY, "mcp_error", msg.clone()),
            BeemFlowError::Network(e) => {
                // Log full error details internally
                tracing::error!("Network error: {:?}", e);
                (
                    StatusCode::BAD_GATEWAY,
                    "network_error",
                    "A network error occurred".to_string(),
                )
            }
            _ => {
                // Log full error details internally
                tracing::error!("Internal error: {:?}", self.0);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "An internal error occurred".to_string(),
                )
            }
        };

        // Log the sanitized error response
        tracing::debug!(
            error_type = error_type,
            status = %status,
            message = %message,
            "HTTP request error response"
        );

        let body = json!({
            "error": {
                "type": error_type,
                "message": message,
                "status": status.as_u16(),
            }
        });

        (status, Json(body)).into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<BeemFlowError>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

/// Marker to indicate the request is over HTTPS (from X-Forwarded-Proto)
#[derive(Clone, Copy, Debug)]
pub struct IsHttps(pub bool);

/// Validate frontend URL for security
///
/// Ensures the frontend URL is safe to use in OAuth redirects to prevent open redirect attacks.
/// This is a security-critical validation that prevents attackers from redirecting OAuth flows
/// to malicious domains.
///
/// # Security Requirements
///
/// 1. Must be valid HTTP/HTTPS URL
/// 2. Must use HTTPS in production (HTTP only allowed for localhost)
/// 3. No URL fragments allowed (prevents fragment-based attacks)
/// 4. Only http:// and https:// schemes allowed (prevents javascript:, data:, etc.)
///
/// # Example Valid URLs
///
/// - `http://localhost:5173` (development)
/// - `http://127.0.0.1:5173` (development)
/// - `https://app.beemflow.com` (production)
///
/// # Example Invalid URLs
///
/// - `http://app.beemflow.com` (HTTP in production - rejected)
/// - `javascript:alert(1)` (invalid scheme)
/// - `https://app.beemflow.com#evil` (contains fragment)
fn validate_frontend_url(url: &str) -> Result<()> {
    use url::Url;

    // Parse URL
    let parsed = Url::parse(url)
        .map_err(|e| BeemFlowError::validation(format!("Invalid frontend URL format: {}", e)))?;

    // Get host (fail fast if missing)
    let host = parsed
        .host_str()
        .ok_or_else(|| BeemFlowError::validation("Frontend URL must have a valid host"))?;

    // Only allow HTTP and HTTPS schemes (prevent javascript:, data:, file:, etc.)
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(BeemFlowError::validation(format!(
            "Frontend URL must use http:// or https:// scheme, not {}://",
            parsed.scheme()
        )));
    }

    // Reject URLs with userinfo (username:password@) - potential phishing vector
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(BeemFlowError::validation(
            "Frontend URL must not contain username or password",
        ));
    }

    // Require HTTPS in production (HTTP only for localhost/127.*)
    if parsed.scheme() == "http" {
        // Check if this is a localhost address (positive logic)
        let is_localhost = host == "localhost" || host == "127.0.0.1" || host.starts_with("127.");

        if !is_localhost {
            return Err(BeemFlowError::validation(
                "Frontend URL must use HTTPS for non-localhost domains. \
                 HTTP is only allowed for localhost/127.0.0.1 (development).",
            ));
        }
    }

    // No fragments allowed (prevents fragment-based redirect attacks)
    if parsed.fragment().is_some() {
        return Err(BeemFlowError::validation(
            "Frontend URL must not contain URL fragments (#)",
        ));
    }

    Ok(())
}

/// Middleware to detect HTTPS from X-Forwarded-Proto header when behind a reverse proxy
///
/// This middleware checks the X-Forwarded-Proto header and sets an IsHttps marker
/// in request extensions if the protocol is HTTPS. This is used for secure cookie flags.
///
/// Only active when `trust_proxy` is enabled in config.
///
/// Uses Arc<HttpConfig> to avoid cloning config on every request.
async fn proxy_headers_middleware(
    http_config: Arc<HttpConfig>,
    mut req: Request,
    next: Next,
) -> Response {
    if http_config.trust_proxy {
        // Check X-Forwarded-Proto header
        if let Some(proto) = req.headers().get("x-forwarded-proto")
            && let Ok(proto_str) = proto.to_str()
        {
            let is_https = proto_str.eq_ignore_ascii_case("https");
            req.extensions_mut().insert(IsHttps(is_https));

            if is_https {
                tracing::debug!("Request detected as HTTPS via X-Forwarded-Proto");
            }
        }
    } else if http_config.secure {
        // If not trusting proxy but secure flag is set, assume HTTPS
        req.extensions_mut().insert(IsHttps(true));
    } else {
        // Default to HTTP
        req.extensions_mut().insert(IsHttps(false));
    }

    next.run(req).await
}

// ============================================================================
// AUTO-GENERATED ROUTES - All operation routes are now generated from metadata
// ============================================================================
// The old handler macros are no longer needed - routes are auto-generated
// in build_operation_routes() from operation metadata

/// Start the HTTP server with configurable interfaces
pub async fn start_server(config: Config, interfaces: ServerInterfaces) -> Result<()> {
    // Initialize telemetry
    crate::telemetry::init(config.tracing.as_ref())?;

    // Ensure HTTP config exists (use defaults if not provided)
    let mut http_config = config.http.as_ref().cloned().unwrap_or_else(|| HttpConfig {
        host: "127.0.0.1".to_string(),
        port: crate::constants::DEFAULT_HTTP_PORT,
        secure: false, // Default to false for local development
        allowed_origins: None,
        trust_proxy: false,
        enable_http_api: true,
        enable_mcp: true,
        enable_oauth_server: false,
        oauth_issuer: None,
        public_url: None,
        frontend_url: None, // Integrated mode by default
    });

    // Allow environment variable override for frontend URL (development convenience)
    if http_config.frontend_url.is_none()
        && let Ok(frontend_url) = std::env::var("FRONTEND_URL")
    {
        // SECURITY: Validate frontend URL before accepting to prevent open redirect attacks
        if let Err(e) = validate_frontend_url(&frontend_url) {
            tracing::error!(
                "Invalid FRONTEND_URL rejected: {}. This is a security-critical configuration. \
                 See documentation for valid formats.",
                e
            );
            return Err(e);
        }

        tracing::info!("Frontend URL loaded from environment: {}", frontend_url);
        http_config.frontend_url = Some(frontend_url);
    }

    // Use centralized dependency creation from core module
    let mut dependencies = crate::core::create_dependencies(&config).await?;

    // Create cron manager ONLY in HTTP server mode (prevents duplicate executions)
    // CLI and MCP-stdio modes don't need cron scheduler
    dependencies.cron_manager = match crate::cron::CronManager::new(
        dependencies.storage.clone(),
        dependencies.engine.clone(),
    )
    .await
    {
        Ok(manager) => {
            let manager = Arc::new(manager);

            // Initial sync - load all cron jobs on startup
            if let Err(e) = manager.sync().await {
                tracing::warn!(error = %e, "Failed to sync cron jobs on startup");
            }

            Some(manager)
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Failed to initialize cron scheduler, continuing without scheduling"
            );
            None
        }
    };

    // Create registry (takes ownership, so we clone dependencies to keep using them below)
    let registry = Arc::new(OperationRegistry::new(dependencies.clone()));

    // Create session store
    let session_store = Arc::new(session::SessionStore::new());

    // Initialize template renderer
    let mut template_renderer = template::TemplateRenderer::new("static");
    template_renderer.load_oauth_templates().await?;
    let template_renderer = Arc::new(template_renderer);

    let state = AppState {
        registry,
        session_store: session_store.clone(),
        oauth_client: dependencies.oauth_client.clone(),
        storage: dependencies.storage.clone(),
        template_renderer,
    };

    // Create OAuth server state
    let oauth_config = OAuthConfig {
        issuer: http_config
            .oauth_issuer
            .clone()
            .unwrap_or_else(|| format!("http://{}:{}", http_config.host, http_config.port)),
        ..Default::default()
    };

    let oauth_server_state = Arc::new(OAuthServerState {
        storage: dependencies.storage.clone(),
        config: oauth_config,
        rate_limiter: Arc::new(RwLock::new(HashMap::new())),
        session_store: session_store.clone(),
    });

    // Create webhook manager state
    let webhook_state = WebhookManagerState {
        registry_manager: dependencies.registry_manager.clone(),
        secrets_provider: dependencies.config.create_secrets_provider(),
        storage: dependencies.storage.clone(),
        engine: dependencies.engine.clone(),
        config: dependencies.config.clone(),
    };

    // Build router with config for CORS
    // Note: All static assets are embedded in the binary - no file system access needed
    let app = build_router(
        state,
        webhook_state,
        oauth_server_state,
        &http_config,
        interfaces,
        &dependencies,
    );

    // Determine bind address
    let addr = format!("{}:{}", http_config.host, http_config.port);
    let socket_addr: SocketAddr = addr
        .parse()
        .map_err(|e| BeemFlowError::config(format!("Invalid address {}: {}", addr, e)))?;

    tracing::info!("Starting HTTP server on {}", socket_addr);

    // Create TCP listener
    let listener = tokio::net::TcpListener::bind(socket_addr).await?;

    // Create server with graceful shutdown
    let server = axum::serve(listener, app);

    // Set up graceful shutdown signal handler
    let shutdown_signal = async {
        // Wait for SIGTERM (Docker/Kubernetes) or SIGINT (Ctrl+C)
        let ctrl_c = async {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to install Ctrl+C signal handler");
        };

        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM signal handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                tracing::info!("Received SIGINT (Ctrl+C), initiating graceful shutdown...");
            }
            _ = terminate => {
                tracing::info!("Received SIGTERM, initiating graceful shutdown...");
            }
        }
    };

    // Run server with graceful shutdown
    tracing::info!("Server ready to accept connections");
    server
        .with_graceful_shutdown(shutdown_signal)
        .await
        .map_err(|e| BeemFlowError::config(format!("Server error: {}", e)))?;

    // Shutdown cron scheduler
    if let Some(cron_mgr) = &dependencies.cron_manager
        && let Err(e) = cron_mgr.shutdown().await
    {
        tracing::error!(error = %e, "Failed to shutdown cron scheduler");
    }

    tracing::info!("Server shutdown complete");
    Ok(())
}

/// Auto-generate routes from operation metadata using macro-generated registration functions
fn build_operation_routes(state: &AppState) -> Router {
    let deps = state.registry.get_dependencies();

    // Use generated registration functions from each operation group
    // These functions call the http_route() method on each operation
    [
        crate::core::flows::flows::register_http_routes,
        crate::core::runs::runs::register_http_routes,
        crate::core::tools::tools::register_http_routes,
        crate::core::mcp::mcp::register_http_routes,
        crate::core::system::system::register_http_routes,
    ]
    .into_iter()
    .fold(Router::new(), |router, register_fn| {
        router.merge(register_fn(deps.clone()))
    })
}

/// Build the router with all endpoints
fn build_router(
    state: AppState,
    webhook_state: WebhookManagerState,
    oauth_server_state: Arc<OAuthServerState>,
    http_config: &HttpConfig,
    interfaces: ServerInterfaces,
    deps: &crate::core::Dependencies,
) -> Router {
    let mut app = Router::new();

    // Always serve static assets
    app = app.route("/static/{*path}", get(serve_static_asset));

    // OAuth SERVER routes (opt-in via --oauth-server)
    if interfaces.oauth_server {
        let oauth_server_routes = create_oauth_routes(oauth_server_state);
        app = app.merge(oauth_server_routes);
    }

    // OAuth CLIENT routes (split into public and protected)
    let oauth_client_state = Arc::new(OAuthClientState {
        oauth_client: state.oauth_client.clone(),
        storage: state.storage.clone(),
        registry_manager: state.registry.get_dependencies().registry_manager.clone(),
        session_store: state.session_store.clone(),
        template_renderer: state.template_renderer.clone(),
        frontend_url: http_config.frontend_url.clone(),
    });

    // Public OAuth routes (callbacks - no auth required)
    // These must be public because OAuth providers redirect to them
    let public_oauth_routes = create_public_oauth_client_routes(oauth_client_state.clone());
    app = app.merge(public_oauth_routes);

    // Protected OAuth routes (API endpoints for managing OAuth connections)
    // Nest under /api for consistency with other API endpoints
    // TODO: Apply auth middleware when feat/multi-tenant is merged
    let protected_oauth_routes = create_protected_oauth_client_routes(oauth_client_state);
    app = app.nest("/api", protected_oauth_routes);

    // MCP routes (conditionally enabled)
    if interfaces.mcp {
        let oauth_issuer = if interfaces.oauth_server {
            Some(
                http_config
                    .oauth_issuer
                    .clone()
                    .unwrap_or_else(|| format!("http://{}:{}", http_config.host, http_config.port)),
            )
        } else {
            None
        };

        let mcp_state = Arc::new(McpServerState {
            operations: state.registry.clone(),
            oauth_issuer: oauth_issuer.clone(),
            storage: deps.storage.clone(),
        });

        let mcp_routes = create_mcp_routes(mcp_state);
        app = app.merge(mcp_routes);

        // Add MCP metadata routes if OAuth is enabled
        if let Some(issuer) = oauth_issuer {
            let base_url = http_config
                .oauth_issuer
                .clone()
                .unwrap_or_else(|| format!("http://{}:{}", http_config.host, http_config.port));
            let metadata_routes = create_mcp_metadata_routes(issuer, base_url);
            app = app.merge(metadata_routes);
        }
    }

    // HTTP API routes (conditionally enabled)
    // All operation routes are nested under /api for clean separation from frontend
    if interfaces.http_api {
        let operation_routes = build_operation_routes(&state);
        app = app.nest("/api", operation_routes);
    }

    // Webhooks (always enabled)
    app = app.nest(
        "/webhooks",
        create_webhook_routes().with_state(webhook_state),
    );

    // System endpoints (always enabled - healthz, readyz, metrics)
    let system_routes = Router::new()
        .route("/healthz", get(health_handler))
        .route("/readyz", get(readiness_handler))
        .route("/metrics", get(metrics_handler))
        .with_state(state.storage.clone());
    app = app.merge(system_routes);

    // ============================================================================
    // FRONTEND SERVING (Must be registered LAST, before middleware)
    // ============================================================================
    // Serve React frontend from frontend/dist/ if not using separate frontend URL
    //
    // This must come after all API routes to avoid shadowing them.
    // The SPA fallback serves index.html for unmatched routes, enabling React Router.

    if http_config.frontend_url.is_none() {
        // Integrated mode: serve React build from backend
        tracing::info!("Running in integrated mode: serving frontend from frontend/dist/");
        app = app.merge(frontend::create_frontend_routes());
    } else {
        // Separate mode: API only, frontend served elsewhere
        if let Some(url) = &http_config.frontend_url {
            tracing::info!(
                "Running in separate frontend mode: API only. Frontend URL: {}",
                url
            );
            tracing::info!("Ensure CORS is properly configured for cross-origin requests");
        }
    }

    // Add comprehensive middleware stack
    app.layer(
        ServiceBuilder::new()
            // Proxy headers middleware (must come first to detect HTTPS)
            // Wrap config in Arc to avoid cloning on every request
            .layer(axum::middleware::from_fn({
                let config = Arc::new(http_config.clone());
                move |req, next| {
                    let config = config.clone(); // Clone Arc, not HttpConfig
                    async move { proxy_headers_middleware(config, req, next).await }
                }
            }))
            // Session middleware for OAuth flows and authenticated requests
            .layer(axum::middleware::from_fn(session::session_middleware))
            // Tracing layer for request/response logging
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(DefaultMakeSpan::new().include_headers(true))
                    .on_response(
                        DefaultOnResponse::new()
                            .level(tracing::Level::INFO)
                            .latency_unit(LatencyUnit::Micros),
                    ),
            )
            // CORS layer for cross-origin requests
            .layer({
                use axum::http::HeaderValue;

                // Build allowed origins based on deployment mode
                let allowed_origins: Vec<HeaderValue> =
                    if let Some(origins) = &http_config.allowed_origins {
                        // Explicit origins configured - use those
                        origins
                            .iter()
                            .filter_map(|origin| {
                                origin.parse().ok().or_else(|| {
                                    tracing::warn!("Invalid CORS origin in config: {}", origin);
                                    None
                                })
                            })
                            .collect()
                    } else if let Some(frontend_url) = &http_config.frontend_url {
                        // Separate frontend mode - allow frontend URL + localhost
                        let mut origins = vec![
                            format!("http://localhost:{}", http_config.port)
                                .parse()
                                .expect("valid localhost origin"),
                            format!("http://127.0.0.1:{}", http_config.port)
                                .parse()
                                .expect("valid 127.0.0.1 origin"),
                        ];

                        // Add frontend URL if valid
                        if let Ok(parsed_url) = frontend_url.parse::<HeaderValue>() {
                            origins.push(parsed_url);
                        } else {
                            tracing::error!(
                                "Invalid frontend_url in config: {}. CORS will not include this origin.",
                                frontend_url
                            );
                        }

                        // Also allow default Vite dev server ports in development
                        if frontend_url.contains(&format!("localhost:{}", crate::constants::DEFAULT_VITE_DEV_PORT))
                            || frontend_url.contains(&format!("localhost:{}", crate::constants::DEFAULT_VITE_DEV_PORT_ALT))
                        {
                            origins.push(
                                format!("http://localhost:{}", crate::constants::DEFAULT_VITE_DEV_PORT)
                                    .parse()
                                    .expect("valid Vite dev port"),
                            );
                            origins.push(
                                format!("http://localhost:{}", crate::constants::DEFAULT_VITE_DEV_PORT_ALT)
                                    .parse()
                                    .expect("valid Vite alt port"),
                            );
                        }

                        origins
                    } else {
                        // Integrated mode - same origin, minimal CORS
                        // Frontend embedded and served from same port as API
                        vec![
                            format!("http://localhost:{}", http_config.port)
                                .parse()
                                .expect("valid localhost origin"),
                            format!("http://127.0.0.1:{}", http_config.port)
                                .parse()
                                .expect("valid 127.0.0.1 origin"),
                        ]
                    };

                CorsLayer::new()
                    .allow_origin(allowed_origins)
                    .allow_methods([
                        axum::http::Method::GET,
                        axum::http::Method::POST,
                        axum::http::Method::PUT,
                        axum::http::Method::PATCH,
                        axum::http::Method::DELETE,
                        axum::http::Method::OPTIONS,
                    ])
                    .allow_headers([
                        axum::http::header::CONTENT_TYPE,
                        axum::http::header::AUTHORIZATION,
                        axum::http::header::HeaderName::from_static("x-requested-with"),
                    ])
                    .allow_credentials(true)
            }),
    )
}

// ============================================================================
// STATIC ASSET HANDLERS (Truly static assets only - CSS, JS, images)
// ============================================================================
//
// Note: HTML templates with Jinja2 syntax ({{ }}, {% %}) are NOT served here.
// They are embedded in TemplateRenderer and rendered with dynamic data.
// Only serve assets that don't need server-side processing.

/// Serve embedded static assets (CSS, JS, images, fonts)
///
/// Security: All assets are embedded at compile time from trusted sources.
/// No file system access needed - everything is compiled into the binary.
///
/// To add new static assets:
/// 1. Add the file to the static/ directory
/// 2. Add a match arm below with the path and content type
/// 3. Only add truly static files (CSS, JS, images) - NOT templates
async fn serve_static_asset(AxumPath(path): AxumPath<String>) -> impl IntoResponse {
    // Match on the requested path and return (content_type, content)
    let asset = match path.as_str() {
        // CSS files
        "oauth/style.css" => (
            "text/css; charset=utf-8",
            include_str!("../../static/oauth/style.css"),
        ),
        // Add more static assets here (JS, images, fonts, etc.)
        // Example: "js/app.js" => ("application/javascript", include_str!("../../static/js/app.js")),
        // Example: "images/logo.png" => ("image/png", include_bytes!("../../static/images/logo.png")),
        _ => {
            return (StatusCode::NOT_FOUND, "Asset not found").into_response();
        }
    };

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, asset.0)],
        asset.1,
    )
        .into_response()
}

// ============================================================================
// SYSTEM HANDLERS (Special cases not in operation registry)
// ============================================================================

/// Health check endpoint - lightweight check that the service is running
///
/// Returns 200 OK if the service process is alive. Does not check dependencies.
/// Use /readyz for a full readiness check including database connectivity.
async fn health_handler() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

/// Readiness check endpoint - verifies service is ready to handle requests
///
/// Returns 200 OK only if:
/// - Service is running
/// - Database is accessible
/// - All critical dependencies are healthy
///
/// Use this for Kubernetes readiness probes and load balancer health checks.
async fn readiness_handler(
    State(storage): State<Arc<dyn crate::storage::Storage>>,
) -> std::result::Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Check database connectivity by attempting a simple query
    // We use list_runs(1, 0) as a canary - if it succeeds, the database is accessible
    match storage.list_runs(1, 0).await {
        Ok(_) => {
            // Database is accessible
            Ok(Json(json!({
                "status": "ready",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "checks": {
                    "database": "ok"
                }
            })))
        }
        Err(e) => {
            // Database check failed
            tracing::error!("Readiness check failed: database error: {:?}", e);
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "status": "not_ready",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "checks": {
                        "database": "failed"
                    }
                })),
            ))
        }
    }
}

async fn metrics_handler() -> std::result::Result<(StatusCode, String), AppError> {
    let metrics = crate::telemetry::get_metrics()?;
    Ok((StatusCode::OK, metrics))
}

#[cfg(test)]
mod http_test;
#[cfg(test)]
mod session_test;
#[cfg(test)]
mod template_test;
#[cfg(test)]
mod webhook_test;
