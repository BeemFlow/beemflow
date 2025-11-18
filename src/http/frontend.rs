//! Frontend asset serving for integrated SPA deployment
//!
//! Provides routes to serve React frontend with proper SPA fallback for client-side routing.
//!
//! # Embedding Strategy
//!
//! Frontend assets are embedded at compile-time using rust-embed.
//! This creates a truly standalone binary that can be distributed without dependencies.
//!
//! # Architecture
//!
//! This module enables single-server deployment where the backend serves both:
//! - API endpoints (under /api/*)
//! - React frontend (embedded in binary)
//!
//! # Route Priority
//!
//! **CRITICAL:** This module MUST be registered AFTER all API routes to avoid conflicts.
//!
//! Correct order:
//! 1. API routes (/api/*, /oauth/*, /healthz, etc.) - highest priority
//! 2. Static assets (/assets/*) - medium priority
//! 3. SPA fallback (/*) - lowest priority (catch-all)
//!
//! # SPA Fallback Pattern
//!
//! For unmatched routes, serve index.html to support React Router:
//! - GET /flows/new → No API route → Serves index.html → React Router handles
//! - GET /oauth/success → No API route → Serves index.html → React Router handles
//! - GET /unknown → No API route → Serves index.html → React Router shows 404
//!
//! # Build Requirements
//!
//! Frontend must be built BEFORE compiling Rust:
//! ```bash
//! cd frontend && npm run build
//! cd .. && cargo build --release
//! ```
//!
//! The frontend/dist/ folder is embedded at compile-time via rust-embed.

use axum::{
    Router,
    extract::Path as AxumPath,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use rust_embed::RustEmbed;

/// Frontend assets embedded at compile-time
///
/// The frontend/dist/ folder is embedded into the binary at compile time.
/// If the folder doesn't exist during compilation, rust-embed will fail with clear error.
///
/// Build frontend first: cd frontend && npm run build
#[derive(RustEmbed)]
#[folder = "frontend/dist/"]
#[prefix = ""]
struct FrontendAssets;

/// Create routes for serving React frontend
///
/// Frontend assets are embedded in the binary at compile-time using rust-embed.
/// This creates a standalone executable that can be distributed without the frontend/dist/ folder.
///
/// # Requirements
///
/// - Frontend must be built BEFORE compiling Rust: `cd frontend && npm run build`
/// - Must be registered AFTER all API routes to avoid shadowing them
///
/// # Returns
///
/// Router with embedded frontend serving routes
///
/// # Example
///
/// ```rust,ignore
/// let app = Router::new()
///     .merge(api_routes)                  // Register API first
///     .merge(create_frontend_routes());   // Frontend last (fallback)
/// ```
pub fn create_frontend_routes() -> Router {
    tracing::info!("Serving React frontend from embedded assets");

    Router::new()
        // Catch-all route for both assets and SPA fallback
        .route("/{*path}", get(serve_embedded_frontend))
        // Also handle root path explicitly
        .route("/", get(serve_embedded_index))
}

/// Serve embedded frontend assets or SPA fallback
async fn serve_embedded_frontend(AxumPath(path): AxumPath<String>) -> impl IntoResponse {
    let path = path.trim_start_matches('/');

    // Try to serve the specific asset
    if let Some(content) = FrontendAssets::get(path) {
        let mime = mime_guess::from_path(path)
            .first_or_octet_stream()
            .as_ref()
            .to_string();

        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, mime.as_str())],
            content.data.into_owned(),
        )
            .into_response();
    }

    // SPA fallback: serve index.html for unmatched routes
    // This enables React Router to handle /flows, /oauth, /runs, etc.
    serve_embedded_index().await.into_response()
}

/// Serve the embedded index.html (SPA entry point)
async fn serve_embedded_index() -> impl IntoResponse {
    match FrontendAssets::get("index.html") {
        Some(content) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            content.data.into_owned(),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            "Frontend not embedded. Build frontend before compiling: cd frontend && npm run build",
        )
            .into_response(),
    }
}
