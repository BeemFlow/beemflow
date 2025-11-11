//! BeemFlow - Workflow orchestration runtime
//!
//! This library provides a complete workflow engine that can be:
//! - Used as a library in other Rust applications
//! - Run as a CLI tool (`flow` binary)
//! - Exposed as an HTTP API server
//! - Exposed as an MCP server for AI tools
//!
//! # Architecture
//!
//! BeemFlow is GitHub Actions for every business process. It features:
//! - Text-first YAML/JSON workflow definitions
//! - Universal protocol across CLI, HTTP, and MCP interfaces
//! - Template-based execution with Handlebars
//! - Pluggable adapters for tools and services
//! - Multiple storage backends (in-memory, SQLite, PostgreSQL)
//! - Event-driven architecture
//! - OAuth 2.1 support
//!
//! # Example
//!
//! ```rust,no_run
//! use beemflow::core::create_dependencies;
//! use beemflow::config::Config;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize dependencies (engine, storage, etc.)
//!     let config = Config::default();
//!     let deps = create_dependencies(&config).await?;
//!
//!     // Execute a flow (with user and tenant context)
//!     let flow = beemflow::dsl::parse_file("flow.yaml", None)?;
//!     let outputs = deps.engine.execute(&flow, std::collections::HashMap::new(), "default_user", "default").await?;
//!     println!("{:?}", outputs);
//!
//!     Ok(())
//! }
//! ```

// Core modules
pub mod constants;
pub mod error;
pub mod model;

// ⭐ Unified operations - the key to CLI/HTTP/MCP parity
pub mod core;

// Execution components
pub mod adapter;
pub mod cli;
pub mod dsl;
pub mod engine;

// Infrastructure
pub mod audit;
pub mod blob;
pub mod config;
pub mod cron;
pub mod registry;
pub mod secrets;
pub mod storage;
pub mod telemetry;

// Interface layers (all delegate to operations)
pub mod auth;
pub mod http;
pub mod mcp;

// Utilities
pub mod utils;

// Re-exports for convenience
pub use engine::Engine;
pub use error::{BeemFlowError, Result};
pub use model::{Flow, FlowName, ResumeToken, Run, RunId, Step, StepId};

/// Initialize logging for the application
pub fn init_logging() {
    use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "beemflow=info".into()))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();
}
