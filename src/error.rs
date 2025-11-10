//! Error types for BeemFlow
//!
//! This module provides a comprehensive error hierarchy using thiserror.
//! All errors can be converted to BeemFlowError for unified error handling.

use thiserror::Error;

/// Main error type for BeemFlow operations
#[derive(Error, Debug)]
pub enum BeemFlowError {
    #[error("Flow validation failed: {0}")]
    Validation(String),

    #[error("Template rendering failed: {0}")]
    Template(#[from] TemplateError),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Adapter error: {0}")]
    Adapter(String),

    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("OAuth error: {0}")]
    OAuth(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("MCP error: {0}")]
    Mcp(String),

    #[error("Step execution failed: {step_id}: {message}")]
    StepExecution { step_id: String, message: String },

    #[error("Await event pause: {0}")]
    AwaitEventPause(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Template-specific errors
#[derive(Error, Debug)]
pub enum TemplateError {
    #[error("Template syntax error: {0}")]
    Syntax(String),

    #[error("Variable not found: {0}")]
    VariableNotFound(String),

    #[error("Filter error: {0}")]
    Filter(String),

    #[error("Template render error: {0}")]
    Render(#[from] minijinja::Error),
}

/// Storage-specific errors
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[source] sqlx::Error),

    #[error("Not found: {entity} '{id}'")]
    NotFound { entity: String, id: String },

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("UUID parse error: {0}")]
    UuidParse(#[from] uuid::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

// Implement From for sqlx::Error - now preserves the original error
impl From<sqlx::Error> for StorageError {
    fn from(err: sqlx::Error) -> Self {
        StorageError::Database(err)
    }
}

impl From<sqlx::Error> for BeemFlowError {
    fn from(err: sqlx::Error) -> Self {
        BeemFlowError::Storage(StorageError::from(err))
    }
}

// Implement From for uuid::Error through StorageError
impl From<uuid::Error> for BeemFlowError {
    fn from(err: uuid::Error) -> Self {
        BeemFlowError::Storage(StorageError::UuidParse(err))
    }
}

/// Network-specific errors
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("HTTP request failed: {0}")]
    Http(String),

    #[error("Connection timeout")]
    Timeout,

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
}

/// Convenient result type for BeemFlow operations
pub type Result<T> = std::result::Result<T, BeemFlowError>;

impl BeemFlowError {
    /// Create a validation error
    #[inline]
    pub fn validation<S: Into<String>>(msg: S) -> Self {
        BeemFlowError::Validation(msg.into())
    }

    /// Create an adapter error
    #[inline]
    pub fn adapter<S: Into<String>>(msg: S) -> Self {
        BeemFlowError::Adapter(msg.into())
    }

    /// Create a config error
    #[inline]
    pub fn config<S: Into<String>>(msg: S) -> Self {
        BeemFlowError::Config(msg.into())
    }

    /// Create a storage error with a message
    #[inline]
    pub fn storage<S: Into<String>>(msg: S) -> Self {
        BeemFlowError::Storage(StorageError::Connection(msg.into()))
    }

    /// Create an auth error
    #[inline]
    pub fn auth<S: Into<String>>(msg: S) -> Self {
        BeemFlowError::OAuth(msg.into())
    }

    /// Create a not found error
    #[inline]
    pub fn not_found(entity: impl Into<String>, id: impl Into<String>) -> Self {
        BeemFlowError::Storage(StorageError::NotFound {
            entity: entity.into(),
            id: id.into(),
        })
    }

    /// Create a step execution error
    #[inline]
    pub fn step_execution<S: Into<String>>(step_id: S, message: S) -> Self {
        BeemFlowError::StepExecution {
            step_id: step_id.into(),
            message: message.into(),
        }
    }

    /// Create an internal error for unexpected conditions
    #[inline]
    pub fn internal<S: Into<String>>(msg: S) -> Self {
        BeemFlowError::Internal(msg.into())
    }

    /// Add context to an error
    pub fn context<C: std::fmt::Display>(self, context: C) -> Self {
        match self {
            Self::Validation(msg) => Self::Validation(format!("{}: {}", context, msg)),
            Self::Adapter(msg) => Self::Adapter(format!("{}: {}", context, msg)),
            Self::Config(msg) => Self::Config(format!("{}: {}", context, msg)),
            Self::OAuth(msg) => Self::OAuth(format!("{}: {}", context, msg)),
            Self::Mcp(msg) => Self::Mcp(format!("{}: {}", context, msg)),
            Self::Internal(msg) => Self::Internal(format!("{}: {}", context, msg)),
            // For errors with source, preserve the source and add context at the top level
            other => Self::Internal(format!("{}: {}", context, other)),
        }
    }
}
