//! Core data models for BeemFlow
//!
//! This module contains all the data structures that define BeemFlow workflows,
//! runs, steps, and related types. These models provide complete workflow orchestration
//! capabilities with strong type safety and comprehensive serialization support.
//!
//! It also includes domain-specific types with validation (FlowName, StepId, ResumeToken)
//! to prevent common mistakes through type safety.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::ops::Deref;
use uuid::Uuid;

// ============================================================================
// Domain Types - Validated newtypes for type safety
// ============================================================================

/// Flow identifier with validation
///
/// Ensures flow names are:
/// - Non-empty
/// - Valid identifiers (alphanumeric, underscore, hyphen)
/// - Not just whitespace
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FlowName(String);

impl FlowName {
    /// Create a new FlowName with validation
    pub fn new(name: impl Into<String>) -> crate::Result<Self> {
        let name = name.into();

        // Validate non-empty
        if name.trim().is_empty() {
            return Err(crate::BeemFlowError::validation(
                "Flow name cannot be empty",
            ));
        }

        // Validate characters (alphanumeric, underscore, hyphen, dot)
        if !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            return Err(crate::BeemFlowError::validation(format!(
                "Flow name '{}' contains invalid characters (only alphanumeric, _, -, . allowed)",
                name
            )));
        }

        Ok(Self(name))
    }

    /// Get the raw string value
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume self and return the inner String
    #[inline]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Deref for FlowName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for FlowName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for FlowName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// For test/debug builds: provide From<String> for convenience (.into())
// For production builds: provide TryFrom<String> for safety (.try_into()?)
#[cfg(any(test, debug_assertions))]
#[allow(clippy::expect_used)] // Test-only convenience trait
impl From<String> for FlowName {
    fn from(name: String) -> Self {
        Self::new(name).expect("Invalid flow name in test code")
    }
}

#[cfg(not(any(test, debug_assertions)))]
impl TryFrom<String> for FlowName {
    type Error = crate::BeemFlowError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        Self::new(name)
    }
}

/// Step identifier with validation
///
/// Ensures step IDs are:
/// - Non-empty
/// - Valid identifiers
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StepId(String);

impl StepId {
    /// Create a new StepId with validation
    ///
    /// Supports both static IDs and template expressions:
    /// - Static: `"process"`, `"send_email"`, `"step-1"`
    /// - Templated: `"process_{{ item_index }}"`, `"{{ step.name }}"`
    ///
    /// Templates are identified by presence of `{{` and `}}` and allow any characters.
    /// Static IDs only allow alphanumeric, underscore, and hyphen.
    pub fn new(id: impl Into<String>) -> crate::Result<Self> {
        let id = id.into();

        // Validate non-empty
        if id.trim().is_empty() {
            return Err(crate::BeemFlowError::validation("Step ID cannot be empty"));
        }

        // Check if this is a templated ID (contains {{ and }})
        let is_template = id.contains("{{") && id.contains("}}");

        if !is_template {
            // Strict validation for static IDs (alphanumeric, underscore, hyphen only)
            if !id
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
            {
                return Err(crate::BeemFlowError::validation(format!(
                    "Step ID '{}' contains invalid characters (only alphanumeric, _, - allowed)",
                    id
                )));
            }
        }
        // Templates allow any characters (validated at template rendering time)

        Ok(Self(id))
    }

    /// Create without validation - ONLY FOR TESTING
    #[cfg(test)]
    pub(crate) fn unchecked(id: String) -> Self {
        Self(id)
    }

    /// Get the raw string value
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume self and return the inner String
    #[inline]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Deref for StepId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for StepId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for StepId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// For test/debug builds: provide From<String> for convenience (.into())
// For production builds: provide TryFrom<String> for safety (.try_into()?)
#[cfg(any(test, debug_assertions))]
#[allow(clippy::expect_used)] // Test-only convenience trait
impl From<String> for StepId {
    fn from(id: String) -> Self {
        Self::new(id).expect("Invalid step ID in test code")
    }
}

#[cfg(not(any(test, debug_assertions)))]
impl TryFrom<String> for StepId {
    type Error = crate::BeemFlowError;

    fn try_from(id: String) -> Result<Self, Self::Error> {
        Self::new(id)
    }
}

/// Resume token for paused runs (awaiting events)
///
/// Opaque identifier for resuming paused workflow runs.
/// Validates that the token is a valid UUID v4.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ResumeToken(String);

impl ResumeToken {
    /// Create a new resume token (generates a UUID v4)
    pub fn generate() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Create from an existing string with validation
    pub fn new(token: impl Into<String>) -> crate::Result<Self> {
        let token = token.into();

        // Validate it's a valid UUID
        Uuid::parse_str(&token)
            .map_err(|_| crate::BeemFlowError::validation("Resume token must be a valid UUID"))?;

        Ok(Self(token))
    }

    /// Get the raw string value
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume self and return the inner String
    #[inline]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Deref for ResumeToken {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for ResumeToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for ResumeToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Type alias for Run IDs to improve code clarity
///
/// While this is just a Uuid, using RunId makes the intent clearer
/// and makes it easier to change the implementation later if needed.
pub type RunId = Uuid;

// ============================================================================
// Workflow Models
// ============================================================================

/// A complete workflow definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    /// Unique workflow identifier (REQUIRED)
    pub name: FlowName,

    /// Human-readable description (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Semantic version (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Trigger type (REQUIRED)
    pub on: Trigger,

    /// Cron expression (REQUIRED if on contains schedule.cron trigger)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cron: Option<String>,

    /// Workflow-level variables (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vars: Option<HashMap<String, serde_json::Value>>,

    /// Array of execution steps (REQUIRED)
    pub steps: Vec<Step>,

    /// Error handling steps (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catch: Option<Vec<Step>>,
}

impl Flow {
    /// Create a minimal flow for testing with a valid name
    #[cfg(test)]
    pub fn test(name: &str) -> Self {
        Self {
            name: FlowName::new(name).expect("Invalid test flow name"),
            description: None,
            version: None,
            on: Trigger::Single("cli.manual".to_string()),
            cron: None,
            vars: None,
            steps: Vec::new(),
            catch: None,
        }
    }
}

// Allow Default for struct update syntax in tests, but with validation
#[allow(clippy::expect_used)] // Default uses hardcoded valid flow name
impl Default for Flow {
    fn default() -> Self {
        Self {
            name: FlowName::new("default_flow".to_string())
                .expect("hardcoded default_flow is valid"),
            description: None,
            version: None,
            on: Trigger::Single("cli.manual".to_string()),
            cron: None,
            vars: None,
            steps: Vec::new(),
            catch: None,
        }
    }
}

/// Trigger type for workflow execution
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Trigger {
    /// Single trigger type as string
    Single(String),
    /// Multiple trigger types as array of strings
    Multiple(Vec<String>),
    /// Mixed array with strings and objects (e.g., ["schedule.cron", {webhook: {...}}])
    Complex(Vec<serde_json::Value>),
    /// Single object or catch-all (e.g., {webhook: {topic: "..."}})
    Raw(serde_json::Value),
}

impl Trigger {
    /// Check if this trigger includes a specific type
    pub fn includes(&self, trigger_type: &str) -> bool {
        match self {
            Trigger::Single(t) => t == trigger_type,
            Trigger::Multiple(triggers) => triggers.iter().any(|t| t == trigger_type),
            Trigger::Complex(values) => values.iter().any(|v| Self::value_matches(v, trigger_type)),
            Trigger::Raw(value) => {
                if let Some(arr) = value.as_array() {
                    arr.iter().any(|v| Self::value_matches(v, trigger_type))
                } else {
                    Self::value_matches(value, trigger_type)
                }
            }
        }
    }

    /// Check if a JSON value matches a trigger type
    ///
    /// Only checks plain strings - used for validating cron triggers in mixed arrays.
    /// Webhook topics use extract_topic_from_trigger_value() for database indexing.
    fn value_matches(value: &serde_json::Value, trigger_type: &str) -> bool {
        value.as_str().is_some_and(|s| s == trigger_type)
    }
}

/// A single workflow step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    /// Unique step identifier (REQUIRED)
    pub id: StepId,

    /// Tool to execute
    #[serde(skip_serializing_if = "Option::is_none", rename = "use")]
    pub use_: Option<String>,

    /// Tool input parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub with: Option<HashMap<String, serde_json::Value>>,

    /// Step dependencies
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depends_on: Option<Vec<String>>,

    /// Run nested steps in parallel
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallel: Option<bool>,

    /// Conditional execution
    #[serde(skip_serializing_if = "Option::is_none", rename = "if")]
    pub if_: Option<String>,

    /// Loop over array
    #[serde(skip_serializing_if = "Option::is_none")]
    pub foreach: Option<String>,

    /// Loop variable name
    #[serde(skip_serializing_if = "Option::is_none", rename = "as")]
    pub as_: Option<String>,

    /// Steps to execute in loop
    #[serde(skip_serializing_if = "Option::is_none", rename = "do")]
    pub do_: Option<Vec<Step>>,

    /// Steps for parallel block
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steps: Option<Vec<Step>>,

    /// Retry configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry: Option<RetrySpec>,

    /// Event wait configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub await_event: Option<AwaitEventSpec>,

    /// Time delay configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait: Option<WaitSpec>,
}

impl Step {
    /// Create a minimal step for testing with a valid id
    #[cfg(test)]
    pub fn test(id: &str) -> Self {
        Self {
            id: StepId::new(id).expect("Invalid test step ID"),
            use_: None,
            with: None,
            depends_on: None,
            parallel: None,
            if_: None,
            foreach: None,
            as_: None,
            do_: None,
            steps: None,
            retry: None,
            await_event: None,
            wait: None,
        }
    }
}

// Allow Default for struct update syntax in tests, but with validation
#[allow(clippy::expect_used)] // Default uses hardcoded valid step ID
impl Default for Step {
    fn default() -> Self {
        Self {
            id: StepId::new("default_step_id".to_string())
                .expect("hardcoded default_step_id is valid"),
            use_: None,
            with: None,
            depends_on: None,
            parallel: None,
            if_: None,
            foreach: None,
            as_: None,
            do_: None,
            steps: None,
            retry: None,
            await_event: None,
            wait: None,
        }
    }
}

/// Retry configuration for a step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrySpec {
    /// Total attempts (including first)
    pub attempts: u32,

    /// Delay between attempts in seconds
    pub delay_sec: u64,
}

/// Event wait configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwaitEventSpec {
    /// Event source
    pub source: String,

    /// Match criteria
    #[serde(rename = "match")]
    pub match_: HashMap<String, serde_json::Value>,

    /// Timeout duration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
}

/// Time delay configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaitSpec {
    /// Wait seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seconds: Option<u64>,

    /// Wait until timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
}

/// MCP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerConfig {
    /// Command to execute
    pub command: String,

    /// Command arguments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,

    /// Environment variables
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<HashMap<String, String>>,

    /// Server port
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    /// Transport protocol
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,

    /// Server endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

/// A workflow run instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    /// Unique run identifier
    pub id: RunId,

    /// Flow name
    pub flow_name: FlowName,

    /// Event data that triggered this run
    pub event: HashMap<String, serde_json::Value>,

    /// Flow variables
    pub vars: HashMap<String, serde_json::Value>,

    /// Current run status
    pub status: RunStatus,

    /// Start timestamp
    pub started_at: DateTime<Utc>,

    /// End timestamp (if completed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<DateTime<Utc>>,

    /// Step execution records
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steps: Option<Vec<StepRun>>,

    /// Organization ID (organization context) - REQUIRED for multi-tenant isolation
    pub organization_id: String,

    /// User who triggered this run - REQUIRED for audit trail and per-user OAuth
    pub triggered_by_user_id: String,
}

/// Run execution status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunStatus {
    /// Run is pending execution
    Pending,

    /// Run is currently executing
    Running,

    /// Run completed successfully
    Succeeded,

    /// Run failed with error
    Failed,

    /// Run is waiting for external event
    Waiting,

    /// Run was skipped (duplicate)
    Skipped,
}

/// A single step execution record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepRun {
    /// Unique step run identifier
    pub id: RunId,

    /// Parent run identifier
    pub run_id: RunId,

    /// Organization identifier for multi-tenant isolation
    ///
    /// Denormalized from the parent run for efficient org-scoped queries
    /// without requiring a JOIN. This is critical for security - queries
    /// should always filter by organization_id.
    pub organization_id: String,

    /// Step name/ID
    pub step_name: StepId,

    /// Step execution status
    pub status: StepStatus,

    /// Start timestamp
    pub started_at: DateTime<Utc>,

    /// End timestamp (if completed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<DateTime<Utc>>,

    /// Error message (if failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Step outputs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outputs: Option<HashMap<String, serde_json::Value>>,
}

/// Step execution status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StepStatus {
    /// Step is pending execution
    Pending,

    /// Step is currently executing
    Running,

    /// Step completed successfully
    Succeeded,

    /// Step failed with error
    Failed,

    /// Step is waiting for external event
    Waiting,

    /// Step was skipped (conditional)
    Skipped,
}

/// OAuth credential for managing OAuth2.0 credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCredential {
    /// Unique identifier
    pub id: String,

    /// Provider name (e.g., "google", "github")
    pub provider: String,

    /// Integration name (e.g., "sheets_default")
    pub integration: String,

    /// Access token (encrypted at storage layer)
    pub access_token: String,

    /// Refresh token (optional)
    pub refresh_token: Option<String>,

    /// Token expiration time (optional)
    pub expires_at: Option<DateTime<Utc>>,

    /// OAuth scope
    pub scope: Option<String>,

    /// Creation time
    pub created_at: DateTime<Utc>,

    /// Last update time
    pub updated_at: DateTime<Utc>,

    /// User ID (owner of this credential)
    pub user_id: String,

    /// Organization ID (organization context)
    pub organization_id: String,
}

// Validation macros for required fields
macro_rules! require_field {
    ($field:expr, $name:literal) => {
        if $field.is_empty() {
            return Err(concat!($name, " is required"));
        }
    };
}

macro_rules! require_field_err {
    ($field:expr, $name:literal) => {
        if $field.is_empty() {
            return Err(crate::BeemFlowError::validation(concat!(
                $name,
                " is required"
            )));
        }
    };
}

impl OAuthCredential {
    /// Validate the OAuth credential
    pub fn validate(&self) -> Result<(), &'static str> {
        require_field!(self.provider, "provider");
        require_field!(self.integration, "integration");
        require_field!(self.access_token, "access_token");
        Ok(())
    }

    /// Check if the credential is expired
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .is_some_and(|expires_at| Utc::now() >= expires_at)
    }

    /// Get unique key for the credential
    #[must_use]
    pub fn unique_key(&self) -> String {
        format!("{}:{}", self.provider, self.integration)
    }
}

/// OAuth provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProvider {
    /// Unique identifier
    pub id: String,

    /// Provider name
    pub name: String,

    /// OAuth client ID
    pub client_id: String,

    /// OAuth client secret (encrypted at storage layer)
    pub client_secret: String,

    /// Authorization URL
    pub auth_url: String,

    /// Token URL
    pub token_url: String,

    /// Supported scopes
    pub scopes: Option<Vec<String>>,

    /// OAuth authorization parameters
    /// Additional query parameters to append to the authorization URL
    /// Example: {"prompt": "select_account", "access_type": "offline"}
    pub auth_params: Option<HashMap<String, String>>,

    /// Creation time
    pub created_at: DateTime<Utc>,

    /// Last update time
    pub updated_at: DateTime<Utc>,
}

impl OAuthProvider {
    /// Validate the OAuth provider configuration
    pub fn validate(&self) -> crate::Result<()> {
        require_field_err!(self.client_id, "client_id");
        require_field_err!(self.client_secret, "client_secret");
        require_field_err!(self.auth_url, "auth_url");
        require_field_err!(self.token_url, "token_url");
        Ok(())
    }
}

/// Registered OAuth client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    /// Unique identifier
    pub id: String,

    /// Client secret (encrypted at storage layer)
    pub secret: String,

    /// Client name
    pub name: String,

    /// Allowed redirect URIs
    pub redirect_uris: Vec<String>,

    /// Supported grant types
    pub grant_types: Vec<String>,

    /// Supported response types
    pub response_types: Vec<String>,

    /// OAuth scope
    pub scope: String,

    /// Client URI (homepage)
    pub client_uri: Option<String>,

    /// Logo URI
    pub logo_uri: Option<String>,

    /// Creation time
    pub created_at: DateTime<Utc>,

    /// Last update time
    pub updated_at: DateTime<Utc>,
}

/// OAuth token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthToken {
    /// Unique identifier
    pub id: String,

    /// Client ID
    pub client_id: String,

    /// User ID
    pub user_id: String,

    /// Redirect URI used
    pub redirect_uri: String,

    /// OAuth scope
    pub scope: String,

    /// Authorization code
    pub code: Option<String>,

    /// Code creation time
    pub code_create_at: Option<DateTime<Utc>>,

    /// Code expiration duration
    pub code_expires_in: Option<std::time::Duration>,

    /// PKCE code challenge (for OAuth 2.1 PKCE)
    pub code_challenge: Option<String>,

    /// PKCE code challenge method (S256)
    pub code_challenge_method: Option<String>,

    /// Access token
    pub access: Option<String>,

    /// Access token creation time
    pub access_create_at: Option<DateTime<Utc>>,

    /// Access token expiration duration
    pub access_expires_in: Option<std::time::Duration>,

    /// Refresh token
    pub refresh: Option<String>,

    /// Refresh token creation time
    pub refresh_create_at: Option<DateTime<Utc>>,

    /// Refresh token expiration duration
    pub refresh_expires_in: Option<std::time::Duration>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Model Tests
    // ========================================================================

    #[test]
    fn test_flow_deserialization() {
        let yaml = r#"
name: hello
description: Hello world flow
on: cli.manual
steps:
  - id: greet
    use: core.echo
    with:
      text: "Hello, world!"
"#;

        let flow: Flow = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(flow.name.as_str(), "hello");
        assert_eq!(flow.steps.len(), 1);
        assert_eq!(flow.steps[0].id.as_str(), "greet");
    }

    #[test]
    fn test_trigger_includes() {
        let single = Trigger::Single("cli.manual".to_string());
        assert!(single.includes("cli.manual"));
        assert!(!single.includes("http.request"));

        let multiple =
            Trigger::Multiple(vec!["cli.manual".to_string(), "schedule.cron".to_string()]);
        assert!(multiple.includes("cli.manual"));
        assert!(multiple.includes("schedule.cron"));
        assert!(!multiple.includes("http.request"));
    }

    #[test]
    fn test_oauth_credential_expired() {
        let mut cred = OAuthCredential {
            id: "test".to_string(),
            provider: "google".to_string(),
            integration: "sheets".to_string(),
            access_token: "token".to_string(),
            refresh_token: None,
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
            scope: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            user_id: "test_user".to_string(),
            organization_id: "test_org".to_string(),
        };

        assert!(cred.is_expired());

        cred.expires_at = Some(Utc::now() + chrono::Duration::hours(1));
        assert!(!cred.is_expired());
    }

    // ========================================================================
    // Domain Type Tests (formerly domain_test.rs)
    // ========================================================================

    #[test]
    fn test_flow_name_valid() {
        assert!(FlowName::new("my_flow").is_ok());
        assert!(FlowName::new("my-flow").is_ok());
        assert!(FlowName::new("my_flow_123").is_ok());
        assert!(FlowName::new("MyFlow").is_ok());
        assert!(FlowName::new("flow.name").is_ok());
    }

    #[test]
    fn test_flow_name_invalid() {
        assert!(FlowName::new("").is_err());
        assert!(FlowName::new("   ").is_err());
        assert!(FlowName::new("my flow").is_err()); // spaces not allowed
        assert!(FlowName::new("my/flow").is_err()); // slashes not allowed
    }

    #[test]
    fn test_step_id_valid() {
        assert!(StepId::new("step1").is_ok());
        assert!(StepId::new("my_step").is_ok());
        assert!(StepId::new("my-step").is_ok());
        assert!(StepId::new("step_123").is_ok());
    }

    #[test]
    fn test_step_id_invalid() {
        assert!(StepId::new("").is_err());
        assert!(StepId::new("   ").is_err());
        assert!(StepId::new("my step").is_err()); // spaces not allowed
        assert!(StepId::new("step.name").is_err()); // dots not allowed in step IDs
    }

    #[test]
    fn test_resume_token_generate() {
        let token1 = ResumeToken::generate();
        let token2 = ResumeToken::generate();
        assert_ne!(token1, token2); // Should be unique
    }

    #[test]
    fn test_resume_token_from_uuid() {
        let uuid = Uuid::new_v4();
        let token = ResumeToken::new(uuid.to_string());
        assert!(token.is_ok());
    }

    #[test]
    fn test_resume_token_invalid() {
        assert!(ResumeToken::new("not-a-uuid").is_err());
        assert!(ResumeToken::new("").is_err());
    }

    #[test]
    fn test_deref() {
        let flow = FlowName::new("test_flow").unwrap();
        assert_eq!(flow.len(), 9); // Deref to str

        let step = StepId::new("step1").unwrap();
        assert_eq!(step.as_str(), "step1");
    }

    #[test]
    fn test_display() {
        let flow = FlowName::new("test_flow").unwrap();
        assert_eq!(format!("{}", flow), "test_flow");

        let step = StepId::new("step1").unwrap();
        assert_eq!(format!("{}", step), "step1");
    }

    #[test]
    fn test_serialization() {
        let flow = FlowName::new("test_flow").unwrap();
        let json = serde_json::to_string(&flow).unwrap();
        assert_eq!(json, "\"test_flow\"");

        let deserialized: FlowName = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, flow);
    }
}
