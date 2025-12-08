//! Common SQL storage implementation for SQLite and PostgreSQL
//!
//! This module provides shared helpers and parsing logic for both SQL backends,
//! eliminating ~1360 lines of duplication.

use crate::model::*;
use std::collections::HashMap;

// ============================================================================
// Flow Topic Extraction (used during deployment)
// ============================================================================

/// Extract topic from any trigger value (string or webhook object)
///
/// Handles both:
/// - Plain strings: "schedule.cron", "cli.manual"
/// - Webhook objects: {webhook: {topic: "twilio.sms"}} → "twilio.sms"
///
/// This allows flows to have multiple triggers of different types.
#[inline]
fn extract_topic_from_trigger_value(value: &serde_json::Value) -> Option<String> {
    // Plain string (cron, cli, etc.)
    if let Some(s) = value.as_str() {
        return Some(s.to_string());
    }

    // Webhook object: {webhook: {topic: "..."}}
    value
        .as_object()?
        .get("webhook")?
        .as_object()?
        .get("topic")?
        .as_str()
        .map(String::from)
}

/// Extract webhook topics from flow YAML content for indexing
///
/// This function powers topic-based routing by extracting topics during deployment.
/// Topics are stored in the flow_triggers table for O(log N) webhook routing.
///
/// # Topic-Based Routing (Uses this function)
/// - **Webhooks**: `on: {webhook: {topic: "twilio.sms"}}` → indexed for routing
/// - **Cron**: `on: {schedule: {cron: "..."}}` → extracted as "schedule.cron" topic
///
/// # Direct Execution (Does NOT use topics)
/// - **CLI/HTTP API**: Flows executed by name - `on:` field is documentation only
/// - Flows with `on: cli.manual` or `on: manual` are never looked up by topic
///
/// # Performance
/// Cold path operation (deployment only). YAML parsing acceptable.
///
/// # Returns
/// - Vector of topic strings if flow has indexed triggers
/// - Empty vector otherwise
pub fn extract_topics_from_flow_yaml(content: &str) -> Vec<String> {
    let flow = match crate::dsl::parse_string(content, None) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let topics = match flow.on {
        // Single trigger: "schedule.cron", "cli.manual", etc.
        Trigger::Single(topic) => vec![topic],

        // Multiple plain strings: ["schedule.cron", "cli.manual"]
        Trigger::Multiple(topics) => topics,

        // Mixed triggers: ["schedule.cron", {webhook: {topic: "twilio.sms"}}]
        Trigger::Complex(values) => values
            .iter()
            .filter_map(extract_topic_from_trigger_value)
            .collect(),

        // Single object: {webhook: {topic: "twilio.sms"}}
        Trigger::Raw(value) => extract_topic_from_trigger_value(&value)
            .map(|t| vec![t])
            .unwrap_or_default(),
    };

    tracing::debug!("Extracted topics from flow: {:?}", topics);
    topics
}

// ============================================================================
// Status Conversions (used by both backends)
// ============================================================================

#[inline]
pub fn parse_run_status(s: &str) -> RunStatus {
    match s {
        "PENDING" => RunStatus::Pending,
        "RUNNING" => RunStatus::Running,
        "SUCCEEDED" => RunStatus::Succeeded,
        "FAILED" => RunStatus::Failed,
        "WAITING" => RunStatus::Waiting,
        "SKIPPED" => RunStatus::Skipped,
        _ => RunStatus::Failed,
    }
}

#[inline]
pub fn run_status_to_str(status: RunStatus) -> &'static str {
    match status {
        RunStatus::Pending => "PENDING",
        RunStatus::Running => "RUNNING",
        RunStatus::Succeeded => "SUCCEEDED",
        RunStatus::Failed => "FAILED",
        RunStatus::Waiting => "WAITING",
        RunStatus::Skipped => "SKIPPED",
    }
}

#[inline]
pub fn parse_step_status(s: &str) -> StepStatus {
    match s {
        "PENDING" => StepStatus::Pending,
        "RUNNING" => StepStatus::Running,
        "SUCCEEDED" => StepStatus::Succeeded,
        "FAILED" => StepStatus::Failed,
        "SKIPPED" => StepStatus::Skipped,
        "WAITING" => StepStatus::Waiting,
        _ => StepStatus::Failed,
    }
}

#[inline]
pub fn step_status_to_str(status: StepStatus) -> &'static str {
    match status {
        StepStatus::Pending => "PENDING",
        StepStatus::Running => "RUNNING",
        StepStatus::Succeeded => "SUCCEEDED",
        StepStatus::Failed => "FAILED",
        StepStatus::Skipped => "SKIPPED",
        StepStatus::Waiting => "WAITING",
    }
}

// ============================================================================
// SQLite-specific Helpers
// ============================================================================
// Note: Trivial wrappers removed - use serde_json::from_str, .timestamp_millis(),
// and DateTime::from_timestamp_millis directly (all timestamps stored as milliseconds)

// ============================================================================
// PostgreSQL-specific Helpers
// ============================================================================

/// Parse HashMap from Postgres JSONB
#[inline]
pub fn parse_hashmap_from_jsonb(val: serde_json::Value) -> HashMap<String, serde_json::Value> {
    val.as_object()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

// ============================================================================
// OAuth Credential Parsing (shared logic, backend-specific timestamp handling)
// ============================================================================

use chrono::{DateTime, Utc};
use sqlx::Row;

/// Parse OAuthCredential from SQLite row
///
/// SQLite stores timestamps as i64 milliseconds, requires conversion.
/// Tokens are decrypted after extraction.
pub fn parse_oauth_credential_sqlite(
    row: &sqlx::sqlite::SqliteRow,
) -> crate::Result<OAuthCredential> {
    // Decrypt tokens after retrieval
    let encrypted_access: String = row.try_get("access_token")?;
    let encrypted_refresh: Option<String> = row.try_get("refresh_token")?;

    let (access_token, refresh_token) = crate::auth::TokenEncryption::decrypt_credential_tokens(
        encrypted_access,
        encrypted_refresh,
    )?;

    // SQLite stores timestamps as i64 milliseconds
    let created_at_unix: i64 = row.try_get("created_at")?;
    let updated_at_unix: i64 = row.try_get("updated_at")?;
    let expires_at_unix: Option<i64> = row.try_get("expires_at")?;

    Ok(OAuthCredential {
        id: row.try_get("id")?,
        provider: row.try_get("provider")?,
        integration: row.try_get("integration")?,
        access_token,
        refresh_token,
        expires_at: expires_at_unix.and_then(DateTime::from_timestamp_millis),
        scope: row.try_get("scope")?,
        created_at: DateTime::from_timestamp_millis(created_at_unix).unwrap_or_else(Utc::now),
        updated_at: DateTime::from_timestamp_millis(updated_at_unix).unwrap_or_else(Utc::now),
        user_id: row.try_get("user_id")?,
        organization_id: row.try_get("organization_id")?,
    })
}

/// Parse OAuthCredential from PostgreSQL row
///
/// PostgreSQL stores timestamps as DateTime<Utc> directly.
/// Tokens are decrypted after extraction.
pub fn parse_oauth_credential_postgres(
    row: &sqlx::postgres::PgRow,
) -> crate::Result<OAuthCredential> {
    // Decrypt tokens after retrieval
    let encrypted_access: String = row.try_get("access_token")?;
    let encrypted_refresh: Option<String> = row.try_get("refresh_token")?;

    let (access_token, refresh_token) = crate::auth::TokenEncryption::decrypt_credential_tokens(
        encrypted_access,
        encrypted_refresh,
    )?;

    Ok(OAuthCredential {
        id: row.try_get("id")?,
        provider: row.try_get("provider")?,
        integration: row.try_get("integration")?,
        access_token,
        refresh_token,
        expires_at: row.try_get("expires_at")?,
        scope: row.try_get("scope")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        user_id: row.try_get("user_id")?,
        organization_id: row.try_get("organization_id")?,
    })
}

// ============================================================================
// User Parsing (shared logic, backend-specific timestamp/boolean handling)
// ============================================================================

use crate::auth::User;

/// Parse User from SQLite row
///
/// SQLite stores:
/// - timestamps as i64 milliseconds
/// - booleans as i32 (0/1)
pub fn parse_user_sqlite(row: &sqlx::sqlite::SqliteRow) -> crate::Result<User> {
    Ok(User {
        id: row.try_get("id")?,
        email: row.try_get("email")?,
        name: row.try_get("name")?,
        password_hash: row.try_get("password_hash")?,
        email_verified: row.try_get::<i32, _>("email_verified")? != 0,
        avatar_url: row.try_get("avatar_url")?,
        mfa_enabled: row.try_get::<i32, _>("mfa_enabled")? != 0,
        mfa_secret: row.try_get("mfa_secret")?,
        created_at: DateTime::from_timestamp_millis(row.try_get("created_at")?)
            .unwrap_or_else(Utc::now),
        updated_at: DateTime::from_timestamp_millis(row.try_get("updated_at")?)
            .unwrap_or_else(Utc::now),
        last_login_at: row
            .try_get::<Option<i64>, _>("last_login_at")?
            .and_then(DateTime::from_timestamp_millis),
        disabled: row.try_get::<i32, _>("disabled")? != 0,
        disabled_reason: row.try_get("disabled_reason")?,
        disabled_at: row
            .try_get::<Option<i64>, _>("disabled_at")?
            .and_then(DateTime::from_timestamp_millis),
    })
}

/// Parse User from PostgreSQL row
///
/// PostgreSQL schema uses BIGINT for timestamps (milliseconds) and BOOLEAN for booleans.
/// (Schema is consistent with SQLite for timestamp storage)
pub fn parse_user_postgres(row: &sqlx::postgres::PgRow) -> crate::Result<User> {
    Ok(User {
        id: row.try_get("id")?,
        email: row.try_get("email")?,
        name: row.try_get("name")?,
        password_hash: row.try_get("password_hash")?,
        email_verified: row.try_get("email_verified")?,
        avatar_url: row.try_get("avatar_url")?,
        mfa_enabled: row.try_get("mfa_enabled")?,
        mfa_secret: row.try_get("mfa_secret")?,
        created_at: DateTime::from_timestamp_millis(row.try_get("created_at")?)
            .unwrap_or_else(Utc::now),
        updated_at: DateTime::from_timestamp_millis(row.try_get("updated_at")?)
            .unwrap_or_else(Utc::now),
        last_login_at: row
            .try_get::<Option<i64>, _>("last_login_at")?
            .and_then(DateTime::from_timestamp_millis),
        disabled: row.try_get("disabled")?,
        disabled_reason: row.try_get("disabled_reason")?,
        disabled_at: row
            .try_get::<Option<i64>, _>("disabled_at")?
            .and_then(DateTime::from_timestamp_millis),
    })
}
