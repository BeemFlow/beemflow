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
// Note: Trivial wrappers removed - use serde_json::from_str, .timestamp(),
// and DateTime::from_timestamp directly

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
