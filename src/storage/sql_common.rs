//! Common SQL storage implementation for SQLite and PostgreSQL
//!
//! This module provides shared helpers and parsing logic for both SQL backends,
//! eliminating ~1360 lines of duplication.

use crate::model::*;
use std::collections::HashMap;

// ============================================================================
// Flow Topic Extraction (used during deployment)
// ============================================================================

/// Extract webhook topics from flow YAML content for indexing
///
/// Parses the flow's `on` trigger field and returns all topic strings.
/// This is called during deployment to populate the flow_triggers table,
/// enabling O(log N) webhook routing by topic.
///
/// # Performance
/// This is a cold path operation (deployment only). YAML parsing here is acceptable.
///
/// # Returns
/// - Vector of topic strings if flow has `on:` field
/// - Empty vector if no triggers or parse error
pub fn extract_topics_from_flow_yaml(content: &str) -> Vec<String> {
    let flow = match crate::dsl::parse_string(content, None) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let trigger = flow.on;

    match trigger {
        Trigger::Single(topic) => vec![topic],
        Trigger::Multiple(topics) => topics,
        Trigger::Complex(values) => values
            .iter()
            .filter_map(|v| {
                v.as_str().map(String::from).or_else(|| {
                    v.as_object()
                        .and_then(|obj| obj.get("event"))
                        .and_then(|e| e.as_str())
                        .map(String::from)
                })
            })
            .collect(),
        Trigger::Raw(value) => {
            if let Some(arr) = value.as_array() {
                arr.iter()
                    .filter_map(|v| {
                        v.as_str().map(String::from).or_else(|| {
                            v.as_object()
                                .and_then(|obj| obj.get("event"))
                                .and_then(|e| e.as_str())
                                .map(String::from)
                        })
                    })
                    .collect()
            } else {
                value
                    .as_str()
                    .map(|s| vec![s.to_string()])
                    .unwrap_or_default()
            }
        }
    }
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
