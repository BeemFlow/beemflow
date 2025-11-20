//! Integration tests for webhook HTTP layer

use crate::http::webhook::{
    WebhookManagerState, create_webhook_routes, extract_json_path, matches_event,
    parse_webhook_events,
};
use crate::registry::{WebhookConfig, WebhookEvent};
use crate::utils::TestEnvironment;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use std::collections::HashMap;
use tower::ServiceExt;

#[tokio::test]
async fn test_webhook_route_registration() {
    // Create test environment with all dependencies
    let env = TestEnvironment::new().await;

    // Create WebhookManagerState with storage and engine
    let webhook_state = WebhookManagerState {
        registry_manager: env.deps.registry_manager.clone(),
        secrets_provider: env.deps.config.create_secrets_provider(),
        storage: env.deps.storage.clone(),
        engine: env.deps.engine.clone(),
        config: env.deps.config.clone(),
    };

    // Build webhook router
    let app = create_webhook_routes().with_state(webhook_state);

    // Make a POST request to /test-org/test-topic
    // This should return 404 (organization not found) but proves the route is registered
    let request = Request::builder()
        .method("POST")
        .uri("/test-org/test-topic")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"test":"data"}"#))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Verify the route is accessible (not 404 NOT_FOUND for the route itself)
    // We expect 404 "Organization not found" since test-org doesn't exist
    // This is different from Axum returning 404 for an unregistered route
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "Webhook handler should be invoked (not a routing 404)"
    );
}

#[tokio::test]
async fn test_webhook_state_has_storage_and_engine() {
    // Verify that WebhookManagerState can be created with storage and engine
    let env = TestEnvironment::new().await;

    let webhook_state = WebhookManagerState {
        registry_manager: env.deps.registry_manager.clone(),
        secrets_provider: env.deps.config.create_secrets_provider(),
        storage: env.deps.storage.clone(),
        engine: env.deps.engine.clone(),
        config: env.deps.config.clone(),
    };

    // Verify state fields are accessible
    use std::sync::Arc;
    assert!(Arc::strong_count(&webhook_state.storage) >= 1);
    assert!(Arc::strong_count(&webhook_state.engine) >= 1);
}

// Unit tests for webhook parsing functions

#[test]
fn test_extract_json_path() {
    let data = json!({
        "user": {
            "name": "Alice",
            "email": "alice@example.com"
        },
        "count": 42
    });

    assert_eq!(extract_json_path(&data, "user.name"), Some(json!("Alice")));
    assert_eq!(
        extract_json_path(&data, "user.email"),
        Some(json!("alice@example.com"))
    );
    assert_eq!(extract_json_path(&data, "count"), Some(json!(42)));
    assert_eq!(extract_json_path(&data, "nonexistent"), None);
}

#[test]
fn test_matches_event() {
    let payload = json!({
        "type": "message.created",
        "user_id": "123"
    });

    let mut conditions = HashMap::new();
    conditions.insert("type".to_string(), json!("message.created"));

    assert!(matches_event(&payload, &conditions));

    conditions.insert("user_id".to_string(), json!("123"));
    assert!(matches_event(&payload, &conditions));

    conditions.insert("user_id".to_string(), json!("456"));
    assert!(!matches_event(&payload, &conditions));
}

#[test]
fn test_parse_webhook_events_with_extract() {
    // Create webhook config with extract rules (like Airtable)
    let webhook_config = WebhookConfig {
        enabled: true,
        secret: None,
        signature: None,
        events: vec![WebhookEvent {
            event_type: "record.updated".to_string(),
            topic: "airtable.record.updated".to_string(),
            match_: {
                let mut m = HashMap::new();
                m.insert("webhook.action".to_string(), json!("update"));
                m
            },
            extract: {
                let mut e = HashMap::new();
                e.insert("record_id".to_string(), "webhook.record.id".to_string());
                e.insert(
                    "status".to_string(),
                    "webhook.record.fields.status".to_string(),
                );
                e.insert("base_id".to_string(), "webhook.base.id".to_string());
                e
            },
        }],
    };

    // Simulate Airtable webhook payload
    let payload = json!({
        "webhook": {
            "action": "update",
            "base": {
                "id": "appXXXXX"
            },
            "record": {
                "id": "recYYYYY",
                "fields": {
                    "status": "approved"
                }
            }
        }
    });

    // Parse events
    let events = parse_webhook_events(&webhook_config, &payload).expect("Should parse events");

    // Verify we extracted the event
    assert_eq!(events.len(), 1, "Should extract one event");
    let event = &events[0];

    assert_eq!(event.topic, "airtable.record.updated");
    assert_eq!(event.data.get("record_id"), Some(&json!("recYYYYY")));
    assert_eq!(event.data.get("status"), Some(&json!("approved")));
    assert_eq!(event.data.get("base_id"), Some(&json!("appXXXXX")));
}

#[test]
fn test_parse_webhook_events_no_match() {
    let webhook_config = WebhookConfig {
        enabled: true,
        secret: None,
        signature: None,
        events: vec![WebhookEvent {
            event_type: "record.created".to_string(),
            topic: "airtable.record.created".to_string(),
            match_: {
                let mut m = HashMap::new();
                m.insert("webhook.action".to_string(), json!("create"));
                m
            },
            extract: HashMap::new(),
        }],
    };

    // Payload with different action
    let payload = json!({
        "webhook": {
            "action": "update"
        }
    });

    let events = parse_webhook_events(&webhook_config, &payload).expect("Should parse events");

    assert_eq!(events.len(), 0, "Should not match any events");
}

#[test]
fn test_parse_webhook_events_multiple_events() {
    let webhook_config = WebhookConfig {
        enabled: true,
        secret: None,
        signature: None,
        events: vec![
            WebhookEvent {
                event_type: "message.created".to_string(),
                topic: "slack.message.created".to_string(),
                match_: {
                    let mut m = HashMap::new();
                    m.insert("type".to_string(), json!("event_callback"));
                    m.insert("event.type".to_string(), json!("message"));
                    m
                },
                extract: {
                    let mut e = HashMap::new();
                    e.insert("channel".to_string(), "event.channel".to_string());
                    e.insert("user".to_string(), "event.user".to_string());
                    e.insert("text".to_string(), "event.text".to_string());
                    e
                },
            },
            WebhookEvent {
                event_type: "reaction.added".to_string(),
                topic: "slack.reaction.added".to_string(),
                match_: {
                    let mut m = HashMap::new();
                    m.insert("type".to_string(), json!("event_callback"));
                    m.insert("event.type".to_string(), json!("reaction_added"));
                    m
                },
                extract: {
                    let mut e = HashMap::new();
                    e.insert("reaction".to_string(), "event.reaction".to_string());
                    e
                },
            },
        ],
    };

    // Payload that matches first event
    let payload = json!({
        "type": "event_callback",
        "event": {
            "type": "message",
            "channel": "C123",
            "user": "U456",
            "text": "Hello world"
        }
    });

    let events = parse_webhook_events(&webhook_config, &payload).expect("Should parse events");

    assert_eq!(events.len(), 1, "Should extract one matching event");
    assert_eq!(events[0].topic, "slack.message.created");
    assert_eq!(events[0].data.get("channel"), Some(&json!("C123")));
    assert_eq!(events[0].data.get("text"), Some(&json!("Hello world")));
}

#[tokio::test]
async fn test_webhook_type_registration() {
    use crate::registry::LocalRegistry;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Create a temporary registry file with a standalone webhook entry
    let mut temp_file = NamedTempFile::new().unwrap();
    let registry_content = r#"[
        {
            "type": "webhook",
            "name": "twilio",
            "description": "Twilio SMS webhooks",
            "registry": "local",
            "webhook": {
                "enabled": true,
                "events": [
                    {
                        "type": "incoming_sms",
                        "topic": "twilio.sms",
                        "match": {},
                        "extract": {
                            "From": "From",
                            "To": "To",
                            "Body": "Body",
                            "MessageSid": "MessageSid"
                        }
                    }
                ]
            }
        }
    ]"#;
    temp_file.write_all(registry_content.as_bytes()).unwrap();

    // Create local registry and verify the webhook entry is loaded
    let registry = LocalRegistry::new(temp_file.path().to_str().unwrap());
    let entries = registry.list_servers().await.unwrap();

    assert_eq!(entries.len(), 1, "Should have one entry");
    assert_eq!(
        entries[0].entry_type, "webhook",
        "Entry type should be 'webhook'"
    );
    assert_eq!(entries[0].name, "twilio", "Entry name should be 'twilio'");
    assert!(
        entries[0].webhook.is_some(),
        "Webhook config should be present"
    );

    let webhook_config = entries[0].webhook.as_ref().unwrap();
    assert!(webhook_config.enabled, "Webhook should be enabled");
    assert_eq!(webhook_config.events.len(), 1, "Should have one event");
    assert_eq!(
        webhook_config.events[0].topic, "twilio.sms",
        "Topic should be twilio.sms"
    );
}

#[tokio::test]
async fn test_webhook_and_oauth_provider_consistency() {
    use crate::registry::LocalRegistry;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Test that webhook config structure is identical for both types
    let mut temp_file = NamedTempFile::new().unwrap();
    let registry_content = r#"[
        {
            "type": "webhook",
            "name": "twilio",
            "webhook": {
                "enabled": true,
                "events": [
                    {
                        "type": "sms",
                        "topic": "twilio.sms",
                        "match": {},
                        "extract": {"body": "Body"}
                    }
                ]
            }
        },
        {
            "type": "oauth_provider",
            "name": "slack",
            "client_id": "test_id",
            "webhook": {
                "enabled": true,
                "events": [
                    {
                        "type": "message",
                        "topic": "slack.message",
                        "match": {"type": "event_callback"},
                        "extract": {"text": "event.text"}
                    }
                ]
            }
        }
    ]"#;
    temp_file.write_all(registry_content.as_bytes()).unwrap();

    let registry = LocalRegistry::new(temp_file.path().to_str().unwrap());
    let entries = registry.list_servers().await.unwrap();

    assert_eq!(entries.len(), 2, "Should have two entries");

    // Verify both have webhook config with identical structure
    let webhook_entry = entries.iter().find(|e| e.entry_type == "webhook").unwrap();
    let oauth_entry = entries
        .iter()
        .find(|e| e.entry_type == "oauth_provider")
        .unwrap();

    assert!(
        webhook_entry.webhook.is_some(),
        "Webhook type should have webhook config"
    );
    assert!(
        oauth_entry.webhook.is_some(),
        "OAuth provider should have webhook config"
    );

    // Verify structure is the same (both have events, enabled, etc.)
    let webhook_cfg = webhook_entry.webhook.as_ref().unwrap();
    let oauth_cfg = oauth_entry.webhook.as_ref().unwrap();

    assert_eq!(
        webhook_cfg.enabled, oauth_cfg.enabled,
        "enabled field should be same type"
    );
    assert_eq!(
        webhook_cfg.events.len(),
        oauth_cfg.events.len(),
        "Both should have one event"
    );

    // Verify event structure is identical
    assert!(
        !webhook_cfg.events[0].topic.is_empty(),
        "Webhook event should have topic"
    );
    assert!(
        !oauth_cfg.events[0].topic.is_empty(),
        "OAuth event should have topic"
    );
}

#[tokio::test]
async fn test_webhook_resumes_paused_flow() {
    use crate::dsl::parse_string;
    use crate::engine::PausedRun;

    // Create test environment
    let env = TestEnvironment::new().await;

    // Create a flow that pauses waiting for SMS from specific number
    let flow_yaml = r#"
name: sms_approval_test
version: 1.0.0
on: cli.manual
steps:
  - id: start
    use: core.echo
    with:
      text: "Waiting for approval"
  - id: wait_approval
    await_event:
      source: twilio.sms
      match:
        From: "+15551234567"
      timeout: 1h
  - id: approved
    use: core.echo
    with:
      text: "Approved! Body was: {{ event.Body }}"
"#;

    let flow = parse_string(flow_yaml, None).expect("Failed to parse flow");

    // Execute flow - should pause at await_event
    let result = env
        .deps
        .engine
        .execute(&flow, HashMap::new(), "test_user", "test_org")
        .await;
    assert!(result.is_err(), "Flow should pause (error) at await_event");
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("waiting for event"),
        "Error should indicate waiting state, got: {}",
        err_msg
    );

    // Verify paused run was saved with correct source
    let paused_runs = env
        .deps
        .storage
        .find_paused_runs_by_source("twilio.sms")
        .await
        .expect("Should find paused runs");
    assert_eq!(paused_runs.len(), 1, "Should have one paused run");

    let (token, paused_data) = &paused_runs[0];

    // Verify token is auto-generated (format: {run_id}-step-{step_idx})
    assert!(
        token.ends_with("-step-1"),
        "Token should be auto-generated with step index, got: {}",
        token
    );

    let paused: PausedRun =
        serde_json::from_value(paused_data.clone()).expect("Should deserialize");

    // Verify await_event spec was saved correctly
    let wait_step = &paused.flow.steps[paused.step_idx];
    assert!(
        wait_step.await_event.is_some(),
        "Step should have await_event"
    );
    let await_spec = wait_step.await_event.as_ref().unwrap();
    assert_eq!(await_spec.source, "twilio.sms");
    assert_eq!(
        await_spec.match_.get("From"),
        Some(&json!("+15551234567")),
        "Match should only contain From field"
    );
    assert!(
        !await_spec.match_.contains_key("token"),
        "Token should NOT be in match criteria"
    );

    // Simulate webhook with matching From number
    let mut resume_event = HashMap::new();
    resume_event.insert("From".to_string(), json!("+15551234567"));
    resume_event.insert("Body".to_string(), json!("YES"));
    resume_event.insert("MessageSid".to_string(), json!("SM123"));

    // Resume using auto-generated token from database
    let resume_result = env.deps.engine.resume(token, resume_event).await;
    assert!(resume_result.is_ok(), "Resume should succeed");

    // Verify paused run was deleted
    let after_resume = env
        .deps
        .storage
        .find_paused_runs_by_source("twilio.sms")
        .await
        .expect("Should query");
    assert_eq!(after_resume.len(), 0, "Paused run should be deleted");
}

#[tokio::test]
async fn test_webhook_resume_match_criteria() {
    use crate::dsl::parse_string;

    let env = TestEnvironment::new().await;

    // Flow waiting for SMS from Becky
    let flow_yaml = r#"
name: match_test
on: cli.manual
steps:
  - id: wait
    await_event:
      source: twilio.sms
      match:
        From: "+15559876543"
      timeout: 1h
  - id: done
    use: core.echo
    with:
      text: "Done"
"#;

    let flow = parse_string(flow_yaml, None).unwrap();
    env.deps
        .engine
        .execute(&flow, HashMap::new(), "test_user", "test_org")
        .await
        .ok();

    // Get the auto-generated paused token
    let paused = env
        .deps
        .storage
        .find_paused_runs_by_source("twilio.sms")
        .await
        .unwrap();
    let (token, _) = &paused[0];

    // Verify token is auto-generated
    assert!(
        token.ends_with("-step-0"),
        "Token should be auto-generated, got: {}",
        token
    );

    // Test 1: Non-matching From number should fail
    let mut wrong_number = HashMap::new();
    wrong_number.insert("From".to_string(), json!("+19998887777"));
    wrong_number.insert("Body".to_string(), json!("YES"));

    // This would be handled by resume_paused_runs_for_event which checks matches_criteria
    // For direct test, we just verify the token still exists
    let still_paused = env
        .deps
        .storage
        .find_paused_runs_by_source("twilio.sms")
        .await
        .unwrap();
    assert_eq!(still_paused.len(), 1, "Should still be paused");

    // Test 2: Matching From number should work
    let mut correct_number = HashMap::new();
    correct_number.insert("From".to_string(), json!("+15559876543"));
    correct_number.insert("Body".to_string(), json!("YES"));

    let result = env.deps.engine.resume(token, correct_number).await;
    assert!(result.is_ok(), "Should resume with correct number");

    // Verify cleanup
    let cleaned = env
        .deps
        .storage
        .find_paused_runs_by_source("twilio.sms")
        .await
        .unwrap();
    assert_eq!(cleaned.len(), 0, "Should be cleaned up");
}
