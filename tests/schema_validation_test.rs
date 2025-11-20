//! Schema validation tests
//!
//! These tests explicitly validate schema features that were added/fixed.
//! They will FAIL with the old schema and PASS with the new schema.
//!
//! This provides proof that our schema changes are actually working.
//!
//! **Critical:** These tests use raw SQL to bypass Rust type safety and
//! directly test database constraints, triggers, and data types.

use chrono::Utc;
use sqlx::Row;

/// Test that CHECK constraints reject invalid status values
///
/// OLD SCHEMA: No CHECK constraint (would accept any value)
/// NEW SCHEMA: CHECK(status IN ('PENDING', 'RUNNING', 'SUCCEEDED', ...))
#[tokio::test]
async fn test_check_constraint_rejects_invalid_status() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:?mode=rwc")
        .await
        .unwrap();

    // Apply NEW schema
    sqlx::migrate!("./migrations/sqlite")
        .run(&pool)
        .await
        .unwrap();

    // Try to insert run with INVALID status (bypassing Rust enums)
    let result = sqlx::query(
        "INSERT INTO runs (
            id, flow_name, event, vars, status, started_at,
            organization_id, triggered_by_user_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("test_run_123")
    .bind("test_flow")
    .bind("{}")
    .bind("{}")
    .bind("INVALID_STATUS_VALUE") // ← Should be rejected!
    .bind(Utc::now().timestamp_millis())
    .bind("test_org")
    .bind("test_user")
    .bind(Utc::now().timestamp_millis())
    .execute(&pool)
    .await;

    // NEW SCHEMA: Must fail
    assert!(
        result.is_err(),
        "CHECK constraint should reject invalid status value"
    );

    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.to_lowercase().contains("check")
            || error_msg.to_lowercase().contains("constraint"),
        "Error should mention CHECK constraint: {}",
        error_msg
    );

    // Verify VALID status works
    let valid_result = sqlx::query(
        "INSERT INTO runs (
            id, flow_name, event, vars, status, started_at,
            organization_id, triggered_by_user_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("test_run_456")
    .bind("test_flow")
    .bind("{}")
    .bind("{}")
    .bind("SUCCEEDED") // ← Valid status
    .bind(Utc::now().timestamp_millis())
    .bind("test_org")
    .bind("test_user")
    .bind(Utc::now().timestamp_millis())
    .execute(&pool)
    .await;

    assert!(valid_result.is_ok(), "Valid status should be accepted");
}

/// Test that audit logs cannot be deleted
///
/// OLD SCHEMA (SQLite): No trigger (DELETE would succeed)
/// NEW SCHEMA: Trigger prevents DELETE
#[tokio::test]
async fn test_audit_log_delete_prevented_by_trigger() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:?mode=rwc")
        .await
        .unwrap();

    sqlx::migrate!("./migrations/sqlite")
        .run(&pool)
        .await
        .unwrap();

    // Create user and organization first (foreign key requirement)
    sqlx::query(
        "INSERT INTO users (id, email, name, password_hash, created_at, updated_at, disabled)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("test_user")
    .bind("test@example.com")
    .bind("Test")
    .bind("$2b$12$test")
    .bind(Utc::now().timestamp_millis())
    .bind(Utc::now().timestamp_millis())
    .bind(0)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO organizations (
            id, name, slug, created_by_user_id, created_at, updated_at, disabled
        ) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("test_org")
    .bind("Test Organization")
    .bind("test-org")
    .bind("test_user")
    .bind(Utc::now().timestamp_millis())
    .bind(Utc::now().timestamp_millis())
    .bind(0)
    .execute(&pool)
    .await
    .unwrap();

    // Insert audit log
    sqlx::query(
        "INSERT INTO audit_logs (
            id, timestamp, organization_id, action, success, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind("audit_123")
    .bind(Utc::now().timestamp_millis())
    .bind("test_org")
    .bind("test.action")
    .bind(1) // SQLite boolean
    .bind(Utc::now().timestamp_millis())
    .execute(&pool)
    .await
    .unwrap();

    // Try to DELETE (should fail)
    let result = sqlx::query("DELETE FROM audit_logs WHERE id = ?")
        .bind("audit_123")
        .execute(&pool)
        .await;

    // NEW SCHEMA: Must fail
    assert!(
        result.is_err(),
        "Trigger should prevent DELETE on audit_logs"
    );

    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.to_lowercase().contains("immutable")
            || error_msg.to_lowercase().contains("abort"),
        "Error should mention immutability: {}",
        error_msg
    );
}

/// Test that audit logs cannot be updated
///
/// OLD SCHEMA (SQLite): No trigger (UPDATE would succeed)
/// NEW SCHEMA: Trigger prevents UPDATE
#[tokio::test]
async fn test_audit_log_update_prevented_by_trigger() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:?mode=rwc")
        .await
        .unwrap();

    sqlx::migrate!("./migrations/sqlite")
        .run(&pool)
        .await
        .unwrap();

    // Create user and organization first (foreign key requirement)
    sqlx::query(
        "INSERT INTO users (id, email, name, password_hash, created_at, updated_at, disabled)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("test_user")
    .bind("test@example.com")
    .bind("Test")
    .bind("$2b$12$test")
    .bind(Utc::now().timestamp_millis())
    .bind(Utc::now().timestamp_millis())
    .bind(0)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO organizations (
            id, name, slug, created_by_user_id, created_at, updated_at, disabled
        ) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("test_org")
    .bind("Test Organization")
    .bind("test-org")
    .bind("test_user")
    .bind(Utc::now().timestamp_millis())
    .bind(Utc::now().timestamp_millis())
    .bind(0)
    .execute(&pool)
    .await
    .unwrap();

    // Insert audit log
    sqlx::query(
        "INSERT INTO audit_logs (
            id, timestamp, organization_id, action, success, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind("audit_456")
    .bind(Utc::now().timestamp_millis())
    .bind("test_org")
    .bind("test.action")
    .bind(1)
    .bind(Utc::now().timestamp_millis())
    .execute(&pool)
    .await
    .unwrap();

    // Try to UPDATE (should fail)
    let result = sqlx::query("UPDATE audit_logs SET success = 0 WHERE id = ?")
        .bind("audit_456")
        .execute(&pool)
        .await;

    // NEW SCHEMA: Must fail
    assert!(
        result.is_err(),
        "Trigger should prevent UPDATE on audit_logs"
    );

    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.to_lowercase().contains("immutable")
            || error_msg.to_lowercase().contains("abort"),
        "Error should mention immutability: {}",
        error_msg
    );
}

/// Test that timestamps are stored with millisecond precision
///
/// OLD SCHEMA (SQLite): Stored seconds (would lose milliseconds)
/// NEW SCHEMA: Stores milliseconds
#[tokio::test]
async fn test_timestamp_stores_milliseconds_not_seconds() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:?mode=rwc")
        .await
        .unwrap();

    sqlx::migrate!("./migrations/sqlite")
        .run(&pool)
        .await
        .unwrap();

    // Insert timestamp with specific millisecond value
    let timestamp_millis: i64 = 1704672123456; // Has milliseconds: 456

    sqlx::query(
        "INSERT INTO runs (
            id, flow_name, event, vars, status, started_at,
            organization_id, triggered_by_user_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("test_run")
    .bind("test_flow")
    .bind("{}")
    .bind("{}")
    .bind("SUCCEEDED")
    .bind(timestamp_millis)
    .bind("test_org")
    .bind("test_user")
    .bind(Utc::now().timestamp_millis())
    .execute(&pool)
    .await
    .unwrap();

    // Query back the stored value
    let row = sqlx::query("SELECT started_at FROM runs WHERE id = ?")
        .bind("test_run")
        .fetch_one(&pool)
        .await
        .unwrap();

    let stored_value: i64 = row.try_get("started_at").unwrap();

    // NEW SCHEMA: Should preserve exact milliseconds
    assert_eq!(
        stored_value, timestamp_millis,
        "Milliseconds should be preserved exactly"
    );

    // Check that it's in millisecond range (13 digits, not 10)
    assert!(
        stored_value > 1_000_000_000_000,
        "Value should be in milliseconds (>1 trillion), got: {}",
        stored_value
    );

    // OLD SCHEMA: Would store 1704672123 (lost 456 milliseconds)
    // NEW SCHEMA: Stores 1704672123456 (preserves milliseconds)
}

/// Test that millisecond differences are preserved
///
/// This proves we're not rounding to seconds
#[tokio::test]
async fn test_millisecond_precision_preserved_in_differences() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:?mode=rwc")
        .await
        .unwrap();

    sqlx::migrate!("./migrations/sqlite")
        .run(&pool)
        .await
        .unwrap();

    // Create two timestamps with 250ms difference
    let start_millis: i64 = 1704672000000;
    let end_millis: i64 = 1704672000250; // +250 milliseconds

    sqlx::query(
        "INSERT INTO runs (
            id, flow_name, event, vars, status, started_at, ended_at,
            organization_id, triggered_by_user_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("test_run_precision")
    .bind("test_flow")
    .bind("{}")
    .bind("{}")
    .bind("SUCCEEDED")
    .bind(start_millis)
    .bind(end_millis)
    .bind("test_org")
    .bind("test_user")
    .bind(Utc::now().timestamp_millis())
    .execute(&pool)
    .await
    .unwrap();

    // Query back
    let row = sqlx::query("SELECT started_at, ended_at FROM runs WHERE id = ?")
        .bind("test_run_precision")
        .fetch_one(&pool)
        .await
        .unwrap();

    let stored_start: i64 = row.try_get("started_at").unwrap();
    let stored_end: i64 = row.try_get("ended_at").unwrap();

    // Calculate difference
    let diff = stored_end - stored_start;

    // NEW SCHEMA: Should be exactly 250 milliseconds
    assert_eq!(
        diff, 250,
        "Millisecond precision should be preserved, diff should be 250ms, got: {}ms",
        diff
    );

    // OLD SCHEMA (seconds): Both would round to 1704672000, diff = 0
    // NEW SCHEMA (milliseconds): Exact values, diff = 250
}

/// Test that CHECK constraint validates quota > 0
///
/// OLD SCHEMA: No CHECK constraint
/// NEW SCHEMA: CHECK(max_users > 0)
#[tokio::test]
async fn test_check_constraint_validates_positive_quotas() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:?mode=rwc")
        .await
        .unwrap();

    sqlx::migrate!("./migrations/sqlite")
        .run(&pool)
        .await
        .unwrap();

    // Try to insert organization with max_users = 0 (invalid)
    let result = sqlx::query(
        "INSERT INTO organizations (
            id, name, slug, plan, max_users, max_flows, max_runs_per_month,
            created_by_user_id, created_at, updated_at, disabled
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("test_org")
    .bind("Test")
    .bind("test")
    .bind("free")
    .bind(0) // ← Invalid!
    .bind(10)
    .bind(1000)
    .bind("user_123")
    .bind(Utc::now().timestamp_millis())
    .bind(Utc::now().timestamp_millis())
    .bind(0)
    .execute(&pool)
    .await;

    // NEW SCHEMA: Must fail
    assert!(
        result.is_err(),
        "CHECK constraint should reject max_users = 0"
    );

    // Try with negative value
    let result2 = sqlx::query(
        "INSERT INTO organizations (
            id, name, slug, plan, max_users, max_flows, max_runs_per_month,
            created_by_user_id, created_at, updated_at, disabled
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("test_org2")
    .bind("Test")
    .bind("test2")
    .bind("free")
    .bind(-1) // ← Invalid!
    .bind(10)
    .bind(1000)
    .bind("user_123")
    .bind(Utc::now().timestamp_millis())
    .bind(Utc::now().timestamp_millis())
    .bind(0)
    .execute(&pool)
    .await;

    assert!(
        result2.is_err(),
        "CHECK constraint should reject max_users < 0"
    );
}

/// Test that NOT NULL constraints are enforced
///
/// OLD SCHEMA: flow_name was nullable
/// NEW SCHEMA: flow_name is NOT NULL
#[tokio::test]
async fn test_not_null_constraint_on_flow_name() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:?mode=rwc")
        .await
        .unwrap();

    sqlx::migrate!("./migrations/sqlite")
        .run(&pool)
        .await
        .unwrap();

    // Try to insert run with NULL flow_name
    let result = sqlx::query(
        "INSERT INTO runs (
            id, flow_name, event, vars, status, started_at,
            organization_id, triggered_by_user_id, created_at
        ) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?)", // ← NULL flow_name
    )
    .bind("test_run")
    .bind("{}")
    .bind("{}")
    .bind("PENDING")
    .bind(Utc::now().timestamp_millis())
    .bind("test_org")
    .bind("test_user")
    .bind(Utc::now().timestamp_millis())
    .execute(&pool)
    .await;

    // NEW SCHEMA: Must fail
    assert!(
        result.is_err(),
        "NOT NULL constraint should reject NULL flow_name"
    );

    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.to_lowercase().contains("not null")
            || error_msg.to_lowercase().contains("constraint"),
        "Error should mention NOT NULL: {}",
        error_msg
    );
}

/// Test that waits.wake_at is nullable (optional timeout)
///
/// OLD SCHEMA: Was NOT NULL (our bug!)
/// NEW SCHEMA: Is nullable
#[tokio::test]
async fn test_waits_wake_at_nullable() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:?mode=rwc")
        .await
        .unwrap();

    sqlx::migrate!("./migrations/sqlite")
        .run(&pool)
        .await
        .unwrap();

    // Insert wait with NULL wake_at (indefinite wait)
    let result = sqlx::query(
        "INSERT INTO waits (token, wake_at) VALUES (?, NULL)", // ← NULL should work
    )
    .bind("wait_token_123")
    .execute(&pool)
    .await;

    // NEW SCHEMA: Must succeed
    assert!(
        result.is_ok(),
        "Should allow NULL wake_at for indefinite waits: {:?}",
        result.err()
    );

    // Verify it was actually stored as NULL
    let row = sqlx::query("SELECT wake_at FROM waits WHERE token = ?")
        .bind("wait_token_123")
        .fetch_one(&pool)
        .await
        .unwrap();

    let wake_at: Option<i64> = row.try_get("wake_at").unwrap();
    assert!(wake_at.is_none(), "wake_at should be NULL");
}

/// Test that oauth_providers.name column exists
///
/// OLD SCHEMA: No name column
/// NEW SCHEMA: Has name column
#[tokio::test]
async fn test_oauth_providers_has_name_column() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:?mode=rwc")
        .await
        .unwrap();

    sqlx::migrate!("./migrations/sqlite")
        .run(&pool)
        .await
        .unwrap();

    // Insert with name != id
    let result = sqlx::query(
        "INSERT INTO oauth_providers (
            id, name, client_id, client_secret, auth_url, token_url,
            scopes, auth_params, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("github")
    .bind("GitHub") // ← Different from id!
    .bind("client_123")
    .bind("secret_456")
    .bind("https://github.com/login/oauth/authorize")
    .bind("https://github.com/login/oauth/access_token")
    .bind("[]")
    .bind("{}")
    .bind(Utc::now().timestamp_millis())
    .bind(Utc::now().timestamp_millis())
    .execute(&pool)
    .await;

    // NEW SCHEMA: Must succeed
    assert!(
        result.is_ok(),
        "Should accept name column: {:?}",
        result.err()
    );

    // Query back and verify name != id
    let row = sqlx::query("SELECT id, name FROM oauth_providers WHERE id = ?")
        .bind("github")
        .fetch_one(&pool)
        .await
        .unwrap();

    let id: String = row.try_get("id").unwrap();
    let name: String = row.try_get("name").unwrap();

    assert_eq!(id, "github");
    assert_eq!(name, "GitHub");
    assert_ne!(id, name, "Name should differ from ID");

    // OLD SCHEMA: Would fail (no name column)
}

/// Test that UNIQUE constraint includes organization_id
///
/// This allows same user to connect same provider in different organizations
#[tokio::test]
async fn test_oauth_credentials_unique_includes_organization_id() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:?mode=rwc")
        .await
        .unwrap();

    sqlx::migrate!("./migrations/sqlite")
        .run(&pool)
        .await
        .unwrap();

    // Insert credential for user in organization A
    sqlx::query(
        "INSERT INTO oauth_credentials (
            id, provider, integration, access_token, user_id, organization_id,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("cred_1")
    .bind("google")
    .bind("default")
    .bind("token_A")
    .bind("user_123")
    .bind("org_A")
    .bind(Utc::now().timestamp_millis())
    .bind(Utc::now().timestamp_millis())
    .execute(&pool)
    .await
    .unwrap();

    // Insert same user/provider/integration in organization B (should succeed)
    let result = sqlx::query(
        "INSERT INTO oauth_credentials (
            id, provider, integration, access_token, user_id, organization_id,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("cred_2")
    .bind("google")
    .bind("default")
    .bind("token_B")
    .bind("user_123") // Same user
    .bind("org_B") // Different organization
    .bind(Utc::now().timestamp_millis())
    .bind(Utc::now().timestamp_millis())
    .execute(&pool)
    .await;

    // NEW SCHEMA: Must succeed (organization_id in UNIQUE constraint)
    assert!(
        result.is_ok(),
        "Should allow same user/provider in different organizations: {:?}",
        result.err()
    );

    // OLD SCHEMA: Would fail (UNIQUE didn't include organization_id)

    // Verify we have 2 credentials
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_credentials")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(count, 2, "Should have 2 credentials (different organizations)");
}

/// Test that critical indexes exist (performance)
///
/// This doesn't test performance, but verifies indexes are actually created
#[tokio::test]
async fn test_critical_indexes_exist() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:?mode=rwc")
        .await
        .unwrap();

    sqlx::migrate!("./migrations/sqlite")
        .run(&pool)
        .await
        .unwrap();

    // Query SQLite's index catalog
    let indexes: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    // Critical indexes that MUST exist
    let required_indexes = vec![
        "idx_flow_triggers_organization_topic", // Webhook routing (hot path)
        "idx_runs_organization_flow_status_time", // Run pagination
        "idx_steps_run_id",                      // Step lookup
        "idx_users_email_active",                // User login
        "idx_refresh_tokens_hash_active",        // Token validation
    ];

    for required in required_indexes {
        assert!(
            indexes.contains(&required.to_string()),
            "Critical index missing: {}",
            required
        );
    }

    println!("Total indexes created: {}", indexes.len());
    assert!(
        indexes.len() >= 25,
        "Should have at least 25 indexes, got: {}",
        indexes.len()
    );
}

/// Test DEFAULT values for timestamps work
///
/// NEW SCHEMA: Has DEFAULT expressions
#[tokio::test]
async fn test_default_timestamp_values() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:?mode=rwc")
        .await
        .unwrap();

    sqlx::migrate!("./migrations/sqlite")
        .run(&pool)
        .await
        .unwrap();

    // Insert run WITHOUT specifying created_at (should use DEFAULT)
    sqlx::query(
        "INSERT INTO runs (
            id, flow_name, event, vars, status, started_at,
            organization_id, triggered_by_user_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", // ← No created_at!
    )
    .bind("test_run")
    .bind("test_flow")
    .bind("{}")
    .bind("{}")
    .bind("PENDING")
    .bind(Utc::now().timestamp_millis())
    .bind("test_org")
    .bind("test_user")
    .execute(&pool)
    .await
    .unwrap();

    // Query created_at
    let row = sqlx::query("SELECT created_at FROM runs WHERE id = ?")
        .bind("test_run")
        .fetch_one(&pool)
        .await
        .unwrap();

    let created_at: i64 = row.try_get("created_at").unwrap();

    // Should have a valid timestamp from DEFAULT
    assert!(
        created_at > 1_000_000_000_000,
        "DEFAULT should provide current timestamp in milliseconds"
    );

    // Verify it's recent (within last minute)
    let now = Utc::now().timestamp_millis();
    let age = now - created_at;
    assert!(
        age < 60_000,
        "DEFAULT timestamp should be current (age: {}ms)",
        age
    );
}
