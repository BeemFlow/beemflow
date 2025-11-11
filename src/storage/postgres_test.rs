// Note: These tests require a running PostgreSQL instance
// Use `docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=test postgres:15` for testing

use super::*;
use crate::storage::{PostgresStorage, Run, RunStatus};
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

#[tokio::test]
#[ignore] // Requires PostgreSQL to be running
async fn test_save_and_get_run() {
    let storage = PostgresStorage::new("postgres://postgres:test@localhost/postgres")
        .await
        .unwrap();

    let run = Run {
        id: Uuid::new_v4(),
        flow_name: "test".to_string().into(),
        event: HashMap::new(),
        vars: HashMap::new(),
        status: RunStatus::Running,
        started_at: Utc::now(),
        ended_at: None,
        steps: None,
        tenant_id: "test_tenant".to_string(),
        triggered_by_user_id: "test_user".to_string(),
    };

    storage.save_run(&run).await.unwrap();
    let retrieved = storage.get_run(run.id, "test_tenant").await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().flow_name.as_str(), "test");
}
