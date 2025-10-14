
use super::*;
use crate::registry::RegistryManager;
use crate::storage::{MemoryStorage, OAuthStorage};

fn create_test_credential() -> OAuthCredential {
    OAuthCredential {
        id: "test-cred".to_string(),
        provider: "google".to_string(),
        integration: "sheets".to_string(),
        access_token: "test-token".to_string(),
        refresh_token: Some("test-refresh".to_string()),
        expires_at: Some(Utc::now() + Duration::hours(1)),
        scope: Some("https://www.googleapis.com/auth/spreadsheets".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[tokio::test]
async fn test_get_token_no_credential() {
    let storage = Arc::new(MemoryStorage::new());
    let registry_manager = Arc::new(RegistryManager::standard(None));
    let client = OAuthClientManager::new(
        storage,
        registry_manager,
        "http://localhost:3000/callback".to_string(),
    )
    .expect("Failed to create OAuth client manager");

    let result = client.get_token("google", "sheets").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_get_token_valid() {
    let storage = Arc::new(MemoryStorage::new());
    let registry_manager = Arc::new(RegistryManager::standard(None));
    let cred = create_test_credential();

    storage.save_oauth_credential(&cred).await.unwrap();

    let client = OAuthClientManager::new(
        storage,
        registry_manager,
        "http://localhost:3000/callback".to_string(),
    )
    .expect("Failed to create OAuth client manager");
    let token = client.get_token("google", "sheets").await.unwrap();

    assert_eq!(token, "test-token");
}

#[tokio::test]
async fn test_needs_refresh_not_expired() {
    let cred = create_test_credential();
    assert!(!OAuthClientManager::needs_refresh(&cred));
}

#[tokio::test]
async fn test_needs_refresh_expired() {
    let mut cred = create_test_credential();
    cred.expires_at = Some(Utc::now() - Duration::hours(1));

    assert!(OAuthClientManager::needs_refresh(&cred));
}

#[tokio::test]
async fn test_needs_refresh_no_expiry() {
    let mut cred = create_test_credential();
    cred.expires_at = None;

    assert!(!OAuthClientManager::needs_refresh(&cred));
}
