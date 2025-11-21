//! Secrets management module
//!
//! This module provides a unified interface for accessing secrets and environment variables
//! through the `SecretsProvider` trait. All environment variable access in BeemFlow goes
//! through this module - there should be NO direct `std::env::var()` calls elsewhere.
//!
//! # Architecture
//!
//! - **EnvSecretsProvider** (default): Reads from environment variables and .env files
//! - **AwsSecretsProvider** (future): Reads from AWS Secrets Manager
//! - **VaultSecretsProvider** (future): Reads from HashiCorp Vault
//!
//! # Design Principles
//!
//! 1. **Single Source of Truth**: All secret access goes through SecretsProvider
//! 2. **Pluggable Backends**: Swap providers without changing code
//! 3. **Future-Proof**: Async trait design supports cloud providers
//! 4. **No Magic**: Simple 1:1 mapping for environment variables

mod env;

pub use env::EnvSecretsProvider;

use crate::Result;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;

/// Provides access to secrets and environment variables
///
/// This is the ONLY way to access environment variables in BeemFlow.
/// All direct std::env::var() calls should be removed and replaced with this trait.
///
/// ## Design Decision: Async Trait
///
/// This trait uses `async fn` even though `EnvSecretsProvider` doesn't need async.
/// This is a deliberate design choice:
///
/// - **Forward Compatible**: AWS Secrets Manager and Vault WILL require async (network I/O)
/// - **No Breaking Changes**: Starting with async prevents breaking changes when adding cloud providers
/// - **Idiomatic Rust**: Async trait is the standard pattern for pluggable I/O backends
/// - **Negligible Overhead**: EnvSecretsProvider wraps sync calls in async (trivial cost)
///
/// This follows the principle: "Design for known future requirements."
#[async_trait::async_trait]
pub trait SecretsProvider: Send + Sync {
    /// Get a single secret value by key
    ///
    /// Returns None if the secret doesn't exist.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use beemflow::secrets::{SecretsProvider, EnvSecretsProvider};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let provider = EnvSecretsProvider::new();
    /// let api_key = provider.get_secret("OPENAI_API_KEY").await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn get_secret(&self, key: &str) -> Result<Option<String>>;

    /// Get a secret value with a default fallback
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use beemflow::secrets::{SecretsProvider, EnvSecretsProvider};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let provider = EnvSecretsProvider::new();
    /// let port = provider.get_secret_or("PORT", "8080").await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn get_secret_or(&self, key: &str, default: &str) -> Result<String> {
        Ok(self
            .get_secret(key)
            .await?
            .unwrap_or_else(|| default.to_string()))
    }

    /// Check if a secret exists
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use beemflow::secrets::{SecretsProvider, EnvSecretsProvider};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let provider = EnvSecretsProvider::new();
    /// if provider.has_secret("DEBUG").await {
    ///     println!("Debug mode enabled");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    async fn has_secret(&self, key: &str) -> bool {
        self.get_secret(key).await.ok().flatten().is_some()
    }

    /// Get all secrets as a HashMap (for template context)
    ///
    /// For EnvSecretsProvider, this returns ALL environment variables.
    /// Future providers (AWS, Vault) may apply filtering based on configuration.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use beemflow::secrets::{SecretsProvider, EnvSecretsProvider};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let provider = EnvSecretsProvider::new();
    /// let all_secrets = provider.get_all_secrets().await?;
    /// println!("Available secrets: {}", all_secrets.len());
    /// # Ok(())
    /// # }
    /// ```
    async fn get_all_secrets(&self) -> Result<HashMap<String, String>>;
}

/// Expand $env:VAR patterns in a string using the secrets provider
///
/// This is the ONLY function that should expand environment variable patterns.
/// It replaces all 4 duplicate expand_env_value() implementations that were
/// scattered across the codebase.
///
/// ## Pattern Syntax
///
/// - `$env:VARNAME` - Expands to the value of the secret named VARNAME
/// - Variable names must start with a letter or underscore
/// - Variable names can contain letters, numbers, and underscores
///
/// ## Behavior
///
/// - If the secret exists, it's replaced with the secret value
/// - If the secret doesn't exist, the pattern is left unchanged
/// - Multiple patterns in the same string are all expanded
///
/// # Examples
///
/// ```no_run
/// # use beemflow::secrets::{expand_value, EnvSecretsProvider, SecretsProvider};
/// # use std::sync::Arc;
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let provider: Arc<dyn SecretsProvider> = Arc::new(EnvSecretsProvider::new());
///
/// // Simple expansion
/// let result = expand_value("$env:GITHUB_TOKEN", &provider).await?;
///
/// // Bearer token pattern
/// let auth = expand_value("Bearer $env:OPENAI_API_KEY", &provider).await?;
///
/// // Multiple variables
/// let config = expand_value("host=$env:DB_HOST port=$env:DB_PORT", &provider).await?;
///
/// // Missing variable (unchanged)
/// let unchanged = expand_value("$env:MISSING_VAR", &provider).await?;
/// # Ok(())
/// # }
/// ```
pub async fn expand_value(value: &str, provider: &Arc<dyn SecretsProvider>) -> Result<String> {
    // Pattern matches $env:VARNAME format where VARNAME starts with letter/underscore
    // followed by alphanumeric/underscore characters
    static ENV_VAR_PATTERN: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\$env:([A-Za-z_][A-Za-z0-9_]*)").expect("Invalid environment variable regex")
    });

    // If no patterns found, return original string (fast path)
    if !value.contains("$env:") {
        return Ok(value.to_string());
    }

    // Collect all variable names to look up
    let var_names: Vec<&str> = ENV_VAR_PATTERN
        .captures_iter(value)
        .filter_map(|caps| caps.get(1).map(|m| m.as_str()))
        .collect();

    // Fetch all secrets (future optimization: parallel fetching for cloud providers)
    let mut secret_values = HashMap::new();
    for var_name in var_names {
        if let Some(secret_value) = provider.get_secret(var_name).await? {
            secret_values.insert(var_name.to_string(), secret_value);
        }
    }

    // Replace all patterns with their values using manual string building
    // We can't use replace_all with a closure that borrows from the outer scope
    // because of lifetime constraints, so we build the result string manually
    let mut result = String::new();
    let mut last_match = 0;

    for cap in ENV_VAR_PATTERN.captures_iter(value) {
        let Some(full_match) = cap.get(0) else {
            continue; // Should never happen, but be defensive
        };
        let Some(var_name) = cap.get(1).map(|m| m.as_str()) else {
            continue; // Should never happen, but be defensive
        };

        // Append the part before this match
        result.push_str(&value[last_match..full_match.start()]);

        // Append the replacement (secret value or original pattern)
        if let Some(secret_value) = secret_values.get(var_name) {
            result.push_str(secret_value);
        } else {
            result.push_str(full_match.as_str());
        }

        last_match = full_match.end();
    }

    // Append any remaining part after the last match
    result.push_str(&value[last_match..]);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_expand_value_simple() {
        unsafe {
            std::env::set_var("TEST_VAR", "test_value");
        }

        let provider: Arc<dyn SecretsProvider> = Arc::new(EnvSecretsProvider::new());
        let result = expand_value("$env:TEST_VAR", &provider).await.unwrap();

        assert_eq!(result, "test_value");

        unsafe {
            std::env::remove_var("TEST_VAR");
        }
    }

    #[tokio::test]
    async fn test_expand_value_bearer_token() {
        unsafe {
            std::env::set_var("API_KEY", "secret123");
        }

        let provider: Arc<dyn SecretsProvider> = Arc::new(EnvSecretsProvider::new());
        let result = expand_value("Bearer $env:API_KEY", &provider)
            .await
            .unwrap();

        assert_eq!(result, "Bearer secret123");

        unsafe {
            std::env::remove_var("API_KEY");
        }
    }

    #[tokio::test]
    async fn test_expand_value_multiple() {
        unsafe {
            std::env::set_var("VAR1", "value1");
            std::env::set_var("VAR2", "value2");
        }

        let provider: Arc<dyn SecretsProvider> = Arc::new(EnvSecretsProvider::new());
        let result = expand_value("$env:VAR1 and $env:VAR2", &provider)
            .await
            .unwrap();

        assert_eq!(result, "value1 and value2");

        unsafe {
            std::env::remove_var("VAR1");
            std::env::remove_var("VAR2");
        }
    }

    #[tokio::test]
    async fn test_expand_value_missing() {
        let provider: Arc<dyn SecretsProvider> = Arc::new(EnvSecretsProvider::new());
        let result = expand_value("$env:MISSING_VAR", &provider).await.unwrap();

        // Missing variables are left unchanged
        assert_eq!(result, "$env:MISSING_VAR");
    }

    #[tokio::test]
    async fn test_expand_value_no_pattern() {
        let provider: Arc<dyn SecretsProvider> = Arc::new(EnvSecretsProvider::new());
        let result = expand_value("literal value", &provider).await.unwrap();

        assert_eq!(result, "literal value");
    }

    #[tokio::test]
    async fn test_secrets_provider_trait() {
        unsafe {
            std::env::set_var("TEST_SECRET", "secret_value");
        }

        let provider = EnvSecretsProvider::new();

        // Test get_secret
        let secret = provider.get_secret("TEST_SECRET").await.unwrap();
        assert_eq!(secret, Some("secret_value".to_string()));

        // Test get_secret_or
        let with_default = provider.get_secret_or("MISSING", "default").await.unwrap();
        assert_eq!(with_default, "default");

        // Test has_secret
        assert!(provider.has_secret("TEST_SECRET").await);
        assert!(!provider.has_secret("MISSING").await);

        // Test get_all_secrets
        let all = provider.get_all_secrets().await.unwrap();
        assert!(all.contains_key("TEST_SECRET"));

        unsafe {
            std::env::remove_var("TEST_SECRET");
        }
    }
}
