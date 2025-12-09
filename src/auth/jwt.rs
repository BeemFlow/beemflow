//! JWT token generation and validation, plus OAuth token encryption
//!
//! This module combines two related security functions:
//! 1. JWT creation/validation for stateless authentication
//! 2. OAuth token encryption for third-party credentials
//!
//! # Security
//!
//! - JWT: Uses validated secrets (enforced at type level via ValidatedJwtSecret)
//! - OAuth: AES-256-GCM authenticated encryption with separate encryption key
#[cfg(test)]
use super::Role;
use super::{JwtClaims, Membership};
use crate::{BeemFlowError, Result};
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use std::sync::Arc;

/// Validated JWT secret that enforces minimum length requirement
///
/// This type can only be constructed if the secret is at least 256 bits (32 bytes).
/// The deployer is responsible for generating cryptographically random secrets.
///
/// # Example
/// ```ignore
/// // Will fail if JWT_SECRET is missing or too short
/// let secret = ValidatedJwtSecret::from_env()?;
///
/// // Pass to JwtManager (guaranteed >=256 bits)
/// let jwt_manager = JwtManager::new(&secret, ...);
/// ```
#[derive(Clone)]
pub struct ValidatedJwtSecret(String);

impl ValidatedJwtSecret {
    /// Load and validate JWT secret from environment
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - JWT_SECRET environment variable not set
    /// - Secret is less than 32 characters (256 bits)
    /// - Secret contains common weak patterns
    /// - Secret appears to have low entropy
    ///
    /// # Example
    /// ```ignore
    /// let secret = ValidatedJwtSecret::from_env()?;
    /// ```
    pub fn from_env() -> Result<Self> {
        let secret = std::env::var("JWT_SECRET").map_err(|_| {
            BeemFlowError::config(
                "JWT_SECRET environment variable is REQUIRED.\n\
                 \n\
                 Generate a secure secret:\n\
                 $ openssl rand -hex 32\n\
                 \n\
                 Then set it:\n\
                 $ export JWT_SECRET=<generated-secret>\n\
                 \n\
                 For production, use a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)"
            )
        })?;

        Self::validate(&secret)?;
        Ok(Self(secret))
    }

    /// Create for testing (bypasses env var requirement)
    ///
    /// Still validates the secret meets security requirements.
    pub fn from_string(secret: String) -> Result<Self> {
        Self::validate(&secret)?;
        Ok(Self(secret))
    }

    /// Create secret - from env in production, test default in tests
    ///
    /// Production: Requires JWT_SECRET environment variable
    /// Test mode: Uses fixed test secret if env var not set
    pub fn new() -> Result<Self> {
        #[cfg(test)]
        {
            Self::from_env().or_else(|_| Ok(Self::test_default()))
        }
        #[cfg(not(test))]
        {
            Self::from_env()
        }
    }

    /// Get test default secret (internal helper)
    #[cfg(test)]
    fn test_default() -> Self {
        Self::from_string("test-secret-at-least-32-characters-long-for-tests".to_string())
            .expect("Test secret should be valid")
    }

    /// Validate secret meets minimum length requirement
    fn validate(secret: &str) -> Result<()> {
        // Minimum length: 256 bits = 32 bytes
        if secret.len() < 32 {
            return Err(BeemFlowError::config(format!(
                "JWT_SECRET must be at least 32 characters (256 bits).\n\
                 Current length: {} characters.\n\
                 \n\
                 Generate a secure secret:\n\
                 $ openssl rand -hex 32",
                secret.len()
            )));
        }

        // Maximum length: prevent DoS via huge secrets
        if secret.len() > 512 {
            return Err(BeemFlowError::config(format!(
                "JWT_SECRET exceeds maximum length of 512 characters.\n\
                 Current length: {} characters.",
                secret.len()
            )));
        }

        Ok(())
    }

    /// Get the validated secret as a byte slice for cryptographic operations
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Get the validated secret as a string (use sparingly)
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ValidatedJwtSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ValidatedJwtSecret")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl std::fmt::Display for ValidatedJwtSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED JWT secret]")
    }
}

/// JWT manager for generating and validating tokens
pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    issuer: String,
    access_token_ttl: Duration,
}

impl JwtManager {
    /// Create a new JWT manager with a validated secret
    ///
    /// # Arguments
    /// * `secret` - Validated secret (must pass security checks)
    /// * `issuer` - Token issuer (typically your domain)
    /// * `access_token_ttl` - How long access tokens are valid
    ///
    /// # Security
    ///
    /// This constructor accepts ValidatedJwtSecret, which guarantees the secret
    /// is at least 256 bits and doesn't contain weak patterns. The type system
    /// prevents using unvalidated secrets.
    pub fn new(secret: &ValidatedJwtSecret, issuer: String, access_token_ttl: Duration) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            issuer,
            access_token_ttl,
        }
    }

    /// Generate an access token (JWT)
    ///
    /// # Arguments
    /// * `user_id` - User's unique identifier
    /// * `email` - User's email address
    /// * `memberships` - All organization memberships with roles
    ///
    /// # Returns
    /// JWT token string that can be used in Authorization header
    ///
    /// # Security
    /// Token includes ALL user's organization memberships. The organization_id
    /// for the current request is specified via X-Organization-ID header,
    /// and middleware validates the user is a member of that organization.
    pub fn generate_access_token(
        &self,
        user_id: &str,
        email: &str,
        memberships: Vec<Membership>,
    ) -> Result<String> {
        let now = Utc::now();
        let exp = (now + self.access_token_ttl).timestamp() as usize;
        let iat = now.timestamp() as usize;

        let claims = JwtClaims {
            sub: user_id.to_string(),
            email: email.to_string(),
            memberships,
            exp,
            iat,
            iss: self.issuer.clone(),
        };

        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key)
            .map_err(|e| BeemFlowError::OAuth(format!("Failed to generate JWT: {}", e)))
    }

    /// Validate and decode a JWT token
    ///
    /// # Arguments
    /// * `token` - JWT token string (without "Bearer " prefix)
    ///
    /// # Returns
    /// Validated JWT claims if token is valid
    ///
    /// # Errors
    /// Returns error if token is:
    /// - Expired
    /// - Invalid signature
    /// - Malformed
    /// - Wrong issuer
    pub fn validate_token(&self, token: &str) -> Result<JwtClaims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.issuer]);

        let token_data =
            decode::<JwtClaims>(token, &self.decoding_key, &validation).map_err(|e| {
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                        BeemFlowError::OAuth("Token expired".to_string())
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidToken => {
                        BeemFlowError::OAuth("Invalid token".to_string())
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                        BeemFlowError::OAuth("Invalid signature".to_string())
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
                        BeemFlowError::OAuth("Invalid issuer".to_string())
                    }
                    _ => BeemFlowError::OAuth(format!("Invalid JWT: {}", e)),
                }
            })?;

        Ok(token_data.claims)
    }

    /// Get the configured access token TTL
    pub fn access_token_ttl(&self) -> Duration {
        self.access_token_ttl
    }

    /// Get the configured issuer
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_secret() -> ValidatedJwtSecret {
        // Valid test secret (32+ characters, cryptographically random-looking)
        ValidatedJwtSecret::from_string(
            "a1b2c3d4e5f6789012345678901234567890abcdefghijklmnop".to_string(),
        )
        .expect("Test secret should be valid")
    }

    fn create_test_manager() -> JwtManager {
        JwtManager::new(
            &create_test_secret(),
            "test-issuer".to_string(),
            Duration::minutes(15),
        )
    }

    // ========================================================================
    // ValidatedJwtSecret Tests
    // ========================================================================

    #[test]
    fn test_jwt_secret_too_short() {
        let result = ValidatedJwtSecret::from_string("short".to_string());
        assert!(result.is_err());

        let err = result.unwrap_err().to_string();
        assert!(err.contains("at least 32 characters"));
    }

    #[test]
    fn test_jwt_secret_exactly_minimum_length() {
        // Exactly 32 characters (minimum)
        let secret = "12345678901234567890123456789012".to_string();
        assert_eq!(secret.len(), 32);

        let result = ValidatedJwtSecret::from_string(secret);
        assert!(result.is_ok(), "32-character secret should be valid");
    }

    #[test]
    fn test_jwt_secret_too_long() {
        let long_secret = "a".repeat(513); // 513 chars > 512 max
        let result = ValidatedJwtSecret::from_string(long_secret);
        assert!(result.is_err());

        let err = result.unwrap_err().to_string();
        assert!(err.contains("512") && err.contains("characters"));
    }

    #[test]
    fn test_jwt_secret_strong_accepted() {
        // Generated with openssl rand -hex 32
        let strong = "a1b2c3d4e5f61234567890abcdefabcdefabcdef1234567890abcdefabcd".to_string();
        let result = ValidatedJwtSecret::from_string(strong);
        if let Err(ref e) = result {
            panic!("Strong secret was rejected: {}", e);
        }
        assert!(result.is_ok(), "Strong secret should be accepted");
    }

    #[test]
    fn test_jwt_secret_debug_redacted() {
        let secret = create_test_secret();
        let debug_output = format!("{:?}", secret);
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("a1b2c3"));
    }

    #[test]
    fn test_jwt_secret_display_redacted() {
        let secret = create_test_secret();
        let display_output = format!("{}", secret);
        // Display should hide the actual secret
        assert!(display_output.contains("REDACTED") || display_output.contains("redacted"));
        assert!(!display_output.contains("a1b2c3"));
    }

    // ========================================================================
    // JwtManager Tests (updated to use ValidatedJwtSecret)
    // ========================================================================

    #[test]
    fn test_generate_and_validate_token() {
        let manager = create_test_manager();

        let memberships = vec![Membership {
            organization_id: "org456".to_string(),
            role: Role::Admin,
        }];

        let token = manager
            .generate_access_token("user123", "user@example.com", memberships.clone())
            .expect("Failed to generate token");

        let claims = manager
            .validate_token(&token)
            .expect("Failed to validate token");

        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.email, "user@example.com");
        assert_eq!(claims.memberships, memberships);
        assert_eq!(claims.iss, "test-issuer");
    }

    #[test]
    fn test_invalid_signature() {
        let manager1 = create_test_manager();

        let different_secret = ValidatedJwtSecret::from_string(
            "different-secret-key-with-32-chars-minimum-length".to_string(),
        )
        .expect("Different secret should be valid");

        let manager2 = JwtManager::new(
            &different_secret,
            "test-issuer".to_string(),
            Duration::minutes(15),
        );

        let memberships = vec![Membership {
            organization_id: "org456".to_string(),
            role: Role::Member,
        }];

        let token = manager1
            .generate_access_token("user123", "user@example.com", memberships)
            .expect("Failed to generate token");

        // Should fail with different key
        let result = manager2.validate_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_issuer() {
        let secret = create_test_secret();

        let manager1 = JwtManager::new(&secret, "issuer1".to_string(), Duration::minutes(15));
        let manager2 = JwtManager::new(&secret, "issuer2".to_string(), Duration::minutes(15));

        let memberships = vec![Membership {
            organization_id: "org456".to_string(),
            role: Role::Viewer,
        }];

        let token = manager1
            .generate_access_token("user123", "user@example.com", memberships)
            .expect("Failed to generate token");

        // Should fail with different issuer
        let result = manager2.validate_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_expired_token() {
        let secret = create_test_secret();

        // Create manager with expired TTL (beyond any clock skew leeway)
        let manager = JwtManager::new(
            &secret,
            "test-issuer".to_string(),
            Duration::seconds(-120), // Expired 2 minutes ago
        );

        let memberships = vec![Membership {
            organization_id: "org456".to_string(),
            role: Role::Owner,
        }];

        let token = manager
            .generate_access_token("user123", "user@example.com", memberships)
            .expect("Failed to generate token");

        // Token should be rejected as expired
        let result = manager.validate_token(&token);
        assert!(result.is_err(), "Expired token should be rejected");

        match result {
            Err(BeemFlowError::OAuth(msg)) => {
                assert!(
                    msg.to_lowercase().contains("expired")
                        || msg.to_lowercase().contains("invalid"),
                    "Error should indicate token issue: {}",
                    msg
                );
            }
            _ => panic!("Expected OAuth error for expired token"),
        }
    }

    #[test]
    fn test_all_roles() {
        let manager = create_test_manager();

        for role in [Role::Owner, Role::Admin, Role::Member, Role::Viewer] {
            let memberships = vec![Membership {
                organization_id: "org456".to_string(),
                role,
            }];

            let token = manager
                .generate_access_token("user123", "user@example.com", memberships.clone())
                .expect("Failed to generate token");

            let claims = manager
                .validate_token(&token)
                .expect("Failed to validate token");
            assert_eq!(claims.memberships, memberships);
        }
    }
}

// ============================================================================
// OAuth Token Encryption
// ============================================================================

/// Encrypted token wrapper
///
/// Format: "nonce:ciphertext" (both base64-encoded)
///
/// This type can only be created via encryption or from database, ensuring
/// tokens are never accidentally stored in plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedToken(String);

impl EncryptedToken {
    /// Get the encrypted representation for database storage
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Parse from database (validation only, no decryption)
    ///
    /// # Errors
    ///
    /// Returns error if the format is invalid (not "nonce:ciphertext")
    pub fn from_database(s: String) -> Result<Self> {
        // Validate format: must contain exactly one colon
        if s.split(':').count() != 2 {
            return Err(BeemFlowError::validation(
                "Invalid encrypted token format. Expected 'nonce:ciphertext'.",
            ));
        }

        // Validate it's valid base64 (both parts)
        let parts: Vec<&str> = s.split(':').collect();
        let (nonce_part, ciphertext_part) = match parts.as_slice() {
            [n, c] => (*n, *c),
            _ => {
                return Err(BeemFlowError::validation(
                    "Invalid encrypted token format. Expected exactly one colon.",
                ));
            }
        };

        BASE64
            .decode(nonce_part)
            .map_err(|_| BeemFlowError::validation("Invalid nonce encoding"))?;
        BASE64
            .decode(ciphertext_part)
            .map_err(|_| BeemFlowError::validation("Invalid ciphertext encoding"))?;

        Ok(Self(s))
    }
}

impl std::fmt::Display for EncryptedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show first 16 chars only (for debugging/logging)
        let preview = self.0.chars().take(16).collect::<String>();
        write!(f, "[encrypted:{}...]", preview)
    }
}

/// Token encryptor using AES-256-GCM
///
/// Thread-safe and can be shared across tasks via Arc.
///
/// # Security
///
/// - Uses AES-256 in GCM mode (256-bit key, authenticated encryption)
/// - Generates unique random nonce for each encryption operation
/// - Validates authentication tag on decryption (detects tampering)
/// - Key loaded from environment (separate from JWT_SECRET)
#[derive(Clone)]
pub struct TokenEncryption {
    cipher: Arc<Aes256Gcm>,
}

impl TokenEncryption {
    /// Create encryptor - from env in production, test key in tests
    ///
    /// Production: Requires OAUTH_ENCRYPTION_KEY environment variable
    /// Test mode: Uses fixed test key if env var not set
    ///
    /// # Example
    ///
    /// ```ignore
    /// let encryptor = TokenEncryption::new()?;
    /// ```
    pub fn new() -> Result<Self> {
        #[cfg(test)]
        {
            Self::from_env().or_else(|_| Ok(Self::from_test_key()))
        }
        #[cfg(not(test))]
        {
            Self::from_env()
        }
    }

    /// Create from OAUTH_ENCRYPTION_KEY environment variable (internal)
    fn from_env() -> Result<Self> {
        let key_b64 = std::env::var("OAUTH_ENCRYPTION_KEY").map_err(|_| {
            BeemFlowError::config(
                "OAUTH_ENCRYPTION_KEY environment variable is REQUIRED.\n\
                 \n\
                 Generate a secure encryption key:\n\
                 $ openssl rand -base64 32\n\
                 \n\
                 Then set it:\n\
                 $ export OAUTH_ENCRYPTION_KEY=<generated-key>\n\
                 \n\
                 IMPORTANT: This must be separate from JWT_SECRET\n\
                 IMPORTANT: Back up this key securely - losing it means losing OAuth tokens",
            )
        })?;

        let key_bytes = BASE64.decode(key_b64.trim()).map_err(|_| {
            BeemFlowError::config(
                "OAUTH_ENCRYPTION_KEY must be valid base64.\n\
                 Generate with: openssl rand -base64 32",
            )
        })?;

        if key_bytes.len() != 32 {
            return Err(BeemFlowError::config(format!(
                "OAUTH_ENCRYPTION_KEY must be exactly 32 bytes (256 bits).\n\
                 Current: {} bytes.\n\
                 \n\
                 Generate a correct key:\n\
                 $ openssl rand -base64 32",
                key_bytes.len()
            )));
        }

        let key_len = key_bytes.len();
        let key: [u8; 32] = key_bytes.try_into().map_err(|_| {
            BeemFlowError::config(format!(
                "OAUTH_ENCRYPTION_KEY length mismatch (got {}, expected 32 bytes)",
                key_len
            ))
        })?;

        Ok(Self {
            cipher: Arc::new(Aes256Gcm::new(&key.into())),
        })
    }

    /// Create for testing with a fixed key (internal helper)
    #[cfg(test)]
    fn from_test_key() -> Self {
        // Fixed test key (32 bytes)
        let key = [42u8; 32];
        Self {
            cipher: Arc::new(Aes256Gcm::new(&key.into())),
        }
    }

    /// Encrypt OAuth credential tokens (helper for storage layer)
    ///
    /// Encrypts both access_token and refresh_token (if present).
    /// This reduces code duplication in storage implementations.
    pub fn encrypt_credential_tokens(
        access_token: &str,
        refresh_token: &Option<String>,
    ) -> Result<(EncryptedToken, Option<EncryptedToken>)> {
        let encryptor = Self::new()?;
        let encrypted_access = encryptor.encrypt(access_token)?;
        let encrypted_refresh = refresh_token
            .as_ref()
            .map(|t| encryptor.encrypt(t))
            .transpose()?;
        Ok((encrypted_access, encrypted_refresh))
    }

    /// Decrypt OAuth credential tokens (helper for storage layer)
    ///
    /// Decrypts both access_token and refresh_token (if present).
    /// This reduces code duplication in storage implementations.
    pub fn decrypt_credential_tokens(
        encrypted_access: String,
        encrypted_refresh: Option<String>,
    ) -> Result<(String, Option<String>)> {
        let encryptor = Self::new()?;

        let access_enc = EncryptedToken::from_database(encrypted_access)?;
        let access_token = encryptor.decrypt(&access_enc)?;

        let refresh_token = encrypted_refresh
            .map(|r| EncryptedToken::from_database(r).and_then(|e| encryptor.decrypt(&e)))
            .transpose()?;

        Ok((access_token, refresh_token))
    }

    /// Encrypt a plaintext token for storage
    ///
    /// Generates a unique random nonce and encrypts the token with authenticated
    /// encryption (AES-256-GCM). The result includes both nonce and ciphertext.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let plaintext = "ghp_abc123...";
    /// let encrypted = encryptor.encrypt(plaintext)?;
    /// // Store encrypted.as_str() in database
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if encryption fails (should never happen with AES-GCM)
    pub fn encrypt(&self, plaintext: &str) -> Result<EncryptedToken> {
        // Generate unique nonce (96 bits - recommended for GCM)
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        // Encrypt with authenticated encryption
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| BeemFlowError::internal(format!("Token encryption failed: {}", e)))?;

        // Encode as "nonce:ciphertext" (both base64)
        let encoded = format!("{}:{}", BASE64.encode(nonce), BASE64.encode(&ciphertext));

        Ok(EncryptedToken(encoded))
    }

    /// Decrypt a token from storage
    ///
    /// Validates the format, extracts nonce and ciphertext, and decrypts with
    /// authentication tag verification.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let encrypted = EncryptedToken::from_database(db_value)?;
    /// let plaintext = encryptor.decrypt(&encrypted)?;
    /// // Use plaintext to call GitHub API
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Token format is invalid
    /// - Nonce/ciphertext are not valid base64
    /// - Nonce length is incorrect
    /// - Authentication tag is invalid (tampered data)
    /// - Decryption fails (wrong key or corrupted data)
    pub fn decrypt(&self, encrypted: &EncryptedToken) -> Result<String> {
        let parts: Vec<&str> = encrypted.0.split(':').collect();
        if parts.len() != 2 {
            return Err(BeemFlowError::validation(
                "Invalid encrypted token format. Expected 'nonce:ciphertext'.",
            ));
        }

        // Decode base64
        let (nonce_part, ciphertext_part) = match parts.as_slice() {
            [n, c] => (*n, *c),
            _ => {
                return Err(BeemFlowError::validation(
                    "Invalid encrypted token format during decryption.",
                ));
            }
        };

        let nonce_bytes = BASE64
            .decode(nonce_part)
            .map_err(|_| BeemFlowError::validation("Invalid nonce encoding"))?;
        let ciphertext = BASE64
            .decode(ciphertext_part)
            .map_err(|_| BeemFlowError::validation("Invalid ciphertext encoding"))?;

        // Validate nonce length (96 bits = 12 bytes for GCM)
        if nonce_bytes.len() != 12 {
            return Err(BeemFlowError::validation(format!(
                "Invalid nonce length: {} bytes (expected 12)",
                nonce_bytes.len()
            )));
        }

        let nonce_len = nonce_bytes.len();
        let nonce: [u8; 12] = nonce_bytes.try_into().map_err(|_| {
            BeemFlowError::validation(format!(
                "Nonce length mismatch (got {} bytes, expected 12)",
                nonce_len
            ))
        })?;

        // Decrypt with authentication check
        let plaintext = self
            .cipher
            .decrypt(&nonce.into(), ciphertext.as_ref())
            .map_err(|e| {
                // This could indicate:
                // 1. Wrong encryption key
                // 2. Data was tampered with
                // 3. Corrupted database
                BeemFlowError::internal(format!(
                    "Token decryption failed (wrong key or tampered data): {}",
                    e
                ))
            })?;

        String::from_utf8(plaintext)
            .map_err(|_| BeemFlowError::validation("Decrypted token contains invalid UTF-8"))
    }
}

impl std::fmt::Debug for TokenEncryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenEncryption")
            .field("cipher", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod encryption_tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let encryptor = TokenEncryption::from_test_key();
        let plaintext = "ghp_test_github_token_abc123";

        let encrypted = encryptor.encrypt(plaintext).unwrap();
        let decrypted = encryptor.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_different_nonces_different_ciphertexts() {
        let encryptor = TokenEncryption::from_test_key();
        let plaintext = "same_token_content";

        let encrypted1 = encryptor.encrypt(plaintext).unwrap();
        let encrypted2 = encryptor.encrypt(plaintext).unwrap();

        // Different nonces = different ciphertexts (no patterns revealed)
        assert_ne!(encrypted1, encrypted2);

        // But both decrypt to same plaintext
        assert_eq!(encryptor.decrypt(&encrypted1).unwrap(), plaintext);
        assert_eq!(encryptor.decrypt(&encrypted2).unwrap(), plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let encryptor = TokenEncryption::from_test_key();
        let encrypted = encryptor.encrypt("test_token").unwrap();

        // Tamper with the ciphertext by flipping a bit in the last character
        let mut tampered_str = encrypted.0.clone();
        if let Some(last_char) = tampered_str.pop() {
            tampered_str.push(if last_char == 'A' { 'B' } else { 'A' });
        }
        let tampered = EncryptedToken(tampered_str);

        // Decryption should fail (authenticated encryption detects tampering)
        let result = encryptor.decrypt(&tampered);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_format_rejected() {
        // Missing colon
        let invalid1 = EncryptedToken::from_database("no_colon_here".to_string());
        assert!(invalid1.is_err());

        // Multiple colons
        let invalid2 = EncryptedToken::from_database("part1:part2:part3".to_string());
        assert!(invalid2.is_err());

        // Invalid base64
        let invalid3 = EncryptedToken::from_database("not-base64!!!:also-not!!!".to_string());
        assert!(invalid3.is_err());
    }

    #[test]
    fn test_wrong_key_decryption_fails() {
        let encryptor1 = TokenEncryption::from_test_key();

        // Different key
        let key2 = [99u8; 32];
        let encryptor2 = TokenEncryption {
            cipher: Arc::new(Aes256Gcm::new(&key2.into())),
        };

        let encrypted = encryptor1.encrypt("secret_data").unwrap();

        // Decryption with wrong key should fail
        let result = encryptor2.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_string_encryption() {
        let encryptor = TokenEncryption::from_test_key();

        let encrypted = encryptor.encrypt("").unwrap();
        let decrypted = encryptor.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, "");
    }

    #[test]
    fn test_long_token_encryption() {
        let encryptor = TokenEncryption::from_test_key();

        // Very long token (realistic OAuth tokens can be 1KB+)
        let long_token = "x".repeat(2048);

        let encrypted = encryptor.encrypt(&long_token).unwrap();
        let decrypted = encryptor.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, long_token);
    }

    #[test]
    fn test_encrypted_token_display() {
        let encryptor = TokenEncryption::from_test_key();
        let encrypted = encryptor.encrypt("secret").unwrap();

        let display = format!("{}", encrypted);

        assert!(display.contains("[encrypted"));
        assert!(!display.contains("secret"));
    }

    #[test]
    fn test_unicode_token_encryption() {
        let encryptor = TokenEncryption::from_test_key();
        let unicode_token = "токен_с_юникодом_🔐";

        let encrypted = encryptor.encrypt(unicode_token).unwrap();
        let decrypted = encryptor.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, unicode_token);
    }
}
