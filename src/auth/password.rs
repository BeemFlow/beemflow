//! Password hashing and verification
//!
//! Uses bcrypt for secure password hashing with automatic salting.
use crate::Result;

/// Default bcrypt cost factor (2^12 iterations)
/// This provides a good balance between security and performance
const DEFAULT_COST: u32 = 12;

/// Hash a password using bcrypt
///
/// # Arguments
/// * `password` - Plain text password to hash
///
/// # Returns
/// Bcrypt hash string including salt (safe to store in database)
///
/// # Example
/// ```ignore
/// let hash = hash_password("my-secure-password")?;
/// assert!(hash.starts_with("$2b$"));
/// ```
pub fn hash_password(password: &str) -> Result<String> {
    bcrypt::hash(password, DEFAULT_COST)
        .map_err(|e| crate::BeemFlowError::OAuth(format!("Failed to hash password: {}", e)))
}

/// Verify a password against a hash
///
/// # Arguments
/// * `password` - Plain text password to verify
/// * `hash` - Bcrypt hash to verify against
///
/// # Returns
/// `Ok(true)` if password matches, `Ok(false)` if it doesn't
///
/// # Example
/// ```ignore
/// let hash = hash_password("my-password")?;
/// assert!(verify_password("my-password", &hash)?);
/// assert!(!verify_password("wrong-password", &hash)?);
/// ```
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    bcrypt::verify(password, hash)
        .map_err(|e| crate::BeemFlowError::OAuth(format!("Failed to verify password: {}", e)))
}

/// Validate password strength
///
/// Requirements:
/// - At least 8 characters
/// - At least one uppercase letter (optional but recommended)
/// - At least one lowercase letter (optional but recommended)
/// - At least one digit (optional but recommended)
///
/// # Arguments
/// * `password` - Password to validate
///
/// # Returns
/// `Ok(())` if password meets minimum requirements
pub fn validate_password_strength(password: &str) -> Result<()> {
    if password.len() < 8 {
        return Err(crate::BeemFlowError::validation(
            "Password must be at least 8 characters",
        ));
    }

    if password.len() > 128 {
        return Err(crate::BeemFlowError::validation(
            "Password must be less than 128 characters",
        ));
    }

    // Check for common weak passwords
    let weak_passwords = ["password", "12345678", "password123", "qwerty"];
    if weak_passwords.contains(&password.to_lowercase().as_str()) {
        return Err(crate::BeemFlowError::validation("Password is too common"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let password = "my-secure-password-123";
        let hash = hash_password(password).expect("Failed to hash password");

        // Hash should be valid bcrypt format
        assert!(hash.starts_with("$2b$") || hash.starts_with("$2a$"));

        // Correct password should verify
        assert!(verify_password(password, &hash).expect("Failed to verify"));

        // Wrong password should not verify
        assert!(!verify_password("wrong-password", &hash).expect("Failed to verify"));
    }

    #[test]
    fn test_different_hashes() {
        let password = "same-password";

        let hash1 = hash_password(password).expect("Failed to hash");
        let hash2 = hash_password(password).expect("Failed to hash");

        // Different salts should produce different hashes
        assert_ne!(hash1, hash2);

        // But both should verify
        assert!(verify_password(password, &hash1).expect("Failed to verify"));
        assert!(verify_password(password, &hash2).expect("Failed to verify"));
    }

    #[test]
    fn test_validate_password_strength() {
        // Too short
        assert!(validate_password_strength("short").is_err());

        // Too long
        let too_long = "a".repeat(129);
        assert!(validate_password_strength(&too_long).is_err());

        // Common weak password
        assert!(validate_password_strength("password").is_err());
        assert!(validate_password_strength("12345678").is_err());

        // Valid passwords
        assert!(validate_password_strength("MySecure123").is_ok());
        assert!(validate_password_strength("correct-horse-battery-staple").is_ok());
        assert!(validate_password_strength("abcdefgh").is_ok()); // Minimum length
    }

    #[test]
    fn test_empty_password() {
        assert!(validate_password_strength("").is_err());
    }

    #[test]
    fn test_unicode_password() {
        let password = "пароль123"; // Russian + numbers
        assert!(validate_password_strength(password).is_ok());

        let hash = hash_password(password).expect("Failed to hash");
        assert!(verify_password(password, &hash).expect("Failed to verify"));
    }
}
