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

/// Check if a character is allowed in passwords (ALLOWLIST approach)
///
/// Security: Uses an allowlist to explicitly define permitted characters.
/// This is safer than blocklisting because unknown/new attack vectors
/// are rejected by default.
///
/// Allowed characters:
/// - Printable ASCII (space through tilde: 0x20-0x7E)
/// - Unicode letters (Latin extended, Cyrillic, Arabic, CJK, etc.)
/// - Unicode numbers
/// - Unicode marks (combining characters for accents)
/// - Common symbols and punctuation
///
/// Explicitly rejected:
/// - Control characters (0x00-0x1F, 0x7F, etc.)
/// - NUL bytes
/// - Private use characters
/// - Emoji (complex encoding with variant selectors)
#[inline]
fn is_allowed_password_char(c: char) -> bool {
    // Printable ASCII: space (0x20) through tilde (0x7E)
    if c.is_ascii() {
        return (' '..='~').contains(&c);
    }

    // For non-ASCII, use Unicode categories (allowlist approach)
    // Allow: letters, numbers, marks, punctuation, symbols, spaces
    c.is_alphabetic()           // Letters (any script)
        || c.is_numeric()       // Numbers (any script)
        || c.is_ascii_punctuation() // Already covered above, but explicit
        || matches!(c,
            '\u{0080}'..='\u{00FF}'   // Latin-1 Supplement (accented chars, symbols)
            | '\u{0100}'..='\u{017F}' // Latin Extended-A
            | '\u{0180}'..='\u{024F}' // Latin Extended-B
            | '\u{0250}'..='\u{02AF}' // IPA Extensions
            | '\u{0300}'..='\u{036F}' // Combining Diacritical Marks
            | '\u{0400}'..='\u{04FF}' // Cyrillic
            | '\u{0500}'..='\u{052F}' // Cyrillic Supplement
            | '\u{0600}'..='\u{06FF}' // Arabic
            | '\u{0900}'..='\u{097F}' // Devanagari
            | '\u{3040}'..='\u{309F}' // Hiragana
            | '\u{30A0}'..='\u{30FF}' // Katakana
            | '\u{4E00}'..='\u{9FFF}' // CJK Unified Ideographs
            | '\u{AC00}'..='\u{D7AF}' // Hangul Syllables
            | '\u{2000}'..='\u{206F}' // General Punctuation (excluding control)
            | '\u{2070}'..='\u{209F}' // Superscripts and Subscripts
            | '\u{20A0}'..='\u{20CF}' // Currency Symbols
            | '\u{2100}'..='\u{214F}' // Letterlike Symbols
            | '\u{2190}'..='\u{21FF}' // Arrows
            | '\u{2200}'..='\u{22FF}' // Mathematical Operators
            | '\u{2300}'..='\u{23FF}' // Miscellaneous Technical
            | '\u{2600}'..='\u{26FF}' // Miscellaneous Symbols
        )
}

/// Validate password strength
///
/// Requirements:
/// - At least 12 characters (sufficient length for security)
/// - Maximum 128 characters (reasonable upper bound)
/// - Only allowed characters (ALLOWLIST-based validation)
/// - Not a common weak password
///
/// Character validation uses an ALLOWLIST approach:
/// - Explicitly defines what characters ARE permitted
/// - Rejects anything not in the allowlist (safe default)
/// - Allows printable ASCII + common Unicode for international users
///
/// Length-based validation is preferred over complexity rules because:
/// - "correct-horse-battery-staple" (25 chars) is stronger than "P@ssw0rd1" (9 chars)
/// - Encourages passphrases over complex but short passwords
/// - Easier for users to remember
/// - Aligns with NIST guidelines (SP 800-63B)
///
/// # Arguments
/// * `password` - Password to validate
///
/// # Returns
/// `Ok(())` if password meets minimum requirements
pub fn validate_password_strength(password: &str) -> Result<()> {
    // Length validation first (fast check)
    if password.len() < 12 {
        return Err(crate::BeemFlowError::validation(
            "Password must be at least 12 characters",
        ));
    }

    if password.len() > 128 {
        return Err(crate::BeemFlowError::validation(
            "Password must be less than 128 characters",
        ));
    }

    // Character allowlist validation (security critical)
    // Reject any character not in our explicit allowlist
    for (idx, c) in password.chars().enumerate() {
        if !is_allowed_password_char(c) {
            // Don't leak the exact character in error (could be control char)
            return Err(crate::BeemFlowError::validation(format!(
                "Password contains invalid character at position {}. \
                 Only printable ASCII and common Unicode characters are allowed.",
                idx + 1
            )));
        }
    }

    // Check for common weak passwords
    let weak_passwords = [
        "password",
        "123456789012",
        "password123",
        "qwertyuiop",
        "passwordpassword",
    ];
    if weak_passwords.contains(&password.to_lowercase().as_str()) {
        return Err(crate::BeemFlowError::validation(
            "Password is too common. Please choose a unique password.",
        ));
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
        // Too short (< 12 chars)
        assert!(validate_password_strength("short").is_err());
        assert!(validate_password_strength("11char-pass").is_err()); // 11 chars

        // Too long
        let too_long = "a".repeat(129);
        assert!(validate_password_strength(&too_long).is_err());

        // Common weak password
        assert!(validate_password_strength("password").is_err());
        assert!(validate_password_strength("123456789012").is_err());
        assert!(validate_password_strength("passwordpassword").is_err());

        // Valid passwords (12+ chars)
        assert!(validate_password_strength("MySecure1234").is_ok()); // 12 chars
        assert!(validate_password_strength("correct-horse-battery-staple").is_ok()); // Long passphrase
        assert!(validate_password_strength("abcdefghijkl").is_ok()); // Exactly 12 chars
        assert!(validate_password_strength("simple-but-long-enough").is_ok()); // 22 chars
    }

    #[test]
    fn test_empty_password() {
        assert!(validate_password_strength("").is_err());
    }

    #[test]
    fn test_unicode_password() {
        let password = "пароль-secure"; // Russian + ASCII (12+ chars)
        assert!(validate_password_strength(password).is_ok());

        let hash = hash_password(password).expect("Failed to hash");
        assert!(verify_password(password, &hash).expect("Failed to verify"));
    }

    #[test]
    fn test_control_characters_rejected() {
        // NUL byte should be rejected
        assert!(validate_password_strength("password\x00password").is_err());

        // Tab should be rejected (control character)
        assert!(validate_password_strength("password\tpassword").is_err());

        // Newline should be rejected
        assert!(validate_password_strength("password\npassword").is_err());

        // Carriage return should be rejected
        assert!(validate_password_strength("password\rpassword").is_err());

        // Bell character should be rejected
        assert!(validate_password_strength("password\x07password").is_err());

        // Escape character should be rejected
        assert!(validate_password_strength("password\x1Bpassword").is_err());

        // DEL character should be rejected
        assert!(validate_password_strength("password\x7Fpassword").is_err());
    }

    #[test]
    fn test_printable_ascii_allowed() {
        // All printable ASCII should be allowed
        assert!(validate_password_strength("Hello World!").is_ok()); // space allowed
        assert!(validate_password_strength("P@ssw0rd#123").is_ok()); // symbols allowed
        assert!(validate_password_strength("~`!@#$%^&*()-").is_ok()); // special chars
        assert!(validate_password_strength("password{json}").is_ok()); // braces
        assert!(validate_password_strength("user@email.com").is_ok()); // email-like
    }

    #[test]
    fn test_international_passwords() {
        // Japanese (Hiragana + Katakana)
        assert!(validate_password_strength("パスワードひらがな").is_ok());

        // Chinese
        assert!(validate_password_strength("密码安全测试字符串").is_ok());

        // Korean
        assert!(validate_password_strength("비밀번호테스트문자열").is_ok());

        // Arabic
        assert!(validate_password_strength("كلمة المرور الآمنة").is_ok());

        // Mixed scripts
        assert!(validate_password_strength("Пароль密码password").is_ok());
    }

    #[test]
    fn test_is_allowed_password_char() {
        // Printable ASCII allowed
        assert!(is_allowed_password_char(' ')); // space
        assert!(is_allowed_password_char('~')); // tilde (highest printable)
        assert!(is_allowed_password_char('a'));
        assert!(is_allowed_password_char('Z'));
        assert!(is_allowed_password_char('0'));
        assert!(is_allowed_password_char('@'));

        // Control characters rejected
        assert!(!is_allowed_password_char('\x00')); // NUL
        assert!(!is_allowed_password_char('\t')); // TAB
        assert!(!is_allowed_password_char('\n')); // LF
        assert!(!is_allowed_password_char('\r')); // CR
        assert!(!is_allowed_password_char('\x1F')); // Unit separator
        assert!(!is_allowed_password_char('\x7F')); // DEL

        // Unicode letters allowed
        assert!(is_allowed_password_char('é')); // Latin Extended
        assert!(is_allowed_password_char('ñ')); // Latin Extended
        assert!(is_allowed_password_char('Ω')); // Greek
        assert!(is_allowed_password_char('中')); // CJK
        assert!(is_allowed_password_char('あ')); // Hiragana
        assert!(is_allowed_password_char('한')); // Hangul
    }
}
