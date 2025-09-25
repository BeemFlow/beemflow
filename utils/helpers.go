package utils

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/beemflow/beemflow/constants"
)

// ============================================================================
// STANDARDIZED ERROR HELPERS
// ============================================================================

// ErrorWrapper provides standardized error handling patterns
type ErrorWrapper struct {
	context string
}

// NewErrorWrapper creates a new error wrapper with context
func NewErrorWrapper(context string) *ErrorWrapper {
	return &ErrorWrapper{context: context}
}

// Wrapf wraps an error with context and formatting
func (e *ErrorWrapper) Wrapf(err error, format string, args ...any) error {
	if err == nil {
		return nil
	}
	message := fmt.Sprintf(format, args...)
	return Errorf("%s: %s: %w", e.context, message, err)
}

// Failf creates a new error with context and formatting
func (e *ErrorWrapper) Failf(format string, args ...any) error {
	message := fmt.Sprintf(format, args...)
	return Errorf("%s: %s", e.context, message)
}

// ============================================================================
// STANDARDIZED JSON HELPERS
// ============================================================================

// JSONResult represents the result of a JSON operation
type JSONResult struct {
	Data []byte
	Err  error
}

// MarshalJSON marshals data to JSON with error handling
func MarshalJSON(v any) JSONResult {
	data, err := json.Marshal(v)
	return JSONResult{Data: data, Err: err}
}

// MarshalJSONIndent marshals data to pretty JSON with error handling
func MarshalJSONIndent(v any, indent string) JSONResult {
	if indent == "" {
		indent = constants.JSONIndent
	}
	data, err := json.MarshalIndent(v, "", indent)
	return JSONResult{Data: data, Err: err}
}

// UnmarshalJSON unmarshals JSON data with error handling
func UnmarshalJSON(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// MustMarshalJSON marshals to JSON and panics on error (for testing)
func MustMarshalJSON(v any) []byte {
	result := MarshalJSON(v)
	if result.Err != nil {
		panic(result.Err)
	}
	return result.Data
}

// ============================================================================
// STANDARDIZED HTTP HELPERS
// ============================================================================

// HTTPErrorResponse represents a standardized HTTP error response
type HTTPErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code"`
}

// WriteHTTPError writes a standardized HTTP error response
func WriteHTTPError(w http.ResponseWriter, message string, code int) {
	w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
	w.WriteHeader(code)

	response := HTTPErrorResponse{
		Error:   http.StatusText(code),
		Message: message,
		Code:    code,
	}

	if result := MarshalJSON(response); result.Err == nil {
		w.Write(result.Data)
	} else {
		// Fallback to plain text if JSON marshaling fails
		w.Header().Set(constants.HeaderContentType, constants.ContentTypeText)
		fmt.Fprintf(w, "Error: %s", message)
	}
}

// WriteHTTPJSON writes a JSON response with proper headers
func WriteHTTPJSON(w http.ResponseWriter, v any) error {
	w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)

	result := MarshalJSON(v)
	if result.Err != nil {
		WriteHTTPError(w, "Failed to encode response", http.StatusInternalServerError)
		return result.Err
	}

	w.Write(result.Data)
	return nil
}

// WriteHTTPJSONIndent writes a pretty JSON response with proper headers
func WriteHTTPJSONIndent(w http.ResponseWriter, v any, indent string) error {
	w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)

	result := MarshalJSONIndent(v, indent)
	if result.Err != nil {
		WriteHTTPError(w, "Failed to encode response", http.StatusInternalServerError)
		return result.Err
	}

	w.Write(result.Data)
	return nil
}

// ============================================================================
// STANDARDIZED VALIDATION HELPERS
// ============================================================================

// ValidateRequired checks if required fields are present
func ValidateRequired(fieldName string, value any) error {
	if value == nil {
		return Errorf("required field '%s' is missing", fieldName)
	}

	switch v := value.(type) {
	case string:
		if v == "" {
			return Errorf("required field '%s' cannot be empty", fieldName)
		}
	case []any:
		if len(v) == 0 {
			return Errorf("required field '%s' cannot be empty", fieldName)
		}
	case map[string]any:
		if len(v) == 0 {
			return Errorf("required field '%s' cannot be empty", fieldName)
		}
	}

	return nil
}

// ValidateOneOf checks if value is one of the allowed values
func ValidateOneOf(fieldName string, value string, allowed []string) error {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	return Errorf("field '%s' must be one of %v, got '%s'", fieldName, allowed, value)
}

// ============================================================================
// STANDARDIZED CONTEXT HELPERS
// ============================================================================

// ContextValue safely extracts a value from context
func ContextValue[T any](ctx context.Context, key any) (T, bool) {
	var zero T
	value := ctx.Value(key)
	if value == nil {
		return zero, false
	}

	typed, ok := value.(T)
	return typed, ok
}

// ContextValueRequired extracts a required value from context
func ContextValueRequired[T any](ctx context.Context, key any) (T, error) {
	value, ok := ContextValue[T](ctx, key)
	if !ok {
		var zero T
		return zero, Errorf("required context value '%v' not found", key)
	}
	return value, nil
}

// ============================================================================
// STANDARDIZED SAFE TYPE ASSERTION HELPERS
// ============================================================================

// SafeStringAssert safely asserts a value to string
func SafeStringAssert(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// SafeMapAssert safely asserts a value to map[string]any
func SafeMapAssert(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// SafeSliceAssert safely asserts a value to []any
func SafeSliceAssert(v any) ([]any, bool) {
	s, ok := v.([]any)
	return s, ok
}

// SafeIntAssert safely asserts a value to int
func SafeIntAssert(v any) (int, bool) {
	switch val := v.(type) {
	case int:
		return val, true
	case int64:
		return int(val), true
	case float64:
		return int(val), true
	default:
		return 0, false
	}
}

// SafeBoolAssert safely asserts a value to bool
func SafeBoolAssert(v any) (bool, bool) {
	b, ok := v.(bool)
	return b, ok
}

// ============================================================================
// CRYPTO UTILITIES FOR SECURE TOKEN STORAGE
// ============================================================================

// EncryptToken encrypts a token using AES-GCM with a fixed key
// WARNING: In production, use a proper key management system
func EncryptToken(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	// Use a fixed key for development - IN PRODUCTION, USE PROPER KEY MANAGEMENT
	key := []byte("beemflow-oauth-encryption-key-32") // Exactly 32 bytes

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptToken decrypts a token encrypted with EncryptToken
func DecryptToken(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	// Use the same fixed key
	key := []byte("beemflow-oauth-encryption-key-32") // Exactly 32 bytes

	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertextBytes) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertextBytes := ciphertextBytes[:nonceSize], ciphertextBytes[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}
