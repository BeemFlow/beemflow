package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"unicode"

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
// STANDARDIZED STRING HELPERS
// ============================================================================

// ToTitle is a replacement for the deprecated strings.Title function
// It capitalizes the first letter and letters after spaces
func ToTitle(s string) string {
	if s == "" {
		return s
	}
	
	runes := []rune(s)
	result := make([]rune, len(runes))
	
	// Capitalize first letter and letters after spaces
	capitalizeNext := true
	for i, r := range runes {
		if capitalizeNext && unicode.IsLetter(r) {
			result[i] = unicode.ToUpper(r)
			capitalizeNext = false
		} else {
			result[i] = unicode.ToLower(r)
		}
		
		if unicode.IsSpace(r) {
			capitalizeNext = true
		}
	}
	
	return string(result)
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
