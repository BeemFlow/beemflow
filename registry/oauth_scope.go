package registry

import "strings"

// OAuthScope represents an OAuth scope with automatic string formatting
type OAuthScope string

// String implements the fmt.Stringer interface to provide user-friendly scope names
func (s OAuthScope) String() string {
	// Extract a friendly name from scope URL
	parts := strings.Split(string(s), "/")
	if len(parts) > 0 {
		lastPart := parts[len(parts)-1]
		// Remove common prefixes and make it more readable
		lastPart = strings.ReplaceAll(lastPart, "_", " ")
		lastPart = strings.ReplaceAll(lastPart, ".", " ")
		return strings.Title(lastPart)
	}
	return string(s)
}

// Raw returns the original scope string without formatting
func (s OAuthScope) Raw() string {
	return string(s)
}

// ScopesToStrings converts a slice of OAuthScope to a slice of strings (raw values)
func ScopesToStrings(scopes []OAuthScope) []string {
	result := make([]string, len(scopes))
	for i, scope := range scopes {
		result[i] = scope.Raw()
	}
	return result
}
