package dsl

import (
	"fmt"
	"maps"
	"strings"
	"sync"

	"github.com/beemflow/beemflow/utils"
	pongo2 "github.com/flosch/pongo2/v6"
)

var (
	// Global filter registration to avoid duplicate registrations
	filterRegistrationOnce sync.Once
	// Global mutex to protect all Pongo2 operations since the library has global state
	pongo2Mutex sync.Mutex
)

// Templater provides template rendering with Jinja2-style (pongo2) for BeemFlow flows.
type Templater struct{}

// NewTemplater creates a new Templater.
func NewTemplater() *Templater {
	t := &Templater{}

	// Register default custom filters only once globally
	filterRegistrationOnce.Do(func() {
		defaultFilters := map[string]pongo2.FilterFunction{
			"reverse": func(in *pongo2.Value, param *pongo2.Value) (*pongo2.Value, *pongo2.Error) {
				s := in.String()
				runes := []rune(s)
				for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
					runes[i], runes[j] = runes[j], runes[i]
				}
				return pongo2.AsValue(string(runes)), nil
			},
		}

		// Register the filters globally (this also needs global protection)
		pongo2Mutex.Lock()
		for name, fn := range defaultFilters {
			if err := pongo2.RegisterFilter(name, fn); err != nil {
				// Log the error but don't fail - the filter might already exist
				utils.Debug("Filter registration warning: %v", err)
			}
		}
		pongo2Mutex.Unlock()
	})

	return t
}

// Render renders a template string with the provided data using pongo2.
func (t *Templater) Render(tmpl string, data map[string]any) (string, error) {
	if data == nil {
		return "", fmt.Errorf("template data is nil")
	}
	ctx := flattenContext(data)

	// Protect ALL pongo2 operations with global mutex since they share global state
	pongo2Mutex.Lock()
	pl, err := pongo2.FromString(tmpl)
	if err != nil {
		pongo2Mutex.Unlock()
		return "", err
	}
	out, err := pl.Execute(ctx)
	pongo2Mutex.Unlock()

	if err != nil {
		return "", err
	}
	return out, nil
}

// RegisterFilters allows registering custom pongo2 filters.
func (t *Templater) RegisterFilters(filters map[string]pongo2.FilterFunction) error {
	pongo2Mutex.Lock()
	defer pongo2Mutex.Unlock()
	for name, fn := range filters {
		if err := pongo2.RegisterFilter(name, fn); err != nil {
			return utils.Errorf("failed to register filter %s: %w", name, err)
		}
	}
	return nil
}

// Render applies templating to the given string with the provided data.
func Render(tmpl string, data map[string]any) (string, error) {
	return NewTemplater().Render(tmpl, data)
}

// RegisterFilters applies custom filters for rendering.
func RegisterFilters(filters map[string]pongo2.FilterFunction) error {
	return NewTemplater().RegisterFilters(filters)
}

// flattenContext converts the map for pongo2 compatibility.
func flattenContext(data map[string]any) pongo2.Context {
	converted := make(pongo2.Context, len(data))
	maps.Copy(converted, data)
	return converted
}

// EvaluateExpression evaluates a template expression and returns the actual value
// instead of rendering it to a string. This is useful for foreach expressions.
func (t *Templater) EvaluateExpression(tmpl string, data map[string]any) (any, error) {
	if data == nil {
		return nil, fmt.Errorf("template data is nil")
	}

	// If it's not a template expression, return as-is
	if !strings.Contains(tmpl, "{{") {
		return tmpl, nil
	}

	// For simple variable expressions like {{varname}} or {{obj.field}}, look up directly
	trimmed := strings.TrimSpace(tmpl)
	if strings.HasPrefix(trimmed, "{{") && strings.HasSuffix(trimmed, "}}") &&
		!strings.Contains(trimmed, "|") {

		varPath := strings.TrimSpace(trimmed[2 : len(trimmed)-2])

		// Check if it's a simple variable or dot notation path
		if !strings.Contains(varPath, " ") && !strings.Contains(varPath, "(") &&
			!strings.Contains(varPath, "+") && !strings.Contains(varPath, "-") &&
			!strings.Contains(varPath, "*") && !strings.Contains(varPath, "/") {

			// Try to resolve the path in the flattened context
			ctx := flattenContext(data)
			if val, exists := ctx[varPath]; exists {
				return val, nil
			}

			// If not found in flattened context, try dot notation lookup
			if strings.Contains(varPath, ".") {
				if val := lookupNestedPath(data, varPath); val != nil {
					return val, nil
				}
			}
		}
	}

	// For complex expressions, render as string (template engine handles the complexity)
	return t.Render(tmpl, data)
}

// lookupNestedPath traverses a nested path like "obj.field.subfield" in the data
func lookupNestedPath(data map[string]any, path string) any {
	parts := strings.Split(path, ".")
	current := data

	for i, part := range parts {
		if val, ok := current[part]; ok {
			// If it's the last part, return the value
			if i == len(parts)-1 {
				return val
			}
			// If it's not the last part, it must be a map to continue
			if nextMap, ok := val.(map[string]any); ok {
				current = nextMap
			} else {
				return nil // Can't traverse further
			}
		} else {
			return nil // Path not found
		}
	}

	return nil
}
