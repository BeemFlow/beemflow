package cue

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/load"
	"github.com/beemflow/beemflow/model"
)

// Parser handles CUE-based flow parsing and validation
type Parser struct {
	ctx *cue.Context
}

// NewParser creates a new CUE parser
func NewParser() *Parser {
	return &Parser{
		ctx: cuecontext.New(),
	}
}

// ParseFile parses a CUE file into a Flow struct
func (p *Parser) ParseFile(path string) (*model.Flow, error) {
	// Load CUE file
	insts := load.Instances([]string{path}, nil)
	if len(insts) == 0 {
		return nil, fmt.Errorf("no CUE instances found in %s", path)
	}

	inst := insts[0]
	if inst.Err != nil {
		return nil, fmt.Errorf("CUE load error: %w", inst.Err)
	}

	// Build the instance
	value := p.ctx.BuildInstance(inst)
	if value.Err() != nil {
		return nil, fmt.Errorf("CUE build error: %w", value.Err())
	}

	// Validate against schema
	if err := p.validateSchema(value); err != nil {
		return nil, fmt.Errorf("schema validation error: %w", err)
	}

	// Convert to Flow struct
	return p.valueToFlow(value)
}

// ParseString parses CUE content from a string
func (p *Parser) ParseString(cueStr string) (*model.Flow, error) {
	value := p.ctx.CompileString(cueStr)
	if value.Err() != nil {
		return nil, fmt.Errorf("CUE compile error: %w", value.Err())
	}

	// Validate against schema
	if err := p.validateSchema(value); err != nil {
		return nil, fmt.Errorf("schema validation error: %w", err)
	}

	// Convert to Flow struct
	return p.valueToFlow(value)
}

// validateSchema checks the CUE value against our schema
func (p *Parser) validateSchema(value cue.Value) error {
	// For now, just check that required fields exist
	// In the future, we could unify this with the embedded schema
	nameVal := value.LookupPath(cue.ParsePath("name"))
	if nameVal.Err() != nil {
		return fmt.Errorf("flow must have a 'name' field")
	}

	stepsVal := value.LookupPath(cue.ParsePath("steps"))
	if stepsVal.Err() != nil {
		return fmt.Errorf("flow must have 'steps' field")
	}

	onVal := value.LookupPath(cue.ParsePath("on"))
	if onVal.Err() != nil {
		return fmt.Errorf("flow must have 'on' field")
	}

	return nil
}

// valueToFlow converts a CUE value to a model.Flow
func (p *Parser) valueToFlow(value cue.Value) (*model.Flow, error) {
	// Convert CUE value to JSON, then unmarshal to model.Flow
	jsonBytes, err := value.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CUE to JSON: %w", err)
	}

	var flow model.Flow
	if err := json.Unmarshal(jsonBytes, &flow); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON to Flow: %w", err)
	}

	return &flow, nil
}

// Validate runs validation on a parsed flow
func (p *Parser) Validate(flow *model.Flow) error {
	// For now, just basic validation
	// In the future, we could do more sophisticated CUE-based validation
	if flow.Name == "" {
		return fmt.Errorf("flow name cannot be empty")
	}
	if len(flow.Steps) == 0 {
		return fmt.Errorf("flow must have at least one step")
	}
	return nil
}

// ParseFile parses a CUE flow file
func ParseFile(path string) (*model.Flow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".cue":
		parser := NewParser()
		return parser.ParseString(string(data))
	default:
		return nil, fmt.Errorf("unsupported file extension %q, only .cue files are supported", ext)
	}
}

// ResolveRuntimeTemplates resolves runtime-dependent templates using CUE evaluation
func ResolveRuntimeTemplates(text string, context map[string]any) string {
	if !strings.Contains(text, "{{") {
		return text
	}

	re := regexp.MustCompile(`\{\{\s*([^{}]+)\s*\}\}`)
	return re.ReplaceAllStringFunc(text, func(match string) string {
		expr := strings.TrimSpace(match[2 : len(match)-2]) // Remove {{ }}
		return evaluateCUEExpression(expr, context)
	})
}

// normalizeSingleQuotes converts single-quoted strings to double-quoted for CUE compatibility
// CUE treats 'x' as bytes, not strings, so we need to convert 'str' to "str"
func normalizeSingleQuotes(expr string) string {
	var result strings.Builder
	inDoubleQuote := false
	inSingleQuote := false

	for i := 0; i < len(expr); i++ {
		ch := expr[i]

		switch ch {
		case '"':
			if !inSingleQuote {
				inDoubleQuote = !inDoubleQuote
			}
			result.WriteByte(ch)
		case '\'':
			if !inDoubleQuote {
				// Convert single quote to double quote
				result.WriteByte('"')
				inSingleQuote = !inSingleQuote
			} else {
				result.WriteByte(ch)
			}
		case '\\':
			// Handle escape sequences
			result.WriteByte(ch)
			if i+1 < len(expr) {
				i++
				result.WriteByte(expr[i])
			}
		default:
			result.WriteByte(ch)
		}
	}

	return result.String()
}

// EvaluateCUEExpression evaluates expressions using CUE and returns a string (exported for engine use)
func EvaluateCUEExpression(expr string, context map[string]any) string {
	return evaluateCUEExpression(expr, context)
}

// EvaluateCUEBoolean evaluates a CUE expression and returns it as a boolean
// This eliminates the need for custom isTruthy logic by using CUE's native bool evaluation
func EvaluateCUEBoolean(expr string, context map[string]any) (bool, error) {
	ctx := cuecontext.New()

	// Normalize single quotes to double quotes
	expr = normalizeSingleQuotes(expr)

	// Create a CUE script with the context
	contextScript := buildCUEContextScript(context)
	if strings.HasSuffix(contextScript, "}") {
		contextScript = contextScript[:len(contextScript)-1]
		contextScript += "\tresult: " + expr + "\n}"
	} else {
		contextScript = "{\n\tresult: " + expr + "\n}"
	}

	cueValue := ctx.CompileString(contextScript)
	if cueValue.Err() != nil {
		// CUE compilation errors (like undefined vars) are treated as falsy
		return false, nil
	}

	resultField := cueValue.LookupPath(cue.ParsePath("result"))
	if resultField.Err() != nil {
		// CUE evaluation errors (like missing fields) are treated as falsy
		return false, nil
	}

	// Try to get as boolean directly
	if boolVal, err := resultField.Bool(); err == nil {
		return boolVal, nil
	}

	// Try to get as number (non-zero numbers are truthy)
	if numVal, err := resultField.Int64(); err == nil {
		return numVal != 0, nil
	}
	if floatVal, err := resultField.Float64(); err == nil {
		return floatVal != 0.0, nil
	}

	// Fallback: check for common truthy/falsy string representations
	strVal, err := resultField.String()
	if err != nil {
		// If we can't get string, bool, or number, treat as falsy
		return false, nil
	}

	// Apply truthiness rules for string values
	strVal = strings.TrimSpace(strVal)
	if strVal == "" || strVal == "false" || strVal == "0" || strVal == "null" || strVal == "<nil>" || strVal == "_|_" {
		return false, nil
	}
	if strings.HasPrefix(strVal, "{{") && strings.HasSuffix(strVal, "}}") {
		// Unresolved template
		return false, nil
	}

	return true, nil
}

// EvaluateCUEArray evaluates a CUE expression and returns it as a Go slice
func EvaluateCUEArray(expr string, context map[string]any) []any {
	ctx := cuecontext.New()

	// Create a CUE script that defines the context and evaluates the expression
	contextScript := buildCUEContextScript(context)
	if strings.HasSuffix(contextScript, "}") {
		contextScript = contextScript[:len(contextScript)-1]
		contextScript += "\tresult: " + expr + "\n}"
	} else {
		contextScript = "{\n\tresult: " + expr + "\n}"
	}

	cueValue := ctx.CompileString(contextScript)
	if cueValue.Err() != nil {
		return nil
	}

	resultField := cueValue.LookupPath(cue.ParsePath("result"))
	if resultField.Err() != nil {
		return nil
	}

	// Check if it's a list
	list, err := resultField.List()
	if err != nil {
		return nil
	}

	var items []any
	for list.Next() {
		val := list.Value()
		goValue := ExtractCUEValue(val)
		items = append(items, goValue)
	}

	return items
}

// evaluateCUEExpression evaluates expressions using CUE (internal)
func evaluateCUEExpression(expr string, context map[string]any) string {
	ctx := cuecontext.New()

	// Normalize single quotes to double quotes for CUE compatibility
	// CUE treats 'x' as bytes, not strings, so we convert 'str' to "str"
	expr = normalizeSingleQuotes(expr)

	// Create a CUE script that defines the context and evaluates the expression
	// We need to put result inside the same struct as the context variables
	contextScript := buildCUEContextScript(context)
	// Remove the closing brace and add result field inside
	if strings.HasSuffix(contextScript, "}") {
		contextScript = contextScript[:len(contextScript)-1]
		contextScript += "\tresult: " + expr + "\n}"
	} else {
		// Fallback if script format changes
		contextScript = "{\n\tresult: " + expr + "\n}"
	}

	// DEBUG: Uncomment to see generated CUE script
	// fmt.Printf("DEBUG CUE Script for expr '%s':\n%s\n\n", expr, contextScript)

	cueValue := ctx.CompileString(contextScript)
	if cueValue.Err() != nil {
		// If CUE compilation fails, return the original expression wrapped in {{ }}
		return "{{" + expr + "}}"
	}

	resultField := cueValue.LookupPath(cue.ParsePath("result"))
	if resultField.Err() != nil {
		// If result lookup fails, return the original expression wrapped in {{ }}
		return "{{" + expr + "}}"
	}

	value := ExtractCUEValue(resultField)
	return convertToString(value)
}

// buildCUEContextScript creates a CUE script that defines the context
func buildCUEContextScript(context map[string]any) string {
	var result strings.Builder
	result.WriteString("{\n")

	// First, add individual vars at top level for direct access (e.g., {{ item }} instead of {{ vars.item }})
	// This is especially important for foreach loop variables like item, item_index, item_row
	if vars, ok := context["vars"].(map[string]any); ok && len(vars) > 0 {
		for k, v := range vars {
			// Add each var as a top-level field for direct access
			if isValidCUEKey(k) {
				result.WriteString("\t")
				result.WriteString(k)
				result.WriteString(": ")
				writeCUEValue(&result, v)
				result.WriteString("\n")
			}
		}
		// Also keep vars namespace for explicit access
		result.WriteString("\tvars: ")
		writeCUEValue(&result, vars)
		result.WriteString("\n")
	}

	if outputs, ok := context["outputs"].(map[string]any); ok && len(outputs) > 0 {
		result.WriteString("\toutputs: ")
		writeCUEValue(&result, outputs)
		result.WriteString("\n")
	}

	if secrets, ok := context["secrets"].(map[string]any); ok && len(secrets) > 0 {
		result.WriteString("\tsecrets: ")
		writeCUEValue(&result, secrets)
		result.WriteString("\n")
	}

	if event, ok := context["event"].(map[string]any); ok && len(event) > 0 {
		result.WriteString("\tevent: ")
		writeCUEValue(&result, event)
		result.WriteString("\n")
	}

	if env, ok := context["env"].(map[string]any); ok && len(env) > 0 {
		result.WriteString("\tenv: ")
		writeCUEValue(&result, env)
		result.WriteString("\n")
	}

	if runs, ok := context["runs"].(map[string]any); ok && len(runs) > 0 {
		result.WriteString("\truns: ")
		writeCUEValue(&result, runs)
		result.WriteString("\n")
	}

	result.WriteString("}")
	return result.String()
}

// writeCUEValue writes a value in CUE syntax to the buffer
func writeCUEValue(buf *strings.Builder, val any) {
	if val == nil {
		buf.WriteString("null")
		return
	}

	// Use reflection to handle slice types generically
	rv := reflect.ValueOf(val)
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		buf.WriteString("[")
		for i := 0; i < rv.Len(); i++ {
			if i > 0 {
				buf.WriteString(", ")
			}
			writeCUEValue(buf, rv.Index(i).Interface())
		}
		buf.WriteString("]")
		return
	case reflect.Map:
		if m, ok := val.(map[string]any); ok {
			buf.WriteString("{")
			first := true
			for k, val := range m {
				// Skip keys that start with _ (CUE reserved) or are not valid CUE identifiers
				if strings.HasPrefix(k, "_") || !isValidCUEKey(k) {
					continue
				}
				if !first {
					buf.WriteString(", ")
				}
				first = false
				buf.WriteString(k)
				buf.WriteString(": ")
				writeCUEValue(buf, val)
			}
			buf.WriteString("}")
			return
		}
	}

	// Handle primitive types
	switch v := val.(type) {
	case string:
		// Escape all special characters for CUE strings
		buf.WriteString("\"")
		escaped := strings.ReplaceAll(v, "\\", "\\\\")
		escaped = strings.ReplaceAll(escaped, "\"", "\\\"")
		escaped = strings.ReplaceAll(escaped, "\n", "\\n")
		escaped = strings.ReplaceAll(escaped, "\r", "\\r")
		escaped = strings.ReplaceAll(escaped, "\t", "\\t")
		buf.WriteString(escaped)
		buf.WriteString("\"")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case int, int32, int64, float32, float64:
		buf.WriteString(fmt.Sprintf("%v", v))
	default:
		// For other types, convert to string
		buf.WriteString("\"")
		buf.WriteString(fmt.Sprintf("%v", v))
		buf.WriteString("\"")
	}
}

// isValidCUEKey checks if a string is a valid CUE map key (allowing some special cases)
func isValidCUEKey(s string) bool {
	if s == "" {
		return false
	}
	// First character must be letter (not underscore for keys, as _ is reserved)
	first := s[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')) {
		return false
	}
	// Rest can be letters, digits, or underscores
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

// isValidCUEIdentifier checks if a string is a valid CUE identifier
func isValidCUEIdentifier(s string) bool {
	if s == "" {
		return false
	}
	// First character must be letter or underscore
	first := s[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '_') {
		return false
	}
	// Rest can be letters, digits, or underscores
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// convertToString converts any value to string representation
func convertToString(val any) string {
	if val == nil {
		return ""
	}

	switch v := val.(type) {
	case string:
		return v
	case bool:
		return fmt.Sprintf("%t", v)
	case int:
		return fmt.Sprintf("%d", v)
	case int64:
		return fmt.Sprintf("%d", v)
	case float64:
		return fmt.Sprintf("%g", v)
	case float32:
		return fmt.Sprintf("%g", float64(v))
	default:
		// For complex types (maps, arrays), always use JSON marshaling
		bytes, err := json.Marshal(val)
		if err != nil {
			// If JSON marshaling fails, this is a serious issue
			// Return error indicator instead of Go's %v format
			return fmt.Sprintf("[marshal error: %v]", err)
		}
		return string(bytes)
	}
}

// ConvertToCUEFormat converts Go data structures to CUE-compatible format
func ConvertToCUEFormat(data any) any {
	switch v := data.(type) {
	case map[string]any:
		result := make(map[string]any)
		for k, val := range v {
			result[k] = ConvertToCUEFormat(val)
		}
		return result
	case []any:
		result := make([]any, len(v))
		for i, val := range v {
			result[i] = ConvertToCUEFormat(val)
		}
		return result
	default:
		return v
	}
}

// ExtractCUEValue extracts a value from a CUE result
func ExtractCUEValue(val cue.Value) any {
	// Try to get as string first
	if str, err := val.String(); err == nil {
		return str
	}

	// Try to get as bool
	if b, err := val.Bool(); err == nil {
		return b
	}

	// Try to get as int
	if i, err := val.Int(nil); err == nil {
		if i.IsInt64() {
			intVal := i.Int64()
			return int(intVal)
		}
		return i.String()
	}

	// Try to get as float
	if f, err := val.Float64(); err == nil {
		return f
	}

	// Try to extract as list
	if list, err := val.List(); err == nil {
		var items []any
		for list.Next() {
			items = append(items, ExtractCUEValue(list.Value()))
		}
		return items
	}

	// Try to extract as struct/map
	if fields, err := val.Fields(); err == nil {
		result := make(map[string]any)
		for fields.Next() {
			key := fields.Label()
			value := ExtractCUEValue(fields.Value())
			result[key] = value
		}
		return result
	}

	// Fallback to string representation
	if str, err := val.String(); err == nil {
		return str
	}

	return nil
}
