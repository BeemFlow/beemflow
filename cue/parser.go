package cue

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
		return resolveRuntimeExpression(expr, context)
	})
}

// resolveRuntimeExpression resolves complex expressions using CUE evaluation
func resolveRuntimeExpression(expr string, context map[string]any) string {
	// For complex expressions, use CUE evaluation
	if strings.Contains(expr, " ") || strings.Contains(expr, ">") || strings.Contains(expr, "<") ||
		strings.Contains(expr, "and") || strings.Contains(expr, "or") || strings.Contains(expr, "not") ||
		strings.Contains(expr, "|") || strings.Contains(expr, "[") || strings.Contains(expr, "(") {
		return evaluateCUEExpression(expr, context)
	}

	// For simple expressions, try direct resolution first, then fall back to CUE
	result := resolveSimpleExpression(expr, context)
	if result != "{{"+expr+"}}" {
		return result
	}

	// If simple resolution fails, try CUE evaluation
	return evaluateCUEExpression(expr, context)
}

// resolveSimpleExpression handles basic dot-notation access
func resolveSimpleExpression(expr string, context map[string]any) string {
	parts := strings.Split(expr, ".")

	if len(parts) < 1 {
		return "{{" + expr + "}}"
	}

	switch parts[0] {
	case "outputs", "steps":
		if len(parts) >= 2 {
			if stepOutputs, ok := context["outputs"].(map[string]any); ok {
				if stepOutput, exists := stepOutputs[parts[1]]; exists {
					return resolveNestedValue(stepOutput, parts[2:])
				}
			}
		}
	case "vars":
		if vars, ok := context["vars"].(map[string]any); ok {
			return resolveNestedValue(vars, parts[1:])
		}
	case "secrets":
		if secrets, ok := context["secrets"].(map[string]any); ok {
			return resolveNestedValue(secrets, parts[1:])
		}
	case "event":
		if event, ok := context["event"].(map[string]any); ok {
			return resolveNestedValue(event, parts[1:])
		}
	case "env":
		if env, ok := context["env"].(map[string]string); ok {
			if len(parts) >= 2 {
				if val, ok := env[parts[1]]; ok {
					return val
				}
			}
		}
	case "runs":
		if runs, ok := context["runs"].(map[string]any); ok {
			return resolveNestedValue(runs, parts[1:])
		}
	default:
		// Check if it's a variable reference (e.g., "item" or "item.field")
		// First, check if the first part is a variable in vars
		if vars, ok := context["vars"].(map[string]any); ok {
			// Check if the whole expression is a simple var
			if val, exists := vars[expr]; exists {
				if str, ok := val.(string); ok {
					return str
				}
				if bytes, err := json.Marshal(val); err == nil {
					return string(bytes)
				}
			}
			// Also check if parts[0] is a variable and resolve nested
			if val, exists := vars[parts[0]]; exists {
				return resolveNestedValue(val, parts[1:])
			}
		}
		// Also check top-level context for backwards compatibility
		if val, ok := context[expr]; ok {
			if str, ok := val.(string); ok {
				return str
			}
			if bytes, err := json.Marshal(val); err == nil {
				return string(bytes)
			}
		}
	}

	return "{{" + expr + "}}"
}

// evaluateCUEExpression evaluates complex expressions using CUE
func evaluateCUEExpression(expr string, context map[string]any) string {
	// Convert single quotes to double quotes for CUE compatibility
	cueExpr := strings.ReplaceAll(expr, "'", "\"")

	// First try to evaluate as a simple literal without context
	ctx := cuecontext.New()
	simpleValue := ctx.CompileString(cueExpr)
	if simpleValue.Err() == nil {
		value := ExtractCUEValue(simpleValue)
		if value != nil {
			return convertToString(value)
		}
	}

	// If simple evaluation fails, try with context in a single script
	simpleContext := map[string]any{}
	if vars, ok := context["vars"]; ok {
		simpleContext["vars"] = vars
		// Also add vars at the top level for easier access (e.g., "item" instead of "vars.item")
		if varsMap, ok := vars.(map[string]any); ok {
			for k, v := range varsMap {
				simpleContext[k] = v
			}
		}
	}
	if outputs, ok := context["outputs"]; ok {
		simpleContext["outputs"] = outputs
	}
	if secrets, ok := context["secrets"]; ok {
		simpleContext["secrets"] = secrets
	}
	if event, ok := context["event"]; ok {
		simpleContext["event"] = event
	}

	// Create a single CUE script with data and expression as fields in one object
	cueData := buildCUEData(simpleContext)
	// Remove the closing brace and add result field, then close
	if strings.HasSuffix(cueData, "\n}") {
		cueData = cueData[:len(cueData)-2] + "\tresult: " + cueExpr + "\n}"
	}
	cueValue := ctx.CompileString(cueData)
	if cueValue.Err() != nil {
		return "{{" + expr + "}}"
	}

	resultField := cueValue.LookupPath(cue.ParsePath("result"))
	if resultField.Err() != nil {
		return "{{" + expr + "}}"
	}

	value := ExtractCUEValue(resultField)
	return convertToString(value)
}

// buildCUEData converts context map to CUE syntax
func buildCUEData(data map[string]any) string {
	var result strings.Builder
	buildCUEValue(&result, data, 0)
	return result.String()
}

func buildCUEValue(buf *strings.Builder, val any, indent int) {
	switch v := val.(type) {
	case []map[string]any:
		buf.WriteString("[")
		for i, item := range v {
			if i > 0 {
				buf.WriteString(", ")
			}
			buildCUEValue(buf, item, indent)
		}
		buf.WriteString("]")
	case map[string]string:
		buf.WriteString("{\n")
		indent++
		i := 0
		for k, val := range v {
			if i > 0 {
				buf.WriteString("\n")
			}
			for j := 0; j < indent; j++ {
				buf.WriteString("\t")
			}
			// Always quote env var keys to avoid CUE identifier issues
			buf.WriteString("\"")
			buf.WriteString(k)
			buf.WriteString("\"")
			buf.WriteString(": ")
			buf.WriteString("\"")
			buf.WriteString(val)
			buf.WriteString("\",")
			i++
		}
		buf.WriteString("\n")
		indent--
		for j := 0; j < indent; j++ {
			buf.WriteString("\t")
		}
		buf.WriteString("}")
	case map[string]any:
		buf.WriteString("{\n")
		indent++
		i := 0
		for k, v := range v {
			if i > 0 {
				buf.WriteString("\n")
			}
			for j := 0; j < indent; j++ {
				buf.WriteString("\t")
			}
			// Quote keys that are not valid CUE identifiers
			if isValidCUEIdentifier(k) {
				buf.WriteString(k)
			} else {
				buf.WriteString("\"")
				buf.WriteString(k)
				buf.WriteString("\"")
			}
			buf.WriteString(": ")
			buildCUEValue(buf, v, indent)
			buf.WriteString(",")
			i++
		}
		buf.WriteString("\n")
		indent--
		for j := 0; j < indent; j++ {
			buf.WriteString("\t")
		}
		buf.WriteString("}")
	case []any:
		buf.WriteString("[")
		for i, item := range v {
			if i > 0 {
				buf.WriteString(", ")
			}
			buildCUEValue(buf, item, indent)
		}
		buf.WriteString("]")
	case string:
		buf.WriteString("\"")
		// Escape backslashes first, then quotes
		escaped := strings.ReplaceAll(v, "\\", "\\\\")
		escaped = strings.ReplaceAll(escaped, "\"", "\\\"")
		escaped = strings.ReplaceAll(escaped, "\n", "\\n")
		escaped = strings.ReplaceAll(escaped, "\t", "\\t")
		escaped = strings.ReplaceAll(escaped, "\r", "\\r")
		buf.WriteString(escaped)
		buf.WriteString("\"")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case nil:
		buf.WriteString("null")
	case int, int32, int64, float32, float64:
		buf.WriteString(fmt.Sprintf("%v", v))
	default:
		buf.WriteString(fmt.Sprintf("%v", v))
	}
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
	case float64:
		return fmt.Sprintf("%g", v)
	default:
		// For complex types, use JSON marshaling
		if bytes, err := json.Marshal(val); err == nil {
			return string(bytes)
		}
		return fmt.Sprintf("%v", val)
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

// resolveNestedValue resolves nested map access like obj.field.subfield
func resolveNestedValue(obj any, path []string) string {
	current := obj
	for _, part := range path {
		switch v := current.(type) {
		case map[string]any:
			if val, ok := v[part]; ok {
				current = val
			} else {
				return ""
			}
		case []any:
			if idx, err := strconv.Atoi(part); err == nil && idx >= 0 && idx < len(v) {
				current = v[idx]
			} else {
				return ""
			}
		default:
			return fmt.Sprintf("%v", current)
		}
	}
	return fmt.Sprintf("%v", current)
}
