package cue

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/load"
	"github.com/beemflow/beemflow/model"
)

// Embed the schema file at compile time
//
//go:embed schema.cue
var schemaFile string

// Parser handles CUE-based flow parsing and validation
type Parser struct {
	ctx        *cue.Context
	schemaFlow cue.Value // Cached schema #Flow definition
}

// NewParser creates a new CUE parser
func NewParser() *Parser {
	ctx := cuecontext.New()

	// Load and cache the schema at initialization time
	schemaValue := ctx.CompileString(schemaFile, cue.Filename("schema.cue"))
	if schemaValue.Err() != nil {
		// This is a critical error - schema is part of the protocol
		panic(fmt.Sprintf("failed to compile embedded schema: %v", schemaValue.Err()))
	}

	// Extract the #Flow definition
	flowDef := schemaValue.LookupPath(cue.ParsePath("#Flow"))
	if flowDef.Err() != nil {
		panic(fmt.Sprintf("schema missing #Flow definition: %v", flowDef.Err()))
	}

	return &Parser{
		ctx:        ctx,
		schemaFlow: flowDef,
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

// validateSchema checks the CUE value against our schema using CUE's built-in validation
// This is what `cue vet` uses under the hood
func (p *Parser) validateSchema(value cue.Value) error {
	// Use CUE's Unify to merge the value with the schema definition
	// This validates that the value conforms to the schema constraints
	unified := value.Unify(p.schemaFlow)

	// Check if unification succeeded (no conflicts)
	if err := unified.Err(); err != nil {
		return fmt.Errorf("flow does not conform to schema: %w", err)
	}

	// Use CUE's built-in Validate to check the unified value
	// We use Concrete(false) to allow templates ({{ }} expressions) which are incomplete values
	if err := unified.Validate(cue.Concrete(false)); err != nil {
		return fmt.Errorf("schema validation failed: %w", err)
	}

	// Check critical required fields that Concrete(false) allows to be missing
	if err := p.checkCriticalFields(value); err != nil {
		return err
	}

	// Check for duplicate step IDs
	return p.checkDuplicateStepIDs(value)
}

// checkCriticalFields verifies that critical required fields exist
// This is necessary because Concrete(false) allows incomplete values
func (p *Parser) checkCriticalFields(value cue.Value) error {
	if !value.LookupPath(cue.ParsePath("name")).Exists() {
		return fmt.Errorf("flow must have a 'name' field")
	}
	if !value.LookupPath(cue.ParsePath("on")).Exists() {
		return fmt.Errorf("flow must have an 'on' field")
	}
	if !value.LookupPath(cue.ParsePath("steps")).Exists() {
		return fmt.Errorf("flow must have a 'steps' field")
	}
	return nil
}

// checkDuplicateStepIDs validates that step IDs are unique within a flow
func (p *Parser) checkDuplicateStepIDs(value cue.Value) error {
	stepsVal := value.LookupPath(cue.ParsePath("steps"))
	if stepsVal.Err() != nil {
		return nil // Schema validation already handled this
	}

	stepsIter, err := stepsVal.List()
	if err != nil {
		return nil // Schema validation already handled this
	}

	stepIDs := make(map[string]bool)
	for stepsIter.Next() {
		stepVal := stepsIter.Value()
		idVal := stepVal.LookupPath(cue.ParsePath("id"))
		if idVal.Err() == nil {
			if stepID, err := idVal.String(); err == nil {
				if stepIDs[stepID] {
					return fmt.Errorf("duplicate step ID '%s'", stepID)
				}
				stepIDs[stepID] = true
			}
		}
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

// ResolveRuntimeTemplates resolves {{ }} template expressions in a string using CUE evaluation
func ResolveRuntimeTemplates(template string, context map[string]any) (string, error) {
	if !strings.Contains(template, "{{") {
		return template, nil
	}

	// Build CUE context script once and create context once for efficiency
	contextScript := BuildCUEContextScript(context)
	ctx := cuecontext.New()

	// Use a strings.Builder for efficient string building
	var result strings.Builder
	lastEnd := 0

	for {
		start := strings.Index(template[lastEnd:], "{{")
		if start == -1 {
			// No more templates found, append remaining text
			result.WriteString(template[lastEnd:])
			break
		}
		start += lastEnd

		end := strings.Index(template[start:], "}}")
		if end == -1 {
			// Malformed template, return error with more specific context
			remaining := template[start:]
			if len(remaining) > 50 {
				remaining = remaining[:50] + "..."
			}
			return "", fmt.Errorf("malformed template: missing closing }} in %q (starting at position %d)", remaining, start)
		}
		end += start + 2

		// Append text before this template
		result.WriteString(template[lastEnd:start])

		// Extract the expression inside {{ }}
		expr := template[start+2 : end-2]
		expr = strings.TrimSpace(expr)

		// Handle empty expressions - return error instead of silent conversion
		if expr == "" {
			// Limit template preview in error message to avoid log pollution
			templatePreview := template
			if len(template) > 100 {
				templatePreview = template[:50] + "..." + template[len(template)-47:]
			}
			return "", fmt.Errorf("empty template expression {{ }} found at position %d-%d in template: %q", start, end, templatePreview)
		}

		// Note: We let CUE handle all expression parsing natively

		// Add conditional imports based on what's in the expression
		imports := buildImportsForExpression(expr)

		// Evaluate the expression using the pre-built context
		cueScript := imports + contextScript + "\nresult: " + expr
		cueValue := ctx.CompileString(cueScript)

		if cueValue.Err() != nil {
			return "", fmt.Errorf("CUE compilation error in template %q: %w", expr, cueValue.Err())
		}

		resultField := cueValue.LookupPath(cue.ParsePath("result"))
		if resultField.Err() != nil {
			return "", fmt.Errorf("CUE evaluation error in template %q: %w", expr, resultField.Err())
		}

		value := ExtractCUEValue(resultField)
		replacement := convertToString(value)

		// Append the replacement
		result.WriteString(replacement)

		// Move past this template
		lastEnd = end
	}

	return result.String(), nil
}

// buildImportsForExpression adds CUE package imports if referenced in the expression
func buildImportsForExpression(expr string) string {
	var imports strings.Builder

	if strings.Contains(expr, "strings.") {
		imports.WriteString("import \"strings\"\n")
	}
	if strings.Contains(expr, "math.") {
		imports.WriteString("import \"math\"\n")
	}
	if strings.Contains(expr, "list.") {
		imports.WriteString("import \"list\"\n")
	}
	if strings.Contains(expr, "encoding/json.") {
		imports.WriteString("import \"encoding/json\"\n")
	}

	if imports.Len() > 0 {
		return imports.String() + "\n"
	}
	return ""
}

// EvaluateCUEArray evaluates a CUE expression and returns it as a Go []any
func EvaluateCUEArray(expr string, context map[string]any) ([]any, error) {
	// Validate input
	if expr == "" {
		return nil, fmt.Errorf("empty array expression")
	}

	// Trim and validate expression structure
	trimmedExpr := strings.TrimSpace(expr)
	if trimmedExpr == "" {
		return nil, fmt.Errorf("array expression is empty after trimming whitespace")
	}

	contextScript := BuildCUEContextScript(context)
	imports := buildImportsForExpression(trimmedExpr)

	cueScript := imports + contextScript + "\nresult: " + normalizeSingleQuotes(trimmedExpr)

	ctx := cuecontext.New()
	cueValue := ctx.CompileString(cueScript)
	if cueValue.Err() != nil {
		return nil, fmt.Errorf("CUE compilation error in array expression %q: %w", trimmedExpr, cueValue.Err())
	}

	resultField := cueValue.LookupPath(cue.ParsePath("result"))
	if resultField.Err() != nil {
		return nil, fmt.Errorf("CUE evaluation error in array expression %q: %w", trimmedExpr, resultField.Err())
	}

	// Check if the result is incomplete or has errors
	if !resultField.IsConcrete() {
		return nil, fmt.Errorf("expression %q evaluates to an incomplete value (contains unresolved references)", trimmedExpr)
	}

	result := ExtractCUEValue(resultField)

	// Handle nil result
	if result == nil {
		return nil, fmt.Errorf("expression %q evaluates to null, expected array", trimmedExpr)
	}

	// Check if it's an array
	if arr, ok := result.([]any); ok {
		return arr, nil
	}

	return nil, fmt.Errorf("expression %q does not evaluate to an array: got %T", trimmedExpr, result)
}

// EvaluateCUEBoolean evaluates a CUE expression and returns a boolean result
func EvaluateCUEBoolean(expr string, context map[string]any) (bool, error) {
	contextScript := BuildCUEContextScript(context)
	imports := buildImportsForExpression(expr)

	cueScript := imports + contextScript + "\nresult: " + normalizeSingleQuotes(expr)

	ctx := cuecontext.New()
	cueValue := ctx.CompileString(cueScript)
	if cueValue.Err() != nil {
		return false, fmt.Errorf("CUE compilation error: %w", cueValue.Err())
	}

	resultField := cueValue.LookupPath(cue.ParsePath("result"))
	if resultField.Err() != nil {
		return false, fmt.Errorf("CUE evaluation error: %w", resultField.Err())
	}

	result := ExtractCUEValue(resultField)
	if b, ok := result.(bool); ok {
		return b, nil
	}

	// Handle truthiness for non-boolean values
	// nil (null in CUE) is falsy, but undefined variables should have caused evaluation errors

	switch v := result.(type) {
	case int:
		return v != 0, nil
	case int64:
		return v != 0, nil
	case float64:
		return v != 0, nil
	case string:
		return v != "", nil
	case []any:
		return len(v) > 0, nil
	case map[string]any:
		return len(v) > 0, nil
	case nil:
		return false, nil
	default:
		return false, fmt.Errorf("expression does not evaluate to a boolean or truthy value: %T", result)
	}
}

// BuildCUEContextScript creates a CUE script string from a context map
func BuildCUEContextScript(context map[string]any) string {
	var buf strings.Builder

	// Note: We don't import CUE packages here because they must be imported
	// per-expression only when needed. Instead, we make them available via
	// conditional imports in the evaluation functions.

	// Template context data
	buf.WriteString("// Runtime context\n")

	// Separate valid and invalid identifiers
	validKeys := make(map[string]any)
	quotedKeys := make(map[string]any)

	for key, value := range context {
		if isValidCUEKey(key) {
			validKeys[key] = value
		} else {
			quotedKeys[key] = value
		}
	}

	// Write valid keys first
	for key, value := range validKeys {
		buf.WriteString(key)
		buf.WriteString(": ")
		writeCUEValue(&buf, value)
		buf.WriteString("\n")
	}

	// Write quoted keys in a sub-object if any exist
	if len(quotedKeys) > 0 {
		buf.WriteString("quoted: {\n")
		for key, value := range quotedKeys {
			buf.WriteByte('"')
			// Escape quotes in key
			escapedKey := strings.ReplaceAll(key, `"`, `\"`)
			buf.WriteString(escapedKey)
			buf.WriteByte('"')
			buf.WriteString(": ")
			writeCUEValue(&buf, value)
			buf.WriteString("\n")
		}
		buf.WriteString("}\n")
	}

	return buf.String()
}

// writeCUEValue writes a Go value as CUE literal to a string builder
func writeCUEValue(buf *strings.Builder, value any) {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		fmt.Fprintf(buf, "%v", v)
	case string:
		buf.WriteString("\"")
		escaped := strings.ReplaceAll(v, "\\", "\\\\")
		escaped = strings.ReplaceAll(escaped, "\"", "\\\"")
		escaped = strings.ReplaceAll(escaped, "\n", "\\n")
		escaped = strings.ReplaceAll(escaped, "\r", "\\r")
		escaped = strings.ReplaceAll(escaped, "\t", "\\t")
		escaped = strings.ReplaceAll(escaped, "\f", "\\f")
		escaped = strings.ReplaceAll(escaped, "\b", "\\b")
		escaped = strings.ReplaceAll(escaped, "\v", "\\v")
		buf.WriteString(escaped)
		buf.WriteString("\"")
	case []any:
		buf.WriteString("[")
		for i, item := range v {
			if i > 0 {
				buf.WriteString(", ")
			}
			writeCUEValue(buf, item)
		}
		buf.WriteString("]")
	case []map[string]any:
		buf.WriteString("[")
		for i, item := range v {
			if i > 0 {
				buf.WriteString(", ")
			}
			writeCUEValue(buf, item)
		}
		buf.WriteString("]")
	case []string:
		buf.WriteString("[")
		for i, item := range v {
			if i > 0 {
				buf.WriteString(", ")
			}
			writeCUEValue(buf, item)
		}
		buf.WriteString("]")
	case map[string]any:
		buf.WriteString("{")
		first := true
		for k, val := range v {
			if !first {
				buf.WriteString(", ")
			}
			first = false

			// Always quote keys to handle invalid identifiers
			if isValidCUEKey(k) {
				buf.WriteString(k)
			} else {
				buf.WriteByte('"')
				// Escape quotes in key
				escapedKey := strings.ReplaceAll(k, `"`, `\"`)
				buf.WriteString(escapedKey)
				buf.WriteByte('"')
			}
			buf.WriteString(": ")
			writeCUEValue(buf, val)
		}
		buf.WriteString("}")
	default:
		// For unknown types, convert to string
		buf.WriteString("\"")
		buf.WriteString(strings.ReplaceAll(fmt.Sprintf("%v", v), "\"", "\\\""))
		buf.WriteString("\"")
	}
}

// normalizeSingleQuotes converts single quotes to double quotes for CUE compatibility
func normalizeSingleQuotes(expr string) string {
	// Convert single quotes to double quotes to avoid CUE treating them as bytes
	return strings.ReplaceAll(expr, "'", "\"")
}

// isValidCUEKey checks if a string is a valid CUE map key
func isValidCUEKey(s string) bool {
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "__") {
		return false // Filter reserved double-underscore
	}
	first := s[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '_') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

// ExtractCUEValue extracts a Go value from a CUE value
func ExtractCUEValue(val cue.Value) any {
	// Try as string first
	if str, err := val.String(); err == nil {
		return str
	}

	// Try as int
	if i, err := val.Int64(); err == nil {
		return int(i)
	}

	// Try as float
	if f, err := val.Float64(); err == nil {
		return f
	}

	// Try as bool
	if b, err := val.Bool(); err == nil {
		return b
	}

	// Try as list
	if iter, err := val.List(); err == nil {
		var arr []any
		for iter.Next() {
			arr = append(arr, ExtractCUEValue(iter.Value()))
		}
		return arr
	}

	// Try as struct
	if fields, err := val.Fields(); err == nil {
		m := make(map[string]any)
		for fields.Next() {
			label := fields.Label()
			if isValidCUEKey(label) {
				m[label] = ExtractCUEValue(fields.Value())
			}
		}
		return m
	}

	// Default to nil
	return nil
}

// convertToString converts a value to string representation
func convertToString(value any) string {
	if value == nil {
		return ""
	}
	if s, ok := value.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", value)
}
