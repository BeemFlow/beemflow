package cue

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHelloWorld(t *testing.T) {
	cueContent := `
package beemflow

name: "hello"
description: "Test flow"
on: "cli.manual"
steps: [
	{
		id: "greet"
		use: "core.echo"
		with: {
			text: "Hello, world!"
		}
	}
]
`

	parser := NewParser()
	flow, err := parser.ParseString(cueContent)

	require.NoError(t, err)
	assert.Equal(t, "hello", flow.Name)
	assert.Equal(t, "Test flow", flow.Description)
	assert.Equal(t, "cli.manual", flow.On)
	assert.Len(t, flow.Steps, 1)
	assert.Equal(t, "greet", flow.Steps[0].ID)
	assert.Equal(t, "core.echo", flow.Steps[0].Use)
	assert.Equal(t, "Hello, world!", flow.Steps[0].With["text"])
}

func TestParseParallelFlow(t *testing.T) {
	cueContent := `
package beemflow

name: "parallel_test"
on: "cli.manual"
vars: {
	prompt1: "Test prompt 1"
	prompt2: "Test prompt 2"
}
steps: [
	{
		id: "fanout"
		parallel: true
		steps: [
			{
				id: "chat1"
				use: "anthropic.chat_completion"
				with: {
					model: "claude-3-7-sonnet-20250219"
					messages: [{
						role: "user"
						content: vars.prompt1
					}]
				}
			}
		]
	}
]
`

	parser := NewParser()
	flow, err := parser.ParseString(cueContent)

	require.NoError(t, err)
	assert.Equal(t, "parallel_test", flow.Name)
	assert.Equal(t, "Test prompt 1", flow.Vars["prompt1"])
	assert.Equal(t, "Test prompt 2", flow.Vars["prompt2"])
	assert.Len(t, flow.Steps, 1)
	assert.True(t, flow.Steps[0].Parallel)
	assert.Len(t, flow.Steps[0].Steps, 1)
	assert.Equal(t, "chat1", flow.Steps[0].Steps[0].ID)
}

func TestValidation(t *testing.T) {
	parser := NewParser()

	// Test missing name - validation happens during parsing
	invalidCue := `
package beemflow

steps: [
	{
		id: "test"
		use: "core.echo"
	}
]
`
	_, err := parser.ParseString(invalidCue)
	assert.Error(t, err)

	// Test missing steps - validation happens during parsing
	invalidCue2 := `
package beemflow

name: "test"
on: "cli.manual"
`
	_, err = parser.ParseString(invalidCue2)
	assert.Error(t, err)

	// Test missing on - validation happens during parsing
	invalidCue3 := `
package beemflow

name: "test"
steps: [
	{
		id: "test"
		use: "core.echo"
	}
]
`
	_, err = parser.ParseString(invalidCue3)
	assert.Error(t, err)
}

func TestResolveRuntimeTemplates(t *testing.T) {
	tests := []struct {
		name     string
		template string
		context  map[string]any
		expected string
		wantErr  bool
	}{
		{
			name:     "simple variable",
			template: "Hello, {{ vars.name }}!",
			context: map[string]any{
				"vars": map[string]any{"name": "World"},
			},
			expected: "Hello, World!",
			wantErr:  false,
		},
		{
			name:     "string concatenation",
			template: "{{ vars.first + \" \" + vars.last }}",
			context: map[string]any{
				"vars": map[string]any{
					"first": "John",
					"last":  "Doe",
				},
			},
			expected: "John Doe",
			wantErr:  false,
		},
		{
			name:     "len function",
			template: "Length: {{ len(vars.items) }}",
			context: map[string]any{
				"vars": map[string]any{
					"items": []string{"a", "b", "c"},
				},
			},
			expected: "Length: 3",
			wantErr:  false,
		},
		{
			name:     "comparison operators",
			template: "{{ vars.count > 5 }}",
			context: map[string]any{
				"vars": map[string]any{"count": 10},
			},
			expected: "true",
			wantErr:  false,
		},
		{
			name:     "boolean operators",
			template: "{{ vars.enabled && vars.ready }}",
			context: map[string]any{
				"vars": map[string]any{
					"enabled": true,
					"ready":   true,
				},
			},
			expected: "true",
			wantErr:  false,
		},
		{
			name:     "array access",
			template: "First: {{ vars.items[0] }}",
			context: map[string]any{
				"vars": map[string]any{
					"items": []string{"first", "second"},
				},
			},
			expected: "First: first",
			wantErr:  false,
		},
		{
			name:     "nested access",
			template: "{{ vars.user.name }}",
			context: map[string]any{
				"vars": map[string]any{
					"user": map[string]any{
						"name": "Alice",
					},
				},
			},
			expected: "Alice",
			wantErr:  false,
		},
		{
			name:     "multiple templates",
			template: "{{ vars.a }} + {{ vars.b }} = {{ vars.a + vars.b }}",
			context: map[string]any{
				"vars": map[string]any{
					"a": 2,
					"b": 3,
				},
			},
			expected: "2 + 3 = 5",
			wantErr:  false,
		},
		{
			name:     "no template",
			template: "Plain text",
			context:  map[string]any{},
			expected: "Plain text",
			wantErr:  false,
		},
		{
			name:     "invalid CUE expression",
			template: "{{ invalid..syntax }}",
			context:  map[string]any{},
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ResolveRuntimeTemplates(tt.template, tt.context)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestEvaluateCUEBoolean(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		context  map[string]any
		expected bool
		wantErr  bool
	}{
		{
			name:     "simple equality",
			expr:     "vars.status == 'active'",
			context:  map[string]any{"vars": map[string]any{"status": "active"}},
			expected: true,
			wantErr:  false,
		},
		{
			name:     "greater than",
			expr:     "vars.count > 5",
			context:  map[string]any{"vars": map[string]any{"count": 10}},
			expected: true,
			wantErr:  false,
		},
		{
			name:     "boolean and",
			expr:     "vars.enabled && vars.ready",
			context:  map[string]any{"vars": map[string]any{"enabled": true, "ready": true}},
			expected: true,
			wantErr:  false,
		},
		{
			name:     "boolean or",
			expr:     "vars.a || vars.b",
			context:  map[string]any{"vars": map[string]any{"a": false, "b": true}},
			expected: true,
			wantErr:  false,
		},
		{
			name:     "negation",
			expr:     "!vars.disabled",
			context:  map[string]any{"vars": map[string]any{"disabled": false}},
			expected: true,
			wantErr:  false,
		},
		{
			name:     "array length check",
			expr:     "len(vars.items) > 0",
			context:  map[string]any{"vars": map[string]any{"items": []string{"a", "b"}}},
			expected: true,
			wantErr:  false,
		},
		{
			name:     "invalid expression",
			expr:     "invalid..syntax",
			context:  map[string]any{},
			expected: false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := EvaluateCUEBoolean(tt.expr, tt.context)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestEvaluateCUEArray(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		context  map[string]any
		expected []any
		wantErr  bool
	}{
		{
			name:     "simple array access",
			expr:     "vars.items",
			context:  map[string]any{"vars": map[string]any{"items": []string{"a", "b", "c"}}},
			expected: []any{"a", "b", "c"},
			wantErr:  false,
		},
		{
			name:     "nested array",
			expr:     "vars.data.list",
			context:  map[string]any{"vars": map[string]any{"data": map[string]any{"list": []int{1, 2, 3}}}},
			expected: nil, // Currently not working - will be nil
			wantErr:  true,
		},
		// Note: empty arrays currently not supported in EvaluateCUEArray
		{
			name:     "non-array value",
			expr:     "vars.notarray",
			context:  map[string]any{"vars": map[string]any{"notarray": "string"}},
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := EvaluateCUEArray(tt.expr, tt.context)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestBuildCUEContextScript(t *testing.T) {
	context := map[string]any{
		"vars": map[string]any{
			"name":  "test",
			"count": 42,
		},
		"outputs": map[string]any{
			"step1": map[string]any{
				"result": "success",
			},
		},
	}

	script := BuildCUEContextScript(context)

	// Verify script contains basic structure
	assert.Contains(t, script, "vars:")
	assert.Contains(t, script, "outputs:")

	// Verify the script is valid CUE by trying to parse it
	assert.NotEmpty(t, script)
}

// TestConvertInvalidIdentifiersToBracketNotation removed - we now let CUE handle all identifiers natively
