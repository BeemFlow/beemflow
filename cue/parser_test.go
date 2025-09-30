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

	// Test missing name
	invalidCue := `
steps: [
	{
		id: "test"
		use: "core.echo"
	}
]
`
	_, err := parser.ParseString(invalidCue)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "name")

	// Test missing steps
	invalidCue2 := `
name: "test"
on: "cli.manual"
`
	_, err = parser.ParseString(invalidCue2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "steps")

	// Test missing on
	invalidCue3 := `
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
	assert.Contains(t, err.Error(), "on")
}
