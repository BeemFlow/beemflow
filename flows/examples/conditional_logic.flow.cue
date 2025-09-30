// Conditional Logic Example in CUE
// Demonstrates how conditionals and complex logic work in CUE
// Instead of embedded string templates, we use CUE's structural composition

package beemflow

name: "conditional_logic_demo"
description: """
Demonstrates conditional logic, loops, and complex expressions in CUE.
This replaces the Django/Jinja2 templating approach with structural CUE.
"""

on: "cli.manual"

vars: {
	user_name: env.USER or "testuser"
	test_object: {
		name: "Test Object"
		values: [1, 2, 3, 4, 5]
		nested: {
			deep_value: "found it"
		}
	}
	should_process: true
}

steps: [
	// Basic templating equivalent
	{
		id: "basic_templating"
		use: "core.echo"
		with: {
			text: "Hello \(vars.user_name), current time is \(#now)"
		}
	},

	// Object access and expressions
	{
		id: "object_templating"
		use: "core.echo"
		with: {
			text: """
Object name: \(vars.test_object.name)
First value: \(vars.test_object.values[0])
Values length: \(len(vars.test_object.values))
Uppercase name: \(strings.ToUpper(vars.test_object.name))
Deep value: \(vars.test_object.nested.deep_value)
"""
		}
	},

	// Conditional logic using CUE's if expressions
	{
		id: "conditional_templating"
		use: "core.echo"
		with: {
			text: [
				if len(vars.test_object.values) > 3 {
					"We have many values: \(strings.Join(vars.test_object.values, ", "))"
				},
				if len(vars.test_object.values) <= 3 {
					"We have few values"
				}
			][0] // Take the first non-empty result
		}
	},

	// Foreach equivalent using CUE comprehensions
	{
		id: "loop_templating"
		use: "core.echo"
		with: {
			text: """
Processing values:
\([ for i, v in vars.test_object.values {
	"- Value \(i): \(v)"
}].join("\n"))
"""
		}
	},

	// Step output referencing
	{
		id: "step_reference_test"
		use: "core.echo"
		with: {
			text: "Previous step said: \(outputs.basic_templating.text)"
		}
	},

	// Complex expressions
	{
		id: "expression_test"
		use: "core.echo"
		with: {
			text: """
Math: \(vars.test_object.values[0] + vars.test_object.values[1])
String ops: \(strings.ToUpper("hello"))
Boolean: \(len(vars.test_object.values) > 0)
"""
		}
	},

	// Environment variable access
	{
		id: "env_test"
		use: "core.echo"
		with: {
			text: """
User: \(#env.USER or "unknown")
Home: \(#env.HOME or "/tmp")
Path exists: \(len(#env.PATH) > 0)
"""
		}
	},

	// Foreach with templated IDs (using CUE comprehensions)
	for i, num in vars.test_object.values {
		"process_number_\(num)": {
			use: "core.echo"
			with: {
				text: "Processing number \(num), squared is \(num * num)"
			}
		}
	},

	// Error handling and safe access
	{
		id: "error_handling_test"
		use: "core.echo"
		with: {
			text: """
Safe access: \(outputs.nonexistent?.field or "default")
Null coalescing: \(outputs.null or "fallback")
Empty string: \((outputs.empty or "") or "not empty")
"""
		}
	}
]
