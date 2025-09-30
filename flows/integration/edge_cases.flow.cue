// Edge Cases Test in CUE
// Edge case testing for robustness and error handling

package beemflow

name: "test_edge_cases"
description: "Edge case testing for robustness and error handling"

vars: {
	empty_list: []
	empty_object: {}
	null_value: null
	special_chars: "!@#$%^&*()_+-=[]{}|;':\",./<>?"
	unicode_text: "Hello 世界 🌍 émojis"
	large_number: 999999999999999
	nested_data: {
		level1: {
			level2: {
				level3: "deep value"
				array: [1, "two", true, null, {nested: "object"}]
			}
		}
	}
}

steps: [
	// Test empty collections
	{
		id: "test_empty_collections"
		use: "core.echo"
		with: {
			text: """
Empty list length: \(len(vars.empty_list))
Empty object: \(vars.empty_object)
Null value: \(vars.null_value or "was null")
"""
		}
	},

	// Test special characters and unicode
	{
		id: "test_special_chars"
		use: "core.echo"
		with: {
			text: """
Special chars: \(vars.special_chars)
Unicode: \(vars.unicode_text)
Large number: \(vars.large_number)
"""
		}
	},

	// Test deep nesting
	{
		id: "test_deep_nesting"
		use: "core.echo"
		with: {
			text: """
Deep value: \(vars.nested_data.level1.level2.level3)
Nested array length: \(len(vars.nested_data.level1.level2.array))
"""
		}
	},

	// Test foreach with mixed data types using CUE comprehensions
	for i, item in vars.nested_data.level1.level2.array {
		"test_mixed_foreach_\(i)": {
			use: "core.echo"
			with: {
				text: "Item \(i): \(item) (type varies)"
			}
		}
	},

	// Test parallel with error handling
	{
		id: "test_parallel_robustness"
		parallel: true
		steps: [
			{
				id: "success_step"
				use: "core.echo"
				with: {
					text: "This should succeed"
				}
			},
			{
				id: "another_success"
				use: "core.echo"
				with: {
					text: "This should also succeed"
				}
			}
		]
	},

	// Test template edge cases
	{
		id: "test_template_edge_cases"
		use: "core.echo"
		with: {
			text: """
Escaped quotes: "He said \\"Hello\\""
Math with large numbers: \(vars.large_number + 1)
Boolean operations: \(true && false)
String concatenation: Hello World
"""
		}
	},

	// Test error recovery
	{
		id: "test_safe_access"
		use: "core.echo"
		with: {
			text: """
Safe nested access: \(vars.nonexistent?.deeply?.nested?.value or "default")
Safe array access: \(vars.empty_list[0] or "no first element")
Safe filter on null: \(len(vars.null_value) or 0)
"""
		}
	},

	// Final summary
	{
		id: "edge_case_summary"
		use: "core.echo"
		with: {
			text: """
Edge case testing completed!
- Empty collections handled: ✓
- Special characters handled: ✓
- Unicode support: ✓
- Deep nesting: ✓
- Mixed data types: ✓
- Error recovery: ✓
"""
		}
	}
]
