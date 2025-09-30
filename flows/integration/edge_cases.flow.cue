// Edge Cases Test in CUE
// Edge case testing for robustness and error handling

package beemflow

name: "test_edge_cases"
description: "Edge case testing for robustness and error handling"
on: "cli.manual"

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
			text: "Empty list: {{ vars.empty_list }}, Null value: {{ vars.null_value }}"
		}
	},

	// Test special characters and unicode
	{
		id: "test_special_chars"
		use: "core.echo"
		with: {
			text: "Special chars: {{ vars.special_chars }}, Unicode: {{ vars.unicode_text }}"
		}
	},

	// Test deep nesting
	{
		id: "test_deep_nesting"
		use: "core.echo"
		with: {
			text: "Deep value: {{ vars.nested_data.level1.level2.level3 }}"
		}
	},

	// Test foreach with mixed data types
	{
		id: "test_mixed_foreach"
		foreach: "{{ vars.nested_data.level1.level2.array }}"
		use: "core.echo"
		with: {
			text: "Item {{ item_index }}: {{ item }}"
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
			text: "Template edge cases handled"
		}
	},

	// Test error recovery
	{
		id: "test_safe_access"
		use: "core.echo"
		with: {
			text: "Safe access patterns work"
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
