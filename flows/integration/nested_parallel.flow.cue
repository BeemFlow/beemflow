// Nested Parallel Test in CUE
// Simple test to debug nested parallel issue

package beemflow

name: "test_nested_parallel"
description: "Simple test to debug nested parallel issue"

vars: {
	items: ["alpha", "beta"]
}

steps: [
	// Test nested parallel within foreach using CUE comprehensions
	for item in vars.items {
		"nested_test_\(item)": {
			parallel: true
			steps: [
				{
					id: "upper_\(item)"
					use: "core.echo"
					with: {
						text: strings.ToUpper(item)
					}
				},
				{
					id: "length_\(item)"
					use: "core.echo"
					with: {
						text: "\(len(item))"
					}
				},
				{
					id: "reverse_\(item)"
					use: "core.echo"
					with: {
						text: strings.Join([for i, _ in item { item[len(item)-1-i] }], "")
					}
				}
			]
		}
	}
]
