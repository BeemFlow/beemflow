// Truth Seeking Counsel in CUE
// Analyze a claim from multiple perspectives using parallel AI analysis.
// Demonstrates CUE's structural approach to complex workflows.

package beemflow

name: "truth_seeking_counsel"
description: """
Analyze a claim from multiple perspectives using parallel AI analysis. Generate skeptic,
optimist, and analyst viewpoints simultaneously, then synthesize all perspectives into
a balanced, evidence-based conclusion. Demonstrates parallel execution and data flow.
"""

on: "cli.manual"

vars: {
	claim: "The world is a simulation."
	analysis_types: [
		{name: "skeptic", prompt: "Question the claim's assumptions and evidence."},
		{name: "optimist", prompt: "Find positive or constructive angles to the claim."},
		{name: "analyst", prompt: "Provide a data-driven, neutral analysis of the claim."}
	]
}

steps: [
	// Parallel analysis using CUE comprehensions
	for analysis in vars.analysis_types {
		"\(analysis.name)_analysis": {
			use: "openai.chat_completion"
			with: {
				model: "gpt-4o"
				messages: [
					{
						role: "system"
						content: "\(analysis.prompt) Evaluate this claim: \(vars.claim)"
					},
					{
						role: "user"
						content: vars.claim
					}
				]
			}
		}
	},

	// Synthesize responses - using CUE's structural composition
	{
		id: "synthesize"
		use: "openai.chat_completion"
		with: {
			model: "gpt-4o"
			messages: [
				{
					role: "system"
					content: """
Synthesize the following analyses of the claim "\(vars.claim)":
\([
	for analysis in vars.analysis_types {
		"- \(strings.ToTitle(analysis.name)): {{ outputs.\(analysis.name)_analysis.choices.0.message.content }}"
	}
].join("\n"))

Provide a balanced, evidence-based conclusion.
"""
				},
				{
					role: "user"
					content: vars.claim
				}
			]
		}
	},

	// Output the result
	{
		id: "output"
		use: "core.echo"
		with: {
			text: "Truth-Seeking Counsel Conclusion: {{ outputs.synthesize.choices.0.message.content }}"
		}
	}
]
