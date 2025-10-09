// Truth Seeking Counsel in CUE
// Analyze a claim from multiple perspectives using parallel AI analysis.

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
}

steps: [
	// Parallel analysis
	{
		id: "parallel_analysis"
		parallel: true
		steps: [
			{
				id: "skeptic_analysis"
				use: "openai.chat_completion"
				with: {
					model: "gpt-4o"
					messages: [
						{
							role: "system"
							content: "Question the claim's assumptions and evidence. Evaluate this claim: {{ vars.claim }}"
						},
						{
							role: "user"
							content: "{{ vars.claim }}"
						}
					]
				}
			},
			{
				id: "optimist_analysis"
				use: "openai.chat_completion"
				with: {
					model: "gpt-4o"
					messages: [
						{
							role: "system"
							content: "Find positive or constructive angles to the claim. Evaluate this claim: {{ vars.claim }}"
						},
						{
							role: "user"
							content: "{{ vars.claim }}"
						}
					]
				}
			},
			{
				id: "analyst_analysis"
				use: "openai.chat_completion"
				with: {
					model: "gpt-4o"
					messages: [
						{
							role: "system"
							content: "Provide a data-driven, neutral analysis of the claim. Evaluate this claim: {{ vars.claim }}"
						},
						{
							role: "user"
							content: "{{ vars.claim }}"
						}
					]
				}
			}
		]
	},

	// Synthesize responses
	{
		id: "synthesize"
		use: "openai.chat_completion"
		with: {
			model: "gpt-4o"
			messages: [
				{
					role: "system"
					content: """
Synthesize the following analyses of the claim "{{ vars.claim }}":
- Skeptic: {{ outputs.skeptic_analysis.choices[0].message.content }}
- Optimist: {{ outputs.optimist_analysis.choices[0].message.content }}
- Analyst: {{ outputs.analyst_analysis.choices[0].message.content }}

Provide a balanced, evidence-based conclusion.
"""
				},
				{
					role: "user"
					content: "{{ vars.claim }}"
				}
			]
		}
	},

	// Output the result
	{
		id: "output"
		use: "core.echo"
		with: {
			text: "Truth-Seeking Counsel Conclusion: {{ outputs.synthesize.choices[0].message.content }}"
		}
	}
]