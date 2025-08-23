package graph

import (
	"fmt"
	"strings"

	"github.com/beemflow/beemflow/model"
)

// Node is a vertex in the graph.
type Node struct {
	ID    string
	Label string
}

// Edge is a directed connection between two nodes.
type Edge struct {
	From  string
	To    string
	Label string
}

// Graph is a directed graph composed of nodes and edges.
type Graph struct {
	Nodes []*Node
	Edges []*Edge
}

// Renderer renders a Graph into a specific output format.
type Renderer interface {
	Render(g *Graph) (string, error)
}

// MermaidRenderer outputs Graphs in Mermaid flowchart syntax.
type MermaidRenderer struct{}

// NewGraph creates a Graph representation of the given Flow.
func NewGraph(flow *model.Flow) *Graph {
	g := &Graph{}
	if flow == nil || len(flow.Steps) == 0 {
		return g
	}

	g.processSteps(flow.Steps, "")
	return g
}

// processSteps recursively processes steps and their nested parallel steps
func (g *Graph) processSteps(steps []model.Step, parentID string) {
	for i, step := range steps {
		// Create node
		g.Nodes = append(g.Nodes, &Node{ID: step.ID, Label: step.ID})

		// Handle parallel steps by recursing into nested steps
		if step.Parallel && len(step.Steps) > 0 {
			g.processSteps(step.Steps, step.ID)
			continue
		}

		// Determine dependencies
		var deps []string
		switch {
		case len(step.DependsOn) > 0:
			deps = step.DependsOn
		case parentID != "":
			// If we're in a parallel block, depend on the parent
			deps = []string{parentID}
		case i > 0:
			// Sequential dependency on previous step
			deps = []string{steps[i-1].ID}
		}

		// Create edges
		for _, dep := range deps {
			g.Edges = append(g.Edges, &Edge{From: dep, To: step.ID})
		}
	}
}

// Render renders the graph using Mermaid syntax.
func (r *MermaidRenderer) Render(g *Graph) (string, error) {
	if len(g.Nodes) == 0 {
		return "", nil
	}
	var sb strings.Builder
	sb.WriteString("graph TD\n")
	// Output node definitions
	for _, node := range g.Nodes {
		sb.WriteString(fmt.Sprintf("%s[%s]\n", node.ID, node.Label))
	}
	// Output edges
	for _, edge := range g.Edges {
		if edge.Label != "" {
			sb.WriteString(fmt.Sprintf("%s -->|%s| %s\n", edge.From, edge.Label, edge.To))
		} else {
			sb.WriteString(fmt.Sprintf("%s --> %s\n", edge.From, edge.To))
		}
	}
	return sb.String(), nil
}

// ExportMermaid is a helper to create a Mermaid diagram from a Flow.
func ExportMermaid(flow *model.Flow) (string, error) {
	g := NewGraph(flow)
	renderer := &MermaidRenderer{}
	return renderer.Render(g)
}
