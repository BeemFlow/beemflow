package graph

import (
	"strings"
	"testing"

	"github.com/beemflow/beemflow/model"
)

func TestExportMermaid_EmptyFlow(t *testing.T) {
	f := &model.Flow{Name: "f"}
	s, err := ExportMermaid(f)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if s != "" {
		t.Errorf("expected empty string, got %q", s)
	}
}

func TestExportMermaid_RealFlow(t *testing.T) {
	f := &model.Flow{
		Name: "tweet_to_instagram",
		Steps: []model.Step{
			{ID: "fetch_tweet", Use: "twitter.tweet.get"},
			{ID: "rewrite", Use: "agent.llm.rewrite"},
			{ID: "post_instagram", Use: "instagram.media.create"},
		},
	}
	s, err := ExportMermaid(f)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if s == "" {
		t.Errorf("expected non-empty string")
	}
	if !strings.Contains(s, "fetch_tweet") || !strings.Contains(s, "rewrite") || !strings.Contains(s, "post_instagram") {
		t.Errorf("output missing step names: %q", s)
	}
}

func TestNewGraphSequential(t *testing.T) {
	f := &model.Flow{
		Name: "seq_flow",
		Steps: []model.Step{
			{ID: "a"},
			{ID: "b"},
			{ID: "c"},
		},
	}
	g := NewGraph(f)
	if len(g.Nodes) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(g.Nodes))
	}
	if len(g.Edges) != 2 {
		t.Errorf("expected 2 edges, got %d", len(g.Edges))
	}
	if g.Edges[0].From != "a" || g.Edges[0].To != "b" {
		t.Errorf("expected edge a->b, got %s->%s", g.Edges[0].From, g.Edges[0].To)
	}
	if g.Edges[1].From != "b" || g.Edges[1].To != "c" {
		t.Errorf("expected edge b->c, got %s->%s", g.Edges[1].From, g.Edges[1].To)
	}
}

func TestNewGraphDependsOn(t *testing.T) {
	f := &model.Flow{
		Name: "dep_flow",
		Steps: []model.Step{
			{ID: "first"},
			{ID: "second", DependsOn: []string{"first"}},
		},
	}
	g := NewGraph(f)
	if len(g.Edges) != 1 {
		t.Errorf("expected 1 edge, got %d", len(g.Edges))
	}
	e := g.Edges[0]
	if e.From != "first" || e.To != "second" {
		t.Errorf("expected edge first->second, got %s->%s", e.From, e.To)
	}
}
