package dsl

import (
	"encoding/json"
	"os"

	"github.com/awantoch/beemflow/docs"
	"github.com/awantoch/beemflow/model"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

// Parse reads a YAML flow file from the given path and unmarshals it into a Flow struct.
func Parse(path string) (*model.Flow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseFromString(string(data))
}

// ParseFromString unmarshals a YAML string into a Flow struct.
func ParseFromString(yamlStr string) (*model.Flow, error) {
	var flow model.Flow
	if err := yaml.Unmarshal([]byte(yamlStr), &flow); err != nil {
		return nil, err
	}
	return &flow, nil
}

// Validate runs JSON-Schema validation against the embedded BeemFlow schema.
func Validate(flow *model.Flow) error {
	// Marshal the flow to JSON for validation
	jsonBytes, err := json.Marshal(flow)
	if err != nil {
		return err
	}
	// Compile the embedded schema
	schema, err := jsonschema.CompileString("beemflow.schema.json", docs.BeemflowSchema)
	if err != nil {
		return err
	}
	// Unmarshal JSON into a generic interface for validation
	var doc any
	if err := json.Unmarshal(jsonBytes, &doc); err != nil {
		return err
	}
	// Validate the flow
	return schema.Validate(doc)
}

// Load reads, templates, parses, and validates a flow file in one step.
func Load(path string, vars map[string]any) (*model.Flow, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rendered, err := Render(string(raw), vars)
	if err != nil {
		return nil, err
	}
	flow, err := ParseFromString(rendered)
	if err != nil {
		return nil, err
	}
	if err := Validate(flow); err != nil {
		return nil, err
	}
	return flow, nil
}
