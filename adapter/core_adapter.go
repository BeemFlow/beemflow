package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/beemflow/beemflow/constants"
	"github.com/beemflow/beemflow/registry"
	"github.com/beemflow/beemflow/utils"
)

// CoreAdapter handles built-in BeemFlow utilities and debugging tools.
type CoreAdapter struct{}

// ID returns the adapter ID.
func (a *CoreAdapter) ID() string {
	return constants.AdapterCore
}

// Execute handles various core BeemFlow tools based on the __use field.
func (a *CoreAdapter) Execute(ctx context.Context, inputs map[string]any) (map[string]any, error) {
	use, ok := inputs["__use"].(string)
	if !ok {
		return nil, fmt.Errorf("missing __use for CoreAdapter")
	}

	switch use {
	case constants.CoreEcho:
		return a.executeEcho(ctx, inputs)
	case constants.CoreConvertOpenAPI:
		return a.executeConvertOpenAPI(ctx, inputs)
	case constants.CoreConvertN8N:
		return a.executeConvertN8N(ctx, inputs)
	default:
		return nil, fmt.Errorf("unknown core tool: %s", use)
	}
}

// executeEcho prints the 'text' field to stdout and returns inputs unchanged.
func (a *CoreAdapter) executeEcho(ctx context.Context, inputs map[string]any) (map[string]any, error) {
	_ = ctx // Context not needed for this operation
	if text, ok := inputs["text"].(string); ok {
		if os.Getenv(constants.EnvDebug) != "" {
			utils.Info("%s", text)
		}
	}

	// Return inputs but filter out internal fields like __use
	result := make(map[string]any)
	for k, v := range inputs {
		if k != "__use" {
			result[k] = v
		}
	}

	return result, nil
}

// executeConvertOpenAPI converts OpenAPI specs to BeemFlow tool manifests.
func (a *CoreAdapter) executeConvertOpenAPI(ctx context.Context, inputs map[string]any) (map[string]any, error) {
	_ = ctx // Context not needed for this operation
	// Get required inputs - can be either a JSON string or an object
	var spec map[string]any
	if openapiStr, ok := inputs["openapi"].(string); ok {
		// Parse JSON string
		if err := json.Unmarshal([]byte(openapiStr), &spec); err != nil {
			return nil, fmt.Errorf("invalid OpenAPI JSON: %w", err)
		}
	} else if openapiObj, ok := inputs["openapi"].(map[string]any); ok {
		// Use object directly
		spec = openapiObj
	} else {
		return nil, fmt.Errorf("missing required field: openapi (must be JSON string or object)")
	}

	// Get optional inputs with defaults
	apiName, _ := inputs["api_name"].(string)
	if apiName == "" {
		apiName = constants.DefaultAPIName
	}

	baseURL, _ := inputs["base_url"].(string)

	// Extract base URL from spec if not provided
	if baseURL == "" {
		if servers, ok := spec["servers"].([]any); ok && len(servers) > 0 {
			if server, ok := servers[0].(map[string]any); ok {
				if url, ok := server["url"].(string); ok {
					baseURL = url
				}
			}
		}
		if baseURL == "" {
			baseURL = constants.DefaultBaseURL
		}
	}

	// Convert OpenAPI paths to BeemFlow tool manifests
	manifests, err := a.convertOpenAPIToManifests(spec, apiName, baseURL)
	if err != nil {
		return nil, fmt.Errorf("conversion failed: %w", err)
	}

	// Return the converted manifests
	return map[string]any{
		"manifests": manifests,
		"count":     len(manifests),
		"api_name":  apiName,
		"base_url":  baseURL,
	}, nil
}

// convertOpenAPIToManifests converts OpenAPI spec to BeemFlow tool manifests
func (a *CoreAdapter) convertOpenAPIToManifests(spec map[string]any, apiName, baseURL string) ([]map[string]any, error) {
	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("no paths found in OpenAPI spec")
	}

	var manifests []map[string]any

	for path, pathItem := range paths {
		pathObj, ok := pathItem.(map[string]any)
		if !ok {
			continue
		}

		// Process each HTTP method
		for method, operation := range pathObj {
			if !a.isValidHTTPMethod(method) {
				continue
			}

			opObj, ok := operation.(map[string]any)
			if !ok {
				continue
			}

			// Generate tool name
			toolName := a.generateToolName(apiName, path, method)

			// Extract description
			description := a.extractDescription(opObj, path)

			// Extract parameters schema
			parameters := a.extractParameters(opObj, method)

			// Create manifest
			manifest := map[string]any{
				"name":        toolName,
				"description": description,
				"kind":        "task",
				"parameters":  parameters,
				"endpoint":    baseURL + path,
				"method":      strings.ToUpper(method),
				"headers": map[string]string{
					constants.HeaderContentType:   a.determineContentType(opObj, method),
					constants.HeaderAuthorization: "Bearer $env:" + strings.ToUpper(apiName) + "_API_KEY",
				},
			}

			manifests = append(manifests, manifest)
		}
	}

	return manifests, nil
}

// executeConvertN8N converts n8n workflows to BeemFlow flows.
func (a *CoreAdapter) executeConvertN8N(ctx context.Context, inputs map[string]any) (map[string]any, error) {
	_ = ctx // Context not needed for this operation
	// Get required inputs - can be either a JSON string or an object
	var workflow map[string]any
	if n8nStr, ok := inputs["n8n"].(string); ok {
		// Parse JSON string
		if err := json.Unmarshal([]byte(n8nStr), &workflow); err != nil {
			return nil, fmt.Errorf("invalid n8n JSON: %w", err)
		}
	} else if n8nObj, ok := inputs["n8n"].(map[string]any); ok {
		// Use object directly
		workflow = n8nObj
	} else {
		return nil, fmt.Errorf("missing required field: n8n (must be JSON string or object)")
	}

	// Get optional inputs with defaults
	flowName, _ := inputs["flow_name"].(string)
	if flowName == "" {
		flowName = "converted_n8n_workflow"
	}

	// Convert n8n workflow to BeemFlow flow
	flow, err := a.convertN8NToBeemFlow(workflow, flowName)
	if err != nil {
		return nil, fmt.Errorf("conversion failed: %w", err)
	}

	// Return the converted flow
	return map[string]any{
		"flow":      flow,
		"flow_name": flowName,
	}, nil
}

// convertN8NToBeemFlow converts n8n workflow to BeemFlow flow
func (a *CoreAdapter) convertN8NToBeemFlow(workflow map[string]any, flowName string) (map[string]any, error) {
	// Extract nodes from n8n workflow
	nodes, ok := workflow["nodes"].([]any)
	if !ok {
		return nil, fmt.Errorf("no nodes found in n8n workflow")
	}

	// Extract connections
	connections, _ := workflow["connections"].(map[string]any)

	// Convert nodes to BeemFlow steps
	steps, err := a.convertN8NNodesToSteps(nodes, connections)
	if err != nil {
		return nil, fmt.Errorf("failed to convert nodes: %w", err)
	}

	// Create BeemFlow flow
	flow := map[string]any{
		"name":  flowName,
		"on":    "cli.manual", // Default trigger
		"steps": steps,
	}

	// Add variables if any
	if vars := a.extractN8NVariables(workflow); len(vars) > 0 {
		flow["vars"] = vars
	}

	return flow, nil
}

// convertN8NNodesToSteps converts n8n nodes to BeemFlow steps
func (a *CoreAdapter) convertN8NNodesToSteps(nodes []any, connections map[string]any) ([]map[string]any, error) {
	var steps []map[string]any
	nodeMap := make(map[string]map[string]any)

	// First pass: create a map of node ID to node data
	for _, node := range nodes {
		if nodeObj, ok := node.(map[string]any); ok {
			if id, ok := nodeObj["id"].(string); ok {
				nodeMap[id] = nodeObj
			}
		}
	}

	// Second pass: convert nodes to steps
	for _, node := range nodes {
		if nodeObj, ok := node.(map[string]any); ok {
			step, err := a.convertN8NNodeToStep(nodeObj, connections, nodeMap)
			if err != nil {
				return nil, fmt.Errorf("failed to convert node %v: %w", nodeObj["id"], err)
			}
			if step != nil {
				steps = append(steps, step)
			}
		}
	}

	return steps, nil
}

// convertN8NNodeToStep converts a single n8n node to a BeemFlow step
func (a *CoreAdapter) convertN8NNodeToStep(node map[string]any, connections map[string]any, nodeMap map[string]map[string]any) (map[string]any, error) {
	id, ok := node["id"].(string)
	if !ok {
		return nil, fmt.Errorf("node missing id")
	}

	// Extract node type and parameters
	nodeType, _ := node["type"].(string)
	parameters, _ := node["parameters"].(map[string]any)

	// Create base step
	step := map[string]any{
		"id": id,
	}

	// Convert based on node type
	switch nodeType {
	case "n8n-nodes-base.httpRequest":
		return a.convertHTTPRequestNode(step, parameters)
	case "n8n-nodes-base.openAi":
		return a.convertOpenAINode(step, parameters)
	case "n8n-nodes-base.if":
		return a.convertIfNode(step, parameters, connections, nodeMap)
	case "n8n-nodes-base.wait":
		return a.convertWaitNode(step, parameters)
	case "n8n-nodes-base.set":
		return a.convertSetNode(step, parameters)
	case "n8n-nodes-base.code":
		return a.convertCodeNode(step, parameters)
	default:
		// For unknown node types, create a generic HTTP step
		return a.convertGenericNode(step, nodeType, parameters)
	}
}

// convertHTTPRequestNode converts n8n HTTP request node to BeemFlow HTTP step
func (a *CoreAdapter) convertHTTPRequestNode(step map[string]any, parameters map[string]any) (map[string]any, error) {
	if parameters == nil {
		parameters = make(map[string]any)
	}

	// Extract HTTP parameters
	method, _ := parameters["method"].(string)
	if method == "" {
		method = "GET"
	}

	url, _ := parameters["url"].(string)
	if url == "" {
		return nil, fmt.Errorf("HTTP request node missing URL")
	}

	// Create HTTP step
	step["use"] = "http"
	step["with"] = map[string]any{
		"url":    url,
		"method": strings.ToUpper(method),
	}

	// Add headers if present
	if headers, ok := parameters["headers"].(map[string]any); ok && len(headers) > 0 {
		step["with"].(map[string]any)["headers"] = headers
	}

	// Add body if present
	if body, ok := parameters["body"].(string); ok && body != "" {
		step["with"].(map[string]any)["body"] = body
	}

	return step, nil
}

// convertOpenAINode converts n8n OpenAI node to BeemFlow OpenAI step
func (a *CoreAdapter) convertOpenAINode(step map[string]any, parameters map[string]any) (map[string]any, error) {
	if parameters == nil {
		parameters = make(map[string]any)
	}

	// Extract OpenAI parameters
	model, _ := parameters["model"].(string)
	if model == "" {
		model = "gpt-4o"
	}

	// Handle different message formats
	var messages []map[string]any
	
	// Check for messages structure (newer format)
	if messagesObj, ok := parameters["messages"].(map[string]any); ok {
		if messageValues, ok := messagesObj["messageValues"].([]any); ok {
			for _, msg := range messageValues {
				if msgMap, ok := msg.(map[string]any); ok {
					role, _ := msgMap["role"].(string)
					content, _ := msgMap["content"].(string)
					if role != "" && content != "" {
						messages = append(messages, map[string]any{
							"role":    role,
							"content": content,
						})
					}
				}
			}
		}
	}
	
	// Fallback to simple prompt if no messages found
	if len(messages) == 0 {
		if prompt, ok := parameters["prompt"].(string); ok && prompt != "" {
			messages = []map[string]any{
				{
					"role":    "user",
					"content": prompt,
				},
			}
		} else {
			return nil, fmt.Errorf("OpenAI node missing messages or prompt")
		}
	}

	// Create OpenAI step
	step["use"] = "openai.chat_completion"
	step["with"] = map[string]any{
		"model":    model,
		"messages": messages,
	}

	return step, nil
}

// convertIfNode converts n8n IF node to BeemFlow conditional step
func (a *CoreAdapter) convertIfNode(step map[string]any, parameters map[string]any, connections map[string]any, nodeMap map[string]map[string]any) (map[string]any, error) {
	if parameters == nil {
		parameters = make(map[string]any)
	}

	// Extract condition
	condition, _ := parameters["conditions"].(map[string]any)
	if condition == nil {
		return nil, fmt.Errorf("IF node missing conditions")
	}

	// Create conditional step
	step["if"] = a.buildConditionExpression(condition)

	return step, nil
}

// convertWaitNode converts n8n WAIT node to BeemFlow wait step
func (a *CoreAdapter) convertWaitNode(step map[string]any, parameters map[string]any) (map[string]any, error) {
	if parameters == nil {
		parameters = make(map[string]any)
	}

	// Extract wait parameters
	waitType, _ := parameters["waitType"].(string)
	
	switch waitType {
	case "seconds":
		seconds, _ := parameters["seconds"].(float64)
		step["wait"] = map[string]any{
			"seconds": int(seconds),
		}
	case "until":
		until, _ := parameters["until"].(string)
		step["wait"] = map[string]any{
			"until": until,
		}
	default:
		// Default to 1 second wait
		step["wait"] = map[string]any{
			"seconds": 1,
		}
	}

	return step, nil
}

// convertSetNode converts n8n SET node to BeemFlow variable assignment
func (a *CoreAdapter) convertSetNode(step map[string]any, parameters map[string]any) (map[string]any, error) {
	if parameters == nil {
		parameters = make(map[string]any)
	}

	// Extract set parameters
	values, ok := parameters["values"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("SET node missing values")
	}

	// Create a simple echo step that sets variables
	step["use"] = "core.echo"
	step["with"] = map[string]any{
		"text": fmt.Sprintf("Set variables: %v", values),
	}

	return step, nil
}

// convertCodeNode converts n8n CODE node to BeemFlow step
func (a *CoreAdapter) convertCodeNode(step map[string]any, parameters map[string]any) (map[string]any, error) {
	if parameters == nil {
		parameters = make(map[string]any)
	}

	// Extract code
	code, _ := parameters["code"].(string)
	if code == "" {
		return nil, fmt.Errorf("CODE node missing code")
	}

	// Create a simple echo step (code execution would need custom adapter)
	step["use"] = "core.echo"
	step["with"] = map[string]any{
		"text": fmt.Sprintf("Code execution: %s", code),
	}

	return step, nil
}

// convertGenericNode converts unknown n8n node types to generic HTTP step
func (a *CoreAdapter) convertGenericNode(step map[string]any, nodeType string, parameters map[string]any) (map[string]any, error) {
	// Create a generic echo step for unknown node types
	step["use"] = "core.echo"
	step["with"] = map[string]any{
		"text": fmt.Sprintf("Unsupported n8n node type: %s with parameters: %v", nodeType, parameters),
	}

	return step, nil
}

// buildConditionExpression builds a BeemFlow condition expression from n8n conditions
func (a *CoreAdapter) buildConditionExpression(condition map[string]any) string {
	// Simple condition building - can be enhanced for complex conditions
	if conditions, ok := condition["conditions"].([]any); ok && len(conditions) > 0 {
		if firstCondition, ok := conditions[0].(map[string]any); ok {
			leftValue, _ := firstCondition["leftValue"].(string)
			operator, _ := firstCondition["operator"].(string)
			rightValue, _ := firstCondition["rightValue"].(string)
			
			if leftValue != "" && operator != "" && rightValue != "" {
				return fmt.Sprintf("{{ %s %s %s }}", leftValue, operator, rightValue)
			}
		}
	}
	
	return "true" // Default condition
}

// extractN8NVariables extracts variables from n8n workflow
func (a *CoreAdapter) extractN8NVariables(workflow map[string]any) map[string]any {
	// Look for variables in the workflow
	if settings, ok := workflow["settings"].(map[string]any); ok {
		if variables, ok := settings["variables"].(map[string]any); ok {
			return variables
		}
	}
	
	return make(map[string]any)
}

// Helper functions for OpenAPI conversion

func (a *CoreAdapter) isValidHTTPMethod(method string) bool {
	validMethods := map[string]bool{
		"get": true, "post": true, "put": true, "patch": true, "delete": true,
	}
	return validMethods[strings.ToLower(method)]
}

func (a *CoreAdapter) generateToolName(apiName, path, method string) string {
	// Clean path: remove leading slash, replace slashes and special chars with underscores
	cleanPath := strings.TrimPrefix(path, "/")
	cleanPath = strings.ReplaceAll(cleanPath, "/", "_")

	// Replace path parameters {param} with _by_id
	re := regexp.MustCompile(`\{[^}]+\}`)
	cleanPath = re.ReplaceAllString(cleanPath, "_by_id")

	// Remove non-alphanumeric characters except underscores
	var result strings.Builder
	for _, r := range cleanPath {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			result.WriteRune(r)
		} else {
			result.WriteRune('_')
		}
	}
	cleanPath = result.String()

	// Remove duplicate underscores and trailing underscores
	cleanPath = strings.Trim(cleanPath, "_")
	for strings.Contains(cleanPath, "__") {
		cleanPath = strings.ReplaceAll(cleanPath, "__", "_")
	}

	// Add method suffix to distinguish between different HTTP methods on same path
	methodSuffix := strings.ToLower(method)

	// Handle empty path (root endpoint)
	if cleanPath == "" {
		return apiName + "." + methodSuffix
	}

	return apiName + "." + cleanPath + "_" + methodSuffix
}

func (a *CoreAdapter) extractDescription(operation map[string]any, path string) string {
	if summary, ok := operation["summary"].(string); ok && summary != "" {
		return summary
	}
	if desc, ok := operation["description"].(string); ok && desc != "" {
		return desc
	}
	return "API endpoint: " + path
}

func (a *CoreAdapter) extractParameters(operation map[string]any, method string) map[string]any {
	// For POST/PUT/PATCH, look for requestBody
	if strings.ToUpper(method) != constants.HTTPMethodGET {
		if requestBody, ok := operation["requestBody"].(map[string]any); ok {
			if content, ok := requestBody["content"].(map[string]any); ok {
				// Try application/json first
				if jsonContent, ok := content[constants.ContentTypeJSON].(map[string]any); ok {
					if schema, ok := jsonContent["schema"].(map[string]any); ok {
						return schema
					}
				}
				// Try application/x-www-form-urlencoded
				if formContent, ok := content[constants.ContentTypeForm].(map[string]any); ok {
					if schema, ok := formContent["schema"].(map[string]any); ok {
						return schema
					}
				}
			}
		}
	}

	// For GET or if no requestBody, look for parameters
	if params, ok := operation["parameters"].([]any); ok && len(params) > 0 {
		properties := make(map[string]any)
		var required []string

		for _, param := range params {
			if paramObj, ok := param.(map[string]any); ok {
				if name, ok := paramObj["name"].(string); ok {
					prop := map[string]any{
						"type": "string", // Default type
					}

					if desc, ok := paramObj["description"].(string); ok {
						prop["description"] = desc
					}

					if schema, ok := paramObj["schema"].(map[string]any); ok {
						if paramType, ok := schema["type"].(string); ok {
							prop["type"] = paramType
						}
						if enum, ok := schema["enum"].([]any); ok {
							prop["enum"] = enum
						}
					}

					properties[name] = prop

					if req, ok := paramObj["required"].(bool); ok && req {
						required = append(required, name)
					}
				}
			}
		}

		return map[string]any{
			"type":       "object",
			"properties": properties,
			"required":   required,
		}
	}

	// Default empty schema
	return map[string]any{
		"type":       "object",
		"properties": map[string]any{},
	}
}

func (a *CoreAdapter) determineContentType(operation map[string]any, method string) string {
	if strings.ToUpper(method) == constants.HTTPMethodGET {
		return constants.ContentTypeJSON
	}

	// Check if requestBody specifies form data
	if requestBody, ok := operation["requestBody"].(map[string]any); ok {
		if content, ok := requestBody["content"].(map[string]any); ok {
			if _, hasForm := content[constants.ContentTypeForm]; hasForm {
				return constants.ContentTypeForm
			}
		}
	}

	return constants.ContentTypeJSON
}

func (a *CoreAdapter) Manifest() *registry.ToolManifest {
	return nil
}
