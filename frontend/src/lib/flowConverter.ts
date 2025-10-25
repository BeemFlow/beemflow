import type { Node, Edge } from '@xyflow/react';
import type { Flow, Step, Trigger, JsonValue } from '../types/beemflow';
import * as yaml from 'yaml';
import dagre from '@dagrejs/dagre';

/**
 * Extract step ID references from a template string
 * Mimics the Rust DependencyAnalyzer behavior
 * Matches patterns like:
 * - {{ read_sheet.values }}
 * - {{ steps.foo.output }}
 * - {{ steps['foo'] }}
 *
 * Filters out:
 * - System variables: vars, env
 * - Previous run references: runs.previous (not runtime dependencies)
 */
function extractStepReferences(template: string): Set<string> {
  const refs = new Set<string>();

  // Filter out runs.previous references - these are historical, not runtime dependencies
  // Example: {{ runs.previous.outputs.generate_draft.text }} should NOT create a dependency
  const withoutPreviousRuns = template.replace(/runs\.previous\.\S+/g, '');

  // Regex patterns matching the Rust implementation
  const patterns = [
    // Direct step reference: {{ step_id.field }}
    /\{\{\s*([a-zA-Z0-9_-]+)\.[a-zA-Z0-9_.[\]'"]+\s*\}\}/g,
    // steps.step_id syntax: {{ steps.foo }}
    /\{\{\s*steps\.([a-zA-Z0-9_-]+)/g,
    // steps['step_id'] syntax
    /\{\{\s*steps\['([^']+)'\]/g,
    // steps["step_id"] syntax
    /\{\{\s*steps\["([^"]+)"\]/g,
    // Jinja2 for loops: {% for x in step_id.field %}
    /\{%\s+for\s+\w+\s+in\s+([a-zA-Z0-9_-]+)\.[a-zA-Z0-9_.[\]'"]+/g,
    // Jinja2 if conditions: {% if step_id.field %}
    /\{%\s+if\s+([a-zA-Z0-9_-]+)\.[a-zA-Z0-9_.[\]'"]+/g,
  ];

  patterns.forEach((pattern) => {
    const matches = withoutPreviousRuns.matchAll(pattern);
    for (const match of matches) {
      if (match[1] && match[1] !== 'vars' && match[1] !== 'env' && match[1] !== 'runs') {
        refs.add(match[1]);
      }
    }
  });

  return refs;
}

/**
 * Analyze a step to find all implicit dependencies from template references
 * Scans: if, with, foreach, nested do blocks
 * Mimics Rust DependencyAnalyzer::analyze_step behavior
 */
function analyzeStepDependencies(step: Step): Set<string> {
  const deps = new Set<string>();

  // Check 'if' condition
  if (step.if) {
    extractStepReferences(step.if).forEach((ref) => deps.add(ref));
  }

  // Check 'with' parameters (recursively scan all values)
  if (step.with) {
    const withStr = JSON.stringify(step.with);
    extractStepReferences(withStr).forEach((ref) => deps.add(ref));
  }

  // Check 'foreach' expression
  if (step.foreach) {
    extractStepReferences(step.foreach).forEach((ref) => deps.add(ref));
  }

  // Recursively check nested steps (do blocks)
  if (step.do) {
    step.do.forEach((nestedStep) => {
      analyzeStepDependencies(nestedStep).forEach((ref) => deps.add(ref));
    });
  }

  // Also check parallel step blocks
  if (step.steps) {
    step.steps.forEach((nestedStep) => {
      analyzeStepDependencies(nestedStep).forEach((ref) => deps.add(ref));
    });
  }

  return deps;
}

/**
 * Build dependency map from both explicit depends_on and implicit template references
 * Mimics Rust build_dependency_graph behavior
 */
function buildDependencyMap(steps: Step[]): Map<string, Set<string>> {
  const depMap = new Map<string, Set<string>>();
  const stepIds = new Set(steps.map((s) => s.id));

  steps.forEach((step) => {
    const deps = new Set<string>();

    // Add explicit dependencies
    if (step.depends_on) {
      step.depends_on.forEach((dep) => deps.add(dep));
    }

    // Add implicit dependencies from template references
    const implicitDeps = analyzeStepDependencies(step);
    implicitDeps.forEach((dep) => {
      // Only add if it's a valid step ID (not a variable reference)
      if (stepIds.has(dep)) {
        deps.add(dep);
      }
    });

    depMap.set(step.id, deps);
  });

  return depMap;
}

/**
 * Convert ReactFlow graph to BeemFlow YAML
 */
export function graphToYaml(
  nodes: Node[],
  edges: Edge[],
  metadata: {
    name: string;
    description?: string;
    version?: string;
    vars?: Record<string, JsonValue>;
    cron?: string;
  }
): string {
  const flow = graphToFlow(nodes, edges, metadata);
  return yaml.stringify(flow);
}

/**
 * Convert ReactFlow graph to BeemFlow Flow object
 */
export function graphToFlow(
  nodes: Node[],
  edges: Edge[],
  metadata: {
    name: string;
    description?: string;
    version?: string;
    vars?: Record<string, JsonValue>;
    cron?: string;
  }
): Flow {
  // Find trigger node
  const triggerNode = nodes.find((n) => n.type === 'trigger');
  const triggerData = triggerNode?.data as { trigger?: Trigger; cronExpression?: string } | undefined;
  const trigger: Trigger = triggerData?.trigger || 'cli.manual';

  // Extract cron expression from trigger node data or metadata
  let cronExpression: string | undefined = metadata.cron || triggerData?.cronExpression;

  // If trigger is in format "cron.EXPRESSION", extract the expression for the separate cron field
  // Backend requires both: on: ["cron.*/5 * * * *"] AND cron: "*/5 * * * *"
  if (!cronExpression) {
    if (typeof trigger === 'string' && trigger.startsWith('cron.')) {
      cronExpression = trigger.substring(5); // Remove "cron." prefix
    } else if (Array.isArray(trigger)) {
      // Check each trigger in the array for cron.EXPRESSION format
      const cronTrigger = trigger.find((t) => t.startsWith('cron.'));
      if (cronTrigger) {
        cronExpression = cronTrigger.substring(5); // Remove "cron." prefix
      }
    }
  }

  // BeemFlow uses 6-field cron (with seconds): "second minute hour day month weekday"
  // Convert 5-field cron to 6-field by prepending "0 " (run at 0 seconds)
  if (cronExpression) {
    const fields = cronExpression.trim().split(/\s+/);
    if (fields.length === 5) {
      cronExpression = '0 ' + cronExpression; // Prepend seconds field
    }
  }

  // Build dependency map from edges (exclude edges from trigger node)
  const dependencies = new Map<string, string[]>();
  edges.forEach((edge) => {
    // Skip edges from trigger - trigger is not a valid step dependency
    if (edge.source === 'trigger') return;

    const deps = dependencies.get(edge.target) || [];
    deps.push(edge.source);
    dependencies.set(edge.target, deps);
  });

  // Convert step nodes to steps
  const steps: Step[] = nodes
    .filter((n) => n.type === 'step')
    .map((node) => {
      const step = node.data.step as Step;
      const deps = dependencies.get(node.id);

      return {
        ...step,
        depends_on: deps && deps.length > 0 ? deps : undefined,
      };
    });

  return {
    name: metadata.name,
    description: metadata.description,
    version: metadata.version || '1.0.0', // Default to 1.0.0 if not specified
    on: trigger,
    vars: metadata.vars,
    cron: cronExpression,
    steps,
  };
}

/**
 * Convert BeemFlow YAML to ReactFlow graph
 */
export function yamlToGraph(yamlString: string): {
  nodes: Node[];
  edges: Edge[];
  metadata: {
    name: string;
    description?: string;
    version?: string;
    vars?: Record<string, JsonValue>;
    cron?: string;
  };
} {
  const flow = yaml.parse(yamlString) as Flow;
  return flowToGraph(flow);
}

/**
 * Convert BeemFlow Flow object to ReactFlow graph
 *
 * Automatically detects step dependencies from template references.
 * For example, if step B has `{{ step_a.output }}` in its parameters,
 * an edge from step_a -> step_b will be created automatically.
 *
 * This mirrors the Rust DependencyAnalyzer behavior where dependencies
 * are detected from both:
 * 1. Explicit `depends_on` fields
 * 2. Implicit template references in `if`, `with`, `foreach`, and nested blocks
 */
export function flowToGraph(flow: Flow): {
  nodes: Node[];
  edges: Edge[];
  metadata: {
    name: string;
    description?: string;
    version?: string;
    vars?: Record<string, JsonValue>;
    cron?: string;
  };
} {
  const nodes: Node[] = [];
  const edges: Edge[] = [];

  // Add trigger node - support both single and multiple triggers
  const triggerValue: Trigger = typeof flow.on === 'string'
    ? flow.on
    : Array.isArray(flow.on)
    ? flow.on
    : 'cli.manual'; // Fallback to manual trigger

  // Extract cron expression for trigger node
  let cronExpression = flow.cron;

  // If trigger is in format "cron.EXPRESSION" and no separate cron field, extract it
  if (!cronExpression) {
    if (typeof triggerValue === 'string' && triggerValue.startsWith('cron.')) {
      cronExpression = triggerValue.substring(5);
    } else if (Array.isArray(triggerValue)) {
      const cronTrigger = triggerValue.find((t) => t.startsWith('cron.'));
      if (cronTrigger) {
        cronExpression = cronTrigger.substring(5);
      }
    }
  }

  // Normalize cron to display format (remove leading "0 " seconds if present for cleaner UI)
  // Backend stores as 6-field, but we can display as 5-field in UI
  if (cronExpression) {
    const fields = cronExpression.trim().split(/\s+/);
    if (fields.length === 6 && fields[0] === '0') {
      // If seconds field is "0", show 5-field format in UI
      cronExpression = fields.slice(1).join(' ');
    }
  }

  nodes.push({
    id: 'trigger',
    type: 'trigger',
    position: { x: 250, y: 50 },
    data: {
      trigger: triggerValue,
      cronExpression,
    },
  });

  // Build complete dependency map (explicit + implicit from templates)
  const dependencyMap = buildDependencyMap(flow.steps);

  // Calculate hierarchical layout levels
  const positions = calculateHierarchicalLayout(flow.steps, dependencyMap);

  // Add step nodes
  flow.steps.forEach((step, index) => {
    const node: Node = {
      id: step.id,
      type: 'step',
      position: positions.get(step.id) || calculatePosition(index),
      data: {
        step,
      },
    };
    nodes.push(node);

    // Create edges from dependencies (both explicit and implicit)
    const deps = dependencyMap.get(step.id);
    if (deps && deps.size > 0) {
      deps.forEach((depId) => {
        edges.push({
          id: `${depId}-${step.id}`,
          source: depId,
          target: step.id,
          type: 'default',
        });
      });
    } else if (index === 0) {
      // First step with no dependencies connects to trigger
      edges.push({
        id: `trigger-${step.id}`,
        source: 'trigger',
        target: step.id,
        type: 'default',
      });
    }
  });

  return {
    nodes,
    edges,
    metadata: {
      name: flow.name,
      description: flow.description,
      version: flow.version,
      vars: flow.vars,
      cron: flow.cron,
    },
  };
}

/**
 * Calculate layout positions using Dagre graph layout library
 */
function calculateHierarchicalLayout(
  steps: Step[],
  dependencyMap: Map<string, Set<string>>
): Map<string, { x: number; y: number }> {
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));

  // Configure graph layout
  dagreGraph.setGraph({
    rankdir: 'LR', // Left to right (better for workflow diagrams)
    nodesep: 150,  // Vertical spacing between nodes at same rank
    ranksep: 250,  // Horizontal spacing between ranks (levels)
    marginx: 100,
    marginy: 100,
  });

  // Node dimensions (approximate size of our step cards)
  const nodeWidth = 250;
  const nodeHeight = 120;

  // Add all step nodes to dagre
  steps.forEach((step) => {
    dagreGraph.setNode(step.id, { width: nodeWidth, height: nodeHeight });
  });

  // Add edges based on dependency map
  steps.forEach((step) => {
    const deps = dependencyMap.get(step.id);
    if (deps && deps.size > 0) {
      deps.forEach((depId) => {
        dagreGraph.setEdge(depId, step.id);
      });
    }
  });

  // Run dagre layout algorithm
  dagre.layout(dagreGraph);

  // Extract calculated positions
  const positions = new Map<string, { x: number; y: number }>();
  steps.forEach((step) => {
    const nodeWithPosition = dagreGraph.node(step.id);
    if (nodeWithPosition) {
      positions.set(step.id, {
        x: nodeWithPosition.x - nodeWidth / 2,
        y: nodeWithPosition.y - nodeHeight / 2,
      });
    }
  });

  return positions;
}

/**
 * Calculate node position for auto-layout (fallback)
 */
function calculatePosition(index: number): { x: number; y: number } {
  const VERTICAL_SPACING = 150;
  const START_Y = 200;

  // Simple vertical layout for now
  return {
    x: 250,
    y: START_Y + index * VERTICAL_SPACING,
  };
}
