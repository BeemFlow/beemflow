//! Automatic dependency detection from template references
//!
//! This module analyzes flow definitions to automatically detect step dependencies
//! by scanning template strings for `{{ steps.X }}` references.
//!
//! ## Hybrid Approach
//!
//! Dependencies are detected from two sources:
//! 1. **Automatic**: Scanning templates for `{{ steps.step_id }}` patterns
//! 2. **Manual**: Explicit `depends_on` field in step definitions
//!
//! The analyzer merges both sources to create a complete dependency graph.

use crate::error::{BeemFlowError, Result};
use crate::model::{Flow, Step};
use regex::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// Analyzes flows to detect and resolve step dependencies
pub struct DependencyAnalyzer {
    /// Regex to match {{ steps.step_id }} or {{ steps['step_id'] }}
    step_ref_regex: Regex,
    /// Maximum recursion depth for nested structures (prevents stack overflow)
    max_recursion_depth: usize,
}

impl DependencyAnalyzer {
    /// Create a new dependency analyzer with default max recursion depth (1000)
    pub fn new() -> Self {
        Self::with_max_depth(1000)
    }

    /// Create a new dependency analyzer with custom max recursion depth
    pub fn with_max_depth(max_recursion_depth: usize) -> Self {
        Self {
            // Matches various forms:
            // - {{ steps.foo }}
            // - {{ steps.foo.output }}
            // - {{ steps['foo'] }}
            // - {{ steps["foo"] }}
            #[allow(clippy::expect_used)] // Static regex compilation should fail-fast
            step_ref_regex: Regex::new(
                r#"steps\.([a-zA-Z0-9_-]+)|steps\['([^']+)'\]|steps\["([^"]+)"\]"#,
            )
            .expect("step reference regex is valid"),
            max_recursion_depth,
        }
    }

    /// Extract all step ID references from a template string
    pub(crate) fn extract_step_refs(&self, template: &str) -> HashSet<String> {
        let mut refs = HashSet::new();

        for cap in self.step_ref_regex.captures_iter(template) {
            // Check each capture group (handles different syntaxes)
            if let Some(step_id) = cap.get(1) {
                refs.insert(step_id.as_str().to_string());
            } else if let Some(step_id) = cap.get(2) {
                refs.insert(step_id.as_str().to_string());
            } else if let Some(step_id) = cap.get(3) {
                refs.insert(step_id.as_str().to_string());
            }
        }

        refs
    }

    /// Recursively extract step references from a JSON value
    fn extract_refs_from_value(&self, value: &Value) -> HashSet<String> {
        self.extract_refs_from_value_depth(value, 0)
    }

    /// Extract step references with depth tracking to prevent stack overflow
    fn extract_refs_from_value_depth(&self, value: &Value, depth: usize) -> HashSet<String> {
        let mut refs = HashSet::new();

        // Enforce recursion depth limit
        if depth > self.max_recursion_depth {
            tracing::warn!(
                "Maximum recursion depth ({}) exceeded in extract_refs_from_value",
                self.max_recursion_depth
            );
            return refs;
        }

        match value {
            Value::String(s) => {
                refs.extend(self.extract_step_refs(s));
            }
            Value::Array(arr) => {
                for item in arr {
                    refs.extend(self.extract_refs_from_value_depth(item, depth + 1));
                }
            }
            Value::Object(obj) => {
                for v in obj.values() {
                    refs.extend(self.extract_refs_from_value_depth(v, depth + 1));
                }
            }
            _ => {}
        }

        refs
    }

    /// Analyze a single step to find all template-based dependencies
    pub(crate) fn analyze_step(&self, step: &Step) -> HashSet<String> {
        self.analyze_step_depth(step, 0)
    }

    /// Analyze a step with depth tracking to prevent stack overflow
    fn analyze_step_depth(&self, step: &Step, depth: usize) -> HashSet<String> {
        let mut deps = HashSet::new();

        // Enforce recursion depth limit
        if depth > self.max_recursion_depth {
            tracing::warn!(
                "Maximum recursion depth ({}) exceeded in analyze_step for step '{}'",
                self.max_recursion_depth,
                step.id
            );
            return deps;
        }

        // Check 'if' condition
        if let Some(ref condition) = step.if_ {
            deps.extend(self.extract_step_refs(condition));
        }

        // Check 'with' parameters (recursively)
        if let Some(ref with) = step.with {
            for value in with.values() {
                deps.extend(self.extract_refs_from_value(value));
            }
        }

        // Check 'foreach' expression
        if let Some(ref foreach_expr) = step.foreach {
            deps.extend(self.extract_step_refs(foreach_expr));
        }

        // Recursively check nested steps (do blocks)
        if let Some(ref nested_steps) = step.do_ {
            for nested_step in nested_steps {
                deps.extend(self.analyze_step_depth(nested_step, depth + 1));
            }
        }

        // Recursively check parallel blocks
        if let Some(ref parallel_steps) = step.steps {
            for parallel_step in parallel_steps {
                deps.extend(self.analyze_step_depth(parallel_step, depth + 1));
            }
        }

        deps
    }

    /// Build dependency graph from automatic detection (template refs)
    fn build_automatic_deps(&self, flow: &Flow) -> HashMap<String, HashSet<String>> {
        let mut graph = HashMap::new();

        for step in &flow.steps {
            let deps = self.analyze_step(step);
            graph.insert(step.id.to_string(), deps);
        }

        graph
    }

    /// Build dependency graph from manual depends_on fields
    fn build_manual_deps(&self, flow: &Flow) -> HashMap<String, HashSet<String>> {
        let mut graph = HashMap::new();

        for step in &flow.steps {
            let deps = if let Some(ref depends_on) = step.depends_on {
                depends_on.iter().cloned().collect()
            } else {
                HashSet::new()
            };
            graph.insert(step.id.to_string(), deps);
        }

        graph
    }

    /// Merge automatic and manual dependencies
    pub(crate) fn merge_dependencies(
        &self,
        auto: HashMap<String, HashSet<String>>,
        manual: HashMap<String, HashSet<String>>,
    ) -> HashMap<String, HashSet<String>> {
        let mut merged = auto;

        for (step_id, manual_deps) in manual {
            merged.entry(step_id).or_default().extend(manual_deps);
        }

        merged
    }

    /// Build complete dependency graph (auto + manual)
    pub fn build_dependency_graph(&self, flow: &Flow) -> HashMap<String, HashSet<String>> {
        let auto_deps = self.build_automatic_deps(flow);
        let manual_deps = self.build_manual_deps(flow);
        self.merge_dependencies(auto_deps, manual_deps)
    }

    /// Validate that all referenced steps exist
    fn validate_references(
        &self,
        flow: &Flow,
        graph: &HashMap<String, HashSet<String>>,
    ) -> Result<()> {
        let all_steps: HashSet<String> = flow.steps.iter().map(|s| s.id.to_string()).collect();

        for (step_id, deps) in graph {
            for dep in deps {
                if !all_steps.contains(dep) {
                    return Err(BeemFlowError::validation(format!(
                        "Step '{}' depends on non-existent step '{}'",
                        step_id, dep
                    )));
                }
            }
        }

        Ok(())
    }

    /// Detect circular dependencies using DFS
    fn detect_cycles(&self, graph: &HashMap<String, HashSet<String>>) -> Result<()> {
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();

        fn visit(
            node: &str,
            graph: &HashMap<String, HashSet<String>>,
            visited: &mut HashSet<String>,
            rec_stack: &mut HashSet<String>,
        ) -> Result<()> {
            if rec_stack.contains(node) {
                return Err(BeemFlowError::validation(format!(
                    "Circular dependency detected involving step '{}'",
                    node
                )));
            }

            if visited.contains(node) {
                return Ok(());
            }

            rec_stack.insert(node.to_string());

            if let Some(deps) = graph.get(node) {
                for dep in deps {
                    visit(dep, graph, visited, rec_stack)?;
                }
            }

            rec_stack.remove(node);
            visited.insert(node.to_string());

            Ok(())
        }

        for node in graph.keys() {
            if !visited.contains(node) {
                visit(node, graph, &mut visited, &mut rec_stack)?;
            }
        }

        Ok(())
    }

    /// Perform topological sort on steps based on dependencies
    ///
    /// Returns step IDs in execution order (dependencies before dependents)
    pub fn topological_sort(&self, flow: &Flow) -> Result<Vec<String>> {
        let graph = self.build_dependency_graph(flow);

        // Validate references
        self.validate_references(flow, &graph)?;

        // Detect cycles
        self.detect_cycles(&graph)?;

        // Perform topological sort using DFS
        let mut sorted = Vec::new();
        let mut visited = HashSet::new();

        fn visit(
            node: &str,
            graph: &HashMap<String, HashSet<String>>,
            visited: &mut HashSet<String>,
            sorted: &mut Vec<String>,
        ) {
            if visited.contains(node) {
                return;
            }

            visited.insert(node.to_string());

            // Visit dependencies first
            if let Some(deps) = graph.get(node) {
                for dep in deps {
                    visit(dep, graph, visited, sorted);
                }
            }

            // Add this node after its dependencies
            sorted.push(node.to_string());
        }

        // Visit all steps
        for step in &flow.steps {
            if !visited.contains(step.id.as_str()) {
                visit(step.id.as_str(), &graph, &mut visited, &mut sorted);
            }
        }

        Ok(sorted)
    }

    /// Find groups of steps that can run in parallel
    ///
    /// Returns a vector of groups, where each group contains step IDs
    /// that have no dependencies on each other and can execute concurrently.
    pub fn find_parallel_groups(&self, flow: &Flow) -> Result<Vec<Vec<String>>> {
        let sorted = self.topological_sort(flow)?;
        let graph = self.build_dependency_graph(flow);

        let mut groups: Vec<Vec<String>> = Vec::new();
        let mut completed = HashSet::new();

        for step_id in sorted {
            let deps = graph.get(&step_id).cloned().unwrap_or_default();

            // Check if all dependencies are satisfied
            let ready = deps.iter().all(|d| completed.contains(d));

            if !ready {
                // This shouldn't happen if topological sort is correct
                return Err(BeemFlowError::adapter(format!(
                    "Step '{}' not ready (unsatisfied dependencies)",
                    step_id
                )));
            }

            // Can this step run in parallel with the current group?
            if let Some(current_group) = groups.last_mut() {
                // Check if any step in current group is a dependency
                let conflicts_with_current = current_group.iter().any(|g| deps.contains(g));

                if !conflicts_with_current {
                    // No conflict - add to current group
                    current_group.push(step_id.clone());
                } else {
                    // Conflict - start new group
                    groups.push(vec![step_id.clone()]);
                }
            } else {
                // First group
                groups.push(vec![step_id.clone()]);
            }

            completed.insert(step_id);
        }

        Ok(groups)
    }
}

impl Default for DependencyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
