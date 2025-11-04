import { useState, useEffect } from 'react';
import { useFlowEditorStore } from '../../stores/flowEditorStore';
import { graphToYaml, yamlToGraph } from '../../lib/flowConverter';
import type { JsonValue } from '../../types/beemflow';

interface YamlPreviewProps {
  flowName: string;
  description?: string;
  version?: string;
  vars?: Record<string, JsonValue>;
  cron?: string;
  onImportYaml?: (yaml: string) => void;
  onMetadataUpdate?: (metadata: {
    name: string;
    description?: string;
    version?: string;
    vars?: Record<string, JsonValue>;
    cron?: string;
  }) => void;
}

export function YamlPreview({
  flowName,
  description,
  version,
  vars,
  cron,
  onImportYaml,
  onMetadataUpdate,
}: YamlPreviewProps) {
  const { nodes, edges, setNodes, setEdges } = useFlowEditorStore();
  const [yamlContent, setYamlContent] = useState('');
  const [isEditing, setIsEditing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Auto-generate YAML from graph
  useEffect(() => {
    if (!isEditing) {
      try {
        const yaml = graphToYaml(nodes, edges, {
          name: flowName || 'untitled_flow',
          description,
          version,
          vars,
          cron,
        });
        setYamlContent(yaml);
        setError(null);
      } catch (err) {
        setError('Failed to generate YAML: ' + String(err));
      }
    }
  }, [nodes, edges, flowName, description, version, vars, cron, isEditing]);

  // Apply YAML changes to graph
  const handleApplyYaml = () => {
    try {
      const { nodes: newNodes, edges: newEdges, metadata } = yamlToGraph(yamlContent);
      setNodes(newNodes);
      setEdges(newEdges);
      setIsEditing(false);
      setError(null);

      // Update metadata in parent component
      if (onMetadataUpdate) {
        onMetadataUpdate({
          name: metadata.name,
          description: metadata.description,
          version: metadata.version,
          vars: metadata.vars,
          cron: metadata.cron,
        });
      }

      if (onImportYaml) {
        onImportYaml(yamlContent);
      }
    } catch (err) {
      setError('Invalid YAML: ' + String(err));
    }
  };

  const handleCancelEdit = () => {
    setIsEditing(false);
    setError(null);
    // Regenerate from current graph
    const yaml = graphToYaml(nodes, edges, {
      name: flowName || 'untitled_flow',
      description,
      version,
      vars,
      cron,
    });
    setYamlContent(yaml);
  };

  const handleCopyYaml = () => {
    navigator.clipboard.writeText(yamlContent);
  };

  return (
    <div className="h-full flex flex-col bg-gray-900 text-gray-100">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-gray-800 border-b border-gray-700">
        <div className="flex items-center space-x-2">
          <span className="text-sm font-semibold">YAML Preview</span>
          {isEditing && (
            <span className="px-2 py-0.5 bg-amber-500 text-amber-900 rounded text-xs font-semibold">
              EDITING
            </span>
          )}
        </div>
        <div className="flex items-center space-x-2">
          {!isEditing ? (
            <>
              <button
                onClick={handleCopyYaml}
                className="px-2 py-1 text-xs bg-gray-700 hover:bg-gray-600 rounded transition-colors"
                title="Copy YAML"
              >
                📋 Copy
              </button>
              <button
                onClick={() => setIsEditing(true)}
                className="px-2 py-1 text-xs bg-primary-600 hover:bg-primary-700 rounded transition-colors"
              >
                ✏️ Edit
              </button>
            </>
          ) : (
            <>
              <button
                onClick={handleCancelEdit}
                className="px-2 py-1 text-xs bg-gray-700 hover:bg-gray-600 rounded transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleApplyYaml}
                className="px-2 py-1 text-xs bg-green-600 hover:bg-green-700 rounded transition-colors"
              >
                ✓ Apply
              </button>
            </>
          )}
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="px-4 py-2 bg-red-900 text-red-100 text-xs border-b border-red-800">
          {error}
        </div>
      )}

      {/* YAML Content */}
      <div className="flex-1">
        <textarea
          value={yamlContent}
          onChange={(e) => {
            setYamlContent(e.target.value);
            setIsEditing(true);
          }}
          className="w-full h-full p-4 bg-gray-900 text-gray-100 font-mono text-sm resize-none focus:outline-none"
          style={{ tabSize: 2 }}
          spellCheck={false}
        />
      </div>

      {/* Help Text */}
      <div className="px-4 py-2 bg-gray-800 border-t border-gray-700 text-xs text-gray-400">
        {isEditing ? (
          <>Edit the YAML and click "Apply" to update the graph</>
        ) : (
          <>The YAML updates automatically as you edit the graph</>
        )}
      </div>
    </div>
  );
}
