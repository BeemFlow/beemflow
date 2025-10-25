import { useCallback, useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Panel,
  type NodeTypes,
  type NodeMouseHandler,
  type OnSelectionChangeParams,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import toast, { Toaster } from 'react-hot-toast';

import { useFlowEditorStore } from '../../stores/flowEditorStore';
import { StepNode } from './nodes/StepNode';
import { TriggerNode } from './nodes/TriggerNode';
import { Inspector } from './Inspector';
import { YamlPreview } from './YamlPreview';
import { ToolsPalette } from './ToolsPalette';
import { AIAssistant } from './AIAssistant';
import { VarsEditor } from './VarsEditor';
import { useFlow, useSaveFlow, useDeployFlow } from '../../hooks/useFlows';
import { useStartRun } from '../../hooks/useRuns';
import { graphToFlow, flowToGraph } from '../../lib/flowConverter';
import type { StepId, RegistryEntry, JsonValue } from '../../types/beemflow';

// Define custom node types
const nodeTypes = {
  step: StepNode,
  trigger: TriggerNode,
} as NodeTypes;

export function FlowEditor() {
  const { name } = useParams<{ name: string }>();
  const navigate = useNavigate();
  const [flowName, setFlowName] = useState(name || '');
  const [description, setDescription] = useState('');
  const [vars, setVars] = useState<Record<string, JsonValue>>({});
  const [cron, setCron] = useState<string>('');
  const [showVarsEditor, setShowVarsEditor] = useState(false);
  const [showYamlPreview, setShowYamlPreview] = useState(false);
  const [showInspector, setShowInspector] = useState(true);
  const [showToolsPalette, setShowToolsPalette] = useState(true);
  const [showAIAssistant, setShowAIAssistant] = useState(false);

  // Resizable panel widths
  const [toolsPaletteWidth, setToolsPaletteWidth] = useState(280);
  const [inspectorWidth, setInspectorWidth] = useState(320);
  const [yamlPreviewWidth, setYamlPreviewWidth] = useState(400);
  const [aiAssistantWidth, setAIAssistantWidth] = useState(400);

  // Flow editor state from Zustand
  const {
    nodes,
    edges,
    onNodesChange,
    onEdgesChange,
    onConnect,
    addNode,
    clearCanvas,
    selectNode,
    setNodes,
    setEdges,
  } = useFlowEditorStore();

  // Load existing flow if editing
  const { data: existingFlow, isLoading } = useFlow(name);

  // Mutations
  const saveFlow = useSaveFlow();
  const deployFlow = useDeployFlow();
  const startRun = useStartRun();

  // Clear state and initialize when creating a new flow
  useEffect(() => {
    if (!name) {
      // Clear all state when navigating to /flows/new
      clearCanvas();
      setFlowName('');
      setDescription('');
      setVars({});
      setCron('');

      // Add initial trigger node
      const triggerNode = {
        id: 'trigger',
        type: 'trigger',
        position: { x: 250, y: 50 },
        data: { trigger: 'cli.manual' },
      };
      addNode(triggerNode);
      selectNode(triggerNode);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [name]); // Run when 'name' param changes

  // Load existing flow data when editing
  useEffect(() => {
    if (existingFlow) {
      // Convert flow to graph and load it
      const { nodes: flowNodes, edges: flowEdges, metadata } = flowToGraph(existingFlow);
      setNodes(flowNodes);
      setEdges(flowEdges);
      setFlowName(metadata.name);
      setDescription(metadata.description || '');
      setVars(metadata.vars || {});
      setCron(metadata.cron || '');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [existingFlow, name]); // Run when existingFlow changes or when navigating to a different flow

  // Add a new step node
  const handleAddStep = useCallback(() => {
    const newStepId: StepId = `step_${nodes.filter(n => n.type === 'step').length + 1}`;
    const newNode = {
      id: newStepId,
      type: 'step',
      position: {
        x: 250,
        y: 150 + nodes.filter(n => n.type === 'step').length * 100,
      },
      data: {
        step: {
          id: newStepId,
          use: 'core.echo',
          with: { text: 'Hello World' },
        },
      },
    };
    addNode(newNode);
    // Auto-select the newly created node
    selectNode(newNode);
    // Auto-open inspector
    if (!showInspector) {
      setShowInspector(true);
    }
  }, [nodes, addNode, selectNode, showInspector]);

  const handleNodeClick: NodeMouseHandler = useCallback((_event, node) => {
    console.log('Node clicked:', node);
    selectNode(node);
  }, [selectNode]);

  const handlePaneClick = useCallback(() => {
    // Clear selection when clicking on canvas background
    selectNode(null);
  }, [selectNode]);

  const handleSelectionChange = useCallback((params: OnSelectionChangeParams) => {
    // Sync ReactFlow's selection with our store
    if (params.nodes.length > 0) {
      const selectedNode = params.nodes[0]; // Take first selected node
      console.log('Selection changed:', selectedNode);
      selectNode(selectedNode);
    } else {
      selectNode(null);
    }
  }, [selectNode]);

  // Handle tool selection from palette
  const handleToolSelect = useCallback((tool: RegistryEntry) => {
    const newStepId: StepId = `step_${nodes.filter(n => n.type === 'step').length + 1}`;
    const newNode = {
      id: newStepId,
      type: 'step',
      position: {
        x: 250,
        y: 150 + nodes.filter(n => n.type === 'step').length * 100,
      },
      data: {
        step: {
          id: newStepId,
          use: tool.name,
          with: {},
        },
      },
    };
    addNode(newNode);
    // Auto-select the newly created node
    selectNode(newNode);
    // Auto-open inspector
    if (!showInspector) {
      setShowInspector(true);
    }
    toast.success(`Added ${tool.name} to workflow`);
  }, [nodes, addNode, selectNode, showInspector]);

  // Validate flow before saving
  const validateFlow = useCallback(() => {
    if (!flowName.trim()) {
      toast.error('Please enter a flow name');
      return false;
    }

    const stepNodes = nodes.filter(n => n.type === 'step');
    if (stepNodes.length === 0) {
      toast.error('Please add at least one step to the flow');
      return false;
    }

    return true;
  }, [flowName, nodes]);

  // Save draft handler
  const handleSaveDraft = useCallback(async () => {
    if (!validateFlow()) return;

    try {
      const flow = graphToFlow(nodes, edges, {
        name: flowName,
        description: description || undefined,
        vars: Object.keys(vars).length > 0 ? vars : undefined,
        cron: cron || undefined,
      });

      await saveFlow.mutateAsync(flow);
      toast.success('Flow saved successfully!');
      navigate('/');
    } catch (error) {
      toast.error(`Failed to save flow: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }, [flowName, description, vars, cron, nodes, edges, validateFlow, saveFlow, navigate]);

  // Deploy and run handler
  const handleDeployAndRun = useCallback(async () => {
    if (!validateFlow()) return;

    try {
      const flow = graphToFlow(nodes, edges, {
        name: flowName,
        description: description || undefined,
        vars: Object.keys(vars).length > 0 ? vars : undefined,
        cron: cron || undefined,
      });

      // First save the flow
      await saveFlow.mutateAsync(flow);

      // Then deploy it
      await deployFlow.mutateAsync(flowName);
      toast.success('Flow deployed successfully!');

      // Start a run
      const result = await startRun.mutateAsync({ flow_name: flowName });
      toast.success('Flow execution started!');

      // Navigate to execution view
      navigate(`/runs/${result.run_id}`);
    } catch (error) {
      toast.error(`Failed to deploy and run flow: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }, [flowName, description, vars, cron, nodes, edges, validateFlow, saveFlow, deployFlow, startRun, navigate]);

  // Resize handlers - must be before early returns
  const handleToolsPaletteResize = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    const startX = e.clientX;
    const startWidth = toolsPaletteWidth;

    const handleMouseMove = (moveEvent: MouseEvent) => {
      const delta = moveEvent.clientX - startX;
      setToolsPaletteWidth(Math.max(200, Math.min(600, startWidth + delta)));
    };

    const handleMouseUp = () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  }, [toolsPaletteWidth]);

  const handleInspectorResize = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    const startX = e.clientX;
    const startWidth = inspectorWidth;

    const handleMouseMove = (moveEvent: MouseEvent) => {
      const delta = moveEvent.clientX - startX;
      setInspectorWidth(Math.max(250, Math.min(600, startWidth + delta)));
    };

    const handleMouseUp = () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  }, [inspectorWidth]);

  const handleYamlPreviewResize = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    const startX = e.clientX;
    const startWidth = yamlPreviewWidth;

    const handleMouseMove = (moveEvent: MouseEvent) => {
      const delta = startX - moveEvent.clientX; // Reversed because it's on the right
      setYamlPreviewWidth(Math.max(300, Math.min(800, startWidth + delta)));
    };

    const handleMouseUp = () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  }, [yamlPreviewWidth]);

  const handleAIAssistantResize = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    const startX = e.clientX;
    const startWidth = aiAssistantWidth;

    const handleMouseMove = (moveEvent: MouseEvent) => {
      const delta = startX - moveEvent.clientX; // Reversed because it's on the right
      setAIAssistantWidth(Math.max(300, Math.min(800, startWidth + delta)));
    };

    const handleMouseUp = () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  }, [aiAssistantWidth]);

  // Early return must come after all hooks
  if (isLoading) {
    return (
      <div className="h-screen flex items-center justify-center">
        <div className="text-lg text-gray-600">Loading flow...</div>
      </div>
    );
  }

  const actualToolsPaletteWidth = showToolsPalette ? toolsPaletteWidth : 0;
  const actualInspectorWidth = showInspector ? inspectorWidth : 0;
  const actualYamlPreviewWidth = showYamlPreview ? yamlPreviewWidth : 0;
  const actualAIAssistantWidth = showAIAssistant ? aiAssistantWidth : 0;

  return (
    <div className="fixed inset-0 top-16 flex flex-col bg-gray-50">
      <Toaster position="top-right" />
      {/* Header */}
      <div className="bg-white border-b border-gray-200 px-6 py-4 z-10 flex-shrink-0">
        <div className="flex items-center justify-between">
          <div className="flex-1 max-w-2xl">
            <input
              type="text"
              value={flowName}
              onChange={(e) => setFlowName(e.target.value)}
              placeholder="Flow name"
              className="text-2xl font-bold border-none outline-none focus:ring-2 focus:ring-primary-500 rounded px-2 w-full"
            />
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Description (optional)"
              className="mt-1 text-sm text-gray-600 border-none outline-none focus:ring-2 focus:ring-primary-500 rounded px-2 w-full"
            />
          </div>
          <div className="flex items-center space-x-3">
            <button
              onClick={() => setShowToolsPalette(!showToolsPalette)}
              className={`px-3 py-2 rounded-lg transition-colors ${
                showToolsPalette
                  ? 'bg-primary-100 text-primary-700'
                  : 'text-gray-700 hover:bg-gray-100'
              }`}
              title="Toggle Tools Palette"
            >
              Tools
            </button>
            <button
              onClick={() => setShowInspector(!showInspector)}
              className={`px-3 py-2 rounded-lg transition-colors ${
                showInspector
                  ? 'bg-primary-100 text-primary-700'
                  : 'text-gray-700 hover:bg-gray-100'
              }`}
              title="Toggle Inspector"
            >
              Inspector
            </button>
            <button
              onClick={() => setShowYamlPreview(!showYamlPreview)}
              className={`px-3 py-2 rounded-lg transition-colors ${
                showYamlPreview
                  ? 'bg-primary-100 text-primary-700'
                  : 'text-gray-700 hover:bg-gray-100'
              }`}
              title="Toggle YAML Preview"
            >
              YAML
            </button>
            <button
              onClick={() => setShowAIAssistant(!showAIAssistant)}
              className={`px-3 py-2 rounded-lg transition-colors ${
                showAIAssistant
                  ? 'bg-primary-100 text-primary-700'
                  : 'text-gray-700 hover:bg-gray-100'
              }`}
              title="Toggle AI Assistant"
            >
              AI Chat
            </button>
            <div className="h-6 border-l border-gray-300" />
            <button
              onClick={() => setShowVarsEditor(true)}
              className={`px-3 py-2 rounded-lg transition-colors ${
                Object.keys(vars).length > 0
                  ? 'bg-green-100 text-green-700'
                  : 'text-gray-700 hover:bg-gray-100'
              }`}
              title="Edit Flow Variables"
            >
              Variables {Object.keys(vars).length > 0 && `(${Object.keys(vars).length})`}
            </button>
            <div className="h-6 border-l border-gray-300" />
            <button
              onClick={() => navigate('/')}
              className="px-4 py-2 text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleSaveDraft}
              disabled={saveFlow.isPending}
              className="px-4 py-2 bg-gray-200 text-gray-700 hover:bg-gray-300 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {saveFlow.isPending ? 'Saving...' : 'Save Draft'}
            </button>
            <button
              onClick={handleDeployAndRun}
              disabled={saveFlow.isPending || deployFlow.isPending || startRun.isPending}
              className="px-4 py-2 bg-primary-600 text-white hover:bg-primary-700 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {saveFlow.isPending || deployFlow.isPending || startRun.isPending
                ? 'Processing...'
                : 'Deploy & Run'}
            </button>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Tools Palette */}
        {showToolsPalette && (
          <div className="relative flex">
            <div
              className="bg-white overflow-auto"
              style={{ width: actualToolsPaletteWidth }}
            >
              <ToolsPalette onToolSelect={handleToolSelect} />
            </div>
            <div
              onMouseDown={handleToolsPaletteResize}
              className="w-1 hover:w-1.5 bg-gray-200 hover:bg-primary-400 cursor-col-resize transition-all"
            />
          </div>
        )}

        {/* Inspector Panel */}
        {showInspector && (
          <div className="relative flex">
            <div
              className="bg-white overflow-auto"
              style={{ width: actualInspectorWidth }}
            >
              <Inspector />
            </div>
            <div
              onMouseDown={handleInspectorResize}
              className="w-1 hover:w-1.5 bg-gray-200 hover:bg-primary-400 cursor-col-resize transition-all"
            />
          </div>
        )}

        {/* Canvas */}
        <div className="flex-1 bg-gray-50" style={{ width: `calc(100% - ${actualToolsPaletteWidth + actualInspectorWidth + actualYamlPreviewWidth + actualAIAssistantWidth}px)` }}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onNodeClick={handleNodeClick}
            onPaneClick={handlePaneClick}
            onSelectionChange={handleSelectionChange}
            nodeTypes={nodeTypes}
            defaultEdgeOptions={{
              animated: true,
              style: { stroke: '#6366f1', strokeWidth: 2 },
            }}
            fitView
            className="bg-gray-50"
          >
            <Background color="#e5e7eb" gap={16} />
            <Controls />
            <MiniMap />

            {/* Toolbar Panel */}
            <Panel position="top-left" className="bg-white rounded-lg shadow-lg p-2 space-x-2">
              <button
                onClick={handleAddStep}
                className="px-3 py-2 bg-primary-600 text-white rounded hover:bg-primary-700 transition-colors text-sm font-medium"
              >
                + Add Step
              </button>
              <button
                onClick={clearCanvas}
                disabled={nodes.length <= 1}
                className="px-3 py-2 bg-gray-200 text-gray-700 rounded hover:bg-gray-300 transition-colors text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Clear
              </button>
            </Panel>

            {/* Empty State */}
            {nodes.filter(n => n.type === 'step').length === 0 && (
              <Panel position="top-center" className="pointer-events-none" style={{ zIndex: 0 }}>
                <div className="text-center" style={{ marginTop: '100px' }}>
                  <h3 className="text-xl font-semibold text-gray-900 mb-2">
                    Start Building Your Workflow
                  </h3>
                  <p className="text-gray-600">
                    Click "Add Step" to add your first node
                  </p>
                </div>
              </Panel>
            )}
          </ReactFlow>
        </div>

        {/* YAML Preview Panel */}
        {showYamlPreview && (
          <div className="relative flex">
            <div
              onMouseDown={handleYamlPreviewResize}
              className="w-1 hover:w-1.5 bg-gray-200 hover:bg-primary-400 cursor-col-resize transition-all"
            />
            <div
              className="overflow-auto"
              style={{ width: actualYamlPreviewWidth }}
            >
              <YamlPreview
                flowName={flowName}
                description={description}
                vars={vars}
                cron={cron}
                onMetadataUpdate={(metadata) => {
                  setFlowName(metadata.name);
                  setDescription(metadata.description || '');
                  setVars(metadata.vars || {});
                  setCron(metadata.cron || '');
                }}
              />
            </div>
          </div>
        )}

        {/* AI Assistant Panel */}
        {showAIAssistant && (
          <div className="relative flex">
            <div
              onMouseDown={handleAIAssistantResize}
              className="w-1 hover:w-1.5 bg-gray-200 hover:bg-primary-400 cursor-col-resize transition-all"
            />
            <div
              className="overflow-auto"
              style={{ width: actualAIAssistantWidth }}
            >
              <AIAssistant
                flowName={flowName}
                currentFlow={graphToFlow(nodes, edges, { name: flowName, description })}
              />
            </div>
          </div>
        )}
      </div>

      {/* Vars Editor Modal */}
      {showVarsEditor && (
        <VarsEditor
          vars={vars}
          onChange={setVars}
          onClose={() => setShowVarsEditor(false)}
        />
      )}
    </div>
  );
}
