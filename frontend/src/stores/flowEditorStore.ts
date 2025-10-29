import { create } from 'zustand';
import type { Node, Edge, NodeChange, EdgeChange, Connection, NodeRemoveChange } from '@xyflow/react';
import { applyNodeChanges, applyEdgeChanges, addEdge } from '@xyflow/react';

interface FlowEditorState {
  nodes: Node[];
  edges: Edge[];
  selectedNode: Node | null;

  // Actions
  setNodes: (nodes: Node[]) => void;
  setEdges: (edges: Edge[]) => void;
  onNodesChange: (changes: NodeChange[]) => void;
  onEdgesChange: (changes: EdgeChange[]) => void;
  onConnect: (connection: Connection) => void;
  addNode: (node: Node) => void;
  updateNode: (nodeId: string, data: Partial<Node['data']>) => void;
  deleteNode: (nodeId: string) => void;
  selectNode: (node: Node | null) => void;
  clearCanvas: () => void;
}

export const useFlowEditorStore = create<FlowEditorState>((set, get) => ({
  nodes: [],
  edges: [],
  selectedNode: null,

  setNodes: (nodes) => set({ nodes }),

  setEdges: (edges) => set({ edges }),

  onNodesChange: (changes) => {
    const state = get();
    const newNodes = applyNodeChanges(changes, state.nodes);

    // Check if any nodes were removed that match the selected node
    const removedNodeIds = changes
      .filter((change): change is NodeRemoveChange => change.type === 'remove')
      .map((change) => change.id);

    const shouldClearSelection = state.selectedNode && removedNodeIds.includes(state.selectedNode.id);

    set({
      nodes: newNodes,
      selectedNode: shouldClearSelection ? null : state.selectedNode,
    });
  },

  onEdgesChange: (changes) => {
    set({
      edges: applyEdgeChanges(changes, get().edges),
    });
  },

  onConnect: (connection) => {
    set({
      edges: addEdge(connection, get().edges),
    });
  },

  addNode: (node) => {
    set({
      nodes: [...get().nodes, node],
    });
  },

  updateNode: (nodeId, data) => {
    const state = get();
    const updatedNodes = state.nodes.map((node) =>
      node.id === nodeId
        ? { ...node, data: { ...node.data, ...data } }
        : node
    );

    // If the updated node is currently selected, update selectedNode too
    const updatedSelectedNode = state.selectedNode?.id === nodeId
      ? updatedNodes.find((node) => node.id === nodeId) || null
      : state.selectedNode;

    set({
      nodes: updatedNodes,
      selectedNode: updatedSelectedNode,
    });
  },

  deleteNode: (nodeId) => {
    const state = get();
    set({
      nodes: state.nodes.filter((node) => node.id !== nodeId),
      edges: state.edges.filter(
        (edge) => edge.source !== nodeId && edge.target !== nodeId
      ),
      // Clear selection if the deleted node was selected
      selectedNode: state.selectedNode?.id === nodeId ? null : state.selectedNode,
    });
  },

  selectNode: (node) => set({ selectedNode: node }),

  clearCanvas: () => set({ nodes: [], edges: [], selectedNode: null }),
}));
