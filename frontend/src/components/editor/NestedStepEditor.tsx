import { useState } from 'react';
import type { Step } from '../../types/beemflow';

interface NestedStepEditorProps {
  steps: Step[];
  onStepsChange: (steps: Step[]) => void;
  itemVariableName: string;
}

export function NestedStepEditor({ steps, onStepsChange, itemVariableName }: NestedStepEditorProps) {
  const [expandedSteps, setExpandedSteps] = useState<Set<number>>(new Set([0]));

  const toggleExpanded = (index: number) => {
    const newExpanded = new Set(expandedSteps);
    if (newExpanded.has(index)) {
      newExpanded.delete(index);
    } else {
      newExpanded.add(index);
    }
    setExpandedSteps(newExpanded);
  };

  const addStep = () => {
    const newStep: Step = {
      id: `step_${Date.now()}`,
      use: '',
    };
    const newSteps = [...steps, newStep];
    onStepsChange(newSteps);
    setExpandedSteps(new Set([...expandedSteps, steps.length]));
  };

  const updateStep = (index: number, updates: Partial<Step>) => {
    const newSteps = [...steps];
    newSteps[index] = { ...newSteps[index], ...updates };
    onStepsChange(newSteps);
  };

  const deleteStep = (index: number) => {
    const newSteps = steps.filter((_, i) => i !== index);
    onStepsChange(newSteps);
    const newExpanded = new Set(expandedSteps);
    newExpanded.delete(index);
    setExpandedSteps(newExpanded);
  };

  const moveStep = (index: number, direction: 'up' | 'down') => {
    if (
      (direction === 'up' && index === 0) ||
      (direction === 'down' && index === steps.length - 1)
    ) {
      return;
    }

    const newSteps = [...steps];
    const targetIndex = direction === 'up' ? index - 1 : index + 1;
    [newSteps[index], newSteps[targetIndex]] = [newSteps[targetIndex], newSteps[index]];
    onStepsChange(newSteps);
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <label className="block text-xs font-medium text-gray-700">
          Nested Steps ({steps.length})
        </label>
        <button
          onClick={addStep}
          className="px-2 py-1 text-xs bg-orange-500 text-white rounded hover:bg-orange-600 transition-colors"
        >
          + Add Step
        </button>
      </div>

      {steps.length === 0 ? (
        <div className="text-xs text-gray-500 bg-white p-3 rounded border border-orange-200 text-center">
          No nested steps yet. Click "+ Add Step" to add steps that will run for each item.
        </div>
      ) : (
        <div className="space-y-2">
          {steps.map((step, index) => (
            <div
              key={index}
              className="bg-white border border-orange-200 rounded-lg overflow-hidden"
            >
              {/* Step Header */}
              <div
                className="flex items-center justify-between p-2 bg-orange-50 cursor-pointer hover:bg-orange-100 transition-colors"
                onClick={() => toggleExpanded(index)}
              >
                <div className="flex items-center gap-2 flex-1 min-w-0">
                  <span className="text-xs text-gray-500">
                    {expandedSteps.has(index) ? '▼' : '▶'}
                  </span>
                  <span className="text-xs font-medium text-gray-900 truncate">
                    {step.id || `Step ${index + 1}`}
                  </span>
                  {step.use && (
                    <span className="text-xs text-gray-500 truncate">
                      ({step.use})
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                  <button
                    onClick={() => moveStep(index, 'up')}
                    disabled={index === 0}
                    className="p-1 text-xs text-gray-600 hover:text-gray-900 disabled:opacity-30 disabled:cursor-not-allowed"
                    title="Move up"
                  >
                    ↑
                  </button>
                  <button
                    onClick={() => moveStep(index, 'down')}
                    disabled={index === steps.length - 1}
                    className="p-1 text-xs text-gray-600 hover:text-gray-900 disabled:opacity-30 disabled:cursor-not-allowed"
                    title="Move down"
                  >
                    ↓
                  </button>
                  <button
                    onClick={() => deleteStep(index)}
                    className="p-1 text-xs text-red-600 hover:text-red-800"
                    title="Delete step"
                  >
                    🗑️
                  </button>
                </div>
              </div>

              {/* Step Details (Expandable) */}
              {expandedSteps.has(index) && (
                <div className="p-3 space-y-3 bg-white">
                  {/* Step ID */}
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1">
                      Step ID
                    </label>
                    <input
                      type="text"
                      value={step.id}
                      onChange={(e) => updateStep(index, { id: e.target.value })}
                      placeholder="step_name"
                      className="w-full px-2 py-1 text-xs border border-gray-300 rounded focus:ring-2 focus:ring-orange-500"
                    />
                  </div>

                  {/* Tool Selection */}
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1">
                      Tool
                    </label>
                    <input
                      type="text"
                      value={step.use || ''}
                      onChange={(e) => updateStep(index, { use: e.target.value })}
                      placeholder="e.g., core.echo, http.request"
                      className="w-full px-2 py-1 text-xs border border-gray-300 rounded focus:ring-2 focus:ring-orange-500 font-mono"
                    />
                    <p className="mt-1 text-xs text-gray-500">
                      Access current item as {'{{ ' + itemVariableName + ' }}'}
                    </p>
                  </div>

                  {/* Parameters */}
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1">
                      Parameters (JSON)
                    </label>
                    <textarea
                      value={step.with ? JSON.stringify(step.with, null, 2) : ''}
                      onChange={(e) => {
                        try {
                          const parsed = e.target.value ? JSON.parse(e.target.value) : undefined;
                          updateStep(index, { with: parsed });
                        } catch {
                          // Invalid JSON, don't update yet
                        }
                      }}
                      placeholder={`{\n  "message": "{{ ${itemVariableName} }}"\n}`}
                      rows={4}
                      className="w-full px-2 py-1 text-xs border border-gray-300 rounded focus:ring-2 focus:ring-orange-500 font-mono resize-y"
                    />
                    <p className="mt-1 text-xs text-gray-500">
                      Enter valid JSON for step parameters
                    </p>
                  </div>

                  {/* Condition */}
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1">
                      Condition (if) <span className="text-gray-400">- optional</span>
                    </label>
                    <input
                      type="text"
                      value={step.if || ''}
                      onChange={(e) => updateStep(index, { if: e.target.value || undefined })}
                      placeholder={`e.g., {{ ${itemVariableName}.status == "active" }}`}
                      className="w-full px-2 py-1 text-xs border border-gray-300 rounded focus:ring-2 focus:ring-orange-500 font-mono"
                    />
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      <div className="text-xs text-gray-500 bg-orange-50 p-2 rounded border border-orange-200">
        💡 <strong>Tip:</strong> These steps will run once for each item in the loop.
        Use <code className="bg-white px-1 rounded">{'{{ ' + itemVariableName + ' }}'}</code> to reference the current item.
      </div>
    </div>
  );
}
