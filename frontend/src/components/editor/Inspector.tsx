import { useState, useEffect } from 'react';
import { useFlowEditorStore } from '../../stores/flowEditorStore';
import { ParameterEditor } from './ParameterEditor';
import { NestedStepEditor } from './NestedStepEditor';
import type { Step, Trigger } from '../../types/beemflow';

interface StepNodeData {
  step: Step;
}

interface TriggerNodeData {
  trigger: Trigger;
  cronExpression?: string;
}

export function Inspector() {
  const { selectedNode, updateNode, deleteNode } = useFlowEditorStore();
  const [step, setStep] = useState<Step | null>(null);

  useEffect(() => {
    if (selectedNode?.type === 'step') {
      const stepData = selectedNode.data as unknown as StepNodeData;
      setStep(stepData.step);
    } else {
      setStep(null);
    }
  }, [selectedNode]);

  if (!selectedNode) {
    return (
      <div className="h-full flex items-center justify-center p-6 text-center text-gray-500">
        <div>
          <div className="text-4xl mb-2">👆</div>
          <p className="text-sm">Select a node to configure</p>
        </div>
      </div>
    );
  }

  if (selectedNode.type === 'trigger') {
    const triggerData = selectedNode.data as unknown as TriggerNodeData;
    const triggerValue = triggerData.trigger;
    const triggers = Array.isArray(triggerValue) ? triggerValue : [triggerValue];
    const hasCronTrigger = triggers.some((t: string) =>
      t.includes('schedule.cron') || t.includes('cron.')
    );

    return (
      <div className="p-4 space-y-4">
        <h3 className="font-semibold text-gray-900">Trigger Configuration</h3>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Trigger Type
          </label>
          <select
            value={typeof triggerData.trigger === 'string' ? triggerData.trigger : triggerData.trigger[0]}
            onChange={(e) => updateNode(selectedNode.id, { trigger: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
          >
            <option value="cli.manual">Manual (CLI)</option>
            <option value="http.webhook">HTTP Webhook</option>
            <option value="schedule.cron">Scheduled (Cron)</option>
          </select>
        </div>

        {hasCronTrigger && (
          <div className="p-3 bg-blue-50 rounded-lg border border-blue-200">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Cron Expression
            </label>
            <input
              type="text"
              value={triggerData.cronExpression || ''}
              onChange={(e) => updateNode(selectedNode.id, { cronExpression: e.target.value })}
              placeholder="*/5 * * * *"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 font-mono text-sm"
            />
            <p className="mt-2 text-xs text-gray-600">
              Standard cron format: minute hour day month weekday
            </p>
            <p className="mt-1 text-xs text-gray-500">
              (Seconds field will be added automatically as 0)
            </p>
            <div className="mt-2 text-xs text-gray-500">
              Examples:
              <ul className="mt-1 space-y-0.5 ml-3">
                <li>• <code className="bg-white px-1 rounded">*/5 * * * *</code> - Every 5 minutes</li>
                <li>• <code className="bg-white px-1 rounded">0 */2 * * *</code> - Every 2 hours</li>
                <li>• <code className="bg-white px-1 rounded">0 9 * * 1-5</code> - 9 AM on weekdays</li>
              </ul>
            </div>
          </div>
        )}
      </div>
    );
  }

  if (!step) return null;

  const handleUpdateStep = (updates: Partial<Step>) => {
    const newStep = { ...step, ...updates };
    setStep(newStep);
    updateNode(selectedNode.id, { step: newStep });
  };

  return (
    <div className="h-full overflow-auto p-4 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-gray-900">Step Configuration</h3>
        <button
          onClick={() => deleteNode(selectedNode.id)}
          className="px-2 py-1 text-xs text-red-600 hover:bg-red-50 rounded transition-colors"
        >
          🗑️ Delete
        </button>
      </div>

      {/* Step ID */}
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Step ID
        </label>
        <input
          type="text"
          value={step.id}
          onChange={(e) => handleUpdateStep({ id: e.target.value })}
          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
        />
      </div>

      {/* Tool Selection */}
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Tool
        </label>
        <input
          type="text"
          value={step.use || ''}
          onChange={(e) => handleUpdateStep({ use: e.target.value })}
          placeholder="e.g., core.echo, openai.chat_completion"
          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
        />
        <p className="mt-1 text-xs text-gray-500">
          Common tools: core.echo, http.fetch, openai.chat_completion
        </p>
      </div>

      {/* Parameters (with) */}
      <div>
        <ParameterEditor
          toolName={step.use}
          parameters={step.with || {}}
          onChange={(params) => handleUpdateStep({ with: params })}
        />
      </div>

      {/* Conditional (if) */}
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Condition (if)
        </label>
        <textarea
          value={step.if || ''}
          onChange={(e) => handleUpdateStep({ if: e.target.value })}
          placeholder='e.g., {{ outputs.previous_step.status == "success" }}'
          rows={Math.max(2, Math.min((step.if || '').split('\n').length + 1, 6))}
          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500 font-mono text-sm resize-y"
        />
        <p className="mt-1 text-xs text-gray-500">
          Leave empty to always execute. Supports Jinja2 syntax with {'{{ }}'} or {'{%  %}'}
        </p>
      </div>

      {/* Foreach Loop Configuration */}
      <div className="pt-4 border-t border-gray-200">
        <div className="flex items-center justify-between mb-2">
          <label className="block text-sm font-medium text-gray-700">
            For Each Loop
          </label>
          <button
            onClick={() => {
              if (step.foreach) {
                handleUpdateStep({ foreach: undefined, as: undefined, do: undefined });
              } else {
                handleUpdateStep({
                  foreach: '{{ items }}',
                  as: 'item',
                  do: [],
                });
              }
            }}
            className={`px-2 py-1 text-xs rounded ${
              step.foreach
                ? 'bg-orange-100 text-orange-700'
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
          >
            {step.foreach ? 'Disable' : 'Enable'}
          </button>
        </div>
        {step.foreach && (
          <div className="space-y-3 p-3 bg-orange-50 rounded-lg border border-orange-200">
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                Iterate Over (foreach)
              </label>
              <textarea
                value={step.foreach}
                onChange={(e) => handleUpdateStep({ foreach: e.target.value })}
                rows={2}
                placeholder='e.g., {{ items }}, {{ outputs.previous_step.results }}'
                className="w-full px-2 py-1 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-orange-500 font-mono resize-y"
              />
              <p className="mt-1 text-xs text-gray-500">
                Expression that returns an array to loop over
              </p>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                Item Variable Name (as)
              </label>
              <input
                type="text"
                value={step.as || ''}
                onChange={(e) => handleUpdateStep({ as: e.target.value })}
                placeholder="e.g., item, row, user"
                className="w-full px-2 py-1 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-orange-500"
              />
              <p className="mt-1 text-xs text-gray-500">
                Variable name to use for each item (accessible as {'{{ ' + (step.as || 'item') + ' }}'})
              </p>
            </div>
            <NestedStepEditor
              steps={step.do || []}
              onStepsChange={(newSteps) => handleUpdateStep({ do: newSteps })}
              itemVariableName={step.as || 'item'}
            />
          </div>
        )}
      </div>

      {/* Await Event Configuration */}
      <div className="pt-4 border-t border-gray-200">
        <div className="flex items-center justify-between mb-2">
          <label className="block text-sm font-medium text-gray-700">
            Await Event
          </label>
          <button
            onClick={() => {
              if (step.await_event) {
                handleUpdateStep({ await_event: undefined, use: 'core.echo', with: { text: 'Hello' } });
              } else {
                handleUpdateStep({
                  await_event: { source: 'slack', match: {}, timeout: '1h' },
                  use: undefined,
                  with: undefined
                });
              }
            }}
            className={`px-2 py-1 text-xs rounded ${
              step.await_event
                ? 'bg-purple-100 text-purple-700'
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
          >
            {step.await_event ? 'Disable' : 'Enable'}
          </button>
        </div>

        {step.await_event && (
          <div className="space-y-3 p-3 bg-purple-50 rounded-lg border border-purple-200">
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                Event Source
              </label>
              <input
                type="text"
                value={step.await_event.source}
                onChange={(e) =>
                  handleUpdateStep({
                    await_event: { ...step.await_event!, source: e.target.value },
                  })
                }
                placeholder="e.g., slack, airtable, twilio"
                className="w-full px-2 py-1 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-purple-500"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                Match Criteria (JSON)
              </label>
              <textarea
                value={JSON.stringify(step.await_event.match || {}, null, 2)}
                onChange={(e) => {
                  try {
                    const parsed = JSON.parse(e.target.value);
                    handleUpdateStep({
                      await_event: { ...step.await_event!, match: parsed },
                    });
                  } catch {
                    // Invalid JSON, don't update
                  }
                }}
                rows={4}
                className="w-full px-2 py-1 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-purple-500 font-mono"
                placeholder='{"token": "{{ vars.token }}"}'
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                Timeout (optional)
              </label>
              <input
                type="text"
                value={step.await_event.timeout || ''}
                onChange={(e) =>
                  handleUpdateStep({
                    await_event: { ...step.await_event!, timeout: e.target.value || undefined },
                  })
                }
                placeholder="e.g., 1h, 30m, 2d"
                className="w-full px-2 py-1 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-purple-500"
              />
            </div>
          </div>
        )}
      </div>

      {/* Quick Actions */}
      <div className="pt-4 border-t border-gray-200">
        <h4 className="text-sm font-medium text-gray-700 mb-2">Quick Setup</h4>
        <div className="space-y-2">
          <button
            onClick={() => {
              handleUpdateStep({
                use: 'core.echo',
                with: { text: 'Hello World' },
              });
            }}
            className="w-full px-3 py-2 text-sm bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors text-left"
          >
            Echo Text
          </button>
          <button
            onClick={() => {
              handleUpdateStep({
                use: 'http.fetch',
                with: { url: 'https://api.example.com' },
              });
            }}
            className="w-full px-3 py-2 text-sm bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors text-left"
          >
            HTTP Fetch
          </button>
          <button
            onClick={() => {
              handleUpdateStep({
                use: 'openai.chat_completion',
                with: {
                  model: 'gpt-4o',
                  messages: [{ role: 'user', content: 'Hello!' }],
                },
              });
            }}
            className="w-full px-3 py-2 text-sm bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors text-left"
          >
            OpenAI Chat
          </button>
        </div>
      </div>
    </div>
  );
}
