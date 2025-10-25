import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import type { Step } from '../../../types/beemflow';

export interface StepNodeData {
  step: Step;
  label?: string;
  layoutDirection?: 'TB' | 'LR';
}

export const StepNode = memo(({ data, selected }: NodeProps) => {
  const stepData = data as unknown as StepNodeData;
  const step = stepData.step;
  const layoutDirection = stepData.layoutDirection || 'TB';

  // Check if this is an await_event step
  const isAwaitEvent = !!step.await_event;

  // Set handle positions based on layout direction
  const targetPosition = layoutDirection === 'LR' ? Position.Left : Position.Top;
  const sourcePosition = layoutDirection === 'LR' ? Position.Right : Position.Bottom;

  return (
    <div
      className={`px-4 py-3 shadow-lg rounded-lg border-2 min-w-[200px] ${
        isAwaitEvent
          ? selected
            ? 'border-purple-500 bg-purple-50'
            : 'border-purple-300 bg-purple-50'
          : selected
          ? 'border-primary-500 bg-white'
          : 'border-gray-300 bg-white'
      }`}
    >
      <Handle
        type="target"
        position={targetPosition}
        className="w-3 h-3 bg-gray-400!"
      />

      <div className="flex items-center space-x-2">
        <div className="text-2xl">{isAwaitEvent ? '⏳' : '⚙️'}</div>
        <div className="flex-1">
          <div className="text-sm font-semibold text-gray-900">{step.id}</div>
          {isAwaitEvent && step.await_event ? (
            <div className="text-xs text-purple-600">
              await: {step.await_event.source}
            </div>
          ) : (
            <div className="text-xs text-gray-500">{step.use || 'No tool selected'}</div>
          )}
        </div>
      </div>

      {step.if && (
        <div className="mt-2 text-xs text-amber-600 font-mono truncate">
          if: {step.if}
        </div>
      )}

      {isAwaitEvent && step.await_event?.timeout && (
        <div className="mt-2 text-xs text-gray-500">
          timeout: {step.await_event.timeout}
        </div>
      )}

      <Handle
        type="source"
        position={sourcePosition}
        className="w-3 h-3 bg-gray-400!"
      />
    </div>
  );
});

StepNode.displayName = 'StepNode';
