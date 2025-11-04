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

  // Check if this is a foreach loop step
  const isForeachLoop = !!step.foreach;

  // Set handle positions based on layout direction
  const targetPosition = layoutDirection === 'LR' ? Position.Left : Position.Top;
  const sourcePosition = layoutDirection === 'LR' ? Position.Right : Position.Bottom;

  // Determine styling based on step type
  const getContainerClasses = () => {
    if (isForeachLoop) {
      return `px-4 py-3 shadow-lg rounded-lg border-2 min-w-[200px] ${
        selected ? 'border-orange-500 bg-orange-50' : 'border-orange-300 bg-orange-50'
      }`;
    }
    if (isAwaitEvent) {
      return `px-4 py-3 shadow-lg rounded-lg border-2 min-w-[200px] ${
        selected ? 'border-purple-500 bg-purple-50' : 'border-purple-300 bg-purple-50'
      }`;
    }
    return `px-4 py-3 shadow-lg rounded-lg border-2 min-w-[200px] ${
      selected ? 'border-primary-500 bg-white' : 'border-gray-300 bg-white'
    }`;
  };

  return (
    <div className={getContainerClasses()}>
      <Handle
        type="target"
        position={targetPosition}
        className="w-3 h-3 bg-gray-400!"
      />

      <div className="flex items-center space-x-2">
        <div className="text-2xl">
          {isForeachLoop ? '🔁' : isAwaitEvent ? '⏳' : '⚙️'}
        </div>
        <div className="flex-1">
          <div className="text-sm font-semibold text-gray-900">{step.id}</div>
          {isForeachLoop ? (
            <div className="text-xs text-orange-600">
              foreach: {step.as || 'item'}
            </div>
          ) : isAwaitEvent && step.await_event ? (
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

      {/* Foreach loop nested steps - Blockly style */}
      {isForeachLoop && step.do && step.do.length > 0 && (
        <div className="mt-3 border-l-4 border-orange-400 pl-3 space-y-1.5">
          <div className="text-xs font-semibold text-orange-700 mb-1.5">
            do ({step.do.length} step{step.do.length !== 1 ? 's' : ''}):
          </div>
          {step.do.map((nestedStep, index) => (
            <div
              key={index}
              className="bg-white bg-opacity-60 rounded px-2 py-1.5 border border-orange-200 hover:border-orange-400 transition-colors"
            >
              <div className="text-xs font-medium text-gray-800 truncate">
                {nestedStep.id}
              </div>
              {nestedStep.use && (
                <div className="text-xs text-gray-500 truncate">
                  {nestedStep.use}
                </div>
              )}
              {nestedStep.if && (
                <div className="text-xs text-amber-600 truncate font-mono">
                  if: {nestedStep.if}
                </div>
              )}
            </div>
          ))}
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
