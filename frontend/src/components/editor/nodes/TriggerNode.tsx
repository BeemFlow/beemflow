import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';

export interface TriggerNodeData {
  trigger: string | string[];
  label?: string;
}

export const TriggerNode = memo(({ data, selected }: NodeProps) => {
  const triggerData = data as unknown as TriggerNodeData;
  const triggers = Array.isArray(triggerData.trigger) ? triggerData.trigger : [triggerData.trigger];

  const getTriggerIcon = (trigger: string) => {
    if (trigger.includes('cli')) return '⌨️';
    if (trigger.includes('http') || trigger.includes('webhook')) return '🌐';
    if (trigger.includes('schedule') || trigger.includes('cron')) return '⏰';
    return '▶️';
  };

  const getTriggerLabel = (trigger: string) => {
    if (trigger.includes('cli.manual')) return 'Manual';
    if (trigger.includes('http.webhook')) return 'Webhook';
    if (trigger.includes('schedule.cron')) return 'Cron';
    if (trigger.includes('cron.')) return 'Cron';
    return trigger;
  };

  return (
    <div
      className={`px-4 py-3 shadow-lg rounded-lg border-2 bg-gradient-to-br from-green-50 to-emerald-50 min-w-[200px] ${
        selected ? 'border-green-500' : 'border-green-300'
      }`}
    >
      <div className="flex items-center space-x-2">
        <div className="text-2xl">{getTriggerIcon(triggers[0])}</div>
        <div className="flex-1">
          <div className="text-xs text-green-600 font-semibold uppercase">Trigger</div>
          {triggers.length === 1 ? (
            <div className="text-sm font-semibold text-gray-900">
              {getTriggerLabel(triggers[0])}
            </div>
          ) : (
            <div className="text-xs text-gray-900">
              {triggers.map(t => getTriggerLabel(t)).join(' + ')}
            </div>
          )}
        </div>
      </div>

      <Handle
        type="source"
        position={Position.Bottom}
        className="w-3 h-3 !bg-green-500"
      />
    </div>
  );
});

TriggerNode.displayName = 'TriggerNode';
