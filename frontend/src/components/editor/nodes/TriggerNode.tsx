import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';

// Type for webhook trigger objects
interface WebhookTrigger {
  webhook: {
    topic: string;
  };
}

// Union type for all possible trigger formats
type TriggerValue = string | WebhookTrigger;

export interface TriggerNodeData {
  trigger: TriggerValue | TriggerValue[];
  label?: string;
  layoutDirection?: 'TB' | 'LR';
}

export const TriggerNode = memo(({ data, selected }: NodeProps) => {
  const triggerData = data as unknown as TriggerNodeData;
  const triggers = Array.isArray(triggerData.trigger) ? triggerData.trigger : [triggerData.trigger];
  const layoutDirection = triggerData.layoutDirection || 'TB';

  // Set handle position based on layout direction (trigger only has source handle)
  const sourcePosition = layoutDirection === 'LR' ? Position.Right : Position.Bottom;

  // Normalize trigger to string (handle both string and object formats)
  const normalizeTrigger = (trigger: TriggerValue): string => {
    if (typeof trigger === 'string') {
      return trigger;
    }
    if (typeof trigger === 'object' && trigger !== null) {
      // Handle webhook object: { webhook: { topic: "..." } }
      if (trigger.webhook) {
        return `webhook:${trigger.webhook.topic || 'unknown'}`;
      }
      // Handle other object formats - just stringify
      return JSON.stringify(trigger);
    }
    return String(trigger);
  };

  const getTriggerIcon = (trigger: TriggerValue) => {
    const triggerStr = normalizeTrigger(trigger);
    if (triggerStr.includes('cli')) return '⌨️';
    if (triggerStr.includes('http') || triggerStr.includes('webhook')) return '🌐';
    if (triggerStr.includes('schedule') || triggerStr.includes('cron')) return '⏰';
    return '▶️';
  };

  const getTriggerLabel = (trigger: TriggerValue) => {
    const triggerStr = normalizeTrigger(trigger);
    if (triggerStr.includes('cli.manual')) return 'Manual';
    if (triggerStr.includes('http.webhook')) return 'Webhook';
    if (triggerStr.includes('schedule.cron')) return 'Cron';
    if (triggerStr.includes('cron.')) return 'Cron';
    if (triggerStr.startsWith('webhook:')) {
      const topic = triggerStr.split(':')[1];
      return `Webhook: ${topic}`;
    }
    return triggerStr;
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
        position={sourcePosition}
        className="w-3 h-3 !bg-green-500"
      />
    </div>
  );
});

TriggerNode.displayName = 'TriggerNode';
