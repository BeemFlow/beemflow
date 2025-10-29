import { useState, useEffect } from 'react';

interface CronExpressionBuilderProps {
  value: string;
  onChange: (cronExpression: string) => void;
}

type PresetType = 'every_minute' | 'every_5_min' | 'every_15_min' | 'every_30_min' | 'hourly' | 'daily' | 'weekly' | 'monthly' | 'custom';

interface CronPreset {
  label: string;
  value: string;
  description: string;
}

const PRESETS: Record<PresetType, CronPreset> = {
  every_minute: { label: 'Every minute', value: '* * * * *', description: 'Runs every minute' },
  every_5_min: { label: 'Every 5 minutes', value: '*/5 * * * *', description: 'Runs every 5 minutes' },
  every_15_min: { label: 'Every 15 minutes', value: '*/15 * * * *', description: 'Runs every 15 minutes' },
  every_30_min: { label: 'Every 30 minutes', value: '*/30 * * * *', description: 'Runs every 30 minutes' },
  hourly: { label: 'Every hour', value: '0 * * * *', description: 'Runs at the start of every hour' },
  daily: { label: 'Daily', value: '0 9 * * *', description: 'Runs every day at 9:00 AM' },
  weekly: { label: 'Weekly', value: '0 9 * * 1', description: 'Runs every Monday at 9:00 AM' },
  monthly: { label: 'Monthly', value: '0 9 1 * *', description: 'Runs on the 1st of every month at 9:00 AM' },
  custom: { label: 'Custom', value: '', description: 'Enter your own cron expression' },
};

export function CronExpressionBuilder({ value, onChange }: CronExpressionBuilderProps) {
  const [mode, setMode] = useState<'preset' | 'custom'>('preset');
  const [selectedPreset, setSelectedPreset] = useState<PresetType>('every_5_min');
  const [customExpression, setCustomExpression] = useState(value);

  // Custom mode state
  const [minute, setMinute] = useState('*');
  const [hour, setHour] = useState('*');
  const [dayOfMonth, setDayOfMonth] = useState('*');
  const [month, setMonth] = useState('*');
  const [dayOfWeek, setDayOfWeek] = useState('*');

  // Initialize from existing value
  useEffect(() => {
    if (value) {
      // Check if value matches a preset
      const matchingPreset = Object.entries(PRESETS).find(
        ([, preset]) => preset.value === value
      );

      if (matchingPreset) {
        setMode('preset');
        setSelectedPreset(matchingPreset[0] as PresetType);
      } else {
        setMode('custom');
        setCustomExpression(value);

        // Parse the cron expression
        const parts = value.split(' ');
        if (parts.length >= 5) {
          setMinute(parts[0]);
          setHour(parts[1]);
          setDayOfMonth(parts[2]);
          setMonth(parts[3]);
          setDayOfWeek(parts[4]);
        }
      }
    }
  }, [value]);

  const handlePresetChange = (preset: PresetType) => {
    setSelectedPreset(preset);
    if (preset !== 'custom') {
      onChange(PRESETS[preset].value);
    } else {
      setMode('custom');
    }
  };

  const handleCustomExpressionChange = (expr: string) => {
    setCustomExpression(expr);
    onChange(expr);
  };

  const buildCustomExpression = () => {
    return `${minute} ${hour} ${dayOfMonth} ${month} ${dayOfWeek}`;
  };

  const applyCustomFields = () => {
    const expr = buildCustomExpression();
    setCustomExpression(expr);
    onChange(expr);
  };

  return (
    <div className="space-y-3">
      {/* Mode Toggle */}
      <div className="flex gap-2">
        <button
          type="button"
          onClick={() => setMode('preset')}
          className={`flex-1 px-3 py-2 text-sm rounded transition-colors ${
            mode === 'preset'
              ? 'bg-blue-100 text-blue-700 border border-blue-300'
              : 'bg-gray-100 text-gray-700 border border-gray-300 hover:bg-gray-200'
          }`}
        >
          📋 Preset
        </button>
        <button
          type="button"
          onClick={() => setMode('custom')}
          className={`flex-1 px-3 py-2 text-sm rounded transition-colors ${
            mode === 'custom'
              ? 'bg-blue-100 text-blue-700 border border-blue-300'
              : 'bg-gray-100 text-gray-700 border border-gray-300 hover:bg-gray-200'
          }`}
        >
          ⚙️ Custom
        </button>
      </div>

      {/* Preset Mode */}
      {mode === 'preset' && (
        <div className="space-y-2">
          <label className="block text-xs font-medium text-gray-700">
            Choose a schedule
          </label>
          <select
            value={selectedPreset}
            onChange={(e) => handlePresetChange(e.target.value as PresetType)}
            className="w-full px-3 py-2 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-blue-500"
          >
            {Object.entries(PRESETS).filter(([key]) => key !== 'custom').map(([key, preset]) => (
              <option key={key} value={key}>
                {preset.label} - {preset.description}
              </option>
            ))}
          </select>

          <div className="p-2 bg-blue-50 rounded border border-blue-200">
            <div className="text-xs font-mono text-blue-900">
              {PRESETS[selectedPreset].value}
            </div>
            <div className="text-xs text-blue-700 mt-1">
              {PRESETS[selectedPreset].description}
            </div>
          </div>
        </div>
      )}

      {/* Custom Mode */}
      {mode === 'custom' && (
        <div className="space-y-3">
          <div className="grid grid-cols-5 gap-2">
            {/* Minute */}
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                Minute
              </label>
              <input
                type="text"
                value={minute}
                onChange={(e) => setMinute(e.target.value)}
                onBlur={applyCustomFields}
                placeholder="*"
                className="w-full px-2 py-1 text-xs border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 font-mono"
              />
              <div className="text-xs text-gray-500 mt-1">0-59</div>
            </div>

            {/* Hour */}
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                Hour
              </label>
              <input
                type="text"
                value={hour}
                onChange={(e) => setHour(e.target.value)}
                onBlur={applyCustomFields}
                placeholder="*"
                className="w-full px-2 py-1 text-xs border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 font-mono"
              />
              <div className="text-xs text-gray-500 mt-1">0-23</div>
            </div>

            {/* Day of Month */}
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                Day
              </label>
              <input
                type="text"
                value={dayOfMonth}
                onChange={(e) => setDayOfMonth(e.target.value)}
                onBlur={applyCustomFields}
                placeholder="*"
                className="w-full px-2 py-1 text-xs border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 font-mono"
              />
              <div className="text-xs text-gray-500 mt-1">1-31</div>
            </div>

            {/* Month */}
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                Month
              </label>
              <input
                type="text"
                value={month}
                onChange={(e) => setMonth(e.target.value)}
                onBlur={applyCustomFields}
                placeholder="*"
                className="w-full px-2 py-1 text-xs border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 font-mono"
              />
              <div className="text-xs text-gray-500 mt-1">1-12</div>
            </div>

            {/* Day of Week */}
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                Weekday
              </label>
              <input
                type="text"
                value={dayOfWeek}
                onChange={(e) => setDayOfWeek(e.target.value)}
                onBlur={applyCustomFields}
                placeholder="*"
                className="w-full px-2 py-1 text-xs border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 font-mono"
              />
              <div className="text-xs text-gray-500 mt-1">0-6</div>
            </div>
          </div>

          {/* Direct Expression Input */}
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">
              Or enter expression directly
            </label>
            <input
              type="text"
              value={customExpression}
              onChange={(e) => handleCustomExpressionChange(e.target.value)}
              placeholder="*/5 * * * *"
              className="w-full px-3 py-2 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 font-mono"
            />
          </div>

          {/* Help Text */}
          <div className="p-2 bg-gray-50 rounded border border-gray-200 text-xs text-gray-600 space-y-1">
            <div className="font-medium">Special characters:</div>
            <div>• <code className="bg-white px-1 rounded">*</code> = any value</div>
            <div>• <code className="bg-white px-1 rounded">*/5</code> = every 5 units</div>
            <div>• <code className="bg-white px-1 rounded">1-5</code> = range (1 through 5)</div>
            <div>• <code className="bg-white px-1 rounded">1,3,5</code> = specific values</div>
          </div>

          {/* Examples */}
          <details className="text-xs">
            <summary className="cursor-pointer text-gray-700 font-medium">
              Show examples
            </summary>
            <div className="mt-2 space-y-1 text-gray-600">
              <div>• <code className="bg-white px-1 rounded">*/5 * * * *</code> - Every 5 minutes</div>
              <div>• <code className="bg-white px-1 rounded">0 */2 * * *</code> - Every 2 hours</div>
              <div>• <code className="bg-white px-1 rounded">0 9 * * *</code> - Daily at 9 AM</div>
              <div>• <code className="bg-white px-1 rounded">0 9 * * 1-5</code> - Weekdays at 9 AM</div>
              <div>• <code className="bg-white px-1 rounded">0 0 1 * *</code> - 1st of every month</div>
            </div>
          </details>
        </div>
      )}

      {/* Note about seconds */}
      <div className="text-xs text-gray-500 italic">
        Note: Seconds field will be added automatically as 0
      </div>
    </div>
  );
}
