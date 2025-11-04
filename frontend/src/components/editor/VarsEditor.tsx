import { JsonTreeEditor } from './JsonTreeEditor';
import type { JsonValue } from '../../types/beemflow';

interface VarsEditorProps {
  vars: Record<string, JsonValue>;
  onChange: (vars: Record<string, JsonValue>) => void;
  onClose: () => void;
}

export function VarsEditor({ vars, onChange, onClose }: VarsEditorProps) {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl max-h-[80vh] flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-900">Flow Variables</h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 text-2xl leading-none"
          >
            ×
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto p-6">
          <p className="text-sm text-gray-600 mb-4">
            Define variables that can be referenced in your workflow steps using {'{{ vars.VARIABLE_NAME }}'} syntax.
          </p>
          <JsonTreeEditor
            value={vars}
            onChange={(value) => onChange(value as Record<string, JsonValue>)}
            type="object"
          />
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-gray-200 flex justify-end space-x-3">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
}
