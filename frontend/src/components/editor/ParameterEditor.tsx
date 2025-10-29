import { useState, useEffect } from 'react';
import { useTool } from '../../hooks/useTools';
import { JsonTreeEditor } from './JsonTreeEditor';
import type { JsonSchema, JsonSchemaProperty, JsonValue } from '../../types/beemflow';

interface ParameterEditorProps {
  toolName?: string;
  parameters: Record<string, JsonValue>;
  onChange: (parameters: Record<string, JsonValue>) => void;
}

export function ParameterEditor({ toolName, parameters, onChange }: ParameterEditorProps) {
  const { data: tool } = useTool(toolName);
  const [viewMode, setViewMode] = useState<'form' | 'json'>('form');
  const [jsonValue, setJsonValue] = useState('');
  const [jsonError, setJsonError] = useState<string | null>(null);

  // Update JSON value when parameters change in form mode
  useEffect(() => {
    if (viewMode === 'form') {
      setJsonValue(JSON.stringify(parameters, null, 2));
    }
  }, [parameters, viewMode]);

  const schema = tool?.parameters as JsonSchema | undefined;

  const handleParameterChange = (key: string, value: JsonValue) => {
    onChange({ ...parameters, [key]: value });
  };

  const handleRemoveParameter = (key: string) => {
    const newParams = { ...parameters };
    delete newParams[key];
    onChange(newParams);
  };

  const handleJsonChange = (value: string) => {
    setJsonValue(value);
    try {
      const parsed = JSON.parse(value);
      setJsonError(null);
      onChange(parsed);
    } catch (err) {
      setJsonError((err as Error).message);
    }
  };

  const renderParameterInput = (key: string, prop: JsonSchemaProperty, value: JsonValue) => {
    const isRequired = schema?.required?.includes(key);

    // Handle different types
    if (prop.enum) {
      // Select dropdown for enums
      const stringValue = typeof value === 'string' ? value : String(value ?? prop.default ?? '');
      return (
        <select
          value={stringValue}
          onChange={(e) => handleParameterChange(key, e.target.value)}
          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
        >
          {!isRequired && <option value="">None</option>}
          {prop.enum.map((option) => (
            <option key={String(option)} value={String(option)}>
              {String(option)}
            </option>
          ))}
        </select>
      );
    }

    if (prop.type === 'boolean') {
      // Checkbox for booleans
      const boolValue = typeof value === 'boolean' ? value : Boolean(prop.default ?? false);
      return (
        <label className="flex items-center space-x-2 cursor-pointer">
          <input
            type="checkbox"
            checked={boolValue}
            onChange={(e) => handleParameterChange(key, e.target.checked)}
            className="w-4 h-4 text-primary-600 border-gray-300 rounded focus:ring-primary-500"
          />
          <span className="text-sm text-gray-700">
            {boolValue ? 'Enabled' : 'Disabled'}
          </span>
        </label>
      );
    }

    if (prop.type === 'number' || prop.type === 'integer') {
      // Number input
      const numValue = typeof value === 'number' ? value : (typeof prop.default === 'number' ? prop.default : '');
      return (
        <input
          type="number"
          value={numValue}
          onChange={(e) => handleParameterChange(key, parseFloat(e.target.value))}
          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
          placeholder={prop.description || `Enter ${key}`}
        />
      );
    }

    if (prop.type === 'object' || prop.type === 'array') {
      // Use JsonTreeEditor component for complex types
      const defaultValue = prop.type === 'array' ? [] : {};
      return (
        <JsonTreeEditor
          value={value ?? prop.default ?? defaultValue}
          onChange={(val) => handleParameterChange(key, val)}
          type={prop.type}
        />
      );
    }

    // Default: multi-line text input (handles string and template expressions)
    // Calculate optimal row height based on content
    const stringValue = typeof value === 'string' ? value : (typeof prop.default === 'string' ? prop.default : '');
    const calculateRows = () => {
      const lineCount = stringValue.split('\n').length;
      return Math.max(3, Math.min(lineCount + 1, 10)); // Min 3, max 10 rows
    };

    return (
      <textarea
        value={stringValue}
        onChange={(e) => handleParameterChange(key, e.target.value)}
        rows={calculateRows()}
        className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500 font-mono text-sm resize-y"
        placeholder={prop.description || `Enter ${key}`}
      />
    );
  };

  if (viewMode === 'json') {
    return (
      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="block text-sm font-medium text-gray-700">
            Parameters (JSON)
          </label>
          <button
            onClick={() => setViewMode('form')}
            className="text-xs text-primary-600 hover:text-primary-700"
          >
            Switch to Form
          </button>
        </div>
        <textarea
          value={jsonValue}
          onChange={(e) => handleJsonChange(e.target.value)}
          rows={6}
          className={`w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-primary-500 font-mono text-sm ${
            jsonError ? 'border-red-300 bg-red-50' : 'border-gray-300'
          }`}
          placeholder='{"key": "value"}'
        />
        {jsonError && (
          <p className="mt-1 text-xs text-red-600">Invalid JSON: {jsonError}</p>
        )}
      </div>
    );
  }

  // Form mode
  const properties = schema?.properties || {};
  const parameterKeys = Object.keys(parameters);
  const schemaKeys = Object.keys(properties);

  // Combine schema keys with any extra keys in current parameters
  const allKeys = Array.from(new Set([...schemaKeys, ...parameterKeys]));

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <label className="block text-sm font-medium text-gray-700">
          Parameters
        </label>
        <button
          onClick={() => setViewMode('json')}
          className="text-xs text-gray-600 hover:text-gray-700"
        >
          Switch to JSON
        </button>
      </div>

      {allKeys.length === 0 ? (
        <div className="text-sm text-gray-500 italic py-2">
          No parameters configured
        </div>
      ) : (
        <div className="space-y-3">
          {allKeys.map((key) => {
            const prop = properties[key];
            const value = parameters[key];
            const isRequired = schema?.required?.includes(key);
            const isInSchema = !!prop;

            return (
              <div key={key} className="border border-gray-200 rounded-lg p-3 bg-gray-50">
                <div className="flex items-start justify-between mb-1">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2">
                      <label className="text-sm font-medium text-gray-900">
                        {key}
                      </label>
                      {isRequired && (
                        <span className="text-xs text-red-600 font-semibold">*</span>
                      )}
                      {!isInSchema && (
                        <span className="text-xs text-amber-600 bg-amber-50 px-1.5 py-0.5 rounded">
                          custom
                        </span>
                      )}
                    </div>
                    {prop?.description && (
                      <p className="text-xs text-gray-500 mt-0.5">
                        {prop.description}
                      </p>
                    )}
                  </div>
                  {!isRequired && (
                    <button
                      onClick={() => handleRemoveParameter(key)}
                      className="text-xs text-red-600 hover:text-red-700"
                      title="Remove parameter"
                    >
                      ✕
                    </button>
                  )}
                </div>
                <div className="mt-2">
                  {prop ? (
                    renderParameterInput(key, prop, value)
                  ) : (
                    // For custom parameters not in schema, show text input
                    <input
                      type="text"
                      value={typeof value === 'string' ? value : String(value ?? '')}
                      onChange={(e) => handleParameterChange(key, e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500 text-sm"
                    />
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Add custom parameter button */}
      <button
        onClick={() => {
          const newKey = prompt('Enter parameter name:');
          if (newKey && !allKeys.includes(newKey)) {
            handleParameterChange(newKey, '');
          }
        }}
        className="mt-3 w-full px-3 py-2 text-sm bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg transition-colors"
      >
        + Add Custom Parameter
      </button>
    </div>
  );
}
