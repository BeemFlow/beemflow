import { useState } from 'react';
import type { JsonValue } from '../../types/beemflow';

interface JsonTreeEditorProps {
  value: JsonValue;
  onChange: (value: JsonValue) => void;
  type: 'object' | 'array';
}

interface JsonNodeProps {
  keyName: string | number;
  value: JsonValue;
  onUpdate: (newValue: JsonValue) => void;
  onDelete: () => void;
  isRoot?: boolean;
  canDelete?: boolean;
}

function JsonNode({ keyName, value, onUpdate, onDelete, isRoot = false, canDelete = true }: JsonNodeProps) {
  const [isExpanded, setIsExpanded] = useState(true);
  const [isEditing, setIsEditing] = useState(false);
  const [editValue, setEditValue] = useState('');

  const valueType = Array.isArray(value) ? 'array' : typeof value;
  const isComplex = valueType === 'object' || valueType === 'array';

  const handleStartEdit = () => {
    setIsEditing(true);
    setEditValue(typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value));
  };

  const handleSaveEdit = () => {
    try {
      if (valueType === 'number') {
        onUpdate(parseFloat(editValue));
      } else if (valueType === 'boolean') {
        onUpdate(editValue === 'true');
      } else if (valueType === 'object' || valueType === 'array') {
        onUpdate(JSON.parse(editValue));
      } else {
        onUpdate(editValue);
      }
      setIsEditing(false);
    } catch (err) {
      alert('Invalid value: ' + (err as Error).message);
    }
  };

  const handleAddProperty = () => {
    if (valueType === 'object') {
      const newKey = prompt('Property name:');
      if (newKey && newKey.trim()) {
        // Check if key already exists
        const obj = value as Record<string, JsonValue>;
        if (Object.prototype.hasOwnProperty.call(obj, newKey)) {
          alert(`Property "${newKey}" already exists!`);
          return;
        }
        onUpdate({ ...obj, [newKey.trim()]: '' });
      }
    } else if (valueType === 'array') {
      onUpdate([...(value as JsonValue[]), '']);
    }
  };

  const handleUpdateChild = (childKey: string | number, newChildValue: JsonValue) => {
    if (valueType === 'object') {
      onUpdate({ ...(value as Record<string, JsonValue>), [childKey]: newChildValue });
    } else if (valueType === 'array') {
      const newArray = [...(value as JsonValue[])];
      newArray[childKey as number] = newChildValue;
      onUpdate(newArray);
    }
  };

  const handleDeleteChild = (childKey: string | number) => {
    if (valueType === 'object') {
      const newObj = { ...(value as Record<string, JsonValue>) };
      delete newObj[childKey as string];
      onUpdate(newObj);
    } else if (valueType === 'array') {
      const newArray = [...(value as JsonValue[])];
      newArray.splice(childKey as number, 1);
      onUpdate(newArray);
    }
  };

  const renderValue = () => {
    if (isEditing) {
      return (
        <div className="flex items-start space-x-2 flex-1">
          <textarea
            value={editValue}
            onChange={(e) => setEditValue(e.target.value)}
            rows={isComplex ? 4 : 1}
            className="flex-1 px-2 py-1 text-sm border border-primary-300 rounded font-mono"
            autoFocus
          />
          <button
            onClick={handleSaveEdit}
            className="px-2 py-1 text-xs bg-green-500 text-white rounded hover:bg-green-600"
          >
            ✓
          </button>
          <button
            onClick={() => setIsEditing(false)}
            className="px-2 py-1 text-xs bg-gray-500 text-white rounded hover:bg-gray-600"
          >
            ✕
          </button>
        </div>
      );
    }

    if (isComplex) {
      // For collapsed complex types, show expand button
      return (
        <div className="flex items-center space-x-1.5 flex-1">
          <button
            onClick={() => setIsExpanded(true)}
            className="text-xs text-gray-500 hover:text-gray-900 w-3"
          >
            ▶
          </button>
          <span className="text-xs text-gray-600">
            {valueType === 'array' ? `[${(value as JsonValue[]).length}]` : `{${Object.keys(value as Record<string, JsonValue>).length}}`}
          </span>
          <button
            onClick={handleAddProperty}
            className="text-xs px-1.5 py-0.5 bg-primary-100 text-primary-700 rounded hover:bg-primary-200"
          >
            +
          </button>
        </div>
      );
    }

    // Simple value
    return (
      <div className="flex items-center space-x-1.5 flex-1">
        <span className="flex-1 text-xs font-mono text-gray-900 bg-gray-50 px-2 py-0.5 rounded truncate">
          {String(value)}
        </span>
        <button
          onClick={handleStartEdit}
          className="text-xs px-1.5 py-0.5 bg-blue-100 text-blue-700 rounded hover:bg-blue-200 shrink-0"
        >
          Edit
        </button>
      </div>
    );
  };

  const isComplexType = valueType === 'object' || valueType === 'array';

  if (isComplexType && isExpanded) {
    // For expanded complex types, render header row + children rows
    const entries = valueType === 'array'
      ? (value as JsonValue[]).map((v, i) => [i, v] as [number, JsonValue])
      : Object.entries(value as Record<string, JsonValue>);

    return (
      <>
        {/* Header row */}
        <div className={`${isRoot ? '' : 'border-b border-gray-100 py-1.5 px-2 hover:bg-gray-100'}`}>
          <div className="flex items-center space-x-2">
            <span className="text-xs font-medium text-gray-700 w-24 shrink-0">
              {keyName}:
            </span>
            <button
              onClick={() => setIsExpanded(false)}
              className="text-xs text-gray-500 hover:text-gray-900 w-3"
            >
              ▼
            </button>
            <span className="text-xs text-gray-600">
              {valueType === 'array' ? `[${(value as JsonValue[]).length}]` : `{${Object.keys(value as Record<string, JsonValue>).length}}`}
            </span>
            <button
              onClick={handleAddProperty}
              className="text-xs px-1.5 py-0.5 bg-primary-100 text-primary-700 rounded hover:bg-primary-200"
            >
              +
            </button>
            {canDelete && !isRoot && (
              <button
                onClick={onDelete}
                className="text-xs px-1.5 py-0.5 bg-red-100 text-red-700 rounded hover:bg-red-200 shrink-0 ml-auto"
              >
                ✕
              </button>
            )}
          </div>
        </div>
        {/* Children rows */}
        {entries.map(([key, val]) => (
          <JsonNode
            key={String(key)}
            keyName={key}
            value={val}
            onUpdate={(newVal) => handleUpdateChild(key, newVal)}
            onDelete={() => handleDeleteChild(key)}
            canDelete={true}
          />
        ))}
      </>
    );
  }

  // Single row (collapsed complex or simple value)
  return (
    <div className={`${isRoot ? '' : 'border-b border-gray-100 py-1.5 px-2 hover:bg-gray-100'}`}>
      <div className="flex items-center space-x-2">
        <span className="text-xs font-medium text-gray-700 w-24 shrink-0">
          {keyName}:
        </span>
        {renderValue()}
        {canDelete && !isRoot && (
          <button
            onClick={onDelete}
            className="text-xs px-1.5 py-0.5 bg-red-100 text-red-700 rounded hover:bg-red-200 shrink-0 ml-auto"
          >
            ✕
          </button>
        )}
      </div>
    </div>
  );
}

export function JsonTreeEditor({ value, onChange, type }: JsonTreeEditorProps) {
  const [viewMode, setViewMode] = useState<'tree' | 'json'>('tree');
  const [jsonText, setJsonText] = useState(JSON.stringify(value ?? (type === 'array' ? [] : {}), null, 2));
  const [jsonError, setJsonError] = useState<string | null>(null);

  const handleJsonTextChange = (text: string) => {
    setJsonText(text);
    try {
      const parsed = JSON.parse(text);
      setJsonError(null);
      onChange(parsed);
    } catch (err) {
      setJsonError((err as Error).message);
    }
  };

  if (viewMode === 'json') {
    return (
      <div>
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs text-gray-600">Raw JSON</span>
          <button
            onClick={() => setViewMode('tree')}
            className="text-xs text-primary-600 hover:text-primary-700"
          >
            Switch to Tree View
          </button>
        </div>
        <textarea
          value={jsonText}
          onChange={(e) => handleJsonTextChange(e.target.value)}
          rows={Math.max(4, Math.min(jsonText.split('\n').length + 1, 20))}
          className={`w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-primary-500 font-mono text-sm resize-y ${
            jsonError ? 'border-red-300 bg-red-50' : 'border-gray-300'
          }`}
        />
        {jsonError && (
          <p className="mt-1 text-xs text-red-600">Invalid JSON: {jsonError}</p>
        )}
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-gray-600">Tree View</span>
        <button
          onClick={() => {
            setJsonText(JSON.stringify(value, null, 2));
            setViewMode('json');
          }}
          className="text-xs text-primary-600 hover:text-primary-700"
        >
          Switch to JSON
        </button>
      </div>
      <div className="border border-gray-200 rounded-lg bg-white max-h-96 overflow-auto divide-y divide-gray-100">
        <JsonNode
          keyName={type === 'array' ? 'items' : 'properties'}
          value={value ?? (type === 'array' ? [] : {})}
          onUpdate={onChange}
          onDelete={() => {}}
          isRoot={true}
          canDelete={false}
        />
      </div>
    </div>
  );
}
