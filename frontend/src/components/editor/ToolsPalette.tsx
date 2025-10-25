import { useState, useMemo } from 'react';
import { useTools } from '../../hooks/useTools';
import type { RegistryEntry } from '../../types/beemflow';

interface ToolsPaletteProps {
  onToolSelect: (tool: RegistryEntry) => void;
}

// Helper to categorize tools by prefix
function categorizeTool(toolName: string): string {
  // Split by both dots and underscores to get the vendor/category prefix
  const parts = toolName.split(/[._]/);
  const prefix = parts[0].toLowerCase();

  const categoryMap: Record<string, string> = {
    core: 'Core',
    slack: 'Slack',
    github: 'GitHub',
    openai: 'OpenAI',
    anthropic: 'Anthropic',
    google: 'Google',
    x: 'X (Twitter)',
    http: 'HTTP',
    fs: 'File System',
    db: 'Database',
    aws: 'AWS',
    azure: 'Azure',
    gcp: 'GCP',
  };

  return categoryMap[prefix] || 'Other';
}

export function ToolsPalette({ onToolSelect }: ToolsPaletteProps) {
  const { data: tools, isLoading, error } = useTools();
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(
    new Set(['Core'])
  );

  // Group tools by category
  const toolsByCategory = useMemo(() => {
    if (!tools) return {};

    const grouped: Record<string, RegistryEntry[]> = {};

    tools.forEach((tool) => {
      const category = categorizeTool(tool.name);
      if (!grouped[category]) {
        grouped[category] = [];
      }
      grouped[category].push(tool);
    });

    // Sort tools within each category
    Object.keys(grouped).forEach((category) => {
      grouped[category].sort((a, b) => a.name.localeCompare(b.name));
    });

    return grouped;
  }, [tools]);

  // Filter tools by search query
  const filteredToolsByCategory = useMemo(() => {
    if (!searchQuery.trim()) return toolsByCategory;

    const query = searchQuery.toLowerCase();
    const filtered: Record<string, RegistryEntry[]> = {};

    Object.entries(toolsByCategory).forEach(([category, categoryTools]) => {
      const matchingTools = categoryTools.filter(
        (tool) =>
          tool.name.toLowerCase().includes(query) ||
          tool.description?.toLowerCase().includes(query)
      );

      if (matchingTools.length > 0) {
        filtered[category] = matchingTools;
      }
    });

    return filtered;
  }, [toolsByCategory, searchQuery]);

  const toggleCategory = (category: string) => {
    const newExpanded = new Set(expandedCategories);
    if (newExpanded.has(category)) {
      newExpanded.delete(category);
    } else {
      newExpanded.add(category);
    }
    setExpandedCategories(newExpanded);
  };

  if (isLoading) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-sm text-gray-500">Loading tools...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="h-full flex items-center justify-center p-4">
        <div className="text-sm text-red-600">Failed to load tools</div>
      </div>
    );
  }

  const categories = Object.keys(filteredToolsByCategory).sort();

  return (
    <div className="h-full flex flex-col bg-white">
      {/* Header */}
      <div className="px-4 py-3 border-b border-gray-200">
        <h3 className="text-sm font-semibold text-gray-900 mb-2">Tools</h3>
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search tools..."
          className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500"
        />
      </div>

      {/* Tools List */}
      <div className="flex-1 overflow-y-auto">
        {categories.length === 0 ? (
          <div className="p-4 text-center text-sm text-gray-500">
            No tools found
          </div>
        ) : (
          categories.map((category) => (
            <div key={category} className="border-b border-gray-200">
              {/* Category Header */}
              <button
                onClick={() => toggleCategory(category)}
                className="w-full px-4 py-2 flex items-center justify-between hover:bg-gray-50 transition-colors"
              >
                <span className="text-sm font-medium text-gray-700">
                  {category}
                </span>
                <div className="flex items-center space-x-2">
                  <span className="text-xs text-gray-500">
                    {filteredToolsByCategory[category].length}
                  </span>
                  <span className="text-gray-400">
                    {expandedCategories.has(category) ? '▼' : '▶'}
                  </span>
                </div>
              </button>

              {/* Tools in Category */}
              {expandedCategories.has(category) && (
                <div className="pb-2">
                  {filteredToolsByCategory[category].map((tool) => (
                    <button
                      key={tool.name}
                      onClick={() => onToolSelect(tool)}
                      className="w-full px-4 py-2 flex items-start hover:bg-primary-50 transition-colors text-left group"
                      title={tool.description || tool.name}
                    >
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium text-gray-900 group-hover:text-primary-700">
                          {tool.name}
                        </div>
                        {tool.description && (
                          <div className="text-xs text-gray-500 line-clamp-2">
                            {tool.description}
                          </div>
                        )}
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* Footer */}
      <div className="px-4 py-2 border-t border-gray-200 text-xs text-gray-500">
        {tools?.length || 0} tools available
      </div>
    </div>
  );
}
