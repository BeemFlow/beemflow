import { useState } from 'react';
import { useOAuthProviders } from '../../hooks/useOAuthProviders';
import { OAuthProviderCard } from './OAuthProviderCard';

export function OAuthProvidersList() {
  const { data: providers, isLoading, error } = useOAuthProviders();
  const [searchQuery, setSearchQuery] = useState('');

  // Filter providers based on search query
  const filteredProviders = providers?.filter((provider) => {
    if (!searchQuery) return true;
    const query = searchQuery.toLowerCase();
    return (
      provider.name.toLowerCase().includes(query) ||
      provider.display_name?.toLowerCase().includes(query) ||
      provider.description?.toLowerCase().includes(query)
    );
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
          <p className="mt-4 text-gray-600">Loading OAuth providers...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <div className="text-red-500 text-5xl mb-4">⚠</div>
          <h2 className="text-xl font-semibold text-gray-900 mb-2">
            Failed to Load OAuth Providers
          </h2>
          <p className="text-gray-600 mb-4">
            {error instanceof Error ? error.message : 'An error occurred'}
          </p>
          <button
            onClick={() => window.location.reload()}
            className="px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">
          OAuth Integrations
        </h1>
        <p className="text-gray-600">
          Connect your external services to enable powerful workflow automations
        </p>
      </div>

      {/* Search Bar */}
      <div className="mb-6">
        <input
          type="text"
          placeholder="Search providers..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full max-w-md px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
        />
      </div>

      {/* Stats */}
      {providers && (
        <div className="mb-6 flex gap-4 text-sm text-gray-600">
          <span>
            <span className="font-semibold text-gray-900">{providers.length}</span> providers available
          </span>
          <span>•</span>
          <span>
            <span className="font-semibold text-green-600">
              {providers.filter((p) => p.connected).length}
            </span>{' '}
            connected
          </span>
        </div>
      )}

      {/* Providers Grid */}
      {filteredProviders && filteredProviders.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredProviders.map((provider) => (
            <OAuthProviderCard key={provider.id} provider={provider} />
          ))}
        </div>
      ) : (
        <div className="text-center py-12">
          <div className="text-gray-400 text-5xl mb-4">🔍</div>
          <h3 className="text-lg font-medium text-gray-900 mb-2">
            No providers found
          </h3>
          <p className="text-gray-600">
            {searchQuery
              ? `No providers match "${searchQuery}"`
              : 'No OAuth providers are configured'}
          </p>
        </div>
      )}
    </div>
  );
}
