import { useState } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useOAuthProviders } from '../../hooks/useOAuthProviders';
import { OAuthProviderCard } from './OAuthProviderCard';
import { Permission } from '../../types/beemflow';

export function OAuthProvidersList() {
  const { role, hasPermission } = useAuth();
  const { data: providers, isLoading, error } = useOAuthProviders();
  const [searchQuery, setSearchQuery] = useState('');

  // Permission checks
  const canConnect = hasPermission(Permission.OAuthConnect);
  const canDisconnect = hasPermission(Permission.OAuthDisconnect);

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
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 mb-2">
              OAuth Integrations
            </h1>
            <p className="text-gray-600">
              Connect your external services to enable powerful workflow automations
            </p>
          </div>
          {role && (
            <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-600 capitalize">
              Your role: {role}
            </span>
          )}
        </div>

        {/* Permission Warning */}
        {!canConnect && (
          <div className="mt-4 rounded-md bg-yellow-50 p-4 border border-yellow-200">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-yellow-800">Limited Access</h3>
                <p className="mt-1 text-sm text-yellow-700">
                  You don't have permission to connect OAuth integrations. Your current role is <span className="font-medium capitalize">{role}</span>.
                  Contact an administrator to request elevated permissions.
                </p>
              </div>
            </div>
          </div>
        )}
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
            <OAuthProviderCard
              key={provider.id}
              provider={provider}
              canConnect={canConnect}
              canDisconnect={canDisconnect}
            />
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
