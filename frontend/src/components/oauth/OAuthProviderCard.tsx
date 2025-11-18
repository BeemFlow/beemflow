import { useState } from 'react';
import type { OAuthProviderInfo } from '../../types/beemflow';
import { useConnectOAuthProvider, useDisconnectOAuthProvider } from '../../hooks/useOAuthProviders';

interface OAuthProviderCardProps {
  provider: OAuthProviderInfo;
}

export function OAuthProviderCard({ provider }: OAuthProviderCardProps) {
  const [showScopes, setShowScopes] = useState(false);
  const [selectedScopes, setSelectedScopes] = useState<string[]>([]);

  const connectMutation = useConnectOAuthProvider();
  const disconnectMutation = useDisconnectOAuthProvider();

  const handleConnect = () => {
    const scopes = selectedScopes.length > 0 ? selectedScopes : undefined;
    connectMutation.mutate({ providerId: provider.id, scopes });
  };

  const handleDisconnect = () => {
    if (confirm(`Are you sure you want to disconnect from ${provider.display_name || provider.name}?`)) {
      disconnectMutation.mutate(provider.id);
    }
  };

  const toggleScope = (scope: string) => {
    setSelectedScopes((prev) =>
      prev.includes(scope)
        ? prev.filter((s) => s !== scope)
        : [...prev, scope]
    );
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6 hover:shadow-lg transition-shadow">
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          {provider.icon && (
            <span className="text-4xl" aria-label={provider.name}>
              {provider.icon}
            </span>
          )}
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              {provider.display_name || provider.name}
            </h3>
            {provider.description && (
              <p className="text-sm text-gray-600 mt-1">{provider.description}</p>
            )}
          </div>
        </div>

        {/* Connection Status Badge */}
        {provider.connected && (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
            ✓ Connected
          </span>
        )}
      </div>

      {/* Connection Status Details */}
      {provider.connected && provider.connection_status && (
        <div className="mb-4 p-3 bg-gray-50 rounded-md text-sm">
          <p className="text-gray-700">
            <span className="font-medium">Connected:</span>{' '}
            {new Date(provider.connection_status.connected_at).toLocaleDateString()}
          </p>
          {provider.connection_status.expires_at && (
            <p className="text-gray-700 mt-1">
              <span className="font-medium">Expires:</span>{' '}
              {new Date(provider.connection_status.expires_at).toLocaleDateString()}
            </p>
          )}
          {provider.connection_status.scopes_granted && (
            <p className="text-gray-700 mt-1">
              <span className="font-medium">Scopes:</span>{' '}
              {provider.connection_status.scopes_granted.length} granted
            </p>
          )}
        </div>
      )}

      {/* Scopes Section */}
      {provider.scopes && provider.scopes.length > 0 && (
        <div className="mb-4">
          <button
            onClick={() => setShowScopes(!showScopes)}
            className="flex items-center gap-2 text-sm font-medium text-gray-700 hover:text-gray-900"
          >
            <span>{showScopes ? '▼' : '▶'}</span>
            <span>{provider.scopes.length} available scopes</span>
          </button>

          {showScopes && (
            <div className="mt-3 space-y-2 max-h-48 overflow-y-auto">
              {provider.scopes.map((scopeInfo) => (
                <label
                  key={scopeInfo.scope}
                  className="flex items-start gap-2 p-2 hover:bg-gray-50 rounded cursor-pointer"
                >
                  <input
                    type="checkbox"
                    checked={selectedScopes.includes(scopeInfo.scope)}
                    onChange={() => toggleScope(scopeInfo.scope)}
                    disabled={provider.connected}
                    className="mt-1"
                  />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-mono text-gray-800 break-all">
                      {scopeInfo.scope}
                    </p>
                    <p className="text-xs text-gray-600 mt-0.5">
                      {scopeInfo.description}
                    </p>
                  </div>
                </label>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Action Buttons */}
      <div className="flex gap-2">
        {provider.connected ? (
          <>
            <button
              onClick={handleDisconnect}
              disabled={disconnectMutation.isPending}
              className="flex-1 px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors"
            >
              {disconnectMutation.isPending ? 'Disconnecting...' : 'Disconnect'}
            </button>
            <button
              onClick={handleConnect}
              disabled={connectMutation.isPending}
              className="flex-1 px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors"
            >
              {connectMutation.isPending ? 'Reconnecting...' : 'Reconnect'}
            </button>
          </>
        ) : (
          <button
            onClick={handleConnect}
            disabled={connectMutation.isPending}
            className="w-full px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors font-medium"
          >
            {connectMutation.isPending ? 'Connecting...' : 'Connect'}
          </button>
        )}
      </div>

      {/* Selected Scopes Info */}
      {selectedScopes.length > 0 && !provider.connected && (
        <p className="text-xs text-gray-500 mt-2">
          {selectedScopes.length} scope{selectedScopes.length > 1 ? 's' : ''} selected
        </p>
      )}
    </div>
  );
}
