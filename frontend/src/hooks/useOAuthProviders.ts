import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';
import toast from 'react-hot-toast';

/**
 * Hook to fetch all OAuth providers with connection status
 */
export function useOAuthProviders() {
  return useQuery({
    queryKey: ['oauth-providers'],
    queryFn: () => api.listOAuthProviders(),
    staleTime: 30000, // 30 seconds
  });
}

/**
 * Hook to fetch a specific OAuth provider
 */
export function useOAuthProvider(providerId: string) {
  return useQuery({
    queryKey: ['oauth-providers', providerId],
    queryFn: () => api.getOAuthProvider(providerId),
    enabled: !!providerId,
    staleTime: 30000,
  });
}

/**
 * Hook to fetch all OAuth connections
 */
export function useOAuthConnections() {
  return useQuery({
    queryKey: ['oauth-connections'],
    queryFn: () => api.listOAuthConnections(),
    staleTime: 30000,
  });
}

/**
 * Hook to initiate OAuth connection flow
 * Opens the OAuth authorization URL in a new window
 */
export function useConnectOAuthProvider() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({
      providerId,
      scopes,
    }: {
      providerId: string;
      scopes?: string[];
    }) => api.connectOAuthProvider(providerId, scopes),
    onSuccess: (data) => {
      // Open OAuth URL in a popup window
      const width = 600;
      const height = 700;
      const left = window.screen.width / 2 - width / 2;
      const top = window.screen.height / 2 - height / 2;

      const popup = window.open(
        data.auth_url,
        'oauth-popup',
        `width=${width},height=${height},left=${left},top=${top},toolbar=no,menubar=no,location=no,status=no`
      );

      if (!popup) {
        toast.error('Please allow popups for this site to connect OAuth providers');
        // Fallback: navigate in current window
        window.location.href = data.auth_url;
        return;
      }

      // Listen for OAuth completion (if the OAuth callback communicates back)
      const handleMessage = (event: MessageEvent) => {
        if (event.data?.type === 'oauth-success') {
          toast.success(`Connected to ${data.provider_id}`);
          queryClient.invalidateQueries({ queryKey: ['oauth-providers'] });
          queryClient.invalidateQueries({ queryKey: ['oauth-connections'] });
          popup.close();
        }
      };

      window.addEventListener('message', handleMessage);

      // Check if popup was closed manually
      const checkPopupClosed = setInterval(() => {
        if (popup.closed) {
          clearInterval(checkPopupClosed);
          window.removeEventListener('message', handleMessage);
          // Refresh data in case connection was successful
          queryClient.invalidateQueries({ queryKey: ['oauth-providers'] });
          queryClient.invalidateQueries({ queryKey: ['oauth-connections'] });
        }
      }, 500);
    },
    onError: (error: any) => {
      toast.error(
        error?.response?.data?.error?.message ||
          'Failed to initiate OAuth connection'
      );
    },
  });
}

/**
 * Hook to disconnect an OAuth provider
 */
export function useDisconnectOAuthProvider() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (providerId: string) => api.disconnectOAuthProvider(providerId),
    onSuccess: (_, providerId) => {
      toast.success(`Disconnected from ${providerId}`);
      queryClient.invalidateQueries({ queryKey: ['oauth-providers'] });
      queryClient.invalidateQueries({ queryKey: ['oauth-connections'] });
    },
    onError: (error: any) => {
      toast.error(
        error?.response?.data?.error?.message ||
          'Failed to disconnect OAuth provider'
      );
    },
  });
}
