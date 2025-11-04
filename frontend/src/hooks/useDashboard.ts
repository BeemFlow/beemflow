import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';

export function useDashboardStats() {
  return useQuery({
    queryKey: ['dashboard', 'stats'],
    queryFn: () => api.getDashboardStats(),
    refetchInterval: 5000, // Refresh every 5 seconds
  });
}

export function useOAuthProviders() {
  return useQuery({
    queryKey: ['oauth', 'providers'],
    queryFn: () => api.listOAuthProviders(),
  });
}
