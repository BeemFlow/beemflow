import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';

export function useTools() {
  return useQuery({
    queryKey: ['tools'],
    queryFn: () => api.listTools(),
  });
}

export function useTool(name: string | undefined) {
  return useQuery({
    queryKey: ['tools', name],
    queryFn: () => api.getTool(name!),
    enabled: !!name,
  });
}

export function useSearchTools(query?: string) {
  return useQuery({
    queryKey: ['tools', 'search', query],
    queryFn: () => api.searchTools(query),
    enabled: !!query,
  });
}

export function useInstallTool() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (tool: string) => api.installTool(tool),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tools'] });
    },
  });
}

export function useMcpServers() {
  return useQuery({
    queryKey: ['mcp'],
    queryFn: () => api.listMcpServers(),
  });
}

export function useSearchMcpServers(query?: string) {
  return useQuery({
    queryKey: ['mcp', 'search', query],
    queryFn: () => api.searchMcpServers(query),
    enabled: !!query,
  });
}
