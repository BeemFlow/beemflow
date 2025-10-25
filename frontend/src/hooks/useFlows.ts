import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';
import type { Flow } from '../types/beemflow';

export function useFlows() {
  return useQuery({
    queryKey: ['flows'],
    queryFn: () => api.listFlows(),
  });
}

export function useFlow(name: string | undefined) {
  return useQuery({
    queryKey: ['flows', name],
    queryFn: () => api.getFlow(name!),
    enabled: !!name,
  });
}

export function useSaveFlow() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (flow: Flow) => api.saveFlow(flow),
    onSuccess: (_, flow) => {
      queryClient.invalidateQueries({ queryKey: ['flows'] });
      queryClient.invalidateQueries({ queryKey: ['flows', flow.name] });
    },
  });
}

export function useDeleteFlow() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (name: string) => api.deleteFlow(name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['flows'] });
    },
  });
}

export function useDeployFlow() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (name: string) => api.deployFlow(name),
    onSuccess: (_, name) => {
      queryClient.invalidateQueries({ queryKey: ['flows', name] });
      queryClient.invalidateQueries({ queryKey: ['flows', name, 'history'] });
    },
  });
}

export function useFlowHistory(name: string | undefined) {
  return useQuery({
    queryKey: ['flows', name, 'history'],
    queryFn: () => api.getFlowHistory(name!),
    enabled: !!name,
  });
}

export function useFlowGraph(name: string | undefined) {
  return useQuery({
    queryKey: ['flows', name, 'graph'],
    queryFn: () => api.getFlowGraph(name!),
    enabled: !!name,
  });
}
