import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';
import type { StartRunRequest, JsonValue } from '../types/beemflow';

export function useRuns(params?: {
  limit?: number;
  offset?: number;
  flow_name?: string;
  status?: string;
}) {
  return useQuery({
    queryKey: ['runs', params],
    queryFn: () => api.listRuns(params),
  });
}

export function useRun(id: string | undefined, options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: ['runs', id],
    queryFn: () => api.getRun(id!),
    enabled: !!id,
    refetchInterval: options?.refetchInterval,
  });
}

export function useStartRun() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (request: StartRunRequest) => api.startRun(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['runs'] });
    },
  });
}

export function useResumeRun() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ token, event }: { token: string; event: Record<string, JsonValue> }) =>
      api.resumeRun(token, event),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['runs'] });
    },
  });
}

export function useCancelRun() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => api.cancelRun(id),
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: ['runs'] });
      queryClient.invalidateQueries({ queryKey: ['runs', id] });
    },
  });
}
