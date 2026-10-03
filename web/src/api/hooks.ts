import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, idempotencyKey, qs } from "./client";
import type {
  DeviceDetail,
  Frame,
  Job,
  JobAccepted,
  JobType,
  Network,
  NetworkCreate,
  NetworkDetail,
  Page,
  Reading,
  SecurityEvent,
} from "./types";
import { TERMINAL_JOB_STATES } from "./types";

export const keys = {
  networks: ["networks"] as const,
  network: (id: number) => ["network", id] as const,
  device: (id: number, dev: string) => ["device", id, dev] as const,
  frames: (id: number, f: object) => ["frames", id, f] as const,
  events: (f: object) => ["events", f] as const,
  readings: (id: number) => ["readings", id] as const,
  job: (id: number) => ["job", id] as const,
};

export function useNetworks() {
  return useQuery({ queryKey: keys.networks, queryFn: () => api.get<Network[]>("/networks") });
}

export function useNetwork(id: number) {
  return useQuery({ queryKey: keys.network(id), queryFn: () => api.get<NetworkDetail>(`/networks/${id}`) });
}

export function useDevice(id: number, dev: string) {
  return useQuery({
    queryKey: keys.device(id, dev),
    queryFn: () => api.get<DeviceDetail>(`/networks/${id}/devices/${encodeURIComponent(dev)}`),
  });
}

export interface FrameFilter {
  label?: string;
  src?: string;
  dst?: string;
  verdict?: string;
  job?: number;
  run_tag?: string;
  limit?: number;
}

export function useFrames(id: number, filter: FrameFilter = {}) {
  return useQuery({
    queryKey: keys.frames(id, filter),
    queryFn: () => api.get<Page<Frame>>(`/networks/${id}/frames${qs({ limit: 1000, ...filter })}`),
  });
}

export interface EventFilter {
  network?: number;
  severity?: string;
  type?: string;
  device?: string;
  run_tag?: string;
  limit?: number;
}

export function useEvents(filter: EventFilter = {}) {
  return useQuery({
    queryKey: keys.events(filter),
    queryFn: () => api.get<Page<SecurityEvent>>(`/events${qs({ limit: 200, ...filter })}`),
    refetchInterval: 2000, // the log keeps growing while jobs run (FR-14); the query is cheap (V-PERF-04)
  });
}

export function useReadings(id: number, enabled = true) {
  return useQuery({
    queryKey: keys.readings(id),
    queryFn: () => api.get<Page<Reading>>(`/networks/${id}/readings?limit=1000`),
    enabled,
  });
}

export function useJob(jobId: number | null) {
  return useQuery({
    queryKey: keys.job(jobId ?? -1),
    queryFn: () => api.get<Job>(`/jobs/${jobId}`),
    enabled: jobId !== null,
    refetchInterval: (q) => (q.state.data && TERMINAL_JOB_STATES.includes(q.state.data.state) ? false : 500),
  });
}

export function useCreateNetwork() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: NetworkCreate) => api.post<NetworkDetail>("/networks", body),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.networks }),
  });
}

export function useSubmitJob(networkId: number) {
  return useMutation({
    mutationFn: ({ type, args }: { type: JobType; args?: Record<string, unknown> }) =>
      api.post<JobAccepted>(`/networks/${networkId}/jobs`, {
        type,
        args: args ?? {},
        idempotency_key: idempotencyKey(),
      }),
  });
}

export function useCancelJob() {
  return useMutation({ mutationFn: (jobId: number) => api.post<Job>(`/jobs/${jobId}/cancel`) });
}
