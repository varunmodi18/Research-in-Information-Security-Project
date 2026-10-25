import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
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
  const qc = useQueryClient();
  const query = useQuery({
    queryKey: keys.job(jobId ?? -1),
    queryFn: () => api.get<Job>(`/jobs/${jobId}`),
    enabled: jobId !== null,
    refetchInterval: (q) => (q.state.data && TERMINAL_JOB_STATES.includes(q.state.data.state) ? false : 500),
  });
  // When a job finishes, refresh everything it may have changed. The live stream normally does this,
  // but it can connect after a short job has already run (or be down), so do not rely on it alone.
  const state = query.data?.state;
  const nid = query.data?.network_id;
  useEffect(() => {
    if (!state || !TERMINAL_JOB_STATES.includes(state)) return;
    qc.invalidateQueries({ queryKey: ["networks"] });
    qc.invalidateQueries({ queryKey: ["events"] });
    if (nid != null) {
      for (const k of ["network", "frames", "readings", "device", "recovery"]) qc.invalidateQueries({ queryKey: [k, nid] });
    }
  }, [state, nid, qc]);
  return query;
}

// docs/RECOVERY.md: per live cluster head, the behaviour monitor's flags, the "CH suspected" alert and
// the ranked replacement candidates. Read-only; the alert never acts.
export interface RecoveryCandidate {
  ident: string; trust: number; reliability: number; rejections: number; rejections_norm: number; score: number;
}
export interface ClusterRecovery {
  cluster: string; ch: string; flags: boolean[]; suspected: boolean; candidates: RecoveryCandidate[];
  recommended: string | null; trigger_detector: string; trust_detector: string;
}
export interface RecoveryStatus {
  available: boolean; reason?: string; step?: number; monitor_start?: number; windows_scored?: number; window?: number;
  trigger?: string; trigger_detector?: string; trust_detector?: string; clusters?: ClusterRecovery[];
}

export function useRecovery(id: number, enabled: boolean) {
  return useQuery({
    queryKey: ["recovery", id],
    queryFn: () => api.get<RecoveryStatus>(`/networks/${id}/recovery`),
    enabled,
    refetchInterval: 3000,
    retry: false,
  });
}

/** True while a job is being submitted, or the latest submitted job has not yet reported a final
 * state (including before its first status arrives). Controls that start jobs stay disabled meanwhile,
 * so jobs reach the network's queue in the order the operator issued them (CI race on 4d3508b: a
 * step submitted while "Start onboarding" was in flight could be queued first). */
export function jobInProgress(submitPending: boolean, jobId: number | null,
                              job: { data?: Job; isError: boolean }): boolean {
  if (submitPending) return true;
  if (jobId === null || job.isError) return false;
  return !job.data || !TERMINAL_JOB_STATES.includes(job.data.state);
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
