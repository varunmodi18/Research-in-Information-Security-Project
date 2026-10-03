import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";

export type StreamKind = "frame" | "security_event" | "device_status" | "job_progress";
export interface StreamMessage {
  kind: StreamKind;
  id: number;
  data: Record<string, unknown>;
}
export type StreamStatus = "connecting" | "live" | "reconnecting";

// Live updates over SSE (IMPLEMENTATION_PLAN.md §4.5, NFR-PERF-03). EventSource reconnects by
// itself and resends Last-Event-ID, so missed events are replayed by the server buffer.
export function useNetworkStream(networkId: number, onMessage?: (m: StreamMessage) => void) {
  const qc = useQueryClient();
  const [status, setStatus] = useState<StreamStatus>("connecting");
  const handler = useRef(onMessage);
  handler.current = onMessage;

  useEffect(() => {
    const es = new EventSource(`/api/networks/${networkId}/stream`, { withCredentials: true });
    let timer: ReturnType<typeof setTimeout> | null = null;
    const refresh = () => {
      if (timer) return;
      timer = setTimeout(() => {
        timer = null;
        qc.invalidateQueries({ queryKey: ["network", networkId] });
        qc.invalidateQueries({ queryKey: ["frames", networkId] });
        qc.invalidateQueries({ queryKey: ["events"] });
        qc.invalidateQueries({ queryKey: ["readings", networkId] });
        qc.invalidateQueries({ queryKey: ["device", networkId] });
      }, 400);
    };
    const listen = (kind: StreamKind) =>
      es.addEventListener(kind, (ev) => {
        const msg = ev as MessageEvent<string>;
        handler.current?.({ kind, id: Number(msg.lastEventId), data: JSON.parse(msg.data) });
        refresh();
      });
    (["frame", "security_event", "device_status", "job_progress"] as StreamKind[]).forEach(listen);
    es.onopen = () => setStatus("live");
    es.onerror = () => setStatus("reconnecting");
    return () => {
      if (timer) clearTimeout(timer);
      es.close();
    };
  }, [networkId, qc]);

  return status;
}
