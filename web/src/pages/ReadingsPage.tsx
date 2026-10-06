import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiProblem } from "../api/client";
import { useNetwork, useReadings, useSubmitJob } from "../api/hooks";
import { PageHeader } from "../components/Layout";
import { DesignationBanner } from "../components/DesignationNotice";
import { ModeBanner } from "../components/ModeBanner";
import { Empty, ErrorPanel, Loading } from "../components/States";
import { useJobToast, useToast } from "../components/Toast";
import { useNetworkStream } from "../hooks/useNetworkStream";

// FR-06/FR-07: readings decrypted at the BS (Operator and Admin only), periodic transmission.
export function ReadingsPage() {
  const id = Number(useParams().id);
  const toast = useToast();
  const trackJob = useJobToast();
  const network = useNetwork(id);
  const readings = useReadings(id);
  useNetworkStream(id);
  const submit = useSubmitJob(id);
  const [every, setEvery] = useState(20);
  const [periodic, setPeriodic] = useState(false);

  // F5: seq counts readings within one CM-BS session and restarts at 1 after a rekey. Mark the first
  // reading of each new session, per device, in arrival order.
  const newSession = new Set<number>();
  const lastSid = new Map<string, string | null | undefined>();
  for (const r of readings.data?.items ?? []) {
    if (lastSid.has(r.device) && r.session_sid && lastSid.get(r.device) !== r.session_sid) newSession.add(r.id);
    lastSid.set(r.device, r.session_sid);
  }

  if (network.isLoading) return <Loading />;
  if (!network.data) return <ErrorPanel error={network.error} />;
  const job = async (type: "start_periodic" | "stop_periodic" | "send_readings", args: Record<string, unknown> = {}) => {
    try {
      const { job_id } = await submit.mutateAsync({ type, args });
      if (type !== "send_readings") setPeriodic(type === "start_periodic");
      trackJob(job_id, type === "start_periodic" ? "Starting periodic readings…" : type === "stop_periodic" ? "Stopping periodic readings…" : "Sending readings…",
        type === "start_periodic" ? "Periodic readings started" : type === "stop_periodic" ? "Periodic readings stopped" : "Readings sent");
    } catch (err) {
      toast(err instanceof ApiProblem ? `${err.title}: ${err.detail}` : String(err), "error");
    }
  };
  return (
    <div className={network.data.kind === "lab" ? "border-l-4 border-red-500" : ""}>
      <ModeBanner network={network.data} />
      <PageHeader title={`Readings at the base station — ${network.data.name}`}
        subtitle="Simulated sensor values, decrypted by the BS. Viewers cannot see this page."
        actions={<Link className="btn-secondary" to={`/networks/${id}`}>← Topology</Link>} />
      <DesignationBanner devices={network.data.devices} />
      <div className="mx-6 mb-3 flex flex-wrap items-end gap-2">
        <button type="button" className="btn-secondary" onClick={() => job("send_readings", { count: 1 })}>Send one round</button>
        <div>
          <label className="label" htmlFor="every">Every N steps</label>
          <input id="every" type="number" min={5} max={1000} className="input w-24" value={every} onChange={(e) => setEvery(Number(e.target.value))} />
        </div>
        {periodic ? (
          <button type="button" className="btn-danger" onClick={() => job("stop_periodic")}>■ Stop periodic</button>
        ) : (
          <button type="button" className="btn-primary" onClick={() => job("start_periodic", { every_steps: every })} data-testid="btn-periodic">▶ Start periodic</button>
        )}
      </div>
      <div className="card mx-6 mb-8 overflow-x-auto">
        {readings.isLoading && <Loading />}
        {readings.error && <ErrorPanel error={readings.error} onRetry={() => void readings.refetch()} />}
        {readings.data?.items.length === 0 && <Empty title="No readings yet" hint="Onboard the network, then send readings." />}
        {readings.data && readings.data.items.length > 0 && (
          <table className="w-full" data-testid="readings-table">
            <thead><tr><th className="th">Device</th><th className="th">Seq</th><th className="th">Value (simulated)</th><th className="th">Received at step</th></tr></thead>
            <tbody>
              {[...readings.data.items].reverse().map((r) => (
                <tr key={r.id}>
                  <td className="td font-mono">{r.device}</td>
                  <td className="td" data-testid="reading-seq">
                    {newSession.has(r.id) && (
                      <span className="mr-1 font-semibold text-blue-700" title="New CM–BS session (rekey): seq restarted at 1" data-testid="rekey-marker">↻</span>
                    )}
                    {r.seq}
                    {r.session_sid && (
                      <span className="ml-2 font-mono text-[11px] text-slate-500" title={`CM–BS session ${r.session_sid}. seq counts readings within one session and restarts at 1 after a rekey.`}>
                        · {r.session_sid.slice(0, 8)}
                      </span>
                    )}
                  </td>
                  <td className="td font-mono text-xs">{typeof r.value === "string" ? r.value : JSON.stringify(r.value)}</td>
                  <td className="td">{r.received_step}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
