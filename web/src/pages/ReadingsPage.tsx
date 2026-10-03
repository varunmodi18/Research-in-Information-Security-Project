import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiProblem } from "../api/client";
import { useNetwork, useReadings, useSubmitJob } from "../api/hooks";
import { PageHeader } from "../components/Layout";
import { ModeBanner } from "../components/ModeBanner";
import { Empty, ErrorPanel, Loading } from "../components/States";
import { useToast } from "../components/Toast";
import { useNetworkStream } from "../hooks/useNetworkStream";

// FR-06/FR-07: readings decrypted at the BS (Operator and Admin only), periodic transmission.
export function ReadingsPage() {
  const id = Number(useParams().id);
  const toast = useToast();
  const network = useNetwork(id);
  const readings = useReadings(id);
  useNetworkStream(id);
  const submit = useSubmitJob(id);
  const [every, setEvery] = useState(20);
  const [periodic, setPeriodic] = useState(false);

  if (network.isLoading) return <Loading />;
  if (!network.data) return <ErrorPanel error={network.error} />;
  const job = async (type: "start_periodic" | "stop_periodic" | "send_readings", args: Record<string, unknown> = {}) => {
    try {
      await submit.mutateAsync({ type, args });
      if (type !== "send_readings") setPeriodic(type === "start_periodic");
      toast(type === "start_periodic" ? "Periodic readings started" : type === "stop_periodic" ? "Periodic readings stopped" : "Readings sent", "info");
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
                  <td className="td">{r.seq}</td>
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
