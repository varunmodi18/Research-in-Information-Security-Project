import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useFrames, useNetwork } from "../api/hooks";
import { PageHeader } from "../components/Layout";
import { ModeBanner } from "../components/ModeBanner";
import { Empty, ErrorPanel, Loading } from "../components/States";
import { VerdictBadge } from "../components/StatusBadge";
import { useNetworkStream } from "../hooks/useNetworkStream";

// FR-13: frame log -- label, endpoints, sizes (bytes and RP9 paper bits), verdict, payload hex.
export function FramesPage() {
  const id = Number(useParams().id);
  const runTag = useSearchParams()[0].get("run_tag") ?? undefined;
  const network = useNetwork(id);
  useNetworkStream(id);
  const [filter, setFilter] = useState({ label: "", src: "", dst: "", verdict: "" });
  const frames = useFrames(id, {
    label: filter.label || undefined, src: filter.src || undefined, dst: filter.dst || undefined,
    verdict: filter.verdict || undefined, run_tag: runTag,
  });
  if (network.isLoading) return <Loading />;
  if (!network.data) return <ErrorPanel error={network.error} />;
  const set = (k: keyof typeof filter) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setFilter({ ...filter, [k]: k === "label" ? e.target.value.toUpperCase() : e.target.value });
  return (
    <div className={network.data.kind === "lab" ? "border-l-4 border-red-500" : ""}>
      <ModeBanner network={network.data} />
      <PageHeader title={`Frames — ${network.data.name}`}
        subtitle={runTag ? `Evidence of Lab run ${runTag}` : "Every frame the simulated radio carried, as the receiver saw it"}
        actions={<Link className="btn-secondary" to={`/networks/${id}`}>← Topology</Link>} />
      <div className="mx-6 mb-3 flex flex-wrap gap-3">
        {(["label", "src", "dst"] as const).map((k) => (
          <div key={k}>
            <label className="label" htmlFor={`f-${k}`}>{k}</label>
            <input id={`f-${k}`} className="input w-36 font-mono" value={filter[k]} onChange={set(k)} />
          </div>
        ))}
        <div>
          <label className="label" htmlFor="f-verdict">Verdict</label>
          <select id="f-verdict" className="input" value={filter.verdict} onChange={set("verdict")}>
            <option value="">all</option><option value="ACCEPT">PASS</option><option value="REJECT">FAIL</option><option value="DROPPED">DROPPED</option>
          </select>
        </div>
      </div>
      <div className="card mx-6 mb-8 overflow-x-auto">
        {frames.isLoading && <Loading />}
        {frames.error && <ErrorPanel error={frames.error} onRetry={() => void frames.refetch()} />}
        {frames.data?.items.length === 0 && <Empty title="No frames" hint="Run onboarding to put traffic on the channel." />}
        {frames.data && frames.data.items.length > 0 && (
          <table className="w-full" data-testid="frames-table">
            <thead><tr>
              <th className="th">Step</th><th className="th">Label</th><th className="th">From → to</th><th className="th">Bytes</th>
              <th className="th">Paper bits</th><th className="th">Verdict</th><th className="th">Reason</th><th className="th">Payload (hex)</th>
            </tr></thead>
            <tbody>
              {[...frames.data.items].reverse().map((f) => (
                <tr key={f.id}>
                  <td className="td text-xs">{f.step}</td>
                  <td className="td font-mono text-xs">{f.label}{f.fate !== "delivered" ? ` (${f.fate})` : ""}</td>
                  <td className="td font-mono text-xs">{f.src} → {f.to ?? f.dst}</td>
                  <td className="td text-xs">{f.bytes_len}</td>
                  <td className="td text-xs">{f.paper_bits || "—"}</td>
                  <td className="td"><VerdictBadge verdict={f.verdict} /></td>
                  <td className="td font-mono text-xs text-red-700">{f.reason ?? ""}</td>
                  <td className="td max-w-xs truncate font-mono text-[11px] text-slate-500" title={f.payload_hex ?? ""}>{f.payload_hex?.slice(0, 48) ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
