import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { qs } from "../api/client";
import { useEvents } from "../api/hooks";
import { PageHeader } from "../components/Layout";
import { ModeBanner } from "../components/ModeBanner";
import { Empty, ErrorPanel, Loading } from "../components/States";
import { SeverityBadge } from "../components/StatusBadge";

// FR-14: filter by severity, type, device, network; export CSV/JSON.
export function EventsPage() {
  const [params, setParams] = useSearchParams();
  const network = params.get("network") ? Number(params.get("network")) : undefined;
  const [severity, setSeverity] = useState(params.get("severity") ?? "");
  const [type, setType] = useState(params.get("type") ?? "");
  const [device, setDevice] = useState(params.get("device") ?? "");
  const runTag = params.get("run_tag") ?? undefined;
  const filter = { network, severity: severity || undefined, type: type || undefined, device: device || undefined,
    run_tag: runTag, limit: 500 };
  const events = useEvents(filter);
  const exportUrl = (format: string) => `/api/events/export${qs({ format, network, severity, type, device })}`;

  return (
    <div>
      <ModeBanner />
      <PageHeader
        title="Security events"
        subtitle={runTag ? `Lab run ${runTag}` : network ? `Network ${network}` : "All networks"}
        actions={
          <>
            <a className="btn-secondary" href={exportUrl("csv")}>Export CSV</a>
            <a className="btn-secondary" href={exportUrl("json")}>Export JSON</a>
          </>
        }
      />
      <div className="mx-6 mb-3 flex flex-wrap items-end gap-3">
        <div>
          <label className="label" htmlFor="ev-sev">Severity</label>
          <select id="ev-sev" className="input" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">all</option>
            <option value="info">info</option>
            <option value="warn">warn</option>
            <option value="high">high</option>
            <option value="warn,high">warn + high</option>
          </select>
        </div>
        <div>
          <label className="label" htmlFor="ev-type">Type</label>
          <input id="ev-type" className="input font-mono" placeholder="e.g. BAD_TAG" value={type} onChange={(e) => setType(e.target.value.toUpperCase())} />
        </div>
        <div>
          <label className="label" htmlFor="ev-dev">Device</label>
          <input id="ev-dev" className="input font-mono" placeholder="e.g. CM-0101" value={device} onChange={(e) => setDevice(e.target.value)} />
        </div>
        {network && (
          <button type="button" className="btn-secondary" onClick={() => { params.delete("network"); setParams(params); }}>
            Clear network filter
          </button>
        )}
      </div>
      <div className="card mx-6 mb-8 overflow-x-auto">
        {events.isLoading && <Loading />}
        {events.error && <ErrorPanel error={events.error} onRetry={() => void events.refetch()} />}
        {events.data?.items.length === 0 && <Empty title="No events match" hint="Run onboarding or a Lab scenario to generate events." />}
        {events.data && events.data.items.length > 0 && (
          <table className="w-full" data-testid="events-table">
            <thead>
              <tr>
                <th className="th">Time</th>
                <th className="th">Severity</th>
                <th className="th">Type</th>
                <th className="th">Device</th>
                <th className="th">Peer</th>
                <th className="th">Network · step</th>
                <th className="th">Details</th>
              </tr>
            </thead>
            <tbody>
              {events.data.items.map((e) => (
                <tr key={e.id}>
                  <td className="td whitespace-nowrap text-xs text-slate-500">{new Date(e.ts).toLocaleTimeString()}</td>
                  <td className="td"><SeverityBadge severity={e.severity} /></td>
                  <td className="td font-mono text-xs">{e.type}</td>
                  <td className="td font-mono text-xs">{e.device}</td>
                  <td className="td font-mono text-xs">{e.peer ?? ""}</td>
                  <td className="td text-xs">{e.network_id} · {e.step}</td>
                  <td className="td font-mono text-[11px] text-slate-600">
                    {Object.entries(e.details).map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`).join("  ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
