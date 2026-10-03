import { Link } from "react-router-dom";
import { useEvents, useNetworks } from "../api/hooks";
import { useAuth } from "../auth/AuthContext";
import { PageHeader } from "../components/Layout";
import { ModeBanner } from "../components/ModeBanner";
import { Empty, ErrorPanel, Loading } from "../components/States";
import { SeverityBadge, StatusBadge } from "../components/StatusBadge";

export function DashboardPage() {
  const { can } = useAuth();
  const networks = useNetworks();
  const events = useEvents({ limit: 8, severity: "warn,high" });

  return (
    <div>
      <ModeBanner />
      <PageHeader
        title="Networks"
        subtitle="Simulated clustered sensor networks running RP9 (lab) or MAKA-E (product)"
        actions={can("operator") && <Link className="btn-primary" to="/networks/new">+ New network</Link>}
      />
      <div className="grid gap-6 px-6 pb-8 xl:grid-cols-3">
        <section className="card overflow-hidden xl:col-span-2" aria-labelledby="nets-h">
          <h2 id="nets-h" className="sr-only">Networks</h2>
          {networks.isLoading && <Loading />}
          {networks.error && <ErrorPanel error={networks.error} onRetry={() => void networks.refetch()} />}
          {networks.data?.length === 0 && (
            <Empty title="No networks yet" hint={can("operator") ? "Create one with “New network”." : "Ask an operator to create one."} />
          )}
          {networks.data && networks.data.length > 0 && (
            <table className="w-full">
              <thead>
                <tr>
                  <th className="th">Name</th>
                  <th className="th">Kind · protocol</th>
                  <th className="th">Params</th>
                  <th className="th">Devices</th>
                  <th className="th">Status</th>
                </tr>
              </thead>
              <tbody>
                {networks.data.map((n) => (
                  <tr key={n.id} className="hover:bg-slate-50">
                    <td className="td">
                      <Link className="font-medium text-blue-700 hover:underline" to={`/networks/${n.id}`}>{n.name}</Link>
                      <div className="text-xs text-slate-500">{n.template} · step {n.step}</div>
                    </td>
                    <td className="td">
                      <span className={`rounded px-1.5 py-0.5 text-xs font-semibold ${n.kind === "lab" ? "bg-red-100 text-red-800" : "bg-emerald-100 text-emerald-800"}`}>
                        {n.kind === "lab" ? "⚗ lab" : "● product"}
                      </span>{" "}
                      <span className="text-xs">{n.mode === "enhanced" ? "MAKA-E" : "RP9 original"}</span>
                    </td>
                    <td className="td text-xs">{n.params}</td>
                    <td className="td">
                      <div className="flex flex-wrap gap-1">
                        {Object.entries(n.status_counts).map(([s, c]) => (
                          <span key={s} className="inline-flex items-center gap-1 text-xs">
                            <StatusBadge status={s} /> ×{c}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="td text-xs">{n.status === "busy" ? "⟳ busy" : n.status === "failed" ? "✕ last job failed" : "idle"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
        <section className="card" aria-labelledby="ev-h">
          <div className="flex items-center justify-between border-b border-slate-200 px-4 py-2">
            <h2 id="ev-h" className="text-sm font-semibold">Recent warnings</h2>
            <Link className="text-xs text-blue-700 hover:underline" to="/events">All events →</Link>
          </div>
          {events.isLoading && <Loading />}
          {events.error && <ErrorPanel error={events.error} />}
          {events.data?.items.length === 0 && <Empty title="No warnings" hint="Rejections and attacks appear here." />}
          <ul className="divide-y divide-slate-100">
            {events.data?.items.map((e) => (
              <li key={e.id} className="px-4 py-2 text-sm">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={e.severity} />
                  <span className="font-mono text-xs">{e.type}</span>
                </div>
                <div className="mt-0.5 text-xs text-slate-500">
                  {e.device}
                  {e.peer ? ` ← ${e.peer}` : ""} · network {e.network_id} · step {e.step}
                </div>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  );
}
