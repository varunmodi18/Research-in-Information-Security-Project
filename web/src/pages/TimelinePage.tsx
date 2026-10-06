import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiProblem } from "../api/client";
import { useCancelJob, useFrames, useJob, useNetwork, useSubmitJob } from "../api/hooks";
import type { Frame, JobType } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { PageHeader } from "../components/Layout";
import { ModeBanner } from "../components/ModeBanner";
import { Empty, ErrorPanel, Loading, StreamIndicator } from "../components/States";
import { VerdictBadge } from "../components/StatusBadge";
import { useToast } from "../components/Toast";
import { useNetworkStream } from "../hooks/useNetworkStream";

const COL_W = 132;
const ROW_H = 30;
const TOP = 16;
const HEADER_H = 34;
const LEFT = 64;

function colour(f: Frame): string {
  if (f.fate === "injected") return "#ea580c";
  if (f.verdict === "ACCEPT") return "#059669";
  if (f.verdict === "DROPPED") return "#94a3b8";
  return "#dc2626";
}

// FR-15 / M5-T3: sequence diagram of a network's frames with the receiver's checks.
export function TimelinePage() {
  const id = Number(useParams().id);
  const { can } = useAuth();
  const toast = useToast();
  const network = useNetwork(id);
  const [label, setLabel] = useState("");
  const frames = useFrames(id, { label: label || undefined, limit: 1000 });
  const stream = useNetworkStream(id);
  const submit = useSubmitJob(id);
  const cancel = useCancelJob();
  const [jobId, setJobId] = useState<number | null>(null);
  const job = useJob(jobId);
  const [selected, setSelected] = useState<number | null>(null);
  const [showAll, setShowAll] = useState(false);
  const [hexOpen, setHexOpen] = useState(false);
  const [hidden, setHidden] = useState<Set<string>>(new Set());

  const allLanes = useMemo(() => {
    const d = network.data?.devices ?? [];
    const order = { BS: 0, CH: 1, CM: 2 } as Record<string, number>;
    return [...d].sort((a, b) => order[a.role] - order[b.role] || a.ident.localeCompare(b.ident)).map((x) => x.ident);
  }, [network.data]);
  // F4: lane filter. Frames to or from a hidden lane are drawn to the "other" lane on the right.
  const devices = allLanes.filter((d) => !hidden.has(d));
  const toggle = (d: string) => setHidden((h) => { const n = new Set(h); if (n.has(d)) n.delete(d); else n.add(d); return n; });

  if (network.isLoading) return <Loading />;
  if (network.error || !network.data) return <ErrorPanel error={network.error} />;
  const fetched = frames.data?.items ?? [];
  const all = fetched.filter((f) => devices.includes(f.src) || devices.includes(f.to ?? f.dst));
  const shown = showAll ? all : all.slice(-250);
  const others = shown.some((f) => !devices.includes(f.src) || !devices.includes(f.to ?? f.dst));
  const col = (ident: string | null | undefined) => {
    const i = devices.indexOf(ident ?? "");
    return LEFT + (i < 0 ? devices.length : i) * COL_W + COL_W / 2;
  };
  const sel = all.find((f) => f.id === selected) ?? null;
  const running = job.data && !["succeeded", "failed", "cancelled", "aborted"].includes(job.data.state);
  const width = LEFT + (devices.length + 1) * COL_W;
  const height = TOP + shown.length * ROW_H + 20;

  const run = async (type: JobType, args?: Record<string, unknown>) => {
    try {
      setJobId((await submit.mutateAsync({ type, args })).job_id);
    } catch (err) {
      toast(err instanceof ApiProblem ? `${err.title}: ${err.detail}` : String(err), "error");
    }
  };

  return (
    <div className={network.data.kind === "lab" ? "border-l-4 border-red-500" : ""}>
      <ModeBanner network={network.data} />
      <PageHeader
        title={`Timeline — ${network.data.name}`}
        subtitle="Each arrow is one delivered frame; click it for the receiver's checks"
        actions={
          <>
            <StreamIndicator status={stream} />
            <Link className="btn-secondary" to={`/networks/${id}`}>← Topology</Link>
          </>
        }
      />
      <div className="mx-6 mb-3 flex flex-wrap items-end gap-2">
        {can("operator") && (
          <div className="flex flex-wrap gap-2" role="toolbar" aria-label="Step controls">
            <button type="button" className="btn-secondary" disabled={!!running} onClick={() => run("onboard", { step_mode: true })}>
              Start onboarding (step mode)
            </button>
            <button type="button" className="btn-primary" disabled={!!running} onClick={() => run("step", { count: 1 })} data-testid="btn-step">
              Step
            </button>
            <button type="button" className="btn-secondary" disabled={!!running} onClick={() => run("step", { count: 10 })}>Step ×10</button>
            <button type="button" className="btn-secondary" disabled={!!running} onClick={() => run("step", { until: "quiescent" })}>Run to end</button>
            <button type="button" className="btn-secondary" disabled={!running} onClick={() => jobId && cancel.mutate(jobId)}>
              Cancel
            </button>
          </div>
        )}
        <details className="relative ml-auto" data-testid="lane-filter">
          <summary className="btn-secondary cursor-pointer select-none">Lanes ({devices.length}/{allLanes.length})</summary>
          <div className="absolute right-0 z-20 mt-1 max-h-80 w-56 overflow-y-auto rounded-md border border-slate-200 bg-white p-2 shadow-lg">
            <div className="mb-1 flex gap-2 text-xs">
              <button type="button" className="text-blue-700 underline" onClick={() => setHidden(new Set())}>All</button>
              <button type="button" className="text-blue-700 underline" onClick={() => setHidden(new Set(allLanes))}>None</button>
            </div>
            {allLanes.map((d) => (
              <label key={d} className="flex items-center gap-2 py-0.5 font-mono text-xs">
                <input type="checkbox" checked={!hidden.has(d)} onChange={() => toggle(d)} aria-label={`Lane ${d}`} />{d}
              </label>
            ))}
          </div>
        </details>
        <div>
          <label className="label" htmlFor="tl-label">Filter label</label>
          <input id="tl-label" className="input w-44 font-mono" placeholder="e.g. HS2" value={label} onChange={(e) => setLabel(e.target.value.toUpperCase())} />
        </div>
      </div>
      <div className="mx-6 mb-8 grid gap-4 xl:grid-cols-[1fr_26rem]">
        <div className="card overflow-auto" style={{ maxHeight: "70vh" }}>
          {frames.isLoading && <Loading />}
          {frames.error && <ErrorPanel error={frames.error} />}
          {frames.data && fetched.length === 0 && <Empty title="No frames yet" hint="Start onboarding, then step through it." />}
          {fetched.length > 0 && all.length === 0 && <Empty title="No frames in the selected lanes" hint="Show more lanes with the Lanes filter." />}
          {all.length > 250 && !showAll && (
            <button type="button" className="m-2 text-xs text-blue-700 underline" onClick={() => setShowAll(true)}>
              Show all {all.length} frames (showing the latest 250)
            </button>
          )}
          {all.length > 0 && (
            <div style={{ width }}>
            {/* F4: the lane header stays at the top while the diagram scrolls, and scrolls sideways with it */}
            <div className="sticky top-0 z-10 border-b border-slate-200 bg-white" data-testid="timeline-header">
              <svg width={width} height={HEADER_H} aria-hidden="true">
                <text x={8} y={22} className="fill-slate-400 text-[10px]">step</text>
                {devices.map((d) => (
                  <text key={d} x={col(d)} y={22} textAnchor="middle" className="fill-slate-700 font-mono text-[11px] font-semibold">{d}</text>
                ))}
                {others && <text x={col(null)} y={22} textAnchor="middle" className="fill-slate-400 text-[11px] italic">other</text>}
              </svg>
            </div>
            <svg width={width} height={height} role="img" aria-label="Sequence diagram of frames" data-testid="timeline-svg">
              <defs>
                {["#059669", "#dc2626", "#94a3b8", "#ea580c"].map((c) => (
                  <marker key={c} id={`arrow-${c.slice(1)}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill={c} />
                  </marker>
                ))}
              </defs>
              {devices.map((d) => (
                <line key={d} x1={col(d)} x2={col(d)} y1={0} y2={height} stroke="#cbd5e1" strokeDasharray="4 4" />
              ))}
              {shown.map((f, i) => {
                const y = TOP + i * ROW_H;
                const x1 = col(f.src);
                const x2 = f.to ? col(f.to) : (col(f.src) + col(f.dst)) / 2;
                const c = colour(f);
                const isSel = selected === f.id;
                return (
                  <g key={f.id} onClick={() => { setSelected(f.id); setHexOpen(false); }} className="cursor-pointer" data-testid={`frame-${f.label}`}>
                    <text x={8} y={y + 4} className="fill-slate-400 font-mono text-[10px]">{f.step}</text>
                    <rect x={Math.min(x1, x2) - 4} y={y - 12} width={Math.abs(x2 - x1) + 8} height={20} fill={isSel ? "#dbeafe" : "transparent"} />
                    <line x1={x1} x2={x2} y1={y} y2={y} stroke={c} strokeWidth={isSel ? 2.5 : 1.6}
                      strokeDasharray={f.verdict === "DROPPED" || f.fate === "injected" ? "5 3" : undefined} markerEnd={`url(#arrow-${c.slice(1)})`} />
                    <text x={(x1 + x2) / 2} y={y - 4} textAnchor="middle" className="font-mono text-[10px]" fill={c}>
                      {f.label}{f.verdict === "ACCEPT" ? "" : f.verdict === "DROPPED" ? " ⤫" : " ✕"}
                    </text>
                  </g>
                );
              })}
            </svg>
            </div>
          )}
        </div>
        <aside className="card p-4" aria-label="Frame details">
          {!sel ? (
            <p className="text-sm text-slate-500">Select an arrow to see the frame and the receiver's verification checks.</p>
          ) : (
            <div data-testid="frame-detail">
              <div className="flex items-center justify-between">
                <h2 className="font-mono text-base font-semibold">{sel.label}</h2>
                <VerdictBadge verdict={sel.verdict} />
              </div>
              <dl className="mt-2 grid grid-cols-[7.5rem_1fr] gap-y-1 text-sm">
                <dt className="text-slate-500">From → to</dt><dd className="font-mono">{sel.src} → {sel.to ?? sel.dst}</dd>
                <dt className="text-slate-500">Step</dt><dd>sent {sel.sent_step}, delivered {sel.step}</dd>
                <dt className="text-slate-500">Size</dt><dd>{sel.bytes_len} bytes{sel.paper_bits ? ` · ${sel.paper_bits} bits (RP9 paper model)` : ""}</dd>
                <dt className="text-slate-500">Channel</dt><dd>{sel.fate}</dd>
                {sel.reason && (<><dt className="text-slate-500">Reason</dt><dd className="font-mono text-red-700">{sel.reason}</dd></>)}
              </dl>
              <h3 className="mt-4 text-xs font-semibold uppercase tracking-wide text-slate-500">Receiver checks</h3>
              {sel.checks.length === 0 ? (
                <p className="text-sm text-slate-500">No checks recorded for this frame.</p>
              ) : (
                <ul className="mt-1 space-y-1" data-testid="frame-checks">
                  {sel.checks.map((c, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm">
                      <span className={c.ok ? "text-emerald-700" : "text-red-700"} aria-hidden="true">{c.ok ? "✓" : "✕"}</span>
                      <span>
                        {c.name} <span className="sr-only">{c.ok ? "passed" : "failed"}</span>
                        {c.reason && <span className="font-mono text-xs text-red-700"> — {c.reason}</span>}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
              <h3 className="mt-4 text-xs font-semibold uppercase tracking-wide text-slate-500">Payload (ciphertext and public values only)</h3>
              {sel.payload_hex ? (
                <>
                  <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-slate-100 p-2 font-mono text-[11px]">
                    {hexOpen ? sel.payload_hex : sel.payload_hex.slice(0, 192) + (sel.payload_hex.length > 192 ? "…" : "")}
                  </pre>
                  {sel.payload_hex.length > 192 && (
                    <button type="button" className="text-xs text-blue-700 underline" onClick={() => setHexOpen(!hexOpen)}>
                      {hexOpen ? "Collapse" : "Show all"}
                    </button>
                  )}
                </>
              ) : (
                <p className="text-sm text-slate-500">Not stored (product network, payload over 4 KB).</p>
              )}
              <p className="mt-4 text-xs text-slate-500">Key values are never displayed (§4.4).</p>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}
