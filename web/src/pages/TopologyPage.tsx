import { Background, Controls, Handle, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api as http, ApiProblem } from "../api/client";
import { useJob, useNetwork, useSubmitJob } from "../api/hooks";
import type { Device, JobType, NetworkDetail } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { PageHeader } from "../components/Layout";
import { AWAITING, AWAITING_LABEL, DesignationBanner } from "../components/DesignationNotice";
import { ModeBanner } from "../components/ModeBanner";
import { ErrorPanel, Loading, StreamIndicator } from "../components/States";
import { SeverityBadge, STATUS_COLOURS, StatusBadge } from "../components/StatusBadge";
import { useJobToast, useToast } from "../components/Toast";
import { useNetworkStream, type StreamMessage } from "../hooks/useNetworkStream";

type DeviceNodeData = { device: Device; selected: boolean };

function DeviceNode({ data }: NodeProps<Node<DeviceNodeData>>) {
  const d = data.device;
  const colour = STATUS_COLOURS[d.status] ?? "#94a3b8";
  return (
    <div
      className={`rounded-lg border-2 bg-white px-3 py-2 text-center shadow-sm ${data.selected ? "ring-2 ring-blue-500" : ""}`}
      style={{ borderColor: colour, minWidth: 116 }}
      data-testid={`node-${d.ident}`}
      data-status={d.status}
      data-designation={d.designation_state ?? undefined}
    >
      <Handle type="target" position={Position.Top} className="!bg-slate-400" />
      <div className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">{d.role}</div>
      <div className="font-mono text-sm font-semibold">{d.ident}</div>
      <div className="mt-1">
        <StatusBadge status={d.status} />
      </div>
      {d.designation_state === AWAITING && (
        <div className="mt-1 rounded bg-amber-100 px-1 text-[10px] font-semibold text-amber-900" title={AWAITING_LABEL}>
          ⚠ CH revoked
        </div>
      )}
      <Handle type="source" position={Position.Bottom} className="!bg-slate-400" />
    </div>
  );
}

const nodeTypes = { device: DeviceNode };

function layout(net: NetworkDetail, selected: string | null): { nodes: Node<DeviceNodeData>[]; edges: Edge[] } {
  const bs = net.devices.find((d) => d.role === "BS");
  const chs = net.devices.filter((d) => d.role === "CH");
  const cmsOf = (ch: string) => net.devices.filter((d) => d.role === "CM" && d.cluster === ch);
  const colW = 150;
  const nodes: Node<DeviceNodeData>[] = [];
  const edges: Edge[] = [];
  let x = 0;
  const chX: Record<string, number> = {};
  for (const ch of chs) {
    const n = Math.max(1, cmsOf(ch.ident).length);
    chX[ch.ident] = x + ((n - 1) * colW) / 2;
    cmsOf(ch.ident).forEach((cm, i) => {
      nodes.push({ id: cm.ident, type: "device", position: { x: x + i * colW, y: 320 }, data: { device: cm, selected: selected === cm.ident } });
      edges.push({ id: `${ch.ident}-${cm.ident}`, source: ch.ident, target: cm.ident, style: { stroke: "#94a3b8" } });
    });
    x += n * colW + 40;
  }
  chs.forEach((ch) =>
    nodes.push({ id: ch.ident, type: "device", position: { x: chX[ch.ident], y: 160 }, data: { device: ch, selected: selected === ch.ident } }),
  );
  if (bs) {
    nodes.push({ id: bs.ident, type: "device", position: { x: (x - 40 - colW) / 2, y: 0 }, data: { device: bs, selected: selected === bs.ident } });
    chs.forEach((ch) => edges.push({ id: `${bs.ident}-${ch.ident}`, source: bs.ident, target: ch.ident, style: { stroke: "#64748b", strokeWidth: 2 } }));
  }
  return { nodes, edges };
}

export function TopologyPage() {
  const id = Number(useParams().id);
  const { can } = useAuth();
  const toast = useToast();
  const trackJob = useJobToast();
  const navigate = useNavigate();
  const network = useNetwork(id);
  const [dialog, setDialog] = useState<"reset" | "delete" | "designate" | null>(null);
  const [desCluster, setDesCluster] = useState("");
  const [desCh, setDesCh] = useState("");
  const submit = useSubmitJob(id);
  const [jobId, setJobId] = useState<number | null>(null);
  const job = useJob(jobId);
  const [selected, setSelected] = useState<string | null>(null);
  const [feed, setFeed] = useState<StreamMessage[]>([]);
  const stream = useNetworkStream(id, (m) => {
    if (m.kind === "security_event") setFeed((f) => [m, ...f].slice(0, 25));
  });

  useEffect(() => {
    const s = job.data?.state;
    if (!s || !["succeeded", "failed", "cancelled", "aborted"].includes(s)) return;
    if (s === "succeeded") toast(`${job.data?.type} finished`);
    else toast(`${job.data?.type} ${s}: ${job.data?.error ?? ""}`, "error");
  }, [job.data?.state]); // eslint-disable-line react-hooks/exhaustive-deps

  const graph = useMemo(() => (network.data ? layout(network.data, selected) : { nodes: [], edges: [] }), [network.data, selected]);

  if (network.isLoading) return <Loading />;
  if (network.error || !network.data) return <ErrorPanel error={network.error} onRetry={() => void network.refetch()} />;
  const net = network.data;
  const running = job.data && !["succeeded", "failed", "cancelled", "aborted"].includes(job.data.state);
  const sel = net.devices.find((d) => d.ident === selected) ?? null;

  const run = async (type: JobType, args?: Record<string, unknown>, track?: [string, string]) => {
    try {
      const r = await submit.mutateAsync({ type, args });
      setJobId(r.job_id);
      if (track) trackJob(r.job_id, track[0], track[1]);
    } catch (err) {
      toast(err instanceof ApiProblem ? `${err.title}: ${err.detail}` : String(err), "error");
    }
  };
  const deleteNetwork = async () => {
    setDialog(null);
    try {
      await http.del(`/networks/${id}`, { confirm_name: net.name });
      toast(`Network “${net.name}” deleted`);
      navigate("/");
    } catch (err) {
      toast(err instanceof ApiProblem ? `${err.title}: ${err.detail}` : String(err), "error");
    }
  };
  const clusters = [...new Set(net.devices.filter((d) => d.role === "CH").map((d) => d.cluster ?? d.ident))];

  return (
    <div className={net.kind === "lab" ? "border-l-4 border-red-500" : ""}>
      <ModeBanner network={net} />
      <PageHeader
        title={net.name}
        subtitle={`${net.template} · step ${net.step} · ${net.devices.length} devices${net.mode === "enhanced"
          ? ` · registry epoch ${Math.max(0, ...net.devices.map((d) => d.epoch))}` : ""}`}
        actions={
          <>
            <StreamIndicator status={stream} />
            <Link className="btn-secondary" to={`/networks/${id}/frames`}>Frames</Link>
            <Link className="btn-secondary" to={`/networks/${id}/timeline`}>Timeline</Link>
            {can("operator") && <Link className="btn-secondary" to={`/networks/${id}/readings`}>Readings</Link>}
          </>
        }
      />
      {can("operator") && (
        <div className="mx-6 mb-3 flex flex-wrap items-center gap-2" role="toolbar" aria-label="Network actions">
          <button type="button" className="btn-primary" disabled={!!running} onClick={() => run("onboard")} data-testid="btn-onboard">
            ▶ Onboard
          </button>
          <button type="button" className="btn-secondary" disabled={!!running} onClick={() => run("onboard", { step_mode: true })}>
            Onboard (step mode)
          </button>
          <button type="button" className="btn-secondary" disabled={!!running} onClick={() => run("step", { count: 1 })}>Step</button>
          <button type="button" className="btn-secondary" disabled={!!running} onClick={() => run("step", { count: 10 })}>Step ×10</button>
          <button type="button" className="btn-secondary" disabled={!!running} onClick={() => run("step", { until: "quiescent" })}>Run to end</button>
          <button type="button" className="btn-secondary" disabled={!!running} onClick={() => run("send_readings", { count: 1 })} data-testid="btn-readings">
            Send readings
          </button>
          <span className="mx-1 h-6 w-px bg-slate-300" aria-hidden="true" />
          {net.mode === "enhanced" && (
            <button type="button" className="btn-secondary" disabled={!!running} data-testid="btn-designate"
              onClick={() => { setDesCluster(clusters[0] ?? ""); setDesCh(`${clusters[0] ?? "CH"}-r1`); setDialog("designate"); }}>
              Designate CH…
            </button>
          )}
          <button type="button" className="btn-danger" disabled={!!running} onClick={() => setDialog("reset")} data-testid="btn-reset-network">
            Reset network…
          </button>
          {can("admin") && (
            <button type="button" className="btn-danger" disabled={!!running} onClick={() => setDialog("delete")} data-testid="btn-delete-network">
              Delete network…
            </button>
          )}
        </div>
      )}
      {dialog === "reset" && (
        <ConfirmDialog title={`Reset ${net.name}?`} expected={net.name} confirmLabel="Reset network" busy={!!running}
          body="Re-creates the template's devices under a new master key. Every session ends and every device returns to provisioned. Devices added later (by reprovisioning or designation) are removed, and periodic readings stop. Frames, events and readings recorded so far are kept."
          onCancel={() => setDialog(null)}
          onConfirm={() => { setDialog(null); void run("reset_network", {}, [`Resetting ${net.name}…`, `${net.name} reset`]); }} />
      )}
      {dialog === "delete" && (
        <ConfirmDialog title={`Delete ${net.name}?`} expected={net.name} confirmLabel="Delete network"
          body="Deletes the network with its devices, keystores, frames, events and readings. This cannot be undone."
          onCancel={() => setDialog(null)} onConfirm={() => void deleteNetwork()} />
      )}
      {dialog === "designate" && (
        <ConfirmDialog title="Designate a cluster head" expected={desCluster} confirmLabel="Designate" busy={!!running}
          body="The base station designates this CH for the cluster (a new identity is provisioned as a CH first). The previous CH of the cluster is no longer designated; its members follow the new one when it relays their new designation."
          onCancel={() => setDialog(null)}
          onConfirm={() => { setDialog(null); void run("designate", { cluster: desCluster, ch: desCh }, [`Designating ${desCh} for ${desCluster}…`, `${desCh} designated for cluster ${desCluster}`]); }}>
          <div className="mt-3 grid grid-cols-2 gap-2">
            <div>
              <label className="label" htmlFor="des-cluster">Cluster</label>
              <select id="des-cluster" className="input" value={desCluster} onChange={(e) => setDesCluster(e.target.value)}>
                {clusters.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label className="label" htmlFor="des-ch">Cluster head identity</label>
              <input id="des-ch" className="input font-mono" value={desCh} onChange={(e) => setDesCh(e.target.value)} />
            </div>
          </div>
        </ConfirmDialog>
      )}
      <DesignationBanner devices={net.devices} />
      {job.data && (
        <div className="mx-6 mb-3" data-testid="job-status">
          {running ? (
            <div className="card p-3">
              <div className="flex justify-between text-xs text-slate-600">
                <span>⟳ {job.data.type}: {job.data.phase || job.data.state}</span>
                <span>{Math.round(job.data.progress * 100)}%</span>
              </div>
              <div className="mt-1 h-2 overflow-hidden rounded bg-slate-200">
                <div className="h-2 bg-blue-600 transition-all" style={{ width: `${Math.round(job.data.progress * 100)}%` }} />
              </div>
            </div>
          ) : job.data.state !== "succeeded" ? (
            <div className="rounded-md border border-red-300 bg-red-50 p-3 text-sm text-red-900" role="alert">
              ✕ Job {job.data.type} {job.data.state}: {job.data.error}{" "}
              <Link className="underline" to={`/events?network=${id}`}>See events</Link>
            </div>
          ) : null}
        </div>
      )}
      <div className="mx-6 mb-8 grid gap-4 xl:grid-cols-[1fr_22rem]">
        <div className="card h-[460px]" aria-label="Network topology">
          <ReactFlow nodes={graph.nodes} edges={graph.edges} nodeTypes={nodeTypes} fitView
            onNodeClick={(_, n) => setSelected(n.id)} nodesDraggable={false} proOptions={{ hideAttribution: true }}>
            <Background gap={20} color="#e2e8f0" />
            <Controls showInteractive={false} />
          </ReactFlow>
        </div>
        <div className="flex flex-col gap-4">
          <section className="card p-4" aria-label="Selected device">
            {sel ? (
              <>
                <div className="text-xs font-semibold uppercase text-slate-500">{sel.role}</div>
                <div className="font-mono text-lg font-semibold">{sel.ident}</div>
                <dl className="mt-2 grid grid-cols-[7rem_1fr] gap-y-1 text-sm">
                  <dt className="text-slate-500">Status</dt><dd><StatusBadge status={sel.status} /></dd>
                  <dt className="text-slate-500">Cluster</dt><dd>{sel.cluster ?? "—"}</dd>
                  <dt className="text-slate-500">Epoch</dt><dd>{sel.epoch}</dd>
                  <dt className="text-slate-500">Pu fingerprint</dt><dd className="font-mono">{sel.pu_fingerprint}</dd>
                  {sel.role === "CM" && <>
                    <dt className="text-slate-500">Designated CH</dt>
                    <dd>{sel.designated ?? "—"}{sel.designation_state === AWAITING && <span className="ml-1 text-xs font-semibold text-amber-800">({AWAITING_LABEL})</span>}</dd>
                    <dt className="text-slate-500">Readings lost</dt><dd>{sel.undelivered ?? 0}</dd>
                  </>}
                </dl>
                <Link className="btn-secondary mt-3" to={`/networks/${id}/devices/${sel.ident}`}>Device details →</Link>
              </>
            ) : (
              <p className="text-sm text-slate-500">Select a device in the graph to inspect it.</p>
            )}
          </section>
          <section className="card flex-1 overflow-hidden" aria-label="Live security events">
            <div className="border-b border-slate-200 px-4 py-2 text-sm font-semibold">Live events</div>
            {feed.length === 0 ? (
              <p className="p-4 text-sm text-slate-500">Events stream here while jobs run.</p>
            ) : (
              <ul className="max-h-72 divide-y divide-slate-100 overflow-y-auto" data-testid="live-events">
                {feed.map((m) => (
                  <li key={m.id} className="px-4 py-1.5 text-xs">
                    <SeverityBadge severity={String(m.data.severity)} /> <span className="font-mono">{String(m.data.type)}</span>{" "}
                    <span className="text-slate-500">{String(m.data.device)}{m.data.peer ? ` ← ${String(m.data.peer)}` : ""}</span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}
