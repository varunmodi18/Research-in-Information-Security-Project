import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiProblem } from "../api/client";
import { useDevice, useJob, useNetwork, useSubmitJob } from "../api/hooks";
import type { JobType } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { PageHeader } from "../components/Layout";
import { AWAITING, AWAITING_LABEL } from "../components/DesignationNotice";
import { ModeBanner } from "../components/ModeBanner";
import { Empty, ErrorPanel, Loading } from "../components/States";
import { StatusBadge } from "../components/StatusBadge";
import { useJobToast, useToast } from "../components/Toast";
import { useNetworkStream } from "../hooks/useNetworkStream";

// A session row holds "initiator/responder" when the two sides differ (network.session_infos).
function sides(state: string, initiatorIsMe: boolean): { own: string; peer: string } {
  const [ini, rsp = ini] = state.split("/");
  return initiatorIsMe ? { own: ini, peer: rsp } : { own: rsp, peer: ini };
}
const CLOSED_BY_PEER = "closed by peer (device revoked)";

// Device detail (§3.7): identity, public-key fingerprint, status history, sessions (metadata
// only, no key material or key fingerprints, §4.4 rule 4), lifecycle actions.
export function DevicePage() {
  const params = useParams();
  const id = Number(params.id);
  const ident = params.dev ?? "";
  const { can } = useAuth();
  const toast = useToast();
  const trackJob = useJobToast();
  const network = useNetwork(id);
  const device = useDevice(id, ident);
  useNetworkStream(id);
  const submit = useSubmitJob(id);
  const [jobId, setJobId] = useState<number | null>(null);
  const job = useJob(jobId);
  const [confirmRevoke, setConfirmRevoke] = useState(false);
  const [newIdent, setNewIdent] = useState(`${ident}-r1`);

  if (network.isLoading || device.isLoading) return <Loading />;
  if (network.error || device.error || !network.data || !device.data)
    return <ErrorPanel error={network.error ?? device.error} onRetry={() => void device.refetch()} />;
  const d = device.data.device;
  const enhanced = network.data.mode === "enhanced";
  // F2: after a revocation the peers destroy their side of each session; the revoked device is not
  // told (E-09 D7), so its own side still reads ESTABLISHED.
  const stateLabel = (state: string, initiatorIsMe: boolean): string => {
    const { own, peer } = sides(state, initiatorIsMe);
    if (d.status === "revoked" && peer === "CLOSED" && own !== "CLOSED") return CLOSED_BY_PEER;
    return state;
  };
  const closedByPeer = device.data.sessions.some((s) => stateLabel(s.state, s.a === d.ident) === CLOSED_BY_PEER);
  const running = job.data && !["succeeded", "failed", "cancelled", "aborted"].includes(job.data.state);

  const run = async (type: JobType, args: Record<string, unknown>, running: string, done: string) => {
    try {
      const jid = (await submit.mutateAsync({ type, args })).job_id;
      setJobId(jid);
      trackJob(jid, running, done);  // F3: replaced by the outcome when the job finishes
    } catch (err) {
      toast(err instanceof ApiProblem ? `${err.title}: ${err.detail}` : String(err), "error");
    }
  };

  return (
    <div className={network.data.kind === "lab" ? "border-l-4 border-red-500" : ""}>
      <ModeBanner network={network.data} />
      <PageHeader
        title={d.ident}
        subtitle={`${d.role} · cluster ${d.cluster ?? "—"} · network ${network.data.name}`}
        actions={<Link className="btn-secondary" to={`/networks/${id}`}>← Topology</Link>}
      />
      {d.designation_state === AWAITING && (
        <div className="mx-6 mb-3 rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900" role="alert" data-testid="device-awaiting">
          <strong>{AWAITING_LABEL}.</strong> {d.designated} was revoked. {d.ident} is not told: it keeps its sessions and
          PSK with {d.designated} until a replacement CH relays a new designation, and then destroys them. Readings it
          sends until then cannot reach the base station ({d.undelivered ?? 0} lost so far).
        </div>
      )}
      <div className="mx-6 mb-8 grid gap-4 lg:grid-cols-[22rem_1fr]">
        <section className="card p-4" aria-label="Identity">
          <dl className="grid grid-cols-[8rem_1fr] gap-y-1.5 text-sm">
            <dt className="text-slate-500">Status</dt><dd><StatusBadge status={d.status} /></dd>
            <dt className="text-slate-500">Role</dt><dd>{d.role}</dd>
            <dt className="text-slate-500">Cluster</dt><dd>{d.cluster ?? "—"}</dd>
            <dt className="text-slate-500">Epoch</dt><dd title="Registry epoch of this device's last registry change (registration, designation or revocation)">{d.epoch}</dd>
            <dt className="text-slate-500">Pu fingerprint</dt><dd className="font-mono" title="First 8 hex of SHA-256 of the public key H(ID)">{d.pu_fingerprint}</dd>
            {d.role === "CM" && enhanced && <>
              <dt className="text-slate-500">Designated CH</dt><dd className="font-mono">{d.designated ?? "—"}</dd>
              <dt className="text-slate-500">Readings lost</dt><dd>{d.undelivered ?? 0}</dd>
            </>}
          </dl>
          {can("operator") && d.role !== "BS" && (
            <div className="mt-4 space-y-2 border-t border-slate-200 pt-3">
              {!enhanced && <p className="text-xs text-slate-500">RP9 has no revocation or rekey (OB-05); these actions need a MAKA-E network.</p>}
              <button type="button" className="btn-secondary w-full justify-center" disabled={!enhanced || d.status === "revoked" || !!running}
                onClick={() => run("rekey", { device: d.ident }, d.role === "CH" ? "Rekeying the whole cluster…" : "Rekeying…",
                  d.role === "CH" ? `Cluster ${d.ident} rekeyed` : `${d.ident} rekeyed`)}>
                ↻ Rekey {d.role === "CH" ? "cluster" : "sessions"}
              </button>
              <button type="button" className="btn-danger w-full justify-center" disabled={!enhanced || d.status === "revoked" || !!running}
                onClick={() => setConfirmRevoke(true)} data-testid="btn-revoke">
                ⊘ Revoke…
              </button>
              {enhanced && d.status === "revoked" && (
                <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); void run("reprovision", { device: d.ident, new_ident: newIdent }, "Reprovisioning…", `${d.ident} reprovisioned as ${newIdent}`); }}>
                  <label className="sr-only" htmlFor="new-ident">New identity</label>
                  <input id="new-ident" className="input font-mono" value={newIdent} onChange={(e) => setNewIdent(e.target.value)} />
                  <button type="submit" className="btn-primary" disabled={!!running}>Reprovision</button>
                </form>
              )}
            </div>
          )}
          {job.data && (
            <p className="mt-3 text-xs text-slate-600" role="status">
              {running ? "⟳" : job.data.state === "succeeded" ? "✓" : "✕"} {job.data.type}: {job.data.state}
              {job.data.error ? ` — ${job.data.error}` : ""}
            </p>
          )}
          <h2 className="mt-5 text-xs font-semibold uppercase tracking-wide text-slate-500">Status history</h2>
          <ol className="mt-1 space-y-1 text-sm">
            {device.data.status_history.map((h, i) => (
              <li key={i} className="flex items-center gap-2"><span className="w-14 text-xs text-slate-500">step {String(h.step)}</span><StatusBadge status={String(h.status)} /></li>
            ))}
          </ol>
        </section>
        <section className="card overflow-x-auto" aria-label="Sessions">
          <div className="border-b border-slate-200 px-4 py-2 text-sm font-semibold">Sessions (metadata only)</div>
          {device.data.sessions.length === 0 ? (
            <Empty title="No sessions yet" hint="Run Onboard on the topology page." />
          ) : (
            <table className="w-full" data-testid="sessions-table">
              <thead>
                <tr>
                  <th className="th">Peer</th><th className="th">Purpose</th><th className="th">State</th>
                  <th className="th">Established</th><th className="th" title="Registry epoch when the session was established">Epoch</th><th className="th">Sent / recv</th><th className="th">Session id</th>
                </tr>
              </thead>
              <tbody>
                {device.data.sessions.map((s) => (
                  <tr key={s.sid_hex + s.state + s.a}>
                    <td className="td font-mono">{s.a === d.ident ? s.b : s.a}</td>
                    <td className="td">{s.purpose}</td>
                    <td className="td" data-testid="session-state"
                      title={stateLabel(s.state, s.a === d.ident) === CLOSED_BY_PEER
                        ? `This side: ${sides(s.state, s.a === d.ident).own}. Peer: CLOSED (destroyed when ${d.ident} was revoked).` : undefined}>
                      {stateLabel(s.state, s.a === d.ident) === CLOSED_BY_PEER ? "⊘ " : s.state === "ESTABLISHED" ? "✓ "
                        : s.state.startsWith("ABORTED") || s.state.includes("FAILED") ? "✕ " : ""}{stateLabel(s.state, s.a === d.ident)}</td>
                    <td className="td">{s.established_step ?? "—"}</td>
                    <td className="td">{s.epoch}</td>
                    <td className="td">{s.sent} / {s.recv}</td>
                    <td className="td font-mono text-xs" title="public session identifier">{s.sid_hex ? s.sid_hex.slice(0, 12) + "…" : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {closedByPeer && (
            <p className="mx-4 my-2 rounded border border-slate-300 bg-slate-50 p-2 text-xs text-slate-700" data-testid="closed-by-peer-note">
              When {d.ident} was revoked, its peers destroyed their side of these sessions and their PSK with it. The device
              itself is not told (by design: nothing it is told could bind a compromised device), so its own side still reads
              ESTABLISHED. Nothing it sends on these sessions is accepted, and any new handshake from it is refused.
            </p>
          )}
          <p className="px-4 py-2 text-xs text-slate-500">Session keys are never shown, not even as fingerprints (§4.4 rule 4).</p>
        </section>
      </div>
      {confirmRevoke && (
        <ConfirmDialog
          title={`Revoke ${d.ident}?`}
          body="The base station removes it from the registry, destroys its sessions and notifies the cluster head. A revoked identity is never reactivated; it can only rejoin under a new identity."
          expected={d.ident}
          confirmLabel="Revoke device"
          busy={!!running}
          onCancel={() => setConfirmRevoke(false)}
          onConfirm={() => { setConfirmRevoke(false); void run("revoke", { device: d.ident }, `Revoking ${d.ident}…`, `${d.ident} revoked`); }}
        />
      )}
    </div>
  );
}
