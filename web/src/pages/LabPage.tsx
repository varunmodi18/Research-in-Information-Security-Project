import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, ApiProblem, idempotencyKey } from "../api/client";
import { useJob, useNetworks } from "../api/hooks";
import type { JobAccepted } from "../api/types";
import { PageHeader } from "../components/Layout";
import { Empty, ErrorPanel, Loading } from "../components/States";
import { useToast } from "../components/Toast";

interface Scenario {
  id: string;
  title: string;
  gap: string;
  summary: string;
  expected: Record<string, string>;
}

interface RunResult {
  result: string;
  expected: string;
  matches_expectation: boolean;
  explanation: string;
  run_tag: string;
  evidence_frame_rows: number[];
  evidence_event_rows: number[];
  secrets_obtained: string[];
  measurements: Record<string, unknown>;
  frames: number;
  events: number;
}

const MODES = ["original", "enhanced"] as const;
const MODE_LABEL = { original: "RP9 original", enhanced: "MAKA-E" };

function Verdict({ text }: { text: string }) {
  const ok = text === "ATTACK BLOCKED";
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border-2 px-2.5 py-1 text-sm font-bold ${ok ? "border-emerald-500 bg-emerald-50 text-emerald-800" : "border-red-500 bg-red-50 text-red-800"}`}>
      <span aria-hidden="true">{ok ? "🛡" : "⚠"}</span>
      {text}
    </span>
  );
}

// M6-T2: isolated attack experiments, original vs MAKA-E side by side, with linked evidence.
export function LabPage() {
  const toast = useToast();
  const scenarios = useQuery({ queryKey: ["scenarios"], queryFn: () => api.get<Scenario[]>("/lab/scenarios") });
  const networks = useNetworks();
  const labs = (networks.data ?? []).filter((n) => n.kind === "lab");
  const [netId, setNetId] = useState<number | null>(null);
  const [active, setActive] = useState<{ scenario: string; jobId: number } | null>(null);
  const [results, setResults] = useState<Record<string, Record<string, RunResult>>>({});
  const job = useJob(active?.jobId ?? null);
  useEffect(() => {
    if (netId === null && labs.length > 0) setNetId(labs[0].id);
  }, [labs, netId]);
  useEffect(() => {
    const d = job.data;
    if (!d || !active || !["succeeded", "failed", "cancelled", "aborted"].includes(d.state)) return;
    if (d.state === "succeeded" && d.result) {
      const runs = (d.result as { runs: Record<string, RunResult> }).runs;
      setResults((r) => ({ ...r, [active.scenario]: { ...(r[active.scenario] ?? {}), ...runs } }));
    } else toast(`${active.scenario}: ${d.state} ${d.error ?? ""}`, "error");
    setActive(null);
  }, [job.data?.state]); // eslint-disable-line react-hooks/exhaustive-deps

  const run = async (scenario: string, modes: string[]) => {
    if (netId === null) return;
    try {
      const r = await api.post<JobAccepted>(`/networks/${netId}/jobs`, {
        type: "lab_scenario", args: { scenario, modes }, idempotency_key: idempotencyKey(),
      });
      setActive({ scenario, jobId: r.job_id });
    } catch (err) {
      toast(err instanceof ApiProblem ? `${err.title}: ${err.detail}` : String(err), "error");
    }
  };

  return (
    <div className="min-h-screen border-l-4 border-red-500">
      <div className="border-b border-red-300 bg-red-50 px-6 py-1.5 text-xs font-semibold text-red-900" data-testid="mode-banner">
        ⚗ Attack laboratory — not a product network · adversaries act on real protocol bytes inside isolated lab
        networks · results shown are what actually happened, not predictions
      </div>
      <PageHeader title="Attack laboratory" subtitle="Each scenario runs on a fresh network in each mode, from the selected lab network's parameters and seed"
        actions={
          <div>
            <label className="label" htmlFor="lab-net">Lab network</label>
            <select id="lab-net" className="input w-64" value={netId ?? ""} onChange={(e) => setNetId(Number(e.target.value))}>
              {labs.map((n) => <option key={n.id} value={n.id}>{n.name} ({n.params}, scenario seed {n.seed ?? "20260927 (default)"})</option>)}
            </select>
          </div>
        } />
      {(scenarios.isLoading || networks.isLoading) && <Loading />}
      {scenarios.error && <ErrorPanel error={scenarios.error} />}
      {networks.data && labs.length === 0 && (
        <Empty title="No lab network" hint="Create a network of kind “Lab” first (New network)." />
      )}
      <div className="mx-6 mb-8 space-y-4">
        {scenarios.data?.map((s) => {
          const res = results[s.id] ?? {};
          const busy = active?.scenario === s.id;
          return (
            <section key={s.id} className="card p-4" aria-labelledby={`sc-${s.id}`} data-testid={`scenario-${s.id}`}>
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="max-w-2xl">
                  <h2 id={`sc-${s.id}`} className="text-base font-semibold"><span className="font-mono text-red-700">{s.id}</span> {s.title}</h2>
                  <p className="mt-0.5 text-sm text-slate-600">{s.summary}</p>
                  <p className="mt-1 text-xs text-slate-500">Gap {s.gap} · predicted: RP9 {s.expected.original.replace("ATTACK ", "").toLowerCase()}, MAKA-E {s.expected.enhanced.replace("ATTACK ", "").toLowerCase()}</p>
                </div>
                <div className="flex gap-2">
                  <button type="button" className="btn-secondary" disabled={!!active || netId === null} onClick={() => run(s.id, ["original"])}>Run RP9</button>
                  <button type="button" className="btn-secondary" disabled={!!active || netId === null} onClick={() => run(s.id, ["enhanced"])}>Run MAKA-E</button>
                  <button type="button" className="btn-primary" disabled={!!active || netId === null} onClick={() => run(s.id, ["original", "enhanced"])} data-testid={`run-both-${s.id}`}>
                    {busy ? "⟳ Running…" : "Run both"}
                  </button>
                </div>
              </div>
              {Object.keys(res).length > 0 && (
                <div className="mt-4 grid gap-3 md:grid-cols-2">
                  {MODES.map((m) => {
                    const r = res[m];
                    return (
                      <div key={m} className="rounded-md border border-slate-200 p-3" data-testid={`result-${s.id}-${m}`}>
                        <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">{MODE_LABEL[m]}</div>
                        {!r ? <p className="text-sm text-slate-500">Not run.</p> : (
                          <>
                            <Verdict text={r.result} />
                            <span className={`ml-2 text-xs ${r.matches_expectation ? "text-slate-500" : "font-semibold text-amber-700"}`}>
                              {r.matches_expectation ? "✓ as predicted" : `⚠ prediction was ${r.expected} — recorded as a finding`}
                            </span>
                            <p className="mt-2 text-sm">{r.explanation}</p>
                            {r.secrets_obtained.length > 0 && (
                              <p className="mt-2 text-xs text-slate-600">Secrets obtained (names only): <span className="font-mono">{r.secrets_obtained.join(", ")}</span></p>
                            )}
                            <div className="mt-2 flex gap-3 text-xs">
                              <Link className="text-blue-700 underline" to={`/networks/${netId}/frames?run_tag=${encodeURIComponent(r.run_tag)}`}>
                                Evidence frames ({r.evidence_frame_rows.length} linked, {r.frames} total)
                              </Link>
                              <Link className="text-blue-700 underline" to={`/events?run_tag=${encodeURIComponent(r.run_tag)}`}>Events ({r.events})</Link>
                            </div>
                          </>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </section>
          );
        })}
      </div>
    </div>
  );
}
