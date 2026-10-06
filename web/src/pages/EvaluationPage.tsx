import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, LabelList, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, ApiProblem, idempotencyKey } from "../api/client";
import { useJob, useNetworks } from "../api/hooks";
import type { JobAccepted } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { PageHeader } from "../components/Layout";
import { Empty, ErrorPanel, Loading } from "../components/States";
import { useToast } from "../components/Toast";

// M7-T6. Charts follow the dataviz rules: categorical slots 1-3 in fixed order (validated palette),
// a legend plus value labels on every bar (slot 3 is below 3:1 contrast), one axis per chart,
// small multiples per parameter set, a hover tooltip, and a table view of the same numbers.

interface RoleSummary {
  devices: number;
  ops_per_device: Record<string, number>;
  rp9_constant_ms_per_device: number;
  traffic_per_device: Record<string, number>;
  keystore_bytes: number;
  peak_keystore_bytes: number;
}
interface ResultRow {
  variant: Variant;
  topology: string;
  params: string;
  complete: boolean;
  onboard_s: { median: number; q1: number; q3: number; iqr: number };
  per_role: Record<string, RoleSummary>;
  pairings_per_cm: number;
  per_reading_cm_ops: Record<string, number>;
  data_cm_bytes: number;
  reading_payload_bytes: number;
}
interface Threshold { metric: string; value: number; threshold: string; pass: boolean }
interface Comparison { results: ResultRow[]; thresholds: Threshold[]; meta?: Record<string, unknown>; file?: string }
interface RunListItem { id: number; job_id: number; state: string; config: Record<string, unknown>; created_at: string }
interface Reference {
  table2: Record<string, { rp9_formula: string; measured: Record<string, number> }>;
  table3: { phase: string; rp9: number; measured: number; note: string }[];
  table4: { phase: string; rp9: number; derived: number; note: string }[];
  table5: { scheme: string; formula: string; published_ms: number; recomputed_ms: number; flag: string }[];
  table6: { features: string[]; rows: Record<string, string[]> };
  formal: { tool?: string; date?: string; hlpsl?: string; cl_atse?: string;
    results: Record<string, { sessions: number; summary: string; goal: string;
      statistics?: Record<string, string | number>; file?: string }[]> };
  formal_avispa: { obtained: boolean; paper_fig9?: Record<string, string | number>; rows: AvispaRow[] };
  security_levels: Record<string, string>;
  limitations: string[];
  latest_comparison: Comparison | null;
}

type Variant = "original+secure" | "original+clear" | "enhanced";
const VARIANTS: Variant[] = ["original+secure", "original+clear", "enhanced"];
const COLOR: Record<Variant, string> = { "original+secure": "#2a78d6", "original+clear": "#eb6834", enhanced: "#1baf7a" };
const LABEL: Record<Variant, string> = {
  "original+secure": "RP9 (pseudo-IDs encrypted)", "original+clear": "RP9 (as priced in Table 2)", enhanced: "MAKA-E",
};
const INK_2 = "#52514e";
const GRID = "#e4e3df";
const FORMAL_MODELS: Record<string, string> = {
  maka_e_ake: "MAKA-E key exchange",
  maka_e_ake_nopsk_control: "MAKA-E without PSK (negative control)",
  maka_e_ake_fs: "MAKA-E, PSK leaked after the session (forward secrecy)",
  maka_e_ake_fs_nodh_control: "MAKA-E without DH, PSK leaked (negative control)",
  rp9_auth: "RP9 authentication, dishonest CH",
  rp9_auth_honest_ch: "RP9 authentication, insider CM (P-01)",
  rp9_auth_outsider: "RP9 authentication, outsider only",
};
// What a row's result means where the verdict alone would mislead (follow-up Part C3/C4).
const FORMAL_NOTES: Record<string, string> = {
  "rp9_auth_outsider/2": "Without a receiver-side nonce record, replay succeeds; RP9's replay protection rests entirely on that record, which RP9 does not specify.",
  "maka_e_ake_fs/2": "The leaked keys belong to a responder session the intruder opened and completed after the PSK leaked (impersonation after compromise), not to a session completed before it. AnB cannot restrict the leak to after all sessions; see formal/avispa/README.md.",
};

interface AvispaRow {
  model: string; label: string; note: string; sessions: string; backend: string; verdict: string; violated: string;
  message: string; statistics: Record<string, string | number>; file: string;
  per_goal: { goal: string; verdict: string }[]; executable_transitions: string; translated_by_original: boolean;
}

const VERDICT_CLASS: Record<string, string> = { SAFE: "text-emerald-700", NO_ATTACK_FOUND: "text-emerald-700",
  UNSAFE: "text-red-700", ATTACK_FOUND: "text-red-700" };

function stats(s?: Record<string, string | number>): string {
  if (!s) return "—";
  const parts: string[] = [];
  if (s.visited_nodes !== undefined) parts.push(`${s.visited_nodes} nodes`);
  if (s.depth_plies !== undefined) parts.push(`depth ${s.depth_plies}`);
  if (s.analysed_states !== undefined) parts.push(`${s.analysed_states} analysed`);
  if (s.reachable_states !== undefined) parts.push(`${s.reachable_states} reachable`);
  if (s.search_time !== undefined) parts.push(String(s.search_time));
  if (s.time !== undefined) parts.push(String(s.time));
  return parts.length ? parts.join(", ") : "—";
}

function Section({ title, children, id }: { title: string; children: React.ReactNode; id: string }) {
  return (
    <section className="card p-4" aria-labelledby={id} data-testid={id}>
      <h2 id={id} className="mb-3 text-base font-semibold">{title}</h2>
      {children}
    </section>
  );
}

function PassFail({ pass }: { pass: boolean }) {
  return pass
    ? <span className="font-semibold text-emerald-700">✓ pass</span>
    : <span className="font-semibold text-red-700">✗ fail</span>;
}

function VariantBars({ data, unit, digits }: { data: Record<string, string | number>[]; unit: string; digits: number }) {
  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={data} margin={{ top: 18, right: 8, bottom: 0, left: 0 }} barCategoryGap="22%">
        <CartesianGrid vertical={false} stroke={GRID} />
        <XAxis dataKey="group" tickLine={false} axisLine={{ stroke: GRID }} tick={{ fill: INK_2, fontSize: 12 }} />
        <YAxis tickLine={false} axisLine={false} tick={{ fill: INK_2, fontSize: 11 }} width={44}
          label={{ value: unit, angle: -90, position: "insideLeft", fill: INK_2, fontSize: 11 }} />
        <Tooltip cursor={{ fill: "rgba(0,0,0,0.04)" }} itemStyle={{ color: "#0b0b0b" }} labelStyle={{ color: INK_2 }}
          formatter={(v: number, name: string) => [`${v.toFixed(digits)} ${unit}`, LABEL[name as Variant] ?? name]} />
        <Legend formatter={(v: string) => <span style={{ color: "#0b0b0b", fontSize: 12 }}>{LABEL[v as Variant] ?? v}</span>} />
        {VARIANTS.map((v) => (
          <Bar key={v} dataKey={v} maxBarSize={64} fill={COLOR[v]} stroke="#ffffff" strokeWidth={2} radius={[4, 4, 0, 0]} isAnimationActive={false}>
            <LabelList dataKey={v} position="top" fill={INK_2} fontSize={10} formatter={(x: number) => x.toFixed(digits)} />
          </Bar>
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
}

function ComparisonView({ cmp }: { cmp: Comparison }) {
  const [view, setView] = useState<"chart" | "table">("chart");
  const params = ["toy", "demo", "secure"].filter((p) => cmp.results.some((r) => r.params === p));
  const find = (v: Variant, t: string, p: string) => cmp.results.find((r) => r.variant === v && r.topology === t && r.params === p);
  const costParams = params[0];
  const costTopo = ["paper", "small", "net"].find((t) => cmp.results.some((r) => r.params === costParams && r.topology === t)) ?? "paper";
  const costData = ["BS", "CH", "CM"].map((role) => {
    const row: Record<string, string | number> = { group: role };
    for (const v of VARIANTS) row[v] = find(v, costTopo, costParams)?.per_role[role]?.rp9_constant_ms_per_device ?? 0;
    return row;
  });
  return (
    <>
      <div className="mb-3 flex items-center gap-2 text-sm" role="tablist" aria-label="Comparison view">
        {(["chart", "table"] as const).map((k) => (
          <button key={k} type="button" role="tab" aria-selected={view === k}
            className={view === k ? "btn-primary" : "btn-secondary"} onClick={() => setView(k)} data-testid={`view-${k}`}>
            {k === "chart" ? "Charts" : "Table"}
          </button>
        ))}
      </div>
      {view === "chart" ? (
        <div className="space-y-6">
          <div>
            <h3 className="text-sm font-semibold">Onboarding wall time on this host (median of seeds, pure Python)</h3>
            <div className={`grid gap-4 ${params.length > 1 ? "lg:grid-cols-2" : ""}`}>
              {params.map((p) => {
                const topos = ["paper", "small", "net"].filter((t) => cmp.results.some((r) => r.params === p && r.topology === t));
                const data = topos.map((t) => {
                  const row: Record<string, string | number> = { group: t };
                  for (const v of VARIANTS) row[v] = find(v, t, p)?.onboard_s.median ?? 0;
                  return row;
                });
                return (
                  <figure key={p} data-testid={`chart-onboarding-${p}`}>
                    <figcaption className="mb-1 text-xs text-slate-600">{p} parameters</figcaption>
                    <VariantBars data={data} unit="s" digits={2} />
                  </figure>
                );
              })}
            </div>
          </div>
          <figure data-testid="chart-cost">
            <h3 className="text-sm font-semibold">Estimated onboarding cost per device, {costTopo} topology ({costParams} parameters)</h3>
            <figcaption className="mb-1 text-xs text-slate-600">
              Estimate, not a measurement: operation counts × RP9 Table 5 sensor-node constants.
            </figcaption>
            <VariantBars data={costData} unit="ms" digits={0} />
          </figure>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="tbl text-sm" data-testid="comparison-table">
            <thead>
              <tr><th>params</th><th>topology</th><th>variant</th><th className="text-right">onboarding median (s)</th>
                <th className="text-right">IQR (s)</th><th className="text-right">pairings / CM</th>
                <th className="text-right">CM est. ms</th><th className="text-right">CM bytes sent</th>
                <th className="text-right">DATA_CM bytes</th><th>complete</th></tr>
            </thead>
            <tbody>
              {cmp.results.map((r) => (
                <tr key={`${r.params}-${r.topology}-${r.variant}`}>
                  <td>{r.params}</td><td>{r.topology}</td><td>{LABEL[r.variant]}</td>
                  <td className="text-right font-mono">{r.onboard_s.median.toFixed(3)}</td>
                  <td className="text-right font-mono">{r.onboard_s.iqr.toFixed(3)}</td>
                  <td className="text-right font-mono">{r.pairings_per_cm}</td>
                  <td className="text-right font-mono">{r.per_role.CM?.rp9_constant_ms_per_device.toFixed(1)}</td>
                  <td className="text-right font-mono">{r.per_role.CM?.traffic_per_device.bytes_sent ?? 0}</td>
                  <td className="text-right font-mono">{r.data_cm_bytes}</td>
                  <td>{r.complete ? "yes" : "NO"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {cmp.thresholds.length > 0 && (
        <div className="mt-5">
          <h3 className="mb-1 text-sm font-semibold">Thresholds (§6.6, MAKA-E)</h3>
          <table className="tbl text-sm" data-testid="thresholds">
            <thead><tr><th>metric</th><th className="text-right">value</th><th>threshold</th><th>result</th></tr></thead>
            <tbody>
              {cmp.thresholds.map((t) => (
                <tr key={t.metric}><td>{t.metric}</td><td className="text-right font-mono">{t.value}</td>
                  <td className="font-mono">{t.threshold}</td><td><PassFail pass={t.pass} /></td></tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

function RunForm({ onDone }: { onDone: (runId: number) => void }) {
  const toast = useToast();
  const networks = useNetworks();
  const labs = (networks.data ?? []).filter((n) => n.kind === "lab");
  const [netId, setNetId] = useState<number | null>(null);
  const [topology, setTopology] = useState("net");
  const [params, setParams] = useState("demo");
  const [seeds, setSeeds] = useState(5);
  const [jobId, setJobId] = useState<number | null>(null);
  const job = useJob(jobId);
  useEffect(() => {
    if (netId === null && labs.length > 0) setNetId(labs[0].id);
  }, [labs, netId]);
  useEffect(() => {
    const d = job.data;
    if (!d || !["succeeded", "failed", "cancelled", "aborted"].includes(d.state)) return;
    if (d.state === "succeeded" && d.result) onDone((d.result as { run_id: number }).run_id);
    else toast(`Evaluation ${d.state} ${d.error ?? ""}`, "error");
    setJobId(null);
  }, [job.data?.state]); // eslint-disable-line react-hooks/exhaustive-deps

  const submit = async () => {
    if (netId === null) return;
    try {
      const r = await api.post<JobAccepted>(`/networks/${netId}/jobs`, {
        type: "evaluation", args: { topologies: [topology], params: [params], seeds }, idempotency_key: idempotencyKey(),
      });
      setJobId(r.job_id);
    } catch (err) {
      toast(err instanceof ApiProblem ? `${err.title}: ${err.detail}` : String(err), "error");
    }
  };
  if (networks.data && labs.length === 0) {
    return <p className="text-sm text-slate-600">Evaluations run on a lab network; create one first (New network, kind “Lab”).</p>;
  }
  return (
    <div className="flex flex-wrap items-end gap-3">
      <div><label className="label" htmlFor="ev-net">Lab network</label>
        <select id="ev-net" className="input w-48" value={netId ?? ""} onChange={(e) => setNetId(Number(e.target.value))}>
          {labs.map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}
        </select></div>
      <div><label className="label" htmlFor="ev-topo">Topology</label>
        <select id="ev-topo" className="input" value={topology} onChange={(e) => setTopology(e.target.value)}>
          {["paper", "small", "net"].map((t) => <option key={t}>{t}</option>)}
        </select></div>
      <div><label className="label" htmlFor="ev-params">Parameters</label>
        <select id="ev-params" className="input" value={params} onChange={(e) => setParams(e.target.value)}>
          {["toy", "demo", "secure"].map((t) => <option key={t}>{t}</option>)}
        </select></div>
      <div><label className="label" htmlFor="ev-seeds">Seeds</label>
        <input id="ev-seeds" type="number" min={1} max={10} className="input w-20" value={seeds}
          onChange={(e) => setSeeds(Number(e.target.value))} /></div>
      <button type="button" className="btn-primary" disabled={jobId !== null || netId === null} onClick={submit} data-testid="run-evaluation">
        {jobId !== null ? `⟳ Running… ${Math.round((job.data?.progress ?? 0) * 100)}%` : "Run comparison"}
      </button>
      {jobId !== null && job.data?.phase && <span className="text-xs text-slate-500">{job.data.phase}</span>}
    </div>
  );
}

export function EvaluationPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const ref = useQuery({ queryKey: ["evaluation", "reference"], queryFn: () => api.get<Reference>("/evaluation/reference"), staleTime: Infinity });
  const runs = useQuery({ queryKey: ["evaluation", "runs"], queryFn: () => api.get<RunListItem[]>("/evaluation/runs") });
  const [selected, setSelected] = useState<number | null>(null);
  const latestOk = runs.data?.find((r) => r.state === "succeeded")?.id ?? null;
  const runId = selected ?? latestOk;
  const run = useQuery({
    queryKey: ["evaluation", "run", runId], enabled: runId !== null,
    queryFn: () => api.get<{ id: number; config: Record<string, unknown>; result: Comparison }>(`/evaluation/runs/${runId}`),
  });
  const canRun = can("operator");
  const cmp = runId !== null ? run.data?.result : ref.data?.latest_comparison;
  const source = runId !== null
    ? `evaluation run #${runId}`
    : ref.data?.latest_comparison?.file ? `committed artefact ${ref.data.latest_comparison.file}` : "";

  return (
    <div>
      <PageHeader title="Evaluation" subtitle="Original RP9 vs MAKA-E: operation counts, bytes, timings; RP9 table reproductions; formal results" />
      <div className="mx-6 mb-8 space-y-4">
        <aside className="rounded-md border-2 border-amber-400 bg-amber-50 p-4 text-sm text-amber-950" data-testid="limitations" aria-label="Limitations">
          <h2 className="mb-1 font-semibold">Limitations of this evidence (§6.7)</h2>
          <ul className="list-disc space-y-0.5 pl-5">
            {(ref.data?.limitations ?? []).map((l) => <li key={l}>{l}</li>)}
          </ul>
        </aside>
        {ref.isLoading && <Loading />}
        {ref.error && <ErrorPanel error={ref.error} />}

        <Section title="Original vs enhanced comparison" id="ev-comparison">
          {canRun && <div className="mb-4"><RunForm onDone={(id) => { setSelected(id); qc.invalidateQueries({ queryKey: ["evaluation", "runs"] }); }} /></div>}
          {runs.data && runs.data.length > 0 && (
            <div className="mb-3 text-sm">
              <label className="label" htmlFor="ev-run">Run</label>
              <select id="ev-run" className="input w-80" value={runId ?? ""} onChange={(e) => setSelected(Number(e.target.value))}>
                {runs.data.map((r) => <option key={r.id} value={r.id} disabled={r.state !== "succeeded"}>
                  #{r.id} {r.state} · {String((r.config.topologies as string[] | undefined)?.join(",") ?? "")} / {String((r.config.params as string[] | undefined)?.join(",") ?? "")} · {String(r.config.seeds ?? "")} seeds
                </option>)}
              </select>
            </div>
          )}
          {source && <p className="mb-3 text-xs text-slate-500">Source: {source}</p>}
          {run.isLoading && <Loading />}
          {cmp ? <ComparisonView cmp={cmp} /> : !run.isLoading && <Empty title="No comparison yet" hint="Run one above, or commit an artefact with eval/bench/compare.py." />}
        </Section>

        {ref.data && (
          <>
            <Section title="RP9 table reproductions" id="ev-rp9">
              <div className="grid gap-6 lg:grid-cols-2">
                <div>
                  <h3 className="text-sm font-semibold">Table 2: per-role operations (original mode, paper topology, counted)</h3>
                  <table className="tbl text-sm">
                    <thead><tr><th>role</th><th>RP9 formula</th>{["T_HG", "T_SM", "T_E/D", "T_P"].map((o) => <th key={o} className="text-right">{o}</th>)}</tr></thead>
                    <tbody>{Object.entries(ref.data.table2).map(([role, r]) => (
                      <tr key={role}><td>{role}</td><td className="font-mono text-xs">{r.rp9_formula}</td>
                        {["T_HG", "T_SM", "T_E/D", "T_P"].map((o) => <td key={o} className="text-right font-mono">{r.measured[o]}</td>)}</tr>
                    ))}</tbody>
                  </table>
                  <p className="mt-1 text-xs text-slate-500">AM-04: Table 5 prices MAKA at 3T_P; summing Table 2 gives 2T_P.</p>
                </div>
                <div>
                  <h3 className="text-sm font-semibold">Table 3: communication cost (bits, paper size model)</h3>
                  <table className="tbl text-sm">
                    <thead><tr><th>phase</th><th className="text-right">RP9</th><th className="text-right">counted</th><th>note</th></tr></thead>
                    <tbody>{ref.data.table3.map((r) => (
                      <tr key={r.phase}><td>{r.phase}</td><td className="text-right font-mono">{r.rp9}</td>
                        <td className="text-right font-mono">{r.measured}</td><td className="text-xs">{r.note}</td></tr>
                    ))}</tbody>
                  </table>
                </div>
                <div>
                  <h3 className="text-sm font-semibold">Table 4: CM storage (bits)</h3>
                  <table className="tbl text-sm">
                    <thead><tr><th>after</th><th className="text-right">RP9</th><th className="text-right">derived from state</th><th>note</th></tr></thead>
                    <tbody>{ref.data.table4.map((r) => (
                      <tr key={r.phase}><td>{r.phase}</td><td className="text-right font-mono">{r.rp9}</td>
                        <td className="text-right font-mono">{r.derived}</td><td className="text-xs">{r.note}</td></tr>
                    ))}</tbody>
                  </table>
                </div>
                <div>
                  <h3 className="text-sm font-semibold">Table 5: computation cost (ms, RP9 constants)</h3>
                  <table className="tbl text-sm" data-testid="table5">
                    <thead><tr><th>scheme</th><th className="text-right">published</th><th className="text-right">recomputed</th><th>flag</th></tr></thead>
                    <tbody>{ref.data.table5.map((r) => (
                      <tr key={r.scheme} title={r.formula}><td>{r.scheme}</td><td className="text-right font-mono">{r.published_ms}</td>
                        <td className="text-right font-mono">{r.recomputed_ms}</td>
                        <td className={`text-xs ${r.flag.startsWith("ER-") || r.flag.startsWith("AM-") ? "font-semibold text-amber-800" : ""}`}>{r.flag}</td></tr>
                    ))}</tbody>
                  </table>
                </div>
              </div>
              <div className="mt-6 overflow-x-auto">
                <h3 className="text-sm font-semibold">Table 6: security features as published</h3>
                <p className="mb-1 text-xs text-slate-500">Reproduced as claimed by RP9. The Lab and the security argument show F4 (impersonation) and F5 (anonymity) are not supported for RP9.</p>
                <table className="tbl text-xs">
                  <thead><tr><th>scheme</th>{ref.data.table6.features.map((f) => <th key={f}>{f}</th>)}</tr></thead>
                  <tbody>{Object.entries(ref.data.table6.rows).map(([s, row]) => (
                    <tr key={s}><td>{s}</td>{row.map((c, i) => <td key={i} className="text-center">{c}</td>)}</tr>
                  ))}</tbody>
                </table>
              </div>
            </Section>

            <Section title="Formal analysis" id="ev-formal">
              <p className="mb-3 text-sm text-slate-600">
                Symbolic (Dolev-Yao) analysis: perfect cryptography, a bounded number of sessions. &quot;No attack&quot; means
                none within these bounds in this abstract model. What each result does and does not show:
                formal/avispa/README.md.
              </p>
              <h3 className="mb-1 text-sm font-semibold">AVISPA (HLPSL): OFMC, CL-AtSe</h3>
              {!ref.data.formal_avispa.obtained ? <p className="text-sm font-semibold">AVISPA results: not obtained.</p> : (
                <>
                  <p className="mb-2 text-xs text-slate-600">
                    hlpsl2if (SPAN 1.6), OFMC version of 2006/02/13, CL-AtSe 2.2-5 and 2.3-4; typed model unless marked untyped.
                    RP9 Fig. 9 reports OFMC: SAFE, {String(ref.data.formal_avispa.paper_fig9?.visited_nodes ?? 1501)} visited
                    nodes, depth {String(ref.data.formal_avispa.paper_fig9?.depth_plies ?? 7)} plies.
                  </p>
                  <div className="overflow-x-auto">
                  <table className="tbl text-sm" data-testid="formal-avispa">
                    <thead><tr><th>model</th><th>back-end</th><th>sessions</th><th>verdict (all goals)</th><th>per goal</th>
                      <th>statistics</th><th>transitions that can run</th><th>raw output</th></tr></thead>
                    <tbody>{ref.data.formal_avispa.rows.map((r, i, all) => (
                      <tr key={`${r.model}-${r.backend}`} data-testid={`avispa-${r.model}`}>
                        <td>{r.label} <span className="font-mono text-xs text-slate-400">{r.model}</span>
                          {r.note && (i === 0 || all[i - 1].model !== r.model) && <span className="block text-xs text-slate-600">{r.note}</span>}</td>
                        <td className="text-xs">{r.backend}</td>
                        <td className="text-xs">{r.sessions}</td>
                        <td className={`font-semibold ${VERDICT_CLASS[r.verdict] ?? "text-amber-700"}`}>
                          {r.verdict}{r.violated ? <span className="block text-xs font-normal">{r.violated}</span> : null}
                          {r.message ? <span className="block text-xs font-normal">{r.message}</span> : null}</td>
                        <td className="text-xs">{r.per_goal.map((g) => `${g.goal}: ${g.verdict}`).join(", ") || "—"}</td>
                        <td className="font-mono text-xs">{stats(r.statistics)}</td>
                        <td className="text-right font-mono text-xs">{r.executable_transitions || "—"}</td>
                        <td className="font-mono text-xs">{r.file}</td></tr>
                    ))}</tbody>
                  </table>
                  </div>
                </>
              )}
              <h3 className="mb-1 mt-4 text-sm font-semibold">OFMC 2024 (AnB models)</h3>
              <p className="mb-2 text-xs text-slate-600">
                {ref.data.formal.tool ?? "OFMC 2024"} {ref.data.formal.date ? `(${ref.data.formal.date})` : ""}; models in formal/avispa/anb/.
              </p>
              {Object.keys(ref.data.formal.results).length === 0 ? <p className="text-sm font-semibold">OFMC 2024 results: not obtained.</p> : (
                <div className="overflow-x-auto">
                <table className="tbl text-sm" data-testid="formal-results">
                  <thead><tr><th>model</th><th>back-end</th><th>sessions</th><th>verdict</th><th>goal violated</th>
                    <th>statistics</th><th>raw output</th></tr></thead>
                  <tbody>{Object.entries(ref.data.formal.results).flatMap(([m, rs]) => rs.map((r) => (
                    <tr key={`${m}-${r.sessions}`} data-testid={`anb-${m}-${r.sessions}`}>
                      <td>{FORMAL_MODELS[m] ?? m} <span className="font-mono text-xs text-slate-400">{m}</span>
                        {FORMAL_NOTES[`${m}/${r.sessions}`] ? <span className="block text-xs text-slate-600">{FORMAL_NOTES[`${m}/${r.sessions}`]}</span> : null}</td>
                      <td className="text-xs">OFMC 2024</td>
                      <td className="text-right font-mono">{r.sessions}</td>
                      <td className={`font-semibold ${VERDICT_CLASS[r.summary] ?? "text-amber-700"}`}>
                        {r.summary === "ATTACK_FOUND" ? "⚠ attack found" : r.summary === "NO_ATTACK_FOUND" ? "✓ no attack found" : r.summary}</td>
                      <td className="text-xs">{r.summary === "ATTACK_FOUND" ? r.goal : "—"}</td>
                      <td className="font-mono text-xs">{stats(r.statistics)}</td>
                      <td className="font-mono text-xs">{r.file ? `formal/avispa/${r.file}` : "—"}</td></tr>
                  )))}</tbody>
                </table>
                </div>
              )}
            </Section>

            <Section title="Parameter security levels" id="ev-levels">
              <table className="tbl text-sm">
                <tbody>{Object.entries(ref.data.security_levels).map(([p, l]) => (
                  <tr key={p}><td className="font-mono">{p}</td><td>{l}</td></tr>
                ))}</tbody>
              </table>
            </Section>
          </>
        )}
      </div>
    </div>
  );
}
