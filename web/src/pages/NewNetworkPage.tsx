import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { ApiProblem } from "../api/client";
import { useCreateNetwork } from "../api/hooks";
import type { NetworkCreate } from "../api/types";
import { PageHeader } from "../components/Layout";
import { ModeBanner } from "../components/ModeBanner";
import { useToast } from "../components/Toast";

const TEMPLATES = [
  { id: "paper", label: "paper — 1 BS, 1 CH, 1 CM (RP9's cost-table fixture)" },
  { id: "small", label: "small — 1 BS, 1 CH, 3 CM" },
  { id: "net", label: "net — 1 BS, 3 CH × 3 CM" },
  { id: "custom", label: "custom — 1–5 CH, 1–8 CM each" },
];

export function NewNetworkPage() {
  const nav = useNavigate();
  const toast = useToast();
  const create = useCreateNetwork();
  const [name, setName] = useState("");
  const [template, setTemplate] = useState("small");
  const [chs, setChs] = useState(2);
  const [cms, setCms] = useState(2);
  const [kind, setKind] = useState<"product" | "lab">("product");
  const [mode, setMode] = useState<"enhanced" | "original">("enhanced");
  const [params, setParams] = useState<"toy" | "demo" | "secure">("toy");
  const [seed, setSeed] = useState("");
  const [securePseudo, setSecurePseudo] = useState(true);
  const [forward, setForward] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    const body: NetworkCreate = {
      name,
      kind,
      mode: kind === "product" ? "enhanced" : mode,
      params,
      template: template === "custom" ? null : (template as "paper" | "small" | "net"),
      custom: template === "custom" ? { chs, cms_per_ch: cms } : null,
      seed: seed === "" ? null : Number(seed),
      secure_pseudo_ids: securePseudo,
      forward_ciphertexts: forward,
    };
    try {
      const net = await create.mutateAsync(body);
      toast(`Network “${net.name}” created and provisioned`);
      nav(`/networks/${net.id}`);
    } catch (err) {
      setError(err instanceof ApiProblem ? `${err.title}: ${err.detail}` : String(err));
    }
  };

  return (
    <div>
      <ModeBanner />
      <PageHeader title="New network" subtitle="Provisioning creates the BS master key and loads each device's keys" />
      <form onSubmit={submit} className="card mx-6 mb-8 grid max-w-3xl gap-4 p-5 md:grid-cols-2">
        <div className="md:col-span-2">
          <label className="label" htmlFor="nn-name">Name</label>
          <input id="nn-name" className="input" value={name} onChange={(e) => setName(e.target.value)} required
            pattern="[A-Za-z0-9][A-Za-z0-9 _.\-]{0,63}" placeholder="e.g. Vineyard" />
        </div>
        <fieldset>
          <legend className="label">Kind</legend>
          {(["product", "lab"] as const).map((k) => (
            <label key={k} className="mr-4 inline-flex items-center gap-1.5 text-sm">
              <input type="radio" name="kind" checked={kind === k} onChange={() => setKind(k)} />
              {k === "product" ? "Product (MAKA-E only)" : "Lab (attack experiments)"}
            </label>
          ))}
        </fieldset>
        <fieldset>
          <legend className="label">Protocol</legend>
          {(["enhanced", "original"] as const).map((m) => (
            <label key={m} className="mr-4 inline-flex items-center gap-1.5 text-sm">
              <input type="radio" name="mode" checked={(kind === "product" ? "enhanced" : mode) === m}
                disabled={kind === "product" && m === "original"} onChange={() => setMode(m)} />
              {m === "enhanced" ? "MAKA-E v1" : "RP9 original"}
            </label>
          ))}
          {kind === "product" && <p className="mt-1 text-xs text-slate-500">Product networks cannot run RP9's original protocol.</p>}
        </fieldset>
        <div>
          <label className="label" htmlFor="nn-template">Topology</label>
          <select id="nn-template" className="input" value={template} onChange={(e) => setTemplate(e.target.value)}>
            {TEMPLATES.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
          </select>
          {template === "custom" && (
            <div className="mt-2 flex gap-2">
              <label className="text-xs">CHs <input type="number" min={1} max={5} className="input w-20" value={chs} onChange={(e) => setChs(Number(e.target.value))} /></label>
              <label className="text-xs">CMs per CH <input type="number" min={1} max={8} className="input w-20" value={cms} onChange={(e) => setCms(Number(e.target.value))} /></label>
            </div>
          )}
        </div>
        <div>
          <label className="label" htmlFor="nn-params">Parameter set</label>
          <select id="nn-params" className="input" value={params} onChange={(e) => setParams(e.target.value as typeof params)}>
            <option value="toy">toy — INSECURE, fast, hand-checkable</option>
            <option value="demo">demo — about 60-bit, demonstration only</option>
            <option value="secure">secure — about 80-bit, slow</option>
          </select>
        </div>
        {kind === "lab" && (
          <div>
            <label className="label" htmlFor="nn-seed">Seed (optional, reproducible runs)</label>
            <input id="nn-seed" className="input" inputMode="numeric" value={seed} onChange={(e) => setSeed(e.target.value.replace(/\D/g, ""))} />
          </div>
        )}
        {kind === "lab" && mode === "original" && (
          <fieldset className="md:col-span-2">
            <legend className="label">RP9 options</legend>
            <label className="mr-6 inline-flex items-center gap-1.5 text-sm">
              <input type="checkbox" checked={securePseudo} onChange={(e) => setSecurePseudo(e.target.checked)} />
              Encrypt pseudo-identities (I-02 fix; off = RP9 Table 2 pricing)
            </label>
            <label className="inline-flex items-center gap-1.5 text-sm">
              <input type="checkbox" checked={forward} onChange={(e) => setForward(e.target.checked)} />
              CH forwards member ciphertexts (addition to RP9)
            </label>
          </fieldset>
        )}
        {error && <div className="rounded border border-red-300 bg-red-50 p-2 text-sm text-red-800 md:col-span-2" role="alert">✕ {error}</div>}
        <div className="md:col-span-2">
          <button type="submit" className="btn-primary" disabled={create.isPending}>
            {create.isPending ? "Provisioning…" : "Create and provision"}
          </button>
        </div>
      </form>
    </div>
  );
}
