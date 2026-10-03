import type { Network } from "../api/types";

// The mode banner (IMPLEMENTATION_PLAN.md §3.2, V-DOC-02): what is real and what is simulated,
// which protocol runs, and the parameter set with its security level.
export function ModeBanner({ network }: { network?: Network }) {
  if (!network) {
    return (
      <div className="border-b border-slate-200 bg-slate-100 px-6 py-1.5 text-xs text-slate-600" data-testid="mode-banner">
        Devices and radio are <b>simulated</b> · cryptography is <b>real</b> · parameters are demonstration-grade ·
        readings are demo data
      </div>
    );
  }
  const lab = network.kind === "lab";
  const mode = network.mode === "enhanced" ? "MAKA-E v1 (enhanced)" : "RP9 original (as published)";
  return (
    <div
      className={`flex flex-wrap items-center gap-x-4 gap-y-1 border-b px-6 py-1.5 text-xs ${lab ? "border-red-300 bg-red-50 text-red-900" : "border-emerald-200 bg-emerald-50 text-emerald-900"}`}
      data-testid="mode-banner"
    >
      <span className="font-semibold">
        {lab ? "⚗ Attack laboratory — not a product network" : "● Product network"} · {mode}
      </span>
      <span data-testid="param-set">
        Parameters: <b>{network.params}</b> — {network.security_level}
      </span>
      <span>Devices simulated · cryptography real · readings are demo data</span>
    </div>
  );
}
