// Device status (FR-11). Colour is never the only signal: every badge has an icon and text (M5-T6).
const STYLES: Record<string, { icon: string; cls: string; label: string }> = {
  provisioned: { icon: "○", cls: "bg-slate-100 text-slate-700 border-slate-300", label: "provisioned" },
  registered: { icon: "◐", cls: "bg-sky-50 text-sky-800 border-sky-300", label: "registered" },
  authenticated: { icon: "◑", cls: "bg-indigo-50 text-indigo-800 border-indigo-300", label: "authenticated" },
  active: { icon: "✓", cls: "bg-emerald-50 text-emerald-800 border-emerald-400", label: "active" },
  failed: { icon: "✕", cls: "bg-red-50 text-red-800 border-red-400", label: "failed" },
  revoked: { icon: "⊘", cls: "bg-rose-100 text-rose-900 border-rose-500", label: "revoked" },
};

export const STATUS_COLOURS: Record<string, string> = {
  provisioned: "#94a3b8",
  registered: "#0ea5e9",
  authenticated: "#6366f1",
  active: "#10b981",
  failed: "#ef4444",
  revoked: "#9f1239",
};

export function StatusBadge({ status }: { status: string }) {
  const s = STYLES[status] ?? { icon: "?", cls: "bg-slate-100 text-slate-700 border-slate-300", label: status };
  return (
    <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium ${s.cls}`}>
      <span aria-hidden="true">{s.icon}</span>
      {s.label}
    </span>
  );
}

const SEVERITY: Record<string, string> = {
  info: "bg-slate-100 text-slate-700 border-slate-300",
  warn: "bg-amber-50 text-amber-800 border-amber-400",
  high: "bg-red-50 text-red-800 border-red-400",
};
const SEVERITY_ICON: Record<string, string> = { info: "ℹ", warn: "⚠", high: "⛔" };

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs font-semibold ${SEVERITY[severity] ?? SEVERITY.info}`}>
      <span aria-hidden="true">{SEVERITY_ICON[severity] ?? "ℹ"}</span>
      {severity}
    </span>
  );
}

export function VerdictBadge({ verdict }: { verdict: string }) {
  const ok = verdict === "ACCEPT";
  const dropped = verdict === "DROPPED";
  const cls = ok
    ? "bg-emerald-50 text-emerald-800 border-emerald-400"
    : dropped
      ? "bg-slate-100 text-slate-700 border-slate-400"
      : "bg-red-50 text-red-800 border-red-400";
  return (
    <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs font-semibold ${cls}`}>
      <span aria-hidden="true">{ok ? "✓" : dropped ? "⤫" : "✕"}</span>
      {ok ? "PASS" : dropped ? "DROPPED" : "FAIL"}
    </span>
  );
}
