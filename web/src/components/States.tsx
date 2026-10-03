// The data-view states every page implements (IMPLEMENTATION_PLAN.md §3.7, M5-T6).
import { ApiProblem } from "../api/client";

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 p-6 text-sm text-slate-500" role="status">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-300 border-t-blue-600" aria-hidden="true" />
      {label}
    </div>
  );
}

export function Empty({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="p-8 text-center text-sm text-slate-500">
      <div className="font-medium text-slate-700">{title}</div>
      {hint && <div className="mt-1">{hint}</div>}
    </div>
  );
}

export function ErrorPanel({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const p = error instanceof ApiProblem ? error : null;
  return (
    <div className="m-4 rounded-md border border-red-300 bg-red-50 p-4 text-sm text-red-900" role="alert">
      <div className="font-semibold">✕ {p ? p.title : "Something went wrong"}</div>
      <div className="mt-1">{p ? p.detail || p.code : String(error)}</div>
      {onRetry && (
        <button type="button" className="btn-secondary mt-3" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function StreamIndicator({ status }: { status: "connecting" | "live" | "reconnecting" }) {
  const map = {
    live: { dot: "bg-emerald-500", text: "Live" },
    connecting: { dot: "bg-amber-400 animate-pulse", text: "Connecting…" },
    reconnecting: { dot: "bg-amber-500 animate-pulse", text: "Reconnecting…" },
  }[status];
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-slate-600" role="status" aria-live="polite">
      <span className={`h-2 w-2 rounded-full ${map.dot}`} aria-hidden="true" />
      {map.text}
    </span>
  );
}
