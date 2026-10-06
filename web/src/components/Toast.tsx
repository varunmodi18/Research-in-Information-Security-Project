import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { useJob } from "../api/hooks";
import { TERMINAL_JOB_STATES } from "../api/types";

type Tone = "success" | "error" | "info" | "pending";
interface Toast {
  id: number;
  tone: Tone;
  text: string;
}
const DISMISS_MS = 4500;

interface Tracked {
  toastId: number;
  jobId: number;
  done: string;
}
interface ToastApi {
  push: (text: string, tone?: Tone) => number;
  track: (jobId: number, running: string, done: string) => void;
}
const ToastContext = createContext<ToastApi>({ push: () => 0, track: () => undefined });

/** Polls one job and turns its pending toast into the outcome once the job is terminal. */
function JobWatcher({ t, update, remove }: { t: Tracked; update: (id: number, text: string, tone: Tone) => void;
  remove: (jobId: number) => void }) {
  const job = useJob(t.jobId);
  const state = job.data?.state;
  useEffect(() => {
    if (!state || !TERMINAL_JOB_STATES.includes(state)) return;
    if (state === "succeeded") update(t.toastId, t.done, "success");
    else update(t.toastId, `${job.data?.type ?? "job"} ${state}${job.data?.error ? `: ${job.data.error}` : ""}`, "error");
    remove(t.jobId);
  }, [state]); // eslint-disable-line react-hooks/exhaustive-deps
  return null;
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [tracked, setTracked] = useState<Tracked[]>([]);
  const nextId = useRef(1);
  const expire = useCallback((id: number) => {
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), DISMISS_MS);
  }, []);
  // A "pending" toast (a job in progress) stays until it is updated with the job's outcome.
  const push = useCallback((text: string, tone: Tone = "success") => {
    const id = nextId.current++;
    setToasts((t) => [...t, { id, tone, text }]);
    if (tone !== "pending") expire(id);
    return id;
  }, [expire]);
  const update = useCallback((id: number, text: string, tone: Tone) => {
    setToasts((t) => t.map((x) => (x.id === id ? { id, tone, text } : x)));
    if (tone !== "pending") expire(id);
  }, [expire]);
  const track = useCallback((jobId: number, running: string, done: string) => {
    setTracked((t) => [...t, { toastId: push(running, "pending"), jobId, done }]);
  }, [push]);
  const remove = useCallback((jobId: number) => setTracked((t) => t.filter((x) => x.jobId !== jobId)), []);
  const tones = {
    success: "border-emerald-400 bg-emerald-50 text-emerald-900",
    error: "border-red-400 bg-red-50 text-red-900",
    info: "border-slate-300 bg-white text-slate-800",
    pending: "border-blue-300 bg-blue-50 text-blue-900",
  };
  const icons = { success: "✓", error: "✕", info: "ℹ", pending: "⟳" };
  return (
    <ToastContext.Provider value={{ push, track }}>
      {children}
      {tracked.map((t) => <JobWatcher key={t.jobId} t={t} update={update} remove={remove} />)}
      <div className="fixed bottom-4 right-4 z-50 flex w-96 flex-col gap-2" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`rounded-md border px-3 py-2 text-sm shadow ${tones[t.tone]}`} role="status"
            data-testid="toast" data-tone={t.tone}>
            <span aria-hidden="true">{icons[t.tone]} </span>
            {t.text}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

/** Fire-and-forget toast: `toast(text, tone)`. */
export function useToast() {
  return useContext(ToastContext).push;
}

/**
 * A toast that follows a job (follow-up F3): `track(jobId, "Revoking CM-0102…", "CM-0102 revoked")`
 * shows a pending toast that stays while the job runs and is replaced by the outcome when the job
 * reaches a terminal state, so a finished job never leaves "…ing" on screen. Any number of jobs
 * can be tracked at once.
 */
export function useJobToast() {
  return useContext(ToastContext).track;
}
