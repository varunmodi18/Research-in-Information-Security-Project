import { useEffect, useRef, useState, type ReactNode } from "react";

// Typed confirmation for destructive actions: revoke, network delete, demo reset (§3.7).
export function ConfirmDialog(props: {
  title: string;
  body: string;
  expected: string;
  confirmLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
  busy?: boolean;
  children?: ReactNode;  // extra fields shown above the typed confirmation (e.g. Designate CH)
}) {
  const [typed, setTyped] = useState("");
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => { if (!props.children) input.current?.focus(); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-slate-900/40" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
      <div className="card w-[28rem] p-5">
        <h2 id="confirm-title" className="text-lg font-semibold">
          {props.title}
        </h2>
        <p className="mt-2 text-sm text-slate-600">{props.body}</p>
        {props.children}
        <label className="label mt-4" htmlFor="confirm-input">
          Type <span className="font-mono normal-case text-slate-800">{props.expected}</span> to confirm
        </label>
        <input id="confirm-input" ref={input} className="input font-mono" value={typed} onChange={(e) => setTyped(e.target.value)}
          onKeyDown={(e) => e.key === "Escape" && props.onCancel()} />
        <div className="mt-4 flex justify-end gap-2">
          <button type="button" className="btn-secondary" onClick={props.onCancel}>
            Cancel
          </button>
          <button type="button" className="btn-danger" disabled={typed !== props.expected || props.busy} onClick={props.onConfirm}>
            {props.confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
