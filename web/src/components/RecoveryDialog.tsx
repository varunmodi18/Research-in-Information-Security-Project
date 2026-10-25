import { useState } from "react";
import type { ClusterRecovery } from "../api/hooks";
import { ConfirmDialog } from "./ConfirmDialog";

// docs/RECOVERY.md: operator-approved cluster-head replacement with a ranked recommendation. The
// member the operator confirms becomes the cluster head; the base station revokes the current one.
export function RecoveryDialog(props: {
  status: ClusterRecovery;
  busy: boolean;
  onCancel: () => void;
  onConfirm: (member: string) => void;
}) {
  const { status } = props;
  const [member, setMember] = useState(status.recommended ?? status.candidates[0]?.ident ?? "");
  return (
    <ConfirmDialog title={`Replace the cluster head of ${status.cluster}`} expected={status.cluster} confirmLabel="Promote and replace"
      busy={props.busy || !member} onCancel={props.onCancel} onConfirm={() => props.onConfirm(member)}
      body={`The base station revokes ${status.ch} and promotes the chosen member to cluster head with its existing keys. The other members follow the new cluster head when it relays their new designation. The promoted node takes on the cluster head's work and stops sending its own readings.`}>
      <div className="mt-3" data-testid="recovery-dialog">
        <div className="mb-1 flex items-center justify-between text-xs text-slate-600">
          <span>Ranked candidates (active, non-revoked members)</span>
          <span title="Score = 0.5·trust + 0.4·reliability − 0.1·rejections (normalised); ties by identity">score = 0.5·trust + 0.4·reliability − 0.1·rejections</span>
        </div>
        {status.candidates.length === 0 ? (
          <p className="text-sm text-amber-800">No active member can be promoted.</p>
        ) : (
          <table className="tbl text-sm" data-testid="recovery-candidates">
            <thead><tr><th /><th>member</th><th className="text-right">trust</th><th className="text-right">reliability</th>
              <th className="text-right">rejections</th><th className="text-right">score</th></tr></thead>
            <tbody>{status.candidates.map((c) => (
              <tr key={c.ident} data-testid={`candidate-${c.ident}`}>
                <td><input type="radio" name="recovery-member" aria-label={`Promote ${c.ident}`} checked={member === c.ident}
                  onChange={() => setMember(c.ident)} /></td>
                <td className="font-mono">{c.ident}{c.ident === status.recommended && (
                  <span className="ml-1 rounded bg-emerald-100 px-1 text-[10px] font-semibold text-emerald-800" data-testid="recommended">recommended</span>)}</td>
                <td className="text-right font-mono text-xs">{c.trust.toFixed(2)}</td>
                <td className="text-right font-mono text-xs">{c.reliability.toFixed(2)}</td>
                <td className="text-right font-mono text-xs">{c.rejections}</td>
                <td className="text-right font-mono text-xs font-semibold">{c.score.toFixed(3)}</td></tr>
            ))}</tbody>
          </table>
        )}
        <p className="mt-2 text-[11px] text-slate-500">
          Trust from the {status.trust_detector} (1 − normalised anomaly score), reliability = readings accepted at the base station
          without sequence gaps, rejections = rejection events the member caused; last 10 windows. A recommendation, not a
          guarantee: tested, not statistically evaluated.
        </p>
      </div>
    </ConfirmDialog>
  );
}
