import type { Device } from "../api/types";

// Follow-up D2: a CM whose designated CH was revoked is not told. It keeps its sessions and PSK with
// that CH until the replacement CH relays a new DESIGNATION, and every reading it sends meanwhile
// is lost (the revoked CH can no longer reach the BS).
export const AWAITING = "ch_revoked_awaiting_redesignation";
export const AWAITING_LABEL = "CH revoked, awaiting re-designation";

export function awaiting(devices: Device[]): Device[] {
  // a member that is itself revoked is excluded for its own revocation; it awaits nothing
  return devices.filter((d) => d.designation_state === AWAITING && d.status !== "revoked");
}

export function lostReadings(devices: Device[]): number {
  return devices.reduce((n, d) => n + (d.undelivered ?? 0), 0);
}

/** Network-wide banner: who is waiting and how many readings were lost so far. */
export function DesignationBanner({ devices }: { devices: Device[] }) {
  const waiting = awaiting(devices);
  const lost = lostReadings(devices);
  if (waiting.length === 0 && lost === 0) return null;
  return (
    <div className="mx-6 mb-3 rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900" role="alert" data-testid="designation-banner">
      {waiting.length > 0 && (
        <p>
          <strong>{AWAITING_LABEL}:</strong> {waiting.map((d) => d.ident).join(", ")} (designated to{" "}
          {[...new Set(waiting.map((d) => d.designated))].join(", ")}). They are not told of the revocation; their
          readings cannot reach the base station until a replacement CH is designated for their cluster.
        </p>
      )}
      <p data-testid="lost-readings">
        Readings lost while a member's CH was revoked: <strong>{lost}</strong>.
      </p>
    </div>
  );
}
