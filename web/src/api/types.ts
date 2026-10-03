// API types. These mirror docs/openapi.json; `npm run gen:api:file` regenerates
// src/api/schema.d.ts from it, and this file re-exports the shapes the UI uses.
import type { components } from "./schema";

type S = components["schemas"];
export type User = S["UserOut"];
export type SessionInfo = S["SessionInfoOut"];
export type Network = S["NetworkOut"];
export type NetworkDetail = S["NetworkDetail"];
export type NetworkCreate = S["NetworkCreate"];
export type Device = S["DeviceOut"];
export type DeviceDetail = S["DeviceDetail"];
export type ProtocolSession = S["SessionOut"];
export type Job = S["JobOut"];
export type JobAccepted = S["JobAccepted"];
export type Frame = S["FrameOut"];
export type SecurityEvent = S["EventOut"];
export type Reading = S["ReadingOut"];
export type Audit = S["AuditOut"];
export type Role = User["role"];
export interface Page<T> {
  items: T[];
  next_cursor: number | null;
}
export type JobType = S["JobCreate"]["type"];

export const ROLE_RANK: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 };
export const TERMINAL_JOB_STATES = ["succeeded", "failed", "cancelled", "aborted"];
