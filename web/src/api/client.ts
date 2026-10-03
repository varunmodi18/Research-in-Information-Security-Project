// Thin fetch wrapper: same-origin cookie session, CSRF header on every non-GET request,
// RFC 9457 problem+json errors surfaced as ApiProblem (IMPLEMENTATION_PLAN.md §4.5).

export class ApiProblem extends Error {
  constructor(
    public status: number,
    public code: string,
    public title: string,
    public detail: string,
  ) {
    super(detail || title);
  }
}

let csrfToken = "";
export function setCsrfToken(token: string): void {
  csrfToken = token;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = csrfToken;
  const res = await fetch(`/api${path}`, {
    method,
    credentials: "same-origin",
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    let p: { code?: string; title?: string; detail?: string } = {};
    try {
      p = await res.json();
    } catch {
      /* non-JSON error body */
    }
    throw new ApiProblem(res.status, p.code ?? "ERROR", p.title ?? res.statusText, p.detail ?? "");
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body ?? {}),
  patch: <T>(path: string, body: unknown) => request<T>("PATCH", path, body),
  del: <T>(path: string, body?: unknown) => request<T>("DELETE", path, body),
};

export function idempotencyKey(): string {
  return crypto.randomUUID().replace(/-/g, "");
}

export function qs(params: Record<string, string | number | boolean | null | undefined>): string {
  const entries = Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== "");
  return entries.length ? "?" + new URLSearchParams(entries.map(([k, v]) => [k, String(v)])).toString() : "";
}
