import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { api, ApiProblem } from "../api/client";
import type { Audit, Page, Role, User } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { PageHeader } from "../components/Layout";
import { ModeBanner } from "../components/ModeBanner";
import { Empty, ErrorPanel, Loading } from "../components/States";
import { useToast } from "../components/Toast";

// FR-18..FR-20: users and roles, demo reset, audit log (Admin only; enforced server-side).
export function AdminPage() {
  const { session } = useAuth();
  const toast = useToast();
  const qc = useQueryClient();
  const users = useQuery({ queryKey: ["users"], queryFn: () => api.get<User[]>("/admin/users") });
  const audit = useQuery({ queryKey: ["audit"], queryFn: () => api.get<Page<Audit>>("/admin/audit?limit=200") });
  const [form, setForm] = useState({ username: "", password: "", role: "viewer" as Role });
  const [resetOpen, setResetOpen] = useState(false);
  const err = (e: unknown) => toast(e instanceof ApiProblem ? `${e.title}: ${e.detail}` : String(e), "error");

  const create = useMutation({
    mutationFn: () => api.post<User>("/admin/users", form),
    onSuccess: (u) => { toast(`User ${u.username} created`); setForm({ username: "", password: "", role: "viewer" }); void qc.invalidateQueries({ queryKey: ["users"] }); },
    onError: err,
  });
  const patch = useMutation({
    mutationFn: ({ id, body }: { id: number; body: Partial<User> }) => api.patch<User>(`/admin/users/${id}`, body),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["users"] }),
    onError: err,
  });
  const reset = useMutation({
    mutationFn: () => api.post("/admin/reset-demo", { confirm: "RESET" }),
    onSuccess: () => { toast("Demo reset started"); setResetOpen(false); void qc.invalidateQueries(); },
    onError: err,
  });

  return (
    <div>
      <ModeBanner />
      <PageHeader title="Administration" subtitle="Console users, demo data and the audit trail"
        actions={<button type="button" className="btn-danger" onClick={() => setResetOpen(true)}>Reset demo…</button>} />
      <div className="mx-6 mb-8 grid gap-4 xl:grid-cols-2">
        <section className="card" aria-labelledby="users-h">
          <h2 id="users-h" className="border-b border-slate-200 px-4 py-2 text-sm font-semibold">Users</h2>
          {users.isLoading && <Loading />}
          {users.error && <ErrorPanel error={users.error} />}
          {users.data && (
            <table className="w-full">
              <thead><tr><th className="th">User</th><th className="th">Role</th><th className="th">State</th></tr></thead>
              <tbody>
                {users.data.map((u) => (
                  <tr key={u.id}>
                    <td className="td font-mono">{u.username}</td>
                    <td className="td">
                      <label className="sr-only" htmlFor={`role-${u.id}`}>Role of {u.username}</label>
                      <select id={`role-${u.id}`} className="input w-32" value={u.role} disabled={u.id === session?.user.id}
                        onChange={(e) => patch.mutate({ id: u.id, body: { role: e.target.value as Role } })}>
                        <option value="viewer">viewer</option><option value="operator">operator</option><option value="admin">admin</option>
                      </select>
                    </td>
                    <td className="td">
                      <button type="button" className="btn-secondary" disabled={u.id === session?.user.id}
                        onClick={() => patch.mutate({ id: u.id, body: { disabled: !u.disabled } })}>
                        {u.disabled ? "✕ disabled — enable" : "✓ enabled — disable"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <form className="grid grid-cols-[1fr_1fr_8rem_auto] items-end gap-2 border-t border-slate-200 p-4"
            onSubmit={(e: FormEvent) => { e.preventDefault(); create.mutate(); }}>
            <div><label className="label" htmlFor="nu-name">Username</label>
              <input id="nu-name" className="input" required value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></div>
            <div><label className="label" htmlFor="nu-pw">Password (12+)</label>
              <input id="nu-pw" type="password" minLength={12} className="input" required value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></div>
            <div><label className="label" htmlFor="nu-role">Role</label>
              <select id="nu-role" className="input" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
                <option value="viewer">viewer</option><option value="operator">operator</option><option value="admin">admin</option>
              </select></div>
            <button type="submit" className="btn-primary" disabled={create.isPending}>Add</button>
          </form>
        </section>
        <section className="card overflow-x-auto" aria-labelledby="audit-h">
          <h2 id="audit-h" className="border-b border-slate-200 px-4 py-2 text-sm font-semibold">Audit log</h2>
          {audit.isLoading && <Loading />}
          {audit.error && <ErrorPanel error={audit.error} />}
          {audit.data?.items.length === 0 && <Empty title="No audited actions yet" />}
          {audit.data && audit.data.items.length > 0 && (
            <table className="w-full">
              <thead><tr><th className="th">When</th><th className="th">Who</th><th className="th">Action</th><th className="th">Outcome</th></tr></thead>
              <tbody>
                {audit.data.items.map((a) => (
                  <tr key={a.id}>
                    <td className="td whitespace-nowrap text-xs text-slate-500">{new Date(a.ts).toLocaleString()}</td>
                    <td className="td font-mono text-xs">{a.username || "—"}</td>
                    <td className="td font-mono text-xs">{a.action}</td>
                    <td className="td text-xs">{a.outcome === "success" ? "✓ success" : `✕ ${a.outcome}`}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </div>
      {resetOpen && (
        <ConfirmDialog title="Reset the demo?" expected="RESET" confirmLabel="Reset demo" busy={reset.isPending}
          body="Deletes every network and restores the seeded demo dataset (Vineyard and Lab-Paper). Users are kept."
          onCancel={() => setResetOpen(false)} onConfirm={() => reset.mutate()} />
      )}
    </div>
  );
}
