import { useState, type FormEvent } from "react";
import { Navigate } from "react-router-dom";
import { ApiProblem } from "../api/client";
import { useAuth } from "../auth/AuthContext";

export function LoginPage() {
  const { session, login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  if (session) return <Navigate to="/" replace />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username, password);
    } catch (err) {
      setError(err instanceof ApiProblem ? `${err.title}: ${err.detail}` : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-900">
      <form onSubmit={submit} className="card w-96 p-6" aria-labelledby="login-title">
        <h1 id="login-title" className="text-lg font-semibold">MAKA Secure IoT Console</h1>
        <p className="mb-5 mt-1 text-xs text-slate-500">
          Simulated devices · real cryptography · demonstration-grade parameters
        </p>
        <label className="label" htmlFor="username">Username</label>
        <input id="username" className="input mb-3" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
        <label className="label" htmlFor="password">Password</label>
        <input id="password" type="password" className="input mb-4" autoComplete="current-password" value={password}
          onChange={(e) => setPassword(e.target.value)} required />
        {error && <div className="mb-3 rounded border border-red-300 bg-red-50 p-2 text-sm text-red-800" role="alert">✕ {error}</div>}
        <button type="submit" className="btn-primary w-full justify-center" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
