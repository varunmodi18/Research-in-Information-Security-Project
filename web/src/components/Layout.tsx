import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

const NAV = [
  { to: "/", label: "Dashboard", min: "viewer" as const, end: true },
  { to: "/events", label: "Security events", min: "viewer" as const },
  { to: "/lab", label: "Lab", min: "operator" as const },
  { to: "/evaluation", label: "Evaluation", min: "viewer" as const },
  { to: "/admin", label: "Admin", min: "admin" as const },
];

export function Layout() {
  const { session, logout, can } = useAuth();
  return (
    <div className="flex min-h-screen">
      <nav className="flex w-56 shrink-0 flex-col bg-slate-900 text-slate-200" aria-label="Main">
        <div className="px-5 py-4">
          <div className="text-base font-semibold text-white">MAKA Console</div>
          <div className="text-xs text-slate-400">Secure IoT key management</div>
        </div>
        <ul className="flex-1 space-y-0.5 px-2">
          {NAV.filter((n) => can(n.min)).map((n) => (
            <li key={n.to}>
              <NavLink to={n.to} end={n.end}
                className={({ isActive }) => `block rounded-md px-3 py-2 text-sm ${isActive ? "bg-slate-700 text-white" : "hover:bg-slate-800"}`}>
                {n.label}
              </NavLink>
            </li>
          ))}
        </ul>
        <div className="border-t border-slate-700 px-4 py-3 text-xs">
          <div className="text-slate-300" data-testid="current-user">
            {session?.user.username} <span className="rounded bg-slate-700 px-1.5 py-0.5 text-[10px] uppercase">{session?.user.role}</span>
          </div>
          <button type="button" className="mt-2 text-slate-400 underline hover:text-white" onClick={() => void logout()}>
            Sign out
          </button>
        </div>
      </nav>
      <main className="min-w-0 flex-1">
        <Outlet />
      </main>
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3 px-6 pb-3 pt-5">
      <div>
        <h1 className="text-xl font-semibold text-slate-900">{title}</h1>
        {subtitle && <p className="mt-0.5 text-sm text-slate-500">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}
