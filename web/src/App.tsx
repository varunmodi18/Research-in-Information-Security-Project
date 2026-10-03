import { Navigate, Route, Routes } from "react-router-dom";
import type { Role } from "./api/types";
import { useAuth } from "./auth/AuthContext";
import { Layout } from "./components/Layout";
import { Empty, Loading } from "./components/States";
import { DashboardPage } from "./pages/DashboardPage";
import { EventsPage } from "./pages/EventsPage";
import { LoginPage } from "./pages/LoginPage";
import { NewNetworkPage } from "./pages/NewNetworkPage";
import { TopologyPage } from "./pages/TopologyPage";
import { EXTRA_ROUTES } from "./routes";

function Guard({ min, children }: { min: Role; children: React.ReactNode }) {
  const { can } = useAuth();
  return can(min) ? <>{children}</> : <Empty title="Restricted" hint={`This page requires the ${min} role or higher.`} />;
}

export function App() {
  const { session, loading } = useAuth();
  if (loading) return <Loading label="Starting…" />;
  if (!session) {
    return (
      <Routes>
        <Route path="*" element={<LoginPage />} />
      </Routes>
    );
  }
  return (
    <Routes>
      <Route path="/login" element={<Navigate to="/" replace />} />
      <Route element={<Layout />}>
        <Route index element={<DashboardPage />} />
        <Route path="/networks/new" element={<Guard min="operator"><NewNetworkPage /></Guard>} />
        <Route path="/networks/:id" element={<TopologyPage />} />
        <Route path="/events" element={<EventsPage />} />
        {EXTRA_ROUTES.map((r) => (
          <Route key={r.path} path={r.path} element={<Guard min={r.min}>{r.element}</Guard>} />
        ))}
        <Route path="*" element={<Empty title="Page not found" />} />
      </Route>
    </Routes>
  );
}
