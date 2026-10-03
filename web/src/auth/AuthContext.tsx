import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, type ReactNode } from "react";
import { api, ApiProblem, setCsrfToken } from "../api/client";
import type { Role, SessionInfo } from "../api/types";
import { ROLE_RANK } from "../api/types";

interface AuthState {
  session: SessionInfo | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  can: (minimum: Role) => boolean;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const me = useQuery({
    queryKey: ["me"],
    queryFn: async () => {
      try {
        const s = await api.get<SessionInfo>("/auth/me");
        setCsrfToken(s.csrf_token);
        return s;
      } catch (e) {
        if (e instanceof ApiProblem && e.status === 401) return null;
        throw e;
      }
    },
    retry: false,
    staleTime: 60_000,
  });

  const login = useCallback(
    async (username: string, password: string) => {
      const s = await api.post<SessionInfo>("/auth/login", { username, password });
      setCsrfToken(s.csrf_token);
      qc.setQueryData(["me"], s);
    },
    [qc],
  );

  const logout = useCallback(async () => {
    try {
      await api.post("/auth/logout");
    } finally {
      setCsrfToken("");
      qc.clear();
      qc.setQueryData(["me"], null);
    }
  }, [qc]);

  const session = me.data ?? null;
  const can = useCallback(
    (minimum: Role) => (session ? ROLE_RANK[session.user.role] >= ROLE_RANK[minimum] : false),
    [session],
  );

  return (
    <AuthContext.Provider value={{ session, loading: me.isLoading, login, logout, can }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth outside AuthProvider");
  return ctx;
}
