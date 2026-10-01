import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import * as authService from "../services/authService";
import type { AuthUser } from "../services/authService";

interface AuthContextValue {
  user: AuthUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

const STORAGE_KEY = "sentry.auth.user";

function readStoredUser(): AuthUser | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as AuthUser) : null;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(() => readStoredUser());
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      isAuthenticated: user !== null,
      isLoading,
      error,
      async login(username: string, password: string) {
        setIsLoading(true);
        setError(null);
        try {
          const result = await authService.login(username, password);
          setUser(result.user);
          sessionStorage.setItem(STORAGE_KEY, JSON.stringify(result.user));
        } catch (err) {
          setError(err instanceof Error ? err.message : "Unable to sign in.");
          throw err;
        } finally {
          setIsLoading(false);
        }
      },
      logout() {
        setUser(null);
        sessionStorage.removeItem(STORAGE_KEY);
      },
    }),
    [user, isLoading, error],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}
