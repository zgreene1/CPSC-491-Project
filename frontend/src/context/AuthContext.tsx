import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import * as authService from "../services/authService";
import type { AuthUser } from "../services/authService";
import { onSessionInvalidated, setToken } from "../services/authSession";

interface AuthContextValue {
  user: AuthUser | null;
  isAuthenticated: boolean;
  isInitializing: boolean;
  isLoading: boolean;
  error: string | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

const TOKEN_STORAGE_KEY = "sentry.auth.token";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isInitializing, setIsInitializing] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function clearSession() {
    setUser(null);
    sessionStorage.removeItem(TOKEN_STORAGE_KEY);
    setToken(null);
  }

  // A stored token is never trusted on its own — it's verified against
  // GET /api/auth/me before the session is treated as real, closing the gap
  // where a fabricated sessionStorage entry used to grant access outright.
  useEffect(() => {
    const storedToken = sessionStorage.getItem(TOKEN_STORAGE_KEY);
    if (!storedToken) {
      setIsInitializing(false);
      return;
    }

    authService
      .getCurrentUser(storedToken)
      .then((verifiedUser) => setUser(verifiedUser))
      .catch(() => clearSession())
      .finally(() => setIsInitializing(false));
  }, []);

  // A 401 from any API call (token expired, logged out elsewhere, tampered
  // token) invalidates the session the same way an explicit logout does.
  useEffect(() => onSessionInvalidated(clearSession), []);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      isAuthenticated: user !== null,
      isInitializing,
      isLoading,
      error,
      async login(username: string, password: string) {
        setIsLoading(true);
        setError(null);
        try {
          const result = await authService.login(username, password);
          setUser(result.user);
          sessionStorage.setItem(TOKEN_STORAGE_KEY, result.token);
        } catch (err) {
          setError(err instanceof Error ? err.message : "Unable to sign in.");
          throw err;
        } finally {
          setIsLoading(false);
        }
      },
      logout() {
        // authService.logout() is already best-effort (never rejects); it
        // clears the token itself, this just clears the rest of the session.
        void authService.logout();
        clearSession();
      },
    }),
    [user, isInitializing, isLoading, error],
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
