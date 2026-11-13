import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export function ProtectedRoute({ children }: { children: ReactNode }) {
  const { isAuthenticated, isInitializing } = useAuth();
  const location = useLocation();

  // While a stored token is being verified against GET /api/auth/me, show
  // nothing rather than flashing protected content or bouncing to /login.
  if (isInitializing) {
    return (
      <div className="flex min-h-screen items-center justify-center" role="status" aria-label="Loading session">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-ink-650 border-t-signal-400" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  return <>{children}</>;
}
