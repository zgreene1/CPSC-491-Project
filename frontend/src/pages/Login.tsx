import { type FormEvent, useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { Button } from "../components/ui/Button";
import { ErrorMessage } from "../components/ui/ErrorMessage";
import { TextField } from "../components/ui/FormField";
import { useAuth } from "../context/AuthContext";

export function Login() {
  const { login, isAuthenticated, isLoading, error } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  if (isAuthenticated) {
    const from = (location.state as { from?: Location })?.from?.pathname ?? "/dashboard";
    return <Navigate to={from} replace />;
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setFormError(null);
    if (!username.trim() || !password.trim()) {
      setFormError("Enter both a username and password.");
      return;
    }
    try {
      await login(username, password);
      navigate("/dashboard", { replace: true });
    } catch {
      // surfaced via `error` from context
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center gap-3 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-signal-500/15 text-signal-400 ring-1 ring-inset ring-signal-500/30">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path
                d="M12 3 4 6v6c0 5 3.4 8.7 8 9 4.6-.3 8-4 8-9V6l-8-3Z"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinejoin="round"
              />
            </svg>
          </div>
          <div>
            <h1 className="text-2xl font-semibold text-ink-50">Sentry</h1>
            <p className="mt-1 text-sm text-ink-400">Sign in to your vulnerability scanner</p>
          </div>
        </div>

        <form
          onSubmit={handleSubmit}
          className="flex flex-col gap-4 rounded-2xl border border-ink-650 bg-ink-850 p-6 shadow-floating"
          noValidate
        >
          <TextField
            label="Username"
            name="username"
            autoComplete="username"
            placeholder="analyst@company.com"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <TextField
            label="Password"
            name="password"
            type="password"
            autoComplete="current-password"
            placeholder="••••••••"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />

          {(formError ?? error) && <ErrorMessage title="Sign-in failed" message={formError ?? error ?? ""} />}

          <Button type="submit" isLoading={isLoading} className="mt-2 w-full">
            Sign in
          </Button>
          <p className="text-center text-xs text-ink-500">
            Sprint 1 demo — any non-empty credentials will sign you in.
          </p>
        </form>
      </div>
    </div>
  );
}
