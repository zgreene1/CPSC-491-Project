import { useNavigate } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { Button } from "../ui/Button";

interface HeaderProps {
  title: string;
  description?: string;
}

export function Header({ title, description }: HeaderProps) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  function handleLogout() {
    logout();
    navigate("/login", { replace: true });
  }

  return (
    <header className="flex h-16 shrink-0 items-center justify-between border-b border-ink-650 bg-ink-900/60 px-6 backdrop-blur">
      <div>
        <h1 className="text-lg font-semibold text-ink-50">{title}</h1>
        {description && <p className="text-sm text-ink-400">{description}</p>}
      </div>

      <div className="flex items-center gap-3">
        <div className="hidden items-center gap-2 rounded-full border border-ink-650 bg-ink-850 py-1 pl-1 pr-3 sm:flex">
          <span className="flex h-7 w-7 items-center justify-center rounded-full bg-signal-500/15 font-mono text-xs font-semibold text-signal-300">
            {user?.displayName?.slice(0, 2).toUpperCase() ?? "?"}
          </span>
          <span className="text-sm text-ink-200">{user?.displayName ?? "Guest"}</span>
        </div>
        <Button variant="ghost" size="sm" onClick={handleLogout}>
          Sign out
        </Button>
      </div>
    </header>
  );
}
