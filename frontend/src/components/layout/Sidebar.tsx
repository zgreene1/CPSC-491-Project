import { NavLink } from "react-router-dom";

interface NavItem {
  to: string;
  label: string;
  icon: React.ReactNode;
}

function Icon({ path }: { path: string }) {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d={path} stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

const navItems: NavItem[] = [
  { to: "/dashboard", label: "Dashboard", icon: <Icon path="M4 13h6V4H4v9Zm10 7h6v-9h-6v9ZM4 20h6v-5H4v5ZM14 4v5h6V4h-6Z" /> },
  { to: "/scans/new", label: "New Scan", icon: <Icon path="M12 5v14M5 12h14" /> },
  { to: "/history", label: "Scan History", icon: <Icon path="M4 4v6h6M4.5 10a8 8 0 1 1 2 5.3M12 8v4l3 2" /> },
  { to: "/reports", label: "Reports", icon: <Icon path="M6 3h9l4 4v14H6zM15 3v4h4M9 12h6M9 16h6" /> },
  { to: "/settings", label: "Settings", icon: <Icon path="M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z M19.4 13.5c.04-.5.04-1 0-1.5l1.6-1.2-1.6-2.8-1.9.5a7.6 7.6 0 0 0-1.3-.75L15.8 5h-3.2l-.4 2.25a7.6 7.6 0 0 0-1.3.75l-1.9-.5-1.6 2.8 1.6 1.2c-.04.5-.04 1 0 1.5l-1.6 1.2 1.6 2.8 1.9-.5c.4.3.85.55 1.3.75l.4 2.25h3.2l.4-2.25c.45-.2.9-.45 1.3-.75l1.9.5 1.6-2.8-1.6-1.2Z" /> },
];

export function Sidebar() {
  return (
    <aside className="flex h-full w-64 shrink-0 flex-col border-r border-ink-650 bg-ink-900">
      <div className="flex h-16 items-center gap-2.5 border-b border-ink-650 px-5">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-signal-500/15 text-signal-400 ring-1 ring-inset ring-signal-500/30">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path
              d="M12 3 4 6v6c0 5 3.4 8.7 8 9 4.6-.3 8-4 8-9V6l-8-3Z"
              stroke="currentColor"
              strokeWidth="1.6"
              strokeLinejoin="round"
            />
          </svg>
        </div>
        <span className="font-[Space_Grotesk] text-[15px] font-semibold tracking-[-0.02em] text-ink-50">
          Sentry
        </span>
      </div>

      <nav className="flex-1 space-y-1 px-3 py-4" aria-label="Primary">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-signal-400 ${
                isActive
                  ? "bg-signal-500/12 text-signal-300 ring-1 ring-inset ring-signal-500/25"
                  : "text-ink-300 hover:bg-ink-800 hover:text-ink-100"
              }`
            }
          >
            {item.icon}
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-ink-650 px-5 py-4">
        <p className="text-xs text-ink-500">Vulnerability Scanner</p>
        <p className="text-xs text-ink-600">v0.1.0 — Sprint 1</p>
      </div>
    </aside>
  );
}
