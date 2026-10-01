# Frontend Architecture — Sprint 1

**Owner:** Frontend Lead
**Scope:** Sprint 1 — Frontend Foundation (Sept. 3–17)

## Stack

- **React 19 + TypeScript**, scaffolded with Vite (`frontend/`)
- **react-router-dom v7** for client-side routing
- **Tailwind CSS v4** (via `@tailwindcss/vite`) for styling, with a custom design-token theme (see `src/index.css`) — no default Tailwind color palette is used, per project design guardrails
- **Vitest + React Testing Library** for component/unit tests

Rationale: the semester plan requires an API/service-layer architecture (`ScanService`, `AuthService`, `ResultsService`, `HistoryService`), reusable typed components, and a real test suite from Sprint 2 onward. A framework-based SPA gets that architecture in place now instead of requiring a rewrite later.

## Folder structure

```
frontend/src/
├── pages/            One component per route (Login, Dashboard, NewScan, ScanProgress,
│                      ScanResults, ScanHistory, Reports, Settings)
├── components/
│   ├── layout/        AppShell, Sidebar, Header, PageContainer — the app chrome
│   └── ui/             Button, FormField (Text/Select), Card, Table, SeverityBadge,
│                        StatusPill, LoadingIndicator, ErrorMessage, EmptyState
├── routes/            ProtectedRoute (auth guard)
├── context/           AuthContext — the only global state in Sprint 1
├── services/          authService, scanService, resultsService, historyService — the
│                        seam Sprint 2 will swap from mocked to real HTTP calls
├── mocks/             Seed data used by the services above
├── types/             Shared domain types (Severity, ScanConfig, Vulnerability, ...)
└── test/              Test setup + a renderWithProviders helper
```

## Routing map

| Path | Page | Notes |
| --- | --- | --- |
| `/login` | Login | Public |
| `/dashboard` | Dashboard | Protected |
| `/scans/new` | New Scan | Protected |
| `/scans/:scanId/progress` | Scan Progress | Protected |
| `/scans/:scanId/results` | Scan Results | Protected |
| `/history` | Scan History | Protected |
| `/reports` | Reports | Protected |
| `/settings` | Settings | Protected |

`ProtectedRoute` redirects unauthenticated visitors to `/login` and preserves the originally requested location so login can return them there.

## State management

- **Auth** is the only cross-cutting state, held in `AuthContext` (React context + `useState`), backed by `sessionStorage` so a refresh doesn't force a re-login during a demo.
- **Everything else is local component state** (`useState`/`useEffect` per page) fetched through the service layer. There's no global store (Redux/Zustand) yet — nothing in Sprint 1's scope needs data shared across more than one page. If Sprint 3+ introduces cross-page caching needs (e.g. re-using scan results between Dashboard and Results), that's the point to introduce a data-fetching library rather than before.

## Service layer

Every page talks to mock data through a function in `src/services/*`, never by importing `mocks/scans.ts` directly into a component (`Dashboard` reads mock data directly for the aggregate summary, since that view has no equivalent single-scan endpoint yet — everything else goes through a service). Each service function is written with a real-API shape already in mind:

```ts
export async function startScan(config: ScanConfig): Promise<ScanRecord>
export async function getScanResults(scanId: string): Promise<ScanRecord | undefined>
export async function getScanHistory(): Promise<ScanSummary[]>
export async function login(username: string, password: string): Promise<LoginResult>
```

Sprint 2 replaces the mocked bodies with `fetch`/`axios` calls to the real backend without touching any calling component — the validation logic in `scanService.validateScanConfig` also mirrors the target/port-range rules already implemented in the backend's `target_validation.py`, so client-side validation won't drift from server-side rules.

## Accessibility

- All interactive elements have visible `:hover`, `:focus-visible`, and `:active` states (see `Button`, `Table` sort headers, nav links).
- Form fields use `<label htmlFor>` pairs (via `useId`), and errors are announced with `role="alert"`.
- The results table uses semantic `<table>`/`<th scope="col">` markup; sortable headers are real `<button>`s with `aria-label`s, not clickable `<div>`s.
- Loading regions use `role="status"`; the progress bar uses `role="progressbar"` with `aria-valuenow/min/max`.

## Testing

`npm test` runs Vitest + React Testing Library. Sprint 1 covers:

- Component rendering (`Button`, `SeverityBadge`, `Table`, `Sidebar`)
- Form validation (`NewScan`, `scanService.validateScanConfig`)
- Routing/auth behavior (`App` — unauthenticated redirect, login → dashboard navigation)

## Design system

Dark security-dashboard theme, defined as Tailwind v4 `@theme` tokens in `src/index.css`:

- **Ink** scale — navy-black surface colors with three elevation levels (base → elevated → floating)
- **Signal** — a custom teal/emerald brand accent (not Tailwind's default indigo/blue) used for primary actions, active nav state, and focus rings
- **Severity** scale — critical/high/medium/low/info, used consistently by `SeverityBadge`, dashboard stat cards, and alerts
- Typography: Space Grotesk (display/headings) paired with Inter (body/UI) and IBM Plex Mono (CVE IDs, IPs, ports, CVSS scores)

## What's deliberately out of scope for Sprint 1

Per the sprint plan, these are stubbed with clear "coming in a later sprint" messaging rather than built out now: report export/PDF generation, remediation status tracking, real-time progress via websockets, and usability-tested empty/error copy. The routes and components exist; the depth comes in Sprints 2–5.
