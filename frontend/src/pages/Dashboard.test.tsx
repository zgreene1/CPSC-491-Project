import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../context/AuthContext";
import { Dashboard } from "./Dashboard";
import * as historyService from "../services/historyService";
import * as remediationService from "../services/remediationService";
import type { ScanRecord } from "../types/scan";

function renderDashboard() {
  return render(
    <MemoryRouter initialEntries={["/dashboard"]}>
      <AuthProvider>
        <Routes>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/scans/:scanId/results" element={<div>Results page</div>} />
          <Route path="/scans/new" element={<div>New scan page</div>} />
          <Route path="/history" element={<div>History page</div>} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}

function demoScan(overrides: Partial<ScanRecord> = {}): ScanRecord {
  return {
    id: "scan-demo-1",
    target: "10.0.1.0/24",
    startedAt: "2026-09-15T14:32:00Z",
    status: "completed",
    totalFindings: 1,
    severityCounts: { critical: 1, high: 0, medium: 0, low: 0, info: 0, unclassified: 0 },
    isDemo: true,
    config: { target: "10.0.1.0/24", portRange: "1-1024", scanType: "full", scanDepth: "deep" },
    vulnerabilities: [
      {
        id: "vuln-1",
        cve: "CVE-2021-44228",
        severity: "critical",
        host: "10.0.1.31",
        port: 8080,
        service: "Apache Log4j",
        cvss: 10.0,
        description: "Log4Shell",
        remediation: "Upgrade Log4j.",
        matches: [],
      },
    ],
    ...overrides,
  };
}

function liveScan(overrides: Partial<ScanRecord> = {}): ScanRecord {
  return {
    id: "scan-live-1",
    target: "127.0.0.1",
    startedAt: "2026-10-15T17:00:00Z",
    status: "completed",
    totalFindings: 1,
    severityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unclassified: 1 },
    isDemo: false,
    config: { target: "127.0.0.1", portRange: "", scanType: "custom", scanDepth: "standard" },
    vulnerabilities: [
      {
        id: "vuln-live-1",
        cve: "Not yet assessed",
        severity: "unclassified",
        host: "127.0.0.1",
        port: 22,
        service: "OpenSSH",
        cvss: 0,
        description: "Open port detected.",
        remediation: "No automated remediation guidance available yet.",
        matches: [],
      },
    ],
    ...overrides,
  };
}

describe("Dashboard", () => {
  beforeEach(() => {
    vi.spyOn(historyService, "getScanHistory");
    localStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("computes stat tiles and overall risk dynamically from returned scans", async () => {
    vi.mocked(historyService.getScanHistory).mockResolvedValue([liveScan(), demoScan()]);

    renderDashboard();

    expect(await screen.findByText("2")).toBeInTheDocument(); // Total Findings = 1 + 1
    const riskCard = screen.getByText("Overall Risk").closest("div")!.parentElement!;
    expect(within(riskCard).getByText("High")).toBeInTheDocument();
    expect(screen.getByText("Based on 2 scans and 2 total findings.")).toBeInTheDocument();
  });

  it("labels each recent scan Live or Demo", async () => {
    vi.mocked(historyService.getScanHistory).mockResolvedValue([liveScan(), demoScan()]);

    renderDashboard();

    const recentScansCard = (await screen.findByText("Recent Scans")).closest("div")!.parentElement!;
    expect(within(recentScansCard).getByText("Live")).toBeInTheDocument();
    expect(within(recentScansCard).getByText("Demo")).toBeInTheDocument();
  });

  it("navigates to a scan's results when a recent scan row is clicked", async () => {
    vi.mocked(historyService.getScanHistory).mockResolvedValue([liveScan()]);
    const user = userEvent.setup();

    renderDashboard();

    await user.click(await screen.findByText("127.0.0.1"));
    expect(await screen.findByText("Results page")).toBeInTheDocument();
  });

  it("shows an empty state and a way to start a scan when there are no scans", async () => {
    vi.mocked(historyService.getScanHistory).mockResolvedValue([]);
    const user = userEvent.setup();

    renderDashboard();

    expect(await screen.findByText("No scans yet")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Start a scan" }));
    expect(await screen.findByText("New scan page")).toBeInTheDocument();
  });

  it("shows an error state with retry when the dashboard data fails to load", async () => {
    vi.mocked(historyService.getScanHistory)
      .mockRejectedValueOnce(new Error("Could not reach the scan service."))
      .mockResolvedValueOnce([demoScan()]);
    const user = userEvent.setup();

    renderDashboard();

    expect(await screen.findByText("Could not reach the scan service.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("10.0.1.0/24")).toBeInTheDocument();
  });

  it("surfaces a real potential match from the latest scan even when severity is unclassified", async () => {
    const scanWithMatch = liveScan({
      vulnerabilities: [
        {
          id: "vuln-live-1",
          cve: "Not yet assessed",
          severity: "unclassified",
          host: "127.0.0.1",
          port: 22,
          service: "OpenSSH",
          cvss: 0,
          description: "Open port detected.",
          remediation: "No automated remediation guidance available yet.",
          matches: [
            { vulnerabilityId: "CVE-2024-0001", status: "potential", summary: "OpenSSH match", sourceUrl: "https://example.com", confidence: 0.8 },
          ],
        },
      ],
    });
    vi.mocked(historyService.getScanHistory).mockResolvedValue([scanWithMatch]);

    renderDashboard();

    const alertsCard = (await screen.findByText("Alerts")).closest("div")!.parentElement!;
    expect(within(alertsCard).getByText("1 potential match")).toBeInTheDocument();
  });

  it("shows no alerts message when the latest scan has no critical/high findings or matches", async () => {
    vi.mocked(historyService.getScanHistory).mockResolvedValue([liveScan()]);

    renderDashboard();

    expect(await screen.findByText("No alerts from the latest scan.")).toBeInTheDocument();
  });

  it("surfaces an open-remediation count for the latest scan's untouched findings", async () => {
    vi.mocked(historyService.getScanHistory).mockResolvedValue([demoScan()]);

    renderDashboard();

    expect(await screen.findByText("1 open remediation")).toBeInTheDocument();
  });

  it("excludes a resolved finding from the open-remediation count", async () => {
    const scan = demoScan();
    vi.spyOn(remediationService, "getRemediation").mockReturnValue({
      status: "resolved",
      notes: "",
      updatedAt: "2026-10-01T00:00:00Z",
    });
    vi.mocked(historyService.getScanHistory).mockResolvedValue([scan]);

    renderDashboard();

    await screen.findByText("Alerts");
    expect(screen.queryByText(/open remediation/)).not.toBeInTheDocument();
  });
});
