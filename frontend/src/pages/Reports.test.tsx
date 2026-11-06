import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../context/AuthContext";
import { Reports } from "./Reports";
import * as historyService from "../services/historyService";
import type { ScanRecord } from "../types/scan";

function renderReports() {
  return render(
    <MemoryRouter initialEntries={["/reports"]}>
      <AuthProvider>
        <Reports />
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
        matches: [{ vulnerabilityId: "CVE-2024-0001", status: "potential", summary: "OpenSSH match", sourceUrl: "https://example.com", confidence: 0.8 }],
      },
    ],
    ...overrides,
  };
}

describe("Reports", () => {
  beforeEach(() => {
    vi.spyOn(historyService, "getScanHistory");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("computes severity distribution and overall risk dynamically", async () => {
    vi.mocked(historyService.getScanHistory).mockResolvedValue([liveScan(), demoScan()]);

    renderReports();

    const distributionCard = (await screen.findByText("Severity Distribution")).closest("div")!.parentElement!;
    const criticalTile = within(distributionCard).getByText("Critical").closest("div")!;
    expect(within(criticalTile).getByText("1")).toBeInTheDocument();

    const riskCard = screen.getByText("Overall Risk").closest("div")!.parentElement!;
    expect(within(riskCard).getByText("High")).toBeInTheDocument();
    expect(screen.getByText("Based on 2 scans and 2 total findings.")).toBeInTheDocument();
  });

  it("lists critical findings with their source labeled Live or Demo", async () => {
    vi.mocked(historyService.getScanHistory).mockResolvedValue([demoScan()]);

    renderReports();

    const criticalCard = (await screen.findByText("Critical Findings")).closest("div")!.parentElement!;
    expect(within(criticalCard).getByText("CVE-2021-44228")).toBeInTheDocument();
    expect(within(criticalCard).getByText("Demo")).toBeInTheDocument();
  });

  it("shows a no-critical-findings message when there are none", async () => {
    vi.mocked(historyService.getScanHistory).mockResolvedValue([liveScan()]);

    renderReports();

    expect(await screen.findByText("No critical severity findings.")).toBeInTheDocument();
  });

  it("ranks hosts by finding count, highest first", async () => {
    const repeatOffender = liveScan({
      id: "scan-live-2",
      vulnerabilities: [
        { id: "a", cve: "CVE-A", severity: "unclassified", host: "10.0.0.5", port: 80, service: "http", cvss: 0, description: "", remediation: "", matches: [] },
        { id: "b", cve: "CVE-B", severity: "unclassified", host: "10.0.0.5", port: 443, service: "https", cvss: 0, description: "", remediation: "", matches: [] },
      ],
    });
    vi.mocked(historyService.getScanHistory).mockResolvedValue([demoScan(), repeatOffender]);

    renderReports();

    const rankingCard = (await screen.findByText("Highest-Risk Hosts")).closest("div")!.parentElement!;
    const rows = within(rankingCard).getAllByText(/finding/);
    expect(rows[0]).toHaveTextContent("2 findings");
  });

  it("recommends remediating critical findings first when present", async () => {
    vi.mocked(historyService.getScanHistory).mockResolvedValue([demoScan()]);

    renderReports();

    expect(await screen.findByText("Remediate 1 critical finding first.")).toBeInTheDocument();
  });

  it("recommends investigating real potential matches surfaced by the scanner", async () => {
    vi.mocked(historyService.getScanHistory).mockResolvedValue([liveScan()]);

    renderReports();

    expect(
      await screen.findByText("Investigate 1 potential vulnerability match surfaced by the scanner."),
    ).toBeInTheDocument();
  });

  it("shows an empty state when there are no scans", async () => {
    vi.mocked(historyService.getScanHistory).mockResolvedValue([]);

    renderReports();

    expect(await screen.findByText("No scans yet")).toBeInTheDocument();
  });

  it("shows an error state with retry when report data fails to load", async () => {
    vi.mocked(historyService.getScanHistory)
      .mockRejectedValueOnce(new Error("Could not reach the scan service."))
      .mockResolvedValueOnce([demoScan()]);
    const user = userEvent.setup();

    renderReports();

    expect(await screen.findByText("Could not reach the scan service.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("CVE-2021-44228")).toBeInTheDocument();
  });
});
